#!/usr/bin/env python3
"""
security-daily-brief / collect.py

국내·해외 보안 이슈를 결정론적으로 수집해 JSON 하나로 떨어뜨린다.
LLM 은 이 JSON 을 받아 번역/요약/분류만 담당한다 (수집 단계에 판단이 끼면 재현이 안 됨).

수집 대상
  - RSS: 안랩 ASEC, KISA 보호나라, 보안뉴스 등 (sources.yaml)
  - NVD: CVSS 7.0 이상 신규/갱신 CVE
  - CISA KEV: 실제 악용 확인된 취약점
  - EPSS: 악용 확률 스코어 (CVSS 9.0+ 대상)
  - PoC 인덱스: 공개 PoC 저장소 '링크'만 조회 (코드는 내려받지 않음)

사용법
  python3 collect.py                      # 기본 수집 → out/brief-YYYY-MM-DD.json
  python3 collect.py --validate           # 모든 소스 연결 테스트만
  python3 collect.py --window-hours 48    # 수집 기간 조정
  python3 collect.py --no-state           # 중복 제거 끄기 (테스트용)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import feedparser
import requests
import yaml

ROOT = Path(__file__).resolve().parent
STATE_PATH = ROOT / "state" / "seen.json"
OUT_DIR = ROOT / "out"
KST = timezone(timedelta(hours=9))

UA = "security-daily-brief/1.0 (personal threat-intel digest)"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

errors: list[dict] = []


def log(msg: str) -> None:
    print(f"[{datetime.now(KST):%H:%M:%S}] {msg}", file=sys.stderr)


def record_error(source: str, detail: str, fatal: bool = False) -> None:
    errors.append({"source": source, "detail": detail[:300], "fatal": fatal})
    log(f"{'FATAL' if fatal else 'WARN'}: {source} — {detail[:150]}")


# ──────────────────────────── 상태 (중복 제거) ────────────────────────────

def load_state(retention_days: int) -> dict:
    if not STATE_PATH.exists():
        return {"seen": {}}
    try:
        state = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        record_error("state", f"상태파일 로드 실패, 새로 시작: {e}")
        return {"seen": {}}

    cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
    state["seen"] = {k: v for k, v in state.get("seen", {}).items() if v >= cutoff}
    return state


def save_state(state: dict) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=1, sort_keys=True),
        encoding="utf-8",
    )


def is_new(key: str, state: dict, use_state: bool) -> bool:
    if not use_state:
        return True
    if key in state["seen"]:
        return False
    state["seen"][key] = datetime.now(timezone.utc).isoformat()
    return True


# ──────────────────────────── HTTP ────────────────────────────

def http_get(url: str, timeout: int, params: dict | None = None,
             headers: dict | None = None, retries: int = 2):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, params=params, headers=h, timeout=timeout)
            if r.status_code == 403 and "host_not_allowed" in r.headers.get("x-deny-reason", ""):
                raise RuntimeError(
                    f"네트워크 정책에 막힘 — Routine 환경의 Allowed domains 에 이 호스트를 추가하세요: {url}"
                )
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r
        except Exception as e:  # noqa: BLE001
            last = e
            if attempt < retries:
                time.sleep(2 ** attempt)
    raise last  # type: ignore[misc]


# ──────────────────────────── RSS ────────────────────────────

def parse_entry_time(entry) -> datetime | None:
    for field in ("published_parsed", "updated_parsed"):
        tm = getattr(entry, field, None)
        if tm:
            return datetime(*tm[:6], tzinfo=timezone.utc)
    return None


def clean_text(raw: str, limit: int = 700) -> str:
    text = re.sub(r"<[^>]+>", " ", raw or "")
    text = re.sub(r"&[a-zA-Z#0-9]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]


def collect_rss(feeds: list[dict], since: datetime, cfg: dict,
                state: dict, use_state: bool, region: str) -> list[dict]:
    items: list[dict] = []
    max_items = cfg["max_items_per_feed"]

    for feed in feeds:
        name, url = feed["name"], feed["url"]
        try:
            resp = http_get(url, cfg["request_timeout"])
            if resp is None:
                record_error(name, "404 — 피드 주소가 바뀐 것 같습니다",
                             fatal=feed.get("priority", 3) == 1)
                continue
            parsed = feedparser.parse(resp.content)
            if parsed.bozo and not parsed.entries:
                record_error(name, f"파싱 실패: {parsed.bozo_exception}",
                             fatal=feed.get("priority", 3) == 1)
                continue

            kept = 0
            for entry in parsed.entries:
                if kept >= max_items:
                    break
                published = parse_entry_time(entry)
                if published and published < since:
                    continue

                link = getattr(entry, "link", "")
                title = clean_text(getattr(entry, "title", ""), 300)
                if not link or not title:
                    continue
                if not is_new(f"rss::{link}", state, use_state):
                    continue

                body = getattr(entry, "summary", "") or ""
                if getattr(entry, "content", None):
                    body = entry.content[0].get("value", body)

                items.append({
                    "source": name,
                    "region": region,
                    "tag": feed.get("tag", "뉴스"),
                    "title": title,
                    "link": link,
                    "published": published.isoformat() if published else None,
                    "excerpt": clean_text(body),
                    "cve_refs": sorted({m.upper() for m in CVE_RE.findall(f"{title} {body}")}),
                })
                kept += 1
            log(f"RSS  {name}: {kept}건")
        except Exception as e:  # noqa: BLE001
            record_error(name, str(e), fatal=feed.get("priority", 3) == 1)

    return items


# ──────────────────────────── NVD ────────────────────────────

def extract_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    """가장 신뢰도 높은 CVSS 를 뽑는다. v4.0 > v3.1 > v3.0 > v2, Primary 우선."""
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        entries = metrics.get(key) or []
        if not entries:
            continue
        chosen = next((m for m in entries if m.get("type") == "Primary"), entries[0])
        data = chosen.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        severity = data.get("baseSeverity") or chosen.get("baseSeverity")
        return float(score), severity, f"CVSS v{version} ({data.get('vectorString', '')})"
    return None, None, None


def fetch_nvd_page(base_url: str, params: dict, timeout: int, api_key: str | None) -> dict:
    headers = {"apiKey": api_key} if api_key else {}
    resp = http_get(base_url, timeout, params=params, headers=headers, retries=3)
    if resp is None:
        return {"vulnerabilities": [], "totalResults": 0}
    return resp.json()


def collect_nvd(cfg: dict, api_cfg: dict, since: datetime, now: datetime,
                state: dict, use_state: bool) -> list[dict]:
    if not api_cfg.get("enabled"):
        return []

    base_url = api_cfg["base_url"]
    api_key = os.environ.get(api_cfg.get("api_key_env", "NVD_API_KEY")) or None
    if not api_key:
        log("NVD  API 키 없음 — 30초당 5회 제한으로 동작합니다 (느림)")

    fmt = "%Y-%m-%dT%H:%M:%S.000"
    results: list[dict] = []

    # HIGH(7.0~8.9) + CRITICAL(9.0~10.0) 두 번 호출하면 7.0 이상이 정확히 커버된다.
    for severity in ("HIGH", "CRITICAL"):
        start_index, total = 0, None
        while True:
            params = {
                "lastModStartDate": since.strftime(fmt),
                "lastModEndDate": now.strftime(fmt),
                "cvssV3Severity": severity,
                "noRejected": "",
                "resultsPerPage": 2000,
                "startIndex": start_index,
            }
            try:
                data = fetch_nvd_page(base_url, params, cfg["request_timeout"], api_key)
            except Exception as e:  # noqa: BLE001
                record_error(f"NVD/{severity}", str(e), fatal=True)
                break

            if total is None:
                total = data.get("totalResults", 0)
                log(f"NVD  {severity}: 총 {total}건")

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id")
                if not cve_id:
                    continue

                score, sev, vector = extract_cvss(cve.get("metrics", {}))
                if score is None or score < cfg["cvss_min"]:
                    continue
                # 스코어가 바뀌면 다시 알린다 (7.5 → 9.8 승격 케이스)
                if not is_new(f"cve::{cve_id}::{score}", state, use_state):
                    continue

                desc = next(
                    (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                    "",
                )
                refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]

                results.append({
                    "cve_id": cve_id,
                    "cvss": score,
                    "severity": sev or severity,
                    "vector": vector,
                    "published": cve.get("published"),
                    "last_modified": cve.get("lastModified"),
                    "description": desc[:1500],
                    "cwe": sorted({
                        d.get("value", "")
                        for w in cve.get("weaknesses", [])
                        for d in w.get("description", [])
                        if d.get("value", "").startswith("CWE-")
                    }),
                    "references": refs[:8],
                    "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })

            start_index += 2000
            if total is None or start_index >= total:
                break
            time.sleep(0.7 if api_key else 6.5)  # NVD 레이트리밋 준수

    results.sort(key=lambda x: x["cvss"], reverse=True)
    return results


# ──────────────────────────── CISA KEV ────────────────────────────

def collect_kev(cfg: dict, api_cfg: dict, state: dict, use_state: bool) -> list[dict]:
    if not api_cfg.get("enabled"):
        return []
    try:
        resp = http_get(api_cfg["url"], cfg["request_timeout"])
        if resp is None:
            record_error("CISA KEV", "404")
            return []
        catalog = resp.json()
    except Exception as e:  # noqa: BLE001
        record_error("CISA KEV", str(e))
        return []

    cutoff = (datetime.now(timezone.utc) - timedelta(days=cfg["kev_lookback_days"])).date()
    out = []
    for v in catalog.get("vulnerabilities", []):
        try:
            added = datetime.strptime(v["dateAdded"], "%Y-%m-%d").date()
        except (KeyError, ValueError):
            continue
        if added < cutoff:
            continue
        if not is_new(f"kev::{v['cveID']}", state, use_state):
            continue
        out.append({
            "cve_id": v["cveID"],
            "vendor": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "name": v.get("vulnerabilityName", ""),
            "date_added": v["dateAdded"],
            "due_date": v.get("dueDate", ""),
            "required_action": v.get("requiredAction", ""),
            "known_ransomware": v.get("knownRansomwareCampaignUse", "Unknown"),
            "notes": (v.get("notes", "") or "")[:500],
        })
    log(f"KEV  최근 {cfg['kev_lookback_days']}일 신규: {len(out)}건")
    return out


# ──────────────────────────── EPSS ────────────────────────────

def collect_epss(cve_ids: list[str], cfg: dict, api_cfg: dict) -> dict[str, dict]:
    if not api_cfg.get("enabled") or not cve_ids:
        return {}
    scores: dict[str, dict] = {}
    for i in range(0, len(cve_ids), 50):  # API 가 콤마 구분 배치를 지원
        batch = cve_ids[i:i + 50]
        try:
            resp = http_get(api_cfg["base_url"], cfg["request_timeout"],
                            params={"cve": ",".join(batch)})
            if resp is None:
                continue
            for row in resp.json().get("data", []):
                scores[row["cve"]] = {
                    "epss": round(float(row.get("epss", 0)), 5),
                    "percentile": round(float(row.get("percentile", 0)), 5),
                }
        except Exception as e:  # noqa: BLE001
            record_error("EPSS", str(e))
    return scores


# ──────────────────────── 공개 PoC 인덱스 조회 ────────────────────────

def collect_poc_refs(cve_ids: list[str], cfg: dict, api_cfg: dict) -> dict[str, list[dict]]:
    """
    공개된 PoC 저장소의 '메타데이터'만 조회한다 (URL, 설명, 스타수, 갱신일).
    익스플로잇 코드는 내려받지도 실행하지도 않는다.
    실제 악용 여부 판단과 패치 우선순위 산정을 위한 신호로만 쓴다.
    """
    if not api_cfg.get("enabled") or not cve_ids:
        return {}

    base = api_cfg["base_url"]
    found: dict[str, list[dict]] = {}

    for cve_id in cve_ids:
        year = cve_id.split("-")[1]
        try:
            resp = http_get(f"{base}/{year}/{cve_id}.json", cfg["request_timeout"], retries=1)
        except Exception:  # noqa: BLE001
            continue
        if resp is None:
            continue  # 인덱스에 없음 = 공개 PoC 미확인
        try:
            repos = resp.json()
        except json.JSONDecodeError:
            continue

        entries = []
        for repo in repos:
            entries.append({
                "url": repo.get("html_url", ""),
                "full_name": repo.get("full_name", ""),
                "description": clean_text(repo.get("description") or "", 200),
                "stars": int(repo.get("stargazers_count") or 0),
                "created_at": repo.get("created_at", ""),
                "updated_at": repo.get("updated_at", ""),
            })
        entries.sort(key=lambda x: x["stars"], reverse=True)
        if entries:
            found[cve_id] = entries[:5]

    return found


# ──────────────────────────── 검증 모드 ────────────────────────────

def validate(cfg: dict, feeds: list[dict], apis: dict) -> int:
    print("=" * 78)
    print(" 소스 연결 검증")
    print("=" * 78)
    failed = 0

    for feed in feeds:
        name = feed["name"]
        try:
            resp = http_get(feed["url"], cfg["request_timeout"], retries=0)
            if resp is None:
                print(f"  [404 ] {name:<34} 주소 없음 — 피드가 이전됐습니다")
                print(f"         {feed['url']}")
                failed += 1
                continue

            ctype = resp.headers.get("content-type", "?").split(";")[0]
            parsed = feedparser.parse(resp.content)
            n = len(parsed.entries)

            if n:
                latest = parse_entry_time(parsed.entries[0])
                age = ""
                if latest:
                    days = (datetime.now(timezone.utc) - latest).days
                    age = f", 최신글 {days}일 전"
                    if days > 30:
                        age += " ⚠ 방치된 피드일 수 있음"
                print(f"  [OK  ] {name:<34} {n}건{age}")
            else:
                # 200을 주는데 항목이 0 → 대개 경로 이전 후 빈 껍데기를 서빙하는 경우
                hint = "HTML 응답 (피드가 아님)" if "html" in ctype else f"{ctype}, 항목 0건"
                print(f"  [빈  ] {name:<34} {hint}")
                print(f"         {feed['url']}")
                if parsed.bozo:
                    print(f"         파서: {str(parsed.bozo_exception)[:70]}")
                failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {name:<34} {str(e)[:60]}")
            failed += 1

    print("  " + "-" * 74)
    for label, url in (("CISA KEV", apis["kev"]["url"]),
                       ("NVD", apis["nvd"]["base_url"] + "?resultsPerPage=1"),
                       ("EPSS", apis["epss"]["base_url"] + "?cve=CVE-2021-44228"),
                       ("PoC 인덱스", apis["poc_index"]["base_url"] + "/2021/CVE-2021-44228.json")):
        try:
            resp = http_get(url, cfg["request_timeout"], retries=0)
            print(f"  [{'OK  ' if resp else '404 '}] {label}")
            if not resp:
                failed += 1
        except Exception as e:  # noqa: BLE001
            print(f"  [FAIL] {label:<34} {str(e)[:60]}")
            failed += 1

    print("=" * 78)
    if failed:
        print(f" 실패 {failed}건 — sources.yaml 에서 해당 항목의 url 을 수정하세요.")
        print(" 대체 피드는 브라우저로 해당 사이트를 열어 RSS 링크를 확인하는 것이 가장 확실합니다.")
    else:
        print(" 전체 정상")
    return 1 if failed else 0


# ──────────────────────────── main ────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="보안 이슈 일일 수집기")
    ap.add_argument("--config", default=str(ROOT / "sources.yaml"))
    ap.add_argument("--window-hours", type=int)
    ap.add_argument("--validate", action="store_true", help="소스 연결만 테스트")
    ap.add_argument("--no-state", action="store_true", help="중복 제거 끄기")
    ap.add_argument("--out", help="출력 경로 (기본: out/brief-YYYY-MM-DD.json)")
    args = ap.parse_args()

    conf = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    cfg = conf["settings"]
    apis = conf["apis"]
    all_feeds = conf["feeds_kr"] + conf["feeds_global"]

    if args.validate:
        return validate(cfg, all_feeds, apis)

    if args.window_hours:
        cfg["window_hours"] = args.window_hours

    use_state = not args.no_state
    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=cfg["window_hours"])
    state = load_state(cfg["seen_retention_days"])

    log(f"수집 시작 — 기준: {since:%Y-%m-%d %H:%M} ~ {now:%Y-%m-%d %H:%M} UTC")

    news_kr = collect_rss(conf["feeds_kr"], since, cfg, state, use_state, "KR")
    news_global = collect_rss(conf["feeds_global"], since, cfg, state, use_state, "GLOBAL")
    cves = collect_nvd(cfg, apis["nvd"], since, now, state, use_state)
    kev = collect_kev(cfg, apis["kev"], state, use_state)

    # CVSS 9.0 이상만 심층 조회 (EPSS + 공개 PoC 링크)
    deep = [c for c in cves if c["cvss"] >= cfg["cvss_deep_dive"]]
    deep_ids = [c["cve_id"] for c in deep]
    kev_ids = [k["cve_id"] for k in kev]

    epss = collect_epss(sorted(set(deep_ids + kev_ids)), cfg, apis["epss"])
    log(f"EPSS 조회: {len(epss)}건")
    poc = collect_poc_refs(deep_ids, cfg, apis["poc_index"])
    log(f"공개 PoC 확인: {len(poc)}/{len(deep_ids)}건")

    kev_set = set(kev_ids)
    for c in cves:
        c["in_kev"] = c["cve_id"] in kev_set
        c["epss"] = epss.get(c["cve_id"])
        c["public_poc"] = poc.get(c["cve_id"], [])
        c["poc_available"] = bool(c["public_poc"])
    for k in kev:
        k["epss"] = epss.get(k["cve_id"])

    payload = {
        "generated_at": datetime.now(KST).isoformat(),
        "window": {"from": since.isoformat(), "to": now.isoformat(),
                   "hours": cfg["window_hours"]},
        "thresholds": {"cvss_min": cfg["cvss_min"], "cvss_deep_dive": cfg["cvss_deep_dive"]},
        "stats": {
            "news_kr": len(news_kr),
            "news_global": len(news_global),
            "cve_total": len(cves),
            "cve_critical": len(deep),
            "cve_high": len(cves) - len(deep),
            "kev_new": len(kev),
            "poc_available": sum(1 for c in cves if c["poc_available"]),
        },
        "news": {"kr": news_kr, "global": news_global},
        "cve": {
            "critical": deep,
            "high": [c for c in cves if c["cvss"] < cfg["cvss_deep_dive"]],
        },
        "kev": kev,
        "errors": errors,
        "poc_disclaimer": (
            "public_poc 는 제3자가 공개한 저장소 링크입니다. 검증되지 않았으며 "
            "악성코드가 포함될 수 있습니다. 패치 우선순위 판단 근거로만 사용하고, "
            "코드 실행은 반드시 격리된 분석 환경에서만 하십시오."
        ),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else OUT_DIR / f"brief-{datetime.now(KST):%Y-%m-%d}.json"
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    if use_state:
        save_state(state)

    s = payload["stats"]
    log("─" * 50)
    log(f"국내 {s['news_kr']} / 해외 {s['news_global']} / "
        f"CVE {s['cve_total']}(치명 {s['cve_critical']}) / "
        f"KEV {s['kev_new']} / PoC {s['poc_available']}")
    log(f"출력: {out_path}")

    if any(e["fatal"] for e in errors):
        log("주의: 필수(priority 1) 소스 중 실패한 항목이 있습니다.")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
