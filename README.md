# daily_security

국내·해외 보안 이슈를 매일 아침 자동으로 수집해 Notion에 기록하고 메일로 알려주는 파이프라인입니다.
Claude Code Routine이 하루 한 번 실행합니다.

## 무엇을 하나요

1. **수집** `collect.py`가 뉴스 피드 15곳과 취약점 API 4종을 읽어 JSON 파일 하나로 만듭니다.
2. **판단** Claude가 JSON을 읽고 우선순위를 매기고, 중복을 합치고, 한국어로 요약합니다.
3. **기록** 중요한 항목을 Notion 데이터베이스에 행으로 남깁니다.
4. **알림** 하루치 요약을 Gmail로 보냅니다.
5. **상태 저장** 이미 본 항목을 `state/seen.json`에 기록해 다음 날 중복을 막습니다.

## 수집 대상

| 구분 | 소스 |
| --- | --- |
| 국내 | 안랩 ASEC, KISA 보호나라(보안공지, 취약점 정보, 경보단계, 보고서), 보안뉴스, 데일리시큐 |
| 해외 | BleepingComputer, The Hacker News, SANS ISC, Unit 42, Cisco Talos, Google Threat Intelligence, Microsoft Security Blog, Project Zero |
| 취약점 | NVD(CVSS 7.0 이상), CISA KEV(실제 악용 확인), EPSS(악용 확률), 공개 PoC 인덱스(링크와 메타데이터만) |

## 설계 원칙

- **수집과 판단을 분리합니다.** `collect.py`는 LLM을 부르지 않습니다. 같은 입력이면 같은 결과가 나와서 재현과 디버깅이 됩니다. 요약, 분류, 번역은 Routine이 맡습니다.
- **기준값은 설정 파일에 둡니다.** 피드 추가, CVSS 기준, 수집 기간은 `sources.yaml`만 고치면 됩니다.
- **실패를 숨기지 않습니다.** 필수 소스(priority 1)가 실패하면 결과의 `errors`에 `fatal: true`로 남고, 브리핑에 실패 사실이 표시됩니다. 소스 하나가 실패해도 나머지 수집은 계속됩니다.
- **익스플로잇 코드는 다루지 않습니다.** 공개 PoC는 저장소 링크, 별 개수, 갱신일만 가져옵니다. 목적은 패치 우선순위 판단입니다.

## 빠른 시작

```bash
pip install -r requirements.txt

python3 collect.py --validate          # 모든 소스 연결 테스트
python3 collect.py                     # 수집 → out/brief-YYYY-MM-DD.json
python3 collect.py --window-hours 48   # 수집 기간 조정
python3 collect.py --no-state          # 중복 제거 끄기 (테스트용)
```

NVD API 키는 없어도 동작하지만 30초당 5회로 제한됩니다.
[무료로 발급](https://nvd.nist.gov/developers/request-an-api-key)받아 환경변수 `NVD_API_KEY`에 넣으면 30초당 50회로 늘어납니다.

Notion 데이터베이스 구성, Routine 등록, 네트워크 허용 목록은 [SETUP.md](SETUP.md)를 따라 하면 됩니다.

## 출력 형식

`out/brief-YYYY-MM-DD.json`

| 필드 | 내용 |
| --- | --- |
| `stats` | 국내·해외 뉴스 수, CVE 수(치명, 높음), KEV 신규, 공개 PoC 확인 수 |
| `news.kr`, `news.global` | 기사 목록. 본문에 나온 CVE 번호는 `cve_refs`로 추출 |
| `cve.critical`, `cve.high` | CVSS 9.0 이상 / 7.0 이상. `in_kev`, `epss`, `public_poc`, `poc_available` 포함 |
| `kev` | 최근 7일 안에 등재된 실제 악용 취약점 |
| `errors` | 실패한 소스와 사유, 필수 소스 여부(`fatal`) |

## 설정

`sources.yaml`의 `settings`

| 항목 | 기본값 | 설명 |
| --- | --- | --- |
| `window_hours` | 24 | 수집 기간 |
| `cvss_min` | 7.0 | 이 점수 이상만 수집 |
| `cvss_deep_dive` | 9.0 | 이 점수 이상은 EPSS와 공개 PoC까지 조회 |
| `kev_lookback_days` | 7 | KEV 조회 기간 |
| `max_items_per_feed` | 15 | 피드당 최대 건수 |
| `seen_retention_days` | 30 | 중복 제거 기록 보존 기간 |

## 파일 구성

| 파일 | 역할 |
| --- | --- |
| `collect.py` | 수집기 |
| `sources.yaml` | 피드, API, 기준값 설정 |
| `ROUTINE_PROMPT.md` | Routine에 등록하는 지시문 원본 |
| `SETUP.md` | 설치와 설정 순서, 문제 해결 |
| `AGENTS.md` | 코드를 수정할 때 지킬 규칙 |
| `state/seen.json` | 중복 제거 상태 (실행 시 생성) |
| `out/` | 수집 결과 (실행 시 생성) |

## 알아둘 한계

- **NVD 분석 지연:** CVE가 공개돼도 CVSS 점수가 붙기까지 며칠 걸릴 수 있습니다. 수정일 기준으로 조회해 뒤늦게 점수가 붙은 항목은 잡지만, 공개 직후의 제로데이는 놓칠 수 있어 KEV와 벤더 블로그를 함께 봅니다.
- **CVSS만으로는 부족:** 점수가 높아도 쓰는 곳이 없는 제품일 수 있습니다. EPSS, KEV, 국내 사용 여부를 함께 판단합니다.
- **PoC 인덱스는 미검증:** 제3자가 공개한 저장소 링크입니다. 악성코드가 들어 있을 수 있으니 격리된 분석 환경에서만 다뤄야 합니다.
- **Routine 실행 조건:** Claude 유료 플랜과 Notion, Gmail 커넥터 연결이 필요합니다.
