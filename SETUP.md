# 설정 가이드

전체 30~40분. 순서대로 하세요. 3번(네트워크 허용목록)을 빼먹으면 반드시 실패합니다.

---

## 0. 사전 조건

- Claude 유료 플랜 (Pro / Max / Team / Enterprise) — 무료 계정은 Routines 사용 불가
- [claude.ai/settings](https://claude.ai/settings) 에서 Claude Code on the web 활성화
- GitHub 계정 연결 (Routine이 리포지토리를 클론합니다)
- Notion, Gmail 커넥터 연결 — [claude.ai/customize/connectors](https://claude.ai/customize/connectors)

---

## 1. 리포지토리 생성

이 폴더를 **비공개(private)** 리포지토리로 올리세요. `state/seen.json`이 매일 커밋되므로 공개 저장소는 부적절합니다.

```bash
cd security-daily-brief
git init && git branch -M main
git add . && git commit -m "init: 보안 이슈 자동 수집 파이프라인"
gh repo create security-daily-brief --private --source=. --push
```

**브랜치 푸시 허용 설정** — Routine은 기본적으로 `claude/` 접두사 브랜치에만 푸시할 수 있습니다.
매일 상태 파일을 main에 커밋해야 하므로, Routine 생성 후 리포지토리 설정에서
**Allow unrestricted branch pushes** 를 켜세요. 이걸 안 켜면 중복 제거가 동작하지 않아
매일 같은 항목이 반복해서 올라옵니다.

---

## 2. Notion 데이터베이스 만들기

Notion에서 새 데이터베이스를 만들고 이름을 **`보안 이슈 DB`** 로 지정하세요.
(다른 이름을 쓰려면 ROUTINE_PROMPT.md의 `{{보안 이슈 DB}}` 부분을 함께 바꾸세요.)

속성을 아래와 같이 정확히 구성합니다. 이름이 다르면 Routine이 못 찾습니다.

| 속성 이름 | 타입 | 옵션 |
|---|---|---|
| 제목 | 제목 | — |
| 수집일 | 날짜 | — |
| 구분 | 선택 | `CVE` `KEV` `국내동향` `해외동향` |
| 심각도 | 선택 | `CRITICAL` `HIGH` `정보` |
| CVSS | 숫자 | 소수점 1자리 |
| EPSS | 숫자 | 소수점 3자리 |
| CVE ID | 텍스트 | — |
| 출처 | 텍스트 | — |
| 링크 | URL | — |
| PoC공개 | 체크박스 | — |
| 상태 | 선택 | `미확인` `검토완료` `블로그작성` |

**추천 뷰 구성** — DB는 만들어놓고 안 보면 의미가 없습니다. 이 3개만 만들어도 충분합니다.

- `오늘의 위협`: 필터 `수집일 = 오늘`, 정렬 `CVSS 내림차순`
- `조치 필요`: 필터 `심각도 = CRITICAL` **또는** `PoC공개 = 체크`, 그리고 `상태 = 미확인`
- `블로그 소재`: 필터 `상태 = 검토완료`

마지막 뷰가 취업 준비에 실제로 쓰이는 부분입니다. 매일 훑다가 흥미로운 항목을 `검토완료`로 바꿔두면
티스토리에 쓸 소재가 자동으로 쌓입니다.

---

## 3. 클라우드 환경 설정 ⚠️ 필수

Routine의 기본 환경은 **Trusted** 네트워크 정책이라 패키지 저장소 외의 외부 도메인이 전부 차단됩니다.
설정하지 않으면 모든 수집이 `403 host_not_allowed`로 실패합니다.

1. Routine 편집 화면에서 Instructions 아래의 환경 이름(예: **Default**)을 클릭
2. 환경 위에 마우스를 올려 나타나는 톱니바퀴 아이콘 클릭
3. **Network access** 를 `Custom` 으로 변경
4. **Allowed domains** 에 아래를 입력:

```
services.nvd.nist.gov
www.cisa.gov
api.first.org
www.boho.or.kr
asec.ahnlab.com
www.boannews.com
www.dailysecu.com
www.bleepingcomputer.com
feeds.feedburner.com
isc.sans.edu
unit42.paloaltonetworks.com
blog.talosintelligence.com
cloudblog.withgoogle.com
www.microsoft.com
googleprojectzero.blogspot.com
raw.githubusercontent.com
```

5. **Also include default list of common package managers** 를 반드시 체크 (pip 설치에 필요)
6. 저장

Notion·Gmail 커넥터는 Anthropic 서버를 경유하므로 허용목록에 넣을 필요가 없습니다.

### NVD API 키 (선택이지만 권장)

키가 없으면 30초당 5회로 제한돼 수집이 몇 분씩 걸립니다.
[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) 에서 무료로 발급받아
같은 환경 설정의 **Environment variables** 에 `NVD_API_KEY` 로 등록하세요.

> 환경변수는 해당 환경을 쓰는 모든 세션에서 보입니다. 이 용도의 키는 읽기 전용이라 문제없지만,
> 민감한 자격증명은 같은 환경에 두지 마세요.

---

## 4. Routine 생성

[claude.ai/code/routines](https://claude.ai/code/routines) → **New routine**

| 항목 | 값 |
|---|---|
| 이름 | `일일 보안 브리핑` |
| Instructions | `ROUTINE_PROMPT.md` 의 `---` 사이 내용을 붙여넣고 `{{ }}` 3곳 치환 |
| Repositories | `security-daily-brief` |
| Environment | 3번에서 설정한 환경 |
| Trigger | Schedule → **Daily**, **오전 8:00** |
| Connectors | **Notion, Gmail만 남기고 나머지 전부 제거** |

**시각을 8:00으로 잡는 이유**: 스케줄에는 몇 분의 stagger가 있고 수집·요약에 10~20분이 걸립니다.
8:00 시작이면 8:30 전후에 메일이 도착합니다. 며칠 돌려보고 실제 소요 시간에 맞춰 조정하세요.
시각은 로컬(KST) 기준으로 입력하면 자동 변환됩니다.

커넥터는 반드시 정리하세요. Routine은 포함된 커넥터의 **모든 도구를 승인 없이** 쓸 수 있습니다.
Google Drive나 Calendar를 남겨둘 이유가 없습니다.

---

## 5. 첫 실행 및 검증

**Run now** 를 눌러 즉시 테스트하세요. 스케줄을 기다리지 마세요.

실행 목록의 초록색 표시는 "세션이 오류 없이 종료됨"만 의미하고 작업 성공을 뜻하지 않습니다.
반드시 세션을 열어 실제로 무엇을 했는지 확인하세요.

체크리스트:
- [ ] `collect.py` 가 실행됐고 `errors` 배열이 비어있는가
- [ ] Notion DB에 오늘 자 행이 생겼는가
- [ ] 메일이 도착했는가
- [ ] `state/seen.json` 이 main에 푸시됐는가
- [ ] **다음 날** 실행에서 전날 항목이 반복되지 않는가 (중복 제거 검증)

로컬에서 소스 연결만 먼저 확인하려면:

```bash
pip install -r requirements.txt
python3 collect.py --validate
```

---

## 문제 해결

| 증상 | 원인 | 조치 |
|---|---|---|
| 모든 소스가 403 | 네트워크 허용목록 미설정 | 3번 재확인 |
| NVD만 타임아웃 | API 키 없이 레이트리밋 | 키 발급 또는 `window_hours` 축소 |
| 특정 RSS만 404 | 피드 주소 변경 | `--validate` 로 확인 후 `sources.yaml` 수정 |
| 매일 같은 항목 반복 | `seen.json` 푸시 실패 | 1번의 브랜치 푸시 허용 설정 |
| CVE가 하나도 없음 | NVD 분석 지연 | 정상. NVD는 CVSS 부여까지 며칠 걸림. KEV로 보완됨 |
| 항목이 너무 많음 | 임계값이 낮음 | `sources.yaml` 의 `cvss_min` 을 8.0으로 상향 |
| 항목이 너무 적음 | 수집 주기가 짧음 | `window_hours` 를 48로 |

**일일 실행 한도**가 플랜별로 있습니다. [claude.ai/settings/usage](https://claude.ai/settings/usage) 에서
남은 횟수를 확인하세요. 하루 1회 실행이라 여유는 있지만, 다른 Routine과 함께 쓴다면 감안하세요.

---

## 알아둘 한계

**NVD 분석 지연** — CVE가 공개돼도 NVD가 CVSS를 부여하기까지 며칠 걸리는 경우가 흔합니다.
이 파이프라인은 `lastModStartDate` 기준으로 조회해서 "뒤늦게 점수가 매겨진" CVE도 잡아내지만,
공개 직후의 제로데이는 놓칠 수 있습니다. 그래서 KEV와 벤더 블로그 피드가 함께 들어있습니다.

**CVSS만으로는 부족** — CVSS 9.8인데 아무도 안 쓰는 제품일 수 있고, 7.2인데 국내 금융권이
전부 쓰는 제품일 수 있습니다. EPSS와 KEV를 함께 보는 이유이고, 프롬프트에 국내 파급도
가중 규칙을 넣은 이유입니다.

**PoC 인덱스의 성격** — `nomi-sec/PoC-in-GitHub` 는 GitHub을 자동 크롤링한 미검증 인덱스입니다.
저장소 링크와 메타데이터만 가져오며 코드는 내려받지 않습니다. 공개 익스플로잇의 존재 여부는
패치 우선순위 판단에 쓰는 표준적인 신호이지만, 링크된 저장소 자체는 신뢰할 수 없습니다.
반드시 격리 환경에서만 다루세요.
