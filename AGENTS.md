# security-daily-brief

국내·해외 보안 이슈를 매일 아침 수집해 Notion에 기록하고 메일로 알리는 파이프라인.
Claude Code Routine이 하루 한 번 자율 실행한다.

## 구조

- `collect.py` — 수집기. 판단 없이 데이터만 모은다. LLM 호출 없음, 결정론적.
- `sources.yaml` — 피드·API·임계값 설정. 소스 변경은 여기서만.
- `state/seen.json` — 중복 제거 상태. 매 실행 후 main에 커밋되어야 한다.
- `out/brief-YYYY-MM-DD.json` — 수집 결과. Routine이 이걸 읽어 요약한다.
- `ROUTINE_PROMPT.md` — Routine에 등록할 프롬프트 원본.

## 설계 원칙

**수집과 판단을 분리한다.** 수집 단계에 LLM 판단이 끼면 같은 입력에 다른 결과가 나와
재현과 디버깅이 불가능해진다. `collect.py`는 순수 수집만, 요약·분류·번역은 Routine이 맡는다.

**임계값은 코드가 아니라 설정에 둔다.** CVSS 기준을 바꾸려면 `sources.yaml`만 고친다.

**실패는 조용히 넘기지 않는다.** priority 1 소스(안랩 ASEC, KISA)가 실패하면
`errors` 배열에 `fatal: true`로 기록되고, Routine이 이를 브리핑에 명시한다.

## 수정할 때

- 피드 추가: `sources.yaml`의 `feeds_kr` 또는 `feeds_global`에 항목 추가 후 `--validate` 실행
- 새 API 소스 추가: `collect_*` 함수 패턴을 따르고, 반드시 예외를 `record_error`로 잡을 것.
  하나의 소스 실패가 전체 수집을 중단시키면 안 된다.
- 출력 스키마 변경 시 `ROUTINE_PROMPT.md`의 필드 참조도 함께 수정할 것

## 하지 말 것

- 익스플로잇 코드를 작성하거나 저장하지 않는다. PoC는 링크와 메타데이터만 다룬다.
- NVD 레이트리밋을 우회하지 않는다. `time.sleep` 값을 줄이면 차단된다.
- `state/seen.json`을 임의로 삭제하지 않는다. 지우면 과거 항목이 전부 재알림된다.
