# AI 엔진 설계 — 온라인 추론·판정 이후 수신 패킷 차단

> AI 기반 인라인 IPS · C++ 센서 / Python 분석 엔진
> 선행 문서: `flow_features.md`, `ai_training.md`, `overview.md`

> 이 문서는 현재 schema 1·IPv4 구현의 기준이다. 앞으로의 DNS·HTTP·TLS·IPv6 범위는
> [확장 설계](../superpowers/specs/2026-09-01-suricata-inspired-expansion-design.md),
> 차단·관찰 정책은 [핵심 정책 보완](../superpowers/specs/2026-09-12-core-policy-clarification-design.md)을 따른다.

## 1. 목표와 범위

AI는 종료·타임아웃된 플로우를 비동기로 분석한다. **이미 전달된 패킷은 소급 차단하지 못한다.** 센서는 이상 판정을 적용할 때 그 플로우의 출발지 IP를 기존 `block_ttl_seconds` 차단 목록에 등록하고 Qt 트레이와 로그에 알린다. **적용 이후 그 IP의 수신 패킷은 새 연결·기존 연결을 구분하지 않고 DROP**한다. 통계 타임아웃이 실제 연결 종료를 보장하지는 않는다.

Rule 기반 탐지는 패킷 경로에서 즉시 DROP한다. AI는 Rule을 자동 생성하거나 기존 Rule을 변경하지 않는다.

현재 구현의 범위는 방어 호스트의 IPv4 트래픽이다. `INPUT`은 Rule·차단 판정과 원격 시작
Flow의 forward 통계에 사용하고, `OUTPUT`은 그 Flow의 backward 통계 보충에만 사용해 항상
ACCEPT한다. 로컬 시작 Flow는 응답 구분을 위해 추적하지만 AI 분석 요청에는 포함하지 않는다.
IPv6, `FORWARD` 체인, 라우터·브리지 배치, TLS 복호화, 애플리케이션 계층 검사, 고가용성(HA),
다중 센서 관리와 시그니처 업데이트는 현재 구현에 없다. TLS 트래픽도 복호화하지 않고 플로우
메타데이터만 분석한다.

## 2. 처리 흐름

```
패킷 수신 → Rule 검사 → 즉시 ACCEPT/DROP
                    │
플로우 타임아웃 ────┘ → 특징 벡터 전송 → AI 판정
                                           │
                    정상 ──────────────────┴→ 이벤트 없음
                    이상 → 탐지 이벤트 기록·표시 → src_ip TTL 등록
                                                        │
                                           이후 src_ip 패킷 DROP
```

- 현재 화이트리스트 IP는 Rule·AI 차단 목록보다 먼저 ACCEPT하고 Flow 관찰도 생략한다. AI 이상 결과가 와도 TTL 차단 목록에 등록하지 않는다. 확장안의 ‘L7 관찰은 유지하고 차단만 면제’는 아직 미구현이다.
- 이미 차단된 출발지의 패킷은 플로우 통계를 갱신하지 않는다.
- IP 기반 차단이므로 NAT 뒤 여러 사용자가 같은 출발지 IP를 공유하면 정상 사용자도 영향을 받을 수 있다. 데모 환경에서는 공격자 VM의 고정 IP를 사용한다.

## 3. C++↔Python 이벤트 계약

요청과 응답은 JSON schema version 1이다. 전체 필드·타입·오류 코드의 단일 기준은
[`2026-08-28-online-ai-tray-design.md`](../superpowers/specs/2026-08-28-online-ai-tray-design.md)의
7~9장이다. 구현은 다음 안전 조건을 지킨다.

- 요청은 C++이 만든 `flow_id`, IPv4 5-튜플, 시작·종료 시각, 종료 이유, 특징 schema와 27개 특징을 담는다.
- Python은 `AI_READY`에서 알린 `model_version`을 모든 응답에 넣는다.
- C++은 schema·`flow_id`·`model_version`·필드 타입·유한한 score/threshold가 모두 맞는 성공 응답만 사용한다.
- 응답에는 차단 IP를 넣지 않는다. 차단 대상은 C++이 보관한 원본 `FlowRecord`의 출발지에서만 가져온다.
- `ok=false` 요청 오류나 검증 실패는 차단하지 않고 `AI_PROTOCOL_ERROR`로 기록한다.

## 4. 장애·과부하 정책

패킷 경로와 AI 전송 큐는 분리한다. AI가 느리거나 멈춰도 Rule 기반 패킷 verdict는 지연되지 않는다.

| 상황 | 센서 동작 | 기록 |
| --- | --- | --- |
| AI 시작 중·미기동 | 새 AI 차단 없이 Rule·기존 TTL 차단 지속 | `AI_UNAVAILABLE` 빈도 제한 경고 |
| AI 연결 실패·전송과 응답 합산 2초 시간 초과 | 처리 중·입력·결과 큐 폐기, Python 재시작 | timeout·재시작 상태 |
| JSON·버전·특징 수 검증 실패 | 해당 메시지 폐기, 차단 목록 미변경 | `AI_PROTOCOL_ERROR` 오류 |
| AI 전송 대기열 포화 | 새 AI 분석 요청을 버리고 패킷은 계속 처리 | `AI_QUEUE_FULL` 빈도 제한 경고 |
| 모델 로드 실패 | `AI_READY` 전 종료, 자동 재시작 후 Rule-only 지속 | Python stderr·재시작 상태 |
| 센서 재시작 | 메모리 차단 목록과 미처리 AI 요청을 폐기 | 시작·종료 이벤트 |

입력·결과 큐는 기본 1024건으로 제한한다. 입력 큐가 차면 새 Flow만 버리고, 결과 큐가 차면 AI
통신 스레드만 기다린다. `AI_QUEUE_FULL`과 `AI_UNAVAILABLE`은 첫 발생과 이후 60초마다 누계를
요약한다.

센서는 `QProcess`로 `/usr/bin/python3 -m ml.online_server`를 자동 실행한다. endpoint는
`ipc:///tmp/ips-with-ai-<sensor-pid>.sock`으로 자동 생성해 사용자가 설정하지 않는다. 시작 또는 통신
실패 시 1·2·4초 뒤 최대 3회 재시작하고, 60초 동안 안정적으로 ONLINE이면 연속 실패 횟수를
초기화한다. 재시작을 모두 소진하면 노란 트레이와 `AI 오프라인` 알림을 표시하지만 Rule 차단은
계속한다.

여기의 fail-open은 AI 실패로 새 차단을 만들지 않는다는 뜻이다. `--queue-bypass`는 NFQUEUE
listener 부재에만 대응하며, 현재 미설정인 `NFQA_CFG_F_FAIL_OPEN`과 다르다. 따라서 커널 큐
포화 시 기본 DROP·센서 정지 시 지연 가능성까지 없애 주지는 않는다. 상황별 동작과 공식 근거는
[핵심 정책 보완 6장](../superpowers/specs/2026-09-12-core-policy-clarification-design.md)에 정리한다.

## 5. 설정·운영 보안

`config.json`의 `ai` object는 활성화 여부, artifact 경로, 큐 상한, 시작·응답 제한시간, 재시작
상한과 안정화 시간을 설정한다. endpoint·schema version·AI 전용 TTL은 설정하지 않는다. Rule과 AI는
최상위 `block_ttl_seconds`를 공유한다. 형식·범위 검증에 실패하면 시작하지 않는다.

센서는 root GUI 계정에서만 실행한다. Python도 같은 root 권한이므로 저장소 루트와 `ml/`,
`/opt/ips-with-ai/python-packages`, artifact 경로는 root 소유로 두고 group/other 쓰기 권한을
제거한다. 센서는 Python 실행 전에 코드·runtime 경로를 확인하고 최소 환경변수만 넘긴다. 온라인
loader는 artifact 디렉터리와 고정된 세 파일의 소유권·권한·파일 종류를 확인하며 symbolic link와
경로 이탈을 거부한다. 이후 특징·모델 version과 수치 범위를 검사하고 `weights_only=True`, CPU,
eval 모드로 읽는다.

Qt5 UI 범위는 트레이 상태 아이콘, 신규 AI 차단 알림, 최종 AI 오프라인 알림, 읽기 전용 누적 상태,
종료뿐이다. 원격 관리, 설정 변경, 차단 해제, 이벤트 이력 대시보드는 구현 범위 밖이다.

## 6. 검증과 결과 기록

각 실험 결과에는 다음을 함께 기록한다.

- 환경: VM CPU·메모리·NIC, OS·커널, NFQUEUE 번호·길이, IPS·모델 버전
- 입력: 공격 종류·전송률·지속시간·반복 횟수, 정상 트래픽 시나리오
- Rule: 탐지·차단률, 오탐 수, p50/p95 패킷 처리 지연, 처리량, NFQUEUE 드롭 수
- AI: 정상 test 오탐률, 공격 종류별 탐지율, 이벤트까지의 시간, 판정 적용 이후 출발지 IP 수신 차단 성공률
- 안정성: AI 중지·응답 지연·대기열 포화 시 Rule 처리 지속 여부와 fail-open 로그

최종 AI 성능 보고에는 날짜·세션 단위로 분리한 test 집합이 필요하다. 다만 현재 `ml/preprocess.py`의
`split_benign`은 정상 행을 난수로 섞어 나누므로 이 조건을 충족했다고 볼 수 없다. 분할 manifest와
누수 검증은 다음 안정화 작업에서 구현·확인한다. 실험 시작 전에 목표 오탐률·공격별 탐지율·수신
차단 성공률·허용 처리량을 기록하고 결과와 비교한다. 검증 전 임의의 합격 수치를 주장하지 않는다.

*현재 기능과 확장 목표는 구분한다. DNS·HTTP·TLS metadata·로컬 데이터셋 검사는 확장 설계 대상이며,
TLS 복호화·HA·중앙 관리를 구현한다는 뜻은 아니다.*
