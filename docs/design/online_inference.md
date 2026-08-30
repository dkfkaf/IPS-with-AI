# AI 엔진 설계 — 온라인 추론·후속 플로우 차단

> AI 기반 인라인 IPS · C++ 센서 / Python 분석 엔진
> 선행 문서: `flow_features.md`, `ai_training.md`, `overview.md`

## 1. 목표와 범위

AI는 종료·타임아웃된 플로우를 비동기로 분석한다. 이상으로 판정된 **현재 플로우는 이미 통과했으므로 차단하지 않고** 대시보드와 로그에 탐지 이벤트를 남긴다. 센서는 그 플로우의 출발지 IP를 TTL 차단 목록에 등록해 **이후 플로우의 패킷만 DROP**한다.

Rule 기반 탐지는 패킷 경로에서 즉시 DROP한다. AI는 Rule을 자동 생성하거나 기존 Rule을 변경하지 않는다.

이 졸업작품의 범위는 방어 호스트의 IPv4 트래픽이다. `INPUT`은 Rule·차단 판정과 원격 시작
Flow의 forward 통계에 사용하고, `OUTPUT`은 그 Flow의 backward 통계 보충에만 사용해 항상
ACCEPT한다. 로컬 시작 Flow는 응답 구분을 위해 추적하지만 AI 분석 요청에는 포함하지 않는다.
IPv6, `FORWARD` 체인, 라우터·브리지 배치, TLS 복호화, 애플리케이션 계층 검사, 고가용성(HA),
다중 센서 관리와 시그니처 업데이트는 범위 밖이다. TLS 트래픽도 복호화하지 않고 플로우
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

- 화이트리스트 IP는 Rule·AI 차단 목록보다 먼저 ACCEPT하며, AI 이상 결과가 와도 TTL 차단 목록에 등록하지 않는다.
- 이미 차단된 출발지의 패킷은 플로우 통계를 갱신하지 않는다.
- IP 기반 차단이므로 NAT 뒤 여러 사용자가 같은 출발지 IP를 공유하면 정상 사용자도 영향을 받을 수 있다. 데모 환경에서는 공격자 VM의 고정 IP를 사용한다.

## 3. C++↔Python 이벤트 계약

요청과 응답은 JSON이며, 양쪽은 `schema_version`, `flow_id`, `model_version`이 맞지 않으면 해당 메시지를 거부하고 오류 이벤트를 남긴다.

```json
{
  "schema_version": 1,
  "flow_id": "<sensor-unique-id>",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "protocol": 6,
  "first_seen_ms": 0,
  "last_seen_ms": 0,
  "end_reason": "timeout",
  "feature_schema_version": 1,
  "features": [0.0],
  "model_version": "<artifact-version>"
}
```

```json
{
  "schema_version": 1,
  "flow_id": "<request-flow-id>",
  "model_version": "<artifact-version>",
  "anomaly": true,
  "score": 0.0,
  "threshold": 0.0
}
```

- `features`의 개수·순서·정규화 전 단위는 `ml/features.py`와 학습 산출물의 metadata에 따른다.
- `flow_id`는 센서가 생성하며, 응답을 원 요청과 연결하고 중복 이벤트를 막는다.
- `score`는 플로우별 복원 오차, `threshold`는 해당 모델의 판정 임계값이다.
- 센서는 `anomaly=true` 응답에서만 `src_ip`를 `block_ttl_seconds` 동안 등록한다. 이벤트에는 요청의 5-튜플과 응답의 score·threshold·모델 버전을 함께 기록한다.

## 4. 장애·과부하 정책

패킷 경로와 AI 전송 큐는 분리한다. AI가 느리거나 멈춰도 Rule 기반 패킷 verdict는 지연되지 않는다.

| 상황 | 센서 동작 | 기록 |
| --- | --- | --- |
| AI 미기동·연결 실패·응답 시간 초과 | 해당 플로우를 통과(fail-open), 차단 목록 미변경 | `AI_UNAVAILABLE` 경고 |
| JSON·버전·특징 수 검증 실패 | 해당 메시지 폐기, 차단 목록 미변경 | `AI_PROTOCOL_ERROR` 오류 |
| AI 전송 대기열 포화 | 새 AI 분석 요청을 버리고 패킷은 계속 처리 | `AI_QUEUE_FULL` 빈도 제한 경고 |
| 모델 로드 실패 | AI 프로세스는 준비 실패 상태, 센서는 Rule 모드로 계속 동작 | `AI_MODEL_ERROR` 오류 |
| 센서 재시작 | 메모리 차단 목록과 미처리 AI 요청을 폐기 | 시작·종료 이벤트 |

`AI_QUEUE_FULL`과 연결 실패 경고는 첫 발생 및 일정 간격 요약으로만 남긴다. 센서 프로세스 상태, AI 연결 상태, AI 대기열 길이, NFQUEUE 드롭/ENOBUFS 수를 대시보드 상태 지표로 표시한다.

## 5. 설정·운영 보안

`config.json`에는 AI endpoint, 응답 시간 제한, 대기열 상한, feature/model schema version, AI 차단 TTL을 추가한다. 설정 파일이 존재하지만 형식·범위 검증에 실패하면 센서를 시작하지 않는다. AI 연결 실패는 실행 중 장애이므로 fail-open을 유지한다.

센서는 root 권한으로 패킷을 다루므로 파서·JSON 입력을 신뢰하지 않는다. 모델·설정 파일은 관리자만 쓸 수 있는 권한으로 배포하고, 대시보드의 화이트리스트 변경·수동 차단 해제·설정 변경에는 인증과 감사 로그가 필요하다. 이 기능이 구현 전에는 로컬 단일 관리자 데모 전용임을 명시한다.

## 6. 검증과 결과 기록

각 실험 결과에는 다음을 함께 기록한다.

- 환경: VM CPU·메모리·NIC, OS·커널, NFQUEUE 번호·길이, IPS·모델 버전
- 입력: 공격 종류·전송률·지속시간·반복 횟수, 정상 트래픽 시나리오
- Rule: 탐지·차단률, 오탐 수, p50/p95 패킷 처리 지연, 처리량, NFQUEUE 드롭 수
- AI: 정상 test 오탐률, 공격 종류별 탐지율, 이벤트까지의 시간, 이상 출발지의 후속 플로우 차단 성공률
- 안정성: AI 중지·응답 지연·대기열 포화 시 Rule 처리 지속 여부와 fail-open 로그

AI 성능은 CICIDS2017에서 날짜·세션 단위로 분리한 test 집합으로 보고한다. 실험 시작 전에 목표 오탐률·공격별 탐지율·후속 플로우 차단 성공률·허용 처리량을 기록하고, 결과값과 함께 비교한다. 데이터·하드웨어가 확정되기 전에는 임의의 합격 수치를 주장하지 않는다.

*상용 IPS의 TLS 복호화, L7 프로토콜 검사, 시그니처·평판 피드, HA, 중앙 관리 기능은 구현하지 않는다. 발표에서는 이 문서의 범위와 한계를 함께 제시한다.*
