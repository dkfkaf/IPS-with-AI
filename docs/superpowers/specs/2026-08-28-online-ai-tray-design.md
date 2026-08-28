# 온라인 AI 판정·후속 Flow 차단·Qt 알림 설계

## 1. 이 기능을 한 문장으로 설명하면

C++ 센서가 **이미 끝난 원격 Flow의 특징**을 Python AI에 한 건씩 보내고, AI가 이상이라고
판정하면 사용자에게 알린 뒤 그 출발지의 **다음 수신 패킷부터** 기존 TTL 동안 차단한다.

현재 Flow는 판정 결과가 오기 전에 이미 끝났으므로 소급해서 막을 수 없다. 따라서 알림 문구도
"현재 Flow를 차단했다"가 아니라 "종료된 Flow에서 이상을 발견했고 이후 통신을 차단한다"라고
정확히 표현한다.

## 2. 이번 구현의 범위

이번 단계에서 구현하는 것은 다음 세 부분이다.

1. C++ 센서와 Python AI 사이의 로컬 ZeroMQ 통신
2. Python AI의 자동 실행·상태 확인·최대 3회 재시작
3. 이상 판정 후 기존 TTL 차단과 Qt5 시스템 트레이 알림

전체 대시보드, 탐지 이력 데이터베이스, 원격 관리, 다중 센서 관리는 이번 범위가 아니다.
실행 환경은 **Ubuntu VM의 root GUI 로그인 세션 한 개**로 제한한다.

## 3. 전체 동작을 쉬운 흐름으로 보면

```text
원격 사용자의 패킷
        │
        ▼
C++ Rule 검사 ── 명확한 공격 ──> 현재 패킷 즉시 DROP
        │
        └─ 통과한 패킷을 Flow로 모음
                       │
                 Flow 종료·만료
                       │
                       ▼
                 AI 대기 큐
                       │  한 건씩 전송
                       ▼
             Python 오토인코더 판정
                  │            │
                정상          이상
                  │            │
               종료       원본 IP 재확인
                               │
                화이트리스트가 아니고 아직 차단 전
                               │
                    기존 TTL로 BlockList 등록
                               │
                  트레이 알림 1회 + 로그·카운터
                               │
                    이후 수신 패킷부터 DROP
```

AI는 패킷 처리 경로 밖에 있다. AI가 느리거나 죽어도 C++ Rule 판정과 NFQUEUE verdict는
기다리지 않는다. 이것이 이 설계의 가장 중요한 안전장치다.

## 4. 왜 역할을 세 부분으로 나누는가

### 4.1 Qt 메인 스레드

다음 객체는 Qt 메인 스레드만 사용한다.

- `QApplication`
- `QSystemTrayIcon`
- Python을 실행하는 `QProcess`
- 재시작 타이머와 준비 제한시간 타이머

Qt GUI 객체는 메인 스레드에서 다뤄야 안정적이다. Python 프로세스의 시작·종료 이벤트도
`QProcess`가 Qt 이벤트 루프에 전달하므로 같은 스레드가 관리한다.

### 4.2 패킷 캡처 스레드

기존 `PacketCapture`를 별도 스레드에서 실행한다. 이 스레드만 다음 상태를 변경한다.

- NFQUEUE 패킷 수신과 ACCEPT/DROP
- `FlowManager`
- `RuleEngine`
- `Whitelist`
- `BlockList`
- iptables 관리 객체

특히 `BlockList`를 AI 스레드가 직접 수정하지 않는다. AI 결과는 결과 큐에 넣고,
`PacketCapture::on_tick()`이 약 1초마다 큐를 비우면서 실제 차단을 적용한다. 이렇게 하면
기존 패킷 상태에 복잡한 mutex를 추가하지 않아도 된다.

### 4.3 AI 통신 스레드

AI 통신 스레드는 다음만 담당한다.

- 종료 Flow를 받는 bounded 입력 큐
- ZeroMQ context와 REQ socket
- 요청 한 건 전송 후 응답 한 건 수신
- 응답 JSON 검증
- 검증된 결과를 캡처 스레드용 결과 큐에 적재

ZeroMQ socket은 스레드 안전 객체로 간주하지 않고 이 스레드 하나만 소유한다. Qt나 캡처
스레드는 socket을 직접 만지지 않는다.

### 4.4 Python 자식 프로세스

Python은 모델을 한 번 로드한 뒤 ZeroMQ REP socket으로 요청을 받는다. 요청 하나를 검증하고
추론한 뒤 반드시 응답 하나를 보낸다. C++이 순차 처리하므로 동시에 여러 Flow를 추론하지 않는다.

## 5. 시작 순서

1. `geteuid() == 0`인지 검사한다. 아니면 즉시 종료한다.
2. `config.json`과 화이트리스트를 검증한다.
3. Qt5 이벤트 루프와 트레이를 준비한다.
4. 캡처 스레드를 시작해 Rule 기반 보호를 먼저 동작시킨다.
5. AI 통신 스레드는 비활성 상태로 시작한다.
6. Qt 메인 스레드가 Python AI를 비동기로 실행한다.
7. Python이 모델 로드와 IPC bind를 마치면 준비 메시지를 stdout 한 줄로 출력한다.
8. Qt가 준비 메시지를 확인한 뒤 AI 통신 스레드를 활성화한다.

AI 상태가 `STARTING`, `RESTART_WAIT`, `OFFLINE`일 때 끝난 Flow를 미리 쌓아 두지 않는다.
`FlowConsumer::consume()`은 즉시 거부하고 `AI_UNAVAILABLE` 폐기 수만 기록한다. `ONLINE`으로
바뀐 뒤 끝나는 새 Flow부터 분석한다. 오래된 Flow가 복구 직후 한꺼번에 차단을 만드는 것을
막기 위한 정책이다.

준비 메시지 형식은 다음과 같다.

```json
{"event":"AI_READY","schema_version":1,"model_version":"ae-20260828T120000Z"}
```

Python 프로세스가 실행됐다는 사실만으로는 준비 완료가 아니다. 모델을 읽지 못했거나 IPC bind에
실패했을 수 있으므로 `AI_READY`를 받은 뒤에만 Flow 전송을 시작한다.

## 6. 프로세스 실행과 IPC 주소

Python은 shell을 거치지 않고 Qt의 program/argument 분리 기능으로 실행한다.

```text
/usr/bin/python3 -m ml.online_server
    --endpoint ipc:///tmp/ips-with-ai-<sensor-pid>.sock
    --artifact-dir <검증된 artifact_dir>
```

- `/bin/sh -c`나 문자열 명령 조립을 사용하지 않는다.
- Python runtime package는 root 소유 `/opt/ips-with-ai/python-packages`에 설치하고, 자식의
  `PYTHONPATH`를 이 경로와 root 소유 저장소 루트로만 구성한다.
- `PYTHONNOUSERSITE=1`로 일반 user site package를 읽지 않는다.
- endpoint에는 센서 PID를 넣어 이전 실행이나 다른 프로세스와 이름이 겹치지 않게 한다.
- Python은 bind 전에 `umask(077)`을 적용해 IPC 파일을 root만 사용할 수 있게 한다.
- C++과 Python socket은 `linger=0`으로 닫아 종료 시 오래 기다리지 않게 한다.
- 센서는 자신이 만든 정확한 PID 기반 socket 경로만 종료 시 정리한다.

공식 실행 위치는 저장소 루트다. 그래야 `ml` Python 모듈과 기본 `config.json`, 상대 artifact
경로를 같은 기준으로 찾을 수 있다. README의 실행 예시는 root GUI 터미널에서
`./build/ips`를 실행하는 형태로 맞춘다.

## 7. C++에서 Python으로 보내는 요청

Flow ID는 현재 센서 인스턴스 ID와 증가 번호를 결합해 한 실행 안에서 중복되지 않게 한다.

```json
{
  "schema_version": 1,
  "flow_id": "1770000000000000-42",
  "src_ip": "192.0.2.10",
  "src_port": 50123,
  "dst_ip": "198.51.100.20",
  "dst_port": 443,
  "protocol": 6,
  "first_seen_ms": 1770000000000,
  "last_seen_ms": 1770000002500,
  "end_reason": "timeout",
  "feature_schema_version": 1,
  "features": [2500000.0, 12.0, 10.0]
}
```

실제 `features` 배열은 27개다. 위 예시는 읽기 쉽게 일부만 표시했다.

- IP는 사람이 읽을 수 있는 IPv4 문자열로 보낸다.
- protocol은 TCP 6, UDP 17처럼 IP protocol 번호를 쓴다.
- `first_seen_ms`와 `last_seen_ms`는 Unix epoch millisecond다.
- `end_reason`은 기존 C++ 변환값인 `tcp_fin`, `tcp_reset`, `timeout` 중 하나다.
- 특징은 학습 전 원래 단위이며 Python이 저장된 scaler로 정규화한다.

## 8. Python에서 C++로 보내는 응답

정상적으로 판정한 응답은 다음 형식이다.

```json
{
  "schema_version": 1,
  "flow_id": "1770000000000000-42",
  "model_version": "ae-20260828T120000Z",
  "ok": true,
  "anomaly": true,
  "score": 0.0371,
  "threshold": 0.0125
}
```

요청 내용이 잘못됐으면 Python 프로세스를 죽이지 않고 오류 응답을 돌려준다.

```json
{
  "schema_version": 1,
  "flow_id": "1770000000000000-42",
  "model_version": "ae-20260828T120000Z",
  "ok": false,
  "error_code": "FEATURE_SCHEMA_MISMATCH"
}
```

C++은 다음 조건을 모두 만족한 성공 응답만 사용한다.

- JSON object이고 필수 필드의 타입이 맞음
- `schema_version == 1`
- 응답 `flow_id`가 현재 기다리는 요청과 같음
- 응답 `model_version`이 `AI_READY`에서 받은 값과 같음
- `score`와 `threshold`가 NaN·Inf가 아닌 유한한 음이 아닌 수
- `anomaly`가 boolean

응답에 출발지 IP를 넣지 않는다. 공격자가 Python 응답을 속이거나 구현 실수로 다른 IP가 섞이는
위험을 줄이기 위해, 차단 대상은 C++이 보관한 원본 `FlowRecord`에서만 가져온다.

## 9. Python 온라인 추론

시작 시 다음 세 파일을 한 번만 읽는다.

| 파일 | 내용 |
| --- | --- |
| `autoencoder.pt` | 학습된 오토인코더 가중치 |
| `scaler.npz` | 정상 학습 데이터의 평균과 scale |
| `metadata.json` | 임계값, 특징 목록, 특징·모델 버전 |

학습 코드는 metadata에 다음 두 값을 추가한다.

- `feature_schema_version`: C++ 특징 계약 버전, 현재 값 1
- `model_version`: 재학습마다 바뀌는 UTC 기반 문자열, 예: `ae-20260828T120000Z`

서버는 PyTorch 2.1 이상에서 모델을 `map_location="cpu"`, `weights_only=True`로 읽고 `eval()`
상태로 둔다. 각 요청은
다음 순서로 처리한다.

1. 요청 JSON과 필수 필드를 검증한다.
2. 특징 버전이 metadata와 같은지 확인한다.
3. 특징 개수와 순서가 학습 계약 27개와 같은지 확인한다.
4. 모든 특징값이 유한한 숫자인지 확인한다.
5. `(features - mean) / scale`로 학습 때와 똑같이 정규화한다.
6. `torch.no_grad()`에서 모델 복원값을 구한다.
7. 입력과 복원값의 평균제곱오차(MSE)를 score로 계산한다.
8. `score > threshold`이면 이상으로 응답한다.

모델 로드 시에는 특징 목록이 `ml/features.py`의 `FEATURES`와 정확히 같은지, `n_features`, mean,
scale의 길이가 27인지, scale이 0보다 큰지, threshold가 유한한 음이 아닌 수인지 확인한다.
하나라도 맞지 않으면 `AI_READY`를 출력하지 않고 오류 종료한다.

## 10. 이상 결과를 실제 차단으로 바꾸는 방법

AI 통신 스레드는 이상 결과를 받더라도 직접 차단하지 않는다. 다음 정보를 `AiDecision` 결과 큐에
넣는다.

- 원본 Flow ID와 원본 출발지 IP
- 원본 5-tuple
- score와 threshold
- model version
- 이상 여부

캡처 스레드가 결과 큐를 비울 때 다음 순서로 처리한다.

1. 정상 결과이면 카운터만 올리고 끝낸다.
2. 출발지 IP가 현재 화이트리스트인지 다시 확인한다.
3. 이미 BlockList에 있다면 `duplicate`로 기록하고 팝업을 띄우지 않는다.
4. 그 출발지의 활성 Flow를 폐기한다.
5. 기존 전역 `block_ttl_seconds`로 BlockList에 등록한다.
6. 차단 성공 이벤트를 Qt 메인 스레드에 queued 방식으로 전달한다.

Rule과 AI는 별도의 TTL을 두지 않고 기존 `block_ttl_seconds`를 공유한다. AI 판정이 늦는 동안 새
Flow가 이미 시작됐더라도 BlockList 등록 뒤 들어오는 다음 수신 패킷부터 DROP된다. outbound는 기존
설계대로 절대 DROP하지 않는다.

## 11. Qt5 시스템 트레이

이번 Qt 범위는 전체 대시보드가 아니라 작은 상태 표시와 알림뿐이다.

### 11.1 아이콘 상태

| 색 | 뜻 |
| --- | --- |
| 회색 | 시작 중 또는 종료 중 |
| 초록색 | AI까지 정상 동작 중 |
| 노란색 | Rule은 동작하지만 AI는 사용 불가 |

색 원형 아이콘은 Qt 코드에서 그려 별도 이미지 파일을 요구하지 않게 한다.

### 11.2 이상 알림

최초 차단 시 `QSystemTrayIcon::showMessage()`로 다음 정보를 보여준다.

```text
AI 이상 Flow 탐지
192.0.2.10의 종료된 Flow를 이상으로 판정했습니다.
이후 수신 패킷을 600초 동안 차단합니다.
score=0.0371, threshold=0.0125
```

같은 출발지 IP가 TTL 안에 다시 이상으로 판정되면 팝업을 반복하지 않는다. 로그와 duplicate
카운터만 증가시킨다. TTL이 끝난 뒤 새 이상 판정으로 다시 차단되면 새 팝업을 한 번 표시한다.

### 11.3 메뉴

트레이 메뉴는 두 항목만 제공한다.

- `상태 보기`: AI 상태, 모델 버전, 가동 시간, 재시작 횟수와 주요 누계를 작은 창에 표시
- `종료`: 정상 종료 절차 시작

시스템 트레이 기능을 사용할 수 없으면 오류 로그를 남기되 캡처와 AI는 계속 동작한다. 단,
Qt platform이나 GUI 세션 자체가 없어 `QApplication`을 만들 수 없는 headless 환경은 지원하지 않는다.

## 12. 과부하 처리

기본 AI 입력 큐 크기는 1024건이다. `FlowConsumer::consume()`은 큐에 즉시 넣을 수 있을 때만
`true`를 반환하고 절대 AI 응답을 기다리지 않는다.

- 빈 공간이 있으면 새 Flow를 큐 뒤에 넣는다.
- 큐가 가득 차면 새 Flow를 폐기한다.
- `AI_QUEUE_FULL`은 첫 발생과 이후 60초마다 누적 폐기 수를 요약한다.
- 패킷 ACCEPT/DROP과 Rule 판정에는 영향을 주지 않는다.

검증된 AI 결과 큐도 같은 상한을 사용한다. 결과 큐가 가득 차면 이미 계산한 판정을 버리지 않고
AI 통신 스레드가 다음 요청 전송을 잠시 멈춘다. 그동안 입력 큐가 차면 새 Flow가 폐기된다. 따라서
패킷 스레드는 막지 않으면서 이미 받은 이상 판정은 보존한다.

Python에는 한 번에 한 Flow만 보낸다. 응답을 받은 뒤 다음 Flow를 보낸다. 이 방식은 처리량은
낮지만 요청과 응답이 뒤섞이지 않아 졸업작품 범위에서 가장 이해하고 검증하기 쉽다.

## 13. 응답 정지와 자동 재시작

기본 시작 제한시간은 10초, 한 요청의 응답 제한시간은 2초다.

다음 상황은 AI 프로세스 실패로 본다.

- 10초 안에 올바른 `AI_READY`가 오지 않음
- Python 프로세스가 예기치 않게 종료됨
- 요청 후 2초 안에 응답이 오지 않음
- ZeroMQ 송수신에서 복구 불가능한 오류가 발생함

실패 처리 순서는 다음과 같다.

1. 처리 중인 Flow와 입력·결과 큐를 모두 폐기한다.
2. AI 통신 스레드가 자기 REQ socket을 닫아 상태를 초기화한다.
3. Qt가 남은 Python 프로세스를 종료한다.
4. 1초, 2초, 4초 뒤에 차례로 최대 3회 재시작한다.
5. 세 번 모두 실패하면 더 이상 자동 재시작하지 않고 Rule-only로 계속 실행한다.
6. 트레이가 있으면 `AI 오프라인`을 한 번 알리고 아이콘을 노란색으로 바꾼다.

여기서 "3회"는 최초 실행 뒤 가능한 **재시작 횟수**다. AI가 60초 동안 중단 없이 정상 동작하면
연속 실패 횟수를 0으로 되돌린다. 이후 다시 장애가 나면 최대 3회 재시작 기회를 새로 가진다.

메시지 한 건의 JSON 형식이나 특징 버전만 잘못된 경우에는 프로세스 전체를 재시작하지 않는다.
해당 Flow만 폐기하고 protocol error 카운터를 올린다.

## 14. 설정

기존 `config.json`에 `ai` object를 추가한다.

```json
{
  "block_ttl_seconds": 600,
  "ai": {
    "enabled": true,
    "artifact_dir": "ml/artifacts",
    "queue_capacity": 1024,
    "startup_timeout_ms": 10000,
    "response_timeout_ms": 2000,
    "max_restarts": 3,
    "restart_reset_seconds": 60
  }
}
```

- `enabled=false`이면 Python을 실행하지 않고 Rule-only로 동작한다.
- AI endpoint는 PID로 자동 생성하므로 사용자가 설정하지 않는다.
- Python executable은 `/usr/bin/python3`로 고정해 root 프로세스가 임의 실행 파일을 실행하지 않게 한다.
- AI 차단 TTL은 따로 만들지 않고 최상위 `block_ttl_seconds`를 사용한다.
- 설정 파일이 없으면 위 기본값을 사용한다.
- 설정 파일이 있지만 타입이나 범위가 잘못됐으면 기존 정책처럼 프로그램 시작을 중단한다.

권장 검증 범위는 다음과 같다.

| 설정 | 허용 범위 |
| --- | --- |
| `queue_capacity` | 1~65536 |
| `startup_timeout_ms` | 1000~60000 |
| `response_timeout_ms` | 100~60000 |
| `max_restarts` | 0~10 |
| `restart_reset_seconds` | 1~3600 |

`artifact_dir`은 비어 있지 않아야 하며 시작 시 canonical path로 바꾼다. 모델이 없거나 호환되지
않는 것은 설정 문법 오류가 아니라 AI 실행 장애이므로 센서는 Rule-only로 계속 동작한다.

## 15. root 실행 보안 경계

이 구현은 일반 사용자 실행을 지원하지 않는다. 프로그램은 실행 직후 effective UID가 0인지
확인한다. root GUI로 직접 로그인했는지, `sudo`를 거쳤는지는 구분하지 않지만 공식 데모 환경은
root GUI 로그인이다. Python 자식도 같은 root 권한을 상속한다.

root가 Python과 모델을 읽으므로 다음 방어를 적용한다.

- shell을 사용하지 않고 `/usr/bin/python3`를 절대 경로로 실행
- Python package는 root만 수정할 수 있는 `/opt/ips-with-ai/python-packages`에서 로드
- artifact 경로 밖의 파일을 모델로 선택할 수 없게 고정된 파일 이름 사용
- 모델·scaler·metadata가 일반 파일인지 검사
- group/other write가 가능한 artifact는 거부하고 배포 문서에 root 소유 권한을 명시
- PyTorch 가중치는 `weights_only=True`로 로드
- 외부 네트워크 TCP가 아닌 로컬 IPC만 사용
- IPC 권한은 root 전용으로 제한

이 설계는 로컬 root 프로세스 자체가 침해된 상황까지 방어하지 않는다.

## 16. 로그와 상태 카운터

기본 로그에는 전체 특징 배열을 남기지 않는다. 용량과 민감 정보를 줄이고 필요한 상관관계만
남긴다.

AI 판정·차단 로그의 공통 필드는 다음과 같다.

```text
flow_id=<id> source_ip=<ip> score=<n> threshold=<n>
action=<normal|blocked|duplicate|whitelisted|discarded>
model_version=<version>
```

상태 화면에는 다음 누계를 표시한다.

- AI 전송 성공 수
- 큐 포화 폐기 수
- 정상 응답 수
- 이상 응답 수
- AI 신규 차단 수
- TTL 내 중복 이상 수
- protocol error와 timeout 수
- Python 재시작 수
- 현재 AI 상태와 모델 버전
- 센서 가동 시간

Rule 차단 수와 AI 차단 수는 반드시 별도로 집계한다. 그래야 발표에서 어떤 탐지기가 실제 차단을
만들었는지 설명할 수 있다.

## 17. 안전한 종료

트레이 `종료`, `SIGINT`, `SIGTERM`은 같은 종료 경로를 사용한다. POSIX signal handler 안에서는
Qt 함수나 로깅을 호출하지 않고 `sig_atomic_t` 플래그만 세운다. Qt timer가 이 플래그를 확인해
종료를 시작한다.

1. 상태를 `STOPPING`으로 바꾸고 새 UI 동작을 막는다.
2. 캡처에 stop을 요청해 새 패킷 상태 갱신을 멈춘다.
3. AI 통신 스레드에 stop을 요청하고 큐를 비운다.
4. Python에 terminate를 요청하고 2초 뒤에도 살아 있으면 kill한다.
5. 캡처 루프가 빠져나오면서 NFQUEUE와 관리 iptables 규칙을 정리한다.
6. 캡처·AI 스레드를 join한다.
7. PID 기반 IPC 파일을 정리하고 Qt 이벤트 루프를 끝낸다.

캡처 스레드가 NFQUEUE 오류로 먼저 끝나면 AI만 남겨 두지 않는다. Qt에 치명 오류를 전달하고 같은
정상 종료 절차를 실행한다.

## 18. 예상 변경 위치

구현 계획에서 세부 파일명은 조정할 수 있지만 책임은 다음처럼 나눈다.

| 위치 | 책임 |
| --- | --- |
| `src/ai/` | bounded 큐, ZeroMQ 요청·응답, `AiDecision`, AI 통계 |
| `src/capture/packet_capture.*` | 결과 큐 drain, 화이트리스트 재검사, TTL 차단 |
| `src/app/` | Qt 애플리케이션 수명과 Python 프로세스 감독 |
| `src/ui/` | 트레이 아이콘·알림·상태 보기 |
| `src/config/` | `ai` 설정 파싱·범위 검증 |
| `ml/online_server.py` | artifact 로드, REP 서버, 온라인 추론 |
| `ml/train.py` | 특징·모델 버전 metadata 저장 |
| `CMakeLists.txt` | Qt5, libzmq, cppzmq 및 새 소스 연결 |
| `README.md` | Ubuntu 의존성, root GUI 실행, 수동 확인 방법 |

필요한 Ubuntu 패키지는 최소한 `qtbase5-dev`, `libzmq3-dev`, `cppzmq-dev`, `python3-pip`이다.
온라인 Python runtime은 `torch>=2.1`, `numpy`, `pyzmq`를 별도 requirements로 고정한다.

## 19. 완료 판정용 수동 검증

이번 구현 중에는 새 GTest나 자동 통합 테스트를 작성하지 않는다. 전체 기능이 완성된 뒤 테스트
코드를 한 번에 작성한다. 이번 단계에서는 Ubuntu VM에서 아래 증거를 직접 남긴다.

1. root GUI에서 센서를 실행하면 iptables가 등록되고 Python이 자동 실행된다.
2. `AI_READY` 뒤 트레이가 초록색이고 상태 화면에 모델 버전이 나온다.
3. 정상 Flow는 차단이나 팝업 없이 정상 카운터만 증가한다.
4. 이상 Flow는 현재 Flow 탐지 알림을 한 번 표시하고 같은 IP의 이후 수신 패킷을 DROP한다.
5. 같은 IP의 TTL 내 중복 이상은 새 팝업 없이 duplicate만 증가한다.
6. TTL이 끝나면 해당 IP가 다시 통과하고, 새 이상 판정이면 다시 한 번 알림한다.
7. 화이트리스트 IP의 늦게 도착한 이상 응답은 차단하지 않는다.
8. Python을 강제 종료하면 처리 중·대기 Flow가 사라지고 1·2·4초 뒤 재시작한다.
9. 세 번 연속 실패하면 노란 아이콘의 Rule-only 상태가 되고 Rule 차단은 계속된다.
10. 2초 응답 정지, 잘못된 JSON, ID 불일치, 큐 포화가 패킷 verdict를 멈추지 않는다.
11. 트레이 종료와 SIGINT/SIGTERM 모두 Python·스레드·iptables·IPC를 정리한다.

Windows 개발 호스트에는 NFQUEUE와 Ubuntu Qt 실행 환경이 없으므로 Windows 정적 검토만으로 위
통합 검증을 통과했다고 주장하지 않는다.

## 20. 명시적으로 하지 않는 것

- AI 결과로 이미 끝난 현재 Flow를 소급 차단
- AI가 Rule을 자동 생성하거나 수정
- 전체 Qt 대시보드와 장기 이력 저장
- 일반 사용자, headless 서버, 여러 로그인 세션 지원
- 센서 다중 인스턴스
- TCP endpoint, 원격 AI 서버, TLS·인증
- IPv6, `FORWARD`, 라우터·브리지 배치
- L7 payload 검사나 TLS 복호화
- GTest와 자동 통합 테스트 작성

이 범위는 상용 IPS 전체를 흉내 내려는 것이 아니라, 졸업작품의 핵심인 **Rule 즉시 차단 + AI 이상
탐지 + 후속 Flow 차단 + 사용자 알림**을 안전하게 연결하는 데 집중한다.
