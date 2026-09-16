# Suricata 장점을 반영한 AI IPS 확장 설계

> 상태: 확장 설계이며 구현 완료 목록이 아니다. 2026-09-12의
> [핵심 정책 보완](2026-09-12-core-policy-clarification-design.md)을 함께 적용한다.

## 1. 이 문서의 목적

현재 프로젝트는 IPv4 TCP·UDP 패킷을 NFQUEUE로 받아 포트 스캔·SYN Flood Rule을 즉시
적용하고, 제출 조건을 충족한 종료 Flow는 AI로 분석한다. 이상 판정 적용 이후 해당 출발지 IP의
수신 패킷을 TTL 동안 차단한다. 새 연결뿐 아니라 기존 연결도 영향받으며, 이미 통과한 패킷을
소급 차단하지는 않는다.

이번 확장은 Suricata를 복제하는 작업이 아니다. 현재 AI IPS를 유지하면서 실제 활용성과 발표
가치가 큰 기능을 안전한 순서로 추가한다. 구현 완료 기능과 장기 목표를 명확히 구분하며, 각
단계는 독립적으로 실행·검증할 수 있어야 한다.

## 2. 최종 범위

### 2.1 졸업작품 구현 범위

1. 현재 ML 코드와 VM 동작 기준선 안정화
2. PCAP 재생을 이용한 반복 가능한 패킷 테스트
3. DNS 파싱과 악성 IP/CIDR·도메인 데이터셋 탐지
4. 공통 보안 이벤트와 EVE 형식 JSON Lines 기록
5. 확장 가능한 Rule 모델과 `threshold`, `flowbits`
6. `alert`, `drop`, `pass` 대응
7. 기존 설정 파일을 원본으로 사용하는 root 전용 상태 조회·재로드 소켓
8. 메모리 상한이 있는 TCP 스트림 재조립
9. HTTP/1과 복호화 없는 TLS 메타데이터 분석
10. HTTP 파일의 스트리밍 SHA-256 검사
11. IPv6 Rule·로그·차단 기반
12. DNS·HTTP·TLS 관찰 자료의 버전 계약과 AI 학습 데이터 수집 기반

### 2.2 장기 확장 범위

- HTTP/2
- FTP, SMTP, IMAP, SSH, SMB
- Modbus, DNP3, IKE
- 문자열 데이터셋과 더 넓은 앱 계층 Rule
- `reject`, syslog, fast.log
- 텍스트 Rule DSL
- 검증된 별도 데이터셋을 사용하는 DNS·HTTP·TLS 전용 AI 모델

### 2.3 구현하지 않는 기능

- 패킷 콘텐츠를 바꾸는 `replace`
- GeoIP·국가·ASN 기반 차단
- MD5 기반 신규 판정
- 네트워크 TCP 관리 포트
- 다중 테넌트
- TLS 복호화와 인증서 중간자 기능
- 기본 원본 파일 보관
- Suricata Rule 문법 전체 호환

## 3. 설계 원칙

### 3.1 현재 패킷 경로를 지킨다

Rule과 기존 차단 목록은 패킷 경로에서 즉시 판정한다. AI, 로그 파일 기록, 데이터셋 재로드처럼
느릴 수 있는 작업은 패킷 처리 스레드를 기다리게 하지 않는다.

### 3.2 실패 범위를 작게 제한한다

- 앱 파싱 실패: 해당 앱 분석만 중단하고 L3/L4 Rule과 기존 차단은 계속한다.
- 로그 실패: 패킷 처리는 계속하고 로그 손실 카운터를 올린다.
- 재로드 실패: 기존 정상 정책을 그대로 유지한다.
- AI 실패: 기존 Rule-only 모드로 계속한다.
- 자원 상한 초과: 새 상태 생성을 거부하고 정해진 이벤트를 남긴다.

파싱 실패를 이유로 자동 DROP하지 않는다. 명시적인 decoder/anomaly Rule이 있을 때만 차단한다.

### 3.3 읽기 전용 정책을 한 번에 교체한다

Rule, 설정, 데이터셋은 새 객체에 전부 읽고 검증한다. 성공한 객체만 실행 중 정책과 한 번에
교체한다. 패킷 스레드는 완성된 읽기 전용 정책만 참조한다.

### 3.4 지원한다는 말에는 검증이 포함된다

프로토콜 이름만 식별하는 것은 지원 완료가 아니다. 정상 입력, 잘린 입력, 순서 변경, 중복,
상한 초과와 알려진 우회 형태를 자동 테스트해야 해당 기능을 지원한다고 표시한다.

### 3.5 관찰·AI 분석·실제 차단은 별개다

확장 권장 정책은 다음과 같다. 현재 코드에 적용된 것으로 해석하지 않는다.

- 로컬 시작 Flow도 L7 관찰 대상으로 삼지만, 기존 27개 특징 모델에는 보내지 않는다.
  시작 방향까지 검증된 프로토콜 모델이 있을 때만 분석하고 AI 이상은 알림만 제공한다.
- 화이트리스트는 실제 차단을 면제한다. 새 L7 관찰·적중 기록과 호환 프로토콜 AI 분석까지
  생략하지 않는다. 기존 포트 스캔·SYN Flood와 기존 Flow AI의 제외 조건은 유지한다.
- DNS 구현 전에 128바이트 복사 한계를 보완하고, payload 길이·잘림·소유권 계약을 마련한다.
- AI fail-open과 커널 NFQUEUE 포화 동작은 다르다. 현재 `--queue-bypass`만으로 큐 포화 시
  통과를 보장하지 않는다.

정확한 대상·예외·캡처 실패 처리는 [핵심 정책 보완](2026-09-12-core-policy-clarification-design.md)의
2~7장을 따른다.

## 4. 전체 구조

```text
NFQUEUE 또는 PCAP
        │
        ▼
L3/L4 Decoder ────── decoder event
        │
        ├── Flow/Host 상태 ── threshold·flowbits
        │
        ├── UDP DNS Parser ── IP·도메인 Dataset
        │
        └── TCP Reassembly
                 │
                 ├── HTTP/TLS Parser
                 └── HTTP File Hasher ── SHA-256 Dataset
        │
        ▼
Compiled Rule Engine
        │
        ├── pass
        ├── drop
        └── alert
        │
        ├── AI Router ── 기존 Flow 모델
        │             └── 선택적 DNS·HTTP·TLS 모델
        │                    └── 이상 알림·후속 IP 차단
        └── bounded Event Queue ── EVE JSON Writer

config/rules/datasets 파일
        │
        └── Unix command socket의 reload 요청
                 │
                 └── 새 정책 검증 ── 성공 시 원자적 교체
```

Rule은 현재 패킷 또는 재조립된 현재 세션을 즉시 판단한다. AI는 종료된 Flow와 크기가 제한된
프로토콜 관찰 자료를 비동기로 판단한다. 따라서 AI 장애나 지연이 현재 패킷 verdict를 기다리게
하지 않는다.

## 5. 공통 데이터 계약

### 5.1 IP 주소

현재 `uint32_t` IPv4를 바로 사용하는 구조는 IPv6를 담을 수 없다. 확장 단계에서는 다음 의미를
가진 공통 `IpAddress` 값 타입을 도입한다.

- 주소 종류: IPv4 또는 IPv6
- 원본 주소 bytes
- 동등 비교와 hash
- 네트워크 문자열 변환
- IPv4/IPv6 CIDR 포함 여부

초기 IPv4 동작을 먼저 공통 타입으로 옮긴 뒤 IPv6 파서를 연결한다. 주소 타입 전환과 IPv6
패킷 지원을 같은 변경에서 처리하지 않는다.

### 5.2 보안 이벤트

모든 탐지·차단·상태 로그는 하나의 `SecurityEvent` 모델을 사용한다. glog 문자열을 다시
파싱해 EVE 로그를 만들지 않는다.

공통 필드는 다음과 같다.

| 필드 | 의미 |
| --- | --- |
| `event_schema_version` | 이벤트 계약 버전, 최초 `1` |
| `timestamp` | UTC RFC 3339 시각 |
| `event_type` | `alert`, `drop`, `pass`, `flow`, `dns`, `http`, `tls`, `file`, `ai`, `stats` |
| `event_id` | 한 실행 안에서 중복되지 않는 증가 ID |
| `flow_id` | 관련 Flow ID, 없으면 생략 |
| `src` / `dst` | IP, port, direction |
| `protocol` | L4 또는 앱 프로토콜 |
| `policy_version` | 판정에 사용한 정책 버전 |

이벤트별 세부 정보는 `alert`, `dns`, `file`, `ai` 같은 이름의 하위 object에 넣는다. 새 필드는
추가할 수 있지만 기존 필드 의미를 바꿀 때는 schema version을 올린다.

### 5.3 정책 묶음

실행 중 정책은 다음을 한 묶음으로 관리한다.

- 일반 설정
- 화이트리스트
- 컴파일된 Rule
- IP/CIDR 데이터셋
- 도메인 데이터셋
- SHA-256 데이터셋

각 묶음에는 증가하는 `policy_version`을 붙인다. 재로드 성공 시 전체 또는 명령에 해당하는
부분을 교체하며, 실패 시 기존 version이 유지된다.

## 6. 단계 0: 기존 기준선 안정화

새 기능 전에 다음을 완료한다.

1. `plot.run()`의 artifact loader 계약 오류를 고친다.
2. Ubuntu 오프라인 ML 환경에서 전체 Python 테스트를 실행한다.
3. 현재 C++·Python 테스트와 VM 포트 스캔·SYN Flood·AI 후속 차단 결과를 기록한다.
4. 현재 처리량, 패킷 지연, 메모리, NFQUEUE drop 수를 기준선으로 저장한다.

진행 기록: [2026-09-15 안정화 검증](../../validation/2026-09-15-baseline.md).
`plot.run()` 수정·Windows Python 검사는 반영했으며 Linux·실데이터 기준선은 아직 미검증이다.

새 기능 성능은 이 기준선과 비교한다. 기준선 없이 느려졌는지 판단하지 않는다.

## 7. 단계 1: PCAP 재생 테스트 기반

### 7.1 목적

실제 NFQUEUE와 root 환경 없이도 같은 패킷 bytes를 decoder와 Rule 엔진에 반복 입력한다. 새
프로토콜을 구현할 때 수동 네트워크 테스트만 의존하지 않게 한다.

### 7.2 범위

- libpcap 기반 classic PCAP 읽기
- 캡처 시각과 raw packet 전달
- `DLT_EN10MB` Ethernet과 `DLT_RAW` IP packet 해석
- verdict 대신 예상 이벤트·Rule 결과 수집
- PCAPNG는 장기 범위

PCAP 입력은 분석·테스트 전용이며 방화벽을 수정하지 않는다. 파일 크기와 패킷 수 상한을 두고,
손상된 파일은 오류 종료하되 센서 실시간 경로에는 영향을 주지 않는다.

### 7.3 테스트 자료

저장소에는 직접 만든 최소 패킷과 재배포가 허용된 작은 PCAP만 둔다. 각 파일 옆에 예상 Flow,
이벤트, verdict를 텍스트로 기록한다. 민감한 실제 트래픽은 포함하지 않는다.

## 8. 단계 2: DNS 분석

### 8.1 최초 지원 범위

- UDP/53 DNS query와 response
- header, question name, question type
- A·AAAA 응답 주소
- DNS name compression pointer의 범위·순환 검사
- ASCII lower-case와 마지막 점 제거를 통한 도메인 정규화
- 알 수 없는 type은 숫자로 보존

TCP DNS는 TCP 재조립 단계 이후 추가한다. DoH·DoT는 암호화되므로 이 단계에서 분석하지 않는다.

### 8.2 오류 처리

다음 입력은 DNS 파싱 실패 이벤트만 남기고 자동 차단하지 않는다.

- header보다 짧은 payload
- section count가 설정 상한을 넘음
- label 길이·전체 이름 길이 위반
- compression pointer가 payload 밖을 가리킴
- pointer 순환 또는 최대 추적 횟수 초과

파서는 packet buffer 밖을 읽지 않고 recursion 대신 명시적인 방문 상한을 사용한다.

### 8.3 탐지

- 질의 도메인의 exact match
- `.example.com` 형태의 suffix match
- 응답 A·AAAA의 IP/CIDR match
- 비정상 파싱 이벤트를 대상으로 하는 명시적 Rule

도메인 목록 일치는 `alert`가 기본이다. outbound DROP이 명시적으로 활성화되고 Rule 방향과 action이
각각 `outbound`, `drop`일 때만 query를 차단한다. DNS 응답 IP 일치는 inbound 응답을 차단할 수
있다.

## 9. 단계 2: 데이터셋 엔진

### 9.1 지원 종류

| 종류 | 최초 사용처 |
| --- | --- |
| IPv4/IPv6·CIDR | packet·DNS 응답 Rule |
| domain exact/suffix | DNS query Rule |
| SHA-256 | HTTP 파일 Rule |
| string | HTTP/TLS 이후 장기 확장 |

GeoIP와 MD5는 지원하지 않는다.

### 9.2 파일 원칙

- 설정에 등록된 고정 디렉터리 아래 파일만 읽는다.
- root 소유 일반 파일이고 group/other 쓰기가 불가능해야 한다.
- symbolic link와 경로 이탈을 거부한다.
- 빈 줄과 `#` 주석을 허용한다.
- 중복 항목은 하나로 정규화한다.
- 최대 파일 크기와 최대 항목 수를 설정으로 제한한다.
- 한 줄이라도 문법 오류가 있으면 새 데이터셋 전체를 거부한다.

외부 위협 피드 자동 다운로드는 이번 범위가 아니다. 피드를 쓸 경우 관리자가 검증한 파일을
고정 디렉터리에 배치한 뒤 reload한다.

## 10. 단계 3: Rule 엔진

### 10.1 내부 Rule 모델

Rule 입력 문법과 실행 모델을 분리한다. 최초에는 검증하기 쉬운 JSON Rule 파일을 사용하고,
장기적으로 텍스트 DSL parser가 같은 내부 모델을 생성하게 한다.

```json
{
  "schema_version": 1,
  "rules": [
    {
      "sid": 1001,
      "rev": 1,
      "enabled": true,
      "action": "drop",
      "protocol": "dns",
      "direction": "inbound",
      "match": {
        "field": "dns.query",
        "dataset": "bad_domains"
      }
    }
  ]
}
```

`sid`는 Rule 식별자이며 파일 전체에서 중복될 수 없다. `rev`는 같은 Rule의 변경 version이다.
지원하지 않는 field나 action이 있으면 해당 Rule만 무시하지 않고 새 Rule 묶음 전체를 거부한다.

### 10.2 최초 조건

- L3/L4 protocol
- inbound/outbound 방향
- src/dst IP·CIDR와 port
- packet length·TCP flag
- Flow packet·byte count와 duration
- DNS query·type·response IP
- dataset 포함 여부
- `threshold`, `flowbits`

TCP content, HTTP, TLS, file 조건은 해당 기반 기능이 완성될 때 추가한다.

### 10.3 컴파일과 실행

로드 시 문자열 field 이름과 dataset 참조를 실행용 ID·pointer로 변환한다. 패킷마다 JSON이나
Rule 문자열을 다시 해석하지 않는다. protocol·direction·port로 후보 Rule을 먼저 줄인 뒤 세부
조건을 평가한다.

### 10.4 action 우선순위

동일 패킷에 여러 Rule이 맞으면 실제 차단 여부에 다음 우선순위를 사용한다.
화이트리스트가 먼저라는 말은 새 L7 관찰도 즉시 중단한다는 뜻이 아니다. 면제된 적중은
원래 action·실제 action·`suppressed_by=whitelist`를 기록한다.

1. 전역 화이트리스트
2. 기존 TTL BlockList
3. 명시적 `pass`
4. `drop`
5. `alert`

`pass`는 의도적인 예외이므로 매칭된 Flow의 이후 검사를 건너뛸 수 있다. `pass` 자체도 감사용
이벤트와 카운터를 남긴다. AI의 사후 후속 차단은 이 우선순위와 별도로 기존 설계를 유지하며,
화이트리스트를 다시 확인한다.

### 10.5 outbound action 경계

현재 구현은 OUTPUT을 Flow 통계에만 사용하고 항상 ACCEPT한다. DNS·HTTP request Rule을 실제로
차단하려면 이 정책을 제한적으로 확장해야 한다.

- 기본값은 기존과 같은 outbound ACCEPT다.
- `allow_outbound_drop=true`를 명시한 경우에만 outbound `drop` Rule을 허용한다.
- Rule에도 `direction=outbound`가 명시되어야 한다.
- outbound `alert`와 `pass`는 DROP 허용 여부와 무관하게 사용할 수 있다.
- 원격 시작 Flow의 AI 결과만 기존처럼 판정 적용 이후 원격 IP의 inbound 패킷을 차단한다.
  로컬 시작 Flow의 AI 이상은 알림만 제공하고 어느 IP도 자동 차단하지 않는다.
  AI가 outbound 정책을 바꾸지는 않는다.

Rule 차단 팝업을 패킷마다 표시하지 않는다. Rule 결과는 EVE와 빈도 제한 glog에 기록하고, Qt는
누적 건수와 요약만 표시한다.

## 11. 단계 3: 상태 기반 탐지

### 11.1 flowbits

Flow 안에 이름이 컴파일된 boolean 상태를 저장한다. Rule은 상태를 set, unset, toggle, test할 수
있다. Flow가 종료되면 상태도 함께 제거한다.

### 11.2 threshold와 detection filter

Rule ID와 추적 기준을 묶은 bounded 상태 테이블을 사용한다.

- 추적 기준: source IP, destination IP 또는 Flow
- 조건: `seconds` 동안 `count`회
- 만료: 마지막 관찰 이후 지정된 window가 지나면 제거
- 상한: 신규 상태 생성을 거부하고 카운터 증가

고정 창을 최초 구현으로 사용한다. sliding window는 장기 확장이다.

### 11.3 flowint와 tag

숫자 상태인 `flowint`와 후속 패킷 기록인 `tag`는 장기 범위다. 내부 상태 저장소는 이후 추가할
수 있게 Rule ID와 slot ID 기반으로 설계한다.

## 12. 단계 3: 보안 이벤트 기록

### 12.1 역할 분리

- glog: 시작·종료·설정 오류·예외·복구 같은 프로그램 운영 로그
- EVE JSON Lines: 탐지·차단·Flow·DNS·HTTP·TLS·file·AI·통계 보안 이벤트

### 12.2 비동기 기록

패킷 스레드는 `SecurityEvent`를 bounded queue에 넣고 즉시 돌아간다. 전용 writer 스레드가 JSON
직렬화와 파일 기록을 담당한다.

- 기본 queue 크기와 최대 이벤트 bytes를 설정한다.
- queue 포화 시 패킷은 계속 처리하고 새 이벤트를 버린다.
- 첫 손실과 이후 일정 주기마다 glog로 누계를 요약한다.
- 중요도에 따라 별도 무제한 queue를 만들지 않는다.

### 12.3 파일 관리

- 기본 경로: root 소유 `logs/eve.json`
- JSON object 한 개당 한 줄
- 최대 파일 크기 도달 시 번호 기반 회전
- 보관 파일 개수 상한
- flush 주기 설정
- 전체 payload와 파일 원본은 기록하지 않음

writer 시작 실패는 시작 시 명시적으로 알리되, 정책에 따라 EVE 없이 계속 실행할 수 있다. 실행
중 실패는 이벤트 손실 카운터와 glog 오류를 남긴다.

## 13. 단계 4: 설정과 Unix 명령 소켓

### 13.1 설정 파일이 원본이다

소켓 명령으로 값을 직접 수정하지 않는다.

- `config.json`: 실행·상한·로그·파일 경로
- `rules/rules.json`: Rule
- `datasets/`: IP·도메인·SHA-256 목록

### 13.2 소켓

- 경로: `/run/ips-with-ai/control.sock`
- root 소유, 권한 `0600`
- local Unix domain socket만 사용
- 요청·응답은 최대 4 KiB JSON 한 줄
- shell 실행과 임의 파일 경로 입력 금지

최초 명령은 다음과 같다.

| 명령 | 동작 |
| --- | --- |
| `status` | 캡처·AI·writer·정책 version 확인 |
| `stats` | packet·Rule·queue·파싱 오류 누계 확인 |
| `list-rules` | 활성 sid·rev·action 확인 |
| `reload-config` | 고정 config 경로 재검증 |
| `reload-rules` | 고정 Rule 경로 재컴파일 |
| `reload-datasets` | 등록된 dataset 재로드 |
| `shutdown` | 기존 정상 종료 경로 요청 |

재로드는 작업 스레드에서 수행하고, 완성된 정책만 캡처 스레드의 안전 지점에서 교체한다. 요청
연결이 끊겨도 재로드 결과는 event와 glog에 남긴다.

## 14. 단계 5: TCP 스트림 재조립

### 14.1 목적

TCP segment를 양방향 byte stream으로 복원해 HTTP·TLS parser가 packet 경계를 신경 쓰지 않게
한다.

### 14.2 상태

- 각 방향의 최초·다음 예상 sequence
- 순서가 늦은 segment 저장소
- 이미 전달한 범위
- FIN/RST와 timeout
- gap, retransmission, overlap 카운터
- 앱 parser가 소비한 byte 위치

### 14.3 자원 상한

- Flow별 buffered bytes
- 전체 reassembly bytes
- Flow별 out-of-order segment 수
- 허용 gap 유지 시간
- 한 tick의 정리 작업량

상한 초과 시 해당 Flow의 L7 분석을 중단하고 `reassembly_limit` 이벤트를 남긴다. L3/L4 Rule과
기존 BlockList는 계속 동작한다.

### 14.4 겹침 정책

서로 다른 payload가 같은 sequence 범위를 주장하면 임의로 합치지 않는다. evasion 이벤트를
남기고 그 Flow의 L7 검사를 중단한다. 보호 대상 Linux와 정확히 같은 overlap 정규화 정책을
검증하기 전까지 잘못 복원한 내용을 보안 판정에 사용하지 않는다.

### 14.5 인라인 판정 시점

패킷을 stream 완성까지 NFQUEUE에 붙잡아 두지 않는다. 새 패킷으로 연속된 bytes가 완성되고 그
bytes에서 Rule이 매칭되면 현재 패킷과 같은 Flow의 이후 패킷을 DROP한다. 이미 ACCEPT verdict를
준 이전 패킷은 소급 차단할 수 없다.

순서가 늦은 패킷 때문에 과거에 통과한 bytes에서 뒤늦게 매칭된 경우에도 현재 패킷부터 차단하고
`late_stream_match`를 기록한다. 이 정책은 처리 지연과 NFQUEUE queue 고갈을 막는 대신 완성 전
데이터가 일부 통과할 수 있다는 한계를 문서와 실험 결과에 남긴다.

## 15. 단계 6: HTTP와 TLS

### 15.1 HTTP/1

최초 지원 범위는 다음과 같다.

- request method, normalized URI, host, header
- response status, content type, content length
- 고정 길이 body와 chunked body 경계
- 설정된 header/body 상한
- 비정상 줄 끝·길이·chunk 문법 이벤트

압축된 body의 해제는 후속 단계다. parser 오류만으로 자동 차단하지 않고 Rule이 명시한 경우에만
action을 적용한다.

### 15.2 TLS

TLS를 복호화하지 않고 handshake에서 평문으로 보이는 메타데이터만 분석한다.

- version
- ClientHello SNI
- ALPN
- cipher suite 목록
- 계산 규격을 고정한 JA3/JA3S
- TLS version에서 노출되는 범위의 인증서 metadata

TLS 1.3처럼 암호화되어 보이지 않는 필드는 없는 값으로 기록한다. 보이지 않는 값을 추측하거나
복호화 지원이라고 표현하지 않는다.

### 15.3 HTTP/2와 나머지 프로토콜

HTTP/2 HPACK와 frame state, 메일·SMB·산업 프로토콜은 별도 상세 설계를 거쳐 장기 단계로
진행한다. 공통 app parser interface와 event/rule field registry를 재사용한다.

## 16. 단계 7: HTTP 파일 SHA-256 검사

### 16.1 최초 범위

- 성공 HTTP response의 identity-encoded body
- 전송 중 SHA-256 누적 계산
- 설정된 최대 파일 크기
- 파일 이름 후보, content type, 실제 받은 bytes 기록
- 완료 hash의 dataset 비교

기본값은 원본을 디스크에 쓰지 않는 것이다. Content-Encoding 압축, range 응답, 다중 body 조합은
지원 상태를 event에 표시하고 최초 판정 대상에서는 제외한다.

### 16.2 판정 시점

전체 SHA-256은 파일을 끝까지 받은 뒤에만 알 수 있다. 따라서 hash match는 이미 받은 현재 파일을
소급해 되돌릴 수 없다. 탐지 이벤트를 남기고 해당 Flow의 남은 패킷과 같은 출발지의 후속 접근에
적용할 정책을 Rule로 정한다. 이 한계를 UI와 발표에서 명시한다.

## 17. 단계 8: IPv6

### 17.1 범위

- 기본 IPv6 header
- TCP·UDP까지 extension header 순회
- extension 개수·전체 bytes 상한
- IPv6 Flow, whitelist, CIDR dataset, BlockList, JSON 직렬화
- INPUT·OUTPUT IPv6 NFQUEUE 등록과 정리

IPv6 fragment는 TCP reassembly와 별도의 IP fragment 문제다. 완전한 fragment 재조립을 구현하기
전에는 fragment event를 남기고 L4/L7 분석을 중단한다.

### 17.2 AI 정책

IPv6를 Rule로 처리할 수 있다는 이유만으로 기존 IPv4 학습 모델에 보내지 않는다. AI request
schema 2가 IPv6 주소를 표현하고, 해당 모델 metadata가 IPv6 지원을 선언하며, IPv6 검증 자료의
평가 기준을 통과한 경우에만 그 모델로 보낸다. 그전에는 `AI_UNSUPPORTED`로 기록하고 Rule 경로만
사용한다. 특징의 의미와 순서가 같다면 재학습만으로 feature schema version을 올리지 않고 model
version만 바꾼다.

## 18. 확장 기능과 AI 모델 연동

### 18.1 한 모델에 모든 값을 억지로 넣지 않는다

현재 오토인코더는 CICIDS2017과 맞춘 27개 Flow 통계만 입력받는다. DNS 이름, HTTP header, TLS
SNI 같은 값은 학습에 없었으므로 기존 27개 배열 뒤에 붙이거나 값이 없을 때 0으로 채우지 않는다.
0은 "관찰하지 못함"이 아니라 실제 값으로 학습될 수 있어 판정을 왜곡하기 때문이다.

AI는 다음처럼 역할을 나눈다.

| 모델 | 입력 | 적용 시점 |
| --- | --- | --- |
| `flow_autoencoder_v1` | 현재 27개 Flow 통계 | 현재와 동일하게 종료된 지원 Flow마다 실행 |
| `dns_model_v1` | DNS 관찰 자료 | 별도 DNS 데이터셋과 평가가 준비된 뒤 선택 실행 |
| `http_model_v1` | HTTP 관찰 자료 | HTTP parser와 별도 데이터셋 검증 뒤 선택 실행 |
| `tls_model_v1` | TLS 관찰 자료 | TLS parser와 별도 데이터셋 검증 뒤 선택 실행 |

HTTP 파일의 SHA-256 dataset 일치는 입력과 결과가 명확한 결정적 판정이므로 기본적으로 AI에
맡기지 않는다. 나중에 파일 메타데이터 모델을 추가하더라도 hash Rule과 별도 결과로 취급한다.

### 18.2 C++이 만드는 관찰 자료

parser는 원본 payload 대신 크기가 제한된 구조화 자료인 `ProtocolObservation`을 만든다. 각 자료는
자체 `schema_version`을 가져 한 프로토콜의 필드 변경이 기존 Flow 모델을 깨뜨리지 않게 한다.

- DNS: 정규화된 query 이름, query type, response code, answer 수, 응답 IP 수, 크기·TTL 요약
- HTTP: method, host, path·header·body 길이, status, content type 요약
- TLS: version, SNI, ALPN, cipher·extension 수, 인증서 metadata 요약

비밀번호, cookie, authorization 값, 전체 body와 원본 파일은 AI 요청에 넣지 않는다. 문자열과 배열의
최대 길이, Flow당 observation 개수, 전체 요청 bytes 상한을 설정으로 고정한다. 상한을 넘은 자료는
잘라서 모델에 보내지 않고 `AI_OBSERVATION_LIMIT`으로 건너뛴다.

### 18.3 요청과 응답 계약

기존 요청 schema 1은 한 Flow 모델만 표현한다. 확장 요청 schema 2는 공통 Flow와 여러 관찰 자료를
분리한다.

```json
{
  "schema_version": 2,
  "flow_id": "boot-id:42",
  "flow": {
    "src_ip": "192.0.2.10",
    "src_port": 53000,
    "dst_ip": "198.51.100.53",
    "dst_port": 53,
    "protocol": 17,
    "origin": "remote_initiated",
    "local_ip": "198.51.100.53",
    "remote_ip": "192.0.2.10",
    "first_seen_ms": 1788192000000,
    "last_seen_ms": 1788192000120,
    "end_reason": "timeout",
    "feature_schema_version": 1,
    "features": [27]
  },
  "observations": [
    {"type": "dns", "schema_version": 1, "query_name": "example.test"}
  ],
  "requested_models": ["flow_autoencoder_v1", "dns_model_v1"]
}
```

`features: [27]`은 설명용 표기이며 실제 요청에는 유한한 숫자 27개가 들어간다. Python의 AI Router는
요청된 모델 중 입력 종류·schema·IP version·`supported_flow_origins`가 맞는 것만 실행한다.
해당 metadata가 없는 기존 모델은 원격 시작 전용으로 취급한다. 관찰 자료가 없거나 호환되지
않으면 임의 값을 채우지 않고 이유와 함께 건너뛴다. origin과 주소의 일관성도 검증하며,
원본 문맥과 결과 적용 정책은 핵심 정책 보완 3장을 따른다.

응답은 모델별 결과와 최종 종합 결과를 함께 돌려준다.

```json
{
  "schema_version": 2,
  "flow_id": "boot-id:42",
  "ok": true,
  "aggregate_anomaly": true,
  "results": [
    {
      "model_name": "flow_autoencoder_v1",
      "model_version": "2026-09-01T00:00:00Z",
      "status": "ok",
      "anomaly": true,
      "score": 0.42,
      "threshold": 0.30
    },
    {
      "model_name": "dns_model_v1",
      "status": "skipped",
      "reason": "MODEL_NOT_INSTALLED"
    }
  ]
}
```

`aggregate_anomaly`는 성공한 활성 모델 중 하나라도 이상이면 `true`다. 각 모델은 오프라인 평가를
통과한 뒤 설정에서 명시적으로 활성화하므로, 검증되지 않은 모델 결과를 가중 평균하는 기능은
두지 않는다. 요청 자체가 잘못됐거나 실행에 성공한 모델이 하나도 없으면 `ok=false`이며 차단하지
않는다.

### 18.4 AI Router, 전처리와 모델 registry

연결 흐름은 `C++ parser → ProtocolObservation → JSON → Python validator → model별 vectorizer →
scaler/model → 모델별 결과`다. AI Router는 모델 이름에 맞는 validator와 vectorizer를 선택한다.
DNS 이름이나 TLS SNI를 어떤 숫자로 바꿀지는 C++ parser가 결정하지 않는다. Python의 모델별
전처리가 길이·문자 종류·label 수 같은 고정 특징으로 변환하며, 학습과 온라인 추론이 같은 전처리
함수를 공유한다.

각 모델 artifact metadata에는 모델 이름·버전, 입력 종류, 입력 schema, 지원 IP version, 특징
목록·순서, 전처리 version, scaler, threshold를 기록한다. 문자열 vocabulary 같은 학습 산출물이
필요하면 같은 artifact 디렉터리의 고정 파일로 저장하고 안전 검사를 거친다. C++은 AI 시작 알림에서
활성 모델과 버전을 받은 뒤, 응답의 `flow_id`, 모델 이름, 상태를 검증한다. `status=ok` 결과에는
시작 알림과 같은 model version 및 유한한 음이 아닌 score·threshold를 요구하고, `skipped`에는
정해진 reason을 요구한다. 출발지 IP는 AI 응답을 신뢰하지 않고 C++가 보관한 원본 Flow에서만
가져온다.

기존 Flow 모델은 AI 엔진의 필수 모델이다. 선택적 DNS·HTTP·TLS 모델 하나의 파일·schema·추론이
실패해도 다른 모델과 Rule 경로는 계속 동작한다. AI queue 포화, 응답 timeout, 모든 모델 실패는
새 AI 차단을 만들지 않고 카운터와 이벤트를 남긴다. 기존 Rule·TTL 차단은 유지하므로
“AI 장애 시 모든 패킷 통과”를 뜻하지 않는다.

모델 load 오류와 Python 예외는 모델별로 격리한다. native library hang이나 process OOM까지 모델별
격리하려면 별도 process가 필요하므로 졸업작품 범위에서는 AI supervisor가 전체 Python server를
재시작한다. 이런 장애에서도 C++ Rule 경로는 계속 동작한다. 활성 모델 수와 전체 p95 추론 시간은
기존 response timeout 안에 여유 있게 들어오는 값으로 제한하고 VM 측정 결과로 확정한다.

### 18.5 Rule과 AI 결과를 합치는 방법

1. Rule의 `drop`, `pass`, `alert`는 현재 패킷 경로에서 즉시 적용한다.
2. AI는 Flow 종료 뒤 결과가 오므로 이미 전달된 패킷을 소급 차단하지 않는다.
3. `aggregate_anomaly=true`면 모델별 근거를 기록한다. 원본 Flow가 원격 시작이고 현재 whitelist
   면제가 아닐 때만, 결과 적용 이후 해당 원격 IP의 inbound 패킷을 기존 TTL 동안 차단한다.
   이미 진행 중인 연결도 대상이다. 로컬 시작·화이트리스트 Flow는 기록·알림만 제공한다.
4. 늦게 도착한 결과, 알 수 없는 Flow, 버전이 다른 결과는 폐기한다.
5. Rule 이벤트와 AI 이벤트는 별도로 남겨 어떤 판단이 실제 차단 원인이었는지 구분한다.

Qt 알림은 모델 이름·점수·임계값과 실제 대응을 요약한다. 차단했을 때만 TTL을 표시하고,
알림 전용이면 `로컬 시작 통신` 또는 `화이트리스트 면제` 이유를 표시한다. 기존 차단 IP의 중복
결과로 TTL을 연장하거나 신규 차단 팝업을 반복하지 않는다. EVE `ai` object에는 모델별 결과와
건너뛴 이유를 기록하되 27개 원본 특징과 민감한 프로토콜 문자열은 기본 기록하지 않는다.

### 18.6 학습 자료와 출시 조건

CICIDS2017은 기존 Flow 모델에만 사용한다. DNS·HTTP·TLS 학습자료는 운영 트래픽을 몰래 저장해서
만들지 않는다. label 근거가 있는 PCAP와 manifest를 PCAP replay에 입력하고, 런타임 parser가 만든
것과 같은 observation schema의 JSON Lines를 오프라인으로 내보낸다. Python은 패킷을 다시 따로
해석하지 않고 이 자료만 전처리한다.

자료는 capture session 또는 시간 단위로 train·validation·test를 분리한다. 같은 세션의 패킷이
서로 다른 분할에 섞이면 결과가 과대평가되므로 금지한다.

프로토콜 모델은 다음이 모두 준비되기 전에는 "지원"으로 표시하지 않는다.

1. 정상·이상 자료의 출처와 label 근거
2. 고정된 observation schema와 전처리
3. 정상 오탐률, 공격 종류별 탐지율, 추론 시간·메모리 평가
4. PCAP replay로 C++ 관찰값과 Python 학습값이 같은지 확인하는 계약 테스트
5. 실패 시 해당 모델만 끄고 기존 Flow AI와 Rule로 복귀하는 통합 테스트

DNS 단계에서는 먼저 Rule과 observation 수집까지만 완성한다. DNS AI 모델은 자료와 평가가 준비된
뒤 별도 구현 단계로 추가한다. HTTP와 TLS도 같은 순서를 따른다.

### 18.7 schema 1에서 2로 안전하게 옮기는 순서

1. C++이 기존 응답 1과 새 응답 2를 모두 읽되 요청은 계속 1로 보낸다.
2. Python이 요청 1·2를 모두 받고 시작 알림에 지원 schema와 모델 목록을 추가한다.
3. C++이 schema 2 지원을 확인했을 때만 요청 2를 보낸다.
4. 배포·rollback 검증 뒤 schema 2를 기본으로 바꾼다.

이 순서에서는 한쪽만 먼저 업데이트되어도 기존 Flow AI가 즉시 중단되지 않는다. schema 1 제거는
별도 호환성 종료 결정으로 남긴다.

## 19. 동시성과 소유권

| 실행 위치 | 소유 상태 |
| --- | --- |
| 캡처 스레드 | Flow, host state, reassembly, BlockList, 현재 정책 참조 |
| AI 통신 스레드 | ZeroMQ socket과 AI 입력·결과 처리 |
| Event writer 스레드 | EVE 파일과 회전 상태 |
| Reload 작업 | 새 config·Rule·dataset 구성 |
| Qt 메인 스레드 | AI process 감독과 tray UI |
| Control 스레드 | Unix 연결·요청 검증, 작업 전달 |

상태를 여러 스레드가 직접 수정하지 않는다. control과 AI 결과는 bounded message queue로 캡처
스레드에 전달한다. reload 결과는 읽기 전용 정책 pointer로만 전달한다.

## 20. 설정 개요

세부 기본값과 범위는 구현 계획에서 테스트와 함께 확정한다. 구조는 다음처럼 분리한다.

```json
{
  "rules": {
    "path": "rules/rules.json",
    "max_rules": 10000
  },
  "datasets": {
    "directory": "datasets",
    "max_entries_per_set": 1000000
  },
  "events": {
    "enabled": true,
    "path": "logs/eve.json",
    "queue_capacity": 8192,
    "max_file_bytes": 104857600,
    "retained_files": 5
  },
  "actions": {
    "allow_outbound_drop": false
  },
  "control": {
    "enabled": true,
    "socket_path": "/run/ips-with-ai/control.sock"
  },
  "reassembly": {
    "enabled": false,
    "max_flow_bytes": 1048576,
    "max_total_bytes": 268435456
  },
  "ai": {
    "artifact_dir": "ml/artifacts",
    "max_observations_per_flow": 16,
    "max_observation_bytes": 16384,
    "protocol_models": [
      {
        "name": "dns_model_v1",
        "enabled": false,
        "artifact_dir": "ml/artifacts/dns"
      }
    ]
  }
}
```

숫자는 초기 설계 상한 예시다. 실제 기본값은 VM 기준선 측정 뒤 확정한다. 잘못된 타입·음수·상한
초과는 자동 보정하지 않고 명확한 오류로 거부한다. 기존 `ai.artifact_dir`은 Flow 모델 경로로
유지한다. 프로토콜 모델은 기본 비활성이고 이름 중복, 안전하지 않은 경로, metadata 불일치가 있으면
그 모델만 비활성화한다. 통신 schema는 설정값으로 강제하지 않고 18.7의 기능 협상으로 선택한다.

## 21. 보안 경계

- 설정·Rule·dataset·로그 디렉터리는 root 소유와 쓰기 권한을 검증한다.
- 새 입력 파일은 일반 파일만 허용하고 symbolic link를 거부한다.
- parser는 모든 길이·개수·pointer를 packet bounds와 상한으로 검사한다.
- Rule과 dataset 이름은 허용 문자와 길이를 제한한다.
- Unix socket은 root 전용이고 arbitrary command·path를 받지 않는다.
- JSON event에는 전체 payload, 인증정보, 파일 원본을 기본 기록하지 않는다.
- 로그 회전 실패와 디스크 부족이 packet verdict를 막지 않는다.
- 외부 데이터 자동 다운로드와 코드 실행형 Rule은 허용하지 않는다.

## 22. 테스트 전략

### 22.1 단위 테스트

- IPv4/IPv6 address와 CIDR
- DNS 정상·압축·손상·순환 pointer
- dataset 정규화·중복·오류·상한
- Rule load·compile·우선순위
- flowbits·threshold 만료와 상한
- event schema·queue 포화·rotation
- control 권한·명령 크기·reload rollback
- TCP 순서 변경·재전송·gap·overlap·상한
- HTTP chunk·길이·손상 입력
- TLS ClientHello·잘림·상한
- SHA-256 완료·중단·크기 상한
- AI Router 모델 선택·schema/IP version 불일치·observation 없음
- 선택 모델 load·추론 실패와 일부 성공 응답
- 모델별 결과 종합·늦은 응답·알 수 없는 Flow·버전 불일치

### 22.2 PCAP golden test

각 PCAP마다 예상 Flow, event type, sid, action을 고정한다. 동일 PCAP를 반복해 같은 결과가 나와야
한다. 정상 패킷이 새 parser 때문에 차단되지 않는 것도 함께 검증한다.

DNS·HTTP·TLS PCAP에는 예상 `ProtocolObservation`도 고정한다. 학습 전처리가 같은 PCAP에서 만든
값과 일치해야 프로토콜 모델을 활성화할 수 있다.

### 22.3 fuzz test

DNS, TCP segment 삽입, HTTP, TLS, Rule JSON loader를 독립 fuzz 대상으로 만든다. 최소 기준은
crash, out-of-bounds, 무한 loop, 설정 상한을 넘는 메모리 증가가 없는 것이다.

### 22.4 VM 통합 테스트

- NFQUEUE INPUT·OUTPUT 자동 등록과 종료 정리
- DNS 악성 도메인 alert/drop
- Rule·dataset 성공/실패 reload
- EVE queue 포화와 디스크 오류 중 packet 처리 지속
- TCP 순서 변경 HTTP와 TLS metadata
- 악성 SHA-256 이벤트와 후속 정책
- IPv6 Rule·화이트리스트·TTL
- AI 장애 중 새 Rule 경로 지속
- 선택적 프로토콜 모델 장애 중 기존 Flow AI 지속
- AI 이상 알림과 판정 적용 이후 동일 원격 IP의 inbound 패킷 TTL 차단(기존 연결 포함)
- 로컬 시작·화이트리스트 Flow의 관찰·프로토콜 AI 알림과 차단 면제
- 전체 복사·잘림 처리 및 AI 큐 포화와 NFQUEUE 포화의 구분

## 23. 측정과 완료 조건

각 단계는 다음 조건을 만족해야 다음 단계로 넘어간다.

1. 새 단위·golden test가 통과한다.
2. 기존 C++·Python 테스트가 회귀하지 않는다.
3. malformed 입력에서 crash·hang이 없다.
4. 설정된 메모리·queue 상한을 지킨다.
5. 기준선 대비 처리량·p50/p95 지연·메모리 변화를 기록한다.
6. 구현된 기능과 아직 지원하지 않는 조건을 README에 구분한다.
7. 새 AI 모델은 고정 test 자료의 오탐률·공격별 탐지율·추론 시간을 기록한다.

임의의 성능 합격값을 미리 만들지 않는다. 단계 0 기준선을 측정한 뒤 허용 회귀 폭을 구현 계획에
기록한다.

## 24. 구현 단계와 커밋 경계

| 순서 | 결과물 | 다른 단계와 섞지 않을 것 |
| --- | --- | --- |
| 0 | 기존 오류 수정·VM 기준선 | 신규 기능 |
| 1 | 캡처 길이·소유권 계약, PCAP source·golden harness | DNS·Rule |
| 2 | DNS parser·dataset·DNS observation | TCP 재조립 |
| 3 | event writer·Rule·상태 | L7 parser |
| 4 | control·atomic reload | 새 Rule field |
| 5 | TCP reassembly | HTTP/TLS |
| 6 | HTTP/1·TLS metadata·observation | file hashing |
| 7 | HTTP SHA-256 | 원본 격리 저장 |
| 8 | 공통 IP 타입·IPv6 | AI schema 변경 |
| 9 | AI schema 2·Router·PCAP observation exporter | 프로토콜 모델 학습 |
| 10+ | 검증 자료가 준비된 프로토콜 모델 하나씩 | 여러 모델 동시 추가 |

각 행은 다시 테스트 가능한 작은 커밋들로 나눈다. 기능 코드와 대규모 포맷 변경은 같은 커밋에
넣지 않는다.

## 25. 예상 코드 영역

| 위치 | 책임 |
| --- | --- |
| `src/capture/` | NFQUEUE·PCAP source와 L2 입력 경계 |
| `src/decode/` | IPv4/IPv6·TCP/UDP·DNS decoder |
| `src/stream/` | TCP 재조립과 app parser 연결 |
| `src/app_layer/` | DNS·HTTP·TLS·file metadata |
| `src/detect/` | Rule 모델·compiler·state·action 선택 |
| `src/dataset/` | IP·domain·SHA-256 immutable dataset |
| `src/event/` | SecurityEvent, queue, EVE writer·rotation |
| `src/control/` | root Unix socket과 reload 요청 |
| `src/config/` | 새 상한·경로·기능 flag 검증 |
| `src/ai/` | schema 1·2 계약, bounded observation, 결과 검증과 AI Router 입력 |
| `ml/` | 모델 registry, protocol별 validator·전처리·추론과 독립 artifact loader |
| `tests/fixtures/` | 재배포 가능한 packet·PCAP·expected 결과 |

디렉터리는 책임 경계를 설명하기 위한 설계 이름이다. 구현 계획에서 기존 코드와의 중복을 확인한
뒤 정확한 파일 단위로 확정한다.

## 26. 기존 문서와의 관계

- 기존 `overview.md`, `online_inference.md`, `2026-08-28-online-ai-tray-design.md`는 현재 구현의
  기준이다.
- 이 문서는 그 구현을 폐기하지 않고 위에 기능을 추가하는 확장 설계다.
- 차단 범위·로컬 시작·화이트리스트·캡처 입력에 대해서는 2026-09-12 핵심 정책 보완이 우선한다.
  확장 권장안은 해당 코드·테스트가 반영되기 전까지 현재 기능으로 표시하지 않는다.
- 아직 완료되지 않은 기능을 README의 현재 기능처럼 표현하지 않는다.
- 각 단계가 끝날 때 기존 상용 비교 문서의 `본 프로젝트`와 `처리 방침`을 실제 상태에 맞게
  갱신한다.
