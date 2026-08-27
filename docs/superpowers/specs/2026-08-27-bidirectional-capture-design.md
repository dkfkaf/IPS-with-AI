# 양방향 호스트 캡처 설계

## 목표

단일 호스트의 IPv4 `INPUT`·`OUTPUT` 패킷을 같은 NFQUEUE에서 관찰해 원격이 시작한
Flow의 forward/backward 특징을 완성한다. Rule·Whitelist·BlockList는 inbound에만 적용하며,
outbound 패킷은 항상 ACCEPT한다.

## 범위

- 프로그램 시작·종료에 맞춘 iptables 규칙 자동 등록·제거
- NFQUEUE hook 기반 inbound/outbound 구분
- 원격 시작 Flow와 로컬 시작 Flow 구분
- 원격 시작 Flow만 AI `FlowConsumer`에 전달
- 부분 실패 롤백, 비정상 종료 뒤 stale 규칙 복구

IPv6, `FORWARD`, 라우터·브리지 배치, L7 payload 검사는 제외한다. 새 GTest는 추가하지 않고
기존 빌드와 Ubuntu VM 통합 검증을 사용한다.

## 접근 결정

INPUT과 OUTPUT에 같은 queue number를 사용한다. `nfqnl_msg_packet_hdr::hook`으로
`NF_INET_LOCAL_IN`과 `NF_INET_LOCAL_OUT`을 구분하므로 PacketSource나 FlowManager에 별도
스레드·잠금이 필요 없다. 두 큐·두 스레드 방식은 공유 상태 동기화가 필요해 제외한다.

## 패킷 메타데이터

`PacketDirection`은 `INBOUND`, `OUTBOUND`, `UNKNOWN` 세 값이다. `PacketSource::PacketHandler`는
기존 `(data, len)` 대신 `(data, len, direction)`을 받는다.

- `NF_INET_LOCAL_IN` → `INBOUND`
- `NF_INET_LOCAL_OUT` → `OUTBOUND`
- 메타데이터 없음·다른 hook → `UNKNOWN`

UNKNOWN은 로그를 남기고 상태를 갱신하지 않으며 ACCEPT한다. 패킷 ID가 없으면 기존처럼 verdict를
줄 수 없으므로 오류를 반환한다.

## Flow 기원과 갱신

`FlowOrigin`은 `REMOTE_INITIATED`, `LOCAL_INITIATED` 두 값이며 Flow 생성 시 고정한다.

`FlowManager::observe_packet(packet, direction, now)`은 정·역 5-tuple을 조회해 Flow 통계만 갱신하고,
Rule에 사용할 `SourceStats*`를 반환한다. 기존 `add_packet(packet, now)`은 inbound 기본 동작의
호환 래퍼로 유지해 기존 호출부를 깨지 않는다.

- 신규 inbound 패킷 → `REMOTE_INITIATED` Flow 생성, SourceStats 갱신
- 기존 remote Flow의 inbound 패킷 → forward 갱신, SourceStats 갱신
- 신규 outbound 패킷 → `LOCAL_INITIATED` Flow 생성, SourceStats 미갱신
- 기존 local Flow의 inbound 응답 → backward 갱신, SourceStats 미갱신
- 기존 remote Flow의 outbound 응답 → backward 갱신, SourceStats 미갱신

로컬 시작 Flow를 추적하는 이유는 inbound 응답을 신규 원격 Flow로 오인하지 않기 위해서다. 두 기원은
같은 `MAX_FLOWS` 상한을 공유하며 상한 초과 시 기존 fail-open 정책대로 신규 Flow 생성을 생략한다.

완료·만료 Flow 중 `REMOTE_INITIATED`만 `FlowConsumer`에 전달한다. `LOCAL_INITIATED`는 통계 수집 후
폐기한다. FIN/RST/timeout과 1패킷 Flow 제외 정책은 기존 동작을 유지한다.

## PacketCapture 처리

inbound 처리 순서는 기존 보안 정책을 유지한다.

1. 파싱 실패 → ACCEPT
2. Whitelist → ACCEPT, Flow 미갱신
3. BlockList 적중 → DROP, Flow 미갱신
4. 포트 없음 → ACCEPT
5. Flow 관찰 및 원격 시작 패킷일 때만 SourceStats 갱신
6. Rule 적중 → 해당 출발지 활성 Flow 제거·TTL 등록·현재 패킷 DROP
7. 완료 Flow 추출·Consumer 전달

outbound는 목적지 IP가 Whitelist 또는 BlockList에 있으면 Flow를 갱신하지 않고 ACCEPT한다. 그 외
TCP/UDP 패킷은 Flow 통계만 갱신하고, 완료된 원격 시작 Flow가 있으면 Consumer로 보낸 뒤 ACCEPT한다.
outbound 경로에서는 RuleEngine과 BlockList DROP 판정을 호출하지 않는다.

## iptables 자동 관리

`FirewallQueueGuard`가 `/usr/sbin/iptables`를 shell 없이 `fork`·`execv`의 고정 인자로 실행한다.
queue number는 검증된 `uint16_t` 설정값만 사용한다.

전용 체인 `IPS_WITH_AI`를 사용한다.

```text
INPUT  --comment ips-with-ai-managed --> IPS_WITH_AI
OUTPUT --comment ips-with-ai-managed --> IPS_WITH_AI
IPS_WITH_AI --> NFQUEUE <queue_num> --queue-bypass
IPS_WITH_AI --> RETURN --comment ips-with-ai-owned
```

RETURN 규칙은 전용 체인 소유권 표식이며 NFQUEUE 규칙 다음에 둔다. 같은 이름의 체인이 이미 있지만
소유권 표식이 없으면 사용자 체인으로 간주해 수정하지 않고 시작을 중단한다. 표식이 있는 stale 체인만
관리 대상으로 정리하며, comment가 붙은 INPUT·OUTPUT jump는 중복된 수만큼 모두 제거한다.

시작 순서:

1. NFQUEUE를 먼저 연다.
2. 이전 실행의 관리 대상 jump·소유권 표식이 있는 전용 체인을 제거한다.
3. 전용 체인·소유권 표식·NFQUEUE 규칙을 생성한다.
4. INPUT·OUTPUT jump를 등록한다.
5. 모든 단계 성공 후 수신 루프를 시작한다.

한 단계라도 실패하면 이번 실행에서 만든 jump·체인을 역순으로 제거하고 NFQUEUE를 닫은 뒤 시작을
실패 처리한다. 정상 종료와 소멸자는 관리 대상 규칙만 제거한다. `SIGINT`·`SIGTERM`은 기존 stop 경로로
루프를 끝내 정상 정리를 수행한다.

강제 종료에서는 정리 코드가 실행되지 않을 수 있다. 남은 NFQUEUE 규칙은 `--queue-bypass` 때문에
listener가 없으면 트래픽을 통과시키며, 다음 시작 시 stale 관리 체인을 제거한다. 같은 이름의 사용자
체인도 소유권 표식이 없으면 수정하지 않는다.

## 오류 정책

- iptables 실행 실패·부분 성공 → 롤백 후 시작 실패
- hook 누락·UNKNOWN → 상태 미갱신, ACCEPT
- outbound 파싱 실패·Flow 상한 → ACCEPT
- Consumer 거부 → 기존 경고 기록, verdict 영향 없음
- NFQUEUE 수신 오류 → 기존 루프 실패 처리 후 firewall·queue 정리

## 변경 위치

- `src/capture/packet_source.*`: hook 추출, PacketDirection 전달
- `src/capture/packet_capture.*`: 방향별 파이프라인, firewall 수명주기
- `src/capture/firewall_queue_guard.*`: iptables 전용 체인 관리
- `src/flow/flow.h`: FlowOrigin
- `src/flow/flow_manager.*`: 방향·기원 기반 관찰
- `src/main.cpp`: 자동 관리 상태 로그
- `CMakeLists.txt`: 새 소스 등록
- `README.md`, `docs/design/flow_features.md`, `docs/design/online_inference.md`: 실행·범위 갱신

## 검증

정적 검증 후 Ubuntu VM에서 다음을 기록한다.

1. 시작 시 INPUT·OUTPUT jump와 전용 체인이 한 번만 생성된다.
2. 원격 SYN→로컬 SYN/ACK→원격 ACK가 하나의 remote Flow에 forward/backward로 누적된다.
3. 로컬 SYN으로 시작한 Flow는 양방향 누적되지만 Consumer 로그가 없다.
4. inbound Rule 적중 패킷은 DROP되고 outbound 패킷은 항상 ACCEPT한다.
5. 정상 종료 시 관리 규칙만 제거된다.
6. 강제 종료 후 트래픽이 bypass되고 다음 실행이 stale 규칙을 정리한다.
7. iptables 부분 실패 시 생성된 규칙이 남지 않는다.

현 Windows 호스트에는 Linux NFQUEUE·iptables·C++ toolchain이 없어 구현 후 빌드·통합 결과를
검증 완료로 주장하지 않는다.
