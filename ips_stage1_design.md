# IPS 상세 설계 — 1단계: 패킷 수신·파싱

> AI 기반 인라인 IPS · C++ 센서 모듈
> 대상 범위: 1단계 (NFQUEUE 패킷 수신 → 5-튜플 파싱 → 로그 출력)

---

## 1. 이 문서의 범위

전체 개념 설계는 `design.md`, 코딩 규칙은 `coding_style.md`에 있다. 이 문서는 그중 **1단계**를 실제로 구현할 수 있는 수준까지 구체화한다.

1단계의 목표는 다음과 같다.

> NFQUEUE로 통과하는 패킷을 받아, 원시 바이트에서 5-튜플(출발지 IP, 목적지 IP, 출발지 포트, 목적지 포트, 프로토콜)을 파싱하여 로그로 출력한다.

이 단계에서는 아직 플로우 조립, Rule 검사, 차단을 다루지 않는다. "패킷을 받아서 내용을 읽을 수 있다"까지가 목표다. 이것이 되면 이후 단계(플로우 조립 → 화이트리스트 → 차단)의 토대가 된다.

---

## 2. 클래스 구조

1단계는 네 개의 클래스로 구성한다. 각 클래스는 한 가지 책임만 진다(단일 책임 원칙).

| 클래스 | 책임 | 협력 관계 |
| --- | --- | --- |
| `PacketSource` | NFQUEUE에서 패킷 바이트를 꺼내온다 | `PacketCapture`가 사용 |
| `PacketParser` | 원시 바이트에서 5-튜플을 파싱한다 | `PacketCapture`가 사용 |
| `FiveTuple` | 파싱 결과를 담는 데이터 구조 | `PacketParser`가 생성 |
| `PacketCapture` | 위 셋을 조율하는 총괄자 | 진입점 |

### 클래스 다이어그램

```
┌─────────────────────────────┐
│       PacketCapture         │  ← 총괄자
│  - source_ : PacketSource   │
│  - parser_ : PacketParser   │
│  + start() / stop()         │
│  - on_packet(bytes)         │
└───────┬─────────────┬───────┘
        │ uses        │ uses
        ▼             ▼
┌───────────────┐ ┌──────────────────┐
│  PacketSource │ │   PacketParser   │
│  + open()     │ │  + parse(bytes)  │
│  + close()    │ └────────┬─────────┘
│  + next_packet│          │ creates
└───────────────┘          ▼
                  ┌──────────────────┐
                  │    FiveTuple     │
                  │  src_ip, dst_ip  │
                  │  src_port,       │
                  │  dst_port,       │
                  │  protocol        │
                  │  + to_string()   │
                  └──────────────────┘
```

---

## 3. 클래스별 상세

### 3.1 FiveTuple (데이터 구조)

플로우를 식별하는 다섯 가지 값을 담는다. 단순 데이터 묶음이므로 `struct`로 만든다.

```cpp
struct FiveTuple {
  uint32_t src_ip;     // 출발지 IP (네트워크 바이트 순서)
  uint32_t dst_ip;     // 목적지 IP
  uint16_t src_port;   // 출발지 포트
  uint16_t dst_port;   // 목적지 포트
  uint8_t  protocol;   // 프로토콜 (TCP=6, UDP=17)

  std::string to_string() const;   // 로그 출력용 (예: "1.2.3.4:80 -> 5.6.7.8:443 TCP")
};
```

> 참고: IP는 사람이 읽는 문자열이 아니라 `uint32_t` 숫자로 저장한다. 비교·조회가 빠르고, 로그 출력 시에만 `to_string()`으로 변환한다.

### 3.2 PacketParser (파싱)

원시 패킷 바이트에서 `FiveTuple`을 뽑는다. 표준 헤더(`<netinet/ip.h>`, `<netinet/tcp.h>`, `<netinet/udp.h>`)를 직접 사용한다.

```cpp
class PacketParser {
 public:
  // 성공 시 FiveTuple 반환, 파싱 불가 시 std::nullopt
  std::optional<FiveTuple> parse(const uint8_t* data, size_t len);
};
```

파싱 순서:
1. IP 헤더(`struct iphdr`)를 읽어 출발지/목적지 IP와 프로토콜을 얻는다.
2. 프로토콜이 TCP면 TCP 헤더에서, UDP면 UDP 헤더에서 포트를 얻는다.
3. TCP/UDP가 아니면 파싱 대상이 아니므로 `std::nullopt` 반환.

주의사항:
- 버퍼 길이(`len`)를 항상 확인한다. 헤더 크기보다 짧은 패킷은 잘못된 접근을 유발하므로 파싱 전에 검사한다.
- IP 헤더 길이는 고정이 아니다(옵션 필드 존재). `ihl` 필드로 실제 헤더 길이를 계산해 TCP/UDP 헤더 위치를 잡는다.

### 3.3 PacketSource (패킷 수신)

NFQUEUE에서 패킷을 꺼내온다. libnetfilter_queue의 C API를 감싸, 바깥에서는 C++ 방식으로 쓰게 한다(캡슐화).

```cpp
class PacketSource {
 public:
  bool open();                 // NFQUEUE 큐 바인딩, 콜백 등록
  bool close();                // 자원 해제 (open과 짝)
  // 다음 패킷 대기 및 반환 (구현 방식은 콜백 기반이 될 수 있음)

 private:
  struct nfq_handle* handle_ = nullptr;   // NFQUEUE 핸들
  struct nfq_q_handle* queue_ = nullptr;  // 큐 핸들
};
```

> NFQUEUE는 콜백 기반으로 동작한다. 패킷이 도착하면 등록해둔 콜백이 호출되는 구조라, `next_packet()`을 단순 반환형으로 만들지, 콜백에서 상위로 넘길지는 구현 시 결정한다. 자원은 `open()`에서 열고 `close()`에서 정확히 대응 해제한다.

### 3.4 PacketCapture (총괄자)

위 셋을 조합해 "받기 → 파싱 → 로그"의 흐름을 돌린다.

```cpp
class PacketCapture {
 public:
  bool start();   // source_ 열고 수신 루프 시작
  void stop();    // 수신 중단, 자원 정리

 private:
  void on_packet(const uint8_t* data, size_t len);  // 패킷 1개 처리

  PacketSource source_;
  PacketParser parser_;
};
```

`on_packet`이 1단계의 핵심 로직이다:
1. `parser_.parse(data, len)`로 5-튜플을 얻는다.
2. 성공하면 `LOG(INFO) << tuple.to_string();`으로 출력한다.
3. NFQUEUE에 verdict를 반환한다. **1단계에서는 무조건 ACCEPT**(통과)한다. 차단은 이후 단계에서 추가한다.

---

## 4. 데이터 흐름

```
NFQUEUE (커널)
   │  원시 패킷 바이트
   ▼
PacketSource.next_packet()  →  const uint8_t* data, size_t len
   │
   ▼
PacketCapture.on_packet(data, len)
   │
   ├─▶ PacketParser.parse(data, len)  →  std::optional<FiveTuple>
   │                                         │
   │        ┌────────────────────────────────┘
   │        ▼
   ├─▶ 성공: LOG(INFO) << tuple.to_string()
   │
   └─▶ NFQUEUE에 verdict 반환 (1단계: 항상 ACCEPT)
```

---

## 5. 파일 배치

`coding_style.md`의 "한 파일에 한 가지 역할" 원칙에 따라 나눈다.

```
src/
├── main.cpp              # 진입점, PacketCapture 실행
├── packet_capture.h/.cpp # 총괄자
├── packet_source.h/.cpp  # NFQUEUE 수신
├── packet_parser.h/.cpp  # 5-튜플 파싱
└── five_tuple.h/.cpp     # 데이터 구조 + to_string
```

---

## 6. 1단계 구현 순서 (권장)

작은 단위로 만들고 확인하기를 반복한다. 각 단계가 끝나면 Git에 커밋한다.

1. **FiveTuple + PacketParser 먼저.** NFQUEUE 없이, 미리 준비한 샘플 패킷 바이트(하드코딩 또는 pcap에서 추출)로 파싱이 되는지 확인한다. 네트워크 없이 테스트할 수 있어 디버깅이 쉽다.
2. **PacketSource 단독 확인.** NFQUEUE에서 패킷이 실제로 들어오는지, 바이트를 받아 크기만 로그로 찍어본다. (iptables로 특정 트래픽을 NFQUEUE로 보내는 규칙 필요.)
3. **PacketCapture로 통합.** 1과 2를 연결해 "받기 → 파싱 → 로그 → ACCEPT" 전체 흐름을 완성한다.
4. **검증.** 가상환경에서 트래픽을 발생시켜 5-튜플이 정확히 찍히는지 확인한다.

> 1번을 먼저 하는 이유: 파싱 로직은 네트워크·권한 문제와 무관하게 순수 로직만 검증할 수 있다. NFQUEUE(root 권한, 커널 연동)부터 건드리면 "파싱이 틀린 건지 수신이 틀린 건지" 구분이 어려워진다.

---

## 7. 이 단계에서 미루는 것 (과잉 설계 경계)

1단계에서는 아래를 만들지 않는다. 실제로 필요한 단계에서 추가한다.

- 플로우 조립, Rule 검사, AI 판정, 차단 로직
- 화이트리스트, TTL 관리
- Rule 추상 클래스(Strategy) — Rule을 여러 개 만들 때 도입
- Qt 대시보드 — 별도 단계에서

---

*본 문서는 1단계 상세 설계이며, 구현 결과에 따라 조정될 수 있음. 2단계 이후 설계는 별도 문서로 작성 예정.*
