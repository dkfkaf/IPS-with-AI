# IPS 상세 설계 — 2단계: 플로우 조립·Rule 검사·차단

> AI 기반 인라인 IPS · C++ 센서 모듈
> 대상 범위: 2단계 (플로우 조립 → 화이트리스트 → Rule 검사 → 차단 = 대응형 IPS)
> 선행 문서: `design.md`(개념 설계), `ips_stage1_design.md`(1단계), `coding_style.md`(코딩 규칙)

---

## 1. 이 문서의 범위

1단계에서 "패킷을 받아 5-튜플을 읽는다"까지 완성했다. 2단계의 목표는 다음과 같다.

> 패킷을 플로우 단위로 조립해 통계를 쌓고, Rule 검사에 걸린 출발지 IP를
> TTL 기반으로 차단(DROP)한다. 화이트리스트에 있는 IP는 어떤 판정보다 먼저 통과시킨다.

이 단계가 끝나면 nmap 포트 스캔 같은 공격이 **실제로 차단되는 대응형 IPS**가 된다.
AI 엔진 연동(ZeroMQ)과 Qt 대시보드는 이 단계에서 다루지 않는다 — 단, 이 단계에서 만드는
플로우 통계가 이후 AI 특징 벡터의 토대가 된다.

> **로드맵과의 경계**: 1단계에서 NFQUEUE 인라인 배선을 이미 깔았기 때문에, 이 단계의
> 차단은 그 자체로 "패킷이 목적지에 도달하기 전 DROP"하는 인라인 실시간 차단이 된다.
> 따라서 상위 로드맵(README·design.md 2장)의 3단계가 맡을 남은 몫은 구조 전환이 아니라
> **AI 엔진을 포함한 하이브리드 구조의 완성과 성능 측정·고도화**다. 상위 문서의 단계
> 정의는 그대로 두고, 경계만 여기서 명시해 둔다.

---

## 2. 1단계에서 이어받는 것과 확정하는 결정

### 2.1 이어받는 토대

- `PacketCapture::on_packet()`의 반환값이 verdict가 되는 배선은 1단계에 이미 있다.
  2단계는 `return true`(무조건 통과)를 실제 판정 파이프라인으로 바꾸는 것이다.
- `PacketSource`의 수신·종료·자원 관리는 기존 동작을 유지한 채 재사용한다. 단 7장의
  틱 콜백(`TickHandler`)이 추가되어 수신 루프가 주기 정리 작업을 함께 수행하게 되고,
  ENOBUFS 경고에 빈도 제한이 걸린다 (8장 변경 목록 참고).

### 2.2 이 단계에서 확정하는 정책 결정

| 결정 사항 | 결정 | 근거 |
| --- | --- | --- |
| fail-open vs fail-closed | **fail-open 유지** — 파싱 불가·페이로드 읽기 실패·예외 패킷은 통과 | 졸업작품의 1차 리스크는 오탐으로 인한 정상 서비스 마비(design.md 6장). 관찰 불가 트래픽까지 막으면 화이트리스트로도 못 구한다 |
| 차단 단위 | **출발지 IP** (플로우 단위 아님) | design.md 6.2의 BlockList가 IP→만료 시각 구조. 포트 스캔은 플로우 여러 개에 걸친 행위라 플로우 차단으로는 못 막는다 |
| 차단 시점 로그 | 차단 **등록 시 1회** + 만료 해제 시 1회. 차단된 패킷마다 로그 금지 | DDoS 상황에서 초당 수만 줄 로그는 그 자체가 서비스 마비 요인 |
| 과부하 경고 로그 | ENOBUFS 경고에 빈도 제한(첫 발생 + N초당 1회 요약) — 1단계 코드의 "발생마다 경고"를 이 단계에서 수정 | 플러드 상황에서는 이 경고 자체가 초당 수천 줄이 될 수 있어, 위의 로그 억제 결정이 다른 경로로 뚫린다 |

---

## 3. 클래스 구조

1단계 4개 클래스에 아래를 추가한다. 각자 한 가지 책임만 진다.

| 클래스 | 책임 | 협력 관계 |
| --- | --- | --- |
| `ParsedPacket` | 파싱 결과(5-튜플 + 패킷 크기·TCP 플래그)를 담는 데이터 구조 | `PacketParser`가 생성 |
| `Flow` / `SourceStats` | 플로우 1개의 통계 / 출발지 IP 1개의 교차-플로우 통계 | `FlowManager`가 소유 |
| `FlowManager` | 플로우 조립·통계 갱신·만료 정리 | `PacketCapture`가 사용 |
| `Whitelist` | 설정에서 읽은 IP 목록, O(1) 조회 | `PacketCapture`가 사용 |
| `BlockList` | 차단 IP 관리 (map + min-heap, TTL 자동 해제) | `PacketCapture`가 사용 |
| `Rule` (추상) | 탐지 규칙 인터페이스 (Strategy) | `RuleEngine`이 보유 |
| `PortScanRule`, `SynFloodRule` | 구체 규칙 2종 | `Rule`의 자식 |
| `RuleEngine` | 규칙 목록을 순회하며 검사 | `PacketCapture`가 사용 |
| `Config` | `config.json` 로드 (nlohmann/json) | `main`이 로드해 각 클래스에 주입 |

> Rule 추상 클래스는 coding_style.md 7.2의 "Rule을 여러 개 만들 때 도입" 조건이
> 이 단계에서 충족되어(2종) 도입한다. 이름 규칙은 우리 표준대로 snake_case
> (`is_match`)를 쓴다 — coding_style.md 예시의 `IsMatch` 표기는 7.1.1의
> "정신만 취하고 표기는 우리 규칙" 원칙에 따라 통일한다.

---

## 4. 패킷 처리 파이프라인

`PacketCapture::on_packet()`이 다음 순서로 판정한다. **순서 자체가 설계 결정**이다.

```
parse(data, len)
  │ IP 헤더도 못 읽음 → ACCEPT   ← 진짜 관찰 불가 트래픽만 fail-open (2.2절)
  ▼
whitelist.is_whitelisted(src_ip)?
  │ 예 → ACCEPT              ← 어떤 판정보다 먼저 (design.md 6.1 "AI 판정 이전에 검사")
  ▼                             관리자 IP가 오탐 차단되는 사고의 최종 안전장치
block_list.is_blocked(src_ip)?
  │ 예 → DROP                ← ICMP·IP 조각(has_ports=false)도 여기까지는 온다.
  ▼                             차단된 IP가 프로토콜만 바꿔 우회하는 구멍을 막기 위함.
  │                             이미 차단된 IP는 플로우 갱신도 하지 않는다 (통계 오염 방지)
has_ports == false → ACCEPT   ← 포트가 없으면 플로우·규칙 판정이 불가 — 관찰만 생략 (5.1절)
  ▼
flow_manager.add_packet(parsed, now)  →  const SourceStats*
  │ nullptr(MAX_SOURCES 초과 — 통계 미기록) → ACCEPT   ← 상한 초과 시의 fail-open (5.2절)
  ▼
rule_engine.check(src_stats)
  │ 걸림 → block_list.block(src_ip, ttl, now) + LOG(WARNING) → DROP
  ▼
ACCEPT
```

---

## 5. 클래스별 상세

### 5.1 ParsedPacket — 파서 확장

플로우 통계에는 5-튜플 외에 패킷 크기와 TCP 플래그가 필요하다. `FiveTuple`은
플로우 키 역할 그대로 두고, 파싱 결과를 한 겹 감싼다.

1단계 파서는 비 TCP/UDP·뒤쪽 IP 조각·잘린 TCP 헤더를 전부 "파싱 실패(nullopt)"로
뭉뚱그렸지만, 2단계에서는 구분해야 한다 — 이런 패킷도 **IP 헤더는 읽히므로 출발지 IP는
알 수 있다.** 계속 뭉뚱그리면 차단된 IP가 ICMP나 IP 조각만으로 차단을 우회하는 구멍이
생긴다 (4장 파이프라인의 blocklist 단계 참고).

```cpp
struct ParsedPacket {
    FiveTuple tuple;      // has_ports=false면 포트는 0
    uint16_t total_len;   // IP 헤더의 전체 길이 필드
    bool has_ports;       // 전송 계층(TCP/UDP) 파싱 성공 여부
    bool tcp_syn;         // TCP SYN 플래그 (UDP거나 has_ports=false면 false)
    bool tcp_ack;         // TCP ACK 플래그
};

// PacketParser의 시그니처 변경:
// IP 헤더만 읽혀도 반환한다(has_ports=false). IP 헤더 자체를 못 읽을 때만 nullopt.
std::optional<ParsedPacket> parse(const uint8_t* data, size_t len) const;
```

기존 `parser_test`는 시그니처 변경에 맞춰 갱신한다 — ICMP·뒤쪽 조각 케이스의 기대값이
"nullopt"에서 "`has_ports=false`인 ParsedPacket(출발지 IP는 유효)"으로 바뀐다.

### 5.2 Flow / SourceStats / FlowManager

```cpp
struct Flow {
    FiveTuple tuple;
    uint64_t packet_count = 0;
    uint64_t byte_count = 0;
    TimePoint first_seen;
    TimePoint last_seen;
};
// 참고: 플로우 단위 syn_count는 두지 않는다 — SYN 플러드 판정은 SourceStats.syn_count가
// 담당한다(5.5절). hping3는 출발지 포트를 바꿔가며 쏘므로 플로우당 SYN은 1에 머물러
// 플로우 단위 카운트로는 탐지가 안 된다. AI 특징 단계에서 필요해지면 그때 추가한다.

// 포트 스캔은 "한 출발지가 여러 플로우를 만드는" 행위라 플로우 하나만 봐서는
// 탐지할 수 없다 — 출발지 IP 단위의 교차-플로우 통계를 따로 둔다
struct SourceStats {
    std::unordered_set<uint16_t> recent_dst_ports;  // 창(window) 안에 접촉한 목적지 포트
    uint32_t syn_count = 0;                         // 창 안의 SYN 총수
    TimePoint window_start;
};
```

`FlowManager`는 두 맵을 소유하고 통로로만 접근하게 한다 (캡슐화, coding_style.md 7.1):

```cpp
class FlowManager {
 public:
    // 패킷 1개를 반영하고, 갱신된 출발지 통계를 돌려준다.
    // nullptr = MAX_SOURCES 초과로 통계 미기록 (호출자는 규칙 검사를 생략한다).
    // 플로우는 내부에서 함께 조립된다 — 2단계 규칙은 플로우를 직접 읽지 않으므로(5.5절)
    // 반환하지 않는다. AI·대시보드 단계에서 필요해질 때 조회 통로를 추가한다.
    // 시각(now)을 인자로 받는 이유: 테스트에서 시간을 자유롭게 흘릴 수 있게 하기 위함
    const SourceStats* add_packet(const ParsedPacket& packet, TimePoint now);
    // FLOW_TIMEOUT_SEC 지난 플로우와, 창이 끝난 지 오래된 SourceStats를 함께 제거
    void cleanup_expired(TimePoint now);

 private:
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
    std::unordered_map<uint32_t, SourceStats> source_stats_;  // key: src_ip
};
```

- **플로우 키 = 5-튜플 그대로** (단방향). 요청과 응답이 서로 다른 플로우가 되는
  단순화를 감수한다 — 2단계 규칙 2종은 단방향 통계로 충분하고, 양방향 병합은
  AI 특징 추출 단계에서 필요해질 때 도입한다.
- `FiveTuple`에 `operator==`와 해시 함수 객체(`FiveTupleHash`)를 추가한다.
- `SourceStats`의 창은 **고정 창(tumbling window)**: `window_start`에서 설정값
  `rules.window_seconds`(6장)만큼 지나면 통째로 리셋. 창은 두 규칙이 **공유하는 하나**다 —
  규칙별 창을 두면 자료구조가 규칙 수만큼 늘어나는데 규칙 2종 단계에서는 과잉이고,
  슬라이딩 창도 같은 이유로 도입하지 않는다.
- 메모리 상한은 맵마다 하나씩 둔다. 랜덤 출발지 DDoS로 센서 자체가 죽는 것을 막는
  안전장치로, 두 맵 중 하나만 보호하면 나머지가 무한히 커져 취지가 무너진다.
  - `MAX_FLOWS`(예: 100,000) 초과 시 새 플로우를 만들지 않는다 — FlowManager 내부에서
    조용히 생략되고, **출발지 통계는 계속 갱신되므로 포트 스캔·SYN 플러드 탐지는
    유지된다** (2단계 규칙은 SourceStats만 읽는다, 5.5절).
  - `MAX_SOURCES`(예: 100,000) 초과 시 신규 출발지의 통계를 만들지 않는다 —
    `add_packet`이 nullptr을 반환하고 호출자는 규칙 검사를 생략한다 (명시적 fail-open,
    4장 파이프라인).
  - `cleanup_expired()`가 만료 플로우와 끝난 창의 SourceStats를 제거하므로 정상
    운용에서는 상한에 닿지 않는다.

### 5.3 Whitelist

```cpp
class Whitelist {
 public:
    bool load(const std::vector<std::string>& ip_strings);  // 설정에서 받은 목록 적재
    bool is_whitelisted(uint32_t ip) const;                 // O(1)

 private:
    std::unordered_set<uint32_t> ips_;
};
```

design.md 6.1 그대로 — 게이트웨이·DNS·관리자 접속 IP를 넣는다.
**주의: 공격 시뮬레이션 VM의 IP를 넣으면 안 된다** (테스트가 무의미해짐).

### 5.4 BlockList — map + min-heap + 지연 삭제

design.md 6.2의 자료구조 결정을 그대로 구현한다.

```cpp
class BlockList {
 public:
    void block(uint32_t ip, int ttl_seconds, TimePoint now);  // map+heap 동시 갱신
    bool is_blocked(uint32_t ip, TimePoint now);              // O(1), 만료면 false
    void cleanup_expired(TimePoint now);                      // 힙 상단만 확인

 private:
    std::unordered_map<uint32_t, TimePoint> block_map_;       // IP → 만료 시각 (진실의 원천)
    // 만료 시각이 이른 것이 위로 오는 min-heap
    std::priority_queue<HeapEntry, std::vector<HeapEntry>, std::greater<HeapEntry>> expiry_heap_;
};
```

- `block()`: 이미 차단된 IP면 만료 시각만 연장(map 갱신 + 힙에 새 항목 push).
  힙에 남는 낡은 항목은 지연 삭제로 처리한다.
- `cleanup_expired()`: 힙 상단의 만료 시각이 지났으면 pop 후 **map의 값과 대조** —
  일치할 때만 실제 해제(+로그), 불일치(TTL 연장으로 낡은 항목)면 버린다.
- `is_blocked()`: map 조회 후 만료 시각 비교. 만료됐으면 차단 아님으로 답한다
  (실제 제거는 cleanup에 맡긴다 — 조회 경로를 단순하게 유지).

### 5.5 Rule (Strategy) + 구체 규칙 2종

```cpp
class Rule {
 public:
    virtual ~Rule() = default;
    virtual const char* name() const = 0;    // 차단 로그에 남길 규칙 이름
    virtual bool is_match(const SourceStats& stats) const = 0;
};
```

> 인자가 `SourceStats`뿐인 이유: 2단계 규칙 2종은 둘 다 출발지 통계만 읽는다. 읽는
> 규칙이 하나도 없는 `Flow` 인자를 미리 두는 것은 형식적 요소다 (coding_style.md 5·6.1장
> 취지 — 소비자가 없는 구조는 만들지 않는다). 플로우 단위 규칙이 처음 생길 때 인자를
> 추가한다 — Strategy 구조라 자식들 시그니처를 한 번에 바꾸면 된다.

| 규칙 | 판정 | 대응 공격 (검증 계획의 도구) |
| --- | --- | --- |
| `PortScanRule` | 창 안에서 접촉한 목적지 포트 수 ≥ `distinct_port_threshold` | nmap 포트 스캔 |
| `SynFloodRule` | 창 안의 SYN 수 ≥ `syn_threshold` | hping3 SYN 플러드 |

`RuleEngine`은 `std::vector<std::unique_ptr<Rule>>`를 순회하며 처음 걸린 규칙을
반환한다. 새 규칙 추가 = 자식 클래스 추가 + 등록 한 줄 (개방-폐쇄, coding_style.md 7.2).

---

## 6. 설정 파일 — config.json

화이트리스트·TTL·규칙 임계값을 재빌드 없이 바꿀 수 있어야 한다 (design.md 6.1).
형식은 기술 스택 표(design.md 8장)에 이미 채택된 **nlohmann/json**을 쓴다 —
어차피 AI 단계의 ZeroMQ 직렬화에 필요한 라이브러리라 새 의존성이 아니다.

```json
{
    "queue_num": 0,
    "block_ttl_seconds": 600,
    "whitelist": ["127.0.0.1", "192.168.56.1"],
    "rules": {
        "window_seconds": 10,
        "port_scan": { "distinct_port_threshold": 20 },
        "syn_flood": { "syn_threshold": 100 }
    }
}
```

- `window_seconds`가 규칙 공통인 이유: 통계 창(`SourceStats`, 5.2절)이 하나이므로
  설정도 자료구조가 실제로 지원하는 자유도만 약속한다. 규칙별 창이 필요해지면
  그때 자료구조와 스키마를 함께 확장한다.

- `main`이 시작 시 1회 로드해 각 클래스 생성자에 주입한다. 실행 중 재로드(hot reload)는
  design.md 9장대로 부가 기능으로 미룬다.
- 설정 파일이 없으면: 화이트리스트 빈 목록 + 기본 상수(`DEFAULT_TTL_SEC` 등)로 동작하되
  경고 로그를 남긴다. 필수 파일로 만들면 1단계처럼 "일단 돌려보기"가 안 된다.

---

## 7. 스레드 구조 — 이 단계에서는 단일 스레드 유지

**결정: 2단계까지 단일 스레드.** 판정 파이프라인(해시 조회 몇 번)은 패킷 경로에서
직접 수행해도 충분히 빠르다.

유일한 주기 작업인 만료 정리(`BlockList`·`FlowManager`의 `cleanup_expired`)는
스레드 대신 **수신 루프의 시계 검사**로 해결한다: `PacketSource::loop()`가 매 반복마다
시각을 확인해 `CLEANUP_INTERVAL_SEC`(1초) 이상 지났으면 등록된 틱 콜백을 부른다.
트래픽이 계속 들어오면 recv 사이사이에, 유휴 상태면 recv 1초 타임아웃 직후에 불리므로
어느 쪽이든 정리가 1초 안팎 주기로 보장된다.

```cpp
// PacketSource에 추가
using TickHandler = std::function<void()>;   // 약 1초마다 수신 루프 안에서 호출
```

스레드 도입 시점은 다음 단계들이다 — 그때 main이 "서브시스템 start → 대기 → 역순 stop"
오케스트레이터로 바뀐다:
- **AI 연동**: ZeroMQ 송수신은 비동기여야 하므로(design.md 3.2) 별도 스레드 필요.
- **Qt 대시보드**: Qt 이벤트 루프가 main 스레드를 차지하므로, 그 시점에 수신 루프를
  워커 스레드로 옮긴다. 1단계 인터페이스(`stop()` 원자 플래그, `loop()` bool 반환,
  멱등 `close()`)는 이미 스레드에 태울 수 있게 설계되어 있어 main.cpp 변경만으로 끝난다.

---

## 8. 파일 배치

```
src/
├── main.cpp                  # Config 로드, 의존성 조립 (변경)
├── packet_capture.h/.cpp     # 판정 파이프라인 (변경)
├── packet_source.h/.cpp      # 틱 콜백 추가, ENOBUFS 경고 빈도 제한 (변경)
├── packet_parser.h/.cpp      # ParsedPacket 반환 (변경)
├── five_tuple.h/.cpp         # operator== / 해시 추가 (변경)
├── clock.h                   # TimePoint 별칭 — BlockList·Flow가 공유 (신규)
├── flow.h                    # Flow, SourceStats — 데이터만 (신규)
├── flow_manager.h/.cpp       # (신규)
├── whitelist.h/.cpp          # (신규)
├── block_list.h/.cpp         # (신규)
├── rule.h                    # 추상 Rule — 헤더만 (신규)
├── port_scan_rule.h/.cpp     # (신규)
├── syn_flood_rule.h/.cpp     # (신규)
├── rule_engine.h/.cpp        # (신규)
└── config.h/.cpp             # config.json 로드 (신규)
tests/
├── parser_test.cpp           # 기존 (시그니처 갱신)
├── block_list_test.cpp       # GTest (신규)
├── flow_manager_test.cpp     # GTest (신규)
└── rule_test.cpp             # GTest (신규)
```

**Google Test를 이 단계에서 도입한다** — coding_style.md 6.3의 "화이트리스트·TTL 등
핵심 로직이 복잡해지면 도입" 조건이 정확히 지금이다. TTL 지연 삭제나 창 리셋은 수동
테스트로 확인하기 어렵고, 시각을 인자로 받는 설계(5.2·5.4절) 덕에 시간 조작 테스트가
가능하다. 기존 `parser_test`는 손수 만든 하네스 그대로 둔다 (동작하는 것을 옮기는 건
리팩토링 규칙상 별도 커밋으로, 여유 있을 때).

---

## 9. 검증 계획

격리 VM 환경(공격: Kali, 방어: IPS)에서 수행한다. design.md 7장의 계획을 2단계
범위로 구체화한 것이다.

| # | 시나리오 | 확인 사항 |
| --- | --- | --- |
| 1 | nmap 포트 스캔 (`nmap -sS 방어IP`) | 임계값 도달 시 차단 로그 1회, 이후 스캔 패킷 DROP |
| 2 | hping3 SYN 플러드 — 전송률을 명시해 재현 가능하게 (예: `-i u10000` ≈ 초당 100개, `--flood` 금지) | SynFloodRule 차단, 센서 생존(로그 폭주 없음) |
| 3 | TTL 만료 | `block_ttl_seconds` 경과 후 자동 해제 로그, 재접속 가능 |
| 4 | 화이트리스트 | 화이트리스트 IP로 스캔 → 차단되지 않음 |
| 5 | 정상 트래픽 공존 | 공격 차단 중에도 다른 IP의 정상 통신 유지 |
| 6 | 재차단 | 해제 후 공격 재개 시 다시 차단 (design.md 6.2의 보안성 논거 확인) |

측정: 탐지까지 걸린 패킷 수·시간, 오탐 여부(정상 트래픽만으로 장시간 방치).

> **시나리오 2·5 해석 주의**: 차단은 사용자 공간 verdict로 이뤄지므로, 공격 전송률이
> 센서 처리율을 넘으면 NFQUEUE 큐(기본 1024)가 포화된다. `--queue-bypass` 규칙에서는
> 이때 초과 패킷이 **검사 없이 통과**하므로 "차단됐는데 패킷이 도달했다"는 관찰이 나올
> 수 있다. 전송률을 위 표처럼 제한해 재현 가능하게 만들고, 큐 포화가 의심되면 결과
> 해석에 반영한다. 회선 속도 플러드 방어는 11장의 커널 오프로드 확장으로 다룬다.

---

## 10. 구현 순서 (권장)

1단계와 같은 원칙 — 네트워크 없이 검증 가능한 순수 로직부터. 각 항목마다 커밋한다.

1. **ParsedPacket 확장** — 파서 시그니처 변경 + `parser_test` 갱신 + `packet_capture.cpp`의
   호출부(on_packet)도 같은 커밋에서 수정. 호출부를 빼먹으면 ips 빌드가 깨져 "항목마다
   커밋" 원칙이 무너진다. (네트워크 불필요)
2. **공통 시계 정의 + BlockList + GTest** — 먼저 `clock.h`에
   `using TimePoint = std::chrono::steady_clock::time_point;` 별칭을 만든다
   (steady_clock인 이유: 단조 시계라 벽시계 조정·NTP 동기화에 TTL과 창이 영향받지 않는다).
   이어서 map/heap/지연 삭제/TTL 연장을 시간 주입으로 검증. (순수 로직)
3. **FlowManager + GTest** — 플로우 키 해시, 통계 누적, 창 리셋, 만료 정리.
4. **Whitelist + Config** — config.json 로드, 문자열 IP → uint32 변환.
5. **Rule 2종 + RuleEngine + GTest** — 임계값 경계 케이스 위주.
6. **on_packet 통합 + 틱 콜백** — 파이프라인 배선. 여기서 처음 NFQUEUE가 필요해진다.
7. **VM 검증** — 9장 시나리오.

> 1~5가 전부 root 권한·네트워크 없이 진행 가능하다. 1단계에서 파서를 먼저 만든 것과
> 같은 이유 — "판정 로직이 틀린 건지 수신이 틀린 건지"를 분리한다.

## 11. 이 단계에서 미루는 것 (과잉 설계 경계)

- AI 엔진 연동(ZeroMQ), 특징 벡터 직렬화 — AI 단계에서. 단 FlowManager의 통계 필드가 그 토대.
- Qt 대시보드, 스레드 분리 — 대시보드 단계에서 (7장 참고).
- 화이트리스트 hot reload, 양방향 플로우 병합, IP 조각 재조립, IPv6, eBPF/XDP.
- 차단 IP의 커널 오프로드(ipset + iptables) — 사용자 공간 왕복 없이 회선 속도 플러드를
  막아야 할 때 (design.md 5장이 보조 수단으로 남겨둔 iptables 활용, 9장 해석 주의 참고).
- Rule 우선순위·복합 조건 — 규칙이 2종인 동안은 불필요.

---

*본 문서는 2단계 상세 설계이며, 구현 결과에 따라 조정될 수 있음. AI 엔진·대시보드
설계는 별도 문서로 작성 예정.*
