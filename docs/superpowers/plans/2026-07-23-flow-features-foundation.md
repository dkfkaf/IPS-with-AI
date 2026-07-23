# 플로우 특징 토대 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 플로우를 양방향으로 합치고, AI 특징의 원재료(방향별 패킷 크기·간격 통계, TCP 플래그 카운트)를 패킷마다 누적한다. 특징 벡터 확정·전송은 다음 단계.

**Architecture:** `FlowManager::add_packet`이 정/역 5-튜플 조회로 요청·응답을 한 `Flow`에 합치고, 방향(forward/backward)별 `DirectionStats`에 누적한다. 평균·표준편차는 `RunningStats`(합·제곱합·최소·최대) 하나로 계산한다. 2단계 규칙(SourceStats 기반)은 건드리지 않는다.

**Tech Stack:** C++17, Google Test, `<netinet/tcp.h>`(플래그 마스크), `<chrono>`.

## Global Constraints

- **빌드·테스트는 Linux 대상에서만** — 개발 머신은 Windows(WSL 없음)라 로컬 컴파일 불가. 순수 로직이라 아무 Linux 박스에서 `cmake --build` + `ctest`로 검증한다.
- **이름 규칙**(coding_style.md): 변수·함수 snake_case, 클래스 PascalCase, 상수 UPPER_SNAKE, 멤버 뒤 밑줄.
- **바이트 순서**: IP 키는 네트워크 순서, 포트는 호스트 순서(기존 그대로).
- **struct/class**: 상태 없는 데이터(`RunningStats`·`DirectionStats`·`Flow`)는 struct.
- **주석은 "왜"**. YAGNI — 특징 벡터·정규화·전송은 이 계획에 넣지 않는다.
- **아직 커밋 안 함**: 프로젝트 전체가 main에서 미커밋 상태. 이 작업도 검증 후 커밋 판단.
- 설계 근거: `flow_features.md`.

## File Structure

새 파일 없음. 기존 파일만 수정한다.

- `src/common/five_tuple.h` — `reversed()` 추가
- `src/capture/packet_parser.h/.cpp` — `bool tcp_syn` → `uint8_t tcp_flags`
- `src/flow/flow.h` — `RunningStats`·`DirectionStats` 추가, `Flow` 양방향 교체 (`SourceStats`는 유지)
- `src/flow/flow_manager.h/.cpp` — `add_packet` 플로우부 확장, `get_flow` 추가, SYN 카운트 `tcp_flags & TH_SYN`
- `tests/parser_test.cpp` — `tcp_syn` → `tcp_flags` 기대값
- `tests/flow_manager_test.cpp` — 헬퍼 갱신 + 신규 케이스

**공유 타입 계약:**

```cpp
// src/capture/packet_parser.h
struct ParsedPacket {
    FiveTuple tuple;
    uint16_t total_len;
    bool has_ports;
    uint8_t tcp_flags;   // TCP 플래그 옥텟 (has_ports=false·UDP면 0). TH_SYN 등으로 검사
};

// src/flow/flow.h
struct RunningStats { uint64_t count; double sum, sq_sum, min, max;
                      void add(double); double mean() const; double stddev() const; };
struct DirectionStats { RunningStats packet_len, iat_us; TimePoint last_seen;
                        uint32_t syn, ack, fin, rst, psh, urg; };
struct Flow { FiveTuple key; TimePoint first_seen, last_seen;
              DirectionStats forward, backward; };

// src/flow/flow_manager.h  (신규 메서드)
const Flow* get_flow(const FiveTuple& key) const;   // 정/역 둘 다 조회, 없으면 nullptr
```

---

## Task 1: 파서가 TCP 플래그 전체를 넘기게

**Files:**
- Modify: `src/capture/packet_parser.h`, `src/capture/packet_parser.cpp`
- Modify: `src/flow/flow_manager.cpp` (유일한 소비자 — 빌드 유지용 한 줄)
- Test: `tests/parser_test.cpp`, `tests/flow_manager_test.cpp` (필드명 갱신)

**Interfaces:**
- Produces: `ParsedPacket.tcp_flags` (`uint8_t`, TCP 플래그 옥텟).
- 기존 `bool tcp_syn`을 대체한다. 소비자는 `<netinet/tcp.h>`의 `TH_SYN`·`TH_ACK`·`TH_FIN`·`TH_RST`·`TH_PUSH`·`TH_URG`로 검사.

- [ ] **Step 1: 파서 테스트를 tcp_flags로 갱신 (실패 확인용)**

`tests/parser_test.cpp` 상단 include에 추가:

```cpp
#include <netinet/tcp.h>
```

`p->tcp_syn`을 쓰는 두 곳을 교체. TCP 성공 케이스:

```cpp
            expect((p->tcp_flags & TH_SYN) != 0, "TCP SYN 플래그 감지");
```

UDP 케이스:

```cpp
            expect((p->tcp_flags & TH_SYN) == 0, "UDP는 SYN 플래그 없음");
```

- [ ] **Step 2: 빌드해서 실패 확인 (Linux)**

Run: `cmake -S . -B build && cmake --build build --target parser_test`
Expected: FAIL — `ParsedPacket`에 `tcp_flags` 없음(아직 `tcp_syn`).

- [ ] **Step 3: 헤더에서 필드 교체**

`src/capture/packet_parser.h`의 `ParsedPacket`에서 `bool tcp_syn;` 줄을 교체:

```cpp
    uint8_t tcp_flags;    // TCP 플래그 옥텟 (has_ports=false거나 UDP면 0). TH_SYN 등으로 검사
```

그리고 구조체 위 주석의 `tcp_ack는 두지 않는다 ...` 문장을 아래로 바꾼다:

```cpp
// tcp_flags는 SYN·ACK·FIN 등 플래그 옥텟을 통째로 담는다 — 플로우 특징이 플래그별 카운트를
// 쓰므로 SYN 하나만이 아니라 전체를 넘긴다. 소비자가 TH_SYN 등 마스크로 골라 본다.
```

- [ ] **Step 4: 파서 구현에서 tcp_flags 채우기**

`src/capture/packet_parser.cpp`의 TCP 분기에서 `packet.tcp_syn = tcp_header->syn != 0;` 줄을 교체:

```cpp
        packet.tcp_flags = transport[13];  // TCP 헤더 옵셋 13이 플래그 옥텟 (최소 20B 안이라 안전)
```

(UDP·비 TCP·has_ports=false 경로는 `packet = {}` 초기화로 `tcp_flags`가 0으로 남아 손댈 것 없음.)

- [ ] **Step 5: 소비자(flow_manager) 한 줄 갱신 — 빌드 유지**

`src/flow/flow_manager.cpp` 상단 include에 추가:

```cpp
#include <netinet/tcp.h>
```

`add_packet` 안의 SourceStats SYN 카운트 줄을 교체:

```cpp
    if (packet.tcp_flags & TH_SYN) {
        ++stats.syn_count;  // SYN 플래그 선 패킷 전부 카운트 (SYN+ACK 포함, -SA 플러드 방어)
    }
```

- [ ] **Step 6: flow_manager 테스트 헬퍼 갱신**

`tests/flow_manager_test.cpp` 상단 include에 추가:

```cpp
#include <netinet/tcp.h>
```

`tcp()` 헬퍼의 `p.tcp_syn = syn;` 줄을 교체:

```cpp
    p.tcp_flags = syn ? TH_SYN : 0;
```

- [ ] **Step 7: 빌드 + 테스트 통과 확인**

Run: `cmake --build build && ctest --test-dir build --output-on-failure`
Expected: 모든 테스트 스위트 PASS (parser_test SYN 감지, 기존 flow_manager 케이스 그대로).

- [ ] **Step 8: 커밋**

```bash
git add src/capture/packet_parser.h src/capture/packet_parser.cpp src/flow/flow_manager.cpp tests/parser_test.cpp tests/flow_manager_test.cpp
git commit -m "feat(parser): expose full tcp_flags octet instead of syn-only

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Task 2: 양방향 플로우 + 특징 원재료 누적

**Files:**
- Modify: `src/common/five_tuple.h` (`reversed()`)
- Modify: `src/flow/flow.h` (`RunningStats`, `DirectionStats`, `Flow` 교체)
- Modify: `src/flow/flow_manager.h`, `src/flow/flow_manager.cpp` (`add_packet` 플로우부, `get_flow`)
- Test: `tests/flow_manager_test.cpp`

**Interfaces:**
- Consumes: `ParsedPacket.tcp_flags`(Task 1), `TimePoint`(clock.h).
- Produces: `FiveTuple::reversed()`, `Flow`(양방향), `RunningStats`, `DirectionStats`, `FlowManager::get_flow`.

- [ ] **Step 1: FiveTuple에 reversed() 추가**

`src/common/five_tuple.h`의 `operator==` 아래(닫는 `};` 앞)에 추가:

```cpp
    // 출발지·목적지를 뒤집은 5-튜플 (양방향 플로우 조회용 — 응답 방향 키)
    FiveTuple reversed() const {
        return FiveTuple{dst_ip, src_ip, dst_port, src_port, protocol};
    }
```

- [ ] **Step 2: 실패하는 테스트 작성 (양방향·통계·플래그·get_flow)**

`tests/flow_manager_test.cpp`에 헬퍼와 케이스를 추가한다. 먼저 익명 네임스페이스에 리치 헬퍼 추가(기존 `tcp()`는 SourceStats 테스트용으로 그대로 둔다):

```cpp
// 방향·크기·플래그를 지정한 TCP 패킷 (플로우 테스트용)
ParsedPacket pkt(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport,
                 uint16_t len, uint8_t flags) {
    ParsedPacket p = {};
    p.tuple = FiveTuple{sip, dip, sport, dport, 6};
    p.total_len = len;
    p.has_ports = true;
    p.tcp_flags = flags;
    return p;
}
constexpr uint32_t CLI = 0x01010101;
constexpr uint32_t SRV = 0x02020202;
```

그리고 테스트 케이스 추가:

```cpp
TEST(FlowManagerTest, MergesBothDirectionsIntoOneFlow) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, TH_SYN), t0);            // 요청 (forward)
    fm.add_packet(pkt(SRV, 80, CLI, 5000, 100, TH_SYN | TH_ACK), t0);  // 응답 (backward)
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 40, TH_ACK), t0);           // 요청

    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->forward.packet_len.count, 2u);   // 요청 2개
    EXPECT_EQ(f->backward.packet_len.count, 1u);  // 응답 1개
    EXPECT_EQ(f->forward.syn, 1u);                // 요청 중 SYN 1개
    EXPECT_EQ(f->backward.syn, 1u);               // 응답 SYN+ACK → SYN·ACK 각 1
    EXPECT_EQ(f->backward.ack, 1u);
}

TEST(FlowManagerTest, PacketLenMeanAndStddev) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    for (uint16_t len : {100, 100, 100, 100}) {  // 전부 같음 → 표준편차 0
        fm.add_packet(pkt(CLI, 5000, SRV, 80, len, TH_ACK), t0);
    }
    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.mean(), 100.0);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.stddev(), 0.0);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.min, 100.0);
    EXPECT_EQ(f->forward.packet_len.sum, 400.0);  // 바이트 수
}

TEST(FlowManagerTest, InterArrivalTimeAccumulates) {
    FlowManager fm(/*window_seconds=*/1000);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, 0), t0);                            // 첫 패킷: 간격 없음
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, 0), t0 + std::chrono::seconds(2));  // 간격 2s
    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->forward.iat_us.count, 1u);                     // 간격은 패킷수-1
    EXPECT_DOUBLE_EQ(f->forward.iat_us.mean(), 2000000.0);      // 2초 = 2e6 마이크로초
}

TEST(FlowManagerTest, GetFlowFindsEitherDirectionElseNull) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, TH_SYN), t0);
    EXPECT_NE(fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6}), nullptr);  // 정방향
    EXPECT_NE(fm.get_flow(FiveTuple{SRV, CLI, 80, 5000, 6}), nullptr);  // 역방향
    EXPECT_EQ(fm.get_flow(FiveTuple{CLI, SRV, 9999, 80, 6}), nullptr);  // 없음
}
```

- [ ] **Step 3: 빌드해서 실패 확인**

Run: `cmake --build build --target flow_manager_test`
Expected: FAIL — `Flow`에 `forward`/`key` 없음, `get_flow` 없음, `RunningStats` 없음.

- [ ] **Step 4: flow.h 교체 (RunningStats·DirectionStats·Flow)**

`src/flow/flow.h`를 아래로 교체 (`SourceStats`는 그대로 유지):

```cpp
#ifndef IPS_SRC_FLOW_FLOW_H_
#define IPS_SRC_FLOW_FLOW_H_

#include <cmath>
#include <cstdint>
#include <unordered_set>

#include "common/clock.h"
#include "common/five_tuple.h"

// 최소/최대/평균/표준편차를 한 번에 뽑는 누적기. 합·제곱합·개수만 쌓으면 파생값이 다 나온다.
// 패킷 크기와 패킷 간격이 같은 로직을 쓰므로 한 곳에 묶는다.
struct RunningStats {
    uint64_t count = 0;
    double sum = 0.0;
    double sq_sum = 0.0;  // 제곱합 — 표준편차용
    double min = 0.0;     // count>0일 때만 의미
    double max = 0.0;

    void add(double x) {
        if (count == 0) {
            min = max = x;
        } else {
            if (x < min) min = x;
            if (x > max) max = x;
        }
        ++count;
        sum += x;
        sq_sum += x * x;
    }
    double mean() const { return count ? sum / static_cast<double>(count) : 0.0; }
    double stddev() const {
        if (count == 0) return 0.0;
        const double m = mean();
        const double var = sq_sum / static_cast<double>(count) - m * m;  // 모분산
        return var > 0.0 ? std::sqrt(var) : 0.0;  // 부동소수 오차로 음수면 0
    }
};

// 플로우 한 방향의 특징 원재료.
struct DirectionStats {
    RunningStats packet_len;  // count=패킷수, sum=바이트수, mean/stddev/min/max
    RunningStats iat_us;      // 같은 방향 연속 패킷 간격 (마이크로초)
    TimePoint last_seen{};    // IAT 계산용 (packet_len.count==0이면 아직 패킷 없음)
    uint32_t syn = 0, ack = 0, fin = 0, rst = 0, psh = 0, urg = 0;  // TCP 플래그별 카운트
};

// 플로우 1개 = 양방향 대화. key는 정방향(초기자) 5-튜플이자 맵 키.
struct Flow {
    FiveTuple key;
    TimePoint first_seen;
    TimePoint last_seen;      // 지속시간 = last_seen - first_seen
    DirectionStats forward;   // key 방향 (플로우를 연 쪽)
    DirectionStats backward;  // 반대 방향
};

// 출발지 IP 1개의 교차-플로우 통계 (고정 창). 포트 스캔·SYN 플러드 판정의 입력.
struct SourceStats {
    std::unordered_set<uint16_t> recent_dst_ports;  // 창 안에 접촉한 목적지 포트
    uint32_t syn_count = 0;                         // 창 안의 SYN(플래그 선) 패킷 수
    TimePoint window_start;
};

#endif  // IPS_SRC_FLOW_FLOW_H_
```

- [ ] **Step 5: flow_manager.h에 get_flow 선언**

`src/flow/flow_manager.h`의 `cleanup_expired` 선언 아래에 추가:

```cpp
    // 정방향/역방향 어느 키로 물어도 같은 플로우를 찾는다. 없으면 nullptr.
    const Flow* get_flow(const FiveTuple& key) const;
```

- [ ] **Step 6: flow_manager.cpp — add_packet 플로우부 교체 + get_flow 구현**

`src/flow/flow_manager.cpp` 상단 include에 `<netinet/tcp.h>`가 이미 Task 1에서 추가됐다(플래그 마스크용). `add_packet`의 플로우 통계 블록(주석 `// --- 플로우 통계 ...`부터 `return &stats;` 앞까지)을 아래로 교체:

```cpp
    // --- 플로우 통계 (양방향) ---
    // 정방향으로 찾고, 없으면 역방향(응답 방향)으로 찾는다. 둘 다 없으면 새 플로우이고
    // 이 패킷이 정방향(플로우를 연 쪽)이 된다.
    bool is_forward = true;
    auto flow_it = flows_.find(packet.tuple);
    if (flow_it == flows_.end()) {
        flow_it = flows_.find(packet.tuple.reversed());
        if (flow_it != flows_.end()) {
            is_forward = false;
        } else if (flows_.size() < max_flows_) {  // 상한 넘으면 새 플로우는 생략
            Flow flow;
            flow.key = packet.tuple;
            flow.first_seen = now;
            flow_it = flows_.emplace(packet.tuple, flow).first;
        }
    }
    if (flow_it != flows_.end()) {
        Flow& flow = flow_it->second;
        DirectionStats& dir = is_forward ? flow.forward : flow.backward;
        if (dir.packet_len.count > 0) {  // 직전 패킷이 있었으면 간격을 먼저 쌓는다
            const double iat =
                std::chrono::duration<double, std::micro>(now - dir.last_seen).count();
            dir.iat_us.add(iat);
        }
        dir.packet_len.add(packet.total_len);
        dir.last_seen = now;
        const uint8_t f = packet.tcp_flags;
        if (f & TH_SYN) ++dir.syn;
        if (f & TH_ACK) ++dir.ack;
        if (f & TH_FIN) ++dir.fin;
        if (f & TH_RST) ++dir.rst;
        if (f & TH_PUSH) ++dir.psh;
        if (f & TH_URG) ++dir.urg;
        flow.last_seen = now;
    }

    return &stats;
```

파일 끝(또는 `cleanup_expired` 아래)에 `get_flow` 구현 추가:

```cpp
const Flow* FlowManager::get_flow(const FiveTuple& key) const {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        it = flows_.find(key.reversed());
    }
    return it == flows_.end() ? nullptr : &it->second;
}
```

- [ ] **Step 7: 빌드 + 테스트 통과 확인**

Run: `cmake --build build && ctest --test-dir build --output-on-failure`
Expected: 신규 4케이스 + 기존 전부 PASS.

- [ ] **Step 8: 커밋**

```bash
git add src/common/five_tuple.h src/flow/flow.h src/flow/flow_manager.h src/flow/flow_manager.cpp tests/flow_manager_test.cpp
git commit -m "feat(flow): bidirectional flow merge with per-direction feature accumulators

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review 결과

- **스펙 커버리지**: 설계 §3(양방향)→T2 Step1·6, §4(자료구조)→T2 Step4, §5(파서)→T1, §6.1(add_packet)→T2 Step6, §6.2(get_flow)→T2 Step5·6, §9(테스트 1~5)→T2 Step2, §7(2단계 영향)→T1이 파서·소비자·테스트를 한 커밋으로 묶어 빌드 유지. 전부 태스크에 있음.
- **Placeholder 스캔**: 없음. 모든 코드 스텝에 실제 코드.
- **타입 일관성**: `tcp_flags`(uint8_t), `RunningStats`(count/sum/sq_sum/min/max, mean()/stddev()), `DirectionStats`(packet_len/iat_us/last_seen/syn..urg), `Flow`(key/first_seen/last_seen/forward/backward), `get_flow(const FiveTuple&) const`, `reversed()` — 태스크 간 일치. 테스트가 쓰는 필드명(`f->forward.packet_len.count/sum/mean()/stddev()/min`, `f->backward.syn/ack`, `iat_us.count/mean()`)이 flow.h 정의와 일치.
- **경계 확인**: `transport[13]`은 TCP 최소 헤더 20B 검사 뒤라 안전. `RunningStats.stddev` 음수 분산 보호. IAT는 `count>0`일 때만(첫 패킷 제외).
