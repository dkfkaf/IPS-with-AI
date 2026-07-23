# IPS 설계 — 플로우 특징 토대 (AI 연동 준비)

> AI 기반 인라인 IPS · C++ 센서
> 대상 범위: 3번 "C++ 센서 보강" 중 **토대** — 양방향 플로우 병합 + 특징 원재료 누적
> 선행 문서: `overview.md`(개념), `stage2.md`(2단계), `code_explained.md`(코드 원리)

---

## 1. 이 문서의 범위

3단계에서 AI(오토인코더)에 넘길 플로우 특징을 계산하려면, 그 특징의 **원재료**를 패킷마다
플로우에 쌓아둬야 한다. 이 문서는 그 토대만 다룬다.

- **한다**: 양방향 플로우 병합, 방향별 특징 원재료 누적(패킷 크기·간격·플래그 통계), 플로우 조회 통로.
- **안 한다**: 정확한 특징 벡터 확정·정규화, 어떤 플로우를 AI로 보낼지 선별, ZeroMQ·JSON 전송,
  AI→룰 피드백. 이건 AI 엔진을 설계할 때 함께 정한다.

> **왜 지금 하나**: 이 누적은 **패킷 경로에 심어야** 한다. 나중에 붙이면 패킷마다 도는 코드를
> 다시 건드려야 하므로, 토대를 먼저 깔아둔다. 지금 소비자는 테스트뿐이지만(누적이 맞는지 검증),
> AI 단계에서 특징을 고를 때 패킷 경로를 다시 안 건드리게 하는 게 목적이다.

> **왜 특징 목록을 지금 안 정하나**: C++가 뽑는 특징 = AI가 먹는 입력이다. AI 모델(CICIDS2017
> 학습)이 어떤 특징을 쓸지 정해지기 전에 목록을 고정하면 헛일이 된다. 대신 **어떤 특징이든
> 파생되는 원재료**(합·제곱합·최소·최대·플래그 카운트)를 쌓아, 목록 확정을 AI 단계로 미룬다.

---

## 2. 확정한 결정

| 결정 | 내용 | 근거 |
| --- | --- | --- |
| 특징 세트 | 지금은 **토대만** — 원재료 누적까지 | 목록은 AI 모델이 정함. 결합을 피함 |
| 통계 범위 | 방향별 패킷 크기·간격 통계 + 플래그 카운트 + 지속시간 | 평균·표준편차는 합·제곱합·개수만 쌓으면 나오는 싼 원재료. 특징 고정이 아님 |
| 플로우 방향 | **양방향 병합** (fwd/bwd 구분) | AI 특징은 요청·응답을 합쳐 봐야 의미 있음 |
| 파서 | `bool tcp_syn` → `uint8_t tcp_flags` | 플래그를 세려면 SYN만이 아니라 플래그 전체가 필요 |
| 2단계 규칙 | **안 건드림** | 규칙은 `SourceStats`(출발지 통계)를 볼 뿐 `Flow`를 안 봄 |

---

## 3. 양방향 플로우 병합

지금은 A→B와 B→A가 별개 플로우다(2단계 5.2의 단방향 단순화). 이걸 하나로 합친다.

**키 잡는 법 — 새 키 타입 없이**: 패킷이 오면 정방향 5-튜플로 찾고, 없으면 **뒤집은** 5-튜플로
찾는다. 둘 다 없으면 새 플로우이고, 이 패킷이 **정방향**(플로우를 연 쪽)이 된다.

```
add_packet(packet):
    fwd = packet.tuple
    flows_[fwd] 있음      → 이 패킷은 forward
    flows_[fwd.reversed()] 있음 → 이 패킷은 backward
    둘 다 없음            → 새 플로우 생성(키 = fwd), 이 패킷은 forward
```

- 맵 키는 항상 **정방향(초기자) 5-튜플**이다. 되찾을 땐 정/역 두 번 조회한다.
- `FiveTuple`에 `reversed()`(src↔dst 뒤집기)만 추가하면 기존 `FiveTupleHash`를 그대로 쓴다.
- CICFlowMeter 관례와 같다: forward = 플로우 첫 패킷을 보낸 쪽.

```cpp
// common/five_tuple.h 에 추가
FiveTuple reversed() const {
    return FiveTuple{dst_ip, src_ip, dst_port, src_port, protocol};
}
```

---

## 4. 자료구조 (`flow/flow.h`)

### 4.1 RunningStats — 누적 통계 원재료

최소/최대/평균/표준편차를 한 번에 뽑는 작은 헬퍼. 패킷 크기와 간격이 **같은 로직**을 쓰므로
한 곳에 묶는다(중복 제거).

```cpp
struct RunningStats {
    uint64_t count = 0;
    double sum = 0.0;
    double sq_sum = 0.0;   // 제곱합 — 표준편차용
    double min = 0.0;      // count>0일 때만 의미
    double max = 0.0;

    void add(double x) {
        if (count == 0) { min = max = x; }
        else { if (x < min) min = x; if (x > max) max = x; }
        ++count; sum += x; sq_sum += x * x;
    }
    double mean() const { return count ? sum / count : 0.0; }
    double stddev() const {
        if (count == 0) return 0.0;
        const double m = mean();
        const double var = sq_sum / count - m * m;   // 모분산
        return var > 0.0 ? std::sqrt(var) : 0.0;      // 부동소수 오차로 음수면 0
    }
};
```

> `double`로 누적하는 이유: 제곱합이 커진다(패킷 크기 최대 65535, 제곱 ~4.3e9). double의
> 정수 정밀도(~9e15)면 데모 규모 플로우는 오차 없이 담긴다.

### 4.2 DirectionStats — 한 방향의 원재료

```cpp
struct DirectionStats {
    RunningStats packet_len;   // count=패킷수, sum=바이트수, mean/stddev/min/max
    RunningStats iat_us;       // 같은 방향 연속 패킷 간격(마이크로초)
    TimePoint last_seen{};     // IAT 계산용 (packet_len.count==0이면 아직 없음)
    uint32_t syn = 0, ack = 0, fin = 0, rst = 0, psh = 0, urg = 0;  // 플래그별 카운트
};
```

- 패킷 수·바이트 수는 `packet_len.count`·`packet_len.sum`에서 나오므로 따로 두지 않는다.
- IAT는 같은 방향에서 **직전 패킷과의 간격**이다. 첫 패킷은 간격이 없으므로 두 번째부터 쌓인다.

### 4.3 Flow — 양방향으로 교체

```cpp
struct Flow {
    FiveTuple key;           // 정방향(초기자) 5-튜플 = 맵 키
    TimePoint first_seen;
    TimePoint last_seen;     // 지속시간 = last_seen - first_seen
    DirectionStats forward;  // key 방향
    DirectionStats backward; // 반대 방향
};
```

`SourceStats`(2단계 규칙 입력)는 그대로 둔다 — 이 변경과 무관하다.

---

## 5. 파서 변경 (`capture/packet_parser.*`)

플래그를 세려면 파서가 플래그 전체를 넘겨야 한다.

```cpp
struct ParsedPacket {
    FiveTuple tuple;
    uint16_t total_len;
    bool has_ports;
    uint8_t tcp_flags;   // (변경) bool tcp_syn 대신 TCP 플래그 옥텟. has_ports=false·UDP면 0
};
```

- `tcp_flags`는 TCP 헤더의 플래그 바이트(옵셋 13)를 그대로 담는다. 소비자는 `<netinet/tcp.h>`의
  `TH_SYN`·`TH_ACK`·`TH_FIN`·`TH_RST`·`TH_PUSH`·`TH_URG` 마스크로 검사한다.
- 바이트 13은 이미 검사한 TCP 헤더 최소 길이(20B) 안에 있으므로 범위 밖 읽기가 없다.

---

## 6. FlowManager 변경 (`flow/flow_manager.*`)

### 6.1 add_packet — 플로우 부분을 양방향으로 확장

`SourceStats` 갱신(2단계 규칙 입력)은 그대로다. 단 SYN 카운트만 플래그에서 읽는다:

```cpp
if (packet.tcp_flags & TH_SYN) ++stats.syn_count;   // 기존 packet.tcp_syn 대체
```

플로우 부분은 3장 방식으로 정/역 조회 후 해당 방향을 갱신한다:

```cpp
DirectionStats& dir = is_forward ? flow.forward : flow.backward;
if (dir.packet_len.count > 0) {                       // 직전 패킷이 있었으면
    dir.iat_us.add(마이크로초(now - dir.last_seen));   // 간격 먼저 쌓고
}
dir.packet_len.add(packet.total_len);                 // 그 다음 크기 누적
dir.last_seen = now;
if (packet.tcp_flags & TH_SYN)  ++dir.syn;            // 플래그 카운트
if (packet.tcp_flags & TH_ACK)  ++dir.ack;
... (fin/rst/psh/urg 동일)
flow.last_seen = now;
```

- `MAX_FLOWS` 상한은 그대로 — 초과 시 새 플로우를 안 만든다. (출발지 통계는 계속 갱신되어
  2단계 탐지는 유지된다는 성질도 그대로.)

### 6.2 get_flow — 읽는 통로 (신규)

```cpp
// 정방향/역방향 어느 쪽으로 물어도 같은 플로우를 찾는다. 없으면 nullptr.
const Flow* get_flow(const FiveTuple& key) const;
```

지금 소비자는 테스트다(누적이 맞는지 검증). AI 단계에서 특징 벡터를 뽑을 때 이 통로로 읽는다.

---

## 7. 2단계에 미치는 영향 (건드리는 곳)

| 파일 | 변경 |
| --- | --- |
| `common/five_tuple.h` | `reversed()` 추가 |
| `capture/packet_parser.h/.cpp` | `tcp_syn` → `tcp_flags` |
| `flow/flow.h` | `RunningStats`·`DirectionStats` 추가, `Flow` 양방향으로 교체 |
| `flow/flow_manager.h/.cpp` | `add_packet` 플로우부 확장, `get_flow` 추가, SYN 카운트 `tcp_flags & TH_SYN` |
| `tests/parser_test.cpp` | `tcp_syn` 기대값 → `tcp_flags` |
| `tests/flow_manager_test.cpp` | 헬퍼의 `tcp_syn` → `tcp_flags`, 신규 케이스 추가 |

**안 건드리는 것**: `PortScanRule`·`SynFloodRule`·`RuleEngine`(규칙), `on_packet` 파이프라인,
`BlockList`, `Whitelist`, `Config`, `PacketSource`. 규칙은 `SourceStats`만 보고 플로우는 안 본다.

---

## 8. 이 단계에서 미루는 것 (AI 엔진 설계와 함께)

- 정확한 특징 벡터 정의(어느 원재료를 어떤 파생값으로) + 정규화
- "애매한 플로우" 선별 — 어떤 플로우를 언제 AI로 보낼지
- ZeroMQ 전송(cppzmq) + JSON 직렬화(nlohmann)
- AI가 돌려준 판정을 룰로 등록하는 피드백 경로
- 플로우 종료(FIN/RST) 시점의 특징 확정 — 지금은 누적만, 종료 판정은 AI 단계

---

## 9. 검증 계획 (`tests/flow_manager_test.cpp`)

전부 순수 로직 — 네트워크·root 없이 GTest로 확인한다.

| # | 확인 |
| --- | --- |
| 1 | 양방향 병합 — A→B와 B→A 패킷이 **한 플로우**로 합쳐지고, forward/backward에 각각 쌓임 |
| 2 | 패킷 크기 통계 — 여러 크기 넣고 mean·stddev·min·max가 맞는지 |
| 3 | IAT — 시각을 흘려 방향별 간격이 맞게 쌓이는지(첫 패킷은 간격 없음) |
| 4 | 플래그 카운트 — SYN·ACK 등 섞어 넣고 방향별 카운트 확인 |
| 5 | `get_flow` — 정방향·역방향 키 둘 다로 같은 플로우를 찾고, 없으면 nullptr |
| 6 | (기존) 상한·창 리셋·SourceStats 누적은 그대로 통과 |

---

---

## 다음 작업 (TODO) — AI-feed 레이어 (ZeroMQ 전까지)

2026-07-23 브레인스토밍에서 합의한 범위·설계. 구현은 미룸(오늘 안 함). AI 특징 세트(ml/features.py 27개)가
확정됐으므로 이제 만들 수 있다. **ZeroMQ 전송·JSON·AI→룰 피드백은 이 다음 단계(제외).**

- **① 특징 벡터 추출**: `flow_to_features(const Flow&) → double[27]`. forward/backward `DirectionStats`에서
  뽑아 `ml/features.py`와 **동일 순서**로. 순서를 한 곳에 고정하고 features.py를 주석 참조.
  skew(CICFlowMeter와 계산 차이, 예: 패킷 길이 정의)는 주석으로 명시 — 검증은 B(추론) 단계.
- **② 방출 시점**: 플로우가 **타임아웃으로 정리될 때** 방출. `FlowManager::cleanup_expired`가 지워지는
  플로우들을 반환하도록 변경 → `PacketCapture`가 처리. (FIN/RST 조기 방출은 지연 최적화, 나중.)
- **③ 선별**: 화이트리스트·차단된 출발지는 스킵, 나머지 완성 플로우만 AI 후보.
- **④ 구멍(인터페이스)**: 추상 `FeatureConsumer`(`consume(vector)`). 오늘의 stub = `LoggingConsumer`(로그로
  증명). 나중에 ZeroMQ 구현을 이 인터페이스에 끼움(기존 코드 불변).
- **⑤ 파일 배치(제안)**: 새 `src/ai/`(`feature_vector`, `feature_consumer`, `logging_consumer`) +
  `flow_manager`(cleanup 반환)·`packet_capture`(배선) 수정. *미확정: 폴더명 `ai/` vs `detect/`, 방출 방식.*

---

*본 문서는 플로우 특징 토대 설계다. 특징 벡터·전송·피드백은 AI 엔진 설계 문서에서 다룬다.*
