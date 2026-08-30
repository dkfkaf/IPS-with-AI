#ifndef IPS_SRC_FLOW_FLOW_MANAGER_H_
#define IPS_SRC_FLOW_FLOW_MANAGER_H_

#include <cstddef>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "capture/packet_direction.h"
#include "capture/packet_parser.h"
#include "common/clock.h"
#include "common/five_tuple.h"
#include "flow/flow.h"

// 랜덤 출발지 DDoS로 센서가 죽는 것을 막는 메모리 상한 (맵마다 하나).
constexpr size_t MAX_FLOWS = 100000;
constexpr size_t MAX_SOURCES = 100000;
// 마지막 패킷 이후 이만큼 지난 플로우를 정리한다 (메모리 위생, last_seen 기준).
constexpr int FLOW_TIMEOUT_SEC = 60;

// 플로우 조립·출발지 통계 갱신·만료 정리. 두 맵을 캡슐화한다.
class FlowManager {
 public:
    // 상한은 생성자로 주입한다(기본값은 위 상수) — 테스트가 작은 값으로 상한 동작을 검증한다.
    // window_seconds는 SourceStats 고정 창 길이 (config.rules.window_seconds).
    explicit FlowManager(int window_seconds, size_t max_flows = MAX_FLOWS,
                         size_t max_sources = MAX_SOURCES);

    // 패킷 1개(has_ports=true 전제)를 반영하고 갱신된 출발지 통계를 돌려준다.
    // nullptr = max_sources 초과로 신규 출발지 통계 미기록 (호출자는 규칙 검사 생략).
    const SourceStats* add_packet(const ParsedPacket& packet, TimePoint now);
    // 방향에 따라 Flow 기원과 Rule용 출발지 통계 갱신 여부를 결정한다.
    const SourceStats* observe_packet(const ParsedPacket& packet, PacketDirection direction,
                                      TimePoint now);
    // RST 또는 양방향 FIN 뒤 마지막 ACK로 끝난 플로우를 맵에서 꺼낸다.
    std::optional<EndedFlow> extract_completed(const FiveTuple& key);
    // Rule에서 차단한 출발지가 시작한 활성 플로우를 모두 제거한다.
    void discard_source_flows(uint32_t src_ip);
    // FLOW_TIMEOUT_SEC 지난 플로우를 반환하고 창이 끝난 SourceStats를 제거한다.
    // 한 틱에 버킷 일부씩 나눠 훑는다 — 패킷 스레드가 정리 때문에 오래 멈추지 않게.
    std::vector<EndedFlow> cleanup_expired(TimePoint now);

    // 정방향/역방향 어느 키로 물어도 같은 플로우를 찾는다. 없으면 nullptr.
    // 지금 소비자는 테스트, AI 단계에서 특징 벡터를 뽑을 때 이 통로로 읽는다.
    const Flow* get_flow(const FiveTuple& key) const;

 private:
    struct UpdatedFlow {
        Flow* flow;
        bool is_forward;
    };

    // 출발지 단위 Rule 통계를 갱신한다. 신규 출발지 상한 초과 시 nullptr.
    SourceStats* update_source_stats(const ParsedPacket& packet, TimePoint now);
    // 정·역방향 플로우를 찾아 해당 방향의 특징 원재료를 갱신한다.
    std::optional<UpdatedFlow> update_flow(const ParsedPacket& packet,
                                           PacketDirection direction, TimePoint now);
    // 보조 색인에서 플로우 키를 제거하고 빈 출발지 항목도 정리한다.
    void unindex_flow(const FiveTuple& key);

    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
    std::unordered_map<uint32_t, std::unordered_set<FiveTuple, FiveTupleHash>>
        flow_keys_by_source_;
    std::unordered_map<uint32_t, SourceStats> source_stats_;  // key: src_ip
    // cleanup_expired가 다음 틱에 이어서 훑을 버킷 위치
    size_t flow_cursor_ = 0;
    size_t source_cursor_ = 0;
    const int window_seconds_;
    const size_t max_flows_;
    const size_t max_sources_;
};

#endif  // IPS_SRC_FLOW_FLOW_MANAGER_H_
