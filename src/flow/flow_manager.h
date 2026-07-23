#ifndef IPS_SRC_FLOW_FLOW_MANAGER_H_
#define IPS_SRC_FLOW_FLOW_MANAGER_H_

#include <cstddef>
#include <unordered_map>

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
    // FLOW_TIMEOUT_SEC 지난 플로우와 창이 끝난 SourceStats를 제거한다.
    void cleanup_expired(TimePoint now);

    // 정방향/역방향 어느 키로 물어도 같은 플로우를 찾는다. 없으면 nullptr.
    // 지금 소비자는 테스트, AI 단계에서 특징 벡터를 뽑을 때 이 통로로 읽는다.
    const Flow* get_flow(const FiveTuple& key) const;

 private:
    std::unordered_map<FiveTuple, Flow, FiveTupleHash> flows_;
    std::unordered_map<uint32_t, SourceStats> source_stats_;  // key: src_ip
    const int window_seconds_;
    const size_t max_flows_;
    const size_t max_sources_;
};

#endif  // IPS_SRC_FLOW_FLOW_MANAGER_H_
