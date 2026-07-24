#include "flow/flow_manager.h"

#include <netinet/tcp.h>

#include <algorithm>
#include <chrono>
#include <vector>

FlowManager::FlowManager(int window_seconds, size_t max_flows, size_t max_sources)
    : window_seconds_(window_seconds), max_flows_(max_flows), max_sources_(max_sources) {
    // 상한만큼 버킷을 미리 확보 — 맵이 커지는 동안 리해시(그 순간 패킷 처리 정지)가 없다.
    // 버킷 수가 안 변하니 cleanup_expired가 버킷 위치를 저장해 이어 훑는 것도 안전해진다.
    flows_.reserve(max_flows_);
    source_stats_.reserve(max_sources_);
}

const SourceStats* FlowManager::add_packet(const ParsedPacket& packet, TimePoint now) {
    const uint32_t src_ip = packet.tuple.src_ip;

    // --- 출발지 통계 ---
    auto it = source_stats_.find(src_ip);
    if (it == source_stats_.end()) {
        if (source_stats_.size() >= max_sources_) {
            return nullptr;  // 상한 초과 — 신규 출발지 통계를 만들지 않는다 (명시적 fail-open)
        }
        it = source_stats_.emplace(src_ip, SourceStats{}).first;
        it->second.window_start = now;
    } else if (now - it->second.window_start >= std::chrono::seconds(window_seconds_)) {
        // 고정 창 리셋: 기본값으로 되돌린 뒤 창을 지금부터 다시 시작.
        // 필드를 하나씩 비우지 않고 통째로 대입해, SourceStats에 필드가 늘어도 자동 반영된다.
        it->second = SourceStats{};
        it->second.window_start = now;
    }
    SourceStats& stats = it->second;
    stats.recent_dst_ports.insert(packet.tuple.dst_port);
    if (packet.tcp_flags & TH_SYN) {
        ++stats.syn_count;  // SYN 플래그 선 패킷 전부 카운트 (SYN+ACK 포함, -SA 플러드 방어)
    }

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
}

const Flow* FlowManager::get_flow(const FiveTuple& key) const {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        it = flows_.find(key.reversed());
    }
    return it == flows_.end() ? nullptr : &it->second;
}

namespace {

// 만료 정리를 틱마다 나눠서 하는 이유: 맵이 상한(기본 10만)까지 차면 전체 순회가
// 밀리초급인데, 이 작업은 패킷 처리와 같은 스레드에서 돌아 그동안 verdict가 밀린다.
// 한 틱엔 버킷 1/10만 훑고 위치(cursor)를 저장해 다음 틱에 이어서 돈다.
// 늦게 지워져도 add_packet이 창·통계를 리셋하므로 판정 정확성에는 영향이 없다.
template <typename Map, typename Pred>
void sweep_expired(Map& map, size_t& cursor, Pred is_expired) {
    const size_t buckets = map.bucket_count();
    const size_t quota = std::max<size_t>(buckets / 10, 64);  // 작은 맵(테스트)은 사실상 전체
    std::vector<typename Map::key_type> doomed;  // 버킷 순회 중 erase 대신 모아서 삭제
    for (size_t i = 0; i < quota && i < buckets; ++i) {
        const size_t b = (cursor + i) % buckets;
        for (auto it = map.cbegin(b); it != map.cend(b); ++it) {
            if (is_expired(it->second)) {
                doomed.push_back(it->first);
            }
        }
    }
    cursor = (cursor + quota) % buckets;
    for (const auto& key : doomed) {
        map.erase(key);
    }
}

}  // namespace

void FlowManager::cleanup_expired(TimePoint now) {
    // 마지막 패킷 이후 FLOW_TIMEOUT_SEC 지난 플로우 제거
    const auto flow_timeout = std::chrono::seconds(FLOW_TIMEOUT_SEC);
    sweep_expired(flows_, flow_cursor_,
                  [&](const Flow& f) { return now - f.last_seen >= flow_timeout; });
    // 창이 끝난 출발지 통계 제거 (다음 패킷이 어차피 리셋하므로 미리 지워도 안전)
    const auto window = std::chrono::seconds(window_seconds_);
    sweep_expired(source_stats_, source_cursor_,
                  [&](const SourceStats& s) { return now - s.window_start >= window; });
}
