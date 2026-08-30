#include "flow/flow_manager.h"

#include <netinet/tcp.h>

#include <algorithm>
#include <chrono>
#include <utility>
#include <vector>

FlowManager::FlowManager(int window_seconds, size_t max_flows, size_t max_sources)
    : window_seconds_(window_seconds), max_flows_(max_flows), max_sources_(max_sources) {
    // 상한만큼 버킷을 미리 확보 — 맵이 커지는 동안 리해시(그 순간 패킷 처리 정지)가 없다.
    // 버킷 수가 안 변하니 cleanup_expired가 버킷 위치를 저장해 이어 훑는 것도 안전해진다.
    flows_.reserve(max_flows_);
    flow_keys_by_source_.reserve(max_sources_);
    source_stats_.reserve(max_sources_);
}

const SourceStats* FlowManager::add_packet(const ParsedPacket& packet, TimePoint now) {
    return observe_packet(packet, PacketDirection::INBOUND, now);
}

const SourceStats* FlowManager::observe_packet(const ParsedPacket& packet,
                                               PacketDirection direction, TimePoint now) {
    if (direction == PacketDirection::UNKNOWN) {
        return nullptr;
    }
    const std::optional<UpdatedFlow> updated = update_flow(packet, direction, now);
    if (!updated.has_value()) {
        // Flow 저장 상한과 Rule 탐지는 독립이다. 기원을 저장할 공간이 없어도 inbound
        // SourceStats를 계속 갱신해 포트 스캔·SYN 플러드 탐지가 꺼지지 않게 한다.
        return direction == PacketDirection::INBOUND ? update_source_stats(packet, now)
                                                      : nullptr;
    }
    if (direction != PacketDirection::INBOUND || !updated->is_forward ||
        updated->flow->origin != FlowOrigin::REMOTE_INITIATED) {
        return nullptr;
    }
    return update_source_stats(packet, now);
}

SourceStats* FlowManager::update_source_stats(const ParsedPacket& packet, TimePoint now) {
    const uint32_t src_ip = packet.tuple.src_ip;
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
    return &stats;
}

std::optional<FlowManager::UpdatedFlow> FlowManager::update_flow(
    const ParsedPacket& packet, PacketDirection direction, TimePoint now) {
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
            flow.origin = direction == PacketDirection::OUTBOUND
                              ? FlowOrigin::LOCAL_INITIATED
                              : FlowOrigin::REMOTE_INITIATED;
            flow_it = flows_.emplace(packet.tuple, flow).first;
            flow_keys_by_source_[packet.tuple.src_ip].insert(packet.tuple);
        }
    }
    if (flow_it != flows_.end()) {
        Flow& flow = flow_it->second;
        DirectionStats& dir = is_forward ? flow.forward : flow.backward;
        const bool both_fin_seen = flow.forward.fin > 0 && flow.backward.fin > 0;
        if (dir.packet_len.count > 0) {  // 직전 패킷이 있었으면 간격을 먼저 쌓는다
            const double iat = static_cast<double>(
                std::chrono::duration_cast<std::chrono::microseconds>(now - dir.last_seen)
                    .count());
            dir.iat_us.add(iat);
        }
        dir.packet_len.add(packet.total_len);
        dir.payload_len.add(packet.payload_len);
        dir.last_seen = now;
        const uint8_t f = packet.tcp_flags;
        if (f & TH_SYN) ++dir.syn;
        if (f & TH_ACK) ++dir.ack;
        if (f & TH_FIN) ++dir.fin;
        if (f & TH_RST) ++dir.rst;
        if (f & TH_PUSH) ++dir.psh;
        if (f & TH_URG) ++dir.urg;
        if (both_fin_seen && (f & TH_ACK) != 0 && (f & TH_FIN) == 0) {
            flow.fin_handshake_complete = true;
        }
        flow.last_seen = now;
    }
    if (flow_it == flows_.end()) {
        return std::nullopt;
    }
    return UpdatedFlow{&flow_it->second, is_forward};
}

const Flow* FlowManager::get_flow(const FiveTuple& key) const {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        it = flows_.find(key.reversed());
    }
    return it == flows_.end() ? nullptr : &it->second;
}

std::optional<EndedFlow> FlowManager::extract_completed(const FiveTuple& key) {
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        it = flows_.find(key.reversed());
    }
    if (it == flows_.end()) {
        return std::nullopt;
    }

    const Flow& flow = it->second;
    FlowEndReason reason;
    if (flow.forward.rst > 0 || flow.backward.rst > 0) {
        reason = FlowEndReason::TCP_RESET;
    } else if (flow.fin_handshake_complete) {
        reason = FlowEndReason::TCP_FIN;
    } else {
        return std::nullopt;
    }

    unindex_flow(it->first);
    EndedFlow ended{std::move(it->second), reason};
    flows_.erase(it);
    return ended;
}

void FlowManager::discard_source_flows(uint32_t src_ip) {
    auto source_it = flow_keys_by_source_.find(src_ip);
    if (source_it == flow_keys_by_source_.end()) {
        return;
    }
    for (const FiveTuple& key : source_it->second) {
        flows_.erase(key);
    }
    flow_keys_by_source_.erase(source_it);
}

void FlowManager::unindex_flow(const FiveTuple& key) {
    auto source_it = flow_keys_by_source_.find(key.src_ip);
    if (source_it == flow_keys_by_source_.end()) {
        return;
    }
    source_it->second.erase(key);
    if (source_it->second.empty()) {
        flow_keys_by_source_.erase(source_it);
    }
}

namespace {

// 만료 정리를 틱마다 나눠서 하는 이유: 맵이 상한(기본 10만)까지 차면 전체 순회가
// 밀리초급인데, 이 작업은 패킷 처리와 같은 스레드에서 돌아 그동안 verdict가 밀린다.
// 한 틱엔 버킷 1/10만 훑고 위치(cursor)를 저장해 다음 틱에 이어서 돈다.
// 늦게 지워져도 add_packet이 창·통계를 리셋하므로 판정 정확성에는 영향이 없다.
template <typename Map, typename Pred, typename OnExpired>
void sweep_expired(Map& map, size_t& cursor, Pred is_expired, OnExpired on_expired) {
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
        auto it = map.find(key);
        if (it != map.end()) {
            on_expired(std::move(it->second));
            map.erase(it);
        }
    }
}

}  // namespace

std::vector<EndedFlow> FlowManager::cleanup_expired(TimePoint now) {
    std::vector<EndedFlow> expired_flows;
    // 마지막 패킷 이후 FLOW_TIMEOUT_SEC 지난 플로우 제거
    const auto flow_timeout = std::chrono::seconds(FLOW_TIMEOUT_SEC);
    sweep_expired(flows_, flow_cursor_,
                  [&](const Flow& f) { return now - f.last_seen >= flow_timeout; },
                  [&](Flow&& flow) {
                      unindex_flow(flow.key);
                      expired_flows.push_back(
                          EndedFlow{std::move(flow), FlowEndReason::TIMEOUT});
                  });
    // 창이 끝난 출발지 통계 제거 (다음 패킷이 어차피 리셋하므로 미리 지워도 안전)
    const auto window = std::chrono::seconds(window_seconds_);
    sweep_expired(source_stats_, source_cursor_,
                  [&](const SourceStats& s) { return now - s.window_start >= window; },
                  [](SourceStats&& /*unused*/) {});
    return expired_flows;
}
