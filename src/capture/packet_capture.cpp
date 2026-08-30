#include "capture/packet_capture.h"

#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <glog/logging.h>

#include "ai/flow_features.h"
#include "common/clock.h"
#include "common/five_tuple.h"
#include "detect/port_scan_rule.h"
#include "detect/syn_flood_rule.h"

PacketCapture::PacketCapture(const Config& config, Whitelist whitelist,
                             std::unique_ptr<FlowConsumer> flow_consumer,
                             AiBlockHandler ai_block_handler)
    : block_ttl_seconds_(config.block_ttl_seconds),
      whitelist_(std::move(whitelist)),
      flow_manager_(config.window_seconds),
      flow_consumer_(std::move(flow_consumer)),
      ai_block_handler_(std::move(ai_block_handler)),
      steady_anchor_(Clock::now()),
      wall_anchor_(std::chrono::system_clock::now()),
      sensor_instance_id_(std::to_string(std::chrono::duration_cast<std::chrono::microseconds>(
                                             wall_anchor_.time_since_epoch())
                                             .count())),
      firewall_(config.queue_num),
      // 수신원에는 처리 함수와 틱 콜백만 넘긴다 — 둘 다 loop() 안에서만 불리므로
      // 아직 생성 중인 this를 잡아도 안전하다
      source_(config.queue_num,
              [this](const uint8_t* data, size_t len, PacketDirection direction) {
                  return on_packet(data, len, direction);
              },
              [this]() { on_tick(); }) {
    rule_engine_.add_rule(std::make_unique<PortScanRule>(config.distinct_port_threshold));
    rule_engine_.add_rule(std::make_unique<SynFloodRule>(config.syn_threshold));
}

bool PacketCapture::start() {
    if (!source_.open()) {
        return false;  // 실패 원인은 PacketSource::open()이 이미 상세히 기록했다
    }
    if (!firewall_.install()) {
        source_.close();
        return false;
    }
    const bool loop_ok = source_.loop();  // stop()이 불릴 때까지 여기서 블로킹
    const bool firewall_ok = firewall_.uninstall();
    const bool close_ok = source_.close();
    return loop_ok && firewall_ok && close_ok;
}

void PacketCapture::stop() { source_.stop(); }

bool PacketCapture::on_packet(const uint8_t* data, size_t len, PacketDirection direction) {
    if (direction == PacketDirection::UNKNOWN) {
        LOG(WARNING) << "지원하지 않는 NFQUEUE hook — 상태 갱신 없이 통과";
        return true;
    }
    const TimePoint now = Clock::now();

    const std::optional<ParsedPacket> parsed = parser_.parse(data, len);
    if (!parsed.has_value()) {
        return true;  // IP 헤더도 못 읽음 — 진짜 관찰 불가 트래픽만 fail-open
    }
    return direction == PacketDirection::INBOUND ? handle_inbound(*parsed, now)
                                                  : handle_outbound(*parsed, now);
}

bool PacketCapture::handle_inbound(const ParsedPacket& packet, TimePoint now) {
    const uint32_t src_ip = packet.tuple.src_ip;
    if (whitelist_.is_whitelisted(src_ip)) {
        return true;  // 어떤 판정보다 먼저 — 관리자 IP 오탐 차단의 최종 안전장치
    }
    if (block_list_.is_blocked(src_ip, now)) {
        return false;  // 차단 중 — ICMP·조각도 여기서 DROP (프로토콜 우회 방지)
    }
    if (!packet.has_ports) {
        return true;  // 포트 없음 — 규칙 판정 불가, 관찰만 생략
    }

    const SourceStats* stats =
        flow_manager_.observe_packet(packet, PacketDirection::INBOUND, now);
    if (stats != nullptr) {
        const Rule* hit = rule_engine_.check(*stats);
        if (hit != nullptr) {
            flow_manager_.discard_source_flows(src_ip);
            rule_blocks_.fetch_add(1, std::memory_order_relaxed);
            block_list_.block(src_ip, block_ttl_seconds_, now);
            LOG(WARNING) << "규칙 '" << hit->name()
                         << "' 위반 → 차단: " << packet.tuple.to_string();
            return false;
        }
    }

    std::optional<EndedFlow> completed = flow_manager_.extract_completed(packet.tuple);
    if (completed.has_value()) {
        consume_flow(std::move(*completed));
    }
    return true;
}

bool PacketCapture::handle_outbound(const ParsedPacket& packet, TimePoint now) {
    const uint32_t dst_ip = packet.tuple.dst_ip;
    if (whitelist_.is_whitelisted(dst_ip) || block_list_.is_blocked(dst_ip, now) ||
        !packet.has_ports) {
        return true;
    }

    flow_manager_.observe_packet(packet, PacketDirection::OUTBOUND, now);
    std::optional<EndedFlow> completed = flow_manager_.extract_completed(packet.tuple);
    if (completed.has_value()) {
        consume_flow(std::move(*completed));
    }
    return true;
}

void PacketCapture::on_tick() {
    const TimePoint now = Clock::now();
    apply_ai_decisions(now);
    std::vector<EndedFlow> expired = flow_manager_.cleanup_expired(now);
    for (EndedFlow& flow : expired) {
        consume_flow(std::move(flow));
    }
    block_list_.cleanup_expired(now);
}

void PacketCapture::apply_ai_decisions(TimePoint now) {
    for (AiDecision& decision : flow_consumer_->drain_decisions()) {
        if (!decision.anomaly) {
            continue;
        }
        const uint32_t source_ip = decision.record.key.src_ip;
        if (whitelist_.is_whitelisted(source_ip)) {
            ai_whitelisted_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (block_list_.is_blocked(source_ip, now)) {
            ai_duplicates_.fetch_add(1, std::memory_order_relaxed);
            LOG(INFO) << "AI_DECISION action=duplicate flow_id=" << decision.record.flow_id;
            continue;
        }
        flow_manager_.discard_source_flows(source_ip);
        block_list_.block(source_ip, block_ttl_seconds_, now);
        ai_new_blocks_.fetch_add(1, std::memory_order_relaxed);
        LOG(WARNING) << "AI_DECISION action=blocked flow_id=" << decision.record.flow_id
                     << " source_ip=" << ip_to_string(source_ip)
                     << " score=" << decision.score << " threshold=" << decision.threshold
                     << " model_version=" << decision.model_version;
        if (ai_block_handler_) {
            try {
                ai_block_handler_(AiBlockEvent{decision.record.flow_id, source_ip, decision.score,
                                               decision.threshold, block_ttl_seconds_,
                                               decision.model_version});
            } catch (const std::exception& error) {
                LOG(ERROR) << "AI block handler 오류: " << error.what();
            }
        }
    }
}

void PacketCapture::consume_flow(EndedFlow ended_flow) {
    if (ended_flow.flow.origin != FlowOrigin::REMOTE_INITIATED) {
        return;
    }
    const uint64_t packet_count = ended_flow.flow.forward.payload_len.count +
                                  ended_flow.flow.backward.payload_len.count;
    if (packet_count <= 1) {
        return;  // CICFlowMeter 출력과 같이 1패킷 Flow는 AI 입력에서 제외
    }
    const uint32_t src_ip = ended_flow.flow.key.src_ip;
    const TimePoint now = Clock::now();
    if (whitelist_.is_whitelisted(src_ip) || block_list_.is_blocked(src_ip, now)) {
        return;
    }

    FlowRecord record{
        next_flow_id(),
        ended_flow.flow.key,
        to_epoch_ms(ended_flow.flow.first_seen),
        to_epoch_ms(ended_flow.flow.last_seen),
        ended_flow.reason,
        FLOW_FEATURE_SCHEMA_VERSION,
        flow_to_features(ended_flow.flow),
    };
    flow_consumer_->consume(std::move(record));
}

CaptureStatsSnapshot PacketCapture::capture_stats() const {
    return CaptureStatsSnapshot{
        rule_blocks_.load(std::memory_order_relaxed),
        ai_new_blocks_.load(std::memory_order_relaxed),
        ai_duplicates_.load(std::memory_order_relaxed),
        ai_whitelisted_.load(std::memory_order_relaxed),
    };
}

int64_t PacketCapture::to_epoch_ms(TimePoint point) const {
    const auto wall_point = wall_anchor_ + (point - steady_anchor_);
    return std::chrono::duration_cast<std::chrono::milliseconds>(wall_point.time_since_epoch())
        .count();
}

std::string PacketCapture::next_flow_id() {
    return sensor_instance_id_ + '-' + std::to_string(next_flow_sequence_++);
}
