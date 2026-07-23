#include "capture/packet_capture.h"

#include <memory>
#include <optional>
#include <utility>

#include <glog/logging.h>

#include "common/clock.h"
#include "detect/port_scan_rule.h"
#include "detect/syn_flood_rule.h"

PacketCapture::PacketCapture(const Config& config, Whitelist whitelist)
    : block_ttl_seconds_(config.block_ttl_seconds),
      whitelist_(std::move(whitelist)),
      flow_manager_(config.window_seconds),
      // 수신원에는 처리 함수와 틱 콜백만 넘긴다 — 둘 다 loop() 안에서만 불리므로
      // 아직 생성 중인 this를 잡아도 안전하다
      source_(config.queue_num,
              [this](const uint8_t* data, size_t len) { return on_packet(data, len); },
              [this]() { on_tick(); }) {
    rule_engine_.add_rule(std::make_unique<PortScanRule>(config.distinct_port_threshold));
    rule_engine_.add_rule(std::make_unique<SynFloodRule>(config.syn_threshold));
}

bool PacketCapture::start() {
    if (!source_.open()) {
        return false;  // 실패 원인은 PacketSource::open()이 이미 상세히 기록했다
    }
    const bool loop_ok = source_.loop();  // stop()이 불릴 때까지 여기서 블로킹
    const bool close_ok = source_.close();
    return loop_ok && close_ok;
}

void PacketCapture::stop() { source_.stop(); }

bool PacketCapture::on_packet(const uint8_t* data, size_t len) {
    const TimePoint now = Clock::now();

    const std::optional<ParsedPacket> parsed = parser_.parse(data, len);
    if (!parsed.has_value()) {
        return true;  // IP 헤더도 못 읽음 — 진짜 관찰 불가 트래픽만 fail-open
    }
    const uint32_t src_ip = parsed->tuple.src_ip;

    if (whitelist_.is_whitelisted(src_ip)) {
        return true;  // 어떤 판정보다 먼저 — 관리자 IP 오탐 차단의 최종 안전장치
    }
    if (block_list_.is_blocked(src_ip, now)) {
        return false;  // 차단 중 — ICMP·조각도 여기서 DROP (프로토콜 우회 방지)
    }
    if (!parsed->has_ports) {
        return true;  // 포트 없음 — 규칙 판정 불가, 관찰만 생략
    }

    const SourceStats* stats = flow_manager_.add_packet(*parsed, now);
    if (stats == nullptr) {
        return true;  // MAX_SOURCES 초과 — 명시적 fail-open
    }

    const Rule* hit = rule_engine_.check(*stats);
    if (hit != nullptr) {
        block_list_.block(src_ip, block_ttl_seconds_, now);
        LOG(WARNING) << "규칙 '" << hit->name() << "' 위반 → 차단: " << parsed->tuple.to_string();
        return false;
    }
    return true;
}

void PacketCapture::on_tick() {
    const TimePoint now = Clock::now();
    block_list_.cleanup_expired(now);
    flow_manager_.cleanup_expired(now);
}
