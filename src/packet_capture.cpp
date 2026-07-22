#include "packet_capture.h"

#include <optional>

#include <glog/logging.h>

#include "five_tuple.h"

PacketCapture::PacketCapture(uint16_t queue_num)
    // 수신원에는 처리 함수만 넘긴다 — on_packet은 loop() 안에서만 불리므로
    // 아직 생성 중인 this를 잡아도 안전하다
    : source_(queue_num,
              [this](const uint8_t* data, size_t len) { return on_packet(data, len); }) {}

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
    const std::optional<FiveTuple> tuple = parser_.parse(data, len);
    if (tuple.has_value()) {
        LOG(INFO) << tuple->to_string();
    }
    // 1단계는 관찰까지만 한다 — 파싱 실패(비 TCP/UDP 등) 패킷도 통신에 지장이 없도록 무조건 통과
    return true;
}
