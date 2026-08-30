#include "ai/flow_features.h"

#include <chrono>

namespace {

double count_sum(uint32_t forward, uint32_t backward) {
    return static_cast<double>(forward) + static_cast<double>(backward);
}

}  // namespace

std::array<double, FLOW_FEATURE_COUNT> flow_to_features(const Flow& flow) {
    const DirectionStats& forward = flow.forward;
    const DirectionStats& backward = flow.backward;
    const double duration_us = static_cast<double>(
        std::chrono::duration_cast<std::chrono::microseconds>(flow.last_seen - flow.first_seen)
            .count());

    // 이 초기화 순서가 ml/features.py의 FEATURES 순서와 같은 특징 계약이다.
    return {
        duration_us,
        static_cast<double>(forward.payload_len.count),
        static_cast<double>(backward.payload_len.count),
        forward.payload_len.sum,
        backward.payload_len.sum,
        forward.payload_len.max,
        forward.payload_len.min,
        forward.payload_len.mean(),
        forward.payload_len.stddev(),
        backward.payload_len.max,
        backward.payload_len.min,
        backward.payload_len.mean(),
        backward.payload_len.stddev(),
        forward.iat_us.mean(),
        forward.iat_us.stddev(),
        forward.iat_us.max,
        forward.iat_us.min,
        backward.iat_us.mean(),
        backward.iat_us.stddev(),
        backward.iat_us.max,
        backward.iat_us.min,
        count_sum(forward.fin, backward.fin),
        count_sum(forward.syn, backward.syn),
        count_sum(forward.rst, backward.rst),
        count_sum(forward.psh, backward.psh),
        count_sum(forward.ack, backward.ack),
        count_sum(forward.urg, backward.urg),
    };
}

const char* flow_end_reason_to_string(FlowEndReason reason) {
    switch (reason) {
        case FlowEndReason::TCP_FIN:
            return "tcp_fin";
        case FlowEndReason::TCP_RESET:
            return "tcp_reset";
        case FlowEndReason::TIMEOUT:
            return "timeout";
    }
    return "unknown";
}
