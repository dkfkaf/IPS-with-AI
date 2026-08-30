#include "ai/flow_features.h"

#include <array>
#include <chrono>
#include <cstddef>

#include <gtest/gtest.h>

TEST(FlowFeaturesTest, ProducesFeatureContractInPythonOrder) {
    Flow flow{};
    flow.first_seen = TimePoint{};
    flow.last_seen = flow.first_seen + std::chrono::microseconds(1500);
    flow.forward.payload_len.add(10.0);
    flow.forward.payload_len.add(30.0);
    flow.backward.payload_len.add(5.0);
    flow.forward.iat_us.add(100.0);
    flow.forward.iat_us.add(300.0);
    flow.backward.iat_us.add(50.0);
    flow.backward.iat_us.add(150.0);
    flow.forward.fin = 1;
    flow.forward.syn = 2;
    flow.forward.rst = 3;
    flow.forward.psh = 4;
    flow.forward.ack = 5;
    flow.forward.urg = 6;
    flow.backward.fin = 10;
    flow.backward.syn = 20;
    flow.backward.rst = 30;
    flow.backward.psh = 40;
    flow.backward.ack = 50;
    flow.backward.urg = 60;

    const std::array<double, FLOW_FEATURE_COUNT> expected = {
        1500.0,
        2.0,
        1.0,
        40.0,
        5.0,
        30.0,
        10.0,
        20.0,
        14.142135623730951,
        5.0,
        5.0,
        5.0,
        0.0,
        200.0,
        141.4213562373095,
        300.0,
        100.0,
        100.0,
        70.71067811865476,
        150.0,
        50.0,
        11.0,
        22.0,
        33.0,
        44.0,
        55.0,
        66.0,
    };

    const auto actual = flow_to_features(flow);
    for (size_t index = 0; index < expected.size(); ++index) {
        EXPECT_NEAR(actual[index], expected[index], 1e-9) << "feature index=" << index;
    }
}

TEST(FlowFeaturesTest, EmptyFlowProducesOnlyZeroValues) {
    const auto features = flow_to_features(Flow{});
    for (double value : features) {
        EXPECT_DOUBLE_EQ(value, 0.0);
    }
}

TEST(FlowFeaturesTest, SerializesEveryEndReason) {
    EXPECT_STREQ(flow_end_reason_to_string(FlowEndReason::TCP_FIN), "tcp_fin");
    EXPECT_STREQ(flow_end_reason_to_string(FlowEndReason::TCP_RESET), "tcp_reset");
    EXPECT_STREQ(flow_end_reason_to_string(FlowEndReason::TIMEOUT), "timeout");
}
