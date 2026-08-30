#include "ai/ai_protocol.h"

#include <arpa/inet.h>

#include <cstddef>
#include <string>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

FlowRecord make_record() {
    FlowRecord record{};
    record.flow_id = "sensor-7";
    record.key = FiveTuple{htonl(0xC000020A), htonl(0xC6336414), 45678, 443, 6};
    record.first_seen_ms = 1000;
    record.last_seen_ms = 2500;
    record.end_reason = FlowEndReason::TIMEOUT;
    record.feature_schema_version = 1;
    for (size_t index = 0; index < record.features.size(); ++index) {
        record.features[index] = static_cast<double>(index) + 0.5;
    }
    return record;
}

}  // namespace

TEST(AiProtocolTest, SerializesCompleteFlowContract) {
    const auto request = nlohmann::json::parse(serialize_flow_request(make_record()));

    EXPECT_EQ(request.at("schema_version"), 1);
    EXPECT_EQ(request.at("flow_id"), "sensor-7");
    EXPECT_EQ(request.at("src_ip"), "192.0.2.10");
    EXPECT_EQ(request.at("src_port"), 45678);
    EXPECT_EQ(request.at("dst_ip"), "198.51.100.20");
    EXPECT_EQ(request.at("dst_port"), 443);
    EXPECT_EQ(request.at("protocol"), 6);
    EXPECT_EQ(request.at("first_seen_ms"), 1000);
    EXPECT_EQ(request.at("last_seen_ms"), 2500);
    EXPECT_EQ(request.at("end_reason"), "timeout");
    EXPECT_EQ(request.at("feature_schema_version"), 1);
    const nlohmann::json expected_features = {
        0.5,  1.5,  2.5,  3.5,  4.5,  5.5,  6.5,  7.5,  8.5,
        9.5,  10.5, 11.5, 12.5, 13.5, 14.5, 15.5, 16.5, 17.5,
        18.5, 19.5, 20.5, 21.5, 22.5, 23.5, 24.5, 25.5, 26.5,
    };
    EXPECT_EQ(request.at("features"), expected_features);
}

TEST(AiProtocolTest, ParsesValidatedAnomalyResponse) {
    std::string error;
    const auto response = parse_ai_response(
        R"({
            "schema_version": 1,
            "flow_id": "sensor-7",
            "model_version": "ae-v1",
            "ok": true,
            "anomaly": true,
            "score": 1.25,
            "threshold": 0.75
        })",
        "sensor-7", "ae-v1", &error);

    ASSERT_TRUE(response.has_value()) << error;
    EXPECT_TRUE(response->ok);
    EXPECT_TRUE(response->anomaly);
    EXPECT_DOUBLE_EQ(response->score, 1.25);
    EXPECT_DOUBLE_EQ(response->threshold, 0.75);
}

TEST(AiProtocolTest, ParsesErrorResponseWithoutBlockFields) {
    std::string error;
    const auto response = parse_ai_response(
        R"({
            "schema_version": 1,
            "flow_id": "sensor-7",
            "model_version": "ae-v1",
            "ok": false,
            "error_code": "INVALID_FIELD"
        })",
        "sensor-7", "ae-v1", &error);

    ASSERT_TRUE(response.has_value()) << error;
    EXPECT_FALSE(response->ok);
    EXPECT_EQ(response->error_code, "INVALID_FIELD");
}

TEST(AiProtocolTest, RejectsMismatchedFlowOrModelIdentity) {
    const std::string valid =
        R"({
            "schema_version": 1,
            "flow_id": "sensor-7",
            "model_version": "ae-v1",
            "ok": true,
            "anomaly": false,
            "score": 0.25,
            "threshold": 0.75
        })";
    std::string error;

    EXPECT_FALSE(parse_ai_response(valid, "another-flow", "ae-v1", &error).has_value());
    EXPECT_FALSE(parse_ai_response(valid, "sensor-7", "another-model", &error).has_value());
}

TEST(AiProtocolTest, RejectsMalformedOrUnsafeDecisionValues) {
    const std::string negative_score =
        R"({
            "schema_version": 1,
            "flow_id": "sensor-7",
            "model_version": "ae-v1",
            "ok": true,
            "anomaly": true,
            "score": -0.1,
            "threshold": 0.75
        })";
    const std::string wrong_anomaly_type =
        R"({
            "schema_version": 1,
            "flow_id": "sensor-7",
            "model_version": "ae-v1",
            "ok": true,
            "anomaly": 1,
            "score": 1.0,
            "threshold": 0.75
        })";
    std::string error;

    EXPECT_FALSE(parse_ai_response("not-json", "sensor-7", "ae-v1", &error).has_value());
    EXPECT_FALSE(
        parse_ai_response(negative_score, "sensor-7", "ae-v1", &error).has_value());
    EXPECT_FALSE(
        parse_ai_response(wrong_anomaly_type, "sensor-7", "ae-v1", &error).has_value());
}
