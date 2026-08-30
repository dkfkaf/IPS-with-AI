#include "ai/ai_protocol.h"

#include <cmath>
#include <exception>

#include <nlohmann/json.hpp>

#include "ai/flow_features.h"
#include "common/five_tuple.h"

namespace {

void set_error(std::string* error, const std::string& message) {
    if (error != nullptr) {
        *error = message;
    }
}

bool has_string(const nlohmann::json& object, const char* key) {
    return object.contains(key) && object.at(key).is_string();
}

}  // namespace

std::string serialize_flow_request(const FlowRecord& record) {
    const nlohmann::json request{
        {"schema_version", 1},
        {"flow_id", record.flow_id},
        {"src_ip", ip_to_string(record.key.src_ip)},
        {"src_port", record.key.src_port},
        {"dst_ip", ip_to_string(record.key.dst_ip)},
        {"dst_port", record.key.dst_port},
        {"protocol", record.key.protocol},
        {"first_seen_ms", record.first_seen_ms},
        {"last_seen_ms", record.last_seen_ms},
        {"end_reason", flow_end_reason_to_string(record.end_reason)},
        {"feature_schema_version", record.feature_schema_version},
        {"features", record.features},
    };
    return request.dump();
}

std::optional<AiResponse> parse_ai_response(const std::string& json_text,
                                            const std::string& expected_flow_id,
                                            const std::string& expected_model_version,
                                            std::string* error) {
    set_error(error, "");
    try {
        const auto response = nlohmann::json::parse(json_text);
        if (!response.is_object()) {
            set_error(error, "응답이 JSON object가 아님");
            return std::nullopt;
        }
        if (!response.contains("schema_version") ||
            !response.at("schema_version").is_number_integer() ||
            response.at("schema_version").get<int>() != 1) {
            set_error(error, "schema_version 오류");
            return std::nullopt;
        }
        if (!has_string(response, "flow_id") ||
            response.at("flow_id").get<std::string>() != expected_flow_id) {
            set_error(error, "flow_id 불일치");
            return std::nullopt;
        }
        if (!has_string(response, "model_version") ||
            response.at("model_version").get<std::string>() != expected_model_version) {
            set_error(error, "model_version 불일치");
            return std::nullopt;
        }
        if (!response.contains("ok") || !response.at("ok").is_boolean()) {
            set_error(error, "ok 타입 오류");
            return std::nullopt;
        }

        AiResponse parsed;
        parsed.ok = response.at("ok").get<bool>();
        parsed.flow_id = expected_flow_id;
        parsed.model_version = expected_model_version;
        if (!parsed.ok) {
            if (!has_string(response, "error_code") ||
                response.at("error_code").get<std::string>().empty()) {
                set_error(error, "error_code 오류");
                return std::nullopt;
            }
            parsed.error_code = response.at("error_code").get<std::string>();
            return parsed;
        }

        if (!response.contains("anomaly") || !response.at("anomaly").is_boolean()) {
            set_error(error, "anomaly 타입 오류");
            return std::nullopt;
        }
        if (!response.contains("score") || !response.at("score").is_number() ||
            !response.contains("threshold") || !response.at("threshold").is_number()) {
            set_error(error, "score 또는 threshold 타입 오류");
            return std::nullopt;
        }
        const double score = response.at("score").get<double>();
        const double threshold = response.at("threshold").get<double>();
        if (!std::isfinite(score) || score < 0.0 || !std::isfinite(threshold) || threshold < 0.0) {
            set_error(error, "score 또는 threshold 범위 오류");
            return std::nullopt;
        }
        parsed.anomaly = response.at("anomaly").get<bool>();
        parsed.score = score;
        parsed.threshold = threshold;
        return parsed;
    } catch (const nlohmann::json::exception& exception) {
        set_error(error, std::string("응답 JSON 오류: ") + exception.what());
    } catch (const std::exception& exception) {
        set_error(error, std::string("응답 처리 오류: ") + exception.what());
    }
    return std::nullopt;
}
