#include "config/config.h"

#include <fstream>
#include <limits>
#include <sstream>

#include <glog/logging.h>
#include <nlohmann/json.hpp>

namespace {

// 음이 아닌 JSON 정수를 넓은 타입으로 먼저 읽어 목적 타입 변환 전의 축소·오버플로를 막는다.
std::optional<uint64_t> read_nonnegative_integer(const nlohmann::json& object, const char* key,
                                                 uint64_t default_value) {
    if (!object.is_object()) {
        return std::nullopt;
    }
    if (!object.contains(key)) {
        return default_value;
    }
    const auto& value = object.at(key);
    if (value.is_number_unsigned()) {
        return value.get<uint64_t>();
    }
    if (value.is_number_integer()) {
        const int64_t signed_value = value.get<int64_t>();
        if (signed_value >= 0) {
            return static_cast<uint64_t>(signed_value);
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<Config> parse_config(const std::string& json_text) {
    Config cfg;  // 필드별 기본값에서 시작 — 없는 키는 기본값 유지
    try {
        const auto j = nlohmann::json::parse(json_text);
        // 키가 없으면 빈 객체를 대신 써서 안쪽 value()가 기본값을 돌려주게 한다 (가드 중첩 제거).
        const auto rules = j.value("rules", nlohmann::json::object());
        const auto port_scan = rules.value("port_scan", nlohmann::json::object());
        const auto syn_flood = rules.value("syn_flood", nlohmann::json::object());

        const auto queue_num = read_nonnegative_integer(j, "queue_num", cfg.queue_num);
        const auto block_ttl_seconds =
            read_nonnegative_integer(j, "block_ttl_seconds", cfg.block_ttl_seconds);
        const auto window_seconds =
            read_nonnegative_integer(rules, "window_seconds", cfg.window_seconds);
        const auto distinct_port_threshold = read_nonnegative_integer(
            port_scan, "distinct_port_threshold", cfg.distinct_port_threshold);
        const auto syn_threshold =
            read_nonnegative_integer(syn_flood, "syn_threshold", cfg.syn_threshold);

        if (!queue_num.has_value() || !block_ttl_seconds.has_value() ||
            !window_seconds.has_value() || !distinct_port_threshold.has_value() ||
            !syn_threshold.has_value()) {
            LOG(ERROR) << "config.json 정수 필드 타입 오류";
            return std::nullopt;
        }

        cfg.whitelist = j.value("whitelist", cfg.whitelist);

        // 목적지 포트는 uint16_t이므로 한 창에서 구분 가능한 포트는 0~65535의 65536개다.
        constexpr uint64_t MAX_DISTINCT_PORT_COUNT =
            static_cast<uint64_t>(std::numeric_limits<uint16_t>::max()) + 1;
        if (*queue_num > std::numeric_limits<uint16_t>::max() || *block_ttl_seconds == 0 ||
            *block_ttl_seconds > std::numeric_limits<int>::max() || *window_seconds == 0 ||
            *window_seconds > std::numeric_limits<int>::max() || *distinct_port_threshold == 0 ||
            *distinct_port_threshold > MAX_DISTINCT_PORT_COUNT || *syn_threshold == 0 ||
            *syn_threshold > std::numeric_limits<uint32_t>::max()) {
            LOG(ERROR) << "config.json 값 범위 오류";
            return std::nullopt;
        }

        cfg.queue_num = static_cast<uint16_t>(*queue_num);
        cfg.block_ttl_seconds = static_cast<int>(*block_ttl_seconds);
        cfg.window_seconds = static_cast<int>(*window_seconds);
        cfg.distinct_port_threshold = static_cast<size_t>(*distinct_port_threshold);
        cfg.syn_threshold = static_cast<uint32_t>(*syn_threshold);
    } catch (const nlohmann::json::exception& e) {
        LOG(ERROR) << "config.json 파싱 실패: " << e.what();
        return std::nullopt;  // 깨진 설정으로 조용히 도는 것보다 시작 중단이 안전
    }
    return cfg;
}

std::optional<Config> load_config(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        LOG(WARNING) << "config.json 없음 (" << path << ") — 기본값으로 동작";
        return Config{};  // 파일 없음은 fail-open (일단 돌려보기)
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return parse_config(ss.str());
}
