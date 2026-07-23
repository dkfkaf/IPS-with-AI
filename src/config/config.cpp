#include "config/config.h"

#include <fstream>
#include <sstream>

#include <glog/logging.h>
#include <nlohmann/json.hpp>

std::optional<Config> parse_config(const std::string& json_text) {
    Config cfg;  // 필드별 기본값에서 시작 — 없는 키는 기본값 유지
    try {
        const auto j = nlohmann::json::parse(json_text);
        cfg.queue_num = j.value("queue_num", cfg.queue_num);
        cfg.block_ttl_seconds = j.value("block_ttl_seconds", cfg.block_ttl_seconds);
        cfg.whitelist = j.value("whitelist", cfg.whitelist);
        // 키가 없으면 빈 객체를 대신 써서 안쪽 value()가 기본값을 돌려주게 한다 (가드 중첩 제거).
        const auto rules = j.value("rules", nlohmann::json::object());
        cfg.window_seconds = rules.value("window_seconds", cfg.window_seconds);
        cfg.distinct_port_threshold = rules.value("port_scan", nlohmann::json::object())
                                          .value("distinct_port_threshold", cfg.distinct_port_threshold);
        cfg.syn_threshold = rules.value("syn_flood", nlohmann::json::object())
                                .value("syn_threshold", cfg.syn_threshold);
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
