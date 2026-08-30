#ifndef IPS_SRC_CONFIG_CONFIG_H_
#define IPS_SRC_CONFIG_CONFIG_H_

#include <cstddef>  // size_t
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct AiConfig {
    bool enabled = true;
    std::string artifact_dir = "ml/artifacts";
    size_t queue_capacity = 1024;
    int startup_timeout_ms = 10000;
    int response_timeout_ms = 2000;
    int max_restarts = 3;
    int restart_reset_seconds = 60;
};

// config.json에서 읽는 설정. 기본값은 파일이 없을 때 그대로 쓰인다.
struct Config {
    uint16_t queue_num = 0;
    int block_ttl_seconds = 600;
    std::vector<std::string> whitelist;
    int window_seconds = 10;
    size_t distinct_port_threshold = 20;
    uint32_t syn_threshold = 100;
    AiConfig ai;
};

// JSON 텍스트를 파싱한다. 문법 오류·타입 불일치면 nullopt (호출자는 시작을 중단).
std::optional<Config> parse_config(const std::string& json_text);

// 파일을 읽어 파싱한다. 파일이 없으면 기본값 Config(경고 로그), 깨졌으면 nullopt.
std::optional<Config> load_config(const std::string& path);

#endif  // IPS_SRC_CONFIG_CONFIG_H_
