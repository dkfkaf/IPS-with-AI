#include "config/config.h"
#include "response/whitelist.h"

#include <arpa/inet.h>

#include <string>
#include <vector>

#include <gtest/gtest.h>

TEST(ConfigTest, ParsesValidJson) {
    const auto cfg = parse_config(R"({
        "queue_num": 3, "block_ttl_seconds": 300,
        "whitelist": ["127.0.0.1"],
        "rules": { "window_seconds": 5,
                   "port_scan": {"distinct_port_threshold": 15},
                   "syn_flood": {"syn_threshold": 50} }
    })");
    ASSERT_TRUE(cfg.has_value());
    EXPECT_EQ(cfg->queue_num, 3);
    EXPECT_EQ(cfg->block_ttl_seconds, 300);
    EXPECT_EQ(cfg->window_seconds, 5);
    EXPECT_EQ(cfg->distinct_port_threshold, 15u);
    EXPECT_EQ(cfg->syn_threshold, 50u);
    ASSERT_EQ(cfg->whitelist.size(), 1u);
    EXPECT_EQ(cfg->whitelist[0], "127.0.0.1");
}

TEST(ConfigTest, BrokenJsonReturnsNullopt) {
    EXPECT_FALSE(parse_config("{ not valid json ").has_value());  // 호출자는 fail-fast
}

TEST(ConfigTest, MissingFileYieldsDefaults) {
    const auto cfg = load_config("/nonexistent/path/config.json");
    ASSERT_TRUE(cfg.has_value());  // 파일 없음 → 기본값
    EXPECT_EQ(cfg->block_ttl_seconds, 600);
    EXPECT_EQ(cfg->distinct_port_threshold, 20u);
    EXPECT_EQ(cfg->syn_threshold, 100u);
}

TEST(ConfigTest, ParsesAiConfiguration) {
    const auto cfg = parse_config(R"({
        "ai": {
            "enabled": false,
            "artifact_dir": "/opt/ips/artifacts",
            "queue_capacity": 2048,
            "startup_timeout_ms": 15000,
            "response_timeout_ms": 2500,
            "max_restarts": 5,
            "restart_reset_seconds": 120
        }
    })");

    ASSERT_TRUE(cfg.has_value());
    EXPECT_FALSE(cfg->ai.enabled);
    EXPECT_EQ(cfg->ai.artifact_dir, "/opt/ips/artifacts");
    EXPECT_EQ(cfg->ai.queue_capacity, 2048u);
    EXPECT_EQ(cfg->ai.startup_timeout_ms, 15000);
    EXPECT_EQ(cfg->ai.response_timeout_ms, 2500);
    EXPECT_EQ(cfg->ai.max_restarts, 5);
    EXPECT_EQ(cfg->ai.restart_reset_seconds, 120);
}

TEST(ConfigTest, AppliesAiDefaultsWhenObjectIsMissing) {
    const auto cfg = parse_config("{}");

    ASSERT_TRUE(cfg.has_value());
    EXPECT_TRUE(cfg->ai.enabled);
    EXPECT_EQ(cfg->ai.artifact_dir, "ml/artifacts");
    EXPECT_EQ(cfg->ai.queue_capacity, 1024u);
    EXPECT_EQ(cfg->ai.startup_timeout_ms, 10000);
    EXPECT_EQ(cfg->ai.response_timeout_ms, 2000);
    EXPECT_EQ(cfg->ai.max_restarts, 3);
    EXPECT_EQ(cfg->ai.restart_reset_seconds, 60);
}

TEST(ConfigTest, RejectsInvalidAiConfiguration) {
    const std::vector<std::string> invalid_configs = {
        R"({"ai":[]})",
        R"({"ai":{"enabled":1}})",
        R"({"ai":{"artifact_dir":""}})",
        R"({"ai":{"queue_capacity":0}})",
        R"({"ai":{"queue_capacity":65537}})",
        R"({"ai":{"startup_timeout_ms":999}})",
        R"({"ai":{"response_timeout_ms":99}})",
        R"({"ai":{"max_restarts":11}})",
        R"({"ai":{"restart_reset_seconds":0}})",
        R"({"ai":{"restart_reset_seconds":3601}})",
        R"({"ai":{"queue_capacity":-1}})",
    };

    for (const std::string& json : invalid_configs) {
        EXPECT_FALSE(parse_config(json).has_value()) << json;
    }
}

TEST(WhitelistTest, MatchesNetworkOrderIp) {
    Whitelist wl;
    ASSERT_TRUE(wl.load({"192.168.56.1"}));
    struct in_addr addr;
    inet_pton(AF_INET, "192.168.56.1", &addr);  // 파서 src_ip와 같은 네트워크 순서
    EXPECT_TRUE(wl.is_whitelisted(addr.s_addr));
    EXPECT_FALSE(wl.is_whitelisted(0));
}

TEST(WhitelistTest, RejectsMalformedIp) {
    Whitelist wl;
    EXPECT_FALSE(wl.load({"192.168.56.999"}));  // 잘못된 IP → load 실패 (호출자 fail-fast)
}
