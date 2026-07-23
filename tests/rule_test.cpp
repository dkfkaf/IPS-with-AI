#include "detect/port_scan_rule.h"
#include "detect/rule_engine.h"
#include "detect/syn_flood_rule.h"

#include <memory>

#include <gtest/gtest.h>

#include "flow/flow.h"

namespace {
SourceStats with(size_t ports, uint32_t syns) {
    SourceStats s;
    for (uint16_t p = 0; p < ports; ++p) {
        s.recent_dst_ports.insert(p);
    }
    s.syn_count = syns;
    return s;
}
}  // namespace

TEST(PortScanRuleTest, MatchesAtThreshold) {
    PortScanRule rule(20);
    EXPECT_FALSE(rule.is_match(with(19, 0)));  // 임계 미만
    EXPECT_TRUE(rule.is_match(with(20, 0)));   // 임계 도달
}

TEST(SynFloodRuleTest, MatchesAtThreshold) {
    SynFloodRule rule(100);
    EXPECT_FALSE(rule.is_match(with(0, 99)));
    EXPECT_TRUE(rule.is_match(with(0, 100)));
}

TEST(RuleEngineTest, ReturnsFirstMatchingRuleOrNull) {
    RuleEngine engine;
    engine.add_rule(std::make_unique<PortScanRule>(20));
    engine.add_rule(std::make_unique<SynFloodRule>(100));
    EXPECT_EQ(engine.check(with(5, 5)), nullptr);  // 아무 규칙도 안 걸림
    const Rule* hit = engine.check(with(25, 5));   // 포트 스캔 걸림
    ASSERT_NE(hit, nullptr);
    EXPECT_STREQ(hit->name(), "port_scan");
}
