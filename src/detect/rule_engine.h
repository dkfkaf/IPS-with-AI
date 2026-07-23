#ifndef IPS_SRC_DETECT_RULE_ENGINE_H_
#define IPS_SRC_DETECT_RULE_ENGINE_H_

#include <memory>
#include <vector>

#include "detect/rule.h"
#include "flow/flow.h"

// 규칙 목록을 순회하며 처음 걸린 규칙을 돌려준다.
class RuleEngine {
 public:
    void add_rule(std::unique_ptr<Rule> rule);
    const Rule* check(const SourceStats& stats) const;  // 걸린 규칙 또는 nullptr

 private:
    std::vector<std::unique_ptr<Rule>> rules_;
};

#endif  // IPS_SRC_DETECT_RULE_ENGINE_H_
