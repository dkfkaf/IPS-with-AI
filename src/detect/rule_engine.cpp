#include "detect/rule_engine.h"

#include <utility>

void RuleEngine::add_rule(std::unique_ptr<Rule> rule) {
    rules_.push_back(std::move(rule));
}

const Rule* RuleEngine::check(const SourceStats& stats) const {
    for (const auto& rule : rules_) {
        if (rule->is_match(stats)) {
            return rule.get();
        }
    }
    return nullptr;
}
