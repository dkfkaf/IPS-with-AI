#include "detect/syn_flood_rule.h"

SynFloodRule::SynFloodRule(uint32_t syn_threshold) : threshold_(syn_threshold) {}

const char* SynFloodRule::name() const { return "syn_flood"; }

bool SynFloodRule::is_match(const SourceStats& stats) const {
    return stats.syn_count >= threshold_;
}
