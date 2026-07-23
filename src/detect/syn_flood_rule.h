#ifndef IPS_SRC_DETECT_SYN_FLOOD_RULE_H_
#define IPS_SRC_DETECT_SYN_FLOOD_RULE_H_

#include <cstdint>

#include "detect/rule.h"

// 창 안의 SYN(플래그 선) 패킷 수가 임계 이상이면 SYN 플러드로 판정.
class SynFloodRule : public Rule {
 public:
    explicit SynFloodRule(uint32_t syn_threshold);
    const char* name() const override;
    bool is_match(const SourceStats& stats) const override;

 private:
    const uint32_t threshold_;
};

#endif  // IPS_SRC_DETECT_SYN_FLOOD_RULE_H_
