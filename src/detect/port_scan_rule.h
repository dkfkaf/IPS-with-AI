#ifndef IPS_SRC_DETECT_PORT_SCAN_RULE_H_
#define IPS_SRC_DETECT_PORT_SCAN_RULE_H_

#include <cstddef>

#include "detect/rule.h"

// 창 안에서 접촉한 목적지 포트 수가 임계 이상이면 포트 스캔으로 판정.
class PortScanRule : public Rule {
 public:
    explicit PortScanRule(size_t distinct_port_threshold);
    const char* name() const override;
    bool is_match(const SourceStats& stats) const override;

 private:
    const size_t threshold_;
};

#endif  // IPS_SRC_DETECT_PORT_SCAN_RULE_H_
