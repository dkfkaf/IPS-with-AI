#include "detect/port_scan_rule.h"

PortScanRule::PortScanRule(size_t distinct_port_threshold) : threshold_(distinct_port_threshold) {}

const char* PortScanRule::name() const { return "port_scan"; }

bool PortScanRule::is_match(const SourceStats& stats) const {
    return stats.recent_dst_ports.size() >= threshold_;
}
