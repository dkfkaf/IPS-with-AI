#ifndef IPS_SRC_AI_FLOW_RECORD_H_
#define IPS_SRC_AI_FLOW_RECORD_H_

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "common/five_tuple.h"
#include "flow/flow.h"

constexpr size_t FLOW_FEATURE_COUNT = 27;
constexpr uint32_t FLOW_FEATURE_SCHEMA_VERSION = 1;

struct FlowRecord {
    std::string flow_id;
    FiveTuple key;
    int64_t first_seen_ms;
    int64_t last_seen_ms;
    FlowEndReason end_reason;
    uint32_t feature_schema_version;
    std::array<double, FLOW_FEATURE_COUNT> features;
};

#endif  // IPS_SRC_AI_FLOW_RECORD_H_
