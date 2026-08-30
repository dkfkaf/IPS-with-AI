#ifndef IPS_SRC_AI_AI_TYPES_H_
#define IPS_SRC_AI_AI_TYPES_H_

#include <cstdint>
#include <string>

#include "ai/flow_record.h"

enum class AiState { DISABLED, STARTING, ONLINE, RESTART_WAIT, OFFLINE, STOPPING };

struct AiResponse {
    bool ok = false;
    std::string flow_id;
    std::string model_version;
    bool anomaly = false;
    double score = 0.0;
    double threshold = 0.0;
    std::string error_code;
};

struct AiDecision {
    FlowRecord record{};
    bool anomaly = false;
    double score = 0.0;
    double threshold = 0.0;
    std::string model_version;
};

struct AiBlockEvent {
    std::string flow_id;
    uint32_t source_ip = 0;
    double score = 0.0;
    double threshold = 0.0;
    int ttl_seconds = 0;
    std::string model_version;
};

struct AiClientStatsSnapshot {
    uint64_t submitted = 0;
    uint64_t unavailable_dropped = 0;
    uint64_t queue_full_dropped = 0;
    uint64_t normal_responses = 0;
    uint64_t anomaly_responses = 0;
    uint64_t protocol_errors = 0;
    uint64_t timeouts = 0;
};

struct CaptureStatsSnapshot {
    uint64_t rule_blocks = 0;
    uint64_t ai_new_blocks = 0;
    uint64_t ai_duplicates = 0;
    uint64_t ai_whitelisted = 0;
};

#endif  // IPS_SRC_AI_AI_TYPES_H_
