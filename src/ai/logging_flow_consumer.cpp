#include "ai/logging_flow_consumer.h"

#include <sstream>

#include <glog/logging.h>

#include "ai/flow_features.h"

bool LoggingFlowConsumer::consume(FlowRecord record) {
    std::ostringstream features;
    for (size_t index = 0; index < record.features.size(); ++index) {
        if (index > 0) {
            features << ',';
        }
        features << record.features[index];
    }

    LOG(INFO) << "AI_FLOW_READY flow_id=" << record.flow_id
              << " reason=" << flow_end_reason_to_string(record.end_reason)
              << " tuple=" << record.key.to_string()
              << " feature_schema=" << record.feature_schema_version
              << " first_seen_ms=" << record.first_seen_ms
              << " last_seen_ms=" << record.last_seen_ms << " features=[" << features.str() << ']';
    return true;
}
