#ifndef IPS_SRC_AI_FLOW_FEATURES_H_
#define IPS_SRC_AI_FLOW_FEATURES_H_

#include <array>

#include "ai/flow_record.h"
#include "flow/flow.h"

// ml/features.py와 같은 순서·단위로 CICFlowMeter 호환 특징을 만든다.
std::array<double, FLOW_FEATURE_COUNT> flow_to_features(const Flow& flow);
const char* flow_end_reason_to_string(FlowEndReason reason);

#endif  // IPS_SRC_AI_FLOW_FEATURES_H_
