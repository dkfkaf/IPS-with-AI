#ifndef IPS_SRC_AI_FLOW_CONSUMER_H_
#define IPS_SRC_AI_FLOW_CONSUMER_H_

#include <vector>

#include "ai/ai_types.h"

class FlowConsumer {
 public:
    virtual ~FlowConsumer() = default;

    // 패킷 verdict를 지연시키지 않도록 즉시 반환한다. 큐 포화 등 거부 시 false.
    virtual bool consume(FlowRecord record) = 0;
    virtual std::vector<AiDecision> drain_decisions() { return {}; }
};

#endif  // IPS_SRC_AI_FLOW_CONSUMER_H_
