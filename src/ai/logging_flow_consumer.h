#ifndef IPS_SRC_AI_LOGGING_FLOW_CONSUMER_H_
#define IPS_SRC_AI_LOGGING_FLOW_CONSUMER_H_

#include "ai/flow_consumer.h"

class LoggingFlowConsumer : public FlowConsumer {
 public:
    bool consume(FlowRecord record) override;
};

#endif  // IPS_SRC_AI_LOGGING_FLOW_CONSUMER_H_
