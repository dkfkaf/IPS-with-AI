#ifndef IPS_SRC_AI_AI_PROTOCOL_H_
#define IPS_SRC_AI_AI_PROTOCOL_H_

#include <optional>
#include <string>

#include "ai/ai_types.h"
#include "ai/flow_record.h"

std::string serialize_flow_request(const FlowRecord& record);

std::optional<AiResponse> parse_ai_response(const std::string& json_text,
                                            const std::string& expected_flow_id,
                                            const std::string& expected_model_version,
                                            std::string* error);

#endif  // IPS_SRC_AI_AI_PROTOCOL_H_
