#ifndef IPS_SRC_AI_ASYNC_AI_CLIENT_H_
#define IPS_SRC_AI_ASYNC_AI_CLIENT_H_

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ai/ai_types.h"
#include "ai/flow_consumer.h"
#include "config/config.h"

class AsyncAiClient final : public FlowConsumer {
 public:
    using TransportFailureHandler = std::function<void(const std::string&)>;

    AsyncAiClient(const AiConfig& config, TransportFailureHandler failure_handler);
    ~AsyncAiClient() override;

    AsyncAiClient(const AsyncAiClient&) = delete;
    AsyncAiClient& operator=(const AsyncAiClient&) = delete;

    void start();
    void set_online(std::string endpoint, std::string model_version);
    void set_offline();
    void stop();

    bool consume(FlowRecord record) override;
    std::vector<AiDecision> drain_decisions() override;
    AiClientStatsSnapshot stats() const;

 private:
    void run();
    void fail_transport(const std::string& reason, bool timed_out,
                        uint64_t failed_generation);

    const size_t queue_capacity_;
    const int response_timeout_ms_;
    TransportFailureHandler failure_handler_;

    mutable std::mutex mutex_;
    std::condition_variable condition_;
    std::deque<FlowRecord> pending_flows_;
    std::deque<AiDecision> pending_decisions_;
    std::thread worker_;
    bool started_ = false;
    bool stop_requested_ = false;
    bool online_ = false;
    uint64_t connection_generation_ = 0;
    std::string endpoint_;
    std::string model_version_;
    bool unavailable_logged_ = false;
    bool queue_full_logged_ = false;
    std::chrono::steady_clock::time_point last_unavailable_log_;
    std::chrono::steady_clock::time_point last_queue_full_log_;

    std::atomic<uint64_t> submitted_{0};
    std::atomic<uint64_t> unavailable_dropped_{0};
    std::atomic<uint64_t> queue_full_dropped_{0};
    std::atomic<uint64_t> normal_responses_{0};
    std::atomic<uint64_t> anomaly_responses_{0};
    std::atomic<uint64_t> protocol_errors_{0};
    std::atomic<uint64_t> timeouts_{0};
};

#endif  // IPS_SRC_AI_ASYNC_AI_CLIENT_H_
