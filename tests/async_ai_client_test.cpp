#include "ai/async_ai_client.h"

#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <future>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <zmq.hpp>

namespace {

FlowRecord make_record(std::string flow_id) {
    FlowRecord record{};
    record.flow_id = std::move(flow_id);
    record.end_reason = FlowEndReason::TIMEOUT;
    record.feature_schema_version = FLOW_FEATURE_SCHEMA_VERSION;
    return record;
}

std::string unique_endpoint() {
    static std::atomic<uint64_t> sequence{0};
    return "ipc:///tmp/ips-ai-client-test-" + std::to_string(getpid()) + '-' +
           std::to_string(sequence.fetch_add(1, std::memory_order_relaxed)) + ".sock";
}

std::string anomaly_response(const std::string& flow_id,
                             const std::string& model_version) {
    return nlohmann::json{
        {"schema_version", 1}, {"flow_id", flow_id}, {"model_version", model_version},
        {"ok", true},          {"anomaly", true},    {"score", 2.0},
        {"threshold", 1.0},
    }.dump();
}

class OneShotRepServer {
 public:
    OneShotRepServer(std::string endpoint, std::string expected_flow_id,
                     std::string response)
        : endpoint_(std::move(endpoint)),
          socket_path_(endpoint_.substr(std::string("ipc://").size())),
          expected_flow_id_(std::move(expected_flow_id)),
          response_(std::move(response)),
          ready_future_(ready_signal_.get_future()),
          received_future_(received_signal_.get_future()),
          release_future_(release_signal_.get_future().share()),
          worker_(&OneShotRepServer::run, this) {}

    ~OneShotRepServer() {
        release_reply();
        join();
        std::remove(socket_path_.c_str());
    }

    bool wait_until_ready(std::chrono::milliseconds timeout) {
        return ready_future_.wait_for(timeout) == std::future_status::ready &&
               ready_ok_.load(std::memory_order_acquire);
    }

    bool wait_until_received(std::chrono::milliseconds timeout) {
        return received_future_.wait_for(timeout) == std::future_status::ready &&
               received_ok_.load(std::memory_order_acquire);
    }

    void release_reply() {
        bool expected = false;
        if (released_.compare_exchange_strong(expected, true)) {
            release_signal_.set_value();
        }
    }

    void join() {
        if (worker_.joinable()) {
            worker_.join();
        }
    }

    const std::string& error() const { return error_; }

 private:
    void run() {
        bool ready_signaled = false;
        bool received_signaled = false;
        try {
            std::remove(socket_path_.c_str());
            zmq::context_t context(1);
            zmq::socket_t socket(context, zmq::socket_type::rep);
            socket.set(zmq::sockopt::linger, 0);
            socket.set(zmq::sockopt::rcvtimeo, 5000);
            socket.set(zmq::sockopt::sndtimeo, 5000);
            socket.bind(endpoint_);
            ready_ok_.store(true, std::memory_order_release);
            ready_signal_.set_value();
            ready_signaled = true;

            zmq::message_t request_message;
            if (!socket.recv(request_message, zmq::recv_flags::none)) {
                error_ = "요청 수신 시간 초과";
                received_signal_.set_value();
                received_signaled = true;
                return;
            }
            const std::string request_text(
                static_cast<const char*>(request_message.data()), request_message.size());
            const auto request = nlohmann::json::parse(request_text);
            if (!request.contains("flow_id") ||
                request.at("flow_id").get<std::string>() != expected_flow_id_) {
                error_ = "예상하지 않은 flow_id";
                received_signal_.set_value();
                received_signaled = true;
                return;
            }
            received_ok_.store(true, std::memory_order_release);
            received_signal_.set_value();
            received_signaled = true;

            release_future_.wait();
            if (!socket.send(zmq::buffer(response_), zmq::send_flags::none)) {
                error_ = "응답 전송 시간 초과";
            }
            socket.close();
            context.close();
        } catch (const std::exception& exception) {
            error_ = exception.what();
            if (!ready_signaled) {
                ready_signal_.set_value();
            }
            if (!received_signaled) {
                received_signal_.set_value();
            }
        }
        std::remove(socket_path_.c_str());
    }

    std::string endpoint_;
    std::string socket_path_;
    std::string expected_flow_id_;
    std::string response_;
    std::promise<void> ready_signal_;
    std::promise<void> received_signal_;
    std::promise<void> release_signal_;
    std::future<void> ready_future_;
    std::future<void> received_future_;
    std::shared_future<void> release_future_;
    std::atomic<bool> ready_ok_{false};
    std::atomic<bool> received_ok_{false};
    std::atomic<bool> released_{false};
    std::thread worker_;
    std::string error_;
};

}  // namespace

TEST(AsyncAiClientTest, RejectsFlowWhileOfflineWithoutBlocking) {
    AsyncAiClient client(AiConfig{}, {});

    EXPECT_FALSE(client.consume(make_record("flow-1")));
    const auto stats = client.stats();
    EXPECT_EQ(stats.submitted, 0u);
    EXPECT_EQ(stats.unavailable_dropped, 1u);
}

TEST(AsyncAiClientTest, RejectsNewestFlowWhenBoundedQueueIsFull) {
    AiConfig config;
    config.queue_capacity = 1;
    AsyncAiClient client(config, {});
    client.set_online("inproc://unused", "ae-v1");

    EXPECT_TRUE(client.consume(make_record("flow-1")));
    EXPECT_FALSE(client.consume(make_record("flow-2")));
    const auto stats = client.stats();
    EXPECT_EQ(stats.submitted, 1u);
    EXPECT_EQ(stats.queue_full_dropped, 1u);
}

TEST(AsyncAiClientTest, ReconnectionClearsPreviousGenerationQueue) {
    AiConfig config;
    config.queue_capacity = 1;
    AsyncAiClient client(config, {});
    client.set_online("inproc://first", "ae-v1");
    ASSERT_TRUE(client.consume(make_record("old-flow")));

    client.set_offline();
    client.set_online("inproc://second", "ae-v2");

    EXPECT_TRUE(client.consume(make_record("new-flow")));
    EXPECT_EQ(client.stats().submitted, 2u);
}

TEST(AsyncAiClientTest, DiscardsStaleResponseAfterConnectionGenerationChanges) {
    using std::chrono::milliseconds;
    using std::chrono::steady_clock;

    const std::string first_endpoint = unique_endpoint();
    const std::string second_endpoint = unique_endpoint();
    OneShotRepServer first_server(first_endpoint, "old-flow",
                                  anomaly_response("old-flow", "ae-v1"));
    OneShotRepServer second_server(second_endpoint, "new-flow",
                                   anomaly_response("new-flow", "ae-v2"));
    ASSERT_TRUE(first_server.wait_until_ready(milliseconds(2000)));
    ASSERT_TRUE(second_server.wait_until_ready(milliseconds(2000)));

    AiConfig config;
    config.response_timeout_ms = 2000;
    AsyncAiClient client(config, {});
    client.start();
    client.set_online(first_endpoint, "ae-v1");
    ASSERT_TRUE(client.consume(make_record("old-flow")));
    ASSERT_TRUE(first_server.wait_until_received(milliseconds(2000)));

    client.set_offline();
    client.set_online(second_endpoint, "ae-v2");
    ASSERT_TRUE(client.consume(make_record("new-flow")));
    first_server.release_reply();
    ASSERT_TRUE(second_server.wait_until_received(milliseconds(2000)));
    second_server.release_reply();

    std::vector<AiDecision> decisions;
    const auto deadline = steady_clock::now() + milliseconds(2000);
    while (decisions.empty() && steady_clock::now() < deadline) {
        decisions = client.drain_decisions();
        std::this_thread::sleep_for(milliseconds(10));
    }
    client.stop();
    first_server.join();
    second_server.join();

    EXPECT_TRUE(first_server.error().empty()) << first_server.error();
    EXPECT_TRUE(second_server.error().empty()) << second_server.error();
    ASSERT_EQ(decisions.size(), 1u);
    EXPECT_EQ(decisions.front().record.flow_id, "new-flow");
    EXPECT_EQ(decisions.front().model_version, "ae-v2");
}
