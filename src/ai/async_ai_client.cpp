#include "ai/async_ai_client.h"

#include <exception>
#include <memory>
#include <utility>

#include <glog/logging.h>
#include <zmq.hpp>

#include "ai/ai_protocol.h"

namespace {

constexpr auto LOG_INTERVAL = std::chrono::seconds(60);

}  // namespace

AsyncAiClient::AsyncAiClient(const AiConfig& config,
                             TransportFailureHandler failure_handler)
    : queue_capacity_(config.queue_capacity),
      response_timeout_ms_(config.response_timeout_ms),
      failure_handler_(std::move(failure_handler)) {}

AsyncAiClient::~AsyncAiClient() {
    stop();
}

void AsyncAiClient::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (started_ || stop_requested_) {
        return;
    }
    started_ = true;
    worker_ = std::thread(&AsyncAiClient::run, this);
}

void AsyncAiClient::set_online(std::string endpoint, std::string model_version) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (stop_requested_) {
        return;
    }
    endpoint_ = std::move(endpoint);
    model_version_ = std::move(model_version);
    ++connection_generation_;
    pending_flows_.clear();
    pending_decisions_.clear();
    online_ = true;
    condition_.notify_all();
}

void AsyncAiClient::set_offline() {
    std::lock_guard<std::mutex> lock(mutex_);
    online_ = false;
    ++connection_generation_;
    pending_flows_.clear();
    pending_decisions_.clear();
    condition_.notify_all();
}

void AsyncAiClient::stop() {
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_requested_ = true;
        online_ = false;
        ++connection_generation_;
        pending_flows_.clear();
        pending_decisions_.clear();
        condition_.notify_all();
        if (!started_) {
            return;
        }
        started_ = false;
        worker = std::move(worker_);
    }
    if (worker.joinable()) {
        worker.join();
    }
}

bool AsyncAiClient::consume(FlowRecord record) {
    bool unavailable = false;
    bool queue_full = false;
    uint64_t dropped = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        if (!online_ || stop_requested_) {
            dropped = unavailable_dropped_.fetch_add(1, std::memory_order_relaxed) + 1;
            unavailable = !unavailable_logged_ || now - last_unavailable_log_ >= LOG_INTERVAL;
            if (unavailable) {
                unavailable_logged_ = true;
                last_unavailable_log_ = now;
            }
        } else if (pending_flows_.size() >= queue_capacity_) {
            dropped = queue_full_dropped_.fetch_add(1, std::memory_order_relaxed) + 1;
            queue_full = !queue_full_logged_ || now - last_queue_full_log_ >= LOG_INTERVAL;
            if (queue_full) {
                queue_full_logged_ = true;
                last_queue_full_log_ = now;
            }
        } else {
            pending_flows_.push_back(std::move(record));
            submitted_.fetch_add(1, std::memory_order_relaxed);
            condition_.notify_one();
            return true;
        }
    }
    if (unavailable) {
        LOG(WARNING) << "AI_UNAVAILABLE dropped_total=" << dropped;
    } else if (queue_full) {
        LOG(WARNING) << "AI_QUEUE_FULL dropped_total=" << dropped;
    }
    return false;
}

std::vector<AiDecision> AsyncAiClient::drain_decisions() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<AiDecision> drained;
    drained.reserve(pending_decisions_.size());
    while (!pending_decisions_.empty()) {
        drained.push_back(std::move(pending_decisions_.front()));
        pending_decisions_.pop_front();
    }
    condition_.notify_all();
    return drained;
}

AiClientStatsSnapshot AsyncAiClient::stats() const {
    AiClientStatsSnapshot snapshot;
    snapshot.submitted = submitted_.load(std::memory_order_relaxed);
    snapshot.unavailable_dropped = unavailable_dropped_.load(std::memory_order_relaxed);
    snapshot.queue_full_dropped = queue_full_dropped_.load(std::memory_order_relaxed);
    snapshot.normal_responses = normal_responses_.load(std::memory_order_relaxed);
    snapshot.anomaly_responses = anomaly_responses_.load(std::memory_order_relaxed);
    snapshot.protocol_errors = protocol_errors_.load(std::memory_order_relaxed);
    snapshot.timeouts = timeouts_.load(std::memory_order_relaxed);
    return snapshot;
}

void AsyncAiClient::fail_transport(const std::string& reason, bool timed_out,
                                   uint64_t failed_generation) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!online_ || connection_generation_ != failed_generation) {
            return;
        }
        online_ = false;
        ++connection_generation_;
        pending_flows_.clear();
        pending_decisions_.clear();
        condition_.notify_all();
    }
    if (timed_out) {
        timeouts_.fetch_add(1, std::memory_order_relaxed);
    }
    if (failure_handler_) {
        try {
            failure_handler_(reason);
        } catch (const std::exception& error) {
            LOG(ERROR) << "AI failure handler 오류: " << error.what();
        }
    }
}

void AsyncAiClient::run() {
    zmq::context_t context(1);
    std::unique_ptr<zmq::socket_t> socket;
    uint64_t socket_generation = 0;

    while (true) {
        FlowRecord in_flight;
        std::string endpoint;
        std::string model_version;
        uint64_t generation = 0;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [this] {
                return stop_requested_ || (online_ && !pending_flows_.empty());
            });
            if (stop_requested_) {
                break;
            }
            generation = connection_generation_;
            endpoint = endpoint_;
            model_version = model_version_;
            in_flight = std::move(pending_flows_.front());
            pending_flows_.pop_front();
        }

        try {
            if (!socket || socket_generation != generation) {
                socket.reset();
                socket = std::make_unique<zmq::socket_t>(context, zmq::socket_type::req);
                socket->set(zmq::sockopt::linger, 0);
                socket->set(zmq::sockopt::immediate, 1);
                socket->set(zmq::sockopt::sndtimeo, response_timeout_ms_);
                socket->set(zmq::sockopt::rcvtimeo, response_timeout_ms_);
                socket->connect(endpoint);
                socket_generation = generation;
            }

            const auto request_started = std::chrono::steady_clock::now();
            const std::string request = serialize_flow_request(in_flight);
            if (!socket->send(zmq::buffer(request), zmq::send_flags::none)) {
                socket.reset();
                fail_transport("AI 요청 전송 시간 초과", true, generation);
                continue;
            }
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - request_started);
            const int remaining_timeout =
                response_timeout_ms_ - static_cast<int>(elapsed.count());
            if (remaining_timeout <= 0) {
                socket.reset();
                fail_transport("AI 요청 전체 시간 초과", true, generation);
                continue;
            }
            socket->set(zmq::sockopt::rcvtimeo, remaining_timeout);
            zmq::message_t reply;
            if (!socket->recv(reply, zmq::recv_flags::none)) {
                socket.reset();
                fail_transport("AI 응답 시간 초과", true, generation);
                continue;
            }

            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!online_ || connection_generation_ != generation) {
                    socket.reset();
                    continue;
                }
            }
            const std::string response(static_cast<const char*>(reply.data()), reply.size());
            std::string protocol_error;
            auto parsed = parse_ai_response(response, in_flight.flow_id, model_version,
                                            &protocol_error);
            if (!parsed.has_value() || !parsed->ok) {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!online_ || connection_generation_ != generation) {
                        socket.reset();
                        continue;
                    }
                }
                protocol_errors_.fetch_add(1, std::memory_order_relaxed);
                LOG(ERROR) << "AI_PROTOCOL_ERROR flow_id=" << in_flight.flow_id << " reason="
                           << (parsed.has_value() ? parsed->error_code : protocol_error);
                continue;
            }
            if (!parsed->anomaly) {
                std::lock_guard<std::mutex> lock(mutex_);
                if (online_ && connection_generation_ == generation) {
                    normal_responses_.fetch_add(1, std::memory_order_relaxed);
                }
                continue;
            }

            AiDecision decision{std::move(in_flight), true, parsed->score, parsed->threshold,
                                parsed->model_version};
            std::unique_lock<std::mutex> lock(mutex_);
            condition_.wait(lock, [this, generation] {
                return stop_requested_ || !online_ || connection_generation_ != generation ||
                       pending_decisions_.size() < queue_capacity_;
            });
            if (stop_requested_ || !online_ || connection_generation_ != generation) {
                socket.reset();
                continue;
            }
            pending_decisions_.push_back(std::move(decision));
            anomaly_responses_.fetch_add(1, std::memory_order_relaxed);
        } catch (const zmq::error_t& error) {
            socket.reset();
            fail_transport(std::string("ZeroMQ 오류: ") + error.what(), false, generation);
        } catch (const std::exception& error) {
            socket.reset();
            fail_transport(std::string("AI client 오류: ") + error.what(), false, generation);
        }
    }
    socket.reset();
    context.close();
}
