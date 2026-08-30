#include "app/application_controller.h"

#include <exception>
#include <sstream>
#include <system_error>
#include <utility>

#include <QCoreApplication>
#include <QMetaObject>

#include <glog/logging.h>

#include "ai/async_ai_client.h"
#include "app/ai_process_supervisor.h"
#include "capture/packet_capture.h"
#include "ui/tray_controller.h"

namespace {

const char* ai_state_to_string(AiState state) {
    switch (state) {
        case AiState::DISABLED:
            return "DISABLED";
        case AiState::STARTING:
            return "STARTING";
        case AiState::ONLINE:
            return "ONLINE";
        case AiState::RESTART_WAIT:
            return "RESTART_WAIT";
        case AiState::OFFLINE:
            return "OFFLINE";
        case AiState::STOPPING:
            return "STOPPING";
    }
    return "UNKNOWN";
}

}  // namespace

ApplicationController::ApplicationController(Config config, Whitelist whitelist,
                                             QObject* parent)
    : QObject(parent),
      config_(std::move(config)),
      started_at_(std::chrono::steady_clock::now()) {
    tray_ = std::make_unique<TrayController>([this] { show_status(); },
                                             [this] { begin_shutdown(0); });

    auto ai_client = std::make_unique<AsyncAiClient>(
        config_.ai, [this](const std::string& reason) { post_transport_failure(reason); });
    ai_client_ = ai_client.get();
    capture_ = std::make_unique<PacketCapture>(
        config_, std::move(whitelist), std::move(ai_client),
        [this](const AiBlockEvent& event) { post_ai_block(event); });

    supervisor_ = std::make_unique<AiProcessSupervisor>(
        config_.ai,
        [this](const std::string& endpoint, const std::string& model_version) {
            ai_client_->set_online(endpoint, model_version);
            tray_->set_ai_state(AiState::ONLINE, model_version);
        },
        [this](AiState state, const std::string& detail) {
            if (state == AiState::ONLINE) {
                return;
            }
            ai_client_->set_offline();
            tray_->set_ai_state(state, detail);
            if (state == AiState::OFFLINE) {
                tray_->show_ai_offline(detail);
            }
        });
}

ApplicationController::~ApplicationController() {
    begin_shutdown(0);
}

bool ApplicationController::start() {
    if (started_ || stopping_) {
        return false;
    }
    started_ = true;
    ai_client_->start();
    try {
        capture_thread_ = std::thread([this] {
            const bool ok = capture_->start();
            post_capture_result(ok);
        });
    } catch (const std::system_error& error) {
        LOG(ERROR) << "캡처 스레드 시작 실패: " << error.what();
        ai_client_->stop();
        started_ = false;
        return false;
    }
    supervisor_->start();
    return true;
}

void ApplicationController::post_transport_failure(const std::string& reason) {
    QMetaObject::invokeMethod(
        this,
        [this, reason] {
            if (!stopping_) {
                supervisor_->report_transport_failure(reason);
            }
        },
        Qt::QueuedConnection);
}

void ApplicationController::post_ai_block(const AiBlockEvent& event) {
    QMetaObject::invokeMethod(
        this,
        [this, event] {
            if (!stopping_) {
                tray_->show_ai_block(event);
            }
        },
        Qt::QueuedConnection);
}

void ApplicationController::post_capture_result(bool ok) {
    QMetaObject::invokeMethod(
        this,
        [this, ok] {
            if (!stopping_ && !ok) {
                LOG(ERROR) << "패킷 캡처가 오류로 종료됨";
                begin_shutdown(1);
            }
        },
        Qt::QueuedConnection);
}

void ApplicationController::begin_shutdown(int exit_code) {
    if (stopping_) {
        return;
    }
    stopping_ = true;
    tray_->set_ai_state(AiState::STOPPING, "종료 중");
    capture_->stop();
    ai_client_->stop();
    supervisor_->stop();
    if (capture_thread_.joinable()) {
        capture_thread_.join();
    }
    QCoreApplication::exit(exit_code);
}

void ApplicationController::show_status() {
    tray_->show_status(format_status());
}

std::string ApplicationController::format_status() const {
    const AiSupervisorSnapshot supervisor = supervisor_->snapshot();
    const AiClientStatsSnapshot client = ai_client_->stats();
    const CaptureStatsSnapshot capture = capture_->capture_stats();
    const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                            std::chrono::steady_clock::now() - started_at_)
                            .count();
    const uint64_t dropped = client.unavailable_dropped + client.queue_full_dropped;

    std::ostringstream status;
    status << "AI 상태: " << ai_state_to_string(supervisor.state) << '\n'
           << "모델 버전: "
           << (supervisor.model_version.empty() ? "-" : supervisor.model_version) << '\n'
           << "가동 시간: " << uptime << "초\n"
           << "Python 재시작: " << supervisor.restart_count << '\n'
           << "AI 전송/폐기: " << client.submitted << '/' << dropped << '\n'
           << "정상/이상 응답: " << client.normal_responses << '/'
           << client.anomaly_responses << '\n'
           << "Rule 차단: " << capture.rule_blocks << '\n'
           << "AI 신규 차단/중복/화이트리스트 제외: " << capture.ai_new_blocks << '/'
           << capture.ai_duplicates << '/' << capture.ai_whitelisted << '\n'
           << "프로토콜 오류/타임아웃: " << client.protocol_errors << '/'
           << client.timeouts;
    return status.str();
}
