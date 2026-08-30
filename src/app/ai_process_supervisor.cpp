#include "app/ai_process_supervisor.h"

#include <algorithm>
#include <exception>
#include <utility>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QProcessEnvironment>
#include <QStringList>

#include <glog/logging.h>
#include <nlohmann/json.hpp>

namespace {

int restart_delay_ms(int attempt_index) {
    constexpr int MAX_RESTART_DELAY_MS = 4000;
    return std::min(1000 * (1 << std::min(attempt_index, 2)), MAX_RESTART_DELAY_MS);
}

}  // namespace

AiProcessSupervisor::AiProcessSupervisor(const AiConfig& config,
                                         ReadyHandler ready_handler,
                                         StateHandler state_handler, QObject* parent)
    : QObject(parent),
      config_(config),
      ready_handler_(std::move(ready_handler)),
      state_handler_(std::move(state_handler)),
      process_(this),
      startup_timer_(this),
      restart_timer_(this),
      stable_timer_(this) {
    socket_path_ = "/tmp/ips-with-ai-" +
                   std::to_string(QCoreApplication::applicationPid()) + ".sock";
    endpoint_ = "ipc://" + socket_path_;
    process_.setProgram("/usr/bin/python3");
    process_.setArguments({"-m", "ml.online_server", "--endpoint",
                           QString::fromStdString(endpoint_), "--artifact-dir",
                           QString::fromStdString(config_.artifact_dir)});
    process_.setWorkingDirectory(QDir::currentPath());
    process_.setProcessChannelMode(QProcess::SeparateChannels);

    QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
    environment.insert("PYTHONNOUSERSITE", "1");
    environment.insert("PYTHONPATH",
                       "/opt/ips-with-ai/python-packages:" + QDir::currentPath());
    process_.setProcessEnvironment(environment);

    startup_timer_.setSingleShot(true);
    restart_timer_.setSingleShot(true);
    stable_timer_.setSingleShot(true);
    connect(&startup_timer_, &QTimer::timeout, this,
            [this] { handle_failure("AI 시작 제한시간 초과"); });
    connect(&restart_timer_, &QTimer::timeout, this, [this] {
        ++restart_attempts_;
        ++restart_count_;
        start_attempt();
    });
    connect(&stable_timer_, &QTimer::timeout, this, [this] { restart_attempts_ = 0; });
    connect(&process_, &QProcess::readyReadStandardOutput, this,
            [this] { handle_stdout(); });
    connect(&process_, &QProcess::readyReadStandardError, this,
            [this] { handle_stderr(); });
    connect(&process_, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        handle_failure("QProcess 오류 code=" + std::to_string(static_cast<int>(error)) +
                       " message=" + process_.errorString().toStdString());
    });
    connect(&process_,
            static_cast<void (QProcess::*)(int, QProcess::ExitStatus)>(&QProcess::finished),
            this, [this](int exit_code, QProcess::ExitStatus status) {
                handle_stdout();
                handle_stderr();
                flush_partial_output();
                if (state_ != AiState::STOPPING) {
                    handle_failure("AI 프로세스 종료 code=" + std::to_string(exit_code) +
                                   " status=" +
                                   std::to_string(static_cast<int>(status)));
                }
            });
}

AiProcessSupervisor::~AiProcessSupervisor() {
    stop();
}

void AiProcessSupervisor::start() {
    if (stop_requested_ || state_ == AiState::STARTING || state_ == AiState::ONLINE ||
        state_ == AiState::RESTART_WAIT) {
        return;
    }
    if (!config_.enabled) {
        set_state(AiState::DISABLED, "AI 비활성화 설정");
        return;
    }
    restart_attempts_ = 0;
    start_attempt();
}

void AiProcessSupervisor::start_attempt() {
    if (stop_requested_) {
        return;
    }
    failure_handled_for_attempt_ = false;
    stdout_buffer_.clear();
    stderr_buffer_.clear();
    model_version_.clear();
    set_state(AiState::STARTING,
              restart_attempts_ == 0 ? "AI 프로세스 시작 중"
                                     : "AI 프로세스 재시작 중");
    if (!remove_socket()) {
        handle_failure("stale AI socket 제거 실패");
        return;
    }
    startup_timer_.start(config_.startup_timeout_ms);
    process_.start();
}

void AiProcessSupervisor::handle_stdout() {
    stdout_buffer_.append(process_.readAllStandardOutput());
    while (true) {
        const int newline = stdout_buffer_.indexOf('\n');
        if (newline < 0) {
            return;
        }
        QByteArray line = stdout_buffer_.left(newline);
        stdout_buffer_.remove(0, newline + 1);
        if (line.endsWith('\r')) {
            line.chop(1);
        }
        handle_stdout_line(line);
    }
}

void AiProcessSupervisor::handle_stderr() {
    stderr_buffer_.append(process_.readAllStandardError());
    while (true) {
        const int newline = stderr_buffer_.indexOf('\n');
        if (newline < 0) {
            return;
        }
        QByteArray line = stderr_buffer_.left(newline);
        stderr_buffer_.remove(0, newline + 1);
        if (line.endsWith('\r')) {
            line.chop(1);
        }
        if (!line.isEmpty()) {
            LOG(ERROR) << "AI_PROCESS stderr: " << line.constData();
        }
    }
}

void AiProcessSupervisor::handle_stdout_line(const QByteArray& line) {
    if (state_ == AiState::STARTING) {
        try {
            const auto ready = nlohmann::json::parse(line.constData(),
                                                     line.constData() + line.size());
            if (ready.is_object() && ready.contains("event") &&
                ready.at("event").is_string() &&
                ready.at("event").get<std::string>() == "AI_READY" &&
                ready.contains("schema_version") &&
                ready.at("schema_version").is_number_integer() &&
                ready.at("schema_version").get<int>() == 1 &&
                ready.contains("model_version") && ready.at("model_version").is_string()) {
                const std::string version = ready.at("model_version").get<std::string>();
                if (!version.empty()) {
                    startup_timer_.stop();
                    model_version_ = version;
                    try {
                        if (ready_handler_) {
                            ready_handler_(endpoint_, model_version_);
                        }
                    } catch (const std::exception& error) {
                        handle_failure(std::string("AI ready handler 오류: ") + error.what());
                        return;
                    }
                    set_state(AiState::ONLINE, "AI 온라인");
                    stable_timer_.start(config_.restart_reset_seconds * 1000);
                    return;
                }
            }
        } catch (const nlohmann::json::exception&) {
        }
    }
    if (!line.isEmpty()) {
        LOG(INFO) << "AI_PROCESS stdout: " << line.constData();
    }
}

void AiProcessSupervisor::flush_partial_output() {
    if (!stdout_buffer_.isEmpty()) {
        LOG(INFO) << "AI_PROCESS stdout(partial): " << stdout_buffer_.constData();
        stdout_buffer_.clear();
    }
    if (!stderr_buffer_.isEmpty()) {
        LOG(ERROR) << "AI_PROCESS stderr(partial): " << stderr_buffer_.constData();
        stderr_buffer_.clear();
    }
}

void AiProcessSupervisor::report_transport_failure(const std::string& reason) {
    if (state_ == AiState::ONLINE) {
        handle_failure(reason);
    }
}

void AiProcessSupervisor::handle_failure(const std::string& reason) {
    if (stop_requested_ || state_ == AiState::STOPPING ||
        failure_handled_for_attempt_) {
        return;
    }
    failure_handled_for_attempt_ = true;
    startup_timer_.stop();
    stable_timer_.stop();
    model_version_.clear();

    const bool can_restart = restart_attempts_ < config_.max_restarts;
    if (can_restart) {
        set_state(AiState::RESTART_WAIT, reason);
    } else {
        set_state(AiState::OFFLINE,
                  reason + " (자동 재시작 " + std::to_string(config_.max_restarts) +
                      "회 소진)");
    }
    stop_process();
    remove_socket();
    if (can_restart && !stop_requested_) {
        restart_timer_.start(restart_delay_ms(restart_attempts_));
    }
}

void AiProcessSupervisor::stop_process() {
    if (process_.state() == QProcess::NotRunning) {
        return;
    }
    process_.terminate();
    if (!process_.waitForFinished(2000)) {
        process_.kill();
        if (!process_.waitForFinished(2000)) {
            LOG(ERROR) << "AI_PROCESS kill 후에도 종료 확인 실패";
        }
    }
}

bool AiProcessSupervisor::remove_socket() {
    const QString path = QString::fromStdString(socket_path_);
    if (!QFile::exists(path) || QFile::remove(path)) {
        return true;
    }
    LOG(ERROR) << "AI socket 제거 실패: " << socket_path_;
    return false;
}

void AiProcessSupervisor::stop() {
    if (stop_requested_) {
        return;
    }
    stop_requested_ = true;
    set_state(AiState::STOPPING, "종료 중");
    startup_timer_.stop();
    restart_timer_.stop();
    stable_timer_.stop();
    stop_process();
    remove_socket();
}

void AiProcessSupervisor::set_state(AiState state, std::string detail) {
    state_ = state;
    detail_ = std::move(detail);
    if (state_handler_) {
        try {
            state_handler_(state_, detail_);
        } catch (const std::exception& error) {
            LOG(ERROR) << "AI state handler 오류: " << error.what();
        }
    }
}

AiSupervisorSnapshot AiProcessSupervisor::snapshot() const {
    return AiSupervisorSnapshot{state_, model_version_, restart_count_, detail_};
}
