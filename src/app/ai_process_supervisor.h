#ifndef IPS_SRC_APP_AI_PROCESS_SUPERVISOR_H_
#define IPS_SRC_APP_AI_PROCESS_SUPERVISOR_H_

#include <cstdint>
#include <functional>
#include <string>

#include <QByteArray>
#include <QObject>
#include <QProcess>
#include <QTimer>

#include "ai/ai_types.h"
#include "config/config.h"

struct AiSupervisorSnapshot {
    AiState state = AiState::DISABLED;
    std::string model_version;
    uint64_t restart_count = 0;
    std::string detail;
};

class AiProcessSupervisor final : public QObject {
 public:
    using ReadyHandler = std::function<void(const std::string&, const std::string&)>;
    using StateHandler = std::function<void(AiState, const std::string&)>;

    AiProcessSupervisor(const AiConfig& config, ReadyHandler ready_handler,
                        StateHandler state_handler, QObject* parent = nullptr);
    ~AiProcessSupervisor() override;

    void start();
    void stop();
    void report_transport_failure(const std::string& reason);
    AiSupervisorSnapshot snapshot() const;

 private:
    void start_attempt();
    void handle_stdout();
    void handle_stderr();
    void handle_stdout_line(const QByteArray& line);
    void flush_partial_output();
    void handle_failure(const std::string& reason);
    void stop_process();
    bool remove_socket();
    void set_state(AiState state, std::string detail);

    AiConfig config_;
    ReadyHandler ready_handler_;
    StateHandler state_handler_;
    QProcess process_;
    QTimer startup_timer_;
    QTimer restart_timer_;
    QTimer stable_timer_;
    QByteArray stdout_buffer_;
    QByteArray stderr_buffer_;
    std::string socket_path_;
    std::string endpoint_;
    AiState state_ = AiState::DISABLED;
    std::string model_version_;
    std::string detail_;
    uint64_t restart_count_ = 0;
    int restart_attempts_ = 0;
    bool failure_handled_for_attempt_ = false;
    bool stop_requested_ = false;
};

#endif  // IPS_SRC_APP_AI_PROCESS_SUPERVISOR_H_
