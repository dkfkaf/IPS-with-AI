#ifndef IPS_SRC_APP_APPLICATION_CONTROLLER_H_
#define IPS_SRC_APP_APPLICATION_CONTROLLER_H_

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include <QObject>

#include "ai/ai_types.h"
#include "config/config.h"
#include "response/whitelist.h"

class AiProcessSupervisor;
class AsyncAiClient;
class PacketCapture;
class TrayController;

class ApplicationController final : public QObject {
 public:
    ApplicationController(Config config, Whitelist whitelist, QObject* parent = nullptr);
    ~ApplicationController() override;

    bool start();
    void begin_shutdown(int exit_code = 0);

 private:
    void post_transport_failure(const std::string& reason);
    void post_ai_block(const AiBlockEvent& event);
    void post_capture_result(bool ok);
    void show_status();
    std::string format_status() const;

    Config config_;
    std::chrono::steady_clock::time_point started_at_;
    AsyncAiClient* ai_client_ = nullptr;
    std::unique_ptr<PacketCapture> capture_;
    std::thread capture_thread_;
    std::unique_ptr<AiProcessSupervisor> supervisor_;
    std::unique_ptr<TrayController> tray_;
    bool started_ = false;
    bool stopping_ = false;
};

#endif  // IPS_SRC_APP_APPLICATION_CONTROLLER_H_
