#include <unistd.h>

#include <csignal>
#include <utility>

#include <QApplication>
#include <QTimer>

#include <glog/logging.h>

#include "app/application_controller.h"
#include "config/config.h"
#include "response/whitelist.h"

namespace {

volatile std::sig_atomic_t g_shutdown_requested = 0;

void handle_signal(int /*signum*/) { g_shutdown_requested = 1; }

}  // namespace

int main(int argc, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;  // 개발 단계에서는 파일 대신 화면으로 바로 확인

    if (geteuid() != 0) {
        LOG(ERROR) << "root 계정에서만 실행할 수 있습니다";
        google::ShutdownGoogleLogging();
        return 1;
    }

    // 설정 로드: 파일 없음 → 기본값, 깨진 JSON → 시작 중단(fail-fast)
    const auto config = load_config("config.json");
    if (!config.has_value()) {
        LOG(ERROR) << "설정이 깨져 있습니다 — 시작을 중단합니다";
        google::ShutdownGoogleLogging();
        return 1;
    }
    // 화이트리스트를 시작 시점에 적재·검증한다: 잘못된 IP가 있으면 중단(오타로 인한 무음
    // 무력화 방지). 검증한 인스턴스를 그대로 PacketCapture에 넘겨 이중 파싱을 피한다.
    Whitelist whitelist;
    if (!whitelist.load(config->whitelist)) {
        LOG(ERROR) << "화이트리스트 IP 형식 오류 — config.json을 고치고 다시 실행하세요";
        google::ShutdownGoogleLogging();
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    int exit_code = 1;
    {
        ApplicationController controller(*config, std::move(whitelist));
        if (controller.start()) {
            QTimer signal_timer;
            QObject::connect(&signal_timer, &QTimer::timeout, &controller, [&controller] {
                if (g_shutdown_requested != 0) {
                    controller.begin_shutdown(0);
                }
            });
            signal_timer.start(200);

            LOG(INFO) << "AI 기반 인라인 IPS 시작";
            LOG(INFO) << "iptables INPUT·OUTPUT 규칙 자동 관리 (NFQUEUE "
                      << config->queue_num << ')';
            exit_code = app.exec();
            controller.begin_shutdown(exit_code);
        }
    }
    google::ShutdownGoogleLogging();
    return exit_code;
}
