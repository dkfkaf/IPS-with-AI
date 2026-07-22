#include <unistd.h>

#include <csignal>
#include <cstdint>

#include <glog/logging.h>

#include "packet_capture.h"

namespace {

constexpr uint16_t DEFAULT_QUEUE_NUM = 0;

// 시그널 핸들러에는 인자를 넘길 수 없어 전역 포인터로 종료 대상을 알린다
PacketCapture* g_capture = nullptr;

void handle_signal(int /*signum*/) {
    if (g_capture != nullptr) {
        g_capture->stop();
    }
}

}  // namespace

int main(int /*argc*/, char* argv[]) {
    google::InitGoogleLogging(argv[0]);
    FLAGS_logtostderr = true;  // 개발 단계에서는 파일 대신 화면으로 바로 확인

    if (geteuid() != 0) {
        LOG(WARNING) << "root 권한이 아닙니다 — NFQUEUE 열기에 실패할 수 있습니다";
    }

    PacketCapture capture(DEFAULT_QUEUE_NUM);
    g_capture = &capture;

    // Ctrl+C(SIGINT)·kill(SIGTERM)에서 수신 루프를 정상 종료시켜
    // NFQUEUE 자원이 close()로 해제되게 한다
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    LOG(INFO) << "AI 기반 인라인 IPS — 1단계: 패킷 수신·파싱·로그";
    LOG(INFO) << "트래픽 유입 규칙 예: sudo iptables -I INPUT -j NFQUEUE --queue-num "
              << DEFAULT_QUEUE_NUM << " --queue-bypass";

    if (!capture.start()) {
        return 1;
    }
    LOG(INFO) << "정상 종료";
    return 0;
}
