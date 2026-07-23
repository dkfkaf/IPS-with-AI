#include <unistd.h>

#include <csignal>
#include <utility>

#include <glog/logging.h>

#include "capture/packet_capture.h"
#include "config/config.h"
#include "response/whitelist.h"

namespace {

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

    // 설정 로드: 파일 없음 → 기본값, 깨진 JSON → 시작 중단(fail-fast)
    const auto config = load_config("config.json");
    if (!config.has_value()) {
        LOG(ERROR) << "설정이 깨져 있습니다 — 시작을 중단합니다";
        return 1;
    }
    // 화이트리스트를 시작 시점에 적재·검증한다: 잘못된 IP가 있으면 중단(오타로 인한 무음
    // 무력화 방지). 검증한 인스턴스를 그대로 PacketCapture에 넘겨 이중 파싱을 피한다.
    Whitelist whitelist;
    if (!whitelist.load(config->whitelist)) {
        LOG(ERROR) << "화이트리스트 IP 형식 오류 — config.json을 고치고 다시 실행하세요";
        return 1;
    }

    PacketCapture capture(*config, std::move(whitelist));
    g_capture = &capture;

    // Ctrl+C(SIGINT)·kill(SIGTERM)에서 수신 루프를 정상 종료시켜
    // NFQUEUE 자원이 close()로 해제되게 한다
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    LOG(INFO) << "AI 기반 인라인 IPS — 2단계: 대응형 IPS (포트 스캔·SYN 플러드 차단)";
    LOG(INFO) << "트래픽 유입 규칙 예: sudo iptables -I INPUT -j NFQUEUE --queue-num "
              << config->queue_num << " --queue-bypass";

    if (!capture.start()) {
        return 1;
    }
    LOG(INFO) << "정상 종료";
    return 0;
}
