#include "packet_source.h"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <exception>
#include <utility>

#include <glog/logging.h>

namespace {

// NFQNL_COPY_PACKET으로 커널에서 복사해 올 최대 바이트 수 — IP_MAXPACKET(65535)은
// <netinet/ip.h>가 제공하는 IPv4 최대 패킷 크기다
constexpr uint32_t MAX_COPY_BYTES = IP_MAXPACKET;
// 수신 버퍼 = 최대 패킷 + 넷링크 메타데이터 여유분
constexpr size_t RECV_BUFFER_BYTES = MAX_COPY_BYTES + 4096;
// recv 타임아웃 — 패킷이 없어도 이 주기마다 깨어나 stop() 요청을 확인한다
constexpr int RECV_TIMEOUT_SEC = 1;

}  // namespace

PacketSource::PacketSource(uint16_t queue_num, PacketHandler handler)
    : queue_num_(queue_num), handler_(std::move(handler)) {}

bool PacketSource::open() {
    handle_ = nfq_open();
    if (handle_ == nullptr) {
        LOG(ERROR) << "nfq_open 실패 — root 권한으로 실행했는지 확인하세요";
        return false;
    }

    // 이전 실행의 바인딩 잔재를 지우고 다시 거는 관례적 초기화.
    // 커널 3.8부터는 둘 다 no-op이라 실패해도 치명적이지 않으므로 경고만 남긴다.
    nfq_unbind_pf(handle_, AF_INET);
    if (nfq_bind_pf(handle_, AF_INET) < 0) {
        LOG(WARNING) << "nfq_bind_pf 실패 (커널 3.8 이상이면 무시 가능)";
    }

    queue_ = nfq_create_queue(handle_, queue_num_, &on_packet_received, this);
    if (queue_ == nullptr) {
        LOG(ERROR) << "nfq_create_queue 실패 (queue " << queue_num_
                   << ") — 같은 큐를 쓰는 다른 프로세스가 있는지 확인하세요";
        close();  // 여기까지 할당된 handle_을 해제
        return false;
    }

    if (nfq_set_mode(queue_, NFQNL_COPY_PACKET, MAX_COPY_BYTES) < 0) {
        LOG(ERROR) << "nfq_set_mode 실패";
        close();
        return false;
    }

    fd_ = nfq_fd(handle_);

    // 타임아웃 없이 recv가 영원히 블로킹되면 stop() 요청이 전달되지 않는다
    struct timeval timeout = {RECV_TIMEOUT_SEC, 0};
    if (setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        LOG(WARNING) << "recv 타임아웃 설정 실패 — Ctrl+C 종료 반응이 늦어질 수 있음";
    }

    LOG(INFO) << "패킷 수신 준비 완료 (NFQUEUE " << queue_num_ << ")";
    return true;
}

bool PacketSource::close() {
    bool ok = true;
    if (queue_ != nullptr) {
        if (nfq_destroy_queue(queue_) < 0) {
            LOG(ERROR) << "nfq_destroy_queue 실패";
            ok = false;
        }
        queue_ = nullptr;
    }
    if (handle_ != nullptr) {
        if (nfq_close(handle_) < 0) {
            LOG(ERROR) << "nfq_close 실패";
            ok = false;
        }
        handle_ = nullptr;
    }
    fd_ = -1;  // 넷링크 소켓은 nfq_close가 함께 닫으므로 여기서는 표시만 지운다
    return ok;
}

bool PacketSource::loop() {
    running_ = true;
    // stop() 요청에 의한 정상 종료인지, 오류로 인한 중단인지를 호출자에게 알린다 —
    // 이 구분을 버리면 recv가 죽어도 프로그램이 "정상 종료"(종료 코드 0)로 끝난다
    bool ok = true;
    // 넷링크 메시지 파싱은 4바이트 정렬을 전제하므로 char 배열에 정렬을 명시한다
    alignas(4) char buffer[RECV_BUFFER_BYTES];

    while (running_) {
        const ssize_t received = recv(fd_, buffer, sizeof(buffer), 0);
        if (received > 0) {
            // 등록해 둔 콜백(on_packet_received)은 이 호출 안에서 불린다
            nfq_handle_packet(handle_, buffer, static_cast<int>(received));
            continue;
        }
        if (received == 0) {
            LOG(ERROR) << "넷링크 소켓이 닫힘 — 수신 루프 종료";
            ok = false;
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            continue;  // 타임아웃 또는 시그널 — running_을 다시 확인하고 계속
        }
        if (errno == ENOBUFS) {
            // 트래픽이 커널 버퍼보다 빠른 상황일 뿐, 프로그램을 중단할 일은 아니다
            // TODO: 인라인 전환(3단계) 시 NETLINK_NO_ENOBUFS·수신 버퍼 확대로 유실 자체를 방지
            LOG(WARNING) << "커널 수신 버퍼 넘침 — 일부 패킷 유실";
            continue;
        }
        LOG(ERROR) << "recv 실패: " << std::strerror(errno);
        ok = false;
        break;
    }
    running_ = false;
    return ok;
}

void PacketSource::stop() { running_ = false; }

int PacketSource::on_packet_received(struct nfq_q_handle* queue, struct nfgenmsg* /*msg*/,
                                     struct nfq_data* packet_data, void* self_ptr) {
    auto* self = static_cast<PacketSource*>(self_ptr);

    struct nfqnl_msg_packet_hdr* packet_header = nfq_get_msg_packet_hdr(packet_data);
    if (packet_header == nullptr) {
        // 패킷 ID를 모르면 verdict를 줄 방법이 없다 — 기록만 남긴다
        LOG(ERROR) << "패킷 메타데이터 없음 — verdict 생략";
        return -1;
    }
    const uint32_t packet_id = ntohl(packet_header->packet_id);

    unsigned char* payload = nullptr;
    const int payload_len = nfq_get_payload(packet_data, &payload);

    // 페이로드를 읽지 못한 패킷은 정상 통신을 막지 않도록 통과시킨다
    bool accept = true;
    if (payload_len >= 0 && payload != nullptr) {
        // 예외가 C 라이브러리(nfq_handle_packet) 스택을 관통하면 미정의 동작이고,
        // 이 패킷은 verdict를 받지 못한 채 커널 큐에 남는다 — 여기서 막고 통과 처리한다
        try {
            accept = self->handler_(payload, static_cast<size_t>(payload_len));
        } catch (const std::exception& e) {
            LOG(ERROR) << "패킷 처리 중 예외: " << e.what();
        } catch (...) {
            LOG(ERROR) << "패킷 처리 중 알 수 없는 예외";
        }
    }
    return nfq_set_verdict(queue, packet_id, accept ? NF_ACCEPT : NF_DROP, 0, nullptr);
}
