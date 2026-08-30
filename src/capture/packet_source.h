#ifndef IPS_SRC_CAPTURE_PACKET_SOURCE_H_
#define IPS_SRC_CAPTURE_PACKET_SOURCE_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>

#include "capture/packet_direction.h"

// libnetfilter_queue의 C 타입은 전방 선언만 둔다 —
// 이 헤더를 쓰는 쪽(PacketCapture)에 C API가 새어 나가지 않게 하기 위함이다(캡슐화)
struct nfq_handle;
struct nfq_q_handle;
struct nfgenmsg;
struct nfq_data;

// NFQUEUE에서 패킷 바이트를 꺼내오는 수신원.
// libnetfilter_queue의 C API를 감싸, 바깥에서는 C++ 방식으로 쓰게 한다.
class PacketSource {
 public:
    // 패킷 1개에 대한 처리 함수. true를 반환하면 통과(ACCEPT), false면 폐기(DROP).
    // NFQUEUE는 콜백 기반으로 동작하므로, next_packet() 반환형 대신
    // 처리 함수를 등록받아 콜백에서 상위로 넘기는 방식을 택했다 (설계 문서 3.3절 참고).
    // 계약: 페이로드를 읽지 못했거나 처리 함수가 예외를 던진 패킷은 통과(fail-open)로 처리된다.
    using PacketHandler =
        std::function<bool(const uint8_t* data, size_t len, PacketDirection direction)>;

    // 약 1초마다 수신 루프 안에서 불리는 주기 작업 콜백 (BlockList·FlowManager 만료 정리용).
    using TickHandler = std::function<void()>;

    PacketSource(uint16_t queue_num, PacketHandler handler, TickHandler tick_handler);
    ~PacketSource() { close(); }  // close()가 빠진 종료 경로에서도 자원이 해제되게 (close는 멱등)

    // 넷링크 핸들을 두 객체가 공유하면 이중 해제가 되므로 복사를 막는다
    PacketSource(const PacketSource&) = delete;
    PacketSource& operator=(const PacketSource&) = delete;

    bool open();   // NFQUEUE 큐 바인딩, 콜백 등록
    bool close();  // open()에서 할당한 자원을 정확히 대응 해제 (여러 번 불러도 안전)
    bool loop();   // 수신 루프 — 블로킹. stop() 요청으로 끝나면 true, 오류로 끝나면 false
    void stop();   // 수신 루프 중단 요청 (시그널 핸들러에서 불러도 안전)

 private:
    // libnetfilter_queue가 요구하는 C 콜백 시그니처. self_ptr로 객체 자신을 되찾는다.
    static int on_packet_received(struct nfq_q_handle* queue, struct nfgenmsg* msg,
                                  struct nfq_data* packet_data, void* self_ptr);

    uint16_t queue_num_;
    PacketHandler handler_;
    TickHandler tick_handler_;
    struct nfq_handle* handle_ = nullptr;   // NFQUEUE 핸들
    struct nfq_q_handle* queue_ = nullptr;  // 큐 핸들
    int fd_ = -1;                           // 넷링크 소켓 (handle_ 소유 — 직접 닫지 않음)
    std::atomic<bool> running_{false};
    std::atomic<bool> stop_requested_{false};
};

#endif  // IPS_SRC_CAPTURE_PACKET_SOURCE_H_
