#ifndef IPS_SRC_PACKET_CAPTURE_H_
#define IPS_SRC_PACKET_CAPTURE_H_

#include <cstddef>
#include <cstdint>

#include "packet_parser.h"
#include "packet_source.h"

// "받기 → 파싱 → 로그"의 흐름을 조율하는 총괄자.
class PacketCapture {
 public:
    explicit PacketCapture(uint16_t queue_num);

    bool start();  // 수신원을 열고 수신 루프 시작 — stop()이 불릴 때까지 블로킹
    void stop();   // 수신 중단 요청 (시그널 핸들러에서 불러도 안전)

 private:
    // 패킷 1개 처리: 파싱 성공 시 5-튜플을 로그로 남긴다.
    // 반환값이 NFQUEUE verdict가 된다 — 1단계에서는 무조건 통과(true).
    bool on_packet(const uint8_t* data, size_t len);

    PacketParser parser_;
    PacketSource source_;
};

#endif  // IPS_SRC_PACKET_CAPTURE_H_
