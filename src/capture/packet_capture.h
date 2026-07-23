#ifndef IPS_SRC_CAPTURE_PACKET_CAPTURE_H_
#define IPS_SRC_CAPTURE_PACKET_CAPTURE_H_

#include <cstddef>
#include <cstdint>

#include "capture/packet_parser.h"
#include "capture/packet_source.h"
#include "config/config.h"
#include "flow/flow_manager.h"
#include "detect/rule_engine.h"
#include "response/block_list.h"
#include "response/whitelist.h"

// 판정 파이프라인을 조율하는 총괄자. Config에서 각 구성 요소를 만들어 배선한다.
class PacketCapture {
 public:
    // Whitelist는 main이 적재·검증(fail-fast)해 주입한다 — 형식 검증은 한 계층에만 둔다.
    PacketCapture(const Config& config, Whitelist whitelist);

    bool start();  // 수신원을 열고 수신 루프 시작 — stop()까지 블로킹
    void stop();   // 수신 중단 요청 (시그널 핸들러에서 불러도 안전)

 private:
    bool on_packet(const uint8_t* data, size_t len);  // 반환값이 NFQUEUE verdict
    void on_tick();                                    // 약 1초마다 만료 정리

    int block_ttl_seconds_;
    PacketParser parser_;
    Whitelist whitelist_;
    BlockList block_list_;
    FlowManager flow_manager_;
    RuleEngine rule_engine_;
    PacketSource source_;  // 마지막에 둔다 — 생성자에서 위 멤버를 참조하는 콜백을 넘긴다
};

#endif  // IPS_SRC_CAPTURE_PACKET_CAPTURE_H_
