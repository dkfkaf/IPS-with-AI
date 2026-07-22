#ifndef IPS_SRC_PACKET_PARSER_H_
#define IPS_SRC_PACKET_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <optional>

#include "five_tuple.h"

// 원시 패킷 바이트(IP 헤더부터 시작)에서 5-튜플을 파싱한다.
// NFQUEUE가 넘겨주는 페이로드는 네트워크 계층(IP 헤더)부터 시작한다는 전제를 둔다.
// 숨길 내부 상태가 없으므로 struct로 둔다 — 이후 파싱 통계 등 상태가 생기면 class로 바꾼다.
struct PacketParser {
    // 성공 시 FiveTuple을 반환한다.
    // IPv4 TCP/UDP가 아니거나, 헤더가 잘려 있거나, 뒤쪽 IP 조각(fragment)이면 std::nullopt.
    std::optional<FiveTuple> parse(const uint8_t* data, size_t len) const;
};

#endif  // IPS_SRC_PACKET_PARSER_H_
