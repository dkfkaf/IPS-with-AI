#ifndef IPS_SRC_CAPTURE_PACKET_PARSER_H_
#define IPS_SRC_CAPTURE_PACKET_PARSER_H_

#include <cstddef>
#include <cstdint>
#include <optional>

#include "common/five_tuple.h"

// 파싱 결과. FiveTuple(플로우 키)에 플로우 통계용 필드를 한 겹 감싼다.
// tcp_flags는 SYN·ACK·FIN 등 플래그 옥텟을 통째로 담는다 — 플로우 특징이 플래그별 카운트를
// 쓰므로 SYN 하나만이 아니라 전체를 넘긴다. 소비자가 TH_SYN 등 마스크로 골라 본다.
struct ParsedPacket {
    FiveTuple tuple;      // has_ports=false면 src_port/dst_port는 0
    uint16_t total_len;   // IP 전체 길이 (ntohs로 호스트 순서 변환 후 저장)
    bool has_ports;       // 전송 계층(TCP/UDP) 파싱 성공 여부
    uint8_t tcp_flags;    // TCP 플래그 옥텟 (has_ports=false거나 UDP면 0). TH_SYN 등으로 검사
};

// 원시 패킷 바이트(IP 헤더부터)에서 ParsedPacket을 만든다.
// NFQUEUE가 넘겨주는 페이로드는 네트워크 계층(IP 헤더)부터 시작한다는 전제를 둔다.
// 기본 IP 헤더 20바이트가 유효하게 읽히지 않을 때(길이 부족·version≠4·ihl<5)만 nullopt.
// 전송 헤더를 못 읽으면 has_ports=false로 반환한다(출발지 IP는 유효).
// 숨길 내부 상태가 없으므로 struct로 둔다 — 이후 파싱 통계 등 상태가 생기면 class로 바꾼다.
struct PacketParser {
    std::optional<ParsedPacket> parse(const uint8_t* data, size_t len) const;
};

#endif  // IPS_SRC_CAPTURE_PACKET_PARSER_H_
