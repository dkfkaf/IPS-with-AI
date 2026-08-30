#include "capture/packet_parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <cstring>

namespace {

// iphdr의 ihl 필드는 4바이트 단위로 헤더 길이를 표현한다
constexpr size_t IHL_UNIT_BYTES = 4;
constexpr size_t TCP_DATA_OFFSET_UNIT_BYTES = 4;

}  // namespace

std::optional<ParsedPacket> PacketParser::parse(const uint8_t* data, size_t len) const {
    // 기본 IP 헤더(20바이트)보다 짧으면 필드 접근 자체가 범위를 벗어난다
    if (data == nullptr || len < sizeof(struct iphdr)) {
        return std::nullopt;
    }
    struct iphdr ip_header;
    std::memcpy(&ip_header, data, sizeof(ip_header));
    if (ip_header.version != IPVERSION) {  // IPVERSION(4)은 <netinet/ip.h> 제공
        return std::nullopt;                // IPv6 등은 대상 아님
    }
    const size_t ip_header_len = static_cast<size_t>(ip_header.ihl) * IHL_UNIT_BYTES;
    if (ip_header_len < sizeof(struct iphdr)) {
        return std::nullopt;  // ihl<5는 규격 위반 — 신뢰할 수 없는 헤더
    }

    // 여기부터는 기본 20바이트가 읽히므로 출발지 IP·프로토콜·전체 길이를 얻을 수 있다.
    // 전송 헤더를 못 읽는 경우는 nullopt이 아니라 has_ports=false로 돌려준다(차단 우회 방지).
    ParsedPacket packet = {};
    packet.tuple.src_ip = ip_header.saddr;  // 네트워크 바이트 순서 그대로 저장
    packet.tuple.dst_ip = ip_header.daddr;
    packet.tuple.protocol = ip_header.protocol;
    packet.total_len = ntohs(ip_header.tot_len);  // 네트워크→호스트 순서
    packet.has_ports = false;

    if (packet.total_len < ip_header_len) {
        return packet;  // IP 전체 길이가 헤더보다 짧을 수 없음
    }

    // 뒤쪽 IP 조각에는 전송 헤더가 없다. IP_OFFMASK(0x1fff)는 <netinet/ip.h> 제공
    if ((ntohs(ip_header.frag_off) & IP_OFFMASK) != 0) {
        return packet;
    }
    // ihl이 버퍼보다 긴 헤더(옵션 잘림)를 주장하면 전송 헤더 위치를 잡을 수 없다
    if (len < ip_header_len) {
        return packet;
    }

    const uint8_t* transport = data + ip_header_len;
    const size_t transport_len = len - ip_header_len;

    if (packet.tuple.protocol == IPPROTO_TCP) {
        if (transport_len < sizeof(struct tcphdr)) {
            return packet;  // 잘린 TCP 헤더
        }
        struct tcphdr tcp_header;
        std::memcpy(&tcp_header, transport, sizeof(tcp_header));
        const size_t tcp_header_len =
            static_cast<size_t>(tcp_header.doff) * TCP_DATA_OFFSET_UNIT_BYTES;
        if (tcp_header_len < sizeof(struct tcphdr) || tcp_header_len > transport_len ||
            ip_header_len + tcp_header_len > packet.total_len) {
            return packet;
        }
        packet.tuple.src_port = ntohs(tcp_header.source);
        packet.tuple.dst_port = ntohs(tcp_header.dest);
        packet.tcp_flags = transport[13];  // TCP 헤더 옵셋 13이 플래그 옥텟 (최소 20B 안이라 안전)
        packet.payload_len =
            static_cast<uint16_t>(packet.total_len - ip_header_len - tcp_header_len);
        packet.has_ports = true;
    } else if (packet.tuple.protocol == IPPROTO_UDP) {
        if (transport_len < sizeof(struct udphdr)) {
            return packet;  // 잘린 UDP 헤더
        }
        struct udphdr udp_header;
        std::memcpy(&udp_header, transport, sizeof(udp_header));
        const size_t udp_len = ntohs(udp_header.len);
        if (udp_len < sizeof(struct udphdr) || ip_header_len + udp_len > packet.total_len) {
            return packet;
        }
        packet.tuple.src_port = ntohs(udp_header.source);
        packet.tuple.dst_port = ntohs(udp_header.dest);
        packet.payload_len = static_cast<uint16_t>(udp_len - sizeof(struct udphdr));
        packet.has_ports = true;
    }
    // TCP/UDP 외(ICMP 등)는 has_ports=false로 둔다 — 포트가 없어 규칙 판정 대상이 아니다
    return packet;
}
