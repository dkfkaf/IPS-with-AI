#include "packet_parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

namespace {

// iphdr의 ihl 필드는 4바이트 단위로 헤더 길이를 표현한다
constexpr size_t IHL_UNIT_BYTES = 4;

}  // namespace

std::optional<FiveTuple> PacketParser::parse(const uint8_t* data, size_t len) const {
    // 기본 IP 헤더(20바이트)보다 짧으면 필드 접근 자체가 범위를 벗어나므로 먼저 걸러낸다
    if (data == nullptr || len < sizeof(struct iphdr)) {
        return std::nullopt;
    }

    const auto* ip_header = reinterpret_cast<const struct iphdr*>(data);
    if (ip_header->version != IPVERSION) {  // IPVERSION(4)은 <netinet/ip.h> 제공
        return std::nullopt;  // IPv6 등은 1단계 파싱 대상이 아니다
    }

    // IP 헤더 길이는 옵션 필드 때문에 고정이 아니다 — ihl로 실제 길이를 계산해야
    // TCP/UDP 헤더의 시작 위치를 정확히 잡을 수 있다
    const size_t ip_header_len = static_cast<size_t>(ip_header->ihl) * IHL_UNIT_BYTES;
    if (ip_header_len < sizeof(struct iphdr) || len < ip_header_len) {
        return std::nullopt;  // ihl < 5는 규격 위반, 버퍼보다 길면 잘린 패킷
    }

    // 뒤쪽 IP 조각에는 TCP/UDP 헤더가 없다 — 포트 자리에 페이로드가 오므로
    // 그대로 읽으면 엉뚱한 값이 5-튜플로 잡힌다. IP_OFFMASK(0x1fff)는 <netinet/ip.h> 제공
    if ((ntohs(ip_header->frag_off) & IP_OFFMASK) != 0) {
        return std::nullopt;
    }

    FiveTuple tuple = {};
    tuple.src_ip = ip_header->saddr;  // 네트워크 바이트 순서 그대로 저장 (five_tuple.h 참고)
    tuple.dst_ip = ip_header->daddr;
    tuple.protocol = ip_header->protocol;

    const uint8_t* transport = data + ip_header_len;
    const size_t transport_len = len - ip_header_len;

    if (tuple.protocol == IPPROTO_TCP) {
        if (transport_len < sizeof(struct tcphdr)) {
            return std::nullopt;
        }
        const auto* tcp_header = reinterpret_cast<const struct tcphdr*>(transport);
        tuple.src_port = ntohs(tcp_header->source);
        tuple.dst_port = ntohs(tcp_header->dest);
    } else if (tuple.protocol == IPPROTO_UDP) {
        if (transport_len < sizeof(struct udphdr)) {
            return std::nullopt;
        }
        const auto* udp_header = reinterpret_cast<const struct udphdr*>(transport);
        tuple.src_port = ntohs(udp_header->source);
        tuple.dst_port = ntohs(udp_header->dest);
    } else {
        return std::nullopt;  // TCP/UDP 외 프로토콜은 포트가 없어 5-튜플 대상이 아니다
    }

    return tuple;
}
