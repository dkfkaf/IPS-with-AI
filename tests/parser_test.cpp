// PacketParser 단독 테스트.
// NFQUEUE·root 권한 없이 실행할 수 있다 — 순수 파싱 로직만 검증한다.
// (docs/design/stage1.md 6장 구현 순서 1번: 파서를 네트워크 없이 먼저 확인)
//
// 실행: build 디렉터리에서  ./parser_test  (또는 ctest)
// 종료 코드 0이면 전부 통과.

#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <cstdint>
#include <cstdio>
#include <vector>

#include "capture/packet_parser.h"

namespace {

int failed_count = 0;

void expect(bool condition, const char* test_name) {
    std::printf("[%s] %s\n", condition ? "통과" : "실패", test_name);
    if (!condition) {
        ++failed_count;
    }
}

// 192.168.0.10:12345 -> 10.0.0.1:80 (IPv4 + TCP SYN, IP 옵션 없음)
// 파서는 체크섬을 검증하지 않으므로 체크섬 필드는 0으로 둔다.
const std::vector<uint8_t> TCP_PACKET = {
    // IP 헤더 (20바이트)
    0x45, 0x00, 0x00, 0x28,  // 버전 4·헤더 20B, TOS, 전체 길이 40
    0x00, 0x01, 0x40, 0x00,  // ID, 플래그(DF)·조각 오프셋 0
    0x40, 0x06, 0x00, 0x00,  // TTL 64, 프로토콜 TCP(6), 체크섬
    0xC0, 0xA8, 0x00, 0x0A,  // 출발지 192.168.0.10
    0x0A, 0x00, 0x00, 0x01,  // 목적지 10.0.0.1
    // TCP 헤더 (20바이트)
    0x30, 0x39,              // 출발지 포트 12345
    0x00, 0x50,              // 목적지 포트 80
    0x00, 0x00, 0x00, 0x00,  // 순서 번호
    0x00, 0x00, 0x00, 0x00,  // 확인 응답 번호
    0x50, 0x02, 0x20, 0x00,  // 데이터 오프셋 5, SYN, 윈도
    0x00, 0x00, 0x00, 0x00,  // 체크섬, 긴급 포인터
};

// 172.16.0.5:5353 -> 8.8.8.8:53 (IPv4 + UDP)
const std::vector<uint8_t> UDP_PACKET = {
    // IP 헤더 (20바이트)
    0x45, 0x00, 0x00, 0x1C,  // 전체 길이 28
    0x00, 0x02, 0x00, 0x00,  //
    0x40, 0x11, 0x00, 0x00,  // TTL 64, 프로토콜 UDP(17)
    0xAC, 0x10, 0x00, 0x05,  // 출발지 172.16.0.5
    0x08, 0x08, 0x08, 0x08,  // 목적지 8.8.8.8
    // UDP 헤더 (8바이트)
    0x14, 0xE9,              // 출발지 포트 5353
    0x00, 0x35,              // 목적지 포트 53
    0x00, 0x08, 0x00, 0x00,  // 길이 8, 체크섬
};

// 10.0.0.2:443 -> 10.0.0.3:50000 — IP 옵션 4바이트가 붙어 ihl=6(헤더 24B)인 TCP 패킷.
const std::vector<uint8_t> IP_OPTIONS_TCP_PACKET = {
    // IP 헤더 (24바이트, 옵션 포함)
    0x46, 0x00, 0x00, 0x2C,  // 버전 4·헤더 24B, 전체 길이 44
    0x00, 0x03, 0x40, 0x00,  //
    0x40, 0x06, 0x00, 0x00,  // 프로토콜 TCP(6)
    0x0A, 0x00, 0x00, 0x02,  // 출발지 10.0.0.2
    0x0A, 0x00, 0x00, 0x03,  // 목적지 10.0.0.3
    0x01, 0x01, 0x01, 0x00,  // IP 옵션 (NOP NOP NOP EOL)
    // TCP 헤더 (20바이트)
    0x01, 0xBB,              // 출발지 포트 443
    0xC3, 0x50,              // 목적지 포트 50000
    0x00, 0x00, 0x00, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
    0x50, 0x10, 0x20, 0x00,  //
    0x00, 0x00, 0x00, 0x00,  //
};

// 프로토콜이 ICMP(1)인 패킷 — 포트가 없다 (has_ports=false, 출발지 IP는 유효)
const std::vector<uint8_t> ICMP_PACKET = {
    0x45, 0x00, 0x00, 0x1C,  //
    0x00, 0x04, 0x00, 0x00,  //
    0x40, 0x01, 0x00, 0x00,  // 프로토콜 ICMP(1)
    0x0A, 0x00, 0x00, 0x01,  // 출발지 10.0.0.1
    0x0A, 0x00, 0x00, 0x02,  // 목적지 10.0.0.2
    0x08, 0x00, 0x00, 0x00,  // ICMP echo request 앞부분
    0x00, 0x00, 0x00, 0x00,  //
};

}  // namespace

int main() {
    PacketParser parser;
    // 벡터를 (포인터, 길이) 쌍으로 푸는 호출이 반복되므로 한 번만 정의한다.
    // 길이를 일부러 잘라 넘기는 케이스는 이 람다를 쓰지 않고 원형 그대로 호출한다.
    const auto parse = [&parser](const std::vector<uint8_t>& bytes) {
        return parser.parse(bytes.data(), bytes.size());
    };

    // 1. 기본 TCP 패킷 — has_ports·필드·SYN 플래그·total_len
    {
        const auto p = parse(TCP_PACKET);
        expect(p.has_value(), "TCP 패킷 파싱 성공");
        if (p.has_value()) {
            expect(p->has_ports, "TCP has_ports=true");
            expect((p->tcp_flags & TH_SYN) != 0, "TCP SYN 플래그 감지");
            expect(p->total_len == 40, "TCP total_len (호스트 순서)");
            expect(p->tuple.src_ip == htonl(0xC0A8000A), "TCP 출발지 IP (네트워크 순서)");
            expect(p->tuple.dst_ip == htonl(0x0A000001), "TCP 목적지 IP (네트워크 순서)");
            expect(p->tuple.src_port == 12345, "TCP 출발지 포트 (호스트 순서)");
            expect(p->tuple.dst_port == 80, "TCP 목적지 포트 (호스트 순서)");
            expect(p->tuple.to_string() == "192.168.0.10:12345 -> 10.0.0.1:80 TCP",
                   "TCP to_string 형식");
        }
    }

    // 2. UDP 패킷
    {
        const auto p = parse(UDP_PACKET);
        expect(p.has_value() && p->has_ports, "UDP 패킷 파싱 성공(has_ports)");
        if (p.has_value()) {
            expect((p->tcp_flags & TH_SYN) == 0, "UDP는 SYN 플래그 없음");
            expect(p->tuple.to_string() == "172.16.0.5:5353 -> 8.8.8.8:53 UDP",
                   "UDP to_string 형식");
        }
    }

    // 3. IP 옵션 패킷 — ihl 기반 오프셋 계산 검증
    {
        const auto p = parse(IP_OPTIONS_TCP_PACKET);
        expect(p.has_value() && p->has_ports, "IP 옵션 패킷 파싱 성공");
        if (p.has_value()) {
            expect(p->tuple.to_string() == "10.0.0.2:443 -> 10.0.0.3:50000 TCP",
                   "IP 옵션 뒤 TCP 헤더 위치 정확");
        }
    }

    // 4a. nullopt이어야 하는 패킷 — IP 헤더 자체가 안 읽힘
    {
        expect(!parser.parse(nullptr, 0).has_value(), "빈 입력 거부(nullopt)");
        expect(!parser.parse(TCP_PACKET.data(), 10).has_value(), "잘린 IP 헤더 거부(nullopt)");

        std::vector<uint8_t> ipv6_like(40, 0x00);
        ipv6_like[0] = 0x60;  // 버전 6
        expect(!parse(ipv6_like).has_value(), "IPv6 거부(nullopt)");

        std::vector<uint8_t> bad_ihl = TCP_PACKET;
        bad_ihl[0] = 0x44;  // ihl=4 → 헤더 16B, 규격 미달
        expect(!parse(bad_ihl).has_value(), "규격 미달 ihl 거부(nullopt)");
    }

    // 4b. IP는 읽히나 전송 헤더가 없음 — has_ports=false, tuple은 유효
    {
        const auto icmp = parse(ICMP_PACKET);
        expect(icmp.has_value() && !icmp->has_ports, "ICMP → has_ports=false");
        if (icmp.has_value()) {
            expect(icmp->tuple.src_ip == htonl(0x0A000001), "ICMP도 출발지 IP는 유효");
        }

        std::vector<uint8_t> fragment = TCP_PACKET;
        fragment[6] = 0x00;
        fragment[7] = 0xB9;  // 조각 오프셋 185 — 뒤쪽 조각
        const auto frag = parse(fragment);
        expect(frag.has_value() && !frag->has_ports, "뒤쪽 IP 조각 → has_ports=false");

        const auto trunc_tcp = parser.parse(TCP_PACKET.data(), 30);  // TCP 헤더 잘림
        expect(trunc_tcp.has_value() && !trunc_tcp->has_ports,
               "잘린 TCP 헤더 → has_ports=false");

        const auto trunc_udp = parser.parse(UDP_PACKET.data(), 24);  // UDP 헤더 잘림
        expect(trunc_udp.has_value() && !trunc_udp->has_ports,
               "잘린 UDP 헤더 → has_ports=false");

        // ihl=6(헤더 24B) 주장 + 버퍼 22B — 옵션 구간 잘림, len < ip_header_len 분기
        const auto trunc_opt = parser.parse(IP_OPTIONS_TCP_PACKET.data(), 22);
        expect(trunc_opt.has_value() && !trunc_opt->has_ports,
               "옵션 잘린 IP 헤더 → has_ports=false");
    }

    if (failed_count == 0) {
        std::printf("\n모든 테스트 통과\n");
    } else {
        std::printf("\n%d개 테스트 실패\n", failed_count);
    }
    return failed_count == 0 ? 0 : 1;
}
