#include "common/five_tuple.h"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstdio>

// 네트워크 바이트 순서의 IPv4 주소를 점 표기 문자열로 바꾼다 (five_tuple.h 선언).
// inet_ntoa는 내부 정적 버퍼를 재사용해 한 줄에 IP 두 개를 찍으면 값이 덮이므로 inet_ntop을 쓴다.
std::string ip_to_string(uint32_t ip_network_order) {
    char buffer[INET_ADDRSTRLEN] = {};
    struct in_addr address;
    address.s_addr = ip_network_order;
    if (inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
        return "?";
    }
    return buffer;
}

namespace {

// 프로토콜 번호를 사람이 읽는 이름으로 바꾼다. 모르는 번호는 숫자 그대로 출력한다.
std::string protocol_to_string(uint8_t protocol) {
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        default:
            return std::to_string(protocol);
    }
}

}  // namespace

std::string FiveTuple::to_string() const {
    // 패킷마다 불리는 함수라, 고정 형식 한 줄에 ostringstream의 스트림 기계장치(내부 버퍼·로캘)를
    // 매번 만드는 비용을 피하고 스택 버퍼에 한 번에 만든다.
    // 가장 긴 형태("255.255.255.255:65535 -> 255.255.255.255:65535 255")도 50자 안팎 — 64면 충분
    char line[64] = {};
    std::snprintf(line, sizeof(line), "%s:%u -> %s:%u %s", ip_to_string(src_ip).c_str(),
                  static_cast<unsigned>(src_port), ip_to_string(dst_ip).c_str(),
                  static_cast<unsigned>(dst_port), protocol_to_string(protocol).c_str());
    return std::string(line);
}
