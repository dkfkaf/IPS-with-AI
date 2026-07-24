#ifndef IPS_SRC_COMMON_FIVE_TUPLE_H_
#define IPS_SRC_COMMON_FIVE_TUPLE_H_

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

// 네트워크 바이트 순서 IPv4 주소를 점 표기 문자열로 바꾼다 (로그·표시용).
// FiveTuple·BlockList 등이 공유한다 — inet_ntoa의 정적 버퍼 재사용 버그를 피하려고
// 내부적으로 inet_ntop을 쓴다. 이 변환을 각자 다시 짜지 않도록 한 곳에 둔다.
std::string ip_to_string(uint32_t ip_network_order);

// 플로우를 식별하는 5-튜플. 파싱 결과를 담는 단순 데이터 묶음이므로 struct로 둔다.
//
// IP는 사람이 읽는 문자열이 아니라 uint32_t 숫자(네트워크 바이트 순서 그대로)로 저장한다.
// 비교·조회가 빠르고, 로그 출력 시에만 to_string()으로 변환한다.
// 포트는 파싱 시점에 호스트 바이트 순서로 변환해 둔다 — 이후 Rule 검사에서
// 포트 번호를 숫자 그대로 비교할 수 있게 하기 위함이다.
struct FiveTuple {
    uint32_t src_ip;    // 출발지 IP (네트워크 바이트 순서)
    uint32_t dst_ip;    // 목적지 IP (네트워크 바이트 순서)
    uint16_t src_port;  // 출발지 포트 (호스트 바이트 순서)
    uint16_t dst_port;  // 목적지 포트 (호스트 바이트 순서)
    uint8_t protocol;   // 프로토콜 번호 (TCP=6, UDP=17)

    // 로그 출력용 문자열을 만든다 (예: "192.168.0.10:12345 -> 10.0.0.1:80 TCP")
    std::string to_string() const;

    // FlowManager의 플로우 키로 쓰기 위한 동등 비교 (다섯 필드 전부 일치해야 같은 플로우)
    bool operator==(const FiveTuple& other) const {
        return src_ip == other.src_ip && dst_ip == other.dst_ip && src_port == other.src_port &&
               dst_port == other.dst_port && protocol == other.protocol;
    }

    // 출발지·목적지를 뒤집은 5-튜플 (양방향 플로우 조회용 — 응답 방향 키)
    FiveTuple reversed() const {
        return FiveTuple{dst_ip, src_ip, dst_port, src_port, protocol};
    }
};

// unordered_map<FiveTuple, ...>의 키로 쓰기 위한 해시. 다섯 필드를 섞는다.
// TODO: 곱셈 해시는 역산이 가능해 해시 충돌 공격(IPS 자체를 느리게 만드는 공격)에
// 취약하다 — 난수 시드 해시로 교체 예정 (2026-07 성능 리뷰 6번 지적).
struct FiveTupleHash {
    std::size_t operator()(const FiveTuple& t) const {
        std::size_t h = std::hash<uint32_t>{}(t.src_ip);
        h = h * 31 + std::hash<uint32_t>{}(t.dst_ip);
        h = h * 31 + t.src_port;
        h = h * 31 + t.dst_port;
        h = h * 31 + t.protocol;
        return h;
    }
};

#endif  // IPS_SRC_COMMON_FIVE_TUPLE_H_
