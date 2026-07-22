#ifndef IPS_SRC_FIVE_TUPLE_H_
#define IPS_SRC_FIVE_TUPLE_H_

#include <cstdint>
#include <string>

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
};

#endif  // IPS_SRC_FIVE_TUPLE_H_
