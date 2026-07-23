#ifndef IPS_SRC_RESPONSE_WHITELIST_H_
#define IPS_SRC_RESPONSE_WHITELIST_H_

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

// 항상 통과시킬 IP 집합 (규칙 판정 이전에 검사하는 최종 안전장치).
// 키는 네트워크 바이트 순서 uint32 — 파서의 src_ip와 같은 순서라야 조회가 맞는다.
class Whitelist {
 public:
    // 문자열 IP 목록을 적재한다. 형식이 잘못된 항목이 하나라도 있으면 false (호출자 fail-fast).
    bool load(const std::vector<std::string>& ip_strings);
    bool is_whitelisted(uint32_t ip) const;  // O(1)

 private:
    std::unordered_set<uint32_t> ips_;
};

#endif  // IPS_SRC_RESPONSE_WHITELIST_H_
