#ifndef IPS_SRC_RESPONSE_BLOCK_LIST_H_
#define IPS_SRC_RESPONSE_BLOCK_LIST_H_

#include <cstdint>
#include <queue>
#include <unordered_map>
#include <vector>

#include "common/clock.h"

// 힙 항목: 만료 시각으로 정렬. std::greater로 min-heap을 만들기 위해 operator>를 준다.
struct HeapEntry {
    TimePoint expiry;
    uint32_t ip;
    bool operator>(const HeapEntry& other) const { return expiry > other.expiry; }
};

// 차단 IP 관리 (map + min-heap + 지연 삭제, docs/design/overview.md 6.2).
// map이 진실의 원천, heap은 만료 순 정리를 위한 보조 색인.
class BlockList {
 public:
    void block(uint32_t ip, int ttl_seconds, TimePoint now);  // 신규 차단 또는 만료 연장
    bool is_blocked(uint32_t ip, TimePoint now);              // O(1), 만료면 false
    void cleanup_expired(TimePoint now);                      // 힙 상단만 확인

 private:
    std::unordered_map<uint32_t, TimePoint> block_map_;  // IP → 만료 시각 (진실의 원천)
    std::priority_queue<HeapEntry, std::vector<HeapEntry>, std::greater<HeapEntry>> expiry_heap_;
};

#endif  // IPS_SRC_RESPONSE_BLOCK_LIST_H_
