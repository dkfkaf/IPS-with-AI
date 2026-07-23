#include "response/block_list.h"

#include <glog/logging.h>

#include "common/five_tuple.h"  // ip_to_string (네트워크 순서 uint32 → 문자열)

void BlockList::block(uint32_t ip, int ttl_seconds, TimePoint now) {
    const TimePoint expiry = now + std::chrono::seconds(ttl_seconds);
    // insert_or_assign: 신규 삽입이면 second=true. 조회를 한 번만 한다(find+[] 이중 조회 방지).
    const bool is_new = block_map_.insert_or_assign(ip, expiry).second;
    expiry_heap_.push(HeapEntry{expiry, ip});  // 힙엔 항상 push — 낡은 항목은 지연 삭제
    if (is_new) {
        // 차단 등록 시 1회만 로그 (차단된 패킷마다 찍으면 DDoS 시 로그 폭주)
        LOG(WARNING) << "차단 등록: " << ip_to_string(ip) << " (TTL " << ttl_seconds << "s)";
    }
}

bool BlockList::is_blocked(uint32_t ip, TimePoint now) {
    const auto it = block_map_.find(ip);
    if (it == block_map_.end()) {
        return false;
    }
    return now < it->second;  // 만료 시각 이전이면 차단 중 (실제 제거는 cleanup에 맡김)
}

void BlockList::cleanup_expired(TimePoint now) {
    while (!expiry_heap_.empty() && expiry_heap_.top().expiry <= now) {
        const HeapEntry entry = expiry_heap_.top();
        expiry_heap_.pop();
        const auto it = block_map_.find(entry.ip);
        // map 값과 대조 — 일치할 때만 실제 해제. 불일치면 연장으로 생긴 낡은 항목이라 버린다.
        if (it != block_map_.end() && it->second == entry.expiry) {
            LOG(INFO) << "차단 해제(TTL 만료): " << ip_to_string(entry.ip);
            block_map_.erase(it);
        }
    }
}
