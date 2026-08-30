#include "response/block_list.h"

#include <glog/logging.h>

#include "common/five_tuple.h"  // ip_to_string (네트워크 순서 uint32 → 문자열)

namespace {

// 패킷 처리 스레드가 대량 만료 정리에 오래 묶이지 않도록 틱당 작업량을 제한한다.
constexpr size_t MAX_EXPIRY_CLEANUPS_PER_TICK = 16384;

}  // namespace

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
    // 틱당 pop 상한 — 공격 중엔 차단 수천 건이 같은 초에 만료되는데, 건마다 로그를 찍으며
    // 한 번에 전부 비우면 그동안 패킷 처리가 멈춘다. 나머지는 다음 틱에 이어서 지운다.
    // (is_blocked가 만료 시각을 직접 검사하므로 늦게 지워져도 판정은 정확하다)
    // 상한은 설계상 최대 차단 발생률(max_sources/window ≈ 초당 1만)보다 커야 한다 —
    // 배출이 유입을 못 따라가면 힙이 무한히 자란다. 로그가 없는 pop은 건당 수백 ns라
    // 상한을 꽉 채워도 틱 하나가 수 ms를 넘지 않는다.
    size_t released = 0;
    for (size_t i = 0; i < MAX_EXPIRY_CLEANUPS_PER_TICK && !expiry_heap_.empty() &&
                       expiry_heap_.top().expiry <= now;
         ++i) {
        const HeapEntry entry = expiry_heap_.top();
        expiry_heap_.pop();
        const auto it = block_map_.find(entry.ip);
        // map 값과 대조 — 일치할 때만 실제 해제. 불일치면 연장으로 생긴 낡은 항목이라 버린다.
        if (it != block_map_.end() && it->second == entry.expiry) {
            block_map_.erase(it);
            ++released;
        }
    }
    if (released > 0) {
        // 건별 로그는 대량 만료 때 그 자체가 병목 — 요약 한 줄로 찍는다
        LOG(INFO) << "차단 해제(TTL 만료): " << released << "건";
    }
}
