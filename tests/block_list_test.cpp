#include "response/block_list.h"

#include <chrono>

#include <gtest/gtest.h>

#include "common/clock.h"

namespace {
using std::chrono::seconds;
constexpr uint32_t IP_A = 0x0A000001;  // 바이트 순서는 테스트 내에서만 일관되면 됨
constexpr uint32_t IP_B = 0x0A000002;
}  // namespace

TEST(BlockListTest, BlocksAndExpiresByTtl) {
    BlockList list;
    TimePoint t0{};
    list.block(IP_A, 10, t0);
    EXPECT_TRUE(list.is_blocked(IP_A, t0));
    EXPECT_TRUE(list.is_blocked(IP_A, t0 + seconds(9)));
    EXPECT_FALSE(list.is_blocked(IP_A, t0 + seconds(10)));  // 만료 시각 도달 → 차단 아님
    EXPECT_FALSE(list.is_blocked(IP_B, t0));                // 등록 안 된 IP
}

TEST(BlockListTest, ExtendRenewsExpiry) {
    BlockList list;
    TimePoint t0{};
    list.block(IP_A, 10, t0);
    list.block(IP_A, 10, t0 + seconds(5));  // 연장 → 만료 t0+15
    EXPECT_TRUE(list.is_blocked(IP_A, t0 + seconds(12)));
    EXPECT_FALSE(list.is_blocked(IP_A, t0 + seconds(15)));
}

TEST(BlockListTest, CleanupDropsStaleHeapEntryAfterExtend) {
    // 연장으로 힙에 낡은 항목(t0+10)이 남지만, cleanup은 map 값(t0+15)과 대조해
    // 낡은 항목을 버리고 IP를 해제하지 않아야 한다 (지연 삭제).
    BlockList list;
    TimePoint t0{};
    list.block(IP_A, 10, t0);
    list.block(IP_A, 10, t0 + seconds(5));   // map 만료 = t0+15
    list.cleanup_expired(t0 + seconds(11));  // 낡은 힙 항목(t0+10)만 pop, 해제 X
    EXPECT_TRUE(list.is_blocked(IP_A, t0 + seconds(12)));
}
