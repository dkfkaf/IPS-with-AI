#ifndef IPS_SRC_COMMON_CLOCK_H_
#define IPS_SRC_COMMON_CLOCK_H_

#include <chrono>

// 단조(monotonic) 시계 — 벽시계 조정·NTP 동기화에 TTL·창이 영향받지 않게 한다.
// TimePoint를 인자로 주고받는 설계 덕에 테스트에서 시간을 자유롭게 흘릴 수 있다.
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

#endif  // IPS_SRC_COMMON_CLOCK_H_
