#ifndef IPS_SRC_FLOW_FLOW_H_
#define IPS_SRC_FLOW_FLOW_H_

#include <cmath>
#include <cstdint>
#include <unordered_set>

#include "common/clock.h"
#include "common/five_tuple.h"

// 최소/최대/평균/표준편차를 한 번에 뽑는 누적기. 합·제곱합·개수만 쌓으면 파생값이 다 나온다.
// 패킷 크기와 패킷 간격이 같은 로직을 쓰므로 한 곳에 묶는다.
struct RunningStats {
    uint64_t count = 0;
    double sum = 0.0;
    double sq_sum = 0.0;  // 제곱합 — 표준편차용
    double min = 0.0;     // count>0일 때만 의미
    double max = 0.0;

    void add(double x) {
        if (count == 0) {
            min = max = x;
        } else {
            if (x < min) min = x;
            if (x > max) max = x;
        }
        ++count;
        sum += x;
        sq_sum += x * x;
    }
    double mean() const { return count ? sum / static_cast<double>(count) : 0.0; }
    double stddev() const {
        if (count == 0) return 0.0;
        const double m = mean();
        const double var = sq_sum / static_cast<double>(count) - m * m;  // 모분산
        return var > 0.0 ? std::sqrt(var) : 0.0;  // 부동소수 오차로 음수면 0
    }
};

// 플로우 한 방향의 특징 원재료.
struct DirectionStats {
    RunningStats packet_len;  // count=패킷수, sum=바이트수, mean/stddev/min/max
    RunningStats iat_us;      // 같은 방향 연속 패킷 간격 (마이크로초)
    TimePoint last_seen{};    // IAT 계산용 (packet_len.count==0이면 아직 패킷 없음)
    uint32_t syn = 0, ack = 0, fin = 0, rst = 0, psh = 0, urg = 0;  // TCP 플래그별 카운트
};

// 플로우 1개 = 양방향 대화. key는 정방향(초기자) 5-튜플이자 맵 키.
struct Flow {
    FiveTuple key;
    TimePoint first_seen;
    TimePoint last_seen;      // 지속시간 = last_seen - first_seen
    DirectionStats forward;   // key 방향 (플로우를 연 쪽)
    DirectionStats backward;  // 반대 방향
};

// 출발지 IP 1개의 교차-플로우 통계 (고정 창). 포트 스캔·SYN 플러드 판정의 입력.
struct SourceStats {
    std::unordered_set<uint16_t> recent_dst_ports;  // 창 안에 접촉한 목적지 포트
    uint32_t syn_count = 0;                         // 창 안의 SYN(플래그 선) 패킷 수
    TimePoint window_start;
};

#endif  // IPS_SRC_FLOW_FLOW_H_
