#include "flow/flow_manager.h"

#include <chrono>

#include <netinet/tcp.h>

#include <gtest/gtest.h>

#include "capture/packet_parser.h"
#include "common/clock.h"

namespace {
using std::chrono::seconds;

// has_ports=true TCP 패킷 하나를 만든다. SYN 여부·목적지 포트·출발지 IP를 지정.
ParsedPacket tcp(uint32_t src_ip, uint16_t dst_port, bool syn) {
    ParsedPacket p = {};
    p.tuple.src_ip = src_ip;
    p.tuple.dst_ip = 0x0A000001;
    p.tuple.src_port = 40000;
    p.tuple.dst_port = dst_port;
    p.tuple.protocol = 6;
    p.total_len = 40;
    p.has_ports = true;
    p.tcp_flags = syn ? TH_SYN : 0;
    return p;
}
constexpr uint32_t SRC = 0xC0A80005;

// 방향·크기·플래그를 지정한 TCP 패킷 (플로우 테스트용)
ParsedPacket pkt(uint32_t sip, uint16_t sport, uint32_t dip, uint16_t dport, uint16_t len,
                 uint8_t flags) {
    ParsedPacket p = {};
    p.tuple = FiveTuple{sip, dip, sport, dport, 6};
    p.total_len = len;
    p.has_ports = true;
    p.tcp_flags = flags;
    return p;
}
constexpr uint32_t CLI = 0x01010101;
constexpr uint32_t SRV = 0x02020202;
}  // namespace

TEST(FlowManagerTest, AccumulatesPortsAndSyn) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    const SourceStats* s = nullptr;
    for (uint16_t port = 1; port <= 5; ++port) {
        s = fm.add_packet(tcp(SRC, port, /*syn=*/true), t0);
    }
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->recent_dst_ports.size(), 5u);
    EXPECT_EQ(s->syn_count, 5u);
}

TEST(FlowManagerTest, WindowResetsAfterWindowSeconds) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    fm.add_packet(tcp(SRC, 1, true), t0);
    const SourceStats* s = fm.add_packet(tcp(SRC, 2, true), t0 + seconds(10));  // 창 리셋
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->recent_dst_ports.size(), 1u);  // 리셋 후 현재 패킷만
    EXPECT_EQ(s->syn_count, 1u);
}

TEST(FlowManagerTest, MaxSourcesReturnsNullptrForNewSource) {
    FlowManager fm(/*window_seconds=*/10, /*max_flows=*/1000, /*max_sources=*/2);
    TimePoint t0{};
    EXPECT_NE(fm.add_packet(tcp(0x01010101, 1, true), t0), nullptr);
    EXPECT_NE(fm.add_packet(tcp(0x02020202, 1, true), t0), nullptr);
    EXPECT_EQ(fm.add_packet(tcp(0x03030303, 1, true), t0), nullptr);  // 상한 초과 → nullptr
    EXPECT_NE(fm.add_packet(tcp(0x01010101, 2, true), t0), nullptr);  // 기존 출발지는 계속 갱신
}

TEST(FlowManagerTest, MaxFlowsStillUpdatesSourceStats) {
    // 플로우 상한을 넘겨도 출발지 통계는 계속 갱신돼 탐지가 유지돼야 한다.
    FlowManager fm(/*window_seconds=*/10, /*max_flows=*/1, /*max_sources=*/1000);
    TimePoint t0{};
    fm.add_packet(tcp(SRC, 1, true), t0);                        // 플로우 1개 생성
    const SourceStats* s = fm.add_packet(tcp(SRC, 2, true), t0);  // 새 플로우는 생략되지만
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->recent_dst_ports.size(), 2u);                   // 출발지 통계는 계속 쌓임
}

TEST(FlowManagerTest, MergesBothDirectionsIntoOneFlow) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, TH_SYN), t0);            // 요청 (forward)
    fm.add_packet(pkt(SRV, 80, CLI, 5000, 100, TH_SYN | TH_ACK), t0);  // 응답 (backward)
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 40, TH_ACK), t0);            // 요청

    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->forward.packet_len.count, 2u);   // 요청 2개
    EXPECT_EQ(f->backward.packet_len.count, 1u);  // 응답 1개
    EXPECT_EQ(f->forward.syn, 1u);                // 요청 중 SYN 1개
    EXPECT_EQ(f->backward.syn, 1u);               // 응답 SYN+ACK → SYN·ACK 각 1
    EXPECT_EQ(f->backward.ack, 1u);
}

TEST(FlowManagerTest, PacketLenMeanAndStddev) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    for (uint16_t len : {100, 100, 100, 100}) {  // 전부 같음 → 표준편차 0
        fm.add_packet(pkt(CLI, 5000, SRV, 80, len, TH_ACK), t0);
    }
    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.mean(), 100.0);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.stddev(), 0.0);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.min, 100.0);
    EXPECT_DOUBLE_EQ(f->forward.packet_len.sum, 400.0);  // 바이트 수
}

TEST(FlowManagerTest, InterArrivalTimeAccumulates) {
    FlowManager fm(/*window_seconds=*/1000);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, 0), t0);  // 첫 패킷: 간격 없음
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, 0), t0 + seconds(2));  // 간격 2s
    const Flow* f = fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6});
    ASSERT_NE(f, nullptr);
    EXPECT_EQ(f->forward.iat_us.count, 1u);                // 간격은 패킷수-1
    EXPECT_DOUBLE_EQ(f->forward.iat_us.mean(), 2000000.0);  // 2초 = 2e6 마이크로초
}

TEST(FlowManagerTest, GetFlowFindsEitherDirectionElseNull) {
    FlowManager fm(/*window_seconds=*/10);
    TimePoint t0{};
    fm.add_packet(pkt(CLI, 5000, SRV, 80, 60, TH_SYN), t0);
    EXPECT_NE(fm.get_flow(FiveTuple{CLI, SRV, 5000, 80, 6}), nullptr);  // 정방향
    EXPECT_NE(fm.get_flow(FiveTuple{SRV, CLI, 80, 5000, 6}), nullptr);  // 역방향
    EXPECT_EQ(fm.get_flow(FiveTuple{CLI, SRV, 9999, 80, 6}), nullptr);  // 없음
}
