cmake_minimum_required(VERSION 3.16)
project(ips CXX)

# std::optional 사용을 위해 C++17 필요
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# libnetfilter_queue, glog 모두 Ubuntu 패키지가 pkg-config(.pc) 파일을 제공한다.
# IMPORTED_TARGET을 쓰면 include 경로·링크 경로·라이브러리가 타깃 하나로 함께 전파된다.
find_package(PkgConfig REQUIRED)
pkg_check_modules(NFQUEUE REQUIRED IMPORTED_TARGET libnetfilter_queue)
pkg_check_modules(GLOG REQUIRED IMPORTED_TARGET libglog)

# nlohmann/json — 헤더 온리 설정 파서. Ubuntu: sudo apt install nlohmann-json3-dev
find_package(nlohmann_json REQUIRED)
# Google Test — 2단계에서 도입 (coding_style.md 6.3). Ubuntu: sudo apt install libgtest-dev
find_package(GTest REQUIRED)

# 경고 옵션은 모든 타깃에 공통 — 타깃마다 반복하지 않는다
add_compile_options(-Wall -Wextra)

# include는 src 기준 경로로 통일한다 (예: #include "flow/flow_manager.h"). Google 스타일.
include_directories(src)

# --- 센서 본체 ---
add_executable(ips
    src/main.cpp
    src/common/five_tuple.cpp
    src/capture/packet_capture.cpp
    src/capture/packet_source.cpp
    src/capture/packet_parser.cpp
    src/flow/flow_manager.cpp
    src/detect/port_scan_rule.cpp
    src/detect/syn_flood_rule.cpp
    src/detect/rule_engine.cpp
    src/response/block_list.cpp
    src/response/whitelist.cpp
    src/config/config.cpp
)
target_link_libraries(ips PRIVATE PkgConfig::NFQUEUE PkgConfig::GLOG nlohmann_json::nlohmann_json)

enable_testing()

# 파서 단독 테스트 — 손수 만든 하네스(GTest 미사용), NFQUEUE·glog 링크 없음
# (docs/design/stage1.md 6장: 파서를 네트워크 없이 먼저 확인)
add_executable(parser_test
    tests/parser_test.cpp
    src/capture/packet_parser.cpp
    src/common/five_tuple.cpp
)
add_test(NAME parser_test COMMAND parser_test)

# 아래 3종은 GTest. 시간 주입(TimePoint)으로 TTL·창·상한 등 시간 의존 로직을 검증한다.
add_executable(block_list_test
    tests/block_list_test.cpp
    src/response/block_list.cpp
    src/common/five_tuple.cpp  # block_list가 로그에서 ip_to_string() 사용 → 링크에 필요
)
target_link_libraries(block_list_test PRIVATE GTest::gtest_main PkgConfig::GLOG)
add_test(NAME block_list_test COMMAND block_list_test)

add_executable(flow_manager_test
    tests/flow_manager_test.cpp
    src/flow/flow_manager.cpp
    src/common/five_tuple.cpp
)
target_link_libraries(flow_manager_test PRIVATE GTest::gtest_main)
add_test(NAME flow_manager_test COMMAND flow_manager_test)

add_executable(config_test
    tests/config_test.cpp
    src/config/config.cpp
    src/response/whitelist.cpp
)
target_link_libraries(config_test PRIVATE GTest::gtest_main PkgConfig::GLOG nlohmann_json::nlohmann_json)
add_test(NAME config_test COMMAND config_test)

add_executable(rule_test
    tests/rule_test.cpp
    src/detect/port_scan_rule.cpp
    src/detect/syn_flood_rule.cpp
    src/detect/rule_engine.cpp
)
target_link_libraries(rule_test PRIVATE GTest::gtest_main)
add_test(NAME rule_test COMMAND rule_test)
