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

# 경고 옵션은 모든 타깃에 공통 — 타깃마다 반복하지 않는다
add_compile_options(-Wall -Wextra)

add_executable(ips
    src/main.cpp
    src/packet_capture.cpp
    src/packet_source.cpp
    src/packet_parser.cpp
    src/five_tuple.cpp
)
target_link_libraries(ips PRIVATE PkgConfig::NFQUEUE PkgConfig::GLOG)

# 파서 단독 테스트 — NFQUEUE·root 권한 없이 파싱 로직만 검증한다
# (ips_stage1_design.md 6장 "구현 순서 1번": 파서를 네트워크 없이 먼저 확인)
enable_testing()
add_executable(parser_test
    tests/parser_test.cpp
    src/packet_parser.cpp
    src/five_tuple.cpp
)
target_include_directories(parser_test PRIVATE src)
add_test(NAME parser_test COMMAND parser_test)
