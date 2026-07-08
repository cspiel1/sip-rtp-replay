cmake_minimum_required(VERSION 3.16)
project(sip-rtp-replay C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")

find_package(PkgConfig REQUIRED)

# libre
find_library(RE_LIB re PATHS /usr/local/lib REQUIRED)
find_path(RE_INCLUDE re/re.h PATHS /usr/local/include REQUIRED)

# libpcap
find_library(PCAP_LIB pcap REQUIRED)

add_executable(sip-rtp-replay main.c)

target_include_directories(sip-rtp-replay PRIVATE ${RE_INCLUDE})
target_link_libraries(sip-rtp-replay PRIVATE ${RE_LIB} ${PCAP_LIB} m)
