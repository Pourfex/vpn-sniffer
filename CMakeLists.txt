cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

find_library(TINS_LIBRARY tins)
include_directories(include)

find_package(rxcpp CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(Threads)

add_executable(sniffer src/main.cpp src/sniffer/package.h src/sniffer/vpn-sniffer.cpp src/sniffer/vpn-sniffer.h src/udp_packets_saver.h)

target_link_libraries(sniffer "${TINS_LIBRARY}")
target_link_libraries(sniffer ${CMAKE_THREAD_LIBS_INIT})

