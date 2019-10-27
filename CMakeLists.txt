cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

find_library(TINS_LIBRARY tins)

add_executable(sniffer src/main.cpp)

target_link_libraries(sniffer "${TINS_LIBRARY}")