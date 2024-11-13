cmake_minimum_required(VERSION 3.10)
project(PcapAnalysis)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(PCAPPLUSPLUS_DIR "${CMAKE_SOURCE_DIR}/PcapPlusPlus")
add_subdirectory(${PCAPPLUSPLUS_DIR})

set(SOURCES
        main.cpp
        Parser.cpp
        )

add_executable(PcapAnalysis ${SOURCES})
target_link_libraries(PcapAnalysis
        Pcap++
        Packet++
        Common++
        gflags
        )

set_target_properties(PcapAnalysis PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR})