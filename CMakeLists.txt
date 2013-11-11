cmake_minimum_required (VERSION 2.6)
project (dnssniff)

add_definitions(-g -std=c++11 -W -Wall -Wextra -fstack-protector-all)

find_package(Boost REQUIRED COMPONENTS system program_options)

INCLUDE(cmake/locate_library.cmake)
LOCATE_LIBRARY(PCAP "pcap.h" "pcap")

include_directories(${PROJECT_SOURCE_DIR}/include
	${Boost_INCLUDE_DIRS}
	${PCAP_INCLUDE_DIRS}
)

link_directories(
	${Boost_LIBRARY_DIRS}
	${PCAP_LIBRARY_DIRS}
)

add_executable(dnssniff sniff.cpp)
target_link_libraries(dnssniff
	${Boost_LIBRARIES}
	${PCAP_LIBRARIES}
)
