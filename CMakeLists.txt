cmake_minimum_required(VERSION 3.16)

project(EpiScan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_library(episcan_core
	src/app/ScannerEngine.cpp
)

target_include_directories(episcan_core
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(episcan-cli
	src/cli_main.cpp
)

target_link_libraries(episcan-cli
	PRIVATE
		episcan_core
)

find_package(SFML 2.5 COMPONENTS graphics window system QUIET)

if(SFML_FOUND)
	add_executable(episcan
		src/gui_main.cpp
	)

	target_link_libraries(episcan
		PRIVATE
			episcan_core
			sfml-graphics
			sfml-window
			sfml-system
	)
else()
	message(WARNING "SFML not found: building CLI-only mode. Install libsfml-dev to enable GUI.")
	add_executable(episcan
		src/cli_main.cpp
	)
	target_link_libraries(episcan PRIVATE episcan_core)
endif()

# ── Network traffic analyser (requires libpcap) ───────────────────────────────
find_package(LibPCAP QUIET)

if(LibPCAP_FOUND)
	add_executable(episcan-net
		src/net_main.cpp
		src/network/TrafficAnalyzer.cpp
	)
	target_include_directories(episcan-net PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
	target_link_libraries(episcan-net PRIVATE LibPCAP::LibPCAP)
	message(STATUS "libpcap found — episcan-net will be built")
else()
	message(WARNING "libpcap not found: episcan-net will NOT be built. Install libpcap-dev to enable it.")
endif()

