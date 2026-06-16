cmake_minimum_required(VERSION 3.16)

project(EpiScan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ── Google Test via FetchContent ──────────────────────────────────────────────
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.14.0
    GIT_SHALLOW    TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()

add_library(episcan_core
    src/app/ScannerEngine.cpp
    src/analyzer/UnsafeFunctionDetector.cpp
    src/analyzer/InjectionDetector.cpp
    src/analyzer/CryptoDetector.cpp
    src/analyzer/VulnDetector.cpp
    src/analyzer/CodeParser.cpp
    src/core/Vulnerability.cpp
    src/core/Severity.cpp
    src/core/Report.cpp
    src/core/Config.cpp
    src/core/Cvss.cpp
    src/core/Metrics.cpp
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

# ── Network modules (non-pcap) ────────────────────────────────────────────────
add_library(episcan_network
    src/network/PortScanner.cpp
    src/network/BannerGrabber.cpp
    src/network/ServiceDetector.cpp
    src/network/NetworkvulAnalyzer.cpp
)
target_include_directories(episcan_network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(episcan_network PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(episcan_network PRIVATE EPISCAN_HAVE_OPENSSL)
    message(STATUS "OpenSSL found — SSL audit enabled")
else()
    message(WARNING "OpenSSL not found: SSL audit will be limited.")
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
add_subdirectory(tests)

