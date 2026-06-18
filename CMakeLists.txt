cmake_minimum_required(VERSION 3.16)

project(EpiScan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# ── Dependency sourcing (#68) ──────────────────────────────────────────────────
# Two supported paths:
#  - Default: GTest/CLI11/nlohmann_json are pulled via FetchContent (no extra
#    tooling required — this is what build.sh uses).
#  - Conan: run `conan install . --output-folder=build --build=missing` then
#    configure with `-DEPISCAN_USE_CONAN_DEPS=ON
#    -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake` (see conanfile.txt).
#    Boost/OpenSSL already resolve transparently either way since both system
#    package managers and Conan's CMakeDeps generator produce a standard
#    BoostConfig.cmake/OpenSSLConfig.cmake that plain find_package() picks up.
option(EPISCAN_USE_CONAN_DEPS "Resolve GTest/CLI11/nlohmann_json via Conan-generated find_package() instead of FetchContent" OFF)

include(FetchContent)

if(EPISCAN_USE_CONAN_DEPS)
    find_package(GTest REQUIRED)
    find_package(CLI11 REQUIRED)
    find_package(nlohmann_json REQUIRED)
else()
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    FetchContent_Declare(
        cli11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG        v2.4.2
        GIT_SHALLOW    TRUE
    )
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG        v3.11.3
        GIT_SHALLOW    TRUE
    )
    set(JSON_BuildTests OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(cli11 nlohmann_json)
endif()

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
target_link_libraries(episcan_core PUBLIC nlohmann_json::nlohmann_json)

add_executable(episcan-cli
	src/cli_main.cpp
)

target_link_libraries(episcan-cli
	PRIVATE
		episcan_core
		CLI11::CLI11
)

# ── Network modules (port scan, banners, service id, SSL audit — no libpcap) ──
add_library(episcan_network
    src/network/PortScanner.cpp
    src/network/BannerGrabber.cpp
    src/network/ServiceDetector.cpp
    src/network/NetworkvulAnalyzer.cpp
    src/network/CveLookup.cpp
)
target_include_directories(episcan_network PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(episcan-cli PRIVATE episcan_network)
target_link_libraries(episcan_network PUBLIC nlohmann_json::nlohmann_json)

# libcurl — only used by the opt-in live NVD lookup (#73)
find_package(CURL QUIET)
if(CURL_FOUND)
    target_link_libraries(episcan_network PRIVATE CURL::libcurl)
    target_compile_definitions(episcan_network PRIVATE EPISCAN_HAVE_CURL)
    message(STATUS "libcurl found — live NVD CVE lookup enabled (opt-in via cveCheck)")
else()
    message(WARNING "libcurl not found: live NVD CVE lookup will be unavailable (offline signature checks still work).")
endif()

# Standalone Asio (#71) — header-only for our usage (resolver/socket/steady_timer).
# We use the standalone edition (ASIO_STANDALONE) so there is no Boost dependency;
# the API is identical to Boost.Asio but uses std::error_code throughout.
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE
)
FetchContent_MakeAvailable(asio)
add_library(asio_standalone INTERFACE)
target_include_directories(asio_standalone INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio_standalone INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(episcan_network PUBLIC asio_standalone)

find_package(OpenSSL QUIET)
if(OpenSSL_FOUND)
    target_link_libraries(episcan_network PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(episcan_network PRIVATE EPISCAN_HAVE_OPENSSL)
    message(STATUS "OpenSSL found — SSL audit enabled")
else()
    message(WARNING "OpenSSL not found: SSL audit will be limited.")
endif()

# ── Network traffic analyser (requires libpcap) ───────────────────────────────
find_package(LibPCAP QUIET)

if(LibPCAP_FOUND)
	add_library(episcan_traffic
		src/network/TrafficAnalyzer.cpp
	)
	target_include_directories(episcan_traffic PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
	target_link_libraries(episcan_traffic PUBLIC LibPCAP::LibPCAP nlohmann_json::nlohmann_json)

	add_executable(episcan-net
		src/net_main.cpp
	)
	target_link_libraries(episcan-net PRIVATE episcan_traffic)
	message(STATUS "libpcap found — episcan-net will be built")

	# Live capture needs CAP_NET_RAW. Grant it on the binary so it works without
	# sudo; this is best-effort since setting capabilities itself needs privilege.
	find_program(SETCAP_EXECUTABLE setcap)
	if(SETCAP_EXECUTABLE)
		add_custom_command(TARGET episcan-net POST_BUILD
			COMMAND sh -c "${SETCAP_EXECUTABLE} cap_net_raw,cap_net_admin=eip $<TARGET_FILE:episcan-net> 2>/dev/null || echo '[episcan-net] could not grant CAP_NET_RAW automatically -- run: sudo setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:episcan-net>'"
			VERBATIM)
	endif()
else()
	message(WARNING "libpcap not found: episcan-net will NOT be built. Install libpcap-dev to enable it.")
endif()

find_package(SFML 2.5 COMPONENTS graphics window system QUIET)

if(SFML_FOUND)
	add_executable(episcan
		src/gui_main.cpp
	)

	target_link_libraries(episcan
		PRIVATE
			episcan_core
			episcan_network
			sfml-graphics
			sfml-window
			sfml-system
	)

	if(LibPCAP_FOUND)
		target_link_libraries(episcan PRIVATE episcan_traffic)
		target_compile_definitions(episcan PRIVATE EPISCAN_HAVE_PCAP)

		if(SETCAP_EXECUTABLE)
			add_custom_command(TARGET episcan POST_BUILD
				COMMAND sh -c "${SETCAP_EXECUTABLE} cap_net_raw,cap_net_admin=eip $<TARGET_FILE:episcan> 2>/dev/null || echo '[episcan] could not grant CAP_NET_RAW automatically -- run: sudo setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:episcan>'"
				VERBATIM)
		endif()
	endif()
else()
	message(WARNING "SFML not found: building CLI-only mode. Install libsfml-dev to enable GUI.")
	add_executable(episcan
		src/cli_main.cpp
	)
	target_link_libraries(episcan PRIVATE episcan_core episcan_network CLI11::CLI11)
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
add_subdirectory(tests)

