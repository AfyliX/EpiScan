cmake_minimum_required(VERSION 3.16)

project(EpiScan LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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

