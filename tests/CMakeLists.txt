include(GoogleTest)

function(add_episcan_test name src)
    add_executable(${name} ${src})
    target_link_libraries(${name}
        PRIVATE
            episcan_core
            episcan_network
            GTest::gtest_main
    )
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
    )
    gtest_discover_tests(${name})
endfunction()

add_episcan_test(test_code_parser      test_code_parser.cpp)
add_episcan_test(test_vuln_detector    test_vuln_detector.cpp)
add_episcan_test(test_port_scanner     test_port_scanner.cpp)
add_episcan_test(test_service_detector test_service_detector.cpp)
add_episcan_test(test_integration      test_integration.cpp)
