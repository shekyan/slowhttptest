# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(slowhttptest_ng
  VERSION 2.0.0
  DESCRIPTION "Modern C++ rewrite of slowhttptest (M0 scaffold)"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Reusable, testable engine library.
add_library(slowhttp STATIC
  src/net/reactor_poll.cpp
  src/net/socket.cpp
  src/net/address.cpp
  src/engine/engine.cpp
  src/attacks/slow_headers.cpp
  src/attacks/slow_read.cpp
  src/attacks/slow_body.cpp
  src/attacks/range.cpp
  src/config/cli.cpp
)
target_include_directories(slowhttp
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(slowhttp PRIVATE -Wall -Wextra)

# Thin CLI front-end.
add_executable(slowhttptest-ng cli/main.cpp)
target_link_libraries(slowhttptest-ng PRIVATE slowhttp)
target_compile_options(slowhttptest-ng PRIVATE -Wall -Wextra)

enable_testing()

add_executable(test_slow_headers tests/test_slow_headers.cpp)
target_link_libraries(test_slow_headers PRIVATE slowhttp)
add_test(NAME slow_headers_unit COMMAND test_slow_headers)

add_executable(test_slow_read tests/test_slow_read.cpp)
target_link_libraries(test_slow_read PRIVATE slowhttp)
add_test(NAME slow_read_unit COMMAND test_slow_read)

add_executable(test_slow_body tests/test_slow_body.cpp)
target_link_libraries(test_slow_body PRIVATE slowhttp)
add_test(NAME slow_body_unit COMMAND test_slow_body)

add_executable(test_range tests/test_range.cpp)
target_link_libraries(test_range PRIVATE slowhttp)
add_test(NAME range_unit COMMAND test_range)

add_executable(test_cli tests/test_cli.cpp)
target_link_libraries(test_cli PRIVATE slowhttp)
add_test(NAME cli_unit COMMAND test_cli)

# Smoke test: the binary builds and prints help without error.
add_test(NAME cli_help COMMAND slowhttptest-ng -h)

# End-to-end: attack a local vulnerable server and assert it actually saturates.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME e2e_attacks
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e_attacks.py
            $<TARGET_FILE:slowhttptest-ng>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/mock_slow_server.py)
  set_tests_properties(e2e_attacks PROPERTIES TIMEOUT 900)
endif()
