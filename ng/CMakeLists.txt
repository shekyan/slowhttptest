# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.16)
project(slowhttptest_ng
  VERSION 2.0.0
  DESCRIPTION "Modern C++ rewrite of slowhttptest"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# ---------------------------------------------------------------------------
# Apple Silicon: build native even when cmake itself is not.
#
# A cmake installed by Intel Homebrew is an x86_64 binary, so on Apple Silicon
# it runs under Rosetta. Everything it reports about the host is then x86_64 --
# uname(3) included -- and it silently produces an x86_64 binary that runs
# emulated, then finds the x86_64 OpenSSL under /usr/local to match.
#
# That is worth catching rather than tolerating. A tool whose job is measuring
# someone else's timing has no business being emulated, and the mismatch is
# invisible: the build succeeds, the tests pass, and only `file` on the result
# gives it away. It cost a long debugging session here, comparing an emulated
# build against a native one and reading the difference as a bug.
#
# hw.optional.arm64 is the one thing Rosetta does not lie about, so ask it
# rather than uname. Only applied when the caller has expressed no preference;
# -DCMAKE_OSX_ARCHITECTURES=x86_64 still gets exactly what it asked for.
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
  execute_process(COMMAND sysctl -n hw.optional.arm64
                  OUTPUT_VARIABLE _shng_native_arm64
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  if(_shng_native_arm64 STREQUAL "1" AND
     NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(CMAKE_OSX_ARCHITECTURES arm64 CACHE STRING
        "Build architectures for macOS" FORCE)
    message(STATUS
      "Host is Apple Silicon but cmake is running translated; "
      "targeting arm64 so the binary is not emulated")
    # An existing cache cannot come along. This branch only runs when the
    # architecture is changing, and a build directory configured for the other
    # one has already recorded which OpenSSL it found; find_package will reuse
    # that path, and clearing the entry is not enough, because the pkg-config
    # results it was derived from are cached separately under undocumented
    # names. The link then fails on every OpenSSL symbol, which reads as a
    # broken OpenSSL rather than a stale build directory.
    if(DEFINED CACHE{OPENSSL_SSL_LIBRARY})
      message(FATAL_ERROR
        "This build directory was configured for a different architecture "
        "(${CMAKE_HOST_SYSTEM_PROCESSOR}). Delete it and configure again:\n"
        "    rm -rf ${CMAKE_BINARY_DIR} && cmake -S ${CMAKE_SOURCE_DIR} -B ${CMAKE_BINARY_DIR}")
    endif()

    # The matching OpenSSL lives under the Apple Silicon Homebrew prefix. Left
    # to itself, find_package would keep the /usr/local one it can see and fail
    # to link.
    if(NOT OPENSSL_ROOT_DIR AND IS_DIRECTORY /opt/homebrew/opt/openssl@3)
      set(OPENSSL_ROOT_DIR /opt/homebrew/opt/openssl@3)
    endif()
  endif()
endif()

# TLS is on by default and OpenSSL is the only mandatory dependency. Turning it
# off is supported for constrained builds -- the binary still builds and runs,
# and refuses https targets with an explanation rather than failing to link.
# The engine closes descriptors on worker threads; see Closer in engine.cpp.
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

option(SLOWHTTP_TLS "Build with TLS/https support (system OpenSSL)" ON)
if(SLOWHTTP_TLS)
  find_package(OpenSSL REQUIRED)
endif()

# Reusable, testable engine library.
add_library(slowhttp STATIC
  src/net/http2.cpp
  src/net/reactor_poll.cpp
  src/net/socket.cpp
  src/net/address.cpp
  src/net/tls.cpp
  src/engine/engine.cpp
  src/engine/probe.cpp
  src/attacks/slow_headers.cpp
  src/attacks/slow_read.cpp
  src/attacks/slow_body.cpp
  src/attacks/range.cpp
  src/config/cli.cpp
  src/report/event_log.cpp
  src/report/report_json.cpp
  src/report/report_html.cpp
)
target_include_directories(slowhttp
  PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_options(slowhttp PRIVATE -Wall -Wextra)
target_link_libraries(slowhttp PUBLIC Threads::Threads)

# One source of truth for the version. It reaches the -V output, the help text,
# the User-Agent and the report, so a release bump is this line in project()
# and nothing else.
target_compile_definitions(slowhttp PRIVATE SLOWHTTP_VERSION="${PROJECT_VERSION}")

if(SLOWHTTP_TLS)
  target_compile_definitions(slowhttp PUBLIC SLOWHTTP_HAVE_TLS)
  target_link_libraries(slowhttp PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

# Thin CLI front-end.
add_executable(slowhttptest-ng cli/main.cpp)
target_link_libraries(slowhttptest-ng PRIVATE slowhttp)
target_compile_options(slowhttptest-ng PRIVATE -Wall -Wextra)

# ---------------------------------------------------------------------------
# Install
#
# GNUInstallDirs rather than hard-coded paths, because distro packaging is the
# reason this is C++ rather than Rust and every distro disagrees about libdir,
# mandir and DESTDIR handling.
#
# The binary and its man page only. libslowhttp is deliberately NOT installed:
# it is a static library whose headers are still moving, and shipping it would
# be a promise of API stability the project is not ready to make. It stays
# available for in-tree embedding.
include(GNUInstallDirs)

install(TARGETS slowhttptest-ng
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/man/slowhttptest-ng.1
        DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

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

add_executable(test_report tests/test_report.cpp)
target_link_libraries(test_report PRIVATE slowhttp)
add_test(NAME report_unit COMMAND test_report)

add_executable(test_http2 tests/test_http2.cpp)
target_link_libraries(test_http2 PRIVATE slowhttp)
add_test(NAME http2_unit COMMAND test_http2)

add_executable(test_reactor tests/test_reactor.cpp)
target_link_libraries(test_reactor PRIVATE slowhttp)
add_test(NAME reactor_unit COMMAND test_reactor)

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

  # End-to-end: TLS, proxying, the availability probe and the report artifacts.
  add_test(NAME e2e_transport
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/e2e_transport.py
            $<TARGET_FILE:slowhttptest-ng>
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/mock_slow_server.py
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/mock_proxy.py)
  set_tests_properties(e2e_transport PROPERTIES TIMEOUT 900)
endif()
