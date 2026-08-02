# Native host tests for the portable half of the firmware.
#
# A separate CMake project from firmware/CMakeLists.txt on purpose: that one cross-compiles for
# the RP2350, and one CMake tree gets one toolchain. Build it with the host compiler:
#
#   cmake -S firmware/test -B build-test
#   cmake --build build-test
#   ctest --test-dir build-test --output-on-failure
#
# Everything here compiles the same source files the firmware does — no mocks and no second
# implementation, because a test that exercises a copy of the code proves nothing about the
# code that ships.
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

project(remotewake_tests C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

enable_testing()

set(RW_FIRMWARE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
set(RW_SRC ${RW_FIRMWARE_DIR}/src)

# ── mbedTLS ───────────────────────────────────────────────────────────────────
#
# proto/auth.c and ws/ws_handshake.c use mbedTLS's SHA-256, SHA-1 and base64, so the tests
# build those same sources rather than substituting another implementation. Four files and a
# ten-line config is a small price for testing the code that actually runs on the device.
if (NOT MBEDTLS_DIR)
    if (DEFINED ENV{PICO_SDK_PATH})
        set(MBEDTLS_DIR "$ENV{PICO_SDK_PATH}/lib/mbedtls")
    endif()
endif()
if (NOT EXISTS "${MBEDTLS_DIR}/library/sha256.c")
    message(FATAL_ERROR
        "mbedTLS sources not found. Set PICO_SDK_PATH (with its lib/mbedtls submodule checked "
        "out) or pass -DMBEDTLS_DIR=/path/to/mbedtls. Looked in: '${MBEDTLS_DIR}'")
endif()

set(MBEDTLS_SOURCES
    ${MBEDTLS_DIR}/library/base64.c
    ${MBEDTLS_DIR}/library/constant_time.c
    ${MBEDTLS_DIR}/library/platform.c
    ${MBEDTLS_DIR}/library/platform_util.c
    ${MBEDTLS_DIR}/library/sha1.c
    ${MBEDTLS_DIR}/library/sha256.c
    # ota/image.c verifies an ECDSA P-256 signature.
    ${MBEDTLS_DIR}/library/asn1parse.c
    ${MBEDTLS_DIR}/library/asn1write.c
    ${MBEDTLS_DIR}/library/bignum.c
    ${MBEDTLS_DIR}/library/bignum_core.c
    ${MBEDTLS_DIR}/library/ecdsa.c
    ${MBEDTLS_DIR}/library/ecp.c
    ${MBEDTLS_DIR}/library/ecp_curves.c
    ${MBEDTLS_DIR}/library/md.c
)

# ── Signed-image fixtures ─────────────────────────────────────────────────────
#
# A throwaway key is generated here and used to sign a fixture with the real tools/sign_image.py,
# so the tests fail if the writer and src/ota/image.c ever disagree about the format. The build
# never needs the real signing key: only releases do.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(RW_FIXTURE_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
execute_process(
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/tools/make_fixture.py ${RW_FIXTURE_DIR}
    RESULT_VARIABLE RW_FIXTURE_RC
    OUTPUT_VARIABLE RW_FIXTURE_OUT
    ERROR_VARIABLE RW_FIXTURE_ERR
)
if (NOT RW_FIXTURE_RC EQUAL 0)
    message(FATAL_ERROR "could not build the signed-image fixtures (needs openssl on PATH):
${RW_FIXTURE_ERR}")
endif()

# ── The firmware sources under test ───────────────────────────────────────────
#
# Kept in step with RW_PORTABLE_SOURCES in firmware/CMakeLists.txt. A file in one list and not
# the other is either untested or unshipped.
set(RW_PORTABLE_SOURCES
    ${RW_SRC}/config/config.c
    ${RW_SRC}/net/nbns.c
    ${RW_SRC}/net/url.c
    ${RW_SRC}/ota/image.c
    ${RW_SRC}/ota/state.c
    ${RW_SRC}/proto/auth.c
    ${RW_SRC}/proto/json.c
    ${RW_SRC}/provisioning/dhcp_msg.c
    ${RW_SRC}/provisioning/dns_msg.c
    ${RW_SRC}/provisioning/http_req.c
    ${RW_SRC}/usbcfg/cmdline.c
    ${RW_SRC}/vendor/jsmn.c
    ${RW_SRC}/wol/magic.c
    ${RW_SRC}/ws/ws_frame.c
    ${RW_SRC}/ws/ws_handshake.c
)

set(TEST_SOURCES
    test_main.c
    vectors_json.c
    test_config.c
    test_wol.c
    test_ws_frame.c
    test_ws_handshake.c
    test_auth.c
    test_ota_image.c
    test_ota_state.c
    test_json.c
    test_url.c
    test_usbcfg.c
    test_provisioning.c
    test_nbns.c
)

add_executable(rw_tests ${TEST_SOURCES} ${RW_PORTABLE_SOURCES} ${MBEDTLS_SOURCES}
               ${RW_FIXTURE_DIR}/signing_key.c)

target_include_directories(rw_tests PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}
    ${RW_SRC}
    ${CMAKE_CURRENT_LIST_DIR}/host
    ${RW_FIXTURE_DIR}
    ${MBEDTLS_DIR}/include
    ${MBEDTLS_DIR}/library
)

target_compile_definitions(rw_tests PRIVATE
    MBEDTLS_CONFIG_FILE="host_mbedtls_config.h"
)

target_compile_options(rw_tests PRIVATE
    -Wall -Wextra -Wshadow -Wundef -Werror
    # Unconditional, because it is the cheapest possible insurance and it is portable. Ubuntu's
    # GCC turns this on by default and MinGW does not, and that difference alone once let a test
    # with a 529-byte write into a 512-byte buffer pass locally and abort in CI. A check that
    # only some contributors get is a check that finds bugs at the least convenient moment.
    -fstack-protector-strong
)

# ── Sanitizers ────────────────────────────────────────────────────────────────
#
# ASan and UBSan are the right tools for code whose whole job is parsing hostile input, but
# MinGW-w64 ships neither, so they cannot be the default without breaking the Windows build.
# CI turns them on; `-DRW_TEST_SANITIZE=ON` gets you the same locally on Linux or macOS.
option(RW_TEST_SANITIZE "Build the host tests with ASan and UBSan" OFF)

if (RW_TEST_SANITIZE)
    # -fno-sanitize-recover makes UBSan abort rather than print and carry on. A warning in a log
    # that still exits 0 is a warning nobody reads.
    set(RW_SAN_FLAGS -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    target_compile_options(rw_tests PRIVATE ${RW_SAN_FLAGS})
    target_link_options(rw_tests PRIVATE ${RW_SAN_FLAGS})
    # mbedTLS is exempted from our warning settings but not from the sanitizers: a bug there
    # would corrupt our memory just as thoroughly.
    message(STATUS "Host tests built with ASan and UBSan")
endif()
# mbedTLS is held to its own warning settings, not ours.
set_source_files_properties(${MBEDTLS_SOURCES} PROPERTIES COMPILE_OPTIONS "-w")

# Bake the vector directory in so the binary is self-locating. ctest still passes it
# explicitly as argv[1], which wins — that keeps the out-of-tree case working (packaging the
# tests, or running them against a different vector set) without making the ordinary
# `./rw_tests` invocation depend on the working directory.
target_compile_definitions(rw_tests PRIVATE RW_TEST_DATA_DIR="${CMAKE_CURRENT_LIST_DIR}")

add_test(NAME rw_tests COMMAND rw_tests ${CMAKE_CURRENT_LIST_DIR})
