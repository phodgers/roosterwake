# Remote Wake firmware — Raspberry Pi Pico 2 W (RP2350A, CYW43439)
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)

# CMake 4 removed compatibility with cmake_minimum_required(VERSION < 3.5), which some of the
# SDK's vendored dependencies still declare. Raising the floor here keeps those configurable
# without pinning the whole toolchain to CMake 3.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

set(PICO_BOARD pico2_w CACHE STRING "Target board")
set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Target platform")

# ── Build options ─────────────────────────────────────────────────────────────

# Path to a PEM file of root certificates that replaces the curated bundle. For a homelab relay
# behind a private CA.
set(RW_TLS_CUSTOM_CA "" CACHE FILEPATH "PEM file replacing the built-in root CA bundle")

# Disable certificate verification entirely. Off by default and loudly visible when on: the
# firmware flashes the error LED pattern continuously and logs on every connection.
option(RW_TLS_INSECURE "Skip TLS certificate verification (INSECURE)" OFF)

include(pico_sdk_import.cmake)

project(remotewake_firmware C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

if (NOT TARGET pico_cyw43_arch)
    message(FATAL_ERROR
        "pico_cyw43_arch is unavailable. The pico-sdk needs its lib/cyw43-driver and lib/lwip "
        "submodules checked out: git -C \${PICO_SDK_PATH} submodule update --init")
endif()

# ── Sources ───────────────────────────────────────────────────────────────────

# Kept in step with test/CMakeLists.txt, which compiles the host-portable subset of this list
# natively. A file that appears in only one of the two is either untested or unshipped.
set(RW_PORTABLE_SOURCES
    src/config/config.c
    src/net/url.c
    src/proto/auth.c
    src/proto/json.c
    src/usbcfg/cmdline.c
    src/vendor/jsmn.c
    src/wol/magic.c
    src/ws/ws_frame.c
    src/ws/ws_handshake.c
)

set(RW_DEVICE_SOURCES
    src/main.c
    src/rw_log.c
    src/config/config_flash.c
    src/led/led.c
    src/net/arplearn.c
    src/net/net.c
    src/proto/probe.c
    src/proto/proto.c
    src/sys/sys.c
    src/sys/wallclock.c
    src/tls/ca_bundle.c
    src/tls/ca_bundle_custom.c
    src/tls/tls.c
    src/usbcfg/usbcfg.c
    src/wol/wol.c
    src/ws/ws.c
)

add_executable(remotewake ${RW_PORTABLE_SOURCES} ${RW_DEVICE_SOURCES})

target_include_directories(remotewake PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/src
    # mbedtls_config.h lives here and is found by the SDK's pico_mbedtls_config.h, which does
    # #include "mbedtls_config.h" and relies on the application to supply it.
    ${CMAKE_CURRENT_LIST_DIR}/src/tls
    ${CMAKE_CURRENT_BINARY_DIR}/generated
)

target_link_libraries(remotewake
    pico_stdlib
    pico_unique_id
    pico_rand
    pico_flash
    hardware_flash
    hardware_watchdog
    hardware_xip_cache
    # Poll mode, not threadsafe_background: every lwIP callback then runs on the main context.
    pico_cyw43_arch_lwip_poll
    pico_lwip_sntp
    pico_lwip_mbedtls
    pico_mbedtls
)

target_compile_definitions(remotewake PRIVATE
    # Core 1 is never launched, so flash_safe_execute() has nothing to coordinate with. Without
    # this it refuses to run at all, because it cannot know what the other core is doing.
    PICO_FLASH_ASSUME_CORE1_SAFE=1

    # The usbcfg channel (usbcfg.md) is CDC-only; there is no UART on the enclosure.
    PICO_STDIO_USB=1

    # Never wait for a host to open the port. A dongle behind a router has no host, and a
    # firmware that blocks at start-up until one appears would simply never run.
    PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS=0
)

# USB descriptor strings (usbcfg.md §1). VID stays at the SDK default 0x2E8A (Raspberry Pi),
# which is what the document specifies. The strings come from brand.h so that renaming the
# product remains a one-file edit; they are passed as definitions because the SDK's descriptor
# table is built from macros, not from a header it includes.
target_compile_definitions(remotewake PRIVATE
    USBD_MANUFACTURER="Remote Wake"
    USBD_PRODUCT="Remote Wake"
)

# Strict warnings, but only on our own sources. The SDK's libraries are INTERFACE targets whose
# sources compile into this executable, and holding third-party code to our warning settings
# means the build breaks on somebody else's schedule rather than on ours.
#
# -Wswitch-enum is the one worth naming: every switch over a protocol enum should list every
# case, and a frame type nobody handled is exactly the bug it catches.
set_source_files_properties(${RW_PORTABLE_SOURCES} ${RW_DEVICE_SOURCES}
    PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Wundef;-Wswitch-enum;-Werror")

# ── TLS build options ─────────────────────────────────────────────────────────

if (RW_TLS_INSECURE)
    message(WARNING
        "RW_TLS_INSECURE is ON. This build does not verify relay certificates and can be "
        "intercepted by anything on the path. It flashes the error LED continuously.")
    target_compile_definitions(remotewake PRIVATE RW_TLS_INSECURE=1)
endif()

if (RW_TLS_CUSTOM_CA)
    if (NOT EXISTS ${RW_TLS_CUSTOM_CA})
        message(FATAL_ERROR "RW_TLS_CUSTOM_CA points at a file that does not exist: ${RW_TLS_CUSTOM_CA}")
    endif()
    # Emitted as bytes rather than a string literal: a PEM pasted into a C string is one stray
    # backslash away from a bundle that is not what the operator supplied.
    file(READ ${RW_TLS_CUSTOM_CA} _rw_ca_hex HEX)
    string(REGEX REPLACE "(..)" "0x\\1," _rw_ca_bytes ${_rw_ca_hex})
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)
    file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated/rw_custom_ca.h
        "/* Generated from ${RW_TLS_CUSTOM_CA}. Do not edit. */\n"
        "static const unsigned char k_rw_custom_ca[] = {${_rw_ca_bytes}0x00};\n")
    target_compile_definitions(remotewake PRIVATE RW_TLS_CUSTOM_CA=1)
    message(STATUS "TLS root bundle replaced by ${RW_TLS_CUSTOM_CA}")
endif()

# ── Linker assertion: the image must not reach the config sectors ─────────────
#
# See src/config/flash_reserve.ld. Appended to the SDK's memmap rather than replacing it.
target_link_options(remotewake PRIVATE
    -T${CMAKE_CURRENT_LIST_DIR}/src/config/flash_reserve.ld
)
set_target_properties(remotewake PROPERTIES
    LINK_DEPENDS ${CMAKE_CURRENT_LIST_DIR}/src/config/flash_reserve.ld)

# ── Outputs ───────────────────────────────────────────────────────────────────

pico_enable_stdio_usb(remotewake 1)
pico_enable_stdio_uart(remotewake 0)

pico_set_program_name(remotewake "Remote Wake")
pico_set_program_description(remotewake "Wake-on-LAN dongle")
pico_set_program_url(remotewake "https://github.com/remotewake/remotewake")

pico_add_extra_outputs(remotewake)

# ── Host tests ────────────────────────────────────────────────────────────────
#
# Not added here. The test target is a native build and cannot share a CMake tree with an
# ARM cross-compile — one toolchain per configure. Build it separately:
#
#   cmake -S firmware/test -B build-test && cmake --build build-test && ctest --test-dir build-test
