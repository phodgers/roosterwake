# Remote Wake firmware — Raspberry Pi Pico 2 W (RP2350A, CYW43439)
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)

# CMake 4 removed compatibility with cmake_minimum_required(VERSION < 3.5), which some of the
# SDK's vendored dependencies still declare. Raising the floor here keeps those configurable
# without pinning the whole toolchain to CMake 3.
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

# Two supported boards, both CYW43439-equipped:
#
#   pico2_w   RP2350, 4 MB flash, 520 KB SRAM, hardware TRNG   (the product)
#   pico_w    RP2040, 2 MB flash, 264 KB SRAM, no TRNG          (also supported)
#
#   cmake -S firmware -B build -DPICO_BOARD=pico_w
#
# The platform follows the board rather than being pinned, so nothing has to be passed twice
# and no combination can be selected that does not exist. See firmware/README.md for what
# differs between the two at runtime.
set(PICO_BOARD pico2_w CACHE STRING "Target board: pico2_w or pico_w")

if (PICO_BOARD STREQUAL "pico2_w")
    set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2350)
elseif (PICO_BOARD STREQUAL "pico_w")
    set(PICO_PLATFORM rp2040 CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2040)
else()
    message(FATAL_ERROR
        "PICO_BOARD is '${PICO_BOARD}'. This firmware supports pico2_w and pico_w - both have "
        "the CYW43439 radio it needs. Another board will not have Wi-Fi.")
endif()

# ── Build options ─────────────────────────────────────────────────────────────

# Path to a PEM file of root certificates that replaces the curated bundle. For a homelab relay
# behind a private CA.
set(RW_TLS_CUSTOM_CA "" CACHE FILEPATH "PEM file replacing the built-in root CA bundle")

# Disable certificate verification entirely. Off by default and loudly visible when on: the
# firmware flashes the error LED pattern continuously and logs on every connection.
option(RW_TLS_INSECURE "Skip TLS certificate verification (INSECURE)" OFF)

# Force diagnostic logging on regardless of the config flag. The flag lives in the config
# record, which an unprovisioned device does not have - so setup mode, the one state where
# logs are most needed, is the one state that cannot switch them on.
option(RW_FORCE_DIAG_LOG "Enable diagnostic logging at boot, ignoring the config flag" OFF)

# Trace every step of the TLS handshake, including the peer's alerts, over the USB serial
# port. Separate from RW_FORCE_DIAG_LOG because it is several hundred lines per connection
# and slow enough to change the timing of what it is observing - it answers "why was the
# handshake refused", which is a question you ask once, not a log you leave on.
option(RW_TLS_TRACE "Trace the TLS handshake over the serial port (very verbose)" OFF)

include(pico_sdk_import.cmake)

project(remotewake_firmware C CXX ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

pico_sdk_init()

# ── Which slot this image is linked for ───────────────────────────────────────
#
# XIP executes in place, so an image has to be linked at the address of the slot it will occupy.
# A release therefore builds each board twice and the device asks for the variant matching its
# inactive slot. See src/ota/layout.h for why that beats copying images between slots.
#
#   cmake -S firmware -B build-a -DPICO_BOARD=pico_w -DRW_SLOT=a
#   cmake -S firmware -B build-b -DPICO_BOARD=pico_w -DRW_SLOT=b
#
# The SDK puts the FLASH region in a generated pico_flash_region.ld that its memmap INCLUDEs,
# and pico_sdk_init() has already written it by this point — so overwriting it here is the
# supported seam and needs no vendored copy of the linker script. Confining the region to one
# slot also means an image that outgrows its slot is a link error rather than something that
# silently overwrites the other one.
set(RW_SLOT "a" CACHE STRING "Slot this image is linked to run in: a or b")

if (RW_SLOT STREQUAL "a")
    set(RW_SLOT_ORIGIN 0x10010000)
elseif (RW_SLOT STREQUAL "b")
    set(RW_SLOT_ORIGIN 0x100C0000)
else()
    message(FATAL_ERROR "RW_SLOT is '${RW_SLOT}'; it must be a or b.")
endif()
set(RW_SLOT_LENGTH "704 * 1024")

file(WRITE ${CMAKE_BINARY_DIR}/pico_flash_region.ld
     "FLASH(rx) : ORIGIN = ${RW_SLOT_ORIGIN}, LENGTH = ${RW_SLOT_LENGTH}\n")
message(STATUS "Linking for slot ${RW_SLOT} at ${RW_SLOT_ORIGIN}, ${RW_SLOT_LENGTH} bytes")

# The last page of this slot, which is where the RP2350 absolute block goes; see the UF2
# arguments further down.
math(EXPR RW_ABS_BLOCK_ADDR "${RW_SLOT_ORIGIN} + 704 * 1024 - 256" OUTPUT_FORMAT HEXADECIMAL)

# ── Optimisation level ────────────────────────────────────────────
#
# -O2, not -O3.
#
# GCC 14.2 (arm-none-eabi) at -O3 miscompiles mbedTLS's AES-GCM for this target: correct for
# a zero-length message, wrong for anything carrying data. TLS is the only user of GCM, so the
# handshake fails on its first encrypted record with `bad_record_mac` - every step before that
# is asymmetric or hashing and looks correct in a trace.
#
# Check it on hardware:
#   cmake -S firmware -B b -DPICO_BOARD=pico_w -DRW_FORCE_DIAG_LOG=ON -DRW_TLS_TRACE=ON
# then read the serial port - "AES-GCM-128 #1 (enc): failed" at -O3, passes at -O2.
#
# rw_tls_init() also runs a GCM known-answer test at boot in every build and refuses to start
# TLS if it fails.
#
# Normal variables rather than cache entries, so they apply in existing build trees.
set(CMAKE_C_FLAGS_RELEASE          "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE        "-O2 -DNDEBUG")

# ── Stack ─────────────────────────────────────────────────────────────────────
#
# 4 KB, not the SDK's 2 KB.
#
# Every relay frame is parsed by jsmn into a 128-token array, which is 2048 bytes of locals on
# its own — the whole default stack, before the handler it dispatches to has run at all. The
# stack sits at the top of SCRATCH_Y, so what overflowed into was the unused remainder of that
# bank rather than anything live, and the firmware worked. It worked by luck: SCRATCH_Y is 4 KB
# on both chips and nothing else is in it, so taking all of it costs nothing and turns a silent
# overrun into a link error the day something else wants the space.
add_compile_definitions(PICO_STACK_SIZE=4096)
set(CMAKE_C_FLAGS_RELWITHDEBINFO   "-O2 -g -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG")

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
    src/ota/image.c
    src/ota/state.c
    src/proto/auth.c
    src/proto/json.c
    src/provisioning/dhcp_msg.c
    src/provisioning/dns_msg.c
    src/provisioning/http_req.c
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
    src/diag/radio_trace.c
    src/led/led.c
    src/net/arplearn.c
    src/net/lanscan.c
    src/net/net.c
    src/net/scan.c
    src/ota/ota.c
    src/ota/ota_write.c
    src/ota/ota_flash.c
    src/ota/signing_key.c
    src/proto/probe.c
    src/proto/proto.c
    src/provisioning/dhcpserver.c
    src/provisioning/dnsserver.c
    src/provisioning/httpd.c
    src/provisioning/provisioning.c
    src/sys/sys.c
    src/sys/wallclock.c
    src/tls/ca_bundle.c
    src/tls/ca_bundle_custom.c
    src/tls/tls.c
    src/usbcfg/usbcfg.c
    src/wol/wol.c
    src/ws/ws.c
)

# ── Captive portal page ───────────────────────────────────────────────────────
#
# The portal is one self-contained HTML file, gzipped at build time and served straight out of
# flash with Content-Encoding: gzip. Every browser that can render a captive portal can also
# decompress one, so this costs nothing and turns ~16 KB into ~6 KB. Serving it from flash
# rather than a buffer means the page costs no SRAM at all.
#
# The generator is Python because it is already a hard dependency of the SDK's build, so this
# adds nothing to what a contributor must install. Regenerating on every change of the source
# file is what keeps the committed HTML and the shipped blob from ever disagreeing.
set(RW_PORTAL_SRC ${CMAKE_CURRENT_LIST_DIR}/src/provisioning/portal/portal.html)
set(RW_PORTAL_HDR ${CMAKE_CURRENT_BINARY_DIR}/generated/portal_html.h)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

add_custom_command(
    OUTPUT ${RW_PORTAL_HDR}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_LIST_DIR}/tools/gzip_header.py
            ${RW_PORTAL_SRC} ${RW_PORTAL_HDR} k_portal_html_gz
    DEPENDS ${RW_PORTAL_SRC} ${CMAKE_CURRENT_LIST_DIR}/tools/gzip_header.py
    COMMENT "Compressing the captive portal into portal_html.h"
    VERBATIM
)
add_custom_target(rw_portal_html DEPENDS ${RW_PORTAL_HDR})

add_executable(remotewake ${RW_PORTABLE_SOURCES} ${RW_DEVICE_SOURCES})
add_dependencies(remotewake rw_portal_html)

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
    # Poll mode, not threadsafe_background: every lwIP callback then runs on the main context.
    pico_cyw43_arch_lwip_poll
    pico_lwip_sntp
    pico_lwip_mbedtls
    pico_mbedtls
)

# RP2350 only: the RP2040 has no separately-managed XIP cache and no such library.
if (PICO_RP2350)
    target_link_libraries(remotewake hardware_xip_cache)
endif()

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

# ── Radio tracing shim ────────────────────────────────────────────────────────
#
# src/diag/radio_trace.h is force-included into every C translation unit, ours and the SDK's,
# so that it can claim CYW43_PRINTF before cyw43_config.h defines it as printf. That macro is
# the only seam the cyw43 driver offers — the callback that processes async events is compiled
# into the driver's own object alongside symbols the link needs, so a replacement is a duplicate
# symbol rather than an override — and the events it carries are the only place the radio says
# WHY an association was refused. See the header for the full argument.
#
# C only. `-include` applies to whatever language the option reaches, and feeding a C header to
# the assembler breaks the SDK's crt0. Two list entries rather than one string because `-include`
# takes its filename as a separate argument, and this path contains a space.
set(RW_TRACE_HEADER ${CMAKE_CURRENT_LIST_DIR}/src/diag/radio_trace.h)
target_compile_options(remotewake PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-include>
    $<$<COMPILE_LANGUAGE:C>:${RW_TRACE_HEADER}>
)
set_property(TARGET remotewake APPEND PROPERTY LINK_DEPENDS ${RW_TRACE_HEADER})

# Strict warnings, but only on our own sources. The SDK's libraries are INTERFACE targets whose
# sources compile into this executable, and holding third-party code to our warning settings
# means the build breaks on somebody else's schedule rather than on ours.
#
# -Wswitch-enum is the one worth naming: every switch over a protocol enum should list every
# case, and a frame type nobody handled is exactly the bug it catches.
set_source_files_properties(${RW_PORTABLE_SOURCES} ${RW_DEVICE_SOURCES}
    PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Wundef;-Wswitch-enum;-Werror")

# ── TLS build options ─────────────────────────────────────────────────────────

if (RW_FORCE_DIAG_LOG)
    message(STATUS "Diagnostic logging forced ON - this build chatters on the USB serial port")
    target_compile_definitions(remotewake PRIVATE RW_FORCE_DIAG_LOG=1)
endif()

if (RW_TLS_TRACE)
    message(STATUS "TLS handshake tracing is ON - this build prints the whole handshake")
    target_compile_definitions(remotewake PRIVATE RW_TLS_TRACE=1)
endif()

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
# See src/config/flash_reserve.ld.in. Appended to the SDK's memmap rather than replacing it.
#
# The threshold is computed here rather than written down, so it follows the board: the config
# lives in the top two sectors of flash, which is 0x103FE000 on a 4 MB Pico 2 W and 0x101FE000
# on a 2 MB Pico W. A hardcoded constant would pass vacuously on the smaller board while the
# runtime wrote past the end of the chip.
math(EXPR RW_CFG_SLOT_A_XIP "0x10000000 + ${PICO_FLASH_SIZE_BYTES} - 2 * 4096"
     OUTPUT_FORMAT HEXADECIMAL)
message(STATUS "Config sectors reserved from ${RW_CFG_SLOT_A_XIP} (${PICO_BOARD}, "
               "${PICO_FLASH_SIZE_BYTES} bytes of flash)")

set(RW_FLASH_RESERVE_LD ${CMAKE_CURRENT_BINARY_DIR}/generated/flash_reserve.ld)
configure_file(${CMAKE_CURRENT_LIST_DIR}/src/config/flash_reserve.ld.in
               ${RW_FLASH_RESERVE_LD} @ONLY)

target_link_options(remotewake PRIVATE -T${RW_FLASH_RESERVE_LD})
set_target_properties(remotewake PROPERTIES LINK_DEPENDS ${RW_FLASH_RESERVE_LD})

# ── Outputs ───────────────────────────────────────────────────────────────────

pico_enable_stdio_usb(remotewake 1)
pico_enable_stdio_uart(remotewake 0)

pico_set_program_name(remotewake "Remote Wake")
pico_set_program_description(remotewake "Wake-on-LAN dongle")
pico_set_program_url(remotewake "https://github.com/remotewake/remotewake")

# ── Packaging the UF2 ─────────────────────────────────────────────────────────
#
# --platform states the chip rather than leaving picotool to infer it. picotool works the chip
# out from the image's own metadata block, and looks for that block at the start of flash — so an
# image linked into a slot, which has nothing at 0x10000000, is taken for an RP2040 and its
# RP2350 SRAM banks then read as out of range:
#
#   ERROR: Memory segment 20081000->20081800 is outside of valid address range for device
#
# --abs-block places the RP2350-E10 block in the last page of this slot. The block is a page of
# filler whose write is itself the workaround, and picotool addresses it at 0x10ffff00 by default
# — the top of the 16 MB XIP window, which only exists on a 16 MB part. QSPI addressing drops the
# upper bits, so on the 4 MB part fitted it wraps into the second configuration sector, and an
# update that promises to leave configuration alone would erase it. Only the address matters, and
# picotool takes it as an argument; inside the slot the page lands in space the image never
# reaches.
set(RW_UF2_ARGS "--platform;${RW_PICOTOOL_PLATFORM}")
if (PICO_PLATFORM STREQUAL "rp2350-arm-s")
    list(APPEND RW_UF2_ARGS "--abs-block" "${RW_ABS_BLOCK_ADDR}")
endif()
set_target_properties(remotewake PROPERTIES PICOTOOL_EXTRA_UF2_ARGS "${RW_UF2_ARGS}")

pico_add_extra_outputs(remotewake)

# ── Host tests ────────────────────────────────────────────────────────────────
#
# Not added here. The test target is a native build and cannot share a CMake tree with an
# ARM cross-compile — one toolchain per configure. Build it separately:
#
#   cmake -S firmware/test -B build-test && cmake --build build-test && ctest --test-dir build-test
