# The loader — the first 64 KB of flash, and the only part an update never replaces.
#
# A separate CMake project from the firmware because the two are linked into different regions
# and one build tree gets one FLASH region:
#
#   cmake -S firmware/loader -B build-loader -DPICO_BOARD=pico_w
#   cmake --build build-loader
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

# Wider board support than the firmware, which needs the CYW43439. Nothing here touches the
# radio, so the loader and the boot chain it is half of can be exercised on a plain Pico 2 or
# Pico — the same silicon and the same flash size as the boards sold, without the part that is
# hardest to get hold of.
set(PICO_BOARD pico2_w CACHE STRING "Target board: pico2_w, pico2, pico_w or pico")
if (PICO_BOARD STREQUAL "pico2_w" OR PICO_BOARD STREQUAL "pico2")
    set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2350)
elseif (PICO_BOARD STREQUAL "pico_w" OR PICO_BOARD STREQUAL "pico")
    set(PICO_PLATFORM rp2040 CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2040)
else()
    message(FATAL_ERROR "PICO_BOARD is '${PICO_BOARD}'; expected pico2_w, pico2, pico_w or pico.")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../pico_sdk_import.cmake)

project(remotewake_loader C CXX ASM)
set(CMAKE_C_STANDARD 11)

pico_sdk_init()

# -O2 for the same reason the firmware pins it; see firmware/CMakeLists.txt.
set(CMAKE_C_FLAGS_RELEASE   "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")

# Confine the loader to the region reserved for it in src/ota/layout.h. Overwriting the SDK's
# generated flash region is the seam the memmap's INCLUDE leaves open; capping the LENGTH means
# a loader that grows into slot A is a link error rather than a corrupted image.
file(WRITE ${CMAKE_BINARY_DIR}/pico_flash_region.ld
     "FLASH(rx) : ORIGIN = 0x10000000, LENGTH = 64 * 1024\n")

set(RW_SRC ${CMAKE_CURRENT_LIST_DIR}/../src)

add_executable(loader
    main.c
    ${RW_SRC}/ota/state.c
    ${RW_SRC}/ota/ota_flash.c
    ${RW_SRC}/config/config.c   # rw_crc32, and nothing else survives --gc-sections
)

target_include_directories(loader PRIVATE ${RW_SRC})

# Deliberately not pico_stdlib's stdio: there is no USB stack here and no UART on the enclosure,
# so the only thing it could do is add several kilobytes and enumerate a device the host would
# see appear and vanish on every boot.
target_link_libraries(loader
    pico_stdlib
    hardware_flash
)
# A build that explains itself. Off by default: the production loader has no USB at all.
option(RW_LOADER_DIAG "Bring up USB serial and report what the loader found" OFF)
if (RW_LOADER_DIAG)
    message(STATUS "Loader diagnostics ON - this build enumerates as a serial port before booting")
    target_compile_definitions(loader PRIVATE RW_LOADER_DIAG=1
                               PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS=0)
    pico_enable_stdio_usb(loader 1)
else()
    pico_enable_stdio_usb(loader 0)
endif()
pico_enable_stdio_uart(loader 0)

set_source_files_properties(main.c PROPERTIES
    COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Wundef;-Werror")

pico_set_program_name(loader "Rooster Wake loader")

# --platform states the chip instead of leaving picotool to infer it, and --abs-block moves the
# RP2350-E10 block out of the top of the XIP window and into the last page of the loader's own
# region. Both for the reasons set out against the same arguments in firmware/CMakeLists.txt.
set(RW_UF2_ARGS "--platform;${RW_PICOTOOL_PLATFORM}")
if (PICO_PLATFORM STREQUAL "rp2350-arm-s")
    list(APPEND RW_UF2_ARGS "--abs-block" "0x1000ff00")
endif()
set_target_properties(loader PROPERTIES PICOTOOL_EXTRA_UF2_ARGS "${RW_UF2_ARGS}")

pico_add_extra_outputs(loader)
