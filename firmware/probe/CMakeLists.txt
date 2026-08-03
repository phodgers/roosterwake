# The slot probe — a slot-linked program with no radio in it.
#
# Same relationship to the loader as the firmware has, and the same build shape: one tree per
# slot, because a tree gets one FLASH region.
#
#   cmake -S firmware/probe -B build-probe-a -DPICO_BOARD=pico2 -DRW_SLOT=a
#   cmake --build build-probe-a
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

set(PICO_BOARD pico2 CACHE STRING "Target board: pico2, pico2_w, pico or pico_w")
if (PICO_BOARD STREQUAL "pico2" OR PICO_BOARD STREQUAL "pico2_w")
    set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2350)
elseif (PICO_BOARD STREQUAL "pico" OR PICO_BOARD STREQUAL "pico_w")
    set(PICO_PLATFORM rp2040 CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2040)
else()
    message(FATAL_ERROR "PICO_BOARD is '${PICO_BOARD}'; expected pico2, pico2_w, pico or pico_w.")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../pico_sdk_import.cmake)

project(remotewake_probe C CXX ASM)
set(CMAKE_C_STANDARD 11)

pico_sdk_init()

set(RW_SLOT "a" CACHE STRING "Slot this image is linked to run in: a or b")
if (RW_SLOT STREQUAL "a")
    set(RW_SLOT_ORIGIN 0x10010000)
elseif (RW_SLOT STREQUAL "b")
    set(RW_SLOT_ORIGIN 0x100C0000)
else()
    message(FATAL_ERROR "RW_SLOT is '${RW_SLOT}'; it must be a or b.")
endif()

# The same seam the firmware uses, and deliberately the same numbers: a probe that proved the
# boot chain at addresses the firmware does not use would have proved nothing.
file(WRITE ${CMAKE_BINARY_DIR}/pico_flash_region.ld
     "FLASH(rx) : ORIGIN = ${RW_SLOT_ORIGIN}, LENGTH = 704 * 1024\n")
math(EXPR RW_ABS_BLOCK_ADDR "${RW_SLOT_ORIGIN} + 704 * 1024 - 256" OUTPUT_FORMAT HEXADECIMAL)
message(STATUS "Probe linked for slot ${RW_SLOT} at ${RW_SLOT_ORIGIN}")

set(RW_SRC ${CMAKE_CURRENT_LIST_DIR}/../src)

add_executable(probe
    main.c
    ${RW_SRC}/ota/ota.c
    ${RW_SRC}/ota/ota_flash.c
    ${RW_SRC}/ota/state.c
    ${RW_SRC}/config/config.c   # rw_crc32, and nothing else survives --gc-sections
    ${RW_SRC}/rw_log.c
)

target_include_directories(probe PRIVATE ${RW_SRC})
target_compile_definitions(probe PRIVATE RW_PROBE_TAG="slot-${RW_SLOT}")

target_link_libraries(probe
    pico_stdlib
    hardware_flash
    hardware_watchdog
)

pico_enable_stdio_usb(probe 1)
pico_enable_stdio_uart(probe 0)
target_compile_definitions(probe PRIVATE PICO_STDIO_USB_CONNECT_WAIT_TIMEOUT_MS=0)

set_source_files_properties(main.c PROPERTIES
    COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Wundef;-Werror")

pico_set_program_name(probe "Rooster Wake slot probe")

set(RW_UF2_ARGS "--platform;${RW_PICOTOOL_PLATFORM}")
if (PICO_PLATFORM STREQUAL "rp2350-arm-s")
    list(APPEND RW_UF2_ARGS "--abs-block" "${RW_ABS_BLOCK_ADDR}")
endif()
set_target_properties(probe PROPERTIES PICOTOOL_EXTRA_UF2_ARGS "${RW_UF2_ARGS}")

pico_add_extra_outputs(probe)
