# The wipe tool — erase every byte of flash and return to the ROM bootloader.
#
# Its own project because it is built for a different binary type from everything else: `no_flash`
# puts the whole image in SRAM, which is the only way a program can erase the flash it would
# otherwise be executing from.
#
#   cmake -S firmware/tools/wipe -B build-wipe -G Ninja -DPICO_BOARD=pico_w
#   cmake --build build-wipe            # build-wipe/wipe.uf2
#
# Drop the UF2 on a board held in BOOTSEL. It erases, then comes back as the same drive with
# nothing on it.
#
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.13)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "Minimum policy version for vendored deps")

# Any RP2040 or RP2350 board. The wipe touches nothing board-specific — it needs the flash size,
# which comes from the board header, and nothing else.
set(PICO_BOARD pico_w CACHE STRING "Target board")
if (PICO_BOARD STREQUAL "pico2_w" OR PICO_BOARD STREQUAL "pico2")
    set(PICO_PLATFORM rp2350-arm-s CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2350)
else()
    set(PICO_PLATFORM rp2040 CACHE STRING "Target platform" FORCE)
    set(RW_PICOTOOL_PLATFORM rp2040)
endif()

include(${CMAKE_CURRENT_LIST_DIR}/../../pico_sdk_import.cmake)

project(remotewake_wipe C CXX ASM)
set(CMAKE_C_STANDARD 11)

pico_sdk_init()

add_executable(wipe main.c)

target_link_libraries(wipe pico_stdlib hardware_flash)

# The whole point: loaded into SRAM by the bootrom and run from there, so the flash underneath is
# free to be erased. A normal flash build would be erasing the instructions it is fetching.
pico_set_binary_type(wipe no_flash)

pico_enable_stdio_usb(wipe 0)
pico_enable_stdio_uart(wipe 0)

set_source_files_properties(main.c PROPERTIES
    COMPILE_OPTIONS "-Wall;-Wextra;-Wshadow;-Wundef;-Werror")

pico_set_program_name(wipe "Remote Wake flash wipe")

set(RW_UF2_ARGS "--platform;${RW_PICOTOOL_PLATFORM}")
set_target_properties(wipe PROPERTIES PICOTOOL_EXTRA_UF2_ARGS "${RW_UF2_ARGS}")

pico_add_extra_outputs(wipe)
