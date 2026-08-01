/*
 * Erase every byte of flash and return to the ROM bootloader.
 *
 * For a board being sold on, returned, or put back to the state a new one arrives in. It clears
 * the loader, both firmware slots, the OTA state records and both configuration sectors — Wi-Fi
 * credentials and relay token included — leaving a board indistinguishable from one that has
 * never been programmed.
 *
 * ── WHY THIS RUNS FROM RAM ───────────────────────────────────────────────────
 *
 * A program cannot erase the flash it is executing from. The CMakeLists sets the binary type to
 * `no_flash`, so the bootrom loads this whole image into SRAM and runs it there; nothing in it is
 * ever fetched over XIP, and the flash is free to be erased from under it.
 *
 * SPDX-License-Identifier: MIT
 */
#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/bootrom.h"
#include "pico/stdlib.h"

int main(void) {
    /*
     * Interrupts off for the duration. There is no interrupt this program wants, and any handler
     * the bootrom left armed would be reached through a vector table that is about to stop
     * existing.
     */
    (void)save_and_disable_interrupts();

    /*
     * In sector-sized steps rather than one call. `flash_range_erase` on the whole device is a
     * single operation of several seconds during which nothing observes progress; erasing a
     * sector at a time costs nothing and means an interrupted wipe has still cleared everything
     * up to where it stopped, which is the direction that matters for credentials.
     */
    for (uint32_t offset = 0; offset < PICO_FLASH_SIZE_BYTES; offset += FLASH_SECTOR_SIZE) {
        flash_range_erase(offset, FLASH_SECTOR_SIZE);
    }

    /*
     * Back to the bootloader, which is in mask ROM and therefore still there. The board comes up
     * as its drive again, ready to be given firmware — the state it left the factory in.
     */
    reset_usb_boot(0, 0);
    while (1) {
        tight_loop_contents();
    }
}
