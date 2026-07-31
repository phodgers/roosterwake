/*
 * OTA state record in flash. See ota_flash.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ota/ota_flash.h"

#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"
#include "pico/flash.h"

#include "ota/layout.h"

static const uint8_t *sector(uint32_t offset) {
    return (const uint8_t *)(uintptr_t)(RW_FLASH_XIP_BASE + offset);
}

bool rw_ota_flash_load(rw_ota_state_t *out) {
    return rw_ota_state_pick(sector(RW_OTA_STATE_A_OFFSET(PICO_FLASH_SIZE_BYTES)),
                             RW_OTA_STATE_LEN,
                             sector(RW_OTA_STATE_B_OFFSET(PICO_FLASH_SIZE_BYTES)),
                             RW_OTA_STATE_LEN, out);
}

bool rw_ota_flash_save(const rw_ota_state_t *s) {
    /* A page is the smallest unit the flash can be programmed in, so the record is padded out to
     * one rather than programmed short. */
    uint8_t page[FLASH_PAGE_SIZE];
    memset(page, 0, sizeof(page));
    if (rw_ota_state_encode(s, page, sizeof(page)) == 0) {
        return false;
    }

    const uint32_t offsets[2] = {
        RW_OTA_STATE_A_OFFSET(PICO_FLASH_SIZE_BYTES),
        RW_OTA_STATE_B_OFFSET(PICO_FLASH_SIZE_BYTES),
    };

    for (int i = 0; i < 2; i++) {
        uint32_t ints = save_and_disable_interrupts();
        flash_range_erase(offsets[i], RW_FLASH_SECTOR);
        flash_range_program(offsets[i], page, FLASH_PAGE_SIZE);
        restore_interrupts(ints);

        /* Read it back through XIP before trusting it. A sector that will not take the write is
         * the one case where carrying on regardless could leave both copies unreadable. */
        if (memcmp(sector(offsets[i]), page, RW_OTA_STATE_LEN) != 0) {
            return false;
        }
    }
    return true;
}
