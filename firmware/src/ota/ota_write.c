/*
 * Streaming an image into the spare slot. See ota_write.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ota/ota_write.h"

#include <string.h>

#include "hardware/flash.h"
#include "hardware/sync.h"

#include "ota/layout.h"
#include "ota/ota.h"
#include "rw_log.h"
#include "sys/sys.h"

typedef struct {
    bool            active;
    uint8_t         slot;
    uint32_t        base;     /* flash offset of the slot, not an XIP address */
    uint32_t        written;  /* payload bytes accepted */
    uint32_t        total;    /* payload bytes expected */
    size_t          held;     /* bytes sitting in `page` */
    uint8_t         page[FLASH_PAGE_SIZE];
    rw_ota_digest_t digest;
    uint8_t         expected[RW_OTA_SHA_LEN];
} writer_t;

static writer_t w;

/*
 * Program one page, erasing its sector first if this is the first page to land in it.
 *
 * Interrupts are off for the duration because the flash cannot be read while it is being
 * written, and everything that would run — the TLS callbacks carrying the very bytes being
 * written — executes from flash. The watchdog is fed either side: an erase is tens of
 * milliseconds and the main loop is not running to feed it.
 */
static bool program_page(void) {
    uint32_t offset = w.base + (w.written - w.held);

    rw_sys_feed_watchdog();
    uint32_t ints = save_and_disable_interrupts();
    if ((offset % RW_FLASH_SECTOR) == 0) {
        flash_range_erase(offset, RW_FLASH_SECTOR);
    }
    flash_range_program(offset, w.page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);
    rw_sys_feed_watchdog();

    /* Read back through XIP. A page that did not take is worth catching here, while the transfer
     * can still be reported as failed, rather than at the digest check where it would look like
     * a corrupt download. */
    if (memcmp((const void *)(uintptr_t)(RW_FLASH_XIP_BASE + offset), w.page, FLASH_PAGE_SIZE) !=
        0) {
        RW_LOG_ERROR("ota: flash did not take the write at %08lx", (unsigned long)offset);
        return false;
    }

    w.held = 0;
    return true;
}

rw_ota_status_t rw_ota_write_begin(const rw_ota_header_t *header, uint8_t slot) {
    if (w.active) {
        return RW_OTA_ERR_LENGTH;
    }
    if (slot > RW_OTA_SLOT_B || slot == rw_ota_running_slot()) {
        return RW_OTA_ERR_BOARD;
    }
    if (header->payload_len == 0 || header->payload_len > RW_SLOT_PAYLOAD_MAX) {
        return RW_OTA_ERR_LENGTH;
    }

    memset(&w, 0, sizeof(w));
    w.active = true;
    w.slot   = slot;
    w.base   = RW_SLOT_OFFSET(slot);
    w.total  = header->payload_len;
    memcpy(w.expected, header->payload_sha256, RW_OTA_SHA_LEN);
    rw_ota_digest_init(&w.digest);

    RW_LOG_INFO("ota: writing %lu bytes into slot %u", (unsigned long)w.total, (unsigned)slot);
    return RW_OTA_OK;
}

rw_ota_status_t rw_ota_write_chunk(const uint8_t *data, size_t len) {
    if (!w.active) {
        return RW_OTA_ERR_LENGTH;
    }
    if (len > w.total - w.written) {
        /* More than was promised. Refused rather than truncated: the header is signed, so a
         * stream that disagrees with it is not the image that was signed. */
        rw_ota_write_abort();
        return RW_OTA_ERR_LENGTH;
    }

    rw_ota_digest_update(&w.digest, data, len);

    while (len > 0) {
        size_t room = FLASH_PAGE_SIZE - w.held;
        size_t take = len < room ? len : room;
        memcpy(w.page + w.held, data, take);
        w.held += take;
        w.written += (uint32_t)take;
        data += take;
        len -= take;

        if (w.held == FLASH_PAGE_SIZE && !program_page()) {
            rw_ota_write_abort();
            return RW_OTA_ERR_DIGEST;
        }
    }
    return RW_OTA_OK;
}

rw_ota_status_t rw_ota_write_end(void) {
    if (!w.active) {
        return RW_OTA_ERR_LENGTH;
    }

    if (w.held > 0) {
        /* Pad to a whole page with the erased value, so the tail of the last sector reads as
         * blank rather than as whatever the previous image left there. */
        memset(w.page + w.held, 0xFF, FLASH_PAGE_SIZE - w.held);
        size_t held = w.held;
        w.held      = FLASH_PAGE_SIZE;
        w.written += (uint32_t)(FLASH_PAGE_SIZE - held);
        bool ok = program_page();
        w.written -= (uint32_t)(FLASH_PAGE_SIZE - held);
        if (!ok) {
            rw_ota_write_abort();
            return RW_OTA_ERR_DIGEST;
        }
    }

    rw_ota_header_t h;
    memset(&h, 0, sizeof(h));
    h.payload_len = w.total;
    memcpy(h.payload_sha256, w.expected, RW_OTA_SHA_LEN);

    rw_ota_status_t status = rw_ota_digest_finish(&w.digest, &h);
    w.active               = false;

    if (status == RW_OTA_OK) {
        RW_LOG_INFO("ota: slot %u written and verified", (unsigned)w.slot);
    } else {
        RW_LOG_ERROR("ota: slot %u failed verification (%s)", (unsigned)w.slot,
                     rw_ota_status_str(status));
    }
    return status;
}

void rw_ota_write_abort(void) {
    if (w.active) {
        RW_LOG_WARN("ota: transfer abandoned after %lu of %lu bytes", (unsigned long)w.written,
                    (unsigned long)w.total);
    }
    w.active = false;
    w.held   = 0;
}

bool rw_ota_write_active(void) {
    return w.active;
}

uint32_t rw_ota_write_progress(void) {
    return w.written;
}
