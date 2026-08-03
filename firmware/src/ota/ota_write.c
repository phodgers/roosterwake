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

/*
 * Erased per call. A multiple of 64 KB so the bootrom uses block erases rather than sectors, and
 * small enough that the watchdog is fed often — one 64 KB block measured 260 ms against an 8 s
 * timer.
 */
#define RW_ERASE_STEP (64u * 1024u)

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
 * Program one page. The slot was cleared by rw_ota_write_begin(), so nothing is erased here.
 *
 * Interrupts are off for the duration because the flash cannot be read while it is being
 * written, and everything that would run — the TLS callbacks carrying the very bytes being
 * written — executes from flash. A page program is under a millisecond; it is the erase that
 * used to make this expensive, and it no longer happens on this path.
 */
static bool program_page(void) {
    uint32_t offset = w.base + (w.written - w.held);

    uint32_t ints = save_and_disable_interrupts();
    flash_range_program(offset, w.page, FLASH_PAGE_SIZE);
    restore_interrupts(ints);

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

    /*
     * Clear the whole region now, before a byte of payload is asked for.
     *
     * Erasing a sector at a time as pages arrived cost 37.6 ms of interrupts-off per sector,
     * 129 times for a half-megabyte image, in the middle of a transfer. The device stops reading
     * for each one; its receive window is 17.5 KB; a sender at line rate overruns that in 40 ms
     * and drives the window to zero, and reopening it costs a persist probe that backs off. That
     * is what made the same image take 180 seconds instead of 13.
     *
     * Doing it here also makes it cheaper. flash_range_erase hands the bootrom a block size and
     * a block-erase command, so a 64 KB call is one block erase where sixteen 4 KB calls are
     * sixteen sector erases: measured 2.86 s against 6.60 s for the same 704 KB (FLASH_BENCH).
     *
     * In 64 KB steps rather than one call so the watchdog is fed between them — a whole slot in
     * a single call is nearly three seconds with nothing able to feed it, against an 8 s timer.
     */
    const uint32_t span = (header->payload_len + RW_FLASH_SECTOR - 1) & ~(RW_FLASH_SECTOR - 1);
    rw_sys_feed_watchdog();
    for (uint32_t off = 0; off < span; off += RW_ERASE_STEP) {
        uint32_t n = span - off;
        if (n > RW_ERASE_STEP) {
            n = RW_ERASE_STEP;
        }
        uint32_t ints = save_and_disable_interrupts();
        flash_range_erase(w.base + off, n);
        restore_interrupts(ints);
        rw_sys_feed_watchdog();
    }

    RW_LOG_INFO("ota: cleared %lu bytes of slot %u, writing %lu", (unsigned long)span,
                (unsigned)slot, (unsigned long)w.total);
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
