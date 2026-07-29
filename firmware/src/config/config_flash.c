/*
 * Dual-slot flash storage for the configuration record.
 *
 * SPDX-License-Identifier: MIT
 */
#include "config/config_flash.h"

#include <string.h>

#include "hardware/flash.h"
#include "hardware/xip_cache.h"
#include "pico/flash.h"

#include "rw_log.h"

/* A sector image is built in RAM before it is programmed. 4 KB of a 520 KB part, held only for
 * the duration of a save, is cheaper than programming in 256-byte pages from a source the
 * caller might mutate underneath us. */
typedef struct {
    uint32_t offset;
    uint8_t  sector[RW_CFG_SECTOR_SIZE];
} flash_write_job_t;

static const uint8_t *slot_ptr(uint32_t offset) {
    return (const uint8_t *)(XIP_BASE + offset);
}

/*
 * Runs with interrupts disabled and the other core locked out. Nothing in here may allocate,
 * block, log or call back into lwIP.
 */
static void do_erase_and_program(void *param) {
    flash_write_job_t *job = (flash_write_job_t *)param;
    flash_range_erase(job->offset, RW_CFG_SECTOR_SIZE);
    flash_range_program(job->offset, job->sector, RW_CFG_SECTOR_SIZE);
}

static void do_erase_only(void *param) {
    uint32_t offset = *(uint32_t *)param;
    flash_range_erase(offset, RW_CFG_SECTOR_SIZE);
}

bool rw_config_flash_load(rw_config_t *out) {
    return rw_config_select(slot_ptr(RW_CFG_SLOT_A_OFFSET), RW_CFG_SECTOR_SIZE,
                            slot_ptr(RW_CFG_SLOT_B_OFFSET), RW_CFG_SECTOR_SIZE, out) != 0;
}

int rw_config_flash_active_slot(void) {
    rw_config_t scratch;
    return rw_config_select(slot_ptr(RW_CFG_SLOT_A_OFFSET), RW_CFG_SECTOR_SIZE,
                            slot_ptr(RW_CFG_SLOT_B_OFFSET), RW_CFG_SECTOR_SIZE, &scratch);
}

/*
 * One erase-program-verify attempt. Returns RW_FLASH_OK, RW_FLASH_ERR_LOCKED (nothing was
 * written, retrying will not help) or RW_FLASH_ERR_VERIFY (worth one retry).
 */
static rw_flash_status_t write_and_verify(flash_write_job_t *job) {
    int rc = flash_safe_execute(do_erase_and_program, job, 1000);
    if (rc != PICO_OK) {
        RW_LOG_ERROR("flash: safe execute failed (%d)", rc);
        /* PICO_ERROR_TIMEOUT means the callback may have run, so the sector's contents are
         * unknown. Report it as a verify failure so the caller retries the same slot; the
         * other slot is still intact either way. */
        return (rc == PICO_ERROR_TIMEOUT) ? RW_FLASH_ERR_VERIFY : RW_FLASH_ERR_LOCKED;
    }

    /* The ROM program helper flushes the cache, but the read-back is the whole point of this
     * function, so invalidate explicitly rather than relying on that side effect. */
    xip_cache_invalidate_range(job->offset, RW_CFG_SECTOR_SIZE);

    if (memcmp(slot_ptr(job->offset), job->sector, RW_CFG_SECTOR_SIZE) != 0) {
        return RW_FLASH_ERR_VERIFY;
    }
    return RW_FLASH_OK;
}

rw_flash_status_t rw_config_flash_save(rw_config_t *cfg) {
    rw_config_t current;
    int         winner = rw_config_select(slot_ptr(RW_CFG_SLOT_A_OFFSET), RW_CFG_SECTOR_SIZE,
                                          slot_ptr(RW_CFG_SLOT_B_OFFSET), RW_CFG_SECTOR_SIZE, &current);

    /* Write to the slot that is not live. Power loss at any instant therefore leaves the
     * previous configuration readable. */
    uint32_t target_offset = (winner == 1) ? RW_CFG_SLOT_B_OFFSET : RW_CFG_SLOT_A_OFFSET;
    uint32_t new_seq       = (winner == 0) ? 1u : current.seq + 1u;

    static flash_write_job_t job; /* 4 KB; static rather than 4 KB of stack in a 2 KB frame */
    job.offset = target_offset;
    memset(job.sector, 0, sizeof(job.sector));

    uint32_t saved_seq = cfg->seq;
    cfg->seq           = new_seq;
    size_t n           = rw_config_encode(cfg, job.sector, sizeof(job.sector));
    if (n != RW_CFG_RECORD_LEN) {
        cfg->seq = saved_seq;
        return RW_FLASH_ERR_ENCODE;
    }
    /* Bytes past the record are left as 0x00 rather than 0xFF, as config-format.md §2.2 asks,
     * so two devices holding the same configuration hold identical sectors. */

    rw_flash_status_t st = write_and_verify(&job);
    if (st == RW_FLASH_ERR_VERIFY) {
        RW_LOG_WARN("flash: verify failed at 0x%06lx, retrying", (unsigned long)target_offset);
        st = write_and_verify(&job);
    }

    if (st != RW_FLASH_OK) {
        cfg->seq = saved_seq;
        RW_LOG_ERROR("flash: save failed at 0x%06lx, config unchanged",
                     (unsigned long)target_offset);
        return st;
    }

    RW_LOG_INFO("flash: saved seq %lu to slot %c", (unsigned long)new_seq,
                target_offset == RW_CFG_SLOT_A_OFFSET ? 'A' : 'B');
    return RW_FLASH_OK;
}

rw_flash_status_t rw_config_flash_erase_all(void) {
    /* B first: if power is lost between the two erases the device still boots on slot A. */
    static const uint32_t order[2] = {RW_CFG_SLOT_B_OFFSET, RW_CFG_SLOT_A_OFFSET};

    for (int i = 0; i < 2; i++) {
        uint32_t offset = order[i];
        int      rc     = flash_safe_execute(do_erase_only, &offset, 1000);
        if (rc != PICO_OK) {
            RW_LOG_ERROR("flash: erase of 0x%06lx failed (%d)", (unsigned long)offset, rc);
            return (rc == PICO_ERROR_TIMEOUT) ? RW_FLASH_ERR_VERIFY : RW_FLASH_ERR_LOCKED;
        }
        xip_cache_invalidate_range(offset, RW_CFG_SECTOR_SIZE);
    }

    /* An erased sector reads 0xFF, so the magic check fails and both slots are invalid. Prove
     * it rather than assume it — a factory reset that silently left a slot readable would hand
     * the next owner the previous owner's Wi-Fi password. */
    if (rw_config_flash_active_slot() != 0) {
        RW_LOG_ERROR("flash: erase left a readable slot");
        return RW_FLASH_ERR_VERIFY;
    }
    return RW_FLASH_OK;
}
