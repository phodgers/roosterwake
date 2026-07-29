/*
 * Dual-slot flash storage for the configuration record (config-format.md §1 and §3).
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_CONFIG_FLASH_H
#define RW_CONFIG_FLASH_H

#include "config/config.h"

/* Flash offsets of the two config sectors, relative to the start of flash. The XIP addresses
 * are these plus XIP_BASE (0x10000000), which is what config-format.md §1 tabulates. */
#define RW_CFG_SLOT_A_OFFSET 0x3FE000u
#define RW_CFG_SLOT_B_OFFSET 0x3FF000u

typedef enum {
    RW_FLASH_OK = 0,
    RW_FLASH_ERR_ENCODE,  /* the config does not fit the v1 layout */
    RW_FLASH_ERR_LOCKED,  /* flash_safe_execute could not get exclusive access */
    RW_FLASH_ERR_VERIFY,  /* read-back mismatch after two attempts */
} rw_flash_status_t;

/*
 * Read both slots, apply config-format.md §3, and return the winner.
 *
 * Returns true and fills `out` when a valid record exists. Returns false and leaves `out` in
 * the unprovisioned state when neither slot is valid — the device then starts setup mode.
 */
bool rw_config_flash_load(rw_config_t *out);

/* Which slot is currently live: 0 (none), 1 (A) or 2 (B). */
int rw_config_flash_active_slot(void);

/*
 * Write `cfg` to the inactive slot with seq = winner's seq + 1 (or 1 when no slot is valid),
 * then read the sector back and byte-compare. On mismatch the same slot is retried once; a
 * second failure returns RW_FLASH_ERR_VERIFY with the other slot untouched, so the device
 * keeps running on the configuration it already had.
 *
 * On success `cfg->seq` is updated to the sequence number that was written, which is what
 * usbcfg's COMMIT reports back to the host.
 */
rw_flash_status_t rw_config_flash_save(rw_config_t *cfg);

/*
 * Erase both slots (usbcfg FACTORY_RESET, and the BOOTSEL-held-at-power-on path).
 *
 * Slot B is erased first. If power is lost between the two erases the device comes back on
 * slot A's old configuration rather than half-reset, which is the failure everyone would
 * rather have.
 */
rw_flash_status_t rw_config_flash_erase_all(void);

#endif /* RW_CONFIG_FLASH_H */
