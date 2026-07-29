/*
 * Dual-slot flash storage for the configuration record (config-format.md §1 and §3).
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_CONFIG_FLASH_H
#define RW_CONFIG_FLASH_H

/*
 * Brings in PICO_FLASH_SIZE_BYTES from the board header.
 *
 * "pico.h" and not "pico/config.h": the board headers contain bare `pico_board_cmake_set(...)`
 * directives meant for CMake, and pico.h is what defines them away before pulling the board
 * header in. Including the config header directly feeds those lines to the C compiler, which
 * fails a dozen includes later in <stddef.h> with an error that names none of this.
 */
#include "pico.h"

#include "config/config.h"

/*
 * Flash offsets of the two config sectors, relative to the start of flash.
 *
 * The rule is "the top two 4 KB sectors of whatever flash this board has", not a fixed address.
 * A hardcoded 0x3FE000 silently assumes 4 MB for ever: on a 2 MB Pico W those addresses are
 * past the end of the chip, and the failure is a config that appears to save and is gone after
 * a power cycle. config-format.md §1 tabulates the concrete address per board.
 *
 * PICO_FLASH_SIZE_BYTES comes from the board header, so this follows the board automatically —
 * including boards neither of us has thought about yet.
 */
#ifndef PICO_FLASH_SIZE_BYTES
#error "PICO_FLASH_SIZE_BYTES is not defined; the config sectors cannot be located"
#endif

#define RW_CFG_SLOT_B_OFFSET ((uint32_t)PICO_FLASH_SIZE_BYTES - RW_CFG_SECTOR_SIZE)
#define RW_CFG_SLOT_A_OFFSET (RW_CFG_SLOT_B_OFFSET - RW_CFG_SECTOR_SIZE)

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
 * Give `cfg` a device token if it does not already have one, generated from the platform RNG.
 *
 * Called before any commit. A device provisioned through the captive portal has no token —
 * nothing in that flow can supply one — and without it the device is not able to authenticate
 * to any relay. It also used to mean the device did not count as provisioned at all, so it
 * rebooted into setup mode for ever, having apparently saved everything correctly.
 *
 * Returns true if a new token was minted, which is what tells the caller to show it to the
 * user. This is the only moment it is ever displayed: the usbcfg channel never returns it, so
 * a self-hoster who needs it for their own relay's config has exactly this one chance.
 */
bool rw_config_ensure_token(rw_config_t *cfg);

/*
 * Erase both slots (usbcfg FACTORY_RESET, and the BOOTSEL-held-at-power-on path).
 *
 * Slot B is erased first. If power is lost between the two erases the device comes back on
 * slot A's old configuration rather than half-reset, which is the failure everyone would
 * rather have.
 */
rw_flash_status_t rw_config_flash_erase_all(void);

#endif /* RW_CONFIG_FLASH_H */
