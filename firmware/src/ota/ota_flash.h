/*
 * Reading and writing the OTA state record in flash.
 *
 * Shared by the loader and the application, which is the point: they are separate programs that
 * have to agree byte for byte about a record one writes and the other acts on, and the surest
 * way for them to agree is to run the same code.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_FLASH_H
#define RW_OTA_FLASH_H

#include <stdbool.h>

#include "ota/state.h"

/*
 * Read both copies and take the newer valid one.
 *
 * False when neither parses, which is what a device that has never been updated looks like. The
 * caller decides what that means; it is not an error.
 */
bool rw_ota_flash_load(rw_ota_state_t *out);

/*
 * Write the record to both sectors.
 *
 * Both are rewritten rather than alternating between them. Alternating would halve the erase
 * count, but it needs to know which copy is older, and a wrong answer there overwrites the only
 * good record. Writes happen on an update and on the boots of a trial — a handful in a device's
 * life — so the wear is irrelevant and the simpler rule is worth more.
 */
bool rw_ota_flash_save(const rw_ota_state_t *s);

#endif /* RW_OTA_FLASH_H */
