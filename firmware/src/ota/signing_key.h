/*
 * The public key firmware updates are verified against. See ota/image.h.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_SIGNING_KEY_H
#define RW_OTA_SIGNING_KEY_H

#include <stdint.h>

#include "ota/image.h"

/* Uncompressed P-256 public point, X || Y, without the 0x04 prefix. */
extern const uint8_t rw_ota_public_key[RW_OTA_PUBKEY_LEN];

#endif /* RW_OTA_SIGNING_KEY_H */
