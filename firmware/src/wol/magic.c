/*
 * Wake-on-LAN magic packet construction. See magic.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "wol/magic.h"

#include <string.h>

void rw_wol_build_magic(const uint8_t mac[6], uint8_t out[RW_WOL_MAGIC_LEN]) {
    memset(out, 0xFF, 6);
    for (int i = 0; i < 16; i++) {
        memcpy(out + 6 + i * 6, mac, 6);
    }
}
