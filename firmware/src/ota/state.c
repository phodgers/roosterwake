/*
 * The OTA state record. See state.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ota/state.h"

#include <string.h>

#include "config/config.h" /* rw_crc32 */

/*
 *   0   4  magic "RWST"
 *   4   2  format version
 *   6   1  active slot
 *   7   1  fallback slot
 *   8   1  trial boots remaining
 *   9   1  confirmed
 *  10   2  reserved, zero
 *  12   4  sequence
 *  16  16  version string, NUL-padded
 *  32   4  reserved, zero
 *  36   4  CRC-32 of bytes 0..35
 */
#define OFF_MAGIC     0
#define OFF_VERSION   4
#define OFF_ACTIVE    6
#define OFF_FALLBACK  7
#define OFF_TRIAL     8
#define OFF_CONFIRMED 9
#define OFF_SEQ       12
#define OFF_VERSTR    16
#define OFF_CRC       36
#define VERSTR_WIDTH  16

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)(v >> 8);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Copy at most VERSTR_WIDTH characters and terminate. Written out rather than using snprintf so
 * this file needs no stdio: the loader links it and has no room for one. */
static void copy_version(char *dst, const char *src) {
    size_t n = 0;
    while (src[n] != '\0' && n < VERSTR_WIDTH) {
        dst[n] = src[n];
        n++;
    }
    dst[n] = '\0';
}

uint8_t rw_ota_other_slot(uint8_t slot) {
    return slot == RW_OTA_SLOT_A ? RW_OTA_SLOT_B : RW_OTA_SLOT_A;
}

void rw_ota_state_default(rw_ota_state_t *s, const char *version) {
    memset(s, 0, sizeof(*s));
    s->seq       = 1;
    s->active    = RW_OTA_SLOT_A;
    s->fallback  = RW_OTA_SLOT_A;
    s->trial     = 0;
    s->confirmed = true;
    if (version != NULL) {
        copy_version(s->version, version);
    }
}

size_t rw_ota_state_encode(const rw_ota_state_t *s, uint8_t *out, size_t cap) {
    if (out == NULL || cap < RW_OTA_STATE_LEN) {
        return 0;
    }
    if (s->active > RW_OTA_SLOT_B || s->fallback > RW_OTA_SLOT_B) {
        return 0;
    }

    memset(out, 0, RW_OTA_STATE_LEN);
    memcpy(out + OFF_MAGIC, RW_OTA_STATE_MAGIC, 4);
    wr16(out + OFF_VERSION, RW_OTA_STATE_VERSION);
    out[OFF_ACTIVE]    = s->active;
    out[OFF_FALLBACK]  = s->fallback;
    out[OFF_TRIAL]     = s->trial;
    out[OFF_CONFIRMED] = s->confirmed ? 1u : 0u;
    wr32(out + OFF_SEQ, s->seq);

    size_t n = 0;
    while (s->version[n] != '\0' && n < VERSTR_WIDTH) {
        out[OFF_VERSTR + n] = (uint8_t)s->version[n];
        n++;
    }

    wr32(out + OFF_CRC, rw_crc32(out, OFF_CRC));
    return RW_OTA_STATE_LEN;
}

bool rw_ota_state_decode(const uint8_t *raw, size_t len, rw_ota_state_t *out) {
    if (raw == NULL || out == NULL || len < RW_OTA_STATE_LEN) {
        return false;
    }
    if (memcmp(raw + OFF_MAGIC, RW_OTA_STATE_MAGIC, 4) != 0) {
        return false;
    }
    if (rd16(raw + OFF_VERSION) != RW_OTA_STATE_VERSION) {
        return false;
    }
    if (rd32(raw + OFF_CRC) != rw_crc32(raw, OFF_CRC)) {
        return false;
    }

    uint8_t active   = raw[OFF_ACTIVE];
    uint8_t fallback = raw[OFF_FALLBACK];
    if (active > RW_OTA_SLOT_B || fallback > RW_OTA_SLOT_B) {
        /* A CRC-clean record naming a slot that does not exist is a format the loader must not
         * act on: jumping to a computed address that was never written is the one failure this
         * whole record exists to prevent. */
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->seq       = rd32(raw + OFF_SEQ);
    out->active    = active;
    out->fallback  = fallback;
    out->trial     = raw[OFF_TRIAL];
    out->confirmed = raw[OFF_CONFIRMED] != 0;

    size_t n = 0;
    while (n < VERSTR_WIDTH && raw[OFF_VERSTR + n] != '\0') {
        char c = (char)raw[OFF_VERSTR + n];
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
        out->version[n] = c;
        n++;
    }
    out->version[n] = '\0';
    return true;
}

bool rw_ota_state_pick(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                       rw_ota_state_t *out) {
    rw_ota_state_t sa;
    rw_ota_state_t sb;
    bool           ok_a = rw_ota_state_decode(a, a_len, &sa);
    bool           ok_b = rw_ota_state_decode(b, b_len, &sb);

    if (ok_a && ok_b) {
        /* Unsigned difference, so a wrapped counter still orders correctly: the newer record is
         * the one a small number of steps ahead, not the one with the larger value. */
        *out = ((uint32_t)(sa.seq - sb.seq) < 0x80000000u) ? sa : sb;
        return true;
    }
    if (ok_a) {
        *out = sa;
        return true;
    }
    if (ok_b) {
        *out = sb;
        return true;
    }
    return false;
}

rw_ota_boot_t rw_ota_state_on_boot(rw_ota_state_t *s, bool *write_back) {
    *write_back = false;

    if (s->confirmed) {
        return RW_OTA_BOOT_ACTIVE;
    }

    if (s->trial > 0) {
        s->trial--;
        s->seq++;
        *write_back = true;
        return RW_OTA_BOOT_ACTIVE;
    }

    /* Out of attempts and never confirmed. */
    s->active    = s->fallback;
    s->confirmed = true;
    s->trial     = 0;
    s->version[0] = '\0'; /* what the fallback slot holds is not recorded here */
    s->seq++;
    *write_back = true;
    return RW_OTA_BOOT_REVERTED;
}

void rw_ota_state_stage(rw_ota_state_t *s, uint8_t slot, const char *version) {
    if (slot > RW_OTA_SLOT_B) {
        return;
    }
    if (slot == s->active && s->confirmed) {
        /* That is the image currently running. Writing it would destroy the only known-good
         * slot; the caller is meant to hand us the other one. */
        return;
    }

    /*
     * The fallback only moves when a different slot is being entered. An update that is
     * superseded before it ever boots is staged into the slot that is already pending, and
     * taking `active` again there would point the fallback at the slot being overwritten -
     * leaving nothing to revert to.
     */
    if (slot != s->active) {
        s->fallback = s->active;
    }
    s->active    = slot;
    s->trial     = RW_OTA_TRIAL_BOOTS;
    s->confirmed = false;
    s->version[0] = '\0';
    if (version != NULL) {
        copy_version(s->version, version);
    }
    s->seq++;
}

void rw_ota_state_confirm(rw_ota_state_t *s) {
    if (s->confirmed) {
        return;
    }
    s->confirmed = true;
    s->trial     = 0;
    s->fallback  = s->active;
    s->seq++;
}

bool rw_ota_state_on_trial(const rw_ota_state_t *s) {
    return !s->confirmed;
}
