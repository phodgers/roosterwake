/*
 * The stuck detector. See stuck.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "diag/stuck.h"

#include <string.h>

void rw_stuck_init(rw_stuck_t *s) {
    memset(s, 0, sizeof(*s));
}

/*
 * Unsigned difference, so it is correct across the 49.7-day wrap of a millisecond counter.
 * `now - since` is computed modulo 2^32 whatever the two values are, which is the whole reason
 * elapsed time is measured this way rather than by comparing timestamps.
 */
static inline uint32_t elapsed(uint32_t now, uint32_t since) {
    return now - since;
}

bool rw_stuck_step(rw_stuck_t *s, bool net_ready, bool relay_ready, uint32_t now_ms) {
    /*
     * No network is not stuck. net.c owns that case and has its own retry and backoff; a device
     * that cannot associate is already being worked on, and restarting it would throw away the
     * radio trace that explains why.
     */
    if (!net_ready) {
        s->linked = false;
        s->linked_since_ms = 0;
        s->unlinked_since_ms = 0;
        return false;
    }

    if (relay_ready) {
        if (!s->linked) {
            s->linked = true;
            s->linked_since_ms = now_ms;
        }
        s->unlinked_since_ms = 0;

        /*
         * Arm only after the link has HELD. A connection that comes up and dies immediately is a
         * flapping relay, and arming on it would restart this device every trigger period for as
         * long as the flapping continued. Once armed it stays armed for the life of the boot:
         * the device has proved it can reach the relay from here, which is the whole claim the
         * detector rests on.
         */
        if (!s->armed && elapsed(now_ms, s->linked_since_ms) >= RW_STUCK_ARM_MS) {
            s->armed = true;
        }
        return false;
    }

    /* Network up, no link. */
    if (s->linked) {
        s->linked = false;
        s->linked_since_ms = 0;
    }
    if (s->unlinked_since_ms == 0) {
        /*
         * Zero is the "not currently unlinked" sentinel, so a stretch that genuinely begins at
         * millisecond zero has to be nudged. One millisecond of under-counting, once per boot,
         * against a fifteen-minute threshold.
         */
        s->unlinked_since_ms = now_ms ? now_ms : 1u;
    }

    /*
     * The rule the module exists under: a device that has never held a link this boot is not
     * stuck, it is unclaimed, or self-hosted against a relay that is not up, or simply new.
     * Those are legitimate resting states and restarting them would be the bug. See stuck.h.
     */
    if (!s->armed) {
        return false;
    }

    return elapsed(now_ms, s->unlinked_since_ms) >= RW_STUCK_TRIGGER_MS;
}

uint32_t rw_stuck_unlinked_s(const rw_stuck_t *s, uint32_t now_ms) {
    if (s->unlinked_since_ms == 0) {
        return 0;
    }
    return elapsed(now_ms, s->unlinked_since_ms) / 1000u;
}

/*
 * CRC-32 (IEEE), computed a bit at a time.
 *
 * No lookup table: this runs twice in the life of a boot — once to seal a record and once to
 * check one — and a 1 KB table to save microseconds nobody is waiting for is the wrong trade on
 * a part where flash is the scarce resource.
 *
 * A checksum would very nearly do, since the magic already rejects most noise. CRC-32 is here
 * because the failure it guards against is uninitialised RAM that happens to begin with four
 * bytes spelling "STK1", and a sum is much likelier to agree with garbage than a CRC is.
 */
static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return ~crc;
}

/* Everything up to but excluding the trailing crc field. */
static size_t covered_len(void) {
    return offsetof(rw_stuck_record_t, crc);
}

void rw_stuck_record_seal(rw_stuck_record_t *rec) {
    rec->magic = RW_STUCK_MAGIC;
    rec->version = RW_STUCK_RECORD_VERSION;
    rec->reserved = 0;
    rec->crc = crc32((const uint8_t *)rec, covered_len());
}

bool rw_stuck_record_valid(const rw_stuck_record_t *rec) {
    if (rec->magic != RW_STUCK_MAGIC || rec->version != RW_STUCK_RECORD_VERSION) {
        return false;
    }
    return rec->crc == crc32((const uint8_t *)rec, covered_len());
}
