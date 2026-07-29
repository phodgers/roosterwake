/*
 * Wall clock. See wallclock.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "sys/wallclock.h"

#include "pico/time.h"

#include "rw_log.h"

static bool     s_valid;
static uint32_t s_epoch_at_boot; /* Unix seconds corresponding to time-since-boot zero */

bool rw_wallclock_set(uint32_t unix_seconds) {
    if (unix_seconds < RW_WALLCLOCK_SANITY_FLOOR) {
        RW_LOG_WARN("clock: rejected implausible time %lu", (unsigned long)unix_seconds);
        return false;
    }
    uint32_t since_boot = (uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000u);
    s_epoch_at_boot     = unix_seconds - since_boot;
    s_valid             = true;
    return true;
}

bool rw_wallclock_valid(void) {
    return s_valid;
}

uint32_t rw_wallclock_now(void) {
    if (!s_valid) {
        return 0;
    }
    uint32_t since_boot = (uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000u);
    return s_epoch_at_boot + since_boot;
}
