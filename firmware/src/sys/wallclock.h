/*
 * Wall clock.
 *
 * The RP2350 has no battery-backed clock, so every boot starts in 1970. Certificate validity
 * is a date comparison, so until SNTP has answered there is no honest way to verify a
 * certificate — and PROTOCOL.md §1.1 forbids papering over that by skipping the check.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WALLCLOCK_H
#define RW_WALLCLOCK_H

#include <stdbool.h>
#include <stdint.h>

/* Anything earlier than this is not a real answer from a time server; it is an uninitialised
 * counter or a malformed packet. 2024-01-01T00:00:00Z. */
#define RW_WALLCLOCK_SANITY_FLOOR 1704067200u

/* Adopt `unix_seconds` as the current time. Rejected, and returns false, if it is below the
 * sanity floor — a bogus clock is worse than a known-absent one, because it makes expired
 * certificates verify. */
bool rw_wallclock_set(uint32_t unix_seconds);

/* Whether the clock has been set this boot. */
bool rw_wallclock_valid(void);

/* Current Unix time, or 0 when the clock has never been set. Zero propagates into mbedTLS as
 * 1970, which fails every certificate's notBefore — the correct outcome, loudly. */
uint32_t rw_wallclock_now(void);

#endif /* RW_WALLCLOCK_H */
