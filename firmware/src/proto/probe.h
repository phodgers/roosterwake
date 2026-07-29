/*
 * Post-wake liveness probe (PROTOCOL.md §5 `probe`, §4 `probe_result`).
 *
 * The question the probe answers is "did the machine actually come up", which is the one thing
 * a wake cannot tell you on its own — a magic packet is fire-and-forget.
 *
 * The mechanism is ARP. Once the target's address is known, an ARP request to it is answered
 * only by a host that is awake and on the network, which is exactly the signal wanted, costs
 * one frame, and needs nothing installed on the target. ICMP is not used: a large share of
 * Windows machines drop pings by default, so a timeout would mean nothing.
 *
 * The address has to come from somewhere. net/arplearn.c remembers what lwIP's ARP cache has
 * held since boot, so a machine that has been seen on this segment can be probed. A machine
 * that has never been seen cannot, and the probe reports `timeout` — an honest answer, and
 * the reason `probe` is an optional capability the relay feature-detects rather than assumes.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_PROBE_H
#define RW_PROBE_H

#include <stdbool.h>
#include <stdint.h>

#define RW_PROBE_TIMEOUT_MIN_S 10
#define RW_PROBE_TIMEOUT_MAX_S 300

typedef enum {
    RW_PROBE_IDLE = 0,
    RW_PROBE_WAITING,
    RW_PROBE_UP,
    RW_PROBE_TIMEOUT,
} rw_probe_state_t;

/* Called on every state change and once at resolution. `elapsed_s` is seconds since start. */
typedef void (*rw_probe_report_t)(void *ctx, rw_probe_state_t state, uint32_t elapsed_s);

/*
 * Start watching `mac`. `timeout_s` is clamped to [10, 300].
 *
 * Returns false if a probe is already running — PROTOCOL.md §6 gives `busy` for exactly this,
 * and running two probes at once would mean two answers for one `req_id`.
 */
bool rw_probe_start(const uint8_t mac[6], uint32_t timeout_s, rw_probe_report_t report,
                    void *ctx);

/* Drive the probe. Call from the main loop. */
void rw_probe_task(void);

/* Abandon a running probe without reporting. Used when the relay connection drops — the
 * `req_id` it belonged to is gone with it. */
void rw_probe_cancel(void);

bool rw_probe_running(void);

/* "arp", for the `method` field of probe_result. */
const char *rw_probe_method(void);

#endif /* RW_PROBE_H */
