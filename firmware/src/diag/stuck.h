/*
 * The stuck detector: a device that has network but cannot get back to the relay.
 *
 * WHY THIS EXISTS
 * ---------------
 * On 2026-08-12 and again on 2026-08-14, two dongles on the same LAN stopped talking to the
 * relay and stayed that way. Both held a perfectly good Wi-Fi association the whole time — they
 * answered ping and ARP — and both showed RW_LED_ONLINE, which is exactly what the LED is
 * supposed to say. The relay was healthy, the certificates were valid, the tokens were intact,
 * nothing was logged anywhere, and the only thing that fixed either of them was a person walking
 * over and pulling the plug.
 *
 * The root cause is still unknown, and this module does not claim to fix it. What it fixes is
 * the part that is indefensible on its own terms: **a device that gets into a state it cannot
 * leave without human hands.** For a product whose entire promise is that the machine is there
 * when you reach for it, "dead until somebody notices" is the defect, whatever caused it.
 *
 * So: notice, write down what it looked like, and restart.
 *
 * ── THE RULE THAT KEEPS THIS FROM BEING WORSE THAN THE BUG ────────────────────
 *
 * Only a device that has ALREADY HELD A LINK this boot may reboot itself.
 *
 * RW_LED_ONLINE is not an error. led.h says so plainly: a self-hosted device whose relay is not
 * running yet, a device nobody has claimed, a relay that is briefly down — all of them sit here
 * legitimately, sometimes for days, and Wake-on-LAN from the local network keeps working
 * throughout. A detector that rebooted on "not connected" would put those devices into a restart
 * loop for as long as their owner's situation lasted, and would take their working LAN wake down
 * with it every time.
 *
 * Requiring a prior link also makes a reboot loop structurally impossible rather than merely
 * unlikely. After the reboot the device has not yet held a link, so it cannot arm again until it
 * genuinely reconnects. One episode gets one restart; if that does not fix it the device sits in
 * RW_LED_ONLINE — visible, diagnosable, still waking machines on the LAN — instead of thrashing.
 *
 * The arming threshold exists for the same reason at a smaller scale: a link that comes up and
 * dies immediately, over and over, is a flapping relay rather than a stuck device, and a device
 * that armed on a one-second connection would restart every RW_STUCK_TRIGGER_MS for as long as
 * the flapping lasted.
 *
 * This file is PORTABLE — no SDK headers, no hardware. It decides; sys.c stores and reboots, and
 * proto.c reports. That split is what lets the decision be tested on a host.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_STUCK_H
#define RW_STUCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * How long a link must hold before the device trusts it enough to arm. Sixty seconds is well
 * past a handshake and well short of anything a user would notice.
 */
#define RW_STUCK_ARM_MS 60000u

/*
 * How long an armed device tolerates having network but no relay before restarting.
 *
 * Fifteen minutes is chosen against the relay's own reconnect behaviour rather than picked for
 * roundness: RW_RELAY_BACKOFF_MAX_MS is 60 s, so a device that can reconnect at all has had
 * roughly fifteen consecutive attempts by the time this fires. Anything much shorter would
 * restart devices that were about to recover on their own.
 */
#define RW_STUCK_TRIGGER_MS 900000u

/** Longest `last_error` carried across the restart. Long enough for every string net.c sets. */
#define RW_STUCK_ERR_MAX 24

/** "STK1". Distinguishes a real record from whatever RAM held at power-on. */
#define RW_STUCK_MAGIC 0x53544B31u

#define RW_STUCK_RECORD_VERSION 1

/*
 * What the device knew about itself when it gave up, carried across the restart it is about to
 * perform. Kept small and fixed-layout: it lives in uninitialised RAM, so every byte of it has
 * to survive a reset without a loader touching it.
 */
typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  relay_state; /* rw_relay_state_t at the moment it gave up */
    uint16_t reserved;    /* zero; keeps the 32-bit fields aligned and the layout explicit */
    uint32_t uptime_s;    /* how long it had been running */
    uint32_t unlinked_s;  /* how long it had been unable to reach the relay */

    /*
     * The two numbers that separate the likeliest causes of a device that cannot reconnect.
     *
     * `heap_free` is free C heap. A TLS session needs its record buffers in one piece, so a
     * device that has slowly leaked its way down cannot form a connection and every layer above
     * reports something vaguer than "no memory".
     *
     * `mem_err` is lwIP's count of allocations it refused. It is the one that would settle this:
     * a device that failed to reconnect a few hundred times and leaked a PCB on each attempt
     * arrives here with a large number, and a device that was refused by something on the network
     * arrives with zero. Nothing else the device knows distinguishes those two, and they need
     * completely different fixes.
     */
    uint32_t heap_free;
    uint32_t mem_err;

    char     last_error[RW_STUCK_ERR_MAX]; /* rw_net_last_error(), or "" */
    uint32_t crc;                          /* over every byte before it */
} rw_stuck_record_t;

/** Running state. Zeroed by rw_stuck_init; never persists across a restart, by design. */
typedef struct {
    bool     armed;
    bool     linked;
    uint32_t linked_since_ms;
    uint32_t unlinked_since_ms;
} rw_stuck_t;

void rw_stuck_init(rw_stuck_t *s);

/**
 * Advance the detector. Call once per main-loop iteration.
 *
 * Returns true exactly once, on the iteration where the caller should record the reason and
 * restart. `net_ready` gates the whole thing: without a network there is nothing to diagnose and
 * net.c's own retry is the right mechanism.
 *
 * `now_ms` may wrap — it does, every 49.7 days — and every comparison here is written as an
 * unsigned difference so that it keeps working across the wrap rather than restarting a healthy
 * device that has been up for seven weeks.
 */
bool rw_stuck_step(rw_stuck_t *s, bool net_ready, bool relay_ready, uint32_t now_ms);

/** How long the current unlinked stretch has lasted, in seconds. Zero when linked. */
uint32_t rw_stuck_unlinked_s(const rw_stuck_t *s, uint32_t now_ms);

/** Fill in magic, version and crc. Call before handing a record to storage. */
void rw_stuck_record_seal(rw_stuck_record_t *rec);

/** True if this looks like a record we wrote, rather than power-on noise. */
bool rw_stuck_record_valid(const rw_stuck_record_t *rec);

#endif /* RW_STUCK_H */
