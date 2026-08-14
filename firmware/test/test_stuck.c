/*
 * The stuck detector.
 *
 * These tests exist because the module's whole job is to restart a device, which is the most
 * destructive thing this firmware does on its own initiative. The dangerous failure is not
 * "fails to notice" — that is the status quo, and a device sits in RW_LED_ONLINE waking machines
 * on the LAN. The dangerous failure is restarting a device that was fine, or restarting one over
 * and over, and both are decisions this file pins.
 *
 * SPDX-License-Identifier: MIT
 */
#include "rw_test.h"

#include "diag/stuck.h"

/* Comfortably past the arm threshold, in the units rw_stuck_step takes. */
#define ARMED_MS (RW_STUCK_ARM_MS + 1000u)

/** Drive the detector from `from` to `to` in one-second steps, returning true if it ever fired. */
static bool run(rw_stuck_t *s, bool net, bool relay, uint32_t from, uint32_t to) {
    for (uint32_t t = from; t <= to; t += 1000u) {
        if (rw_stuck_step(s, net, relay, t)) {
            return true;
        }
    }
    return false;
}

static void arm(rw_stuck_t *s) {
    rw_stuck_init(s);
    /* Hold a link long enough to be trusted. */
    RW_CHECK(!run(s, true, true, 0, ARMED_MS));
    RW_CHECK(s->armed);
}

void test_stuck(void) {
    rw_stuck_t s;

    /* ── The case this module was written for ─────────────────────────────────────────────── */

    rw_test_begin("stuck: an armed device with a network and no relay restarts");
    {
        arm(&s);
        /* Link drops. Nothing should happen for a long time. */
        RW_CHECK(!run(&s, true, false, ARMED_MS + 1000u, ARMED_MS + RW_STUCK_TRIGGER_MS - 2000u));
        /* And then it should. */
        RW_CHECK(run(&s, true, false, ARMED_MS + RW_STUCK_TRIGGER_MS - 1000u,
                     ARMED_MS + RW_STUCK_TRIGGER_MS + 5000u));
    }

    /* ── The rules that stop it being worse than the bug ──────────────────────────────────── */

    rw_test_begin("stuck: a device that never linked is never restarted");
    {
        /*
         * The unclaimed device, and the self-hoster whose relay is not running. led.h calls this
         * a legitimate resting state and LAN wake keeps working throughout. Restarting these
         * would be a loop for as long as their owner's situation lasted — which could be weeks.
         */
        rw_stuck_init(&s);
        RW_CHECK(!run(&s, true, false, 0, RW_STUCK_TRIGGER_MS * 3u));
        RW_CHECK(!s.armed);
    }

    rw_test_begin("stuck: a link too brief to trust does not arm it");
    {
        /* A relay that accepts and immediately drops. Arming here would restart this device
           every trigger period for as long as the flapping continued. */
        rw_stuck_init(&s);
        RW_CHECK(!run(&s, true, true, 0, RW_STUCK_ARM_MS - 5000u));
        RW_CHECK(!s.armed);
        RW_CHECK(!run(&s, true, false, RW_STUCK_ARM_MS - 4000u,
                      RW_STUCK_ARM_MS + RW_STUCK_TRIGGER_MS * 2u));
    }

    rw_test_begin("stuck: losing the network is not being stuck");
    {
        /* net.c owns this case, with its own retry and backoff, and restarting would throw away
           the radio trace that explains it. */
        arm(&s);
        RW_CHECK(!run(&s, false, false, ARMED_MS, ARMED_MS + RW_STUCK_TRIGGER_MS * 2u));
    }

    rw_test_begin("stuck: a reconnection clears the countdown");
    {
        arm(&s);
        /* Most of the way to the trigger... */
        RW_CHECK(!run(&s, true, false, ARMED_MS, ARMED_MS + RW_STUCK_TRIGGER_MS - 5000u));
        /* ...then it comes back, even briefly. */
        RW_CHECK(!rw_stuck_step(&s, true, true, ARMED_MS + RW_STUCK_TRIGGER_MS - 4000u));
        /* The countdown must start again from here, not resume. */
        RW_CHECK(!run(&s, true, false, ARMED_MS + RW_STUCK_TRIGGER_MS - 3000u,
                      ARMED_MS + RW_STUCK_TRIGGER_MS + 10000u));
    }

    rw_test_begin("stuck: a network drop clears the countdown too");
    {
        arm(&s);
        RW_CHECK(!run(&s, true, false, ARMED_MS, ARMED_MS + RW_STUCK_TRIGGER_MS - 5000u));
        RW_CHECK(!rw_stuck_step(&s, false, false, ARMED_MS + RW_STUCK_TRIGGER_MS - 4000u));
        RW_CHECK(!run(&s, true, false, ARMED_MS + RW_STUCK_TRIGGER_MS - 3000u,
                      ARMED_MS + RW_STUCK_TRIGGER_MS + 10000u));
    }

    /* ── Time ────────────────────────────────────────────────────────────────────────────── */

    rw_test_begin("stuck: the millisecond counter may wrap without restarting a healthy device");
    {
        /*
         * to_ms_since_boot wraps every 49.7 days, and a dongle is expected to run for months. If
         * the arithmetic compared timestamps rather than differences, the wrap would look like an
         * enormous elapsed time and restart every device that reached it.
         */
        const uint32_t near_wrap = 0xFFFFF000u;
        rw_stuck_init(&s);
        RW_CHECK(!rw_stuck_step(&s, true, true, near_wrap));
        /* Arm across the wrap. */
        RW_CHECK(!rw_stuck_step(&s, true, true, (uint32_t)(near_wrap + ARMED_MS)));
        RW_CHECK(s.armed);
        /* Now go unlinked across the wrap and confirm the trigger still lands where it should. */
        const uint32_t unlinked_at = (uint32_t)(near_wrap + ARMED_MS + 1000u);
        RW_CHECK(!rw_stuck_step(&s, true, false, unlinked_at));
        RW_CHECK(!rw_stuck_step(&s, true, false,
                                (uint32_t)(unlinked_at + RW_STUCK_TRIGGER_MS - 2000u)));
        RW_CHECK(rw_stuck_step(&s, true, false,
                               (uint32_t)(unlinked_at + RW_STUCK_TRIGGER_MS)));
    }

    rw_test_begin("stuck: unlinked seconds are reported, and are zero while linked");
    {
        arm(&s);
        RW_CHECK(rw_stuck_unlinked_s(&s, ARMED_MS) == 0);
        RW_CHECK(!rw_stuck_step(&s, true, false, ARMED_MS + 1000u));
        RW_CHECK(rw_stuck_unlinked_s(&s, ARMED_MS + 31000u) == 30);
    }

    /* ── The record that crosses the restart ──────────────────────────────────────────────── */

    rw_test_begin("stuck: a sealed record validates, and a corrupted one does not");
    {
        rw_stuck_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rec.relay_state = 2;
        rec.uptime_s = 123456;
        rec.unlinked_s = 900;
        strcpy(rec.last_error, "sntp_timeout");
        rw_stuck_record_seal(&rec);

        RW_CHECK(rw_stuck_record_valid(&rec));
        RW_CHECK(rec.magic == RW_STUCK_MAGIC);
        RW_CHECK(rec.version == RW_STUCK_RECORD_VERSION);

        /* Any single bit anywhere in the covered area must be caught. */
        rec.unlinked_s ^= 1u;
        RW_CHECK(!rw_stuck_record_valid(&rec));
        rec.unlinked_s ^= 1u;
        RW_CHECK(rw_stuck_record_valid(&rec));

        rec.last_error[0] = 'S';
        RW_CHECK(!rw_stuck_record_valid(&rec));
    }

    rw_test_begin("stuck: power-on noise is not mistaken for a record");
    {
        /*
         * The record lives in uninitialised RAM, so after a power cut it is whatever the SRAM
         * powered up holding. The magic alone is not enough — this checks the case that actually
         * threatens us, where the noise happens to begin with the right four bytes.
         */
        rw_stuck_record_t noise;
        memset(&noise, 0xA5, sizeof(noise));
        RW_CHECK(!rw_stuck_record_valid(&noise));

        noise.magic = RW_STUCK_MAGIC;
        noise.version = RW_STUCK_RECORD_VERSION;
        RW_CHECK_MSG(!rw_stuck_record_valid(&noise),
                     "noise wearing the right magic must still fail the CRC");

        /* All-zero RAM is the other common power-on pattern. */
        rw_stuck_record_t zeroed;
        memset(&zeroed, 0, sizeof(zeroed));
        RW_CHECK(!rw_stuck_record_valid(&zeroed));
    }

    rw_test_begin("stuck: a record from a future firmware version is refused");
    {
        /* An older image reading a newer record would misread every field after the change. */
        rw_stuck_record_t rec;
        memset(&rec, 0, sizeof(rec));
        rw_stuck_record_seal(&rec);
        RW_CHECK(rw_stuck_record_valid(&rec));
        rec.version = RW_STUCK_RECORD_VERSION + 1;
        RW_CHECK(!rw_stuck_record_valid(&rec));
    }
}
