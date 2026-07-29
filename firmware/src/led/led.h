/*
 * Status LED patterns on the CYW43439's GPIO 0.
 *
 * The dongle has one LED and no screen, and it usually lives behind a router where nobody can
 * see a serial console. The patterns are therefore chosen to be distinguishable across a room
 * and to answer the only question an owner actually asks: is it talking to the relay or not.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_LED_H
#define RW_LED_H

#include <stdbool.h>

typedef enum {
    RW_LED_SETUP_AP = 0, /* fast blink   - unprovisioned, setup hotspot is up */
    RW_LED_JOINING,      /* slow blink   - joining Wi-Fi, or waiting on DHCP/SNTP/DNS */
    /*
     * Single pulse every 3 s - on the network, but not talking to a relay.
     *
     * A real and often perfectly fine state: a self-hosted device before its relay is running,
     * a device that has not been claimed yet, or one whose relay is briefly down. Wake-on-LAN
     * from the local network still works. It used to share the slow blink with "joining", which
     * meant the owner could not tell "still trying to get onto your Wi-Fi" from "on your Wi-Fi,
     * just not linked to the cloud" — two problems with completely different fixes.
     */
    RW_LED_ONLINE,
    RW_LED_CONNECTED,    /* double pulse every 3 s - authenticated to the relay */
    RW_LED_ERROR,        /* SOS          - unrecoverable, or TLS verification disabled */
} rw_led_pattern_t;

void rw_led_init(void);

/* Set the resting pattern. Cheap and idempotent; safe to call every loop iteration. */
void rw_led_set(rw_led_pattern_t pattern);

/*
 * Two seconds solid, then back to the resting pattern.
 *
 * This is the one piece of feedback that tells someone standing next to the dongle that a
 * wake actually left the device, which separates "the relay never reached it" from "the PC
 * ignored it" without any tooling at all.
 */
void rw_led_wake_sent(void);

/* Advance the pattern. Must be called from the main loop; does nothing between transitions. */
void rw_led_task(void);

#endif /* RW_LED_H */
