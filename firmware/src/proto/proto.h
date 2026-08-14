/*
 * The relay session: PROTOCOL.md frames, the §3.2 handshake, keepalive and reconnection.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_PROTO_H
#define RW_PROTO_H

#include <stdbool.h>
#include <stdint.h>

#include "config/config.h"
#include "diag/stuck.h"

typedef enum {
    RW_RELAY_OFFLINE = 0, /* not started, or the network is not ready */
    RW_RELAY_BACKOFF,     /* waiting out the reconnect delay */
    RW_RELAY_CONNECTING,  /* TCP/TLS/WebSocket handshake in progress */
    RW_RELAY_AUTHENTICATING, /* hello sent, or auth sent */
    RW_RELAY_READY,       /* proof_s verified; the link is trusted */
    RW_RELAY_AUTH_FAILED, /* the relay rejected us, or its proof did not verify */
    RW_RELAY_STOPPED,     /* close 4002: deprovisioned, do not retry */
} rw_relay_state_t;

/* PROTOCOL.md §9. Not a WebSocket control ping: the exact bytes matter to hibernating relay
 * runtimes, which can answer a known text frame without waking the object behind it. */
#define RW_RELAY_PING_INTERVAL_MS 25000

/*
 * How long a live link may go completely silent before the device stops believing in it.
 *
 * WHY AN APPLICATION-LEVEL TIMEOUT EXISTS AT ALL
 *
 * Until 2026-08-14 there was none: the pong handler returned with the comment "liveness is
 * recorded by the transport", and nothing checked that pongs ever came back. That is a belief
 * about lwIP rather than a guarantee from it, and it is wrong in the one case that matters — a
 * HALF-OPEN socket, where the far end goes away without a FIN or an RST. A NAT table that expires
 * the flow, a mesh access point handing the device between nodes, a Worker evicted mid-connection:
 * all of them leave the device holding a TCP connection that will never carry another byte and
 * will never report an error either.
 *
 * In that state the device sits in RW_RELAY_READY, sends a ping every 25 seconds into nothing,
 * and shows the double-flash that means "authenticated to the relay" — indefinitely. It is the
 * worst shape a fault can have: the device is confident, the LED agrees with it, and the owner
 * finds out when a wake does not arrive.
 *
 * Three missed exchanges. Two would fire on a single dropped frame over a congested link, which
 * costs a reconnection for nothing; four is another 25 seconds of a device that is already gone.
 *
 * The response is deliberately NOT a reboot. A dead socket is fixed by opening another one, and
 * the existing backoff does that in seconds without taking USB, the LED or LAN wake down with it.
 * Rebooting is the next rung up (diag/stuck.h), for when reconnecting itself stops working.
 */
#define RW_RELAY_SILENCE_MS (3 * RW_RELAY_PING_INTERVAL_MS)

/* PROTOCOL.md §8. Full jitter, reset only after authentication completes. */
#define RW_RELAY_BACKOFF_MIN_MS 1000u
#define RW_RELAY_BACKOFF_MAX_MS 60000u

typedef struct {
    /*
     * Persist a configuration the session changed — the enrolled flag, or the account address
     * erased once an adoption is acknowledged. Runs on the main loop, never inside a network
     * callback, because a flash write there would stall lwIP mid-frame. A false return is
     * logged and dropped: both changes re-offer themselves on the next connection.
     */
    bool (*save_config)(rw_config_t *cfg);

    /* A wake left the device. Used for the two-second LED confirmation. */
    void (*on_wake_sent)(void);
} rw_relay_hooks_t;

/*
 * Bind the session to a configuration and the host application's hooks.
 *
 * `cfg` is borrowed, not copied: the session writes the enrolled flag and clears the account
 * address in place, so the caller's copy is the live one and stays consistent with what
 * usbcfg's GET_CONFIG reports.
 */
void rw_relay_init(rw_config_t *cfg, const rw_relay_hooks_t *hooks);

/*
 * Hand over the record the previous boot left behind before restarting itself (diag/stuck.h).
 *
 * Reported once, on the first `hello` after the restart, and then forgotten — a device that
 * reconnected has answered the question, and repeating it on every later reconnection would turn
 * one incident into a permanent property of the device.
 *
 * Optional by design: the overwhelming majority of boots have nothing to report, and the field is
 * simply absent from `hello` in that case.
 */
void rw_relay_set_last_stuck(const rw_stuck_record_t *rec);

/* Permit connections. The first attempt happens as soon as the network is ready. */
void rw_relay_start(void);

/* Close any live connection and stop reconnecting. */
void rw_relay_stop(void);

/*
 * Drive the session: reconnection, the keepalive, deferred command execution and the probe.
 * Must be called from the main loop.
 */
void rw_relay_task(void);

rw_relay_state_t rw_relay_state(void);

/*
 * How far an update in flight has got, for usbcfg's OTA_STATE.
 *
 * A transfer that stalls is otherwise invisible from outside: the device answers INFO, holds its
 * Wi-Fi link and reports the relay as connected, and nothing says whether it is part-way through
 * writing a slot or idle. Only a build with diagnostics forced on could tell the difference, and
 * that is not the build in anyone's hands.
 *
 * `total` is what the signed header promised. Both are zero when no transfer is in progress.
 */
void rw_relay_ota_progress(bool *receiving, uint32_t *got, uint32_t *total);

/* String for usbcfg STATUS: "idle", "connecting", "connected", "auth_failed", "backoff". */
const char *rw_relay_state_name(void);

#endif /* RW_PROTO_H */
