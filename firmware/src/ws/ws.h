/*
 * RFC 6455 WebSocket client over lwIP altcp, with or without TLS.
 *
 * Hand-rolled rather than pulled from a library because the requirements are unusual: 2 KB
 * inbound cap, mandatory subprotocol echo, masking from a hardware TRNG, and a single-threaded
 * poll-mode event loop with no allocation after start-up. Every general-purpose client this
 * would have used breaks at least two of those.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WS_H
#define RW_WS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lwip/altcp.h"
#include "lwip/ip_addr.h"

#include "net/url.h"
#include "ws/ws_frame.h"
#include "ws/ws_handshake.h"

typedef enum {
    RW_WS_CLOSED = 0,
    RW_WS_RESOLVING,
    RW_WS_CONNECTING,
    RW_WS_HANDSHAKING,
    RW_WS_OPEN,
    RW_WS_CLOSING,
} rw_ws_state_t;

/* Why the last connection ended. Surfaced to the reconnect policy, which treats
 * RW_WS_FAIL_DEPROVISIONED as terminal (PROTOCOL.md §7). */
typedef enum {
    RW_WS_FAIL_NONE = 0,
    RW_WS_FAIL_DNS,
    RW_WS_FAIL_CONNECT,
    RW_WS_FAIL_TLS,
    RW_WS_FAIL_HANDSHAKE,     /* not a WebSocket, or the accept value was wrong */
    RW_WS_FAIL_NO_SUBPROTOCOL,/* answered 101 but is not a Rooster Wake relay */
    RW_WS_FAIL_PROTOCOL,      /* framing violation */
    RW_WS_FAIL_TOO_BIG,       /* the relay exceeded the 2048-byte cap */
    RW_WS_FAIL_TIMEOUT,       /* 75 s without a frame */
    RW_WS_FAIL_PEER_CLOSED,
    RW_WS_FAIL_DEPROVISIONED, /* close 4002: stop trying */
    RW_WS_FAIL_LOCAL,         /* out of memory, or a local close */
} rw_ws_fail_t;

/* PROTOCOL.md §9: three missed 25-second heartbeats. */
#define RW_WS_DEAD_PEER_MS 75000u

/* How long a locally-initiated close waits for the peer's close before dropping TCP. */
#define RW_WS_CLOSE_GRACE_MS 2000u

/* Connect attempts that never reach OPEN are abandoned here rather than held forever by a
 * server that accepts TCP and then says nothing. */
#define RW_WS_CONNECT_TIMEOUT_MS 20000u

struct rw_ws_client;

typedef struct {
    void (*on_open)(struct rw_ws_client *ws, void *ctx);
    /* `text` is NUL-terminated for the convenience of the JSON parser; `len` excludes it. */
    void (*on_text)(struct rw_ws_client *ws, void *ctx, char *text, size_t len);
    /*
     * A binary frame. Optional: leave it NULL and a binary frame closes the connection as the
     * protocol violation it is.
     *
     * `data` points into the receive buffer and is valid only for the duration of the call, so a
     * handler that needs to keep the bytes must consume them now. Returning false says the frame
     * was not expected, which closes the connection — the application decides what "expected"
     * means, because a stream of bytes nobody asked for is exactly what this refuses to accept.
     *
     * Fragmented binary messages are refused before this is reached: an update stream is written
     * to flash frame by frame and has nothing to gain from reassembly this side.
     */
    bool (*on_binary)(struct rw_ws_client *ws, void *ctx, const uint8_t *data, size_t len);
    void (*on_close)(struct rw_ws_client *ws, void *ctx, rw_ws_fail_t why, uint16_t close_code);
} rw_ws_callbacks_t;

typedef struct rw_ws_client {
    rw_ws_state_t state;
    rw_ws_fail_t  fail;
    uint16_t      close_code;

    rw_url_t          url;
    ip_addr_t         addr;
    struct altcp_pcb *pcb;

    const rw_ws_callbacks_t *cb;
    void                    *ctx;

    char key_b64[RW_WS_KEY_B64_LEN + 1];
    char accept_b64[RW_WS_ACCEPT_B64_LEN + 1];

    /* Raw inbound stream. Holds the handshake response first, then frames. Sized for the
     * largest legal frame plus its longest header. */
    uint8_t rx[RW_WS_MAX_HEADER + RW_WS_MAX_INBOUND];
    size_t  rx_len;

    /* Reassembled text message across continuation frames. NUL-terminated. */
    char   msg[RW_WS_MAX_INBOUND + 1];
    size_t msg_len;
    bool   msg_active;    /* a fragmented text message is in progress */

    absolute_time_t last_rx;
    absolute_time_t deadline;
} rw_ws_client_t;

/* One-time module setup: nothing global beyond making the DNS resolver's state deterministic
 * for tests. Safe to call more than once. */
void rw_ws_init(void);

/*
 * Begin connecting to `url`. Returns false immediately for a malformed URL, for plaintext to
 * a public address, or if the TLS layer refuses to allocate.
 *
 * The client is single-connection: calling this while one is live tears the old one down.
 */
bool rw_ws_connect(rw_ws_client_t *ws, const char *url, const rw_ws_callbacks_t *cb, void *ctx);

/* Drive timeouts. Inbound data is delivered by lwIP callbacks; this is only the clock. */
void rw_ws_task(rw_ws_client_t *ws);

/* Send a text frame, masked from the TRNG. False if the socket is not open or the frame does
 * not fit the send buffer. */
bool rw_ws_send_text(rw_ws_client_t *ws, const char *text, size_t len);

/* Send a close frame and begin the closing handshake. */
void rw_ws_close(rw_ws_client_t *ws, uint16_t code, const char *reason);

/* Drop the connection without a closing handshake. For a peer that has already gone away. */
void rw_ws_abort(rw_ws_client_t *ws, rw_ws_fail_t why);

bool rw_ws_is_open(const rw_ws_client_t *ws);

#endif /* RW_WS_H */
