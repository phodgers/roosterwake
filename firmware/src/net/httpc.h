/*
 * A minimal HTTP/1.1 client over raw lwIP TCP, for talking to devices on the local segment.
 *
 * The firmware's only other TCP consumer is the relay WebSocket, which runs over altcp+TLS.
 * This one is deliberately plain TCP on port 80: its peers are smart plugs a metre from the
 * router, the traffic never leaves the LAN, and those devices offer nothing better. One
 * request per context, the caller supplies both buffers, and nothing here allocates beyond
 * the pbufs lwIP already uses to carry the bytes.
 *
 * Completion is edge-free: callbacks fired from inside lwIP only record state, and the caller
 * reads it from the main loop via rw_httpc_state() / rw_httpc_poll(). That keeps the rule
 * proto.c is built on — nothing blocking, nothing re-entrant, runs inside a network callback.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_HTTPC_H
#define RW_HTTPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "lwip/ip_addr.h"
#include "pico/time.h"

struct tcp_pcb;

typedef enum {
    RW_HTTPC_IDLE = 0,
    RW_HTTPC_ACTIVE, /* connecting, sending, or reading */
    RW_HTTPC_DONE,   /* the peer finished its response and closed; the buffer holds it all */
    RW_HTTPC_FAILED, /* refused, reset, timed out, or the response outgrew the buffer */
} rw_httpc_state_t;

typedef struct {
    struct tcp_pcb  *pcb;
    rw_httpc_state_t state;
    const char      *req;
    size_t           req_len;
    char            *resp;
    size_t           resp_cap;
    size_t           resp_len;
    absolute_time_t  deadline;
} rw_httpc_t;

/*
 * Start one request. `request` is the complete request text (shelly.c builds it) and must stay
 * valid until the context leaves RW_HTTPC_ACTIVE — it is handed to lwIP without copying,
 * because every caller here keeps it in a static buffer anyway. The response accumulates raw
 * (status line, headers, body) into `resp_buf`, NUL-terminated, which is the form
 * rw_shelly_http_split() reads. Returns false when no connection could even be attempted.
 *
 * Every request carries `Connection: close`, so "the peer closed" is the completion signal
 * and no Content-Length arithmetic happens at this layer.
 */
bool rw_httpc_start(rw_httpc_t *c, const ip4_addr_t *ip, uint16_t port, const char *request,
                    size_t req_len, char *resp_buf, size_t resp_cap, uint32_t timeout_ms);

/* Enforce the deadline. Call from the main loop while the context is active. */
void rw_httpc_poll(rw_httpc_t *c);

/*
 * Drop the connection and return the context to IDLE, whatever state it was in.
 *
 * The teardown is tcp_abort(), not tcp_close(), and that is a constraint rather than a
 * shortcut: MEMP_NUM_TCP_PCB is 4 (lwipopts.h) and the relay connection holds one for the
 * life of the link. A politely closed client connection lingers in TIME_WAIT for minutes,
 * so a sweep that closed politely would strangle itself — and the relay — after three
 * targets. A RST to a plug that has already answered costs nothing.
 */
void rw_httpc_abort(rw_httpc_t *c);

static inline rw_httpc_state_t rw_httpc_state(const rw_httpc_t *c) {
    return c->state;
}

#endif /* RW_HTTPC_H */
