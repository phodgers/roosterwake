/*
 * RFC 6455 WebSocket client over lwIP altcp. See ws.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ws/ws.h"

#include <string.h>

#include "lwip/altcp_tcp.h"
#include "lwip/dns.h"
#include "pico/rand.h"
#include "pico/time.h"

#include "brand.h"
#include "rw_log.h"
#include "tls/tls.h"

/* Buffer for one outbound frame. PROTOCOL.md §1 caps a frame at 2048 bytes in both directions;
 * the largest this firmware constructs is a `hello` with eight maximum-length targets, which
 * is under 800. */
#define WS_TX_MAX (RW_WS_MAX_HEADER + RW_WS_MAX_OUTBOUND)

static void ws_teardown(rw_ws_client_t *ws, rw_ws_fail_t why, uint16_t close_code);

/* ── lwIP callbacks ────────────────────────────────────────────────────────── */

static err_t on_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err);
static err_t on_connected(void *arg, struct altcp_pcb *pcb, err_t err);
static void  on_err(void *arg, err_t err);
static err_t on_poll(void *arg, struct altcp_pcb *pcb);

/* ── Helpers ───────────────────────────────────────────────────────────────── */

static void fill_random(uint8_t *out, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint32_t word = get_rand_32();
        size_t   n    = (len - i < 4) ? (len - i) : 4;
        memcpy(out + i, &word, n);
        i += n;
    }
}

static bool tcp_write_all(rw_ws_client_t *ws, const uint8_t *data, size_t len) {
    if (ws->pcb == NULL) {
        return false;
    }
    if (altcp_sndbuf(ws->pcb) < len) {
        /* Refusing rather than queuing. Everything this client sends is small and infrequent;
         * a full send buffer means the peer has stopped reading, and the honest response is to
         * fail the operation now rather than accumulate state that will be discarded anyway. */
        RW_LOG_WARN("ws: send buffer full (%u < %u)", (unsigned)altcp_sndbuf(ws->pcb),
                    (unsigned)len);
        return false;
    }
    err_t err = altcp_write(ws->pcb, data, (u16_t)len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        RW_LOG_WARN("ws: altcp_write failed (%d)", err);
        return false;
    }
    err = altcp_output(ws->pcb);
    if (err != ERR_OK) {
        RW_LOG_WARN("ws: altcp_output failed (%d)", err);
        return false;
    }
    return true;
}

static bool send_frame(rw_ws_client_t *ws, uint8_t opcode, const uint8_t *payload, size_t len) {
    uint8_t mask[4];
    uint8_t frame[WS_TX_MAX];

    if (len > RW_WS_MAX_OUTBOUND) {
        /* Refused here rather than truncated. A relay is entitled to close us with 1009 for
         * exceeding the symmetric limit, and sending a frame we know is over it would turn a
         * local bug into a reconnect loop. */
        RW_LOG_ERROR("ws: refusing to send %u bytes, the limit is %u", (unsigned)len,
                     (unsigned)RW_WS_MAX_OUTBOUND);
        return false;
    }

    /* RFC 6455 §5.3: every client frame is masked, with a fresh unpredictable key. The key is
     * not a confidentiality mechanism — it exists to stop a client being tricked into emitting
     * attacker-chosen bytes at a transparent proxy — and predictability defeats that, so it
     * comes from the same TRNG the nonces do. */
    fill_random(mask, sizeof(mask));

    size_t n = rw_ws_build_frame(frame, sizeof(frame), true, opcode, payload, len, mask);
    if (n == 0) {
        RW_LOG_ERROR("ws: outbound frame of %u bytes does not fit", (unsigned)len);
        return false;
    }
    return tcp_write_all(ws, frame, n);
}

static void notify_close(rw_ws_client_t *ws, rw_ws_fail_t why, uint16_t code) {
    if (ws->cb != NULL && ws->cb->on_close != NULL) {
        ws->cb->on_close(ws, ws->ctx, why, code);
    }
}

/*
 * Release the pcb and return to RW_WS_CLOSED.
 *
 * `pcb` is set to NULL before any callback runs, so a callback that starts a new connection
 * cannot be handed the one being destroyed.
 */
static void ws_teardown(rw_ws_client_t *ws, rw_ws_fail_t why, uint16_t close_code) {
    struct altcp_pcb *pcb = ws->pcb;
    ws->pcb               = NULL;

    if (pcb != NULL) {
        altcp_arg(pcb, NULL);
        altcp_recv(pcb, NULL);
        altcp_err(pcb, NULL);
        altcp_poll(pcb, NULL, 0);
        if (altcp_close(pcb) != ERR_OK) {
            /* close() can fail when the send buffer cannot be flushed. abort() always
             * succeeds and is the only way to guarantee the pcb is not leaked. */
            altcp_abort(pcb);
        }
    }

    bool was_live = ws->state != RW_WS_CLOSED;
    ws->state     = RW_WS_CLOSED;
    ws->fail      = why;
    ws->close_code = close_code;
    ws->rx_len    = 0;
    ws->msg_len   = 0;
    ws->msg_active = false;

    if (was_live) {
        notify_close(ws, why, close_code);
    }
}

/* ── Handshake ─────────────────────────────────────────────────────────────── */

static bool send_upgrade_request(rw_ws_client_t *ws) {
    uint8_t key[RW_WS_KEY_BYTES];
    fill_random(key, sizeof(key));
    rw_ws_key_encode(key, ws->key_b64);
    rw_ws_compute_accept(ws->key_b64, ws->accept_b64);

    char   request[512];
    size_t n = rw_ws_build_request(request, sizeof(request), ws->url.host, ws->url.port,
                                   ws->url.tls, ws->url.path, ws->key_b64, RW_WS_SUBPROTOCOL);
    if (n == 0) {
        RW_LOG_ERROR("ws: upgrade request does not fit");
        return false;
    }
    return tcp_write_all(ws, (const uint8_t *)request, n);
}

static void handle_handshake_bytes(rw_ws_client_t *ws) {
    size_t            consumed = 0;
    rw_ws_hs_result_t r = rw_ws_parse_response((const char *)ws->rx, ws->rx_len, ws->accept_b64,
                                               RW_WS_SUBPROTOCOL, &consumed);

    switch (r) {
        case RW_WS_HS_NEED_MORE:
            return;
        case RW_WS_HS_OK:
            break;
        case RW_WS_HS_BAD_STATUS:
            RW_LOG_ERROR("ws: relay did not upgrade (no 101)");
            ws_teardown(ws, RW_WS_FAIL_HANDSHAKE, 0);
            return;
        case RW_WS_HS_BAD_UPGRADE:
            RW_LOG_ERROR("ws: 101 without Upgrade/Connection headers");
            ws_teardown(ws, RW_WS_FAIL_HANDSHAKE, 0);
            return;
        case RW_WS_HS_BAD_ACCEPT:
            RW_LOG_ERROR("ws: Sec-WebSocket-Accept mismatch");
            ws_teardown(ws, RW_WS_FAIL_HANDSHAKE, 0);
            return;
        case RW_WS_HS_NO_SUBPROTOCOL:
            /* PROTOCOL.md §1: the endpoint speaks WebSocket but is not a Remote Wake relay.
             * This is the captive-portal and misconfigured-proxy case, and closing here is
             * what turns a device that hangs forever into one that says so. */
            RW_LOG_ERROR("ws: endpoint did not echo %s - this is not a relay", RW_WS_SUBPROTOCOL);
            ws_teardown(ws, RW_WS_FAIL_NO_SUBPROTOCOL, 0);
            return;
        case RW_WS_HS_TOO_LARGE:
            RW_LOG_ERROR("ws: upgrade response headers too large");
            ws_teardown(ws, RW_WS_FAIL_HANDSHAKE, 0);
            return;
    }

    /* A relay may put its first frame in the same segment as the response, so keep the tail. */
    memmove(ws->rx, ws->rx + consumed, ws->rx_len - consumed);
    ws->rx_len = ws->rx_len - consumed;

    ws->state   = RW_WS_OPEN;
    ws->last_rx = get_absolute_time();
    RW_LOG_INFO("ws: connected to %s:%u%s", ws->url.host, ws->url.port, ws->url.path);

    if (ws->cb != NULL && ws->cb->on_open != NULL) {
        ws->cb->on_open(ws, ws->ctx);
    }
}

/* ── Frame handling ────────────────────────────────────────────────────────── */

static void deliver_message(rw_ws_client_t *ws) {
    ws->msg[ws->msg_len] = '\0';
    if (ws->cb != NULL && ws->cb->on_text != NULL) {
        ws->cb->on_text(ws, ws->ctx, ws->msg, ws->msg_len);
    }
    ws->msg_len    = 0;
    ws->msg_active = false;
}

/*
 * Consume as many complete frames as the buffer holds.
 *
 * Returns false when the connection has been torn down, so the caller stops touching `ws`.
 */
static bool pump_frames(rw_ws_client_t *ws) {
    for (;;) {
        rw_ws_header_t h;
        rw_ws_parse_t  pr = rw_ws_parse_header(ws->rx, ws->rx_len, &h);

        if (pr == RW_WS_PARSE_NEED_MORE) {
            return true;
        }
        if (pr == RW_WS_PARSE_ERROR) {
            RW_LOG_ERROR("ws: framing violation");
            rw_ws_close(ws, RW_WS_CLOSE_PROTOCOL_ERR, "bad frame");
            ws->fail = RW_WS_FAIL_PROTOCOL;
            return false;
        }
        if (pr == RW_WS_PARSE_TOO_LARGE) {
            /* PROTOCOL.md §1: reject with 1009. The payload is never read — the buffer could
             * not hold it, which is the whole point of the limit. */
            RW_LOG_ERROR("ws: relay sent %llu bytes, cap is %u",
                         (unsigned long long)h.payload_len, (unsigned)RW_WS_MAX_INBOUND);
            rw_ws_close(ws, RW_WS_CLOSE_TOO_BIG, "frame too large");
            ws->fail = RW_WS_FAIL_TOO_BIG;
            return false;
        }

        const size_t total = h.header_len + (size_t)h.payload_len;
        if (ws->rx_len < total) {
            return true; /* payload still in flight */
        }

        uint8_t     *payload = ws->rx + h.header_len;
        const size_t plen    = (size_t)h.payload_len;

        switch (h.opcode) {
            case RW_WS_OP_PING:
                /* PROTOCOL.md §9 makes the application-level ping the load-bearing one, but a
                 * control ping still has to be answered: the reference relay and several
                 * proxies use them. */
                if (!send_frame(ws, RW_WS_OP_PONG, payload, plen)) {
                    ws_teardown(ws, RW_WS_FAIL_LOCAL, 0);
                    return false;
                }
                break;

            case RW_WS_OP_PONG:
                break; /* liveness is already recorded by last_rx */

            case RW_WS_OP_CLOSE: {
                uint16_t code = RW_WS_CLOSE_NORMAL;
                if (plen >= 2) {
                    code = (uint16_t)((payload[0] << 8) | payload[1]);
                }
                RW_LOG_INFO("ws: relay closed with %u", code);

                if (ws->state == RW_WS_OPEN) {
                    /* Echo the code back, as RFC 6455 §5.5.1 requires of the responding side.
                     * A close with no body is echoed with no body — reading two bytes out of a
                     * zero-length payload would read whatever followed it in the buffer. */
                    if (plen >= 2) {
                        const uint8_t echo[2] = {payload[0], payload[1]};
                        send_frame(ws, RW_WS_OP_CLOSE, echo, 2);
                    } else {
                        send_frame(ws, RW_WS_OP_CLOSE, NULL, 0);
                    }
                }
                rw_ws_fail_t why = (code == RW_WS_CLOSE_DEPROVISIONED) ? RW_WS_FAIL_DEPROVISIONED
                                                                      : RW_WS_FAIL_PEER_CLOSED;
                ws_teardown(ws, why, code);
                return false;
            }

            case RW_WS_OP_TEXT:
            case RW_WS_OP_CONT: {
                if (h.opcode == RW_WS_OP_TEXT) {
                    if (ws->msg_active) {
                        RW_LOG_ERROR("ws: text frame inside a fragmented message");
                        rw_ws_close(ws, RW_WS_CLOSE_PROTOCOL_ERR, "interleaved fragment");
                        ws->fail = RW_WS_FAIL_PROTOCOL;
                        return false;
                    }
                    ws->msg_len = 0;
                } else if (!ws->msg_active) {
                    RW_LOG_ERROR("ws: continuation with no message in progress");
                    rw_ws_close(ws, RW_WS_CLOSE_PROTOCOL_ERR, "orphan continuation");
                    ws->fail = RW_WS_FAIL_PROTOCOL;
                    return false;
                }

                /* The 2048-byte cap is on the *message*, not on each fragment: a relay that
                 * splits 4 KB into two legal frames is still over the limit this device can
                 * hold, and letting it through would overrun this buffer. */
                if (ws->msg_len + plen > RW_WS_MAX_INBOUND) {
                    RW_LOG_ERROR("ws: reassembled message exceeds %u bytes",
                                 (unsigned)RW_WS_MAX_INBOUND);
                    rw_ws_close(ws, RW_WS_CLOSE_TOO_BIG, "message too large");
                    ws->fail = RW_WS_FAIL_TOO_BIG;
                    return false;
                }
                memcpy(ws->msg + ws->msg_len, payload, plen);
                ws->msg_len += plen;
                ws->msg_active = !h.fin;

                if (h.fin) {
                    /* Consume the frame before dispatching: on_text may send, and may even
                     * close, and it must not see a buffer that still contains its own input. */
                    memmove(ws->rx, ws->rx + total, ws->rx_len - total);
                    ws->rx_len -= total;
                    deliver_message(ws);
                    if (ws->state != RW_WS_OPEN) {
                        return false;
                    }
                    continue;
                }
                break;
            }

            case RW_WS_OP_BINARY: {
                /* PROTOCOL.md §1: frames are text, with one exception — the payload of an update
                 * the device asked for. Anything else is a peer speaking a different protocol,
                 * and so is a fragmented one: nothing this firmware accepts as binary benefits
                 * from reassembly, and allowing it would mean a second 2 KB buffer. */
                if (ws->cb->on_binary == NULL || !h.fin || ws->msg_active) {
                    RW_LOG_ERROR("ws: unexpected binary frame");
                    rw_ws_close(ws, RW_WS_CLOSE_PROTOCOL_ERR, "unexpected binary frame");
                    ws->fail = RW_WS_FAIL_PROTOCOL;
                    return false;
                }
                /* Dispatched from the receive buffer rather than copied out of it. The handler
                 * may send, so it must not itself consume `rx`; the frame is dropped below,
                 * once it has returned. */
                bool wanted = ws->cb->on_binary(ws, ws->ctx, payload, plen);
                if (ws->state != RW_WS_OPEN) {
                    return false;
                }
                if (!wanted) {
                    rw_ws_close(ws, RW_WS_CLOSE_POLICY, "binary frame not expected");
                    ws->fail = RW_WS_FAIL_PROTOCOL;
                    return false;
                }
                break;
            }

            default:
                RW_LOG_ERROR("ws: unexpected opcode 0x%x", h.opcode);
                rw_ws_close(ws, RW_WS_CLOSE_PROTOCOL_ERR, "unexpected opcode");
                ws->fail = RW_WS_FAIL_PROTOCOL;
                return false;
        }

        memmove(ws->rx, ws->rx + total, ws->rx_len - total);
        ws->rx_len -= total;
    }
}

static err_t on_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
    rw_ws_client_t *ws = (rw_ws_client_t *)arg;
    if (ws == NULL) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    if (p == NULL) {
        RW_LOG_INFO("ws: peer closed the connection");
        ws_teardown(ws, RW_WS_FAIL_PEER_CLOSED, 0);
        return ERR_OK;
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        ws_teardown(ws, RW_WS_FAIL_PROTOCOL, 0);
        return ERR_OK;
    }

    const u16_t received = p->tot_len;
    ws->last_rx          = get_absolute_time();

    u16_t offset = 0;
    while (offset < received) {
        size_t space = sizeof(ws->rx) - ws->rx_len;
        if (space == 0) {
            /* Only reachable if a peer sends a header claiming a length we accepted and then
             * more than that. The frame parser has already vetoed anything over the cap, so
             * this is a stream that is no longer self-consistent. */
            RW_LOG_ERROR("ws: receive buffer overflow");
            rw_ws_close(ws, RW_WS_CLOSE_TOO_BIG, "buffer overflow");
            ws->fail = RW_WS_FAIL_TOO_BIG;
            break;
        }
        size_t remaining = (size_t)(received - offset);
        u16_t  chunk     = (u16_t)((remaining < space) ? remaining : space);
        pbuf_copy_partial(p, ws->rx + ws->rx_len, chunk, offset);
        ws->rx_len += chunk;
        offset += chunk;

        if (ws->state == RW_WS_HANDSHAKING) {
            handle_handshake_bytes(ws);
            if (ws->state == RW_WS_CLOSED) {
                break;
            }
        }
        if (ws->state == RW_WS_OPEN || ws->state == RW_WS_CLOSING) {
            if (!pump_frames(ws)) {
                break;
            }
        }
    }

    pbuf_free(p);

    /*
     * If processing tore the connection down, `pcb` is gone: ws_teardown() calls altcp_close(),
     * and altcp_abort() if that fails. Touching it now — even to acknowledge the bytes — is a
     * use-after-free, and ERR_ABRT is the return lwIP requires when the pcb no longer exists.
     */
    if (ws->pcb != pcb) {
        return ERR_ABRT;
    }

    /* Acknowledge everything that arrived, even if a frame in it was rejected: lwIP's window
     * accounting is not conditional on our approval of the contents. */
    altcp_recved(pcb, received);
    return ERR_OK;
}

static err_t on_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
    rw_ws_client_t *ws = (rw_ws_client_t *)arg;

    if (ws == NULL) {
        return ERR_OK;
    }
    if (err != ERR_OK) {
        RW_LOG_ERROR("ws: connect failed (%d)", err);
        ws_teardown(ws, RW_WS_FAIL_CONNECT, 0);
        return ERR_ABRT;
    }

    /* For a TLS connection this fires after the handshake completed, so reaching here means
     * the certificate was accepted (or verification is off and we said so loudly). */
    ws->state    = RW_WS_HANDSHAKING;
    ws->last_rx  = get_absolute_time();
    ws->deadline = make_timeout_time_ms(RW_WS_CONNECT_TIMEOUT_MS);

    if (!send_upgrade_request(ws)) {
        ws_teardown(ws, RW_WS_FAIL_LOCAL, 0);
    }
    return (ws->pcb == pcb) ? ERR_OK : ERR_ABRT;
}

static void on_err(void *arg, err_t err) {
    rw_ws_client_t *ws = (rw_ws_client_t *)arg;
    if (ws == NULL) {
        return;
    }
    /* lwIP has already freed the pcb. Clearing it first stops ws_teardown() from touching it. */
    ws->pcb = NULL;

    rw_ws_fail_t why = (ws->state == RW_WS_CONNECTING || ws->state == RW_WS_RESOLVING)
                           ? RW_WS_FAIL_CONNECT
                           : RW_WS_FAIL_PEER_CLOSED;
    RW_LOG_WARN("ws: transport error (%d)", err);
    ws_teardown(ws, why, 0);
}

static err_t on_poll(void *arg, struct altcp_pcb *pcb) {
    rw_ws_client_t *ws = (rw_ws_client_t *)arg;
    if (ws == NULL) {
        return ERR_OK;
    }
    rw_ws_task(ws);
    /* rw_ws_task() can close the connection on a liveness timeout, which destroys the pcb. */
    return (ws->pcb == pcb) ? ERR_OK : ERR_ABRT;
}

/* ── Connection setup ──────────────────────────────────────────────────────── */

static bool start_connect(rw_ws_client_t *ws) {
    if (ws->url.tls) {
        ws->pcb = rw_tls_new(ws->url.host);
    } else {
        ws->pcb = altcp_tcp_new_ip_type(IPADDR_TYPE_V4);
    }
    if (ws->pcb == NULL) {
        RW_LOG_ERROR("ws: could not allocate a pcb");
        ws->state = RW_WS_CLOSED;
        ws->fail  = ws->url.tls ? RW_WS_FAIL_TLS : RW_WS_FAIL_LOCAL;
        return false;
    }

    altcp_arg(ws->pcb, ws);
    altcp_recv(ws->pcb, on_recv);
    altcp_err(ws->pcb, on_err);
    /* One poll every two coarse ticks, i.e. roughly once a second, which is all the resolution
     * the 75-second liveness rule needs. */
    altcp_poll(ws->pcb, on_poll, 2);

    ws->state    = RW_WS_CONNECTING;
    ws->deadline = make_timeout_time_ms(RW_WS_CONNECT_TIMEOUT_MS);

    err_t err = altcp_connect(ws->pcb, &ws->addr, ws->url.port, on_connected);
    if (err != ERR_OK) {
        RW_LOG_ERROR("ws: altcp_connect refused (%d)", err);
        ws_teardown(ws, RW_WS_FAIL_CONNECT, 0);
        return false;
    }
    return true;
}

static void dns_done(const char *name, const ip_addr_t *addr, void *arg) {
    (void)name;
    rw_ws_client_t *ws = (rw_ws_client_t *)arg;
    if (ws == NULL || ws->state != RW_WS_RESOLVING) {
        return;
    }
    if (addr == NULL) {
        RW_LOG_ERROR("ws: DNS lookup of %s failed", ws->url.host);
        ws->state = RW_WS_CLOSED;
        ws->fail  = RW_WS_FAIL_DNS;
        notify_close(ws, RW_WS_FAIL_DNS, 0);
        return;
    }
    ws->addr = *addr;
    start_connect(ws);
}

void rw_ws_init(void) {
    /* dns_init() is already done by lwIP's init path; nothing else is global here. Kept as an
     * explicit entry point so the module has one place to grow into. */
}

bool rw_ws_connect(rw_ws_client_t *ws, const char *url, const rw_ws_callbacks_t *cb, void *ctx) {
    if (ws->state != RW_WS_CLOSED) {
        rw_ws_abort(ws, RW_WS_FAIL_LOCAL);
    }

    ws->rx_len     = 0;
    ws->msg_len    = 0;
    ws->msg_active = false;
    ws->cb         = cb;
    ws->ctx        = ctx;
    ws->fail       = RW_WS_FAIL_NONE;
    ws->close_code = 0;

    if (!rw_url_parse(url, &ws->url)) {
        RW_LOG_ERROR("ws: relay URL is not a valid ws:// or wss:// URL");
        ws->fail = RW_WS_FAIL_DNS;
        return false;
    }
    if (!ws->url.tls && !rw_url_plaintext_permitted(ws->url.host)) {
        /* PROTOCOL.md §1: plaintext only to loopback and RFC 1918. Enforced here as well as at
         * configuration time, because a config image can be written by anything. */
        RW_LOG_ERROR("ws: refusing plaintext ws:// to a public host (%s)", ws->url.host);
        ws->fail = RW_WS_FAIL_LOCAL;
        return false;
    }

    ws->state    = RW_WS_RESOLVING;
    ws->deadline = make_timeout_time_ms(RW_WS_CONNECT_TIMEOUT_MS);
    ws->last_rx  = get_absolute_time();

    err_t err = dns_gethostbyname(ws->url.host, &ws->addr, dns_done, ws);
    if (err == ERR_OK) {
        return start_connect(ws); /* already cached */
    }
    if (err == ERR_INPROGRESS) {
        return true;
    }

    RW_LOG_ERROR("ws: dns_gethostbyname refused (%d)", err);
    ws->state = RW_WS_CLOSED;
    ws->fail  = RW_WS_FAIL_DNS;
    return false;
}

void rw_ws_task(rw_ws_client_t *ws) {
    switch (ws->state) {
        case RW_WS_CLOSED:
            return;

        case RW_WS_RESOLVING:
        case RW_WS_CONNECTING:
        case RW_WS_HANDSHAKING:
            if (time_reached(ws->deadline)) {
                RW_LOG_WARN("ws: timed out before the connection opened");
                ws_teardown(ws, RW_WS_FAIL_TIMEOUT, 0);
            }
            return;

        case RW_WS_OPEN:
            /* PROTOCOL.md §9: no frame of any kind for 75 seconds means the connection is
             * dead, whatever TCP believes. The device is behind NAT, and a router that has
             * dropped the mapping leaves a socket that looks perfectly healthy from here. */
            if (absolute_time_diff_us(ws->last_rx, get_absolute_time()) / 1000 >
                (int64_t)RW_WS_DEAD_PEER_MS) {
                RW_LOG_WARN("ws: no frame for %u ms, treating the peer as dead",
                            (unsigned)RW_WS_DEAD_PEER_MS);
                /* PROTOCOL.md §7: 4003, not 1000 or 1008. The relay has to be able to tell
                 * "you went quiet" from "you failed authentication", and so does our own
                 * backoff logic on the next connection. The frame will usually not arrive —
                 * the peer is, by definition, not answering — and the close grace timer then
                 * drops the socket. */
                rw_ws_close(ws, RW_WS_CLOSE_IDLE_TIMEOUT, "idle");
                ws->fail = RW_WS_FAIL_TIMEOUT;
            }
            return;

        case RW_WS_CLOSING:
            if (time_reached(ws->deadline)) {
                ws_teardown(ws, ws->fail != RW_WS_FAIL_NONE ? ws->fail : RW_WS_FAIL_LOCAL,
                            ws->close_code);
            }
            return;
    }
}

bool rw_ws_send_text(rw_ws_client_t *ws, const char *text, size_t len) {
    if (ws->state != RW_WS_OPEN) {
        return false;
    }
    return send_frame(ws, RW_WS_OP_TEXT, (const uint8_t *)text, len);
}

void rw_ws_close(rw_ws_client_t *ws, uint16_t code, const char *reason) {
    if (ws->state != RW_WS_OPEN && ws->state != RW_WS_HANDSHAKING) {
        return;
    }

    uint8_t mask[4];
    uint8_t frame[RW_WS_MAX_HEADER + 125];
    fill_random(mask, sizeof(mask));

    size_t n = rw_ws_build_close(frame, sizeof(frame), code, reason, mask);
    if (n == 0 || !tcp_write_all(ws, frame, n)) {
        ws_teardown(ws, RW_WS_FAIL_LOCAL, code);
        return;
    }

    ws->state      = RW_WS_CLOSING;
    ws->close_code = code;
    ws->deadline   = make_timeout_time_ms(RW_WS_CLOSE_GRACE_MS);
}

void rw_ws_abort(rw_ws_client_t *ws, rw_ws_fail_t why) {
    ws_teardown(ws, why, 0);
}

bool rw_ws_is_open(const rw_ws_client_t *ws) {
    return ws->state == RW_WS_OPEN;
}
