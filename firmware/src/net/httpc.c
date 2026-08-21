/*
 * A minimal HTTP/1.1 client over raw lwIP TCP. See httpc.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/httpc.h"

#include <string.h>

#include "lwip/tcp.h"

#include "rw_log.h"

/*
 * Detach every callback before the pcb is released. A callback firing into a context that has
 * been reused for the next request would deliver one target's bytes into another's buffer,
 * which is the exact bug this function exists to make unwritable.
 */
static void detach(rw_httpc_t *c) {
    if (c->pcb != NULL) {
        tcp_arg(c->pcb, NULL);
        tcp_recv(c->pcb, NULL);
        tcp_err(c->pcb, NULL);
        tcp_sent(c->pcb, NULL);
    }
}

/* End the request. See httpc.h for why the teardown is an abort rather than a close. */
static void finish(rw_httpc_t *c, rw_httpc_state_t state) {
    detach(c);
    if (c->pcb != NULL) {
        tcp_abort(c->pcb);
        c->pcb = NULL;
    }
    c->state = state;
}

static void on_err(void *arg, err_t err) {
    (void)err;
    rw_httpc_t *c = (rw_httpc_t *)arg;
    if (c == NULL) {
        return;
    }
    /* lwIP has already freed the pcb when this fires; touching it again would be a
     * use-after-free, which is why this path does not go through finish(). */
    c->pcb   = NULL;
    c->state = RW_HTTPC_FAILED;
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    rw_httpc_t *c = (rw_httpc_t *)arg;
    if (c == NULL) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    if (p == NULL) {
        /* The peer closed: with `Connection: close` on every request, that IS end-of-response.
         * The buffer now holds everything the peer had to say. */
        finish(c, RW_HTTPC_DONE);
        return ERR_ABRT; /* finish() aborted the pcb */
    }
    if (err != ERR_OK) {
        pbuf_free(p);
        finish(c, RW_HTTPC_FAILED);
        return ERR_ABRT;
    }

    /* -1 keeps the terminator byte rw_shelly_http_split() relies on. */
    const size_t room = (c->resp_cap - 1) - c->resp_len;
    if (p->tot_len > room) {
        /* A response that outgrows the buffer is refused whole, not truncated: a cut-off JSON
         * body parses as garbage, and a peer this talkative is not the device we asked for. */
        pbuf_free(p);
        finish(c, RW_HTTPC_FAILED);
        return ERR_ABRT;
    }
    const u16_t got = pbuf_copy_partial(p, c->resp + c->resp_len, p->tot_len, 0);
    c->resp_len += got;
    c->resp[c->resp_len] = '\0';
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

static err_t on_connected(void *arg, struct tcp_pcb *pcb, err_t err) {
    rw_httpc_t *c = (rw_httpc_t *)arg;
    if (c == NULL) {
        return ERR_OK;
    }
    if (err != ERR_OK) {
        finish(c, RW_HTTPC_FAILED);
        return ERR_ABRT;
    }
    /*
     * The whole request in one write: the longest one shelly.c builds is under 256 bytes,
     * far inside TCP_SND_BUF, so a partial acceptance means the stack is in a state this
     * request will not outlive. No copy — the caller's buffer outlives ACTIVE by contract.
     */
    if (tcp_write(pcb, c->req, (u16_t)c->req_len, 0) != ERR_OK) {
        finish(c, RW_HTTPC_FAILED);
        return ERR_ABRT;
    }
    tcp_output(pcb);
    return ERR_OK;
}

bool rw_httpc_start(rw_httpc_t *c, const ip4_addr_t *ip, uint16_t port, const char *request,
                    size_t req_len, char *resp_buf, size_t resp_cap, uint32_t timeout_ms) {
    if (c->state == RW_HTTPC_ACTIVE || resp_cap < 2 || req_len == 0) {
        return false;
    }
    memset(c, 0, sizeof(*c));
    c->req      = request;
    c->req_len  = req_len;
    c->resp     = resp_buf;
    c->resp_cap = resp_cap;
    c->resp[0]  = '\0';
    c->deadline = make_timeout_time_ms(timeout_ms);

    struct tcp_pcb *pcb = tcp_new();
    if (pcb == NULL) {
        /* Out of pcbs. The pool is 4 with one held by the relay; see rw_httpc_abort's note. */
        c->state = RW_HTTPC_FAILED;
        return false;
    }
    tcp_arg(pcb, c);
    tcp_err(pcb, on_err);
    tcp_recv(pcb, on_recv);
    c->pcb   = pcb;
    c->state = RW_HTTPC_ACTIVE;

    ip_addr_t dst;
    ip_addr_copy_from_ip4(dst, *ip);
    err_t err = tcp_connect(pcb, &dst, port, on_connected);
    if (err != ERR_OK) {
        finish(c, RW_HTTPC_FAILED);
        return false;
    }
    return true;
}

void rw_httpc_poll(rw_httpc_t *c) {
    if (c->state == RW_HTTPC_ACTIVE && time_reached(c->deadline)) {
        finish(c, RW_HTTPC_FAILED);
    }
}

void rw_httpc_abort(rw_httpc_t *c) {
    finish(c, RW_HTTPC_IDLE);
    c->resp_len = 0;
}
