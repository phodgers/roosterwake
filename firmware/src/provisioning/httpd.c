/*
 * Captive-portal HTTP server. See httpd.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/httpd.h"

#include <stdio.h>
#include <string.h>

#include "lwip/tcp.h"
#include "pico/time.h"

#include "portal_html.h" /* generated at build time from portal/portal.html */
#include "provisioning/http_req.h"
#include "provisioning/provisioning.h"
#include "rw_log.h"

#define HDR_MAX  256
#define JSON_MAX 1600

typedef struct {
    struct tcp_pcb *pcb;
    bool            in_use;

    char   req[RW_HTTP_REQUEST_MAX];
    size_t req_len;

    char   hdr[HDR_MAX];
    size_t hdr_len;

    /* Either points into flash (the portal blob) or at `json` below. Never allocated. */
    const uint8_t *body;
    size_t         body_len;

    size_t sent;  /* bytes of hdr+body handed to lwIP */
    size_t acked; /* bytes the peer has actually acknowledged */

    char   json[JSON_MAX];
    bool   close_when_sent;
    absolute_time_t deadline;
} conn_t;

static conn_t         s_conns[RW_HTTPD_MAX_CONNS];
static struct tcp_pcb *s_listen;
static uint32_t        s_server_ip;
static char            s_redirect[64];

static conn_t *conn_alloc(void) {
    for (int i = 0; i < RW_HTTPD_MAX_CONNS; i++) {
        if (!s_conns[i].in_use) {
            memset(&s_conns[i], 0, sizeof(s_conns[i]));
            s_conns[i].in_use   = true;
            s_conns[i].deadline = make_timeout_time_ms(RW_HTTPD_IDLE_TIMEOUT_MS);
            return &s_conns[i];
        }
    }
    return NULL;
}

static void conn_close(conn_t *c) {
    if (c == NULL) {
        return;
    }
    if (c->pcb != NULL) {
        tcp_arg(c->pcb, NULL);
        tcp_recv(c->pcb, NULL);
        tcp_sent(c->pcb, NULL);
        tcp_err(c->pcb, NULL);
        tcp_poll(c->pcb, NULL, 0);
        if (tcp_close(c->pcb) != ERR_OK) {
            /* Close can fail when the send buffer is full. Aborting is the honest fallback:
             * leaving a half-closed pcb behind would leak the connection slot. */
            tcp_abort(c->pcb);
        }
        c->pcb = NULL;
    }
    c->in_use = false;
}

/* Push as much of hdr+body as lwIP will take. Called on first response and from tcp_sent. */
static void pump(conn_t *c) {
    if (c->pcb == NULL) {
        return;
    }
    size_t total = c->hdr_len + c->body_len;

    while (c->sent < total) {
        size_t remaining = total - c->sent;
        u16_t  space     = tcp_sndbuf(c->pcb);
        if (space == 0) {
            break; /* tcp_sent will call us again */
        }
        size_t chunk = remaining < space ? remaining : space;

        /*
         * One segment at a time. A single large tcp_write has to be split internally anyway,
         * and asking for it in one call makes the allocation all-or-nothing: either every
         * segment is available or the whole write fails and nothing moves.
         */
        if (chunk > TCP_MSS) {
            chunk = TCP_MSS;
        }

        const void *src;
        if (c->sent < c->hdr_len) {
            size_t hdr_left = c->hdr_len - c->sent;
            if (chunk > hdr_left) {
                chunk = hdr_left;
            }
            src = c->hdr + c->sent;
        } else {
            src = c->body + (c->sent - c->hdr_len);
        }

        /*
         * Always copy, even for the portal blob, which is in flash and immortal and could in
         * principle be referenced directly.
         *
         * Zero-copy was the original design and it does not work here: a no-copy tcp_write
         * needs a PBUF_ROM pbuf per segment from a pool this build cannot satisfy, so the body
         * write failed with ERR_MEM every single time — on a completely drained send buffer,
         * at every chunk size. The header went out, the body never did, and the page hung.
         *
         * The copy it avoids is bounded by TCP_SND_BUF, which is memory lwIP has already
         * reserved. Trading a copy this device can easily afford for a failure mode it cannot
         * was a bad bargain, and it was invisible until a real phone asked for a real page.
         */
        err_t err = tcp_write(c->pcb, src, (u16_t)chunk, TCP_WRITE_FLAG_COPY);
        if (err == ERR_MEM) {
            /* Out of send buffer for now; tcp_sent will call us back. Not an error. */
            break;
        }
        if (err != ERR_OK) {
            conn_close(c);
            return;
        }
        c->sent += chunk;
    }

    tcp_output(c->pcb);

    /*
     * Close on acknowledgement, not on submission.
     *
     * c->sent counts bytes handed to lwIP; c->acked counts bytes the peer confirmed. Closing on
     * the former means calling tcp_close() with the tail of the response still in flight — and
     * conn_close()'s fallback when tcp_close() cannot allocate its FIN is tcp_abort(), which
     * discards exactly that unsent tail and sends an RST instead. The reader gets a truncated
     * page and no error.
     */
    if (c->acked >= total && c->close_when_sent) {
        conn_close(c);
    }
}

static void respond(conn_t *c, const char *status, const char *content_type, const void *body,
                    size_t body_len, const char *extra_headers, bool gzip) {
    c->hdr_len = (size_t)snprintf(
        c->hdr, sizeof(c->hdr),
        "HTTP/1.1 %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %u\r\n"
        "%s"
        "%s"
        /* No caching anywhere. A phone that cached the portal would show a stale page on the
         * next device, and a proxy has no business seeing any of this. */
        "Cache-Control: no-store\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, content_type, (unsigned)body_len, gzip ? "Content-Encoding: gzip\r\n" : "",
        extra_headers ? extra_headers : "");

    if (c->hdr_len >= sizeof(c->hdr)) {
        conn_close(c);
        return;
    }

    c->body            = (const uint8_t *)body;
    c->body_len        = body_len;
    c->sent            = 0;
    c->acked           = 0;
    c->close_when_sent = true;
    pump(c);
}

static void respond_json(conn_t *c, size_t json_len) {
    if (json_len == 0) {
        static const char err[] = "{\"err\":\"internal\"}";
        memcpy(c->json, err, sizeof(err));
        json_len = sizeof(err) - 1;
    }
    respond(c, "200 OK", "application/json", c->json, json_len, NULL, false);
}

/*
 * Everything that is not one of our routes gets a redirect to the portal.
 *
 * This is the whole captive-portal mechanism. Android, iOS, macOS and Windows each fetch a
 * known URL after joining and check for a specific answer; give them anything other than that
 * answer and the OS concludes it is behind a portal and opens this page by itself. A 302 to a
 * literal address works on all of them — a name would need DNS resolved first, and we are the
 * only resolver on this network.
 */
static void respond_redirect(conn_t *c) {
    char extra[96];
    snprintf(extra, sizeof(extra), "Location: %s\r\n", s_redirect);
    respond(c, "302 Found", "text/html", "", 0, extra, false);
}

static void handle_request(conn_t *c, const rw_http_request_t *r, const char *body,
                           size_t body_len) {
    RW_LOG_INFO("http: method=%d path=%s", (int)r->method, r->path);
    /* CORS preflight: the portal is same-origin, but a browser extension or a user driving the
     * API from another page will send one, and a bare 200 is cheaper than a support question. */
    if (r->method == RW_HTTP_OPTIONS) {
        respond(c, "204 No Content", "text/plain", "", 0,
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                "Access-Control-Allow-Headers: content-type\r\n",
                false);
        return;
    }

    if (strcmp(r->path, "/api/info") == 0) {
        respond_json(c, rw_portal_api_info(c->json, sizeof(c->json)));
        return;
    }
    if (strcmp(r->path, "/api/scan") == 0) {
        respond_json(c, rw_portal_api_scan(c->json, sizeof(c->json)));
        return;
    }
    if (strcmp(r->path, "/api/join") == 0) {
        /* POST starts an attempt; GET reports the one in progress. The result is held on the
         * device precisely so a phone that lost the hotspot mid-attempt can come back and ask
         * what happened, rather than the answer dying with the connection. */
        if (r->method == RW_HTTP_GET) {
            respond_json(c, rw_portal_api_join_status(c->json, sizeof(c->json)));
            return;
        }
        if (r->method != RW_HTTP_POST) {
            respond(c, "405 Method Not Allowed", "text/plain", "", 0,
                    "Allow: GET, POST\r\n", false);
            return;
        }
        respond_json(c, rw_portal_api_join_start(body, body_len, c->json, sizeof(c->json)));
        return;
    }
    if (strcmp(r->path, "/api/config") == 0) {
        if (r->method != RW_HTTP_POST) {
            respond(c, "405 Method Not Allowed", "text/plain", "", 0, "Allow: POST\r\n", false);
            return;
        }
        respond_json(c, rw_portal_api_config(body, body_len, c->json, sizeof(c->json)));
        return;
    }
    if (strcmp(r->path, "/api/commit") == 0) {
        if (r->method != RW_HTTP_POST) {
            respond(c, "405 Method Not Allowed", "text/plain", "", 0, "Allow: POST\r\n", false);
            return;
        }
        respond_json(c, rw_portal_api_commit(c->json, sizeof(c->json)));
        return;
    }

    if (strcmp(r->path, "/") == 0 || strcmp(r->path, "/index.html") == 0) {
        if (r->method != RW_HTTP_GET && r->method != RW_HTTP_HEAD) {
            respond(c, "405 Method Not Allowed", "text/plain", "", 0, "Allow: GET\r\n", false);
            return;
        }
        respond(c, "200 OK", "text/html; charset=utf-8", k_portal_html_gz, k_portal_html_gz_len,
                NULL, true);
        return;
    }

    /* Probes and anything else alike: send them to the portal. */
    respond_redirect(c);
}

static err_t on_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err) {
    conn_t *c = (conn_t *)arg;
    if (c == NULL) {
        if (p != NULL) {
            pbuf_free(p);
        }
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    if (err != ERR_OK || p == NULL) {
        conn_close(c); /* peer closed, or an error we cannot recover from */
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }

    tcp_recved(pcb, p->tot_len);
    c->deadline = make_timeout_time_ms(RW_HTTPD_IDLE_TIMEOUT_MS);

    size_t space = sizeof(c->req) - c->req_len;
    size_t take  = p->tot_len < space ? p->tot_len : space;
    if (take > 0) {
        pbuf_copy_partial(p, c->req + c->req_len, (uint16_t)take, 0);
        c->req_len += take;
    }
    bool overflowed = p->tot_len > space;
    pbuf_free(p);

    if (overflowed) {
        respond(c, "413 Payload Too Large", "text/plain", "", 0, NULL, false);
        return ERR_OK;
    }

    rw_http_request_t r;
    switch (rw_http_parse(c->req, c->req_len, &r)) {
        case RW_HTTP_PARSE_INCOMPLETE:
            return ERR_OK; /* wait for more */
        case RW_HTTP_PARSE_BAD:
            respond(c, "400 Bad Request", "text/plain", "", 0, NULL, false);
            return ERR_OK;
        case RW_HTTP_PARSE_TOO_LARGE:
            respond(c, "413 Payload Too Large", "text/plain", "", 0, NULL, false);
            return ERR_OK;
        case RW_HTTP_PARSE_OK:
            break;
    }

    /* The head is complete; wait for the declared body before acting on it. */
    if (c->req_len < r.header_len + r.content_length) {
        return ERR_OK;
    }

    handle_request(c, &r, c->req + r.header_len, r.content_length);
    return ERR_OK;
}

static err_t on_sent(void *arg, struct tcp_pcb *pcb, u16_t len) {
    (void)pcb;
    conn_t *c = (conn_t *)arg;
    if (c != NULL) {
        c->acked += len;
        /* Refreshed on progress, so a transfer that is moving is never dropped by the idle
         * timeout, and one that has genuinely stalled still is. */
        c->deadline = make_timeout_time_ms(RW_HTTPD_IDLE_TIMEOUT_MS);
        pump(c);
    }
    return ERR_OK;
}

static void on_err(void *arg, err_t err) {
    RW_LOG_ERROR("http: tcp err %d", (int)err);
    conn_t *c = (conn_t *)arg;
    if (c != NULL) {
        /* lwIP has already freed the pcb; clearing it stops conn_close touching freed memory. */
        c->pcb = NULL;
        c->in_use = false;
    }
}

static err_t on_poll(void *arg, struct tcp_pcb *pcb) {
    (void)pcb;
    conn_t *c = (conn_t *)arg;
    if (c != NULL && time_reached(c->deadline)) {
        conn_close(c);
    }
    return ERR_OK;
}

static err_t on_accept(void *arg, struct tcp_pcb *pcb, err_t err) {
    (void)arg;
    if (err != ERR_OK || pcb == NULL) {
        return ERR_VAL;
    }

    conn_t *c = conn_alloc();
    if (c == NULL) {
        /* Refuse immediately rather than queueing. A queued connection we cannot service is a
         * phone waiting on a page that will never load. */
        tcp_abort(pcb);
        return ERR_ABRT;
    }

    c->pcb = pcb;
    tcp_arg(pcb, c);
    tcp_recv(pcb, on_recv);
    tcp_sent(pcb, on_sent);
    tcp_err(pcb, on_err);
    tcp_poll(pcb, on_poll, 4); /* ~2 s per tick */
    return ERR_OK;
}

bool rw_httpd_start(uint32_t server_ip) {
    rw_httpd_stop();
    s_server_ip = server_ip;
    snprintf(s_redirect, sizeof(s_redirect), "http://%u.%u.%u.%u/",
             (unsigned)((server_ip >> 24) & 0xFF), (unsigned)((server_ip >> 16) & 0xFF),
             (unsigned)((server_ip >> 8) & 0xFF), (unsigned)(server_ip & 0xFF));

    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (pcb == NULL) {
        return false;
    }
    if (tcp_bind(pcb, IP_ANY_TYPE, 80) != ERR_OK) {
        tcp_close(pcb);
        return false;
    }
    s_listen = tcp_listen_with_backlog(pcb, RW_HTTPD_MAX_CONNS);
    if (s_listen == NULL) {
        tcp_close(pcb);
        return false;
    }
    tcp_accept(s_listen, on_accept);

    RW_LOG_INFO("portal: http on %s (%u bytes gzipped)", s_redirect,
                (unsigned)k_portal_html_gz_len);
    return true;
}

void rw_httpd_stop(void) {
    for (int i = 0; i < RW_HTTPD_MAX_CONNS; i++) {
        if (s_conns[i].in_use) {
            conn_close(&s_conns[i]);
        }
    }
    if (s_listen != NULL) {
        tcp_close(s_listen);
        s_listen = NULL;
    }
}
