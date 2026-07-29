/*
 * The captive-portal HTTP server: raw lwIP TCP, no allocation after start-up.
 *
 * Serves one page and five API routes, and answers every OS connectivity probe with a redirect
 * so the sign-in sheet opens by itself. Request parsing is in http_req.c and host-tested; this
 * file is sockets, routing and response framing.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_HTTPD_H
#define RW_HTTPD_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Concurrent connections.
 *
 * A phone opening the portal takes one, plus a second for whichever connectivity probe fires
 * alongside it. Four leaves room for a second device without letting anything in radio range
 * exhaust our memory by opening sockets — the fifth is refused immediately rather than queued.
 */
#define RW_HTTPD_MAX_CONNS 4

/* A connection that has not completed a request in this long is dropped, so a client that
 * opens a socket and says nothing cannot hold a slot indefinitely. */
#define RW_HTTPD_IDLE_TIMEOUT_MS 10000

/*
 * Start listening on port 80 of every interface the AP has.
 *
 * `server_ip` is host byte order and is used to build the redirect Location, which must be a
 * literal address: a name would need DNS to resolve before the phone could follow it, and at
 * that point in setup the only resolver is us.
 */
bool rw_httpd_start(uint32_t server_ip);

void rw_httpd_stop(void);

#endif /* RW_HTTPD_H */
