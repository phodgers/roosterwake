/*
 * WebSocket URL parsing and the plaintext-relay policy.
 *
 * Host-portable: no SDK, no lwIP. The policy in rw_url_plaintext_permitted() is a security
 * decision (PROTOCOL.md §1, usbcfg.md §4) and belongs somewhere it can be read and tested
 * without a device.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_URL_H
#define RW_URL_H

#include <stdbool.h>
#include <stdint.h>

#define RW_URL_HOST_MAX 128
#define RW_URL_PATH_MAX 128

typedef struct {
    bool     tls;                    /* true for wss://, false for ws:// */
    char     host[RW_URL_HOST_MAX];  /* hostname or IPv4 literal, no brackets, no port */
    uint16_t port;                   /* explicit, or 443 for wss and 80 for ws */
    char     path[RW_URL_PATH_MAX];  /* request target, always starts with '/' */
} rw_url_t;

/*
 * Parse a ws:// or wss:// URL. Returns false on anything malformed, on an unknown scheme, or
 * on a host or path that does not fit.
 *
 * userinfo (`ws://user:pass@host/`) is rejected rather than ignored. It has no meaning in this
 * protocol, and silently discarding credentials somebody typed is worse than telling them the
 * URL is wrong.
 */
bool rw_url_parse(const char *url, rw_url_t *out);

/*
 * Whether plaintext ws:// is permitted for this host.
 *
 * True only for loopback and RFC 1918 / RFC 3927 literals. A plaintext relay URL pointing at
 * the public internet would put the device's challenge-response traffic — and, on a relay that
 * asked for it, anything else — in the clear across the internet, so it is refused at the
 * point of configuration rather than at the point of connection.
 *
 * A *hostname* that resolves to a private address is still refused: the check happens before
 * DNS, and a name is not evidence of where it points.
 */
bool rw_url_plaintext_permitted(const char *host);

#endif /* RW_URL_H */
