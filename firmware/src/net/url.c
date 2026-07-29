/*
 * WebSocket URL parsing. See url.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/url.h"

#include <string.h>

static bool copy_bounded(char *dst, size_t dst_size, const char *src, size_t len) {
    if (len >= dst_size) {
        return false;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

static bool parse_u16(const char *s, size_t len, uint16_t *out) {
    if (len == 0 || len > 5) {
        return false;
    }
    uint32_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10 + (uint32_t)(s[i] - '0');
        if (v > 65535) {
            return false;
        }
    }
    if (v == 0) {
        return false;
    }
    *out = (uint16_t)v;
    return true;
}

bool rw_url_parse(const char *url, rw_url_t *out) {
    if (url == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    const char *p;
    if (strncmp(url, "wss://", 6) == 0) {
        out->tls  = true;
        out->port = 443;
        p         = url + 6;
    } else if (strncmp(url, "ws://", 5) == 0) {
        out->tls  = false;
        out->port = 80;
        p         = url + 5;
    } else {
        return false;
    }

    /* Authority runs to the first '/', '?' or '#'. */
    const char *auth_end = p;
    while (*auth_end != '\0' && *auth_end != '/' && *auth_end != '?' && *auth_end != '#') {
        auth_end++;
    }
    if (auth_end == p) {
        return false;
    }
    if (memchr(p, '@', (size_t)(auth_end - p)) != NULL) {
        return false; /* userinfo: see url.h */
    }

    const char *host_start = p;
    const char *host_end   = auth_end;

    if (*host_start == '[') {
        /* An IPv6 literal. This firmware is IPv4-only — lwIP is built without IPv6 to save
         * flash and RAM — so accepting the syntax and then failing at connect time would be a
         * worse experience than refusing it here. */
        return false;
    }

    const char *colon = memchr(host_start, ':', (size_t)(host_end - host_start));
    if (colon != NULL) {
        if (!parse_u16(colon + 1, (size_t)(host_end - colon - 1), &out->port)) {
            return false;
        }
        host_end = colon;
    }
    if (host_end == host_start) {
        return false;
    }
    if (!copy_bounded(out->host, sizeof(out->host), host_start, (size_t)(host_end - host_start))) {
        return false;
    }

    /* Everything from the authority onwards is the request target. A fragment is not sent. */
    const char *target = auth_end;
    if (*target == '\0' || *target == '#') {
        out->path[0] = '/';
        out->path[1] = '\0';
        return true;
    }
    const char *target_end = target;
    while (*target_end != '\0' && *target_end != '#') {
        target_end++;
    }
    if (*target == '?') {
        /* "wss://host?x=1" is legal and means path "/" with a query. */
        size_t query_len = (size_t)(target_end - target);
        if (query_len + 1 >= sizeof(out->path)) {
            return false;
        }
        out->path[0] = '/';
        memcpy(out->path + 1, target, query_len);
        out->path[query_len + 1] = '\0';
        return true;
    }
    return copy_bounded(out->path, sizeof(out->path), target, (size_t)(target_end - target));
}

/* Parse a dotted-quad. Returns false for anything that is not exactly four decimal octets, so
 * a hostname never accidentally satisfies the private-address test. */
static bool parse_ipv4(const char *host, uint8_t out[4]) {
    int         octet = 0;
    int         digits = 0;
    unsigned    value = 0;
    const char *p     = host;

    for (;; p++) {
        if (*p >= '0' && *p <= '9') {
            if (++digits > 3) {
                return false;
            }
            value = value * 10 + (unsigned)(*p - '0');
            if (value > 255) {
                return false;
            }
        } else if (*p == '.' || *p == '\0') {
            if (digits == 0 || octet > 3) {
                return false;
            }
            out[octet++] = (uint8_t)value;
            if (*p == '\0') {
                return octet == 4;
            }
            digits = 0;
            value  = 0;
        } else {
            return false;
        }
    }
}

bool rw_url_plaintext_permitted(const char *host) {
    if (host == NULL || host[0] == '\0') {
        return false;
    }
    if (strcmp(host, "localhost") == 0) {
        return true;
    }

    uint8_t ip[4];
    if (!parse_ipv4(host, ip)) {
        return false;
    }

    if (ip[0] == 127) {
        return true; /* 127.0.0.0/8 loopback */
    }
    if (ip[0] == 10) {
        return true; /* 10.0.0.0/8 */
    }
    if (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) {
        return true; /* 172.16.0.0/12 */
    }
    if (ip[0] == 192 && ip[1] == 168) {
        return true; /* 192.168.0.0/16 */
    }
    if (ip[0] == 169 && ip[1] == 254) {
        return true; /* 169.254.0.0/16 link-local, for a device that never got DHCP */
    }
    return false;
}
