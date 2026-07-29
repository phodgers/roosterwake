/*
 * RFC 6455 opening handshake. See ws_handshake.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ws/ws_handshake.h"

#include <stdio.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "mbedtls/sha1.h"

/* RFC 6455 §1.3. Public constant, not a secret. */
static const char k_ws_guid[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

void rw_ws_key_encode(const uint8_t key[RW_WS_KEY_BYTES], char *out) {
    size_t written = 0;
    /* 16 bytes always encode to exactly 24 base64 characters, so the +1 is the NUL mbedTLS
     * writes and the result never needs padding logic of our own. */
    if (mbedtls_base64_encode((unsigned char *)out, RW_WS_KEY_B64_LEN + 1, &written, key,
                              RW_WS_KEY_BYTES) != 0) {
        out[0] = '\0';
        return;
    }
    out[written] = '\0';
}

void rw_ws_compute_accept(const char *key_b64, char *out) {
    unsigned char digest[20];
    unsigned char buf[RW_WS_KEY_B64_LEN + sizeof(k_ws_guid)];

    size_t key_len = strlen(key_b64);
    if (key_len > RW_WS_KEY_B64_LEN) {
        key_len = RW_WS_KEY_B64_LEN;
    }
    memcpy(buf, key_b64, key_len);
    memcpy(buf + key_len, k_ws_guid, sizeof(k_ws_guid) - 1);

    mbedtls_sha1(buf, key_len + sizeof(k_ws_guid) - 1, digest);

    size_t written = 0;
    if (mbedtls_base64_encode((unsigned char *)out, RW_WS_ACCEPT_B64_LEN + 1, &written, digest,
                              sizeof(digest)) != 0) {
        out[0] = '\0';
        return;
    }
    out[written] = '\0';
}

size_t rw_ws_build_request(char *out, size_t out_len, const char *host, uint16_t port, bool tls,
                           const char *path, const char *key_b64, const char *subprotocol) {
    char host_header[RW_WS_RESPONSE_MAX / 4];
    const uint16_t default_port = tls ? 443 : 80;

    if (port == default_port) {
        if ((size_t)snprintf(host_header, sizeof(host_header), "%s", host) >=
            sizeof(host_header)) {
            return 0;
        }
    } else {
        if ((size_t)snprintf(host_header, sizeof(host_header), "%s:%u", host, port) >=
            sizeof(host_header)) {
            return 0;
        }
    }

    /*
     * Connection: Upgrade and Upgrade: websocket are the two headers proxies rewrite most
     * often, and Sec-WebSocket-Version: 13 is the only version that exists. No compression
     * extension is offered: permessage-deflate would need a zlib window per connection, which
     * is the single largest allocation this firmware could make, for frames that are under
     * 300 bytes.
     */
    int n = snprintf(out, out_len,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: %s\r\n"
                     "\r\n",
                     path, host_header, key_b64, subprotocol);
    if (n < 0 || (size_t)n >= out_len) {
        return 0;
    }
    return (size_t)n;
}

/* ── Response parsing ───────────────────────────────────────────────────────
 *
 * Header names are case-insensitive (RFC 7230 §3.2); header *values* here are compared
 * case-sensitively where the RFC gives an exact token (the accept value, the subprotocol) and
 * case-insensitively where it gives a keyword (websocket, Upgrade).
 */

static int ci_char(char c) {
    return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
}

static bool ci_prefix(const char *s, size_t len, const char *prefix) {
    size_t n = strlen(prefix);
    if (len < n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (ci_char(s[i]) != ci_char(prefix[i])) {
            return false;
        }
    }
    return true;
}

static bool ci_contains(const char *s, size_t len, const char *needle) {
    size_t n = strlen(needle);
    if (n == 0 || len < n) {
        return false;
    }
    for (size_t i = 0; i + n <= len; i++) {
        if (ci_prefix(s + i, len - i, needle)) {
            return true;
        }
    }
    return false;
}

/* Trim leading and trailing spaces and tabs from a header value. */
static void trim(const char **start, size_t *len) {
    while (*len > 0 && ((*start)[0] == ' ' || (*start)[0] == '\t')) {
        (*start)++;
        (*len)--;
    }
    while (*len > 0 && ((*start)[*len - 1] == ' ' || (*start)[*len - 1] == '\t')) {
        (*len)--;
    }
}

rw_ws_hs_result_t rw_ws_parse_response(const char *buf, size_t len, const char *expected_accept,
                                       const char *expected_subprotocol, size_t *consumed) {
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i + 4;
            break;
        }
    }
    if (end == NULL) {
        return (len >= RW_WS_RESPONSE_MAX) ? RW_WS_HS_TOO_LARGE : RW_WS_HS_NEED_MORE;
    }

    const size_t header_len = (size_t)(end - buf);
    *consumed               = header_len;

    /* Status line. Anything other than 101 means no upgrade happened; a captive portal
     * typically answers 200 with a login page, and a misrouted proxy answers 404. */
    if (!ci_prefix(buf, header_len, "HTTP/1.1 101") && !ci_prefix(buf, header_len, "HTTP/1.0 101")) {
        return RW_WS_HS_BAD_STATUS;
    }

    bool saw_upgrade    = false;
    bool saw_connection = false;
    bool saw_accept     = false;
    bool saw_protocol   = false;

    const char *line = buf;
    while (line < end) {
        const char *eol = line;
        while (eol + 1 < end && !(eol[0] == '\r' && eol[1] == '\n')) {
            eol++;
        }
        size_t line_len = (size_t)(eol - line);
        if (line_len == 0) {
            break; /* the blank line that terminates the header block */
        }

        const char *colon = memchr(line, ':', line_len);
        if (colon != NULL) {
            const char *name     = line;
            size_t      name_len = (size_t)(colon - line);
            const char *value    = colon + 1;
            size_t      value_len = line_len - name_len - 1;
            trim(&value, &value_len);

            if (name_len == 7 && ci_prefix(name, name_len, "upgrade")) {
                saw_upgrade = ci_contains(value, value_len, "websocket");
            } else if (name_len == 10 && ci_prefix(name, name_len, "connection")) {
                saw_connection = ci_contains(value, value_len, "upgrade");
            } else if (name_len == 20 && ci_prefix(name, name_len, "sec-websocket-accept")) {
                size_t expect_len = strlen(expected_accept);
                saw_accept = (value_len == expect_len) &&
                             (memcmp(value, expected_accept, expect_len) == 0);
            } else if (name_len == 22 && ci_prefix(name, name_len, "sec-websocket-protocol")) {
                size_t expect_len = strlen(expected_subprotocol);
                saw_protocol = (value_len == expect_len) &&
                               (memcmp(value, expected_subprotocol, expect_len) == 0);
            }
        }

        line = eol + 2;
    }

    if (!saw_upgrade || !saw_connection) {
        return RW_WS_HS_BAD_UPGRADE;
    }
    if (!saw_accept) {
        return RW_WS_HS_BAD_ACCEPT;
    }
    if (!saw_protocol) {
        return RW_WS_HS_NO_SUBPROTOCOL;
    }
    return RW_WS_HS_OK;
}
