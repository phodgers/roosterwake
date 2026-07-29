/*
 * HTTP request parsing for the captive portal. See http_req.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/http_req.h"

#include <string.h>

static char lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c;
}

/* Case-insensitive prefix match, for header names. */
static bool starts_with_ci(const char *s, size_t s_len, const char *prefix) {
    size_t n = strlen(prefix);
    if (s_len < n) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (lower(s[i]) != lower(prefix[i])) {
            return false;
        }
    }
    return true;
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool rw_http_percent_decode(const char *in, size_t in_len, char *out, size_t out_len) {
    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '%') {
            if (i + 2 >= in_len) {
                return false; /* truncated escape */
            }
            int hi = hex_val(in[i + 1]);
            int lo = hex_val(in[i + 2]);
            if (hi < 0 || lo < 0) {
                return false;
            }
            c = (char)((hi << 4) | lo);
            if (c == '\0') {
                /* %00 would truncate the path against every downstream strcmp while leaving
                 * bytes after it. Refuse the request rather than silently shorten it. */
                return false;
            }
            i += 2;
        }
        if (o + 1 >= out_len) {
            return false;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return true;
}

static rw_http_method_t method_of(const char *s, size_t len) {
    if (len == 3 && memcmp(s, "GET", 3) == 0) return RW_HTTP_GET;
    if (len == 4 && memcmp(s, "POST", 4) == 0) return RW_HTTP_POST;
    if (len == 4 && memcmp(s, "HEAD", 4) == 0) return RW_HTTP_HEAD;
    if (len == 7 && memcmp(s, "OPTIONS", 7) == 0) return RW_HTTP_OPTIONS;
    return RW_HTTP_METHOD_UNKNOWN;
}

/* Parse a decimal Content-Length, refusing anything that is not purely digits. A value with a
 * sign, spaces or a second number is a request-smuggling shape, not a typo. */
static bool parse_length(const char *s, size_t len, size_t *out) {
    if (len == 0 || len > 9) {
        return false;
    }
    size_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        v = v * 10 + (size_t)(s[i] - '0');
    }
    *out = v;
    return true;
}

rw_http_parse_t rw_http_parse(const char *buf, size_t len, rw_http_request_t *out) {
    if (buf == NULL || out == NULL) {
        return RW_HTTP_PARSE_BAD;
    }

    /* Find the blank line that ends the head. */
    const char *end = NULL;
    for (size_t i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            end = buf + i + 4;
            break;
        }
    }
    if (end == NULL) {
        /* Not there yet. Cap how long we are willing to wait for it, so a client that opens a
         * socket and dribbles header bytes cannot hold a connection slot indefinitely. */
        return (len >= RW_HTTP_HEADERS_MAX) ? RW_HTTP_PARSE_TOO_LARGE : RW_HTTP_PARSE_INCOMPLETE;
    }

    memset(out, 0, sizeof(*out));
    out->header_len = (size_t)(end - buf);

    /* ── Request line ───────────────────────────────────────────────────── */

    const char *line_end = memchr(buf, '\r', out->header_len);
    if (line_end == NULL) {
        return RW_HTTP_PARSE_BAD;
    }
    size_t line_len = (size_t)(line_end - buf);

    const char *sp1 = memchr(buf, ' ', line_len);
    if (sp1 == NULL) {
        return RW_HTTP_PARSE_BAD;
    }
    out->method = method_of(buf, (size_t)(sp1 - buf));

    const char *target = sp1 + 1;
    size_t      rest   = line_len - (size_t)(target - buf);
    const char *sp2    = memchr(target, ' ', rest);
    if (sp2 == NULL) {
        return RW_HTTP_PARSE_BAD; /* HTTP/0.9 style; not something a browser sends */
    }
    size_t target_len = (size_t)(sp2 - target);
    if (target_len == 0 || target[0] != '/') {
        /* Absolute-form targets (`GET http://host/path`) are legal for proxies and meaningless
         * here. A portal that accepted them would be an open redirector on someone's LAN. */
        return RW_HTTP_PARSE_BAD;
    }

    /* Drop the query string: no portal route reads one, and keeping it would mean every route
     * comparison had to remember to strip it. */
    const char *q = memchr(target, '?', target_len);
    if (q != NULL) {
        target_len = (size_t)(q - target);
    }
    if (target_len >= RW_HTTP_PATH_MAX) {
        return RW_HTTP_PARSE_TOO_LARGE;
    }
    if (!rw_http_percent_decode(target, target_len, out->path, sizeof(out->path))) {
        return RW_HTTP_PARSE_BAD;
    }

    /* ── Headers ────────────────────────────────────────────────────────── */

    const char *p = line_end + 2;
    while (p < end - 2) {
        const char *eol = memchr(p, '\r', (size_t)(end - p));
        if (eol == NULL) {
            break;
        }
        size_t hl = (size_t)(eol - p);

        if (starts_with_ci(p, hl, "content-length:")) {
            const char *v   = p + strlen("content-length:");
            size_t      vl  = hl - strlen("content-length:");
            while (vl > 0 && (*v == ' ' || *v == '\t')) { v++; vl--; }
            while (vl > 0 && (v[vl - 1] == ' ' || v[vl - 1] == '\t')) { vl--; }
            if (!parse_length(v, vl, &out->content_length)) {
                return RW_HTTP_PARSE_BAD;
            }
            if (out->content_length > RW_HTTP_BODY_MAX) {
                return RW_HTTP_PARSE_TOO_LARGE;
            }
        } else if (starts_with_ci(p, hl, "transfer-encoding:")) {
            /* Chunked bodies are not supported, and a request carrying both Transfer-Encoding
             * and Content-Length is the classic smuggling primitive. Refuse outright. */
            return RW_HTTP_PARSE_BAD;
        } else if (starts_with_ci(p, hl, "expect:")) {
            out->expects_continue = true;
        }

        p = eol + 2;
    }

    return RW_HTTP_PARSE_OK;
}

bool rw_http_is_captive_probe(const char *path) {
    static const char *const k_probes[] = {
        "/generate_204",            /* Android */
        "/gen_204",                 /* Android, older */
        "/hotspot-detect.html",     /* iOS, macOS */
        "/library/test/success.html", /* macOS */
        "/success.txt",             /* Firefox */
        "/canonical.html",          /* Ubuntu / NetworkManager */
        "/connecttest.txt",         /* Windows */
        "/ncsi.txt",                /* Windows, older */
        "/redirect",                /* Windows follows this after connecttest */
    };
    for (size_t i = 0; i < sizeof(k_probes) / sizeof(k_probes[0]); i++) {
        if (strcmp(path, k_probes[i]) == 0) {
            return true;
        }
    }
    return false;
}
