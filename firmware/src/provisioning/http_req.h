/*
 * HTTP/1.1 request parsing for the captive-portal server — the pure half.
 *
 * Only what a provisioning portal needs: the request line, Content-Length, and where the body
 * starts. No chunked encoding, no keep-alive negotiation, no header table. What is here is
 * bounds-checked to the byte, because it parses unauthenticated input from anything that can
 * associate with an open hotspot.
 *
 * No lwIP and no SDK, so it compiles into the host test binary.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_HTTP_REQ_H
#define RW_HTTP_REQ_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* A portal request is a short GET or a small JSON POST. Anything larger is refused with 413
 * rather than buffered, which caps what one client can make us hold. */
#define RW_HTTP_PATH_MAX    128
#define RW_HTTP_BODY_MAX    512
#define RW_HTTP_HEADERS_MAX 1024
#define RW_HTTP_REQUEST_MAX (RW_HTTP_HEADERS_MAX + RW_HTTP_BODY_MAX)

typedef enum {
    RW_HTTP_METHOD_UNKNOWN = 0,
    RW_HTTP_GET,
    RW_HTTP_POST,
    RW_HTTP_HEAD,
    RW_HTTP_OPTIONS,
} rw_http_method_t;

typedef enum {
    RW_HTTP_PARSE_OK = 0,
    RW_HTTP_PARSE_INCOMPLETE, /* headers not terminated yet; read more */
    RW_HTTP_PARSE_BAD,        /* malformed: answer 400 and close */
    RW_HTTP_PARSE_TOO_LARGE,  /* answer 413 and close */
} rw_http_parse_t;

typedef struct {
    rw_http_method_t method;
    /* Path with the query string removed and percent-escapes resolved. Always starts with '/'. */
    char             path[RW_HTTP_PATH_MAX];
    size_t           header_len;     /* bytes up to and including the blank line */
    size_t           content_length; /* declared by the header, 0 if absent */
    bool             expects_continue; /* client sent Expect: 100-continue */
} rw_http_request_t;

/*
 * Parse the request head.
 *
 * Returns RW_HTTP_PARSE_INCOMPLETE until the terminating blank line has arrived, so a caller
 * can feed it a growing buffer. `content_length` is then valid and the caller knows how many
 * more bytes to wait for.
 *
 * A request whose head exceeds RW_HTTP_HEADERS_MAX, or whose Content-Length exceeds
 * RW_HTTP_BODY_MAX, is TOO_LARGE — refused rather than truncated, because a truncated JSON body
 * would be answered with a confusing parse error instead of an honest one.
 */
rw_http_parse_t rw_http_parse(const char *buf, size_t len, rw_http_request_t *out);

/*
 * Percent-decode `in` into `out`, rejecting rather than repairing.
 *
 * Returns false on a truncated or non-hex escape, on a NUL introduced by %00, or if the result
 * does not fit. `+` is left alone: this decodes paths, not form bodies, and silently turning a
 * plus into a space inside an SSID would be its own small disaster.
 */
bool rw_http_percent_decode(const char *in, size_t in_len, char *out, size_t out_len);

/*
 * True when `path` is one of the OS connectivity-check URLs.
 *
 * Android hits /generate_204 and expects 204; iOS and macOS hit /hotspot-detect.html and expect
 * a body containing "Success"; Windows hits /connecttest.txt and /ncsi.txt and expects
 * "Microsoft Connect Test" or "Microsoft NCSI". Giving any of them the answer it wants means
 * the OS concludes the network is fine and never offers to open the portal. Answering with a
 * redirect instead is what makes the sign-in sheet appear by itself.
 */
bool rw_http_is_captive_probe(const char *path);

#endif /* RW_HTTP_REQ_H */
