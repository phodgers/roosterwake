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
    /*
     * Whether the client advertised gzip.
     *
     * Load-bearing, not a nicety. The portal is stored gzipped and was being served with
     * Content-Encoding: gzip to everyone, which is a protocol violation — a content-coding may
     * only be applied if the client asked for it. Browsers always ask, so it looked fine. The
     * captive-portal probe clients do not: Apple's CaptiveNetworkSupport sent no Accept-Encoding
     * and got a compressed body it could not decode, so it concluded the network was broken
     * rather than captive, and the sign-in sheet never opened.
     */
    bool             accepts_gzip;
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
 * How a given path should be answered so the OS opens its sign-in sheet.
 *
 * Each OS fetches a known URL after joining and checks for a specific answer: Android wants a
 * 204 from /generate_204, Apple wants a body containing "Success", Windows wants "Microsoft
 * NCSI". Give any of them what it expects and it decides the network is fine and never mentions
 * the portal. Give it something else and it offers to sign in.
 *
 * The *shape* of "something else" matters, and differs:
 *
 *  - Apple's Captive Network Assistant is most reliable when the probe itself returns 200 with
 *    a body that is not "Success". Handed a redirect it has to fetch the target and then judge
 *    that, and the extra round trip is a race it sometimes loses — which shows up as a portal
 *    that opens on the second join but not the first.
 *  - Android and Windows follow a redirect happily and treat it as the definitive portal
 *    signal, so they get the 302.
 */
typedef enum {
    RW_PROBE_NONE = 0,  /* not a probe URL */
    RW_PROBE_REDIRECT,  /* answer 302 to the portal */
    RW_PROBE_INLINE,    /* answer 200 with the portal page itself */
} rw_http_probe_t;

rw_http_probe_t rw_http_probe_kind(const char *path);

/* True for any probe URL, whatever its kind. */
bool rw_http_is_captive_probe(const char *path);

#endif /* RW_HTTP_REQ_H */
