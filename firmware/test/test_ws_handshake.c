/*
 * The RFC 6455 opening handshake, including the subprotocol check that PROTOCOL.md §1 makes
 * the device's defence against being pointed at a captive portal.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "brand.h"
#include "rw_test.h"
#include "ws/ws_handshake.h"

static void test_key_and_accept(void) {
    rw_test_begin("key encoding and accept computation");

    /* RFC 6455 §1.3's worked example. */
    const uint8_t key[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    char          b64[RW_WS_KEY_B64_LEN + 1];
    rw_ws_key_encode(key, b64);
    RW_CHECK_EQ_STR(b64, "AQIDBAUGBwgJCgsMDQ4PEA==");
    RW_CHECK_EQ_INT(strlen(b64), RW_WS_KEY_B64_LEN);

    char accept[RW_WS_ACCEPT_B64_LEN + 1];
    rw_ws_compute_accept("dGhlIHNhbXBsZSBub25jZQ==", accept);
    RW_CHECK_EQ_STR(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    RW_CHECK_EQ_INT(strlen(accept), RW_WS_ACCEPT_B64_LEN);

    /* A different key must produce a different accept, or the check proves nothing. */
    char other[RW_WS_ACCEPT_B64_LEN + 1];
    rw_ws_compute_accept(b64, other);
    RW_CHECK_MSG(strcmp(accept, other) != 0, "the accept value does not depend on the key");
}

static void test_request(void) {
    rw_test_begin("upgrade request");

    char   out[512];
    size_t n = rw_ws_build_request(out, sizeof(out), "relay.roosterwake.com", 443, true, "/ws",
                                   "dGhlIHNhbXBsZSBub25jZQ==", RW_WS_SUBPROTOCOL);
    RW_CHECK(n > 0);
    RW_CHECK_EQ_INT(strlen(out), n);

    RW_CHECK(strstr(out, "GET /ws HTTP/1.1\r\n") == out);
    /* The default port is omitted: a relay behind virtual hosting matches the header verbatim,
     * and "host:443" is not the same string as "host". */
    RW_CHECK_MSG(strstr(out, "Host: relay.roosterwake.com\r\n") != NULL, "Host header wrong");
    RW_CHECK(strstr(out, "Upgrade: websocket\r\n") != NULL);
    RW_CHECK(strstr(out, "Connection: Upgrade\r\n") != NULL);
    RW_CHECK(strstr(out, "Sec-WebSocket-Version: 13\r\n") != NULL);
    RW_CHECK(strstr(out, "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") != NULL);
    RW_CHECK(strstr(out, "Sec-WebSocket-Protocol: roosterwake.v1\r\n") != NULL);
    RW_CHECK_MSG(strstr(out, "\r\n\r\n") != NULL, "request is not terminated");

    /* A non-default port is carried. */
    n = rw_ws_build_request(out, sizeof(out), "192.168.1.10", 8080, false, "/ws", "k",
                            RW_WS_SUBPROTOCOL);
    RW_CHECK(n > 0);
    RW_CHECK_MSG(strstr(out, "Host: 192.168.1.10:8080\r\n") != NULL, "port not in Host header");

    /* ws:// on port 80 is the default for its scheme. */
    n = rw_ws_build_request(out, sizeof(out), "10.0.0.5", 80, false, "/ws", "k",
                            RW_WS_SUBPROTOCOL);
    RW_CHECK(strstr(out, "Host: 10.0.0.5\r\n") != NULL);

    /* Refused rather than truncated when it does not fit. */
    RW_CHECK_EQ_INT(rw_ws_build_request(out, 32, "relay.roosterwake.com", 443, true, "/ws", "k",
                                        RW_WS_SUBPROTOCOL),
                    0);
}

static const char *k_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

static rw_ws_hs_result_t parse(const char *response, size_t *consumed) {
    return rw_ws_parse_response(response, strlen(response), k_accept, RW_WS_SUBPROTOCOL,
                                consumed);
}

static void test_response(void) {
    rw_test_begin("upgrade response");

    size_t consumed = 0;

    const char *good = "HTTP/1.1 101 Switching Protocols\r\n"
                       "Upgrade: websocket\r\n"
                       "Connection: Upgrade\r\n"
                       "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                       "Sec-WebSocket-Protocol: roosterwake.v1\r\n"
                       "\r\n";
    RW_CHECK_EQ_INT(parse(good, &consumed), RW_WS_HS_OK);
    RW_CHECK_EQ_INT(consumed, strlen(good));

    /* A relay is entitled to put its first frame in the same segment; `consumed` must stop at
     * the header block so the frame parser sees the rest. */
    char with_frame[512];
    snprintf(with_frame, sizeof(with_frame), "%s\x81\x05Hello", good);
    RW_CHECK_EQ_INT(rw_ws_parse_response(with_frame, strlen(good) + 7, k_accept,
                                         RW_WS_SUBPROTOCOL, &consumed),
                    RW_WS_HS_OK);
    RW_CHECK_EQ_INT(consumed, strlen(good));

    /* Header names are case-insensitive; the accept value is not. */
    const char *mixed_case = "HTTP/1.1 101 Switching Protocols\r\n"
                             "upgrade: WebSocket\r\n"
                             "CONNECTION: keep-alive, Upgrade\r\n"
                             "sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                             "Sec-WebSocket-Protocol: roosterwake.v1\r\n"
                             "\r\n";
    RW_CHECK_EQ_INT(parse(mixed_case, &consumed), RW_WS_HS_OK);

    /* Incomplete headers ask for more. */
    RW_CHECK_EQ_INT(rw_ws_parse_response(good, 20, k_accept, RW_WS_SUBPROTOCOL, &consumed),
                    RW_WS_HS_NEED_MORE);

    /* A captive portal: 200 with a login page. */
    const char *portal = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/html\r\n"
                         "\r\n";
    RW_CHECK_EQ_INT(parse(portal, &consumed), RW_WS_HS_BAD_STATUS);

    /* A redirect to a login page, which is the other half of the same failure. */
    const char *redirect = "HTTP/1.1 302 Found\r\n"
                           "Location: http://hotel.example/login\r\n"
                           "\r\n";
    RW_CHECK_EQ_INT(parse(redirect, &consumed), RW_WS_HS_BAD_STATUS);

    /* 101 without the upgrade headers: a proxy that answered without understanding. */
    const char *no_upgrade = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                             "\r\n";
    RW_CHECK_EQ_INT(parse(no_upgrade, &consumed), RW_WS_HS_BAD_UPGRADE);

    /* A wrong or missing accept value. */
    const char *bad_accept = "HTTP/1.1 101 Switching Protocols\r\n"
                             "Upgrade: websocket\r\n"
                             "Connection: Upgrade\r\n"
                             "Sec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n"
                             "Sec-WebSocket-Protocol: roosterwake.v1\r\n"
                             "\r\n";
    RW_CHECK_EQ_INT(parse(bad_accept, &consumed), RW_WS_HS_BAD_ACCEPT);

    const char *no_accept = "HTTP/1.1 101 Switching Protocols\r\n"
                            "Upgrade: websocket\r\n"
                            "Connection: Upgrade\r\n"
                            "Sec-WebSocket-Protocol: roosterwake.v1\r\n"
                            "\r\n";
    RW_CHECK_EQ_INT(parse(no_accept, &consumed), RW_WS_HS_BAD_ACCEPT);

    /*
     * The case PROTOCOL.md §1 exists for: a perfectly good WebSocket endpoint that is not a
     * Rooster Wake relay. Somebody's Home Assistant, a misconfigured reverse proxy. The device
     * must close rather than wait for a `challenge` that will never arrive.
     */
    const char *no_subprotocol = "HTTP/1.1 101 Switching Protocols\r\n"
                                 "Upgrade: websocket\r\n"
                                 "Connection: Upgrade\r\n"
                                 "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                 "\r\n";
    RW_CHECK_EQ_INT(parse(no_subprotocol, &consumed), RW_WS_HS_NO_SUBPROTOCOL);

    /* A different subprotocol is just as wrong as none. */
    const char *wrong_subprotocol = "HTTP/1.1 101 Switching Protocols\r\n"
                                    "Upgrade: websocket\r\n"
                                    "Connection: Upgrade\r\n"
                                    "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                    "Sec-WebSocket-Protocol: chat\r\n"
                                    "\r\n";
    RW_CHECK_EQ_INT(parse(wrong_subprotocol, &consumed), RW_WS_HS_NO_SUBPROTOCOL);

    /* A version prefix of ours must not be accepted as ours. */
    const char *prefix_subprotocol = "HTTP/1.1 101 Switching Protocols\r\n"
                                     "Upgrade: websocket\r\n"
                                     "Connection: Upgrade\r\n"
                                     "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
                                     "Sec-WebSocket-Protocol: roosterwake.v12\r\n"
                                     "\r\n";
    RW_CHECK_EQ_INT(parse(prefix_subprotocol, &consumed), RW_WS_HS_NO_SUBPROTOCOL);

    /* Headers larger than the buffer are rejected instead of accumulating. */
    char big[RW_WS_RESPONSE_MAX + 64];
    memset(big, 'A', sizeof(big));
    RW_CHECK_EQ_INT(rw_ws_parse_response(big, sizeof(big), k_accept, RW_WS_SUBPROTOCOL,
                                         &consumed),
                    RW_WS_HS_TOO_LARGE);
}

void test_ws_handshake(void) {
    test_key_and_accept();
    test_request();
    test_response();
}
