/*
 * RFC 6455 opening handshake: request construction and response validation.
 *
 * Host-portable. Split from the connection state machine because this is where a device finds
 * out whether it is talking to a relay or to a hotel captive portal, and that decision is
 * worth testing without hardware.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WS_HANDSHAKE_H
#define RW_WS_HANDSHAKE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RW_WS_KEY_BYTES      16
#define RW_WS_KEY_B64_LEN    24 /* base64 of 16 bytes */
#define RW_WS_ACCEPT_B64_LEN 28 /* base64 of the 20-byte SHA-1 */

/* An upgrade response with more header bytes than this is not a relay's. Bounded because the
 * buffer holding it is statically allocated. */
#define RW_WS_RESPONSE_MAX 1024

typedef enum {
    RW_WS_HS_NEED_MORE = 0,   /* headers are not complete yet */
    RW_WS_HS_OK,
    RW_WS_HS_BAD_STATUS,      /* anything but 101 */
    RW_WS_HS_BAD_UPGRADE,     /* Upgrade/Connection headers missing or wrong */
    RW_WS_HS_BAD_ACCEPT,      /* Sec-WebSocket-Accept absent or does not match */
    RW_WS_HS_NO_SUBPROTOCOL,  /* the relay did not echo remotewake.v1 */
    RW_WS_HS_TOO_LARGE,       /* headers exceeded RW_WS_RESPONSE_MAX */
} rw_ws_hs_result_t;

/* base64 of the 16 random key bytes. `out` needs RW_WS_KEY_B64_LEN + 1. */
void rw_ws_key_encode(const uint8_t key[RW_WS_KEY_BYTES], char *out);

/*
 * The RFC 6455 §4.1 accept value: base64(SHA-1(key_b64 + GUID)).
 *
 * Verifying it is not a security control — the GUID is public — it is a proof that the peer
 * parsed the handshake rather than blindly returning 101, which is exactly what a badly
 * written reverse proxy does. `out` needs RW_WS_ACCEPT_B64_LEN + 1.
 */
void rw_ws_compute_accept(const char *key_b64, char *out);

/*
 * Build the upgrade request. Returns bytes written, or 0 if `out` is too small.
 *
 * The Host header carries the port only when it is not the scheme default, because a relay
 * behind virtual hosting matches on the header verbatim.
 */
size_t rw_ws_build_request(char *out, size_t out_len, const char *host, uint16_t port, bool tls,
                           const char *path, const char *key_b64, const char *subprotocol);

/*
 * Validate a response.
 *
 * Returns RW_WS_HS_NEED_MORE until the header block is complete. On RW_WS_HS_OK, `*consumed`
 * is set to the number of bytes the header block occupied, so the caller can hand whatever
 * follows straight to the frame parser — a relay is entitled to put the first frame in the
 * same TCP segment as the response.
 *
 * A missing Sec-WebSocket-Protocol is a hard failure (PROTOCOL.md §1). That is how a device
 * detects it has been pointed at something that is not a Remote Wake relay, and the
 * alternative — connecting anyway and waiting for a `challenge` that never arrives — is how a
 * device on a hotel network sits there blinking for an hour.
 */
rw_ws_hs_result_t rw_ws_parse_response(const char *buf, size_t len, const char *expected_accept,
                                       const char *expected_subprotocol, size_t *consumed);

#endif /* RW_WS_HANDSHAKE_H */
