/*
 * RFC 6455 frame codec.
 *
 * Host-portable: no lwIP, no SDK, no allocation. Everything about framing that can be got
 * wrong lives here so it can be got wrong in a test instead of on a shelf behind a router.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WS_FRAME_H
#define RW_WS_FRAME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * PROTOCOL.md §1: no frame in either direction may exceed 2048 bytes, and a receiver MUST
 * reject a larger one with close code 1009. The bound is symmetric so both sides can size one
 * buffer; the largest frame this firmware constructs is `scan_result`, which drops hosts to
 * stay inside it rather than growing past it.
 */
#define RW_WS_MAX_INBOUND  2048
#define RW_WS_MAX_OUTBOUND 2048

/* Longest header this codec emits: 2 bytes + 8-byte length + 4-byte mask. */
#define RW_WS_MAX_HEADER 14

typedef enum {
    RW_WS_OP_CONT   = 0x0,
    RW_WS_OP_TEXT   = 0x1,
    RW_WS_OP_BINARY = 0x2,
    RW_WS_OP_CLOSE  = 0x8,
    RW_WS_OP_PING   = 0x9,
    RW_WS_OP_PONG   = 0xA,
} rw_ws_opcode_t;

/* Close codes used by this firmware (PROTOCOL.md §7). */
#define RW_WS_CLOSE_NORMAL       1000
#define RW_WS_CLOSE_PROTOCOL_ERR 1002
#define RW_WS_CLOSE_POLICY       1008
#define RW_WS_CLOSE_TOO_BIG      1009
#define RW_WS_CLOSE_INTERNAL      1011
#define RW_WS_CLOSE_DEPROVISIONED 4002
/* PROTOCOL.md §7: "you went quiet", which must stay distinguishable from 1008. Reusing 1008
 * would corrupt the §8 rule that backoff resets only after authentication completes. */
#define RW_WS_CLOSE_IDLE_TIMEOUT  4003

typedef struct {
    bool     fin;
    uint8_t  opcode;
    bool     masked;
    uint64_t payload_len;
    uint8_t  mask[4];
    size_t   header_len; /* bytes consumed by the header, including any mask */
} rw_ws_header_t;

typedef enum {
    RW_WS_PARSE_OK = 0,
    RW_WS_PARSE_NEED_MORE, /* not enough bytes for a complete header yet */
    RW_WS_PARSE_ERROR,     /* protocol violation; close 1002 */
    RW_WS_PARSE_TOO_LARGE, /* payload exceeds RW_WS_MAX_INBOUND; close 1009 */
} rw_ws_parse_t;

/*
 * Parse a frame header from `buf`.
 *
 * Enforces, as errors rather than as tolerances:
 *   - RSV1..3 clear. No extension was negotiated, so a set reserved bit means the peer is
 *     speaking something this client does not understand.
 *   - Server-to-client frames unmasked (RFC 6455 §5.1).
 *   - Minimal length encoding. A 5-byte payload announced with a 64-bit length is legal-looking
 *     and forbidden, and tolerating it hides a broken sender until it breaks something else.
 *   - Control frames carry at most 125 bytes and are never fragmented.
 */
rw_ws_parse_t rw_ws_parse_header(const uint8_t *buf, size_t len, rw_ws_header_t *out);

/*
 * Write a client frame header. `mask` is mandatory and must never be NULL: RFC 6455 §5.3
 * requires every client-to-server frame to be masked, and a conforming server closes the
 * connection on an unmasked one.
 *
 * Returns the number of bytes written, or 0 if `out` is too small.
 */
size_t rw_ws_encode_header(uint8_t *out, size_t out_len, bool fin, uint8_t opcode,
                           size_t payload_len, const uint8_t mask[4]);

/*
 * XOR `len` bytes of payload with the frame mask. `offset` is the byte position of `data`
 * within the frame payload, so a payload written in pieces masks identically to one written
 * in a single call.
 */
void rw_ws_apply_mask(uint8_t *data, size_t len, const uint8_t mask[4], size_t offset);

/* Build a complete masked frame (header + masked payload). Returns total bytes, or 0. */
size_t rw_ws_build_frame(uint8_t *out, size_t out_len, bool fin, uint8_t opcode,
                         const uint8_t *payload, size_t payload_len, const uint8_t mask[4]);

/*
 * Build a masked close frame carrying `code` and an optional UTF-8 reason.
 *
 * The reason is truncated so that the control frame stays within its 125-byte limit rather
 * than being rejected by the peer, because a close frame the peer discards leaves the socket
 * to time out instead of shutting down cleanly.
 */
size_t rw_ws_build_close(uint8_t *out, size_t out_len, uint16_t code, const char *reason,
                         const uint8_t mask[4]);

#endif /* RW_WS_FRAME_H */
