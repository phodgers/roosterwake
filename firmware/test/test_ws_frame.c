/*
 * RFC 6455 frame codec: masking, the three length encodings, fragmentation, and the 2048-byte
 * cap that PROTOCOL.md §1 makes a hard part of the contract.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "rw_test.h"
#include "ws/ws_frame.h"

static const uint8_t k_mask[4] = {0x37, 0xFA, 0x21, 0x3D};

static void test_masking(void) {
    rw_test_begin("masking");

    /* RFC 6455 §5.7's own example: a masked "Hello" with this key is the canonical vector. */
    uint8_t payload[5] = {'H', 'e', 'l', 'l', 'o'};
    rw_ws_apply_mask(payload, sizeof(payload), k_mask, 0);

    const uint8_t expected[5] = {0x7F, 0x9F, 0x4D, 0x51, 0x58};
    RW_CHECK_EQ_MEM(payload, expected, sizeof(expected));

    /* Masking is its own inverse. */
    rw_ws_apply_mask(payload, sizeof(payload), k_mask, 0);
    RW_CHECK_EQ_MEM(payload, "Hello", 5);

    /* A payload masked in pieces must come out identical to one masked in a single call, or a
     * frame written across two TCP segments decodes to noise. */
    uint8_t whole[16], split[16];
    for (int i = 0; i < 16; i++) {
        whole[i] = split[i] = (uint8_t)(i * 7 + 3);
    }
    rw_ws_apply_mask(whole, 16, k_mask, 0);
    rw_ws_apply_mask(split, 5, k_mask, 0);
    rw_ws_apply_mask(split + 5, 3, k_mask, 5);
    rw_ws_apply_mask(split + 8, 8, k_mask, 8);
    RW_CHECK_EQ_MEM(split, whole, 16);
}

static void test_length_encodings(void) {
    rw_test_begin("length encodings");

    uint8_t frame[RW_WS_MAX_HEADER + RW_WS_MAX_INBOUND];
    uint8_t payload[RW_WS_MAX_INBOUND];
    memset(payload, 'x', sizeof(payload));

    /* 7-bit: 2-byte header plus a 4-byte mask. */
    size_t n = rw_ws_encode_header(frame, sizeof(frame), true, RW_WS_OP_TEXT, 125, k_mask);
    RW_CHECK_EQ_INT(n, 6);
    RW_CHECK_EQ_INT(frame[0], 0x81);
    RW_CHECK_EQ_INT(frame[1], 0x80 | 125);

    /* 16-bit: the boundary at 126. */
    n = rw_ws_encode_header(frame, sizeof(frame), true, RW_WS_OP_TEXT, 126, k_mask);
    RW_CHECK_EQ_INT(n, 8);
    RW_CHECK_EQ_INT(frame[1], 0x80 | 126);
    RW_CHECK_EQ_INT(frame[2], 0x00);
    RW_CHECK_EQ_INT(frame[3], 126);

    n = rw_ws_encode_header(frame, sizeof(frame), true, RW_WS_OP_TEXT, 2048, k_mask);
    RW_CHECK_EQ_INT(n, 8);
    RW_CHECK_EQ_INT(frame[2], 0x08);
    RW_CHECK_EQ_INT(frame[3], 0x00);

    /* 64-bit: the boundary at 65536. Built directly rather than through a payload we do not
     * have the memory to hold, because the encoding is the thing being tested. */
    n = rw_ws_encode_header(frame, sizeof(frame), true, RW_WS_OP_BINARY, 0x10000, k_mask);
    RW_CHECK_EQ_INT(n, 14);
    RW_CHECK_EQ_INT(frame[1], 0x80 | 127);
    RW_CHECK_EQ_INT(frame[2], 0x00);
    RW_CHECK_EQ_INT(frame[6], 0x00);
    RW_CHECK_EQ_INT(frame[7], 0x01);
    RW_CHECK_EQ_INT(frame[8], 0x00);
    RW_CHECK_EQ_INT(frame[9], 0x00);

    /* A header with no room is refused rather than written short. */
    RW_CHECK_EQ_INT(rw_ws_encode_header(frame, 5, true, RW_WS_OP_TEXT, 10, k_mask), 0);
    /* Client frames are always masked; a NULL key is a programming error, not a mode. */
    RW_CHECK_EQ_INT(rw_ws_encode_header(frame, sizeof(frame), true, RW_WS_OP_TEXT, 10, NULL), 0);
}

static void test_round_trip(void) {
    rw_test_begin("build then parse");

    uint8_t frame[RW_WS_MAX_HEADER + 512];
    uint8_t payload[512];
    for (size_t i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    size_t n = rw_ws_build_frame(frame, sizeof(frame), true, RW_WS_OP_TEXT, payload,
                                 sizeof(payload), k_mask);
    RW_CHECK_EQ_INT(n, 8 + sizeof(payload));

    /* The payload must actually be masked; an unmasked client frame is closed by any
     * conforming server. */
    RW_CHECK_MSG(memcmp(frame + 8, payload, sizeof(payload)) != 0,
                 "payload was written unmasked");

    uint8_t restored[512];
    memcpy(restored, frame + 8, sizeof(restored));
    rw_ws_apply_mask(restored, sizeof(restored), k_mask, 0);
    RW_CHECK_EQ_MEM(restored, payload, sizeof(payload));

    /* Parsing our own frame back fails, and must: rw_ws_parse_header is the *server to client*
     * direction, where masking is forbidden by RFC 6455 §5.1. */
    rw_ws_header_t h;
    RW_CHECK_EQ_INT(rw_ws_parse_header(frame, n, &h), RW_WS_PARSE_ERROR);
}

static void test_parsing(void) {
    rw_test_begin("header parsing");

    rw_ws_header_t h;
    uint8_t        buf[32];

    /* Unmasked server text frame, 5 bytes. */
    const uint8_t text5[] = {0x81, 0x05, 'H', 'e', 'l', 'l', 'o'};
    RW_CHECK_EQ_INT(rw_ws_parse_header(text5, sizeof(text5), &h), RW_WS_PARSE_OK);
    RW_CHECK(h.fin);
    RW_CHECK_EQ_INT(h.opcode, RW_WS_OP_TEXT);
    RW_CHECK(!h.masked);
    RW_CHECK_EQ_INT(h.payload_len, 5);
    RW_CHECK_EQ_INT(h.header_len, 2);

    /* Partial headers ask for more rather than guessing. */
    RW_CHECK_EQ_INT(rw_ws_parse_header(text5, 1, &h), RW_WS_PARSE_NEED_MORE);
    const uint8_t len16_partial[] = {0x81, 0x7E, 0x01};
    RW_CHECK_EQ_INT(rw_ws_parse_header(len16_partial, 3, &h), RW_WS_PARSE_NEED_MORE);
    const uint8_t len64_partial[] = {0x81, 0x7F, 0, 0, 0, 0, 0, 1};
    RW_CHECK_EQ_INT(rw_ws_parse_header(len64_partial, 8, &h), RW_WS_PARSE_NEED_MORE);

    /* A reserved bit with no extension negotiated is a protocol error. */
    const uint8_t rsv[] = {0xC1, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(rsv, sizeof(rsv), &h), RW_WS_PARSE_ERROR);

    /* Reserved opcodes. */
    const uint8_t bad_op[] = {0x83, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(bad_op, sizeof(bad_op), &h), RW_WS_PARSE_ERROR);
    const uint8_t bad_ctl[] = {0x8B, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(bad_ctl, sizeof(bad_ctl), &h), RW_WS_PARSE_ERROR);

    /* Non-minimal length encodings. Legal-looking and forbidden; tolerating them hides a
     * broken sender until it breaks something else. */
    const uint8_t nonminimal16[] = {0x81, 0x7E, 0x00, 0x05};
    RW_CHECK_EQ_INT(rw_ws_parse_header(nonminimal16, sizeof(nonminimal16), &h),
                    RW_WS_PARSE_ERROR);
    const uint8_t nonminimal64[] = {0x81, 0x7F, 0, 0, 0, 0, 0, 0, 0x01, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(nonminimal64, sizeof(nonminimal64), &h),
                    RW_WS_PARSE_ERROR);

    /* RFC 6455 §5.2: the top bit of a 64-bit length must be zero. */
    const uint8_t highbit[] = {0x81, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0};
    RW_CHECK_EQ_INT(rw_ws_parse_header(highbit, sizeof(highbit), &h), RW_WS_PARSE_ERROR);

    /* Control frames: never fragmented, never over 125 bytes. */
    const uint8_t frag_ping[] = {0x09, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(frag_ping, sizeof(frag_ping), &h), RW_WS_PARSE_ERROR);
    const uint8_t fat_ping[] = {0x89, 0x7E, 0x00, 0x7E};
    RW_CHECK_EQ_INT(rw_ws_parse_header(fat_ping, sizeof(fat_ping), &h), RW_WS_PARSE_ERROR);

    /* A masked frame from the server. */
    const uint8_t masked[] = {0x81, 0x85, 0x37, 0xFA, 0x21, 0x3D, 0x7F, 0x9F, 0x4D, 0x51, 0x58};
    RW_CHECK_EQ_INT(rw_ws_parse_header(masked, sizeof(masked), &h), RW_WS_PARSE_ERROR);

    /* Fragmentation is accepted at the header level; reassembly limits live in ws.c. */
    const uint8_t frag_text[] = {0x01, 0x03, 'a', 'b', 'c'};
    RW_CHECK_EQ_INT(rw_ws_parse_header(frag_text, sizeof(frag_text), &h), RW_WS_PARSE_OK);
    RW_CHECK(!h.fin);
    RW_CHECK_EQ_INT(h.opcode, RW_WS_OP_TEXT);

    const uint8_t cont[] = {0x80, 0x02, 'd', 'e'};
    RW_CHECK_EQ_INT(rw_ws_parse_header(cont, sizeof(cont), &h), RW_WS_PARSE_OK);
    RW_CHECK(h.fin);
    RW_CHECK_EQ_INT(h.opcode, RW_WS_OP_CONT);

    /* The cap. Exactly 2048 is legal; 2049 is not, and the header must still have been parsed
     * so the caller knows how to answer. */
    buf[0] = 0x81;
    buf[1] = 0x7E;
    buf[2] = (uint8_t)(RW_WS_MAX_INBOUND >> 8);
    buf[3] = (uint8_t)(RW_WS_MAX_INBOUND & 0xFF);
    RW_CHECK_EQ_INT(rw_ws_parse_header(buf, 4, &h), RW_WS_PARSE_OK);
    RW_CHECK_EQ_INT(h.payload_len, RW_WS_MAX_INBOUND);

    buf[2] = (uint8_t)((RW_WS_MAX_INBOUND + 1) >> 8);
    buf[3] = (uint8_t)((RW_WS_MAX_INBOUND + 1) & 0xFF);
    RW_CHECK_EQ_INT(rw_ws_parse_header(buf, 4, &h), RW_WS_PARSE_TOO_LARGE);
    RW_CHECK_EQ_INT(h.payload_len, RW_WS_MAX_INBOUND + 1);

    /* A 64-bit length far beyond anything the device could hold is still reported as too large
     * rather than overflowing into a small number. */
    const uint8_t huge[] = {0x82, 0x7F, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};
    RW_CHECK_EQ_INT(rw_ws_parse_header(huge, sizeof(huge), &h), RW_WS_PARSE_TOO_LARGE);
    RW_CHECK_EQ_INT(h.payload_len, 0x100000000ull);
}

static void test_close_frames(void) {
    rw_test_begin("close frames");

    uint8_t frame[RW_WS_MAX_HEADER + 125];

    size_t n = rw_ws_build_close(frame, sizeof(frame), RW_WS_CLOSE_TOO_BIG, "frame too large",
                                 k_mask);
    RW_CHECK_EQ_INT(n, 6 + 2 + 15);
    RW_CHECK_EQ_INT(frame[0], 0x88);
    RW_CHECK_EQ_INT(frame[1], 0x80 | (2 + 15));

    uint8_t body[125];
    memcpy(body, frame + 6, 2 + 15);
    rw_ws_apply_mask(body, 2 + 15, k_mask, 0);
    RW_CHECK_EQ_INT((body[0] << 8) | body[1], RW_WS_CLOSE_TOO_BIG);
    RW_CHECK_MSG(memcmp(body + 2, "frame too large", 15) == 0, "close reason mismatch");

    /* Code only. */
    n = rw_ws_build_close(frame, sizeof(frame), RW_WS_CLOSE_NORMAL, NULL, k_mask);
    RW_CHECK_EQ_INT(n, 6 + 2);

    /* An over-long reason is truncated to keep the control frame inside 125 bytes, because a
     * close frame the peer rejects leaves the socket to time out instead of shutting down. */
    char long_reason[300];
    memset(long_reason, 'r', sizeof(long_reason) - 1);
    long_reason[sizeof(long_reason) - 1] = '\0';
    n = rw_ws_build_close(frame, sizeof(frame), RW_WS_CLOSE_POLICY, long_reason, k_mask);
    RW_CHECK_EQ_INT(n, 6 + 125);
    RW_CHECK_EQ_INT(frame[1], 0x80 | 125);

    /* The idle-timeout code PROTOCOL.md §7 added, kept distinct from the auth-failure code. */
    RW_CHECK_EQ_INT(RW_WS_CLOSE_IDLE_TIMEOUT, 4003);
    RW_CHECK_EQ_INT(RW_WS_CLOSE_POLICY, 1008);
    RW_CHECK_EQ_INT(RW_WS_CLOSE_DEPROVISIONED, 4002);
    n = rw_ws_build_close(frame, sizeof(frame), RW_WS_CLOSE_IDLE_TIMEOUT, "idle", k_mask);
    memcpy(body, frame + 6, 2);
    rw_ws_apply_mask(body, 2, k_mask, 0);
    RW_CHECK_EQ_INT((body[0] << 8) | body[1], 4003);
}

static void test_size_contract(void) {
    rw_test_begin("size contract");

    /* PROTOCOL.md §1 narrowed the device-to-relay bound from 8192 to a symmetric 2048. Both
     * constants exist so a change to one is visible against the other. */
    RW_CHECK_EQ_INT(RW_WS_MAX_INBOUND, 2048);
    RW_CHECK_EQ_INT(RW_WS_MAX_OUTBOUND, 2048);

    /* A frame that does not fit the caller's buffer is refused whole. */
    uint8_t small[10];
    uint8_t payload[64];
    memset(payload, 'z', sizeof(payload));
    RW_CHECK_EQ_INT(rw_ws_build_frame(small, sizeof(small), true, RW_WS_OP_TEXT, payload,
                                      sizeof(payload), k_mask),
                    0);
}

void test_ws_frame(void) {
    test_masking();
    test_length_encodings();
    test_round_trip();
    test_parsing();
    test_close_frames();
    test_size_contract();
}
