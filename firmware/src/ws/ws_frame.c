/*
 * RFC 6455 frame codec. See ws_frame.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ws/ws_frame.h"

#include <string.h>

rw_ws_parse_t rw_ws_parse_header(const uint8_t *buf, size_t len, rw_ws_header_t *out) {
    if (len < 2) {
        return RW_WS_PARSE_NEED_MORE;
    }

    const uint8_t b0 = buf[0];
    const uint8_t b1 = buf[1];

    if ((b0 & 0x70) != 0) {
        return RW_WS_PARSE_ERROR; /* RSV1..3 with no extension negotiated */
    }

    out->fin    = (b0 & 0x80) != 0;
    out->opcode = (uint8_t)(b0 & 0x0f);
    out->masked = (b1 & 0x80) != 0;

    const bool is_control = (out->opcode & 0x08) != 0;
    switch (out->opcode) {
        case RW_WS_OP_CONT:
        case RW_WS_OP_TEXT:
        case RW_WS_OP_BINARY:
        case RW_WS_OP_CLOSE:
        case RW_WS_OP_PING:
        case RW_WS_OP_PONG:
            break;
        default:
            return RW_WS_PARSE_ERROR; /* reserved opcode */
    }

    if (out->masked) {
        /* RFC 6455 §5.1: a server must not mask. Accepting it would mean guessing which side
         * of a broken proxy we are talking to. */
        return RW_WS_PARSE_ERROR;
    }

    const uint8_t len7 = (uint8_t)(b1 & 0x7f);
    size_t        pos  = 2;

    if (len7 < 126) {
        out->payload_len = len7;
    } else if (len7 == 126) {
        if (len < 4) {
            return RW_WS_PARSE_NEED_MORE;
        }
        uint64_t v = ((uint64_t)buf[2] << 8) | (uint64_t)buf[3];
        if (v < 126) {
            return RW_WS_PARSE_ERROR; /* non-minimal length encoding */
        }
        out->payload_len = v;
        pos              = 4;
    } else {
        if (len < 10) {
            return RW_WS_PARSE_NEED_MORE;
        }
        if ((buf[2] & 0x80) != 0) {
            return RW_WS_PARSE_ERROR; /* RFC 6455 §5.2: the high bit must be 0 */
        }
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (uint64_t)buf[2 + i];
        }
        if (v < 0x10000u) {
            return RW_WS_PARSE_ERROR; /* non-minimal length encoding */
        }
        out->payload_len = v;
        pos              = 10;
    }

    if (is_control) {
        if (out->payload_len > 125) {
            return RW_WS_PARSE_ERROR;
        }
        if (!out->fin) {
            return RW_WS_PARSE_ERROR; /* control frames are never fragmented */
        }
    }

    memset(out->mask, 0, sizeof(out->mask));
    out->header_len = pos;

    /* Reported after the header is fully understood, so the caller knows exactly how many
     * bytes to discard before it can resynchronise and send its 1009. */
    if (out->payload_len > RW_WS_MAX_INBOUND) {
        return RW_WS_PARSE_TOO_LARGE;
    }
    return RW_WS_PARSE_OK;
}

size_t rw_ws_encode_header(uint8_t *out, size_t out_len, bool fin, uint8_t opcode,
                           size_t payload_len, const uint8_t mask[4]) {
    if (mask == NULL) {
        return 0;
    }

    size_t needed = 2 + 4;
    if (payload_len > 0xFFFF) {
        needed += 8;
    } else if (payload_len > 125) {
        needed += 2;
    }
    if (out_len < needed) {
        return 0;
    }

    out[0] = (uint8_t)((fin ? 0x80 : 0x00) | (opcode & 0x0f));

    size_t pos;
    if (payload_len <= 125) {
        out[1] = (uint8_t)(0x80 | payload_len);
        pos    = 2;
    } else if (payload_len <= 0xFFFF) {
        out[1] = 0x80 | 126;
        out[2] = (uint8_t)((payload_len >> 8) & 0xff);
        out[3] = (uint8_t)(payload_len & 0xff);
        pos    = 4;
    } else {
        out[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) {
            out[2 + i] = (uint8_t)((uint64_t)payload_len >> (56 - 8 * i));
        }
        pos = 10;
    }

    memcpy(out + pos, mask, 4);
    return pos + 4;
}

void rw_ws_apply_mask(uint8_t *data, size_t len, const uint8_t mask[4], size_t offset) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= mask[(offset + i) & 3];
    }
}

size_t rw_ws_build_frame(uint8_t *out, size_t out_len, bool fin, uint8_t opcode,
                         const uint8_t *payload, size_t payload_len, const uint8_t mask[4]) {
    size_t hdr = rw_ws_encode_header(out, out_len, fin, opcode, payload_len, mask);
    if (hdr == 0) {
        return 0;
    }
    if (out_len - hdr < payload_len) {
        return 0;
    }
    if (payload_len > 0) {
        memcpy(out + hdr, payload, payload_len);
        rw_ws_apply_mask(out + hdr, payload_len, mask, 0);
    }
    return hdr + payload_len;
}

size_t rw_ws_build_close(uint8_t *out, size_t out_len, uint16_t code, const char *reason,
                         const uint8_t mask[4]) {
    uint8_t payload[125];
    size_t  n = 0;

    payload[n++] = (uint8_t)(code >> 8);
    payload[n++] = (uint8_t)(code & 0xff);

    if (reason != NULL) {
        size_t reason_len = strlen(reason);
        if (reason_len > sizeof(payload) - 2) {
            reason_len = sizeof(payload) - 2;
        }
        memcpy(payload + n, reason, reason_len);
        n += reason_len;
    }

    return rw_ws_build_frame(out, out_len, true, RW_WS_OP_CLOSE, payload, n, mask);
}
