/*
 * Captive-portal DNS codec. See dns_msg.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/dns_msg.h"

#include <string.h>

/* Header field offsets (RFC 1035 §4.1.1). */
#define OFF_ID      0
#define OFF_FLAGS   2
#define OFF_QDCOUNT 4
#define OFF_ANCOUNT 6
#define OFF_NSCOUNT 8
#define OFF_ARCOUNT 10

#define FLAG_QR     0x8000u /* 1 = response */
#define FLAG_OPCODE 0x7800u
#define FLAG_AA     0x0400u /* authoritative */
#define FLAG_RD     0x0100u /* recursion desired */
#define FLAG_RA     0x0080u /* recursion available */

#define LABEL_MAX 63

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

bool rw_dns_parse_query(const uint8_t *buf, size_t len, rw_dns_query_t *out) {
    if (buf == NULL || out == NULL || len < RW_DNS_HEADER_LEN) {
        return false;
    }

    uint16_t flags = rd16(buf + OFF_FLAGS);
    if (flags & FLAG_QR) {
        return false; /* a response arrived on our port; not ours to answer */
    }
    if ((flags & FLAG_OPCODE) != 0) {
        return false; /* only standard QUERY */
    }
    if (rd16(buf + OFF_QDCOUNT) != 1) {
        /* Exactly one question. Zero is nothing to answer; more than one is legal on paper and
         * essentially unheard of in practice, and supporting it would mean a multi-answer
         * encoder that no captive-portal probe would ever exercise. */
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->id                = rd16(buf + OFF_ID);
    out->recursion_desired = (flags & FLAG_RD) != 0;
    out->qname_off         = RW_DNS_HEADER_LEN;

    /* Walk the labels. Every read is bounds-checked, the total name length is capped, and a
     * compression pointer terminates the parse rather than being followed. */
    size_t i     = RW_DNS_HEADER_LEN;
    size_t total = 0;
    while (true) {
        if (i >= len) {
            return false; /* ran off the end before the root label */
        }
        uint8_t label = buf[i];

        if ((label & 0xC0u) == 0xC0u) {
            /* A pointer in a question section is malformed. Refusing it keeps this parser
             * incapable of following a cycle, which is the only way it could be made to hang. */
            return false;
        }
        if (label > LABEL_MAX) {
            return false; /* 0x40 and 0x80 prefixes are reserved */
        }

        i++;
        if (label == 0) {
            break; /* root: the name is complete */
        }
        if (i + label > len) {
            return false;
        }
        total += (size_t)label + 1;
        if (total > RW_DNS_NAME_MAX) {
            return false;
        }
        i += label;
    }

    out->qname_len = i - out->qname_off;

    if (i + 4 > len) {
        return false; /* no room for QTYPE and QCLASS */
    }
    out->qtype        = rd16(buf + i);
    out->qclass       = rd16(buf + i + 2);
    out->question_len = out->qname_len + 4;
    return true;
}

size_t rw_dns_build_response(const uint8_t *request, size_t request_len,
                             const rw_dns_query_t *query, uint32_t answer_ip, uint32_t ttl,
                             uint8_t *out, size_t out_len) {
    if (request == NULL || query == NULL || out == NULL) {
        return 0;
    }

    size_t question_end = RW_DNS_HEADER_LEN + query->question_len;
    if (question_end > request_len) {
        return 0;
    }

    /* Answer only A/IN. Everything else, AAAA above all, gets NOERROR with no answers so a
     * dual-stack client stops waiting on IPv6 and asks for A. */
    bool answer = (query->qtype == RW_DNS_TYPE_A) && (query->qclass == RW_DNS_CLASS_IN);

    /* 2-byte name pointer + type + class + ttl + rdlength + 4-byte address. */
    const size_t answer_len = answer ? 16u : 0u;
    if (question_end + answer_len > out_len) {
        return 0;
    }

    /* Echo the header and the question verbatim: re-encoding a name we have already validated
     * would be a second chance to get it wrong for no benefit. */
    memcpy(out, request, question_end);

    uint16_t flags = FLAG_QR | FLAG_AA;
    if (query->recursion_desired) {
        /* Reflect RD and claim RA. A client that asked for recursion and sees neither bit set
         * treats the answer as suspect, and some resolvers retry the whole exchange. */
        flags |= FLAG_RD | FLAG_RA;
    }
    wr16(out + OFF_FLAGS, flags);
    wr16(out + OFF_QDCOUNT, 1);
    wr16(out + OFF_ANCOUNT, answer ? 1 : 0);
    wr16(out + OFF_NSCOUNT, 0);
    wr16(out + OFF_ARCOUNT, 0);

    if (!answer) {
        return question_end;
    }

    uint8_t *a = out + question_end;
    /* 0xC00C: a pointer to offset 12, the question's name. Every resolver understands it and it
     * keeps the response inside one small datagram whatever the name's length. */
    wr16(a, 0xC00Cu);
    wr16(a + 2, RW_DNS_TYPE_A);
    wr16(a + 4, RW_DNS_CLASS_IN);
    wr32(a + 6, ttl);
    wr16(a + 10, 4);
    wr32(a + 12, answer_ip);

    return question_end + answer_len;
}
