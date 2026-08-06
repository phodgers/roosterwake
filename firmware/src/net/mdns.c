/*
 * mDNS reverse lookup. See mdns.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/mdns.h"

#include <stdio.h>
#include <string.h>

#define MDNS_HEADER_LEN 12
#define MDNS_TYPE_PTR 0x000c
#define MDNS_CLASS_IN 0x0001
/* Set on answer records to say "flush your cache"; not part of the class. */
#define MDNS_CACHE_FLUSH 0x8000u

/* A compression pointer can send the reader anywhere in the packet, including in a circle.
 * Eight hops resolves any name a real responder emits; a ninth is an attack, not a name. */
#define MAX_POINTER_HOPS 8

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * The reverse name for `ip` as uncompressed wire-format labels:
 * "99.4.168.192.in-addr.arpa" for 192.168.4.99, each label length-prefixed, NUL-terminated.
 * Returns the length written. The buffer needs at most 4*4 + 8 + 5 + 1 = 30 bytes.
 */
static size_t reverse_qname(uint8_t *out, const uint8_t ip[4]) {
    size_t n = 0;
    for (int i = 3; i >= 0; i--) {
        char dec[4];
        const int len = snprintf(dec, sizeof(dec), "%u", (unsigned)ip[i]);
        out[n++] = (uint8_t)len;
        memcpy(&out[n], dec, (size_t)len);
        n += (size_t)len;
    }
    /* Spelled as bytes, not as a string literal: in "\x04arpa" the 'a' of "arpa" is a hex
     * digit, so the escape munches it and the label comes out one byte short and wrong. */
    static const uint8_t arpa[] = {7, 'i', 'n', '-', 'a', 'd', 'd', 'r', 4, 'a', 'r', 'p', 'a', 0};
    memcpy(&out[n], arpa, sizeof(arpa));
    n += sizeof(arpa);
    return n;
}

size_t rw_mdns_build_query(uint8_t *buf, size_t cap, uint16_t txid, const uint8_t ip[4]) {
    /* header + worst-case reverse name + type + class */
    const size_t need = MDNS_HEADER_LEN + 30 + 4;
    if (buf == NULL || ip == NULL || cap < need) {
        return 0;
    }

    size_t n = 0;
    buf[n++] = (uint8_t)(txid >> 8);
    buf[n++] = (uint8_t)txid;
    buf[n++] = 0x00; /* flags: a query */
    buf[n++] = 0x00;
    buf[n++] = 0x00; /* one question */
    buf[n++] = 0x01;
    buf[n++] = 0x00; /* no answer, authority or additional records */
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;

    n += reverse_qname(&buf[n], ip);

    buf[n++] = (uint8_t)(MDNS_TYPE_PTR >> 8);
    buf[n++] = (uint8_t)MDNS_TYPE_PTR;
    buf[n++] = (uint8_t)(MDNS_CLASS_IN >> 8);
    buf[n++] = (uint8_t)MDNS_CLASS_IN;
    return n;
}

/*
 * Step over a name. Either length-prefixed labels ending in a zero byte, or ending in a
 * two-byte compression pointer. Returns the offset after it, or 0 on anything malformed.
 */
static size_t skip_name(const uint8_t *pkt, size_t len, size_t at) {
    while (at < len) {
        const uint8_t b = pkt[at];
        if ((b & 0xc0) == 0xc0) {
            return (at + 2 <= len) ? at + 2 : 0;
        }
        if (b == 0) {
            return at + 1;
        }
        if ((b & 0xc0) != 0) {
            return 0; /* 0x40/0x80 label types were never deployed; nothing honest sends them */
        }
        at += (size_t)b + 1;
    }
    return 0;
}

/*
 * Does the possibly-compressed name at `at` equal `want` (uncompressed labels)? Pointers are
 * followed with a hop budget, and every read is bounds-checked — this walks memory laid out by
 * the peer.
 */
static bool name_equals(const uint8_t *pkt, size_t len, size_t at, const uint8_t *want) {
    int hops = 0;
    size_t w = 0;
    while (at < len) {
        const uint8_t b = pkt[at];
        if ((b & 0xc0) == 0xc0) {
            if (++hops > MAX_POINTER_HOPS || at + 2 > len) {
                return false;
            }
            at = (size_t)((b & 0x3f) << 8) | pkt[at + 1];
            continue;
        }
        if (b != want[w]) {
            return false;
        }
        if (b == 0) {
            return true;
        }
        if ((b & 0xc0) != 0 || at + 1 + b > len) {
            return false;
        }
        if (memcmp(&pkt[at + 1], &want[w + 1], b) != 0) {
            return false;
        }
        at += (size_t)b + 1;
        w += (size_t)b + 1;
    }
    return false;
}

/*
 * The first label of the possibly-compressed name at `at`: printable ASCII only, truncated to
 * `out_len - 1`. The whole label is validated even when only a prefix is kept — a name that is
 * partly unprintable is rejected, not trimmed into respectability.
 */
static bool first_label(const uint8_t *pkt, size_t len, size_t at, char *out, size_t out_len) {
    int hops = 0;
    while (at < len && (pkt[at] & 0xc0) == 0xc0) {
        if (++hops > MAX_POINTER_HOPS || at + 2 > len) {
            return false;
        }
        at = (size_t)((pkt[at] & 0x3f) << 8) | pkt[at + 1];
    }
    if (at >= len) {
        return false;
    }
    const uint8_t n = pkt[at];
    if (n == 0 || (n & 0xc0) != 0 || at + 1 + n > len) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        const uint8_t ch = pkt[at + 1 + i];
        if (ch < 0x21 || ch > 0x7e) {
            return false;
        }
    }
    const size_t keep = (n < out_len - 1) ? n : out_len - 1;
    memcpy(out, &pkt[at + 1], keep);
    out[keep] = '\0';
    return true;
}

bool rw_mdns_parse_name(const uint8_t *pkt, size_t len, uint16_t txid, const uint8_t ip[4],
                        char *out, size_t out_len) {
    if (pkt == NULL || ip == NULL || out == NULL || out_len < RW_MDNS_NAME_LEN ||
        len < MDNS_HEADER_LEN) {
        return false;
    }
    /* Our transaction, a response, no error. A legacy unicast response echoes the query id
     * (RFC 6762 §6.7), so a mismatch means this answers somebody else's question. */
    if (rd16(&pkt[0]) != txid || (pkt[2] & 0x80) == 0 || (pkt[3] & 0x0f) != 0) {
        return false;
    }

    const uint16_t questions = rd16(&pkt[4]);
    const uint16_t answers   = rd16(&pkt[6]);
    if (answers == 0) {
        return false;
    }

    uint8_t want[32];
    reverse_qname(want, ip);

    /* A legacy response repeats the question before the answers. */
    size_t at = MDNS_HEADER_LEN;
    for (uint16_t q = 0; q < questions; q++) {
        at = skip_name(pkt, len, at);
        if (at == 0 || at + 4 > len) {
            return false;
        }
        at += 4; /* type, class */
    }

    for (uint16_t a = 0; a < answers; a++) {
        const size_t owner = at;
        at = skip_name(pkt, len, at);
        if (at == 0 || at + 10 > len) {
            return false;
        }
        const uint16_t type   = rd16(&pkt[at]);
        const uint16_t klass  = rd16(&pkt[at + 2]) & (uint16_t)~MDNS_CACHE_FLUSH;
        const uint16_t rdlen  = rd16(&pkt[at + 8]);
        const size_t   rdata  = at + 10;
        if (rdata + rdlen > len) {
            return false;
        }
        at = rdata + rdlen;

        /* The answer has to be a PTR for the reverse name WE asked about. A responder is free
         * to append additional records (its A record, usually); those are skipped, not read. */
        if (type != MDNS_TYPE_PTR || klass != MDNS_CLASS_IN) {
            continue;
        }
        if (!name_equals(pkt, len, owner, want)) {
            continue;
        }
        return first_label(pkt, len, rdata, out, out_len);
    }
    return false;
}
