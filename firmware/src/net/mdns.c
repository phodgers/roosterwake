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
 * Decode one UTF-8 sequence, strictly: overlong encodings, surrogates, values past U+10FFFF
 * and truncated sequences are all malformed, not tolerated. Returns the length consumed
 * (1..4) and writes the code point, or 0.
 */
static size_t utf8_decode(const uint8_t *p, size_t avail, uint32_t *cp) {
    const uint8_t b = p[0];
    if (b < 0x80) {
        *cp = b;
        return 1;
    }
    size_t   need;
    uint32_t v;
    uint32_t min;
    if ((b & 0xe0) == 0xc0) {
        need = 2;
        v    = b & 0x1fu;
        min  = 0x80;
    } else if ((b & 0xf0) == 0xe0) {
        need = 3;
        v    = b & 0x0fu;
        min  = 0x800;
    } else if ((b & 0xf8) == 0xf0) {
        need = 4;
        v    = b & 0x07u;
        min  = 0x10000;
    } else {
        return 0; /* a continuation byte with nothing to continue */
    }
    if (avail < need) {
        return 0;
    }
    for (size_t i = 1; i < need; i++) {
        if ((p[i] & 0xc0) != 0x80) {
            return 0;
        }
        v = (v << 6) | (p[i] & 0x3fu);
    }
    if (v < min || v > 0x10ffff || (v >= 0xd800 && v <= 0xdfff)) {
        return 0;
    }
    *cp = v;
    return need;
}

/*
 * Characters that lie to the person doing the read-and-match the name exists for.
 *
 * The name is rendered for a human to recognise their own machine, so the alphabet is anything
 * a hostname can honestly display — "MacBook Марка" and "客廳的電腦" are both real machines
 * with real names. What is refused is the machinery of visual deception: characters that are
 * invisible, that reorder the text around them, or that impersonate whitespace. This list
 * targets those classes; it does not claim to make lookalike names impossible — an attacker on
 * the same LAN can type PHlL-PC in plain ASCII — it claims a name renders as the bytes it is.
 */
static bool deceptive(uint32_t cp) {
    if (cp < 0x21 || cp == 0x7f) {
        return true; /* C0 controls, space, DEL */
    }
    if (cp >= 0x80 && cp <= 0x9f) {
        return true; /* C1 controls */
    }
    if (cp == 0xa0 || cp == 0xad) {
        return true; /* no-break space, soft hyphen: whitespace and invisibility lookalikes */
    }
    if (cp >= 0x200b && cp <= 0x200f) {
        return true; /* zero-widths and the LTR/RTL marks */
    }
    if (cp >= 0x202a && cp <= 0x202e) {
        return true; /* bidi embeds and overrides */
    }
    if (cp == 0x2028 || cp == 0x2029 || cp == 0x2060 || cp == 0xfeff) {
        return true; /* line separators, word joiner, zero-width no-break space */
    }
    if (cp >= 0x2066 && cp <= 0x2069) {
        return true; /* bidi isolates */
    }
    return false;
}

/*
 * The first label of the possibly-compressed name at `at`: well-formed UTF-8 with nothing
 * deceptive in it, truncated to `out_len - 1` bytes on a character boundary. The whole label
 * is validated even past the truncation point — a name that is partly malformed is rejected,
 * not trimmed into respectability.
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

    const uint8_t *label = &pkt[at + 1];
    size_t         keep  = 0; /* the longest whole-character prefix that fits `out` */
    for (size_t i = 0; i < n;) {
        uint32_t     cp;
        const size_t step = utf8_decode(&label[i], (size_t)n - i, &cp);
        if (step == 0 || deceptive(cp)) {
            return false;
        }
        i += step;
        if (i <= out_len - 1) {
            keep = i;
        }
    }
    memcpy(out, label, keep);
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
