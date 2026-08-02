/*
 * NetBIOS node status. See nbns.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/nbns.h"

#include <string.h>

/* Header, then the encoded question name, then type and class. */
#define NBNS_HEADER_LEN 12
#define NBNS_TYPE_NBSTAT 0x0021
#define NBNS_CLASS_IN 0x0001

/* Each entry in the answer: 15 characters of name, a suffix byte, two flag bytes. */
#define NBNS_ENTRY_LEN 18
/* Set in the flags when the name belongs to a group rather than to this machine alone. */
#define NBNS_FLAG_GROUP 0x8000u
/* The suffix that means "workstation service", which is the entry carrying the computer name. */
#define NBNS_SUFFIX_WORKSTATION 0x00

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

/*
 * First-level encoding: every byte becomes two, each nibble offset from 'A'. Sixteen bytes of
 * NetBIOS name therefore occupy thirty-two on the wire.
 */
static size_t encode_name(uint8_t *out, const uint8_t name[RW_NBNS_NAME_LEN]) {
    size_t n = 0;
    for (size_t i = 0; i < RW_NBNS_NAME_LEN; i++) {
        out[n++] = (uint8_t)('A' + ((name[i] >> 4) & 0x0f));
        out[n++] = (uint8_t)('A' + (name[i] & 0x0f));
    }
    return n;
}

size_t rw_nbns_build_query(uint8_t *buf, size_t cap, uint16_t txid) {
    /* header + length byte + 32 encoded + terminator + type + class */
    const size_t need = NBNS_HEADER_LEN + 1 + 32 + 1 + 4;
    if (buf == NULL || cap < need) {
        return 0;
    }

    size_t n = 0;
    buf[n++] = (uint8_t)(txid >> 8);
    buf[n++] = (uint8_t)txid;
    buf[n++] = 0x00; /* flags: a query, no recursion desired */
    buf[n++] = 0x00;
    buf[n++] = 0x00; /* one question */
    buf[n++] = 0x01;
    buf[n++] = 0x00; /* no answer, authority or additional records */
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;

    /* The wildcard name: '*' followed by fifteen NULs. */
    uint8_t wildcard[RW_NBNS_NAME_LEN];
    memset(wildcard, 0, sizeof(wildcard));
    wildcard[0] = '*';

    buf[n++] = 32;
    n += encode_name(&buf[n], wildcard);
    buf[n++] = 0x00; /* end of the name */

    buf[n++] = (uint8_t)(NBNS_TYPE_NBSTAT >> 8);
    buf[n++] = (uint8_t)NBNS_TYPE_NBSTAT;
    buf[n++] = (uint8_t)(NBNS_CLASS_IN >> 8);
    buf[n++] = (uint8_t)NBNS_CLASS_IN;
    return n;
}

/*
 * Step over a name in the answer. Either a sequence of length-prefixed labels ending in a zero
 * byte, or a two-byte pointer into the packet. Returns the offset after it, or 0 on anything
 * malformed.
 */
static size_t skip_name(const uint8_t *pkt, size_t len, size_t at) {
    while (at < len) {
        const uint8_t b = pkt[at];
        if ((b & 0xc0) == 0xc0) {
            return (at + 2 <= len) ? at + 2 : 0; /* compression pointer */
        }
        if (b == 0) {
            return at + 1;
        }
        at += (size_t)b + 1;
    }
    return 0;
}

bool rw_nbns_parse_name(const uint8_t *pkt, size_t len, char *out, size_t out_len) {
    if (pkt == NULL || out == NULL || out_len < RW_NBNS_NAME_LEN || len < NBNS_HEADER_LEN) {
        return false;
    }
    /* A response, carrying at least one answer. Anything else is not ours to read. */
    if ((pkt[2] & 0x80) == 0 || rd16(&pkt[6]) == 0) {
        return false;
    }

    size_t at = skip_name(pkt, len, NBNS_HEADER_LEN);
    if (at == 0 || at + 10 > len) {
        return false;
    }
    if (rd16(&pkt[at]) != NBNS_TYPE_NBSTAT || rd16(&pkt[at + 2]) != NBNS_CLASS_IN) {
        return false;
    }
    at += 8; /* type, class, ttl */

    const uint16_t rdlen = rd16(&pkt[at]);
    at += 2;
    if (rdlen < 1 || at + rdlen > len) {
        return false;
    }

    const uint8_t entries = pkt[at++];
    if ((size_t)entries * NBNS_ENTRY_LEN > (size_t)rdlen - 1) {
        return false;
    }

    for (uint8_t i = 0; i < entries; i++) {
        const uint8_t *entry = &pkt[at + (size_t)i * NBNS_ENTRY_LEN];
        const uint8_t  suffix = entry[15];
        const uint16_t flags  = rd16(&entry[16]);

        if (suffix != NBNS_SUFFIX_WORKSTATION || (flags & NBNS_FLAG_GROUP) != 0) {
            continue;
        }

        /* Fifteen characters padded with trailing spaces. Trim the padding, then require every
         * remaining byte to be printable ASCII — this came off the network from a device nobody
         * has authenticated, and it is going into JSON and then into a page. Rejecting is the
         * whole contract: a name repaired into something plausible is a name that lies. */
        size_t n = 15;
        while (n > 0 && entry[n - 1] == ' ') {
            n--;
        }
        if (n == 0) {
            return false;
        }
        for (size_t j = 0; j < n; j++) {
            if (entry[j] < 0x21 || entry[j] > 0x7e) {
                return false;
            }
        }
        memcpy(out, entry, n);
        out[n] = '\0';
        return true;
    }
    return false;
}
