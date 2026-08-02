/*
 * NetBIOS node status: the query we send and the reply we are willing to believe.
 *
 * The parser reads a datagram from an unauthenticated device on the same network and its output
 * is rendered in a browser, so what it rejects matters more than what it accepts. Most of these
 * cases are malformed input.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "net/nbns.h"
#include "rw_test.h"

/* A node status response carrying `entries` names, the first of which is `name` with the given
 * suffix and flags. Built rather than captured so each field can be corrupted in turn. */
static size_t build_response(uint8_t *buf, const char *name, uint8_t suffix, uint16_t flags,
                             uint8_t entries) {
    size_t n = 0;
    buf[n++] = 0x52;
    buf[n++] = 0x57;
    buf[n++] = 0x84; /* response, authoritative */
    buf[n++] = 0x00;
    buf[n++] = 0x00; /* no questions echoed */
    buf[n++] = 0x00;
    buf[n++] = 0x00; /* one answer */
    buf[n++] = 0x01;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;

    /* Answer name: the same first-level encoding the query uses. Contents are never read. */
    buf[n++] = 32;
    for (int i = 0; i < 32; i++) {
        buf[n++] = 'A';
    }
    buf[n++] = 0x00;

    buf[n++] = 0x00; /* type NBSTAT */
    buf[n++] = 0x21;
    buf[n++] = 0x00; /* class IN */
    buf[n++] = 0x01;
    buf[n++] = 0x00; /* ttl */
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;

    const uint16_t rdlen = (uint16_t)(1 + entries * 18);
    buf[n++] = (uint8_t)(rdlen >> 8);
    buf[n++] = (uint8_t)rdlen;
    buf[n++] = entries;

    const size_t nlen = strlen(name);
    for (uint8_t e = 0; e < entries; e++) {
        /* Padded to fifteen with spaces. Bounded by the string's own length: indexing the literal
         * past its NUL reads whatever is next in memory, and this builder's whole job is to put
         * known bytes in a known place. */
        for (size_t i = 0; i < 15; i++) {
            buf[n++] = (e == 0 && i < nlen) ? (uint8_t)name[i] : ' ';
        }
        buf[n++] = (e == 0) ? suffix : 0x20;
        buf[n++] = (uint8_t)((e == 0 ? flags : 0) >> 8);
        buf[n++] = (uint8_t)(e == 0 ? flags : 0);
    }
    return n;
}

static void test_query(void) {
    rw_test_begin("nbns query");

    uint8_t buf[64];
    size_t  n = rw_nbns_build_query(buf, sizeof(buf), 0x1234);
    RW_CHECK_EQ_INT((int)n, 50);
    RW_CHECK_EQ_INT(buf[0], 0x12);
    RW_CHECK_EQ_INT(buf[1], 0x34);
    RW_CHECK_EQ_INT(buf[5], 0x01);  /* exactly one question */
    RW_CHECK_EQ_INT(buf[12], 32);   /* encoded name length */
    /* '*' is 0x2A, so its nibbles encode as 'C' and 'K'; the fifteen NULs that follow are 'A'. */
    RW_CHECK_EQ_INT(buf[13], 'C');
    RW_CHECK_EQ_INT(buf[14], 'K');
    RW_CHECK_EQ_INT(buf[15], 'A');
    /* 12 header, 1 length, 32 encoded (13..44), then the terminator, type and class. */
    RW_CHECK_EQ_INT(buf[44], 'A');  /* last encoded nibble */
    RW_CHECK_EQ_INT(buf[45], 0x00); /* end of name */
    RW_CHECK_EQ_INT(buf[47], 0x21); /* NBSTAT */
    RW_CHECK_EQ_INT(buf[49], 0x01); /* IN */

    /* A buffer that cannot hold it is refused rather than half-filled. */
    RW_CHECK_EQ_INT((int)rw_nbns_build_query(buf, 40, 1), 0);
    RW_CHECK_EQ_INT((int)rw_nbns_build_query(NULL, sizeof(buf), 1), 0);
}

static void test_parse(void) {
    rw_test_begin("nbns parse");

    uint8_t buf[512];
    char    name[RW_NBNS_NAME_LEN];

    size_t n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    RW_CHECK(rw_nbns_parse_name(buf, n, name, sizeof(name)));
    RW_CHECK_EQ_STR(name, "PHIL");

    /* Padding is stripped, not kept. */
    n = build_response(buf, "DESKTOP-1A2B3C4", 0x00, 0x0400, 1);
    RW_CHECK(rw_nbns_parse_name(buf, n, name, sizeof(name)));
    RW_CHECK_EQ_STR(name, "DESKTOP-1A2B3C4");

    /* The workstation entry is found past entries that are not it. */
    n = build_response(buf, "PHIL", 0x20, 0x0400, 3);
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    /* A group name is the workgroup, not the machine. */
    n = build_response(buf, "WORKGROUP", 0x00, 0x8000, 1);
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    /* Rejected rather than repaired. */
    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    RW_CHECK(!rw_nbns_parse_name(buf, 8, name, sizeof(name)));       /* shorter than a header */
    RW_CHECK(!rw_nbns_parse_name(buf, n - 4, name, sizeof(name)));   /* rdata cut short */
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, 4));                  /* caller's buffer too small */
    RW_CHECK(!rw_nbns_parse_name(NULL, n, name, sizeof(name)));

    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[2] = 0x00; /* a query, not a response */
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[7] = 0x00; /* no answers */
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[47] = 0x20; /* a different record type */
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    n = build_response(buf, "PHIL", 0x00, 0x0400, 0);
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name))); /* no names at all */

    /* Anything outside printable ASCII, including the escapes and quotes that would end up in
     * JSON, is refused outright. */
    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[n - 18 + 2] = 0x01;
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[n - 18 + 2] = 0xff;
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));

    /* A count that does not fit the record it is in. */
    n = build_response(buf, "PHIL", 0x00, 0x0400, 1);
    buf[n - 18 - 1] = 40;
    RW_CHECK(!rw_nbns_parse_name(buf, n, name, sizeof(name)));
}

void test_nbns(void) {
    test_query();
    test_parse();
}
