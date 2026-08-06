/*
 * mDNS reverse lookup: the query we send and the reply we are willing to believe.
 *
 * Same contract as the NBNS tests next door: the parser reads a datagram from an
 * unauthenticated device and its output is rendered in a browser, so what it rejects matters
 * more than what it accepts. DNS adds one hazard NBNS does not have — compression pointers,
 * which can point anywhere in the packet including in a circle — so those get their own cases.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "net/mdns.h"
#include "rw_test.h"

#define TXID 0x524d

static const uint8_t IP[4] = {192, 168, 4, 20};

/* Where the pieces of the canonical response landed, so cases can corrupt them precisely. */
typedef struct {
    size_t type_off;
    size_t class_off;
    size_t rdlen_off;
    size_t rdata_off;
} layout_t;

/*
 * A legacy unicast reverse-lookup response the way a real responder builds one: the question
 * echoed, one PTR answer whose owner is a compression pointer to the question name, target
 * `host`.local given as raw wire-format labels (length-prefixed, NUL-terminated).
 */
static size_t build_response(uint8_t *buf, uint16_t txid, const uint8_t ip[4],
                             const char *labels, size_t labels_len, layout_t *at) {
    size_t n = 0;
    buf[n++] = (uint8_t)(txid >> 8);
    buf[n++] = (uint8_t)txid;
    buf[n++] = 0x84; /* response, authoritative */
    buf[n++] = 0x00;
    buf[n++] = 0x00; /* the question, echoed */
    buf[n++] = 0x01;
    buf[n++] = 0x00; /* one answer */
    buf[n++] = 0x01;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x00;

    /* The question: the reverse name, built by the same code cases corrupt below. */
    uint8_t query[64];
    const size_t qlen = rw_mdns_build_query(query, sizeof(query), txid, ip);
    const size_t name_len = qlen - 12 - 4; /* header off the front, type and class off the end */
    memcpy(&buf[n], &query[12], name_len);
    n += name_len;
    buf[n++] = 0x00; /* type PTR */
    buf[n++] = 0x0c;
    buf[n++] = 0x00; /* class IN */
    buf[n++] = 0x01;

    /* The answer. Owner compressed to the question name at offset 12. */
    buf[n++] = 0xc0;
    buf[n++] = 0x0c;
    at->type_off = n;
    buf[n++] = 0x00; /* type PTR */
    buf[n++] = 0x0c;
    at->class_off = n;
    buf[n++] = 0x00; /* class IN */
    buf[n++] = 0x01;
    buf[n++] = 0x00; /* ttl */
    buf[n++] = 0x00;
    buf[n++] = 0x00;
    buf[n++] = 0x0a;
    at->rdlen_off = n;
    buf[n++] = (uint8_t)(labels_len >> 8);
    buf[n++] = (uint8_t)labels_len;
    at->rdata_off = n;
    memcpy(&buf[n], labels, labels_len);
    n += labels_len;
    return n;
}

static void test_query(void) {
    rw_test_begin("mdns query");

    uint8_t buf[64];
    /* 12 header + "20"(3) "4"(2) "168"(4) "192"(4) "in-addr"(8) "arpa"(5) NUL(1) + 4 = 43. */
    size_t n = rw_mdns_build_query(buf, sizeof(buf), 0x1234, IP);
    RW_CHECK_EQ_INT((int)n, 43);
    RW_CHECK_EQ_INT(buf[0], 0x12);
    RW_CHECK_EQ_INT(buf[1], 0x34);
    RW_CHECK_EQ_INT(buf[5], 0x01); /* exactly one question */
    RW_CHECK_EQ_INT(buf[12], 2);   /* "20" — the octets come out reversed */
    RW_CHECK_EQ_INT(buf[13], '2');
    RW_CHECK_EQ_INT(buf[14], '0');
    RW_CHECK_EQ_INT(buf[15], 1); /* "4" */
    RW_CHECK_EQ_INT(buf[16], '4');
    RW_CHECK_EQ_INT(buf[25], 7); /* "in-addr" */
    RW_CHECK_EQ_INT(buf[38], 0x00); /* end of name */
    RW_CHECK_EQ_INT(buf[40], 0x0c); /* PTR */
    RW_CHECK_EQ_INT(buf[42], 0x01); /* IN */

    /* A buffer that cannot hold the worst case is refused rather than half-filled. */
    RW_CHECK_EQ_INT((int)rw_mdns_build_query(buf, 40, 1, IP), 0);
    RW_CHECK_EQ_INT((int)rw_mdns_build_query(NULL, sizeof(buf), 1, IP), 0);
}

static void test_parse(void) {
    rw_test_begin("mdns parse");

    uint8_t  buf[512];
    char     name[RW_MDNS_NAME_LEN];
    layout_t at;

    static const char host[] = "\x08study-pc\x05local";
    size_t n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_STR(name, "study-pc");

    /* The cache-flush bit is presentation, not a different class. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.class_off] = 0x80;
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_STR(name, "study-pc");

    /* A label longer than the buffer is kept, truncated: a machine with a long name is still a
     * machine somebody has to pick out of the list. Spelled as bytes because "\x28a..." would
     * munch the leading letters into the hex escape. */
    static const char longhost[] = {40,  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k',
                                    'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
                                    'x', 'y', 'z', '-', '0', '1', '2', '3', '4', '5', '6', '7',
                                    '8', '9', '-', 'a', 'b', 5,   'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, longhost, sizeof(longhost), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT((int)strlen(name), RW_MDNS_NAME_LEN - 1);
    RW_CHECK_EQ_STR(name, "abcdefghijklmnopqrstuvwxyz-0123");

    /* An answer for somebody else's address is not an answer to our question. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    static const uint8_t OTHER[4] = {192, 168, 4, 21};
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, OTHER, name, sizeof(name)));

    /* Somebody else's transaction. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, 0x1111, IP, name, sizeof(name)));

    /* A query, not a response. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[2] = 0x00;
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* An error response carries no name worth reading. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[3] = 0x03; /* NXDOMAIN */
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* No answers at all. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[7] = 0x00;
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A different record type is skipped, and with nothing behind it, that is a miss. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.type_off + 1] = 0x01; /* A record */
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* Rejected rather than repaired. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, 8, TXID, IP, name, sizeof(name)));   /* under a header */
    RW_CHECK(!rw_mdns_parse_name(buf, n - 4, TXID, IP, name, sizeof(name))); /* rdata cut */
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, 8));              /* buffer too small */
    RW_CHECK(!rw_mdns_parse_name(NULL, n, TXID, IP, name, sizeof(name)));

    /* An rdlen that reaches past the packet. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdlen_off + 1] = (uint8_t)(sizeof(host) + 40);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* Anything outside printable ASCII, including the escapes and quotes that would end up in
     * JSON, is refused outright — even when the bad byte is past the truncation point. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdata_off + 1] = 0x22; /* a double quote is printable; prove it survives */
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT(name[0], 0x22);

    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdata_off + 1] = 0x07;
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdata_off + 1] = 0xe9; /* a 3-byte lead with no continuations: malformed UTF-8 */
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A target that is a pointer to a pointer to a pointer... is an attack, not a name. The
     * pointer points at itself, which without the hop budget would walk forever. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdlen_off] = 0x00;
    buf[at.rdlen_off + 1] = 0x02;
    buf[at.rdata_off]     = 0xc0;
    buf[at.rdata_off + 1] = (uint8_t)at.rdata_off;
    RW_CHECK(!rw_mdns_parse_name(buf, at.rdata_off + 2, TXID, IP, name, sizeof(name)));

    /* An empty target name has no label to take. */
    n = build_response(buf, TXID, IP, host, sizeof(host), &at);
    buf[at.rdlen_off] = 0x00;
    buf[at.rdlen_off + 1] = 0x01;
    buf[at.rdata_off]     = 0x00;
    RW_CHECK(!rw_mdns_parse_name(buf, at.rdata_off + 1, TXID, IP, name, sizeof(name)));
}

/*
 * The UTF-8 contract: real names in real scripts pass through as themselves; the machinery of
 * visual deception, and anything malformed, is rejected whole. The label bytes are spelled out
 * because this is exactly the file where an escape-munching literal already bit once.
 */
static void test_utf8(void) {
    rw_test_begin("mdns utf8");

    uint8_t  buf[512];
    char     name[RW_MDNS_NAME_LEN];
    layout_t at;

    /* café: a two-byte character renders as itself. The label length counts bytes, so it is 5. */
    static const char cafe[] = {5, 'c', 'a', 'f', 0xc3 - 256, 0xa9 - 256, 5, 'l', 'o', 'c', 'a', 'l', 0};
    size_t n = build_response(buf, TXID, IP, cafe, sizeof(cafe), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT((unsigned char)name[3], 0xc3);
    RW_CHECK_EQ_INT((unsigned char)name[4], 0xa9);
    RW_CHECK_EQ_INT((int)strlen(name), 5);

    /* 客廳的電腦 — five three-byte characters. */
    static const unsigned char cjk_label[] = {0xe5, 0xae, 0xa2, 0xe5, 0xbb, 0xb3, 0xe7, 0x9a,
                                              0x84, 0xe9, 0x9b, 0xbb, 0xe8, 0x85, 0xa6};
    uint8_t cjk[1 + sizeof(cjk_label) + 7];
    cjk[0] = sizeof(cjk_label);
    memcpy(&cjk[1], cjk_label, sizeof(cjk_label));
    memcpy(&cjk[1 + sizeof(cjk_label)], "\x05local", 7); /* includes the literal's NUL */
    n = build_response(buf, TXID, IP, (const char *)cjk, sizeof(cjk), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT((int)strlen(name), (int)sizeof(cjk_label));
    RW_CHECK(memcmp(name, cjk_label, sizeof(cjk_label)) == 0);

    /* A four-byte character (an emoji) is a character like any other. */
    static const char emoji[] = {6, 'p', 'c', 0xf0 - 256, 0x9f - 256, 0x92 - 256, 0xbb - 256,
                                 5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, emoji, sizeof(emoji), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT((int)strlen(name), 6);

    /* Truncation lands on a character boundary: sixteen two-byte characters are 32 bytes, and
     * the 31-byte buffer keeps fifteen whole ones, never half of the sixteenth. */
    uint8_t wide[1 + 32 + 7];
    wide[0] = 32;
    for (int i = 0; i < 16; i++) {
        wide[1 + i * 2]     = 0xc3;
        wide[1 + i * 2 + 1] = 0xa9;
    }
    memcpy(&wide[33], "\x05local", 7);
    n = build_response(buf, TXID, IP, (const char *)wide, sizeof(wide), &at);
    RW_CHECK(rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
    RW_CHECK_EQ_INT((int)strlen(name), 30);
    RW_CHECK_EQ_INT((unsigned char)name[29], 0xa9); /* ends on a complete character */

    /* An overlong encoding is the classic smuggling vector, not a character. */
    static const char overlong[] = {4, 'p', 'c', 0xc0 - 256, 0xaf - 256, 5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, overlong, sizeof(overlong), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A surrogate is UTF-16's business and has no place in UTF-8. */
    static const char surrogate[] = {5, 'p', 'c', 0xed - 256, 0xa0 - 256, 0x80 - 256,
                                     5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, surrogate, sizeof(surrogate), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A sequence cut off by the end of its label. */
    static const char cut[] = {3, 'p', 'c', 0xc3 - 256, 5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, cut, sizeof(cut), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A bidi override makes text display as something it is not. Rejected whole. */
    static const char bidi[] = {5, 'p', 'c', 0xe2 - 256, 0x80 - 256, 0xae - 256,
                                5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, bidi, sizeof(bidi), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));

    /* A zero-width space makes two different names look identical. */
    static const char zwsp[] = {5, 'p', 'c', 0xe2 - 256, 0x80 - 256, 0x8b - 256,
                                5, 'l', 'o', 'c', 'a', 'l', 0};
    n = build_response(buf, TXID, IP, zwsp, sizeof(zwsp), &at);
    RW_CHECK(!rw_mdns_parse_name(buf, n, TXID, IP, name, sizeof(name)));
}

void test_mdns(void) {
    test_query();
    test_parse();
    test_utf8();
}
