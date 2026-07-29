/*
 * Setup-hotspot DHCP and DNS codec tests.
 *
 * Both servers parse unauthenticated input from anything in radio range of an open hotspot, so
 * the malformed-input cases here matter as much as the happy paths — more, arguably, since the
 * happy path is exercised by every phone that ever connects and the hostile one is not.
 *
 * SPDX-License-Identifier: MIT
 */
#include "rw_test.h"

#include "provisioning/dhcp_msg.h"
#include "provisioning/dns_msg.h"
#include "provisioning/http_req.h"

#define AP_IP     0xC0A80401u /* 192.168.4.1 */
#define AP_MASK   0xFFFFFF00u
#define LEASE_IP  0xC0A80402u /* 192.168.4.2 */
#define LEASE_SEC 86400u

static const uint8_t k_chaddr[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

/* ── DHCP ────────────────────────────────────────────────────────────────── */

/*
 * Build a DHCP request for the parser to chew on. Returns the length.
 *
 * `extra` is appended verbatim after option 53, which is how the malformed-option cases inject
 * their damage without hand-writing a whole packet each time.
 */
static size_t make_dhcp(uint8_t *buf, size_t cap, uint8_t msg_type, const uint8_t *extra,
                        size_t extra_len) {
    memset(buf, 0, cap);
    buf[0]  = RW_DHCP_OP_REQUEST;
    buf[1]  = 1; /* htype ethernet */
    buf[2]  = 6; /* hlen */
    buf[4]  = 0xDE;
    buf[5]  = 0xAD;
    buf[6]  = 0xBE;
    buf[7]  = 0xEF; /* xid */
    memcpy(buf + 28, k_chaddr, sizeof(k_chaddr));

    buf[236] = 0x63;
    buf[237] = 0x82;
    buf[238] = 0x53;
    buf[239] = 0x63;

    size_t pos = 240;
    buf[pos++] = RW_DHCP_OPT_MSG_TYPE;
    buf[pos++] = 1;
    buf[pos++] = msg_type;

    if (extra != NULL && extra_len > 0) {
        memcpy(buf + pos, extra, extra_len);
        pos += extra_len;
    }
    buf[pos++] = RW_DHCP_OPT_END;
    return pos;
}

/* Find an option in a built reply. Returns its value pointer, or NULL. */
static const uint8_t *find_opt(const uint8_t *buf, size_t len, uint8_t code, uint8_t *out_len) {
    size_t i = RW_DHCP_MIN_LEN;
    while (i < len) {
        if (buf[i] == RW_DHCP_OPT_END) return NULL;
        if (buf[i] == 0) { i++; continue; }
        if (i + 2 > len) return NULL;
        uint8_t l = buf[i + 1];
        if (i + 2 + l > len) return NULL;
        if (buf[i] == code) {
            if (out_len) *out_len = l;
            return buf + i + 2;
        }
        i += 2u + l;
    }
    return NULL;
}

static uint32_t opt32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void test_dhcp_parse(void) {
    uint8_t           buf[RW_DHCP_MSG_MAX];
    rw_dhcp_request_t req;

    rw_test_begin("a well-formed DISCOVER parses");
    size_t len = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, NULL, 0);
    RW_CHECK(rw_dhcp_parse(buf, len, &req));
    RW_CHECK(req.type == RW_DHCP_DISCOVER);
    RW_CHECK_EQ_INT(req.xid, 0xDEADBEEF);
    RW_CHECK_EQ_MEM(req.chaddr, k_chaddr, sizeof(k_chaddr));
    RW_CHECK(!req.broadcast);

    rw_test_begin("option 50 and 54 are picked up from a REQUEST");
    static const uint8_t extra[] = {
        RW_DHCP_OPT_REQUESTED_IP, 4, 192, 168, 4, 2,
        RW_DHCP_OPT_SERVER_ID,    4, 192, 168, 4, 1,
    };
    len = make_dhcp(buf, sizeof(buf), RW_DHCP_REQUEST, extra, sizeof(extra));
    RW_CHECK(rw_dhcp_parse(buf, len, &req));
    RW_CHECK(req.type == RW_DHCP_REQUEST);
    RW_CHECK_EQ_INT(req.requested_ip, LEASE_IP);
    RW_CHECK_EQ_INT(req.server_id, AP_IP);

    rw_test_begin("the broadcast flag is read");
    len      = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, NULL, 0);
    buf[10]  = 0x80; /* flags high byte */
    RW_CHECK(rw_dhcp_parse(buf, len, &req));
    RW_CHECK(req.broadcast);

    rw_test_begin("malformed packets are refused, not half-parsed");
    len = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, NULL, 0);
    RW_CHECK(!rw_dhcp_parse(buf, RW_DHCP_MIN_LEN - 1, &req)); /* too short */
    RW_CHECK(!rw_dhcp_parse(NULL, len, &req));

    len      = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, NULL, 0);
    buf[236] = 0x00; /* broken magic cookie */
    RW_CHECK(!rw_dhcp_parse(buf, len, &req));

    len    = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, NULL, 0);
    buf[0] = RW_DHCP_OP_REPLY; /* our own reply echoed back at us */
    RW_CHECK(!rw_dhcp_parse(buf, len, &req));

    rw_test_begin("a BOOTP packet with no option 53 is not DHCP");
    memset(buf, 0, sizeof(buf));
    buf[0]   = RW_DHCP_OP_REQUEST;
    buf[236] = 0x63; buf[237] = 0x82; buf[238] = 0x53; buf[239] = 0x63;
    buf[240] = RW_DHCP_OPT_END;
    RW_CHECK(!rw_dhcp_parse(buf, 241, &req));

    rw_test_begin("an option claiming more bytes than the datagram holds cannot walk off the end");
    /* The length byte is entirely under the sender's control, so this is the shape of the only
     * memory-safety bug this parser could have. */
    static const uint8_t liar[] = {RW_DHCP_OPT_REQUESTED_IP, 200, 1, 2, 3};
    len = make_dhcp(buf, sizeof(buf), RW_DHCP_DISCOVER, liar, sizeof(liar));
    RW_CHECK(rw_dhcp_parse(buf, len, &req)); /* option 53 was already seen, so this still parses */
    RW_CHECK_EQ_INT(req.requested_ip, 0);    /* but the lying option contributed nothing */

    rw_test_begin("an option code with no length byte terminates the walk");
    uint8_t trunc[RW_DHCP_MSG_MAX];
    size_t  tlen = make_dhcp(trunc, sizeof(trunc), RW_DHCP_DISCOVER, NULL, 0);
    trunc[tlen - 1] = RW_DHCP_OPT_REQUESTED_IP; /* replace END with a bare code */
    RW_CHECK(rw_dhcp_parse(trunc, tlen, &req));
    RW_CHECK_EQ_INT(req.requested_ip, 0);

    rw_test_begin("pad bytes between options are skipped");
    static const uint8_t padded[] = {0, 0, 0, RW_DHCP_OPT_REQUESTED_IP, 4, 192, 168, 4, 2};
    len = make_dhcp(buf, sizeof(buf), RW_DHCP_REQUEST, padded, sizeof(padded));
    RW_CHECK(rw_dhcp_parse(buf, len, &req));
    RW_CHECK_EQ_INT(req.requested_ip, LEASE_IP);
}

static void test_dhcp_build(void) {
    uint8_t           in[RW_DHCP_MSG_MAX];
    uint8_t           out[RW_DHCP_MSG_MAX];
    rw_dhcp_request_t req;

    const rw_dhcp_reply_cfg_t cfg = {
        .server_ip   = AP_IP,
        .subnet_mask = AP_MASK,
        .offered_ip  = LEASE_IP,
        .lease_secs  = LEASE_SEC,
    };

    size_t len = make_dhcp(in, sizeof(in), RW_DHCP_DISCOVER, NULL, 0);
    RW_CHECK(rw_dhcp_parse(in, len, &req));

    rw_test_begin("an OFFER carries the address, the mask, the router, DNS and the lease");
    size_t n = rw_dhcp_build_reply(&req, &cfg, RW_DHCP_OFFER, out, sizeof(out));
    RW_CHECK(n > 0);
    RW_CHECK_EQ_INT(out[0], RW_DHCP_OP_REPLY);
    RW_CHECK_EQ_INT(out[1], 1); /* htype */
    RW_CHECK_EQ_INT(out[2], 6); /* hlen */
    RW_CHECK_EQ_INT(opt32(out + 4), 0xDEADBEEF); /* xid echoed */
    RW_CHECK_EQ_INT(opt32(out + 16), LEASE_IP);  /* yiaddr */
    RW_CHECK_EQ_MEM(out + 28, k_chaddr, sizeof(k_chaddr));
    RW_CHECK_EQ_INT(out[236], 0x63);

    uint8_t        l = 0;
    const uint8_t *v = find_opt(out, n, RW_DHCP_OPT_MSG_TYPE, &l);
    RW_CHECK(v != NULL && l == 1 && v[0] == RW_DHCP_OFFER);
    v = find_opt(out, n, RW_DHCP_OPT_SERVER_ID, &l);
    RW_CHECK(v != NULL && l == 4 && opt32(v) == AP_IP);
    v = find_opt(out, n, RW_DHCP_OPT_SUBNET_MASK, &l);
    RW_CHECK(v != NULL && opt32(v) == AP_MASK);
    v = find_opt(out, n, RW_DHCP_OPT_LEASE_TIME, &l);
    RW_CHECK(v != NULL && opt32(v) == LEASE_SEC);

    rw_test_begin("we advertise ourselves as router and DNS, which is the portal (§captive)");
    /* Every name the phone resolves must land on us, or its connectivity check never reaches
     * our HTTP server and the portal never opens by itself. */
    v = find_opt(out, n, RW_DHCP_OPT_ROUTER, &l);
    RW_CHECK(v != NULL && opt32(v) == AP_IP);
    v = find_opt(out, n, RW_DHCP_OPT_DNS, &l);
    RW_CHECK(v != NULL && opt32(v) == AP_IP);

    rw_test_begin("replies are padded to the 300-byte BOOTP minimum");
    /* Short DHCP frames are dropped by some clients and some switches, and the symptom is a
     * hotspot that appears to ignore the phone entirely. */
    RW_CHECK(n >= 300);

    rw_test_begin("an ACK is an OFFER with a different message type");
    n = rw_dhcp_build_reply(&req, &cfg, RW_DHCP_ACK, out, sizeof(out));
    RW_CHECK(n > 0);
    v = find_opt(out, n, RW_DHCP_OPT_MSG_TYPE, &l);
    RW_CHECK(v != NULL && v[0] == RW_DHCP_ACK);
    RW_CHECK_EQ_INT(opt32(out + 16), LEASE_IP);

    rw_test_begin("a NAK carries no address and no lease (RFC 2131 §4.3.2)");
    n = rw_dhcp_build_reply(&req, &cfg, RW_DHCP_NAK, out, sizeof(out));
    RW_CHECK(n > 0);
    RW_CHECK_EQ_INT(opt32(out + 16), 0); /* yiaddr */
    RW_CHECK(find_opt(out, n, RW_DHCP_OPT_LEASE_TIME, &l) == NULL);
    RW_CHECK(find_opt(out, n, RW_DHCP_OPT_SUBNET_MASK, &l) == NULL);
    /* The server id stays, so a client on a network with two servers knows whose NAK this is. */
    v = find_opt(out, n, RW_DHCP_OPT_SERVER_ID, &l);
    RW_CHECK(v != NULL && opt32(v) == AP_IP);

    rw_test_begin("only OFFER, ACK and NAK can be built");
    RW_CHECK_EQ_INT(rw_dhcp_build_reply(&req, &cfg, RW_DHCP_DISCOVER, out, sizeof(out)), 0);
    RW_CHECK_EQ_INT(rw_dhcp_build_reply(&req, &cfg, RW_DHCP_RELEASE, out, sizeof(out)), 0);

    rw_test_begin("a buffer that cannot hold a reply yields 0, never a partial packet");
    uint8_t tiny[64];
    RW_CHECK_EQ_INT(rw_dhcp_build_reply(&req, &cfg, RW_DHCP_OFFER, tiny, sizeof(tiny)), 0);
}

static void test_dhcp_reply_dest(void) {
    rw_dhcp_request_t req;
    memset(&req, 0, sizeof(req));

    rw_test_begin("a client with no address is always answered by broadcast (RFC 2131 §4.1)");
    /* It cannot receive a unicast reply whatever we put in yiaddr. Getting this wrong gives a
     * hotspot that works on one phone and silently fails on another. */
    RW_CHECK_EQ_INT(rw_dhcp_reply_dest(&req, LEASE_IP), 0xFFFFFFFFu);

    rw_test_begin("the broadcast flag wins even when the client has an address");
    req.ciaddr    = LEASE_IP;
    req.broadcast = true;
    RW_CHECK_EQ_INT(rw_dhcp_reply_dest(&req, LEASE_IP), 0xFFFFFFFFu);

    rw_test_begin("a renewing client with an address gets a unicast reply");
    req.broadcast = false;
    RW_CHECK_EQ_INT(rw_dhcp_reply_dest(&req, LEASE_IP), LEASE_IP);
}

/* ── DNS ─────────────────────────────────────────────────────────────────── */

/* Encode "a.b.c" as DNS labels into `out`. Returns the length including the root label. */
static size_t encode_name(uint8_t *out, const char *name) {
    size_t pos = 0;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t      n   = dot ? (size_t)(dot - name) : strlen(name);
        out[pos++]      = (uint8_t)n;
        memcpy(out + pos, name, n);
        pos += n;
        name = dot ? dot + 1 : name + n;
    }
    out[pos++] = 0;
    return pos;
}

static size_t make_dns(uint8_t *buf, const char *name, uint16_t qtype, uint16_t qclass,
                       uint16_t flags) {
    memset(buf, 0, RW_DNS_MSG_MAX);
    buf[0] = 0x12;
    buf[1] = 0x34; /* id */
    buf[2] = (uint8_t)(flags >> 8);
    buf[3] = (uint8_t)flags;
    buf[5] = 1; /* qdcount */

    size_t pos = RW_DNS_HEADER_LEN;
    pos += encode_name(buf + pos, name);
    buf[pos++] = (uint8_t)(qtype >> 8);
    buf[pos++] = (uint8_t)qtype;
    buf[pos++] = (uint8_t)(qclass >> 8);
    buf[pos++] = (uint8_t)qclass;
    return pos;
}

static void test_dns_parse(void) {
    uint8_t        buf[RW_DNS_MSG_MAX];
    rw_dns_query_t q;

    rw_test_begin("a captive-portal probe query parses");
    /* The name Apple's connectivity check asks for. Android uses connectivitycheck.gstatic.com
     * and Windows www.msftconnecttest.com; all three land here identically. */
    size_t len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    RW_CHECK_EQ_INT(q.id, 0x1234);
    RW_CHECK_EQ_INT(q.qtype, RW_DNS_TYPE_A);
    RW_CHECK_EQ_INT(q.qclass, RW_DNS_CLASS_IN);
    RW_CHECK(q.recursion_desired);
    RW_CHECK_EQ_INT(q.qname_off, RW_DNS_HEADER_LEN);
    RW_CHECK_EQ_INT(q.qname_len, 19); /* 7+1 + 5+1 + 3+1 + root */
    RW_CHECK_EQ_INT(q.question_len, 23);

    rw_test_begin("an AAAA query parses; the response layer decides what to do with it");
    len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_AAAA, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    RW_CHECK_EQ_INT(q.qtype, RW_DNS_TYPE_AAAA);

    rw_test_begin("responses, non-QUERY opcodes and multi-question packets are refused");
    len    = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x8000); /* QR set */
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));
    len    = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0800); /* opcode 1 */
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));
    len    = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    buf[5] = 2; /* qdcount */
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));
    buf[5] = 0;
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));

    rw_test_begin("truncation is caught at every step");
    len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(!rw_dns_parse_query(buf, RW_DNS_HEADER_LEN - 1, &q)); /* short header */
    RW_CHECK(!rw_dns_parse_query(buf, RW_DNS_HEADER_LEN, &q));     /* no question */
    RW_CHECK(!rw_dns_parse_query(buf, len - 1, &q));               /* qclass cut in half */
    RW_CHECK(!rw_dns_parse_query(buf, len - 5, &q));               /* name with no type */

    rw_test_begin("a compression pointer in a question is refused, never followed");
    /* Following pointers is the one way this parser could be made to loop forever, and a
     * pointer has no legitimate meaning in a question section. */
    len            = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    buf[RW_DNS_HEADER_LEN] = 0xC0;
    buf[RW_DNS_HEADER_LEN + 1] = 0x0C; /* points at itself */
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));

    rw_test_begin("reserved label prefixes are refused");
    len                    = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    buf[RW_DNS_HEADER_LEN] = 0x40;
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));
    buf[RW_DNS_HEADER_LEN] = 0x80;
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));

    rw_test_begin("a label that overruns the datagram is refused");
    len                    = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    buf[RW_DNS_HEADER_LEN] = 63; /* claims 63 bytes in a name that has 1 */
    RW_CHECK(!rw_dns_parse_query(buf, len, &q));

    rw_test_begin("a name longer than 255 bytes is refused");
    /* Five 63-byte labels is 320 bytes of name, comfortably past RW_DNS_NAME_MAX, and the whole
     * message still fits RW_DNS_MSG_MAX. Eight labels would overrun `buf` itself — which is
     * exactly what an earlier version of this test did, and Ubuntu's stack protector caught in
     * CI after a MinGW build without one had waved it through. */
    memset(buf, 0, sizeof(buf));
    buf[5]     = 1; /* qdcount */
    size_t pos = RW_DNS_HEADER_LEN;
    for (int i = 0; i < 5; i++) {
        buf[pos++] = 63;
        memset(buf + pos, 'a', 63);
        pos += 63;
    }
    buf[pos++] = 0;
    buf[pos++] = 0; buf[pos++] = 1; buf[pos++] = 0; buf[pos++] = 1;
    RW_CHECK(pos <= sizeof(buf));
    RW_CHECK(!rw_dns_parse_query(buf, pos, &q));
}

static void test_dns_build(void) {
    uint8_t        buf[RW_DNS_MSG_MAX];
    uint8_t        out[RW_DNS_MSG_MAX];
    rw_dns_query_t q;

    rw_test_begin("an A query is answered with the hotspot's own address");
    size_t len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    size_t n = rw_dns_build_response(buf, len, &q, AP_IP, 60, out, sizeof(out));
    RW_CHECK_EQ_INT(n, len + 16);

    RW_CHECK_EQ_INT(out[0], 0x12); /* id echoed */
    RW_CHECK_EQ_INT(out[1], 0x34);
    RW_CHECK((out[2] & 0x80) != 0); /* QR: this is a response */
    RW_CHECK((out[2] & 0x04) != 0); /* AA */
    RW_CHECK((out[2] & 0x01) != 0); /* RD reflected */
    RW_CHECK((out[3] & 0x80) != 0); /* RA */
    RW_CHECK_EQ_INT(out[5], 1);     /* qdcount */
    RW_CHECK_EQ_INT(out[7], 1);     /* ancount */
    RW_CHECK_EQ_INT(out[9], 0);     /* nscount */
    RW_CHECK_EQ_INT(out[11], 0);    /* arcount */

    rw_test_begin("the question is echoed byte-for-byte");
    RW_CHECK_EQ_MEM(out + RW_DNS_HEADER_LEN, buf + RW_DNS_HEADER_LEN, q.question_len);

    rw_test_begin("the answer uses a name pointer and carries the address");
    const uint8_t *a = out + len;
    RW_CHECK_EQ_INT(a[0], 0xC0); /* pointer to offset 12 */
    RW_CHECK_EQ_INT(a[1], 0x0C);
    RW_CHECK_EQ_INT(a[3], RW_DNS_TYPE_A);
    RW_CHECK_EQ_INT(a[5], RW_DNS_CLASS_IN);
    RW_CHECK_EQ_INT(opt32(a + 6), 60u); /* ttl */
    RW_CHECK_EQ_INT(a[11], 4);          /* rdlength */
    RW_CHECK_EQ_INT(opt32(a + 12), AP_IP);

    rw_test_begin("AAAA gets NOERROR with no answers, so dual-stack clients fall back promptly");
    /* Answering AAAA with an A record, or with NXDOMAIN, both give the same miserable symptom:
     * a captive portal that takes half a minute to appear, or never does. */
    len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_AAAA, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    n = rw_dns_build_response(buf, len, &q, AP_IP, 60, out, sizeof(out));
    RW_CHECK_EQ_INT(n, len);
    RW_CHECK_EQ_INT(out[7], 0);     /* ancount */
    RW_CHECK((out[3] & 0x0F) == 0); /* rcode NOERROR, not NXDOMAIN */

    rw_test_begin("a non-IN class is not answered either");
    len = make_dns(buf, "a.com", RW_DNS_TYPE_A, 3 /* CHAOS */, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    n = rw_dns_build_response(buf, len, &q, AP_IP, 60, out, sizeof(out));
    RW_CHECK_EQ_INT(n, len);
    RW_CHECK_EQ_INT(out[7], 0);

    rw_test_begin("RD is not claimed when the client did not ask for it");
    len = make_dns(buf, "a.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0000);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    n = rw_dns_build_response(buf, len, &q, AP_IP, 60, out, sizeof(out));
    RW_CHECK(n > 0);
    RW_CHECK((out[2] & 0x01) == 0);
    RW_CHECK((out[3] & 0x80) == 0);

    rw_test_begin("a buffer too small yields 0 rather than a truncated response");
    len = make_dns(buf, "captive.apple.com", RW_DNS_TYPE_A, RW_DNS_CLASS_IN, 0x0100);
    RW_CHECK(rw_dns_parse_query(buf, len, &q));
    uint8_t tiny[24];
    RW_CHECK_EQ_INT(rw_dns_build_response(buf, len, &q, AP_IP, 60, tiny, sizeof(tiny)), 0);
}

/* ── HTTP ────────────────────────────────────────────────────────────────── */

static rw_http_parse_t parse_http(const char *raw, rw_http_request_t *req) {
    return rw_http_parse(raw, strlen(raw), req);
}

static void test_http_parse(void) {
    rw_http_request_t r;

    rw_test_begin("a plain GET parses");
    RW_CHECK(parse_http("GET / HTTP/1.1\r\nHost: 192.168.4.1\r\n\r\n", &r) == RW_HTTP_PARSE_OK);
    RW_CHECK(r.method == RW_HTTP_GET);
    RW_CHECK_EQ_STR(r.path, "/");
    RW_CHECK_EQ_INT(r.content_length, 0);

    rw_test_begin("a POST reports its content length and where the body starts");
    const char *post = "POST /api/join HTTP/1.1\r\nHost: x\r\nContent-Length: 27\r\n"
                       "Content-Type: application/json\r\n\r\n{\"ssid\":\"A\",\"psk\":\"bcdefgh\"}";
    RW_CHECK(parse_http(post, &r) == RW_HTTP_PARSE_OK);
    RW_CHECK(r.method == RW_HTTP_POST);
    RW_CHECK_EQ_STR(r.path, "/api/join");
    RW_CHECK_EQ_INT(r.content_length, 27);
    RW_CHECK_EQ_STR(post + r.header_len, "{\"ssid\":\"A\",\"psk\":\"bcdefgh\"}");

    rw_test_begin("header names are case-insensitive, values may be padded");
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nCONTENT-LENGTH:   5  \r\n\r\nabcde", &r) ==
             RW_HTTP_PARSE_OK);
    RW_CHECK_EQ_INT(r.content_length, 5);

    rw_test_begin("Accept-Encoding decides whether we may compress (RFC 9110)");
    /*
     * This is why the captive-portal sheet would not open. The portal is stored gzipped and was
     * served with Content-Encoding: gzip unconditionally — fine for browsers, which always ask
     * for it, and fatal for Apple's probe client, which sends no Accept-Encoding at all and got
     * back a body it could not decode. It concluded the network was broken rather than captive.
     */
    RW_CHECK(parse_http("GET / HTTP/1.1\r\nAccept-Encoding: gzip, deflate\r\n\r\n", &r) ==
             RW_HTTP_PARSE_OK);
    RW_CHECK(r.accepts_gzip);
    RW_CHECK(parse_http("GET / HTTP/1.1\r\naccept-encoding: GZIP\r\n\r\n", &r) ==
             RW_HTTP_PARSE_OK);
    RW_CHECK(r.accepts_gzip);
    RW_CHECK(parse_http("GET / HTTP/1.1\r\nAccept-Encoding: br, gzip;q=0.8\r\n\r\n", &r) ==
             RW_HTTP_PARSE_OK);
    RW_CHECK(r.accepts_gzip);

    rw_test_begin("no Accept-Encoding means no compression, which is the probe's case");
    RW_CHECK(parse_http("GET /hotspot-detect.html HTTP/1.1\r\nHost: captive.apple.com\r\n\r\n",
                        &r) == RW_HTTP_PARSE_OK);
    RW_CHECK(!r.accepts_gzip);
    RW_CHECK(parse_http("GET / HTTP/1.1\r\nAccept-Encoding: deflate, br\r\n\r\n", &r) ==
             RW_HTTP_PARSE_OK);
    RW_CHECK(!r.accepts_gzip);

    rw_test_begin("an unterminated head is incomplete, not an error");
    /* The caller feeds a growing buffer, so "not yet" has to be distinguishable from "no". */
    RW_CHECK(parse_http("GET / HTTP/1.1\r\nHost: x\r\n", &r) == RW_HTTP_PARSE_INCOMPLETE);
    RW_CHECK(parse_http("GE", &r) == RW_HTTP_PARSE_INCOMPLETE);

    rw_test_begin("the query string is dropped from the path");
    RW_CHECK(parse_http("GET /api/scan?t=123 HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_OK);
    RW_CHECK_EQ_STR(r.path, "/api/scan");

    rw_test_begin("percent escapes in the path are resolved");
    RW_CHECK(parse_http("GET /a%2Fb%20c HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_OK);
    RW_CHECK_EQ_STR(r.path, "/a/b c");

    rw_test_begin("methods we do not implement still parse, so they can be answered 405");
    RW_CHECK(parse_http("PUT / HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_OK);
    RW_CHECK(r.method == RW_HTTP_METHOD_UNKNOWN);
    RW_CHECK(parse_http("HEAD / HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_OK);
    RW_CHECK(r.method == RW_HTTP_HEAD);

    rw_test_begin("malformed request lines are refused");
    RW_CHECK(parse_http("GET\r\n\r\n", &r) == RW_HTTP_PARSE_BAD);
    RW_CHECK(parse_http("GET /\r\n\r\n", &r) == RW_HTTP_PARSE_BAD);      /* no version */
    RW_CHECK(parse_http("GET  HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_BAD); /* empty target */

    rw_test_begin("an absolute-form target is refused, not normalised");
    /* Accepting `GET http://evil/ HTTP/1.1` would make the portal an open redirector on
     * somebody's LAN. It is legal for proxies and meaningless for us. */
    RW_CHECK(parse_http("GET http://example.com/ HTTP/1.1\r\n\r\n", &r) == RW_HTTP_PARSE_BAD);

    rw_test_begin("Transfer-Encoding is refused outright (request smuggling)");
    /* A request carrying both Transfer-Encoding and Content-Length is the classic smuggling
     * primitive; we support neither chunked bodies nor the ambiguity. */
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &r) ==
             RW_HTTP_PARSE_BAD);
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nContent-Length: 5\r\n"
                        "Transfer-Encoding: chunked\r\n\r\n", &r) == RW_HTTP_PARSE_BAD);

    rw_test_begin("a Content-Length that is not purely digits is refused");
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nContent-Length: +5\r\n\r\n", &r) ==
             RW_HTTP_PARSE_BAD);
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nContent-Length: 5 6\r\n\r\n", &r) ==
             RW_HTTP_PARSE_BAD);
    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nContent-Length: abc\r\n\r\n", &r) ==
             RW_HTTP_PARSE_BAD);

    rw_test_begin("oversized requests are refused rather than truncated");
    char big[RW_HTTP_HEADERS_MAX + 64];
    memset(big, 'a', sizeof(big));
    big[sizeof(big) - 1] = '\0';
    RW_CHECK(rw_http_parse(big, sizeof(big) - 1, &r) == RW_HTTP_PARSE_TOO_LARGE);

    char longpath[RW_HTTP_PATH_MAX + 64];
    int  n = snprintf(longpath, sizeof(longpath), "GET /");
    memset(longpath + n, 'p', RW_HTTP_PATH_MAX + 4);
    snprintf(longpath + n + RW_HTTP_PATH_MAX + 4, 24, " HTTP/1.1\r\n\r\n");
    RW_CHECK(parse_http(longpath, &r) == RW_HTTP_PARSE_TOO_LARGE);

    RW_CHECK(parse_http("POST /x HTTP/1.1\r\nContent-Length: 99999\r\n\r\n", &r) ==
             RW_HTTP_PARSE_TOO_LARGE);
}

static void test_http_percent_decode(void) {
    char out[64];

    rw_test_begin("percent decoding handles the ordinary cases");
    RW_CHECK(rw_http_percent_decode("abc", 3, out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "abc");
    RW_CHECK(rw_http_percent_decode("a%41b", 5, out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "aAb");
    RW_CHECK(rw_http_percent_decode("%c3%a9", 6, out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "\xC3\xA9"); /* é, lower-case hex */

    rw_test_begin("a plus is left alone, because this decodes paths and not form bodies");
    /* Turning '+' into a space here would quietly corrupt any value carrying one. */
    RW_CHECK(rw_http_percent_decode("a+b", 3, out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "a+b");

    rw_test_begin("malformed escapes are refused, not repaired");
    RW_CHECK(!rw_http_percent_decode("%", 1, out, sizeof(out)));
    RW_CHECK(!rw_http_percent_decode("%4", 2, out, sizeof(out)));
    RW_CHECK(!rw_http_percent_decode("%zz", 3, out, sizeof(out)));
    RW_CHECK(!rw_http_percent_decode("a%2", 3, out, sizeof(out)));

    rw_test_begin("%00 is refused rather than silently truncating the path");
    /* It would end the string against every downstream strcmp while leaving bytes after it —
     * which is how a route check gets bypassed. */
    RW_CHECK(!rw_http_percent_decode("/a%00/b", 7, out, sizeof(out)));

    rw_test_begin("a result that does not fit is refused");
    char tiny[4];
    RW_CHECK(!rw_http_percent_decode("abcdefgh", 8, tiny, sizeof(tiny)));
}

static void test_http_probes(void) {
    rw_test_begin("every OS connectivity check is recognised");
    /* Each of these expects a specific successful answer. Giving it one means the OS decides
     * the network is fine and never offers to open the portal. */
    RW_CHECK(rw_http_is_captive_probe("/generate_204"));      /* Android */
    RW_CHECK(rw_http_is_captive_probe("/gen_204"));
    RW_CHECK(rw_http_is_captive_probe("/hotspot-detect.html")); /* iOS, macOS */
    RW_CHECK(rw_http_is_captive_probe("/library/test/success.html"));
    RW_CHECK(rw_http_is_captive_probe("/success.txt"));       /* Firefox */
    RW_CHECK(rw_http_is_captive_probe("/canonical.html"));    /* Ubuntu */
    RW_CHECK(rw_http_is_captive_probe("/connecttest.txt"));   /* Windows */
    RW_CHECK(rw_http_is_captive_probe("/ncsi.txt"));

    rw_test_begin("our own routes are not mistaken for probes");
    RW_CHECK(!rw_http_is_captive_probe("/"));
    RW_CHECK(!rw_http_is_captive_probe("/api/scan"));
    RW_CHECK(!rw_http_is_captive_probe("/generate_204x"));
    RW_CHECK(!rw_http_is_captive_probe("/generate_20"));
    RW_CHECK(rw_http_probe_kind("/") == RW_PROBE_NONE);

    rw_test_begin("Apple's probes are answered inline, everyone else's by redirect");
    /*
     * The Captive Network Assistant judges the probe response itself, so a 200 that does not say
     * "Success" opens the sheet at once. Handed a redirect it must fetch and evaluate a second
     * URL first, and losing that race is what makes the portal appear on the second join but not
     * the first. Android and Windows treat the redirect as the definitive signal, so they keep
     * it — answering *them* inline would be the same mistake in reverse.
     */
    RW_CHECK(rw_http_probe_kind("/hotspot-detect.html") == RW_PROBE_INLINE);
    RW_CHECK(rw_http_probe_kind("/library/test/success.html") == RW_PROBE_INLINE);
    RW_CHECK(rw_http_probe_kind("/Library/test/success.html") == RW_PROBE_INLINE);

    RW_CHECK(rw_http_probe_kind("/generate_204") == RW_PROBE_REDIRECT);
    RW_CHECK(rw_http_probe_kind("/gen_204") == RW_PROBE_REDIRECT);
    RW_CHECK(rw_http_probe_kind("/connecttest.txt") == RW_PROBE_REDIRECT);
    RW_CHECK(rw_http_probe_kind("/ncsi.txt") == RW_PROBE_REDIRECT);
    RW_CHECK(rw_http_probe_kind("/success.txt") == RW_PROBE_REDIRECT);
    RW_CHECK(rw_http_probe_kind("/canonical.html") == RW_PROBE_REDIRECT);
}

void test_provisioning(void) {
    test_dhcp_parse();
    test_dhcp_build();
    test_dhcp_reply_dest();
    test_dns_parse();
    test_dns_build();
    test_http_parse();
    test_http_percent_decode();
    test_http_probes();
}
