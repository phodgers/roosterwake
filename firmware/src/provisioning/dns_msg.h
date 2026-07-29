/*
 * DNS query parsing and response construction for the captive-portal resolver.
 *
 * Written from scratch so firmware/ stays uniformly MIT. It is not a resolver: it answers every
 * A query with the hotspot's own address, which is what makes a phone's connectivity check land
 * on our HTTP server and open the portal by itself.
 *
 * No lwIP and no SDK, so the label walker and the response encoder are covered by the host
 * tests — which matters more here than almost anywhere else in the firmware, because this
 * parses unauthenticated input from anything in radio range and DNS name compression is a
 * classic way to walk a parser off the end of a buffer or into a loop.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_DNS_MSG_H
#define RW_DNS_MSG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RW_DNS_PORT       53
#define RW_DNS_HEADER_LEN 12

/* A phone's captive-portal probe asks for one short name. 512 is the classic UDP DNS limit and
 * far more than we ever need to emit. */
#define RW_DNS_MSG_MAX 512

/* Longest name we will echo back, per RFC 1035 §2.3.4. */
#define RW_DNS_NAME_MAX 255

#define RW_DNS_TYPE_A    1
#define RW_DNS_TYPE_AAAA 28
#define RW_DNS_CLASS_IN  1

typedef struct {
    uint16_t id;
    uint16_t qtype;
    uint16_t qclass;
    bool     recursion_desired;
    /* Offset and length of the QNAME within the request, so a reply can echo the question
     * byte-for-byte without decoding and re-encoding it. */
    size_t   qname_off;
    size_t   qname_len;
    /* The whole question section, QNAME + QTYPE + QCLASS. */
    size_t   question_len;
} rw_dns_query_t;

/*
 * Parse a standard query.
 *
 * Returns false for anything that is not one: a response rather than a query, an opcode other
 * than QUERY, qdcount != 1, a truncated header, a label longer than 63 bytes, a name longer
 * than 255, or a compression pointer. Compression is refused outright rather than followed —
 * it is meaningless in a question section, and following pointers is exactly how this kind of
 * parser is made to loop forever.
 */
bool rw_dns_parse_query(const uint8_t *buf, size_t len, rw_dns_query_t *out);

/*
 * Build the response.
 *
 * An A question in class IN is answered with `answer_ip`. Anything else — AAAA above all —
 * gets NOERROR with no answers, which is what makes a dual-stack phone fall back to IPv4
 * promptly. Answering an AAAA query with an A record, or with NXDOMAIN, both produce the same
 * miserable symptom: a captive portal that takes thirty seconds to appear, or never does.
 *
 * Returns the length written, or 0 if it does not fit.
 */
size_t rw_dns_build_response(const uint8_t *request, size_t request_len,
                             const rw_dns_query_t *query, uint32_t answer_ip, uint32_t ttl,
                             uint8_t *out, size_t out_len);

#endif /* RW_DNS_MSG_H */
