/*
 * mDNS reverse lookup, which is how a Mac or a Linux box tells you its name.
 *
 * The sweep's NBNS pass names Windows and Samba and nothing else — macOS, iOS, Android and
 * desktop Linux answer multicast DNS instead. Their responders also answer a plain unicast
 * query sent to port 5353 (RFC 6762 §6.7 calls these legacy queries and requires an answer),
 * so the same per-host pattern as NBNS works: ask each address that answered the ARP sweep for
 * the PTR record of its own reverse name, and the ones running a responder say who they are.
 *
 * Windows answers mDNS too these days, so a host may answer both passes; the NBNS name wins in
 * the collector because it is the name the machine registered rather than derived.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_MDNS_H
#define RW_MDNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * One label of a hostname, truncated to fit. mDNS hostnames run longer than NetBIOS's fifteen
 * characters ("Phils-MacBook-Pro" is seventeen), and the label limit is sixty-three — but the
 * name is for picking a machine out of a list of two dozen, and thirty-one characters do that.
 */
#define RW_MDNS_NAME_LEN 32

/* mDNS answers arrive on the same socket the query left from, so the port matters to callers. */
#define RW_MDNS_PORT 5353

/*
 * Build a reverse PTR query for `ip` (network byte order, so ip[0] is the first octet) into
 * `buf`. Returns the length written, or 0 if `cap` is too small.
 */
size_t rw_mdns_build_query(uint8_t *buf, size_t cap, uint16_t txid, const uint8_t ip[4]);

/*
 * Pull the machine's name out of a reverse-lookup response: the first label of the PTR target,
 * so "study-pc.local" comes out as "study-pc".
 *
 * Returns false for anything that is not a well-formed response to OUR question — a truncated
 * datagram, a wrong transaction id, an answer whose owner is not the reverse name of `ip`, a
 * label that is not printable ASCII. This parses input from an unauthenticated device on the
 * same network and hands the result to a browser, so it rejects rather than repairs; the one
 * repair it performs is truncating a long label to fit `out`, because a machine with a long
 * name is still a machine somebody needs to pick out of the list. Non-ASCII names are rejected
 * outright rather than mangled — that machine simply stays nameless.
 *
 * `out` must be at least RW_MDNS_NAME_LEN bytes.
 */
bool rw_mdns_parse_name(const uint8_t *pkt, size_t len, uint16_t txid, const uint8_t ip[4],
                        char *out, size_t out_len);

#endif /* RW_MDNS_H */
