/*
 * NetBIOS node status, which is how a Windows machine tells you its name.
 *
 * A LAN sweep produces addresses, and an address does not tell anybody which of eight rows is
 * their PC. A node status query — a UDP datagram to port 137 asking for the wildcard name — is
 * answered by Windows, and by Samba, with the list of names that host is registered under. The
 * first unique name with suffix 0x00 is the computer name.
 *
 * Only those two answer. macOS, iOS and Android use mDNS instead and stay silent, which suits
 * this purpose: the machines that answer are the machines wake-on-LAN is for.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_NBNS_H
#define RW_NBNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* NetBIOS names are 15 characters and a one-byte suffix. */
#define RW_NBNS_NAME_LEN 16

/* Build a node status request for the wildcard name into `buf`. Returns the length written, or 0
 * if `cap` is too small. */
size_t rw_nbns_build_query(uint8_t *buf, size_t cap, uint16_t txid);

/*
 * Pull the computer name out of a node status response.
 *
 * Returns false for anything that is not a well-formed response carrying a usable name — a
 * truncated datagram, a reply to a different question, a name that is not printable ASCII. This
 * parses input from an unauthenticated device on the same network and hands the result to a
 * browser, so it rejects rather than repairs.
 *
 * `out` must be at least RW_NBNS_NAME_LEN bytes.
 */
bool rw_nbns_parse_name(const uint8_t *pkt, size_t len, char *out, size_t out_len);

#endif /* RW_NBNS_H */
