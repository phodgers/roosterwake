/*
 * The UDP half of the captive-portal DNS responder. Message handling is in dns_msg.c.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_DNSSERVER_H
#define RW_DNSSERVER_H

#include <stdbool.h>
#include <stdint.h>

/*
 * A short TTL, deliberately.
 *
 * Every name resolves to the hotspot while setup is running, and those answers must not outlive
 * it. A phone that cached "google.com is 192.168.4.1" for an hour would be broken on its real
 * network long after the dongle had gone.
 */
#define RW_DNS_TTL_SECS 5

/* Answer every A query with `answer_ip` (host byte order). */
bool rw_dnsserver_start(uint32_t answer_ip);

void rw_dnsserver_stop(void);

#endif /* RW_DNSSERVER_H */
