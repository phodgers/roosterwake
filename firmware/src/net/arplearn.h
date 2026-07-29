/*
 * Last-known addresses for MACs seen on this segment.
 *
 * lwIP's ARP cache is the only place a device like this can learn where a target sits, and it
 * ages entries out in minutes. Two features need an address that outlives that: the
 * WOL_UNICAST config flag, and `probe`, which cannot send an ARP request to an address it does
 * not have. So the cache is sampled periodically and what it held is remembered.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_ARPLEARN_H
#define RW_ARPLEARN_H

#include <stdbool.h>
#include <stdint.h>

#include "lwip/ip_addr.h"

/* One per configurable target, which is the only reason any of these addresses matter. */
#define RW_ARPLEARN_ENTRIES 8

/*
 * Sample lwIP's ARP table and record what it holds. Rate-limited internally to once a second;
 * safe and cheap to call every loop iteration.
 */
void rw_arp_learn_tick(void);

/* Last address seen for `mac`. False if it has never been seen since boot. */
bool rw_arp_lookup(const uint8_t mac[6], ip4_addr_t *out);

#endif /* RW_ARPLEARN_H */
