/*
 * Last-known addresses for MACs seen on this segment. See arplearn.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/arplearn.h"

#include <string.h>

#include "lwip/etharp.h"
#include "pico/time.h"

typedef struct {
    uint8_t    mac[6];
    ip4_addr_t ip;
    uint32_t   seen_at_s; /* seconds since boot; used only to pick a victim when full */
    bool       valid;
} entry_t;

static entry_t         s_entries[RW_ARPLEARN_ENTRIES];
static absolute_time_t s_next_sample;

static void remember(const uint8_t mac[6], const ip4_addr_t *ip, uint32_t now_s) {
    int oldest = 0;
    for (int i = 0; i < RW_ARPLEARN_ENTRIES; i++) {
        if (s_entries[i].valid && memcmp(s_entries[i].mac, mac, 6) == 0) {
            s_entries[i].ip        = *ip;
            s_entries[i].seen_at_s = now_s;
            return;
        }
        if (!s_entries[i].valid) {
            oldest = i;
            break;
        }
        if (s_entries[i].seen_at_s < s_entries[oldest].seen_at_s) {
            oldest = i;
        }
    }
    memcpy(s_entries[oldest].mac, mac, 6);
    s_entries[oldest].ip        = *ip;
    s_entries[oldest].seen_at_s = now_s;
    s_entries[oldest].valid     = true;
}

void rw_arp_learn_tick(void) {
    if (!time_reached(s_next_sample)) {
        return;
    }
    s_next_sample = make_timeout_time_ms(1000);

    const uint32_t now_s = (uint32_t)(to_us_since_boot(get_absolute_time()) / 1000000u);

    for (size_t i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t      *ip  = NULL;
        struct netif    *nif = NULL;
        struct eth_addr *mac = NULL;
        if (!etharp_get_entry(i, &ip, &nif, &mac) || ip == NULL || mac == NULL) {
            continue;
        }
        if (ip4_addr_get_u32(ip) == 0) {
            continue;
        }
        remember(mac->addr, ip, now_s);
    }
}

bool rw_arp_lookup(const uint8_t mac[6], ip4_addr_t *out) {
    for (int i = 0; i < RW_ARPLEARN_ENTRIES; i++) {
        if (s_entries[i].valid && memcmp(s_entries[i].mac, mac, 6) == 0) {
            *out = s_entries[i].ip;
            return true;
        }
    }
    return false;
}
