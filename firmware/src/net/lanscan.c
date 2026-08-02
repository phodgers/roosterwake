/*
 * Who else is on this segment. See lanscan.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/lanscan.h"

#include <string.h>

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "pico/time.h"

#include "rw_log.h"
#include "sys/sys.h"

/*
 * Requests sent between drains of the ARP table.
 *
 * lwIP's table is ARP_TABLE_SIZE entries and a reply displaces the oldest once it is full, so
 * results have to be collected as they arrive rather than read once at the end. Small batches also
 * keep the pbuf pool from being emptied faster than the driver can send.
 */
#define PROBES_PER_BATCH 8

/* Pumped after each batch. Long enough for the driver to send what was queued and for replies from
 * the previous batch to land. */
#define BATCH_PUMP_MS 20

/* Kept pumping after the last request, because the furthest host has not answered yet when the
 * sweep finishes sending. */
#define SETTLE_MS 1200

typedef struct {
    rw_lan_host_t *out;
    int            max;
    int            count;
} collector_t;

/* Already have this MAC? A host answers once, but a drain can see the same stable entry twice. */
static bool known(const collector_t *c, const uint8_t mac[6]) {
    for (int i = 0; i < c->count; i++) {
        if (memcmp(c->out[i].mac, mac, 6) == 0) {
            return true;
        }
    }
    return false;
}

/* Insertion by address, so the list reads like a network rather than like arrival order. */
static void insert(collector_t *c, const ip4_addr_t *ip, const uint8_t mac[6]) {
    if (c->count >= c->max || known(c, mac)) {
        return;
    }
    const uint32_t key = lwip_ntohl(ip4_addr_get_u32(ip));
    int            at  = c->count;
    while (at > 0 && lwip_ntohl(ip4_addr_get_u32(&c->out[at - 1].ip)) > key) {
        c->out[at] = c->out[at - 1];
        at--;
    }
    c->out[at].ip = *ip;
    memcpy(c->out[at].mac, mac, 6);
    c->count++;
}

/* Take everything stable out of lwIP's table. Entries still PENDING are hosts that have not
 * answered, and etharp_get_entry does not return them. */
static void drain(collector_t *c) {
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
        insert(c, ip, mac->addr);
    }
}

int rw_lan_scan(rw_lan_host_t *out, int max) {
    struct netif *nif = netif_default;
    if (nif == NULL || max <= 0) {
        return RW_LAN_SCAN_ERR_NOT_JOINED;
    }

    const uint32_t self = lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(nif)));
    const uint32_t mask = lwip_ntohl(ip4_addr_get_u32(netif_ip4_netmask(nif)));
    if (self == 0 || mask == 0) {
        return RW_LAN_SCAN_ERR_NOT_JOINED;
    }

    /* Network and broadcast are not hosts, so the sweep runs strictly between them. */
    const uint32_t network   = self & mask;
    const uint32_t broadcast = network | ~mask;

    collector_t c = {.out = out, .max = max, .count = 0};

    const absolute_time_t deadline = make_timeout_time_ms(RW_LAN_SCAN_BUDGET_MS);
    uint32_t              probes   = 0;
    uint32_t              batch    = 0;

    for (uint32_t addr = network + 1; addr < broadcast; addr++) {
        if (probes >= RW_LAN_SCAN_MAX_PROBES || time_reached(deadline)) {
            break;
        }
        if (addr == self) {
            continue; /* asking ourselves proves nothing and does not reply */
        }

        ip4_addr_t target;
        ip4_addr_set_u32(&target, lwip_htonl(addr));
        etharp_request(nif, &target);
        probes++;

        if (++batch >= PROBES_PER_BATCH) {
            batch = 0;
            rw_sys_pump_ms(BATCH_PUMP_MS);
            drain(&c);
        }
    }

    /* The last requests are still in flight. */
    const absolute_time_t settle = make_timeout_time_ms(SETTLE_MS);
    while (!time_reached(settle) && !time_reached(deadline)) {
        rw_sys_pump_ms(50);
        drain(&c);
    }

    RW_LOG_INFO("lanscan: probed %lu address(es), %d answered", (unsigned long)probes, c.count);
    return c.count;
}
