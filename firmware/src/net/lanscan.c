/*
 * Who else is on this segment. See lanscan.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/lanscan.h"

#include <string.h>

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/udp.h"
#include "pico/time.h"

#include "net/mdns.h"
#include "net/nbns.h"
#include "rw_log.h"
#include "sys/sys.h"

/*
 * Requests sent between drains of the ARP table.
 *
 * lwIP's table is ARP_TABLE_SIZE entries and a reply displaces the oldest once it is full, so
 * results have to be collected as they arrive rather than read once at the end. Small batches also
 * keep the pbuf pool from being emptied faster than the driver can send.
 */
#define PROBES_PER_BATCH 4

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
    c->out[at].name[0] = '\0';
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

/* ── Names ───────────────────────────────────────────────────────────────────
 *
 * The sweep produces addresses, which nobody can pick their own machine out of. Two name
 * queries go to each host that answered, because the population splits cleanly in two: a node
 * status query names Windows and Samba, and an mDNS reverse lookup names macOS, desktop Linux
 * (Avahi answers by default on the mainstream distributions) and most phones. Both passes share
 * one wait window, so the second protocol costs no extra time.
 *
 * When a host answers both — modern Windows speaks mDNS too — the NBNS name wins: it is the
 * name the machine is registered under rather than a hostname label, and keeping the rule
 * deterministic means a rescan cannot flip a row's name with arrival order.
 */

/* Long enough for a reply to cross a home network and back, short enough that a list of silent
 * devices does not double the time the sweep takes. */
#define NAME_WAIT_MS 1200
#define NBNS_PORT 137

/* Transaction ids for the two queries; arbitrary, echoed back, and checked on parse. */
#define NBNS_TXID 0x5257
#define MDNS_TXID 0x524d

/* The row this reply belongs to. Matched by address, not by arrival order: replies come back in
 * whatever order the network delivers them. */
static rw_lan_host_t *host_for(collector_t *c, const ip_addr_t *addr) {
    for (int i = 0; i < c->count; i++) {
        if (ip4_addr_get_u32(&c->out[i].ip) == ip_addr_get_ip4_u32(addr)) {
            return &c->out[i];
        }
    }
    return NULL;
}

static void on_nbns(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
                    u16_t port) {
    (void)pcb;
    (void)port;
    collector_t *c = (collector_t *)arg;
    if (p == NULL) {
        return;
    }

    /* Flattened before parsing: a datagram can arrive as a chain, and the parser reads it as one
     * buffer. Anything longer than this is not a node status response worth reading. */
    uint8_t buf[320];
    const uint16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    pbuf_free(p);

    char name[RW_NBNS_NAME_LEN];
    if (c == NULL || addr == NULL || !rw_nbns_parse_name(buf, n, name, sizeof(name))) {
        return;
    }

    rw_lan_host_t *h = host_for(c, addr);
    if (h != NULL) {
        /* Unconditional: the NBNS name outranks whatever the mDNS pass may have written. */
        memcpy(h->name, name, sizeof(name));
    }
}

static void on_mdns(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
                    u16_t port) {
    (void)pcb;
    (void)port;
    collector_t *c = (collector_t *)arg;
    if (p == NULL) {
        return;
    }

    /* A reverse-lookup response is one PTR record and maybe an A record; anything longer than
     * this is answering a different kind of question. */
    uint8_t buf[512];
    const uint16_t n = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    pbuf_free(p);

    if (c == NULL || addr == NULL) {
        return;
    }

    /* The parser checks the answer is for the sender's own reverse name, so the octets come
     * from the address the datagram arrived from — the one thing about it that is hard to get
     * wrong. */
    const uint8_t ip[4] = {
        ip4_addr1_val(*ip_2_ip4(addr)),
        ip4_addr2_val(*ip_2_ip4(addr)),
        ip4_addr3_val(*ip_2_ip4(addr)),
        ip4_addr4_val(*ip_2_ip4(addr)),
    };

    char name[RW_MDNS_NAME_LEN];
    if (!rw_mdns_parse_name(buf, n, MDNS_TXID, ip, name, sizeof(name))) {
        return;
    }

    rw_lan_host_t *h = host_for(c, addr);
    if (h != NULL && h->name[0] == '\0') {
        /* Blanks only: an NBNS name that arrived first is the registered one and keeps. */
        memcpy(h->name, name, sizeof(name));
    }
}

/* One length-prefixed datagram to one host, sent and forgotten. */
static void send_query(struct udp_pcb *pcb, const uint8_t *query, size_t qlen,
                       const ip4_addr_t *ip, uint16_t port) {
    if (qlen == 0) {
        return;
    }
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)qlen, PBUF_RAM);
    if (p == NULL) {
        return;
    }
    memcpy(p->payload, query, qlen);
    ip_addr_t dst;
    ip_addr_copy_from_ip4(dst, *ip);
    udp_sendto(pcb, p, &dst, port);
    pbuf_free(p);
}

/* A socket with its callback attached, or NULL. Any local port: the reply comes back to
 * whatever this was bound to — which for mDNS marks the query as a legacy unicast one, exactly
 * the kind RFC 6762 §6.7 obliges a responder to answer directly. */
static struct udp_pcb *name_socket(udp_recv_fn on_reply, collector_t *c) {
    struct udp_pcb *pcb = udp_new();
    if (pcb == NULL) {
        return NULL;
    }
    if (udp_bind(pcb, IP_ADDR_ANY, 0) != ERR_OK) {
        udp_remove(pcb);
        return NULL;
    }
    udp_recv(pcb, on_reply, c);
    return pcb;
}

static void resolve_names(collector_t *c) {
    if (c->count == 0) {
        return;
    }
    struct udp_pcb *nbns = name_socket(on_nbns, c);
    struct udp_pcb *mdns = name_socket(on_mdns, c);
    if (nbns == NULL && mdns == NULL) {
        return;
    }

    uint8_t      nbns_query[64];
    const size_t nbns_len = rw_nbns_build_query(nbns_query, sizeof(nbns_query), NBNS_TXID);

    for (int i = 0; i < c->count; i++) {
        if (nbns != NULL) {
            send_query(nbns, nbns_query, nbns_len, &c->out[i].ip, NBNS_PORT);
        }
        if (mdns != NULL) {
            /* Built per host: the question names the host's own address. */
            const uint8_t ip[4] = {
                ip4_addr1_val(c->out[i].ip),
                ip4_addr2_val(c->out[i].ip),
                ip4_addr3_val(c->out[i].ip),
                ip4_addr4_val(c->out[i].ip),
            };
            uint8_t      mdns_query[64];
            const size_t mdns_len = rw_mdns_build_query(mdns_query, sizeof(mdns_query),
                                                        MDNS_TXID, ip);
            send_query(mdns, mdns_query, mdns_len, &c->out[i].ip, RW_MDNS_PORT);
        }
        rw_sys_pump_ms(5);
    }

    const absolute_time_t until = make_timeout_time_ms(NAME_WAIT_MS);
    while (!time_reached(until)) {
        rw_sys_pump_ms(50);
    }

    /* Removed before returning: the callbacks hold a pointer to a collector that lives on the
     * caller's stack, and a late datagram after this returns would write through it. */
    if (nbns != NULL) {
        udp_remove(nbns);
    }
    if (mdns != NULL) {
        udp_remove(mdns);
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
    uint32_t              refused  = 0;

    for (uint32_t addr = network + 1; addr < broadcast; addr++) {
        if (probes >= RW_LAN_SCAN_MAX_PROBES || time_reached(deadline)) {
            break;
        }
        if (addr == self) {
            continue; /* asking ourselves proves nothing and does not reply */
        }

        ip4_addr_t target;
        ip4_addr_set_u32(&target, lwip_htonl(addr));

        /*
         * A request that could not be allocated was never sent, and a host that was never asked
         * is indistinguishable in the result from one that stayed silent. Every address gets one
         * retry after the stack has been given time to return the pbufs it is holding; what is
         * still refused after that is counted, because a sweep that quietly skipped a third of
         * the subnet otherwise looks exactly like a quiet network.
         */
        if (etharp_request(nif, &target) != ERR_OK) {
            rw_sys_pump_ms(BATCH_PUMP_MS);
            drain(&c);
            batch = 0;
            if (etharp_request(nif, &target) != ERR_OK) {
                refused++;
                continue;
            }
        }
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

    resolve_names(&c);

    if (refused > 0) {
        /* Out of pbufs twice over for these, so they were never asked. Warned rather than logged
         * at info: the count is the difference between "nothing is there" and "we did not look". */
        RW_LOG_WARN("lanscan: %lu address(es) could not be probed", (unsigned long)refused);
    }
    RW_LOG_INFO("lanscan: probed %lu address(es), %d answered", (unsigned long)probes, c.count);
    return c.count;
}
