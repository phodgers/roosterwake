/*
 * DHCP server socket and lease table. See dhcpserver.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/dhcpserver.h"

#include <string.h>

#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "pico/time.h"

#include "provisioning/dhcp_msg.h"
#include "rw_log.h"

typedef struct {
    uint8_t         mac[16];
    uint8_t         hlen;
    uint32_t        ip;
    absolute_time_t expiry;
    bool            used;
} lease_t;

static struct udp_pcb *s_pcb;
static lease_t         s_leases[RW_DHCP_LEASES];
static uint32_t        s_server_ip;
static uint32_t        s_netmask;

static bool mac_eq(const lease_t *l, const uint8_t *mac, uint8_t hlen) {
    return l->hlen == hlen && memcmp(l->mac, mac, hlen) == 0;
}

static void expire_stale(void) {
    absolute_time_t now = get_absolute_time();
    for (int i = 0; i < RW_DHCP_LEASES; i++) {
        if (s_leases[i].used && absolute_time_diff_us(now, s_leases[i].expiry) < 0) {
            s_leases[i].used = false;
        }
    }
}

/*
 * Find or create a lease for this client.
 *
 * A client that comes back gets the address it had, which is what makes a phone's DHCP renewal
 * a no-op rather than a reshuffle mid-setup. Returns 0 if the table is full.
 */
static uint32_t lease_for(const uint8_t *mac, uint8_t hlen) {
    expire_stale();

    for (int i = 0; i < RW_DHCP_LEASES; i++) {
        if (s_leases[i].used && mac_eq(&s_leases[i], mac, hlen)) {
            s_leases[i].expiry = make_timeout_time_ms(RW_DHCP_LEASE_SECS * 1000);
            return s_leases[i].ip;
        }
    }
    for (int i = 0; i < RW_DHCP_LEASES; i++) {
        if (!s_leases[i].used) {
            s_leases[i].used = true;
            s_leases[i].hlen = hlen;
            memset(s_leases[i].mac, 0, sizeof(s_leases[i].mac));
            memcpy(s_leases[i].mac, mac, hlen > sizeof(s_leases[i].mac) ? sizeof(s_leases[i].mac)
                                                                        : hlen);
            /* server_ip + 1 + index, which stays inside the mask for any sane prefix. */
            s_leases[i].ip     = s_server_ip + 1u + (uint32_t)i;
            s_leases[i].expiry = make_timeout_time_ms(RW_DHCP_LEASE_SECS * 1000);
            return s_leases[i].ip;
        }
    }
    return 0;
}

static void release_lease(const uint8_t *mac, uint8_t hlen) {
    for (int i = 0; i < RW_DHCP_LEASES; i++) {
        if (s_leases[i].used && mac_eq(&s_leases[i], mac, hlen)) {
            s_leases[i].used = false;
            return;
        }
    }
}

static void send_reply(const rw_dhcp_request_t *req, rw_dhcp_type_t type, uint32_t offered) {
    const rw_dhcp_reply_cfg_t cfg = {
        .server_ip   = s_server_ip,
        .subnet_mask = s_netmask,
        .offered_ip  = offered,
        .lease_secs  = RW_DHCP_LEASE_SECS,
    };

    uint8_t out[RW_DHCP_MSG_MAX];
    size_t  n = rw_dhcp_build_reply(req, &cfg, type, out, sizeof(out));
    if (n == 0) {
        RW_LOG_ERROR("dhcp: could not build reply");
        return;
    }

    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)n, PBUF_RAM);
    if (p == NULL) {
        return;
    }
    memcpy(p->payload, out, n);

    uint32_t dest = rw_dhcp_reply_dest(req, offered);
    ip_addr_t addr;
    IP4_ADDR(&addr, (uint8_t)(dest >> 24), (uint8_t)(dest >> 16), (uint8_t)(dest >> 8),
             (uint8_t)dest);

    udp_sendto(s_pcb, p, &addr, RW_DHCP_PORT_CLIENT);
    pbuf_free(p);
}

static void on_datagram(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
                        u16_t port) {
    (void)arg;
    (void)pcb;
    (void)addr;
    (void)port;
    if (p == NULL) {
        return;
    }

    /*
     * Flatten into a local buffer rather than walking the pbuf chain. A DHCP message is under
     * 600 bytes, and a parser that has to cope with a fragmented payload is a parser with a
     * second, much subtler set of bounds bugs in it.
     */
    uint8_t buf[RW_DHCP_MSG_MAX];
    uint16_t len = pbuf_copy_partial(p, buf, sizeof(buf), 0);
    pbuf_free(p);

    rw_dhcp_request_t req;
    if (!rw_dhcp_parse(buf, len, &req)) {
        return;
    }

    switch (req.type) {
        case RW_DHCP_DISCOVER: {
            uint32_t ip = lease_for(req.chaddr, req.hlen);
            if (ip == 0) {
                RW_LOG_WARN("dhcp: lease table full, ignoring DISCOVER");
                return;
            }
            send_reply(&req, RW_DHCP_OFFER, ip);
            return;
        }

        case RW_DHCP_REQUEST: {
            /* A REQUEST naming a different server means the client picked someone else's offer.
             * Staying silent is required: NAKing it would break a network where another DHCP
             * server legitimately won. */
            if (req.server_id != 0 && req.server_id != s_server_ip) {
                return;
            }
            uint32_t ip = lease_for(req.chaddr, req.hlen);
            if (ip == 0) {
                send_reply(&req, RW_DHCP_NAK, 0);
                return;
            }
            /* If it is asking for an address that is not the one we hold for it, tell it so
             * rather than silently handing over a different one — a client that believes it has
             * an address we did not give it will not use ours. */
            if (req.requested_ip != 0 && req.requested_ip != ip) {
                send_reply(&req, RW_DHCP_NAK, 0);
                return;
            }
            send_reply(&req, RW_DHCP_ACK, ip);
            RW_LOG_INFO("dhcp: leased %lu.%lu.%lu.%lu", (unsigned long)(ip >> 24) & 0xFF,
                        (unsigned long)(ip >> 16) & 0xFF, (unsigned long)(ip >> 8) & 0xFF,
                        (unsigned long)ip & 0xFF);
            return;
        }

        case RW_DHCP_RELEASE:
        case RW_DHCP_DECLINE:
            release_lease(req.chaddr, req.hlen);
            return;

        /* We are not a client, so our own replies and everything else are ignored. INFORM asks
         * for options without an address, which a setup hotspot has no reason to answer. */
        case RW_DHCP_UNKNOWN:
        case RW_DHCP_OFFER:
        case RW_DHCP_ACK:
        case RW_DHCP_NAK:
        case RW_DHCP_INFORM:
            return;
    }
}

bool rw_dhcpserver_start(uint32_t server_ip, uint32_t netmask) {
    rw_dhcpserver_stop();

    s_server_ip = server_ip;
    s_netmask   = netmask;
    memset(s_leases, 0, sizeof(s_leases));

    s_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (s_pcb == NULL) {
        return false;
    }
    /* SOF_BROADCAST is required to answer a client that has no address yet. */
    ip_set_option(s_pcb, SOF_BROADCAST);

    if (udp_bind(s_pcb, IP_ANY_TYPE, RW_DHCP_PORT_SERVER) != ERR_OK) {
        udp_remove(s_pcb);
        s_pcb = NULL;
        return false;
    }
    udp_recv(s_pcb, on_datagram, NULL);
    return true;
}

void rw_dhcpserver_stop(void) {
    if (s_pcb != NULL) {
        udp_remove(s_pcb);
        s_pcb = NULL;
    }
}

int rw_dhcpserver_lease_count(void) {
    expire_stale();
    int n = 0;
    for (int i = 0; i < RW_DHCP_LEASES; i++) {
        if (s_leases[i].used) {
            n++;
        }
    }
    return n;
}
