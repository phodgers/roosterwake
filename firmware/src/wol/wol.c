/*
 * Wake-on-LAN transmission over raw lwIP UDP. See wol.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "wol/wol.h"

#include <stdio.h>
#include <string.h>

#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "net/arplearn.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "wol/magic.h"

typedef struct {
    ip_addr_t addr;
    uint16_t  port;
} wol_endpoint_t;

/*
 * Work out where a magic packet has to go.
 *
 * The limited broadcast 255.255.255.255 is never forwarded and is dropped by some drivers that
 * are otherwise happy to deliver to the subnet-directed address, and the reverse is true of
 * others. Sending to both costs two extra datagrams and removes an entire class of "it works
 * on my router" report. Reporting both back in `ifaces` is what lets a support answer be
 * "your dongle broadcast on 192.168.1.255 and your PC is on 192.168.0.x" instead of a guess.
 *
 * Ordering matches the example in PROTOCOL.md §4: port-major, address-minor.
 */
static int build_endpoints(const struct netif *nif, const uint8_t mac[6], bool unicast_too,
                           wol_endpoint_t *out, int max) {
    ip_addr_t global_bcast;
    IP4_ADDR(ip_2_ip4(&global_bcast), 255, 255, 255, 255);
    IP_SET_TYPE_VAL(global_bcast, IPADDR_TYPE_V4);

    const u32_t ip   = ip4_addr_get_u32(netif_ip4_addr(nif));
    const u32_t mask = ip4_addr_get_u32(netif_ip4_netmask(nif));

    ip_addr_t subnet_bcast;
    bool      have_subnet = false;
    if (mask != 0 && mask != 0xFFFFFFFFu) {
        ip4_addr_set_u32(ip_2_ip4(&subnet_bcast), ip | ~mask);
        IP_SET_TYPE_VAL(subnet_bcast, IPADDR_TYPE_V4);
        have_subnet = true;
    }

    /* The target's last-known address, if the ARP cache still has it. A machine in S3 usually
     * does; one in S5 does not, and there is nothing to send unicast to. That is why unicast
     * is an addition to the broadcasts and never a replacement for them. */
    ip_addr_t unicast;
    bool      have_unicast = false;
    if (unicast_too) {
        ip4_addr_t learned;
        if (rw_arp_lookup(mac, &learned)) {
            ip_addr_copy_from_ip4(unicast, learned);
            have_unicast = true;
        } else {
            RW_LOG_DEBUG("wol: unicast requested but this MAC has not been seen on the LAN");
        }
    }

    static const uint16_t ports[2] = {RW_WOL_PORT_PRIMARY, RW_WOL_PORT_SECONDARY};
    int                   n        = 0;
    for (int p = 0; p < 2; p++) {
        if (n < max) {
            out[n].addr = global_bcast;
            out[n].port = ports[p];
            n++;
        }
        if (have_subnet && n < max) {
            out[n].addr = subnet_bcast;
            out[n].port = ports[p];
            n++;
        }
    }
    for (int p = 0; p < 2 && have_unicast; p++) {
        if (n < max) {
            out[n].addr = unicast;
            out[n].port = ports[p];
            n++;
        }
    }
    return n;
}

static err_t send_one(struct udp_pcb *pcb, const uint8_t *payload, const wol_endpoint_t *ep) {
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, RW_WOL_MAGIC_LEN, PBUF_RAM);
    if (p == NULL) {
        return ERR_MEM;
    }
    memcpy(p->payload, payload, RW_WOL_MAGIC_LEN);
    err_t err = udp_sendto(pcb, p, &ep->addr, ep->port);
    pbuf_free(p);
    return err;
}

rw_wol_status_t rw_wol_send(const uint8_t mac[6], int bursts, bool unicast_too,
                            rw_wol_result_t *res) {
    memset(res, 0, sizeof(*res));

    if (bursts < RW_WOL_BURSTS_MIN) {
        bursts = RW_WOL_BURSTS_MIN;
    } else if (bursts > RW_WOL_BURSTS_MAX) {
        bursts = RW_WOL_BURSTS_MAX;
    }

    struct netif *nif = netif_default;
    if (nif == NULL || !netif_is_up(nif) || !netif_is_link_up(nif) ||
        ip4_addr_get_u32(netif_ip4_addr(nif)) == 0) {
        return RW_WOL_ERR_NO_LINK;
    }

    wol_endpoint_t endpoints[RW_WOL_MAX_IFACES];
    int            ep_count = build_endpoints(nif, mac, unicast_too, endpoints, RW_WOL_MAX_IFACES);
    if (ep_count == 0) {
        return RW_WOL_ERR_NO_LINK;
    }

    uint8_t payload[RW_WOL_MAGIC_LEN];
    rw_wol_build_magic(mac, payload);

    struct udp_pcb *pcb = udp_new_ip_type(IPADDR_TYPE_V4);
    if (pcb == NULL) {
        RW_LOG_ERROR("wol: out of UDP PCBs");
        return RW_WOL_ERR_SEND_FAILED;
    }
    /* Without SOF_BROADCAST lwIP silently refuses every one of these with ERR_VAL. */
    ip_set_option(pcb, SOF_BROADCAST);

    /*
     * One datagram per destination per burst. Repetition across bursts is not superstition: a
     * NIC that has only just been given power by the previous burst can miss the first frame
     * it sees, and a switch that has aged the target's MAC out floods the first frame and
     * learns nothing from it.
     */
    for (int burst = 0; burst < bursts; burst++) {
        if (burst > 0) {
            rw_sys_pump_ms(RW_WOL_BURST_GAP_MS);
        }
        for (int i = 0; i < ep_count; i++) {
            err_t err = send_one(pcb, payload, &endpoints[i]);
            if (err != ERR_OK) {
                /* Almost always ERR_MEM: the pbuf pool is momentarily empty behind a burst.
                 * Pumping the stack for a few milliseconds returns the buffers. */
                rw_sys_pump_ms(5);
                err = send_one(pcb, payload, &endpoints[i]);
            }
            if (err != ERR_OK) {
                RW_LOG_ERROR("wol: send to %s:%u failed (%d), abandoning the wake",
                             ipaddr_ntoa(&endpoints[i].addr), endpoints[i].port, err);
                udp_remove(pcb);
                memset(res, 0, sizeof(*res));
                return RW_WOL_ERR_SEND_FAILED;
            }
            res->sent++;
        }
    }

    udp_remove(pcb);

    for (int i = 0; i < ep_count && res->iface_count < RW_WOL_MAX_IFACES; i++) {
        snprintf(res->ifaces[res->iface_count], RW_WOL_IFACE_TEXT, "%s:%u",
                 ipaddr_ntoa(&endpoints[i].addr), endpoints[i].port);
        res->iface_count++;
    }

    /* The contract PROTOCOL.md §4 states outright. If this ever fails, the number reported to
     * the relay would not be derivable from `ifaces`, which is the whole reason the spec fixes
     * the relationship. */
    if (res->sent != res->iface_count * bursts) {
        RW_LOG_ERROR("wol: internal accounting error (%d != %d * %d)", res->sent,
                     res->iface_count, bursts);
        memset(res, 0, sizeof(*res));
        return RW_WOL_ERR_SEND_FAILED;
    }
    return RW_WOL_OK;
}
