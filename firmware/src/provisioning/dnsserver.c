/*
 * Captive-portal DNS responder socket. See dnsserver.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/dnsserver.h"

#include <string.h>

#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "provisioning/dns_msg.h"

static struct udp_pcb *s_pcb;
static uint32_t        s_answer_ip;

static void on_query(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
                     u16_t port) {
    (void)arg;
    (void)pcb;
    if (p == NULL) {
        return;
    }

    uint8_t  req[RW_DNS_MSG_MAX];
    uint16_t len = pbuf_copy_partial(p, req, sizeof(req), 0);
    pbuf_free(p);

    rw_dns_query_t q;
    if (!rw_dns_parse_query(req, len, &q)) {
        /*
         * Silently dropped. A malformed query gets no FORMERR: replying to unparseable UDP from
         * an unauthenticated source turns this into a reflector, and nothing on a setup hotspot
         * benefits from the courtesy.
         */
        return;
    }

    uint8_t out[RW_DNS_MSG_MAX];
    size_t  n = rw_dns_build_response(req, len, &q, s_answer_ip, RW_DNS_TTL_SECS, out,
                                      sizeof(out));
    if (n == 0) {
        return;
    }

    struct pbuf *reply = pbuf_alloc(PBUF_TRANSPORT, (uint16_t)n, PBUF_RAM);
    if (reply == NULL) {
        return;
    }
    memcpy(reply->payload, out, n);
    udp_sendto(s_pcb, reply, addr, port);
    pbuf_free(reply);
}

bool rw_dnsserver_start(uint32_t answer_ip) {
    rw_dnsserver_stop();
    s_answer_ip = answer_ip;

    s_pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (s_pcb == NULL) {
        return false;
    }
    if (udp_bind(s_pcb, IP_ANY_TYPE, RW_DNS_PORT) != ERR_OK) {
        udp_remove(s_pcb);
        s_pcb = NULL;
        return false;
    }
    udp_recv(s_pcb, on_query, NULL);
    return true;
}

void rw_dnsserver_stop(void) {
    if (s_pcb != NULL) {
        udp_remove(s_pcb);
        s_pcb = NULL;
    }
}
