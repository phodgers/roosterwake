/*
 * Post-wake liveness probe. See probe.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "proto/probe.h"

#include <string.h>

#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "pico/time.h"

#include "net/arplearn.h"
#include "rw_log.h"

/* One ARP request per second. Faster gains nothing — a machine that has just been woken takes
 * seconds to bring its NIC up — and slower makes the reported elapsed time coarse. */
#define PROBE_INTERVAL_MS 1000

static struct {
    bool              running;
    uint8_t           mac[6];
    ip4_addr_t        ip;
    bool              have_ip;
    rw_probe_state_t  state;
    absolute_time_t   started;
    absolute_time_t   deadline;
    absolute_time_t   next_request;
    rw_probe_report_t report;
    void             *ctx;
} s;

static uint32_t elapsed_s(void) {
    return (uint32_t)(absolute_time_diff_us(s.started, get_absolute_time()) / 1000000);
}

static void report(rw_probe_state_t state) {
    s.state = state;
    if (s.report != NULL) {
        s.report(s.ctx, state, elapsed_s());
    }
}

/* Ask lwIP whether it currently resolves `ip` to our target's MAC. A hit means the host
 * answered an ARP request, which only a host that is up and on the network does. */
static bool arp_confirms_target(void) {
    struct netif *nif = netif_default;
    if (nif == NULL || !s.have_ip) {
        return false;
    }
    struct eth_addr *found = NULL;
    const ip4_addr_t *unused = NULL;
    if (etharp_find_addr(nif, &s.ip, &found, &unused) < 0 || found == NULL) {
        return false;
    }
    return memcmp(found->addr, s.mac, 6) == 0;
}

bool rw_probe_start(const uint8_t mac[6], uint32_t timeout_s, rw_probe_report_t report_cb,
                    void *ctx) {
    if (s.running) {
        return false;
    }

    if (timeout_s < RW_PROBE_TIMEOUT_MIN_S) {
        timeout_s = RW_PROBE_TIMEOUT_MIN_S;
    } else if (timeout_s > RW_PROBE_TIMEOUT_MAX_S) {
        timeout_s = RW_PROBE_TIMEOUT_MAX_S;
    }

    memset(&s, 0, sizeof(s));
    memcpy(s.mac, mac, 6);
    s.running      = true;
    s.report       = report_cb;
    s.ctx          = ctx;
    s.started      = get_absolute_time();
    s.deadline     = make_timeout_time_ms(timeout_s * 1000);
    s.next_request = get_absolute_time();
    s.have_ip      = rw_arp_lookup(mac, &s.ip);

    if (!s.have_ip) {
        RW_LOG_WARN("probe: no address known for this MAC; the probe can only time out");
    }

    report(RW_PROBE_WAITING);
    return true;
}

void rw_probe_task(void) {
    if (!s.running) {
        return;
    }

    if (!s.have_ip) {
        /* Keep looking: the target may show up in the ARP cache while the probe runs, which is
         * precisely what happens when it boots and starts talking to the gateway. */
        s.have_ip = rw_arp_lookup(s.mac, &s.ip);
    }

    if (time_reached(s.next_request)) {
        s.next_request = make_timeout_time_ms(PROBE_INTERVAL_MS);

        if (s.have_ip) {
            if (arp_confirms_target()) {
                RW_LOG_INFO("probe: %s is up after %lus", ip4addr_ntoa(&s.ip),
                            (unsigned long)elapsed_s());
                s.running = false;
                report(RW_PROBE_UP);
                return;
            }
            struct netif *nif = netif_default;
            if (nif != NULL) {
                /* Errors here are transient — out of pbufs, link momentarily down — and the
                 * next tick retries. There is nothing better to do with them than try again. */
                (void)etharp_request(nif, &s.ip);
            }
        }
    }

    if (time_reached(s.deadline)) {
        RW_LOG_INFO("probe: timed out after %lus", (unsigned long)elapsed_s());
        s.running = false;
        report(RW_PROBE_TIMEOUT);
    }
}

void rw_probe_cancel(void) {
    s.running = false;
    s.report  = NULL;
    s.ctx     = NULL;
    s.state   = RW_PROBE_IDLE;
}

bool rw_probe_running(void) {
    return s.running;
}

const char *rw_probe_method(void) {
    return "arp";
}
