/*
 * Who else is on this segment.
 *
 * Setup asks for the MAC address of the PC to wake, and asking somebody to run `getmac` and copy
 * the right line out of it is the least popular thing this product does. The dongle is already on
 * the network by that point, so it can go and ask: an ARP request to every address in its own
 * subnet, and whoever answers gets listed.
 *
 * What this cannot do is say which of them is *your* PC beyond the name each machine volunteers
 * (NBNS for Windows and Samba, mDNS for most of the rest) — and whether wake-on-LAN is even
 * armed on that adapter exists only on the machine itself. This narrows "work out your MAC
 * address" to "pick from this list"; it does not replace reading something off the PC when the
 * list is ambiguous.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_LANSCAN_H
#define RW_LANSCAN_H

#include <stdbool.h>
#include <stdint.h>

#include "lwip/ip_addr.h"

#include "net/mdns.h"
#include "net/nbns.h"

/*
 * Enough to cover a home network, few enough that the JSON fits one usbcfg response alongside
 * everything else the channel emits. Extras are dropped rather than the response truncated.
 */
#define RW_LAN_SCAN_MAX 24

/* Sized for the longer of the two name sources: NBNS names stop at sixteen, mDNS labels are
 * truncated to this. scan_json.h states the same figure; proto.c asserts they agree. */
#define RW_LAN_NAME_LEN RW_MDNS_NAME_LEN

/* Addresses probed in one sweep. A /24 is 254 and fits; a /22 like a flat with a big DHCP pool is
 * 1022 and does too. Anything larger is a network this product is not going to be set up on by
 * someone who needed this list. */
#define RW_LAN_SCAN_MAX_PROBES 1024

/* Hard ceiling on a sweep, whatever the subnet. usbcfg.md documents this as the worst case. */
#define RW_LAN_SCAN_BUDGET_MS 9000

/* No address of our own, so nothing to sweep. */
#define RW_LAN_SCAN_ERR_NOT_JOINED (-1)

typedef struct {
    ip4_addr_t ip;
    uint8_t    mac[6];
    /* The host's own name, empty when it answered neither name query. NBNS names Windows and
     * Samba; mDNS names macOS, desktop Linux and most phones. What stays nameless is mostly
     * what is not a computer. */
    char       name[RW_LAN_NAME_LEN];
} rw_lan_host_t;

/*
 * Sweep the local subnet and fill `out` with the hosts that answered, lowest address first.
 *
 * Blocks for up to RW_LAN_SCAN_BUDGET_MS while pumping the network stack and feeding the
 * watchdog. Returns the number of hosts found, or RW_LAN_SCAN_ERR_NOT_JOINED.
 */
int rw_lan_scan(rw_lan_host_t *out, int max);

/*
 * The same sweep without the name pass: addresses and MACs only, every `name` left empty.
 *
 * For callers that identify hosts some other way — the plug driver asks each candidate over
 * HTTP, so a NetBIOS name would be a second, worse answer it then had to ignore — and for the
 * targeted re-resolve, where the question is "which address holds this MAC now" and a name
 * pass would only lengthen the outage it is recovering from. Blocks and pumps like
 * rw_lan_scan, minus NAME_WAIT_MS.
 */
int rw_lan_sweep(rw_lan_host_t *out, int max);

#endif /* RW_LANSCAN_H */
