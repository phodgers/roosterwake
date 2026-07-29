/*
 * Wake-on-LAN transmission over raw lwIP UDP.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_WOL_H
#define RW_WOL_H

#include <stdbool.h>
#include <stdint.h>

/* Four broadcast endpoints (two addresses x two ports) plus, when WOL_UNICAST is set, the
 * target's last-known address on the same two ports. */
#define RW_WOL_MAX_IFACES 6
#define RW_WOL_IFACE_TEXT 24 /* "255.255.255.255:9" and room to spare */

/* Wake ports. 9 is `discard`, 7 is `echo`; both are conventional for WoL and NICs differ on
 * which one their firmware listens to, so both are always used. */
#define RW_WOL_PORT_PRIMARY   9
#define RW_WOL_PORT_SECONDARY 7

#define RW_WOL_BURSTS_MIN     1
#define RW_WOL_BURSTS_MAX     5
#define RW_WOL_BURSTS_DEFAULT 3
#define RW_WOL_BURST_GAP_MS   100

/*
 * PROTOCOL.md §4 fixes the relationship between these two fields: `sent` is exactly
 * `iface_count * bursts`, one datagram per destination per burst. A number a support
 * conversation cannot reproduce from the other fields is worse than no number at all, so this
 * invariant is enforced rather than approximated — see rw_wol_send().
 */
typedef struct {
    int  sent;        /* iface_count * bursts, or 0 */
    int  iface_count; /* entries in `ifaces` */
    char ifaces[RW_WOL_MAX_IFACES][RW_WOL_IFACE_TEXT];
} rw_wol_result_t;

typedef enum {
    RW_WOL_OK = 0,
    RW_WOL_ERR_NO_LINK,     /* no netif, no address, or the link is down */
    RW_WOL_ERR_SEND_FAILED, /* the stack refused every datagram */
} rw_wol_status_t;

/*
 * Broadcast magic packets for `mac`.
 *
 * One datagram to each destination per burst, `bursts` bursts RW_WOL_BURST_GAP_MS apart.
 * `bursts` is clamped to [RW_WOL_BURSTS_MIN, RW_WOL_BURSTS_MAX] rather than rejected, as
 * PROTOCOL.md §5 requires. `unicast_too` follows the WOL_UNICAST config flag and adds the
 * target's last-known address when one is known.
 *
 * A datagram the stack refuses is retried once after a short pump; a second refusal fails the
 * whole wake with RW_WOL_ERR_SEND_FAILED and an empty result, because a partial send cannot be
 * reported without breaking the `sent == iface_count * bursts` invariant, and a number that
 * looks authoritative but is not reproducible is the specific failure §4 exists to prevent.
 *
 * Blocks for (bursts - 1) * RW_WOL_BURST_GAP_MS while pumping the network stack, so lwIP
 * timers keep running and the watchdog keeps being fed.
 *
 * `res` is always populated, including on failure — "it did not work" with an empty iface list
 * is still the shape PROTOCOL.md §4 specifies.
 */
rw_wol_status_t rw_wol_send(const uint8_t mac[6], int bursts, bool unicast_too,
                            rw_wol_result_t *res);

#endif /* RW_WOL_H */
