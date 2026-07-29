/*
 * The UDP half of the setup-hotspot DHCP server: a socket, a lease table, and nothing else.
 * All message handling lives in dhcp_msg.c, which is host-tested.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_DHCPSERVER_H
#define RW_DHCPSERVER_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Eight concurrent clients. The realistic load is one phone, but a household walking past with
 * "join this open network" enabled can produce a handful, and a table that runs out silently
 * would leave the one person actually setting the device up unable to get an address.
 */
#define RW_DHCP_LEASES 8

/* 24 hours. The hotspot lives for minutes, so the value only matters in that it must not be so
 * short that a phone renews mid-setup and so long that a client refuses it. */
#define RW_DHCP_LEASE_SECS 86400u

/*
 * Start serving on the AP interface.
 *
 * `server_ip` and `netmask` are host byte order. Leases are handed out from `server_ip + 1`
 * upwards within the mask. Returns false if the socket cannot be opened, which is fatal to
 * setup mode — without DHCP a phone associates and then sits there with no address, which
 * looks exactly like a hotspot that does not work.
 */
bool rw_dhcpserver_start(uint32_t server_ip, uint32_t netmask);

void rw_dhcpserver_stop(void);

/* How many leases are currently held. The portal has no use for this; the serial log does,
 * because "did the phone actually get an address" is the first question when setup stalls. */
int rw_dhcpserver_lease_count(void);

#endif /* RW_DHCPSERVER_H */
