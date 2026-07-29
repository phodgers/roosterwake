/*
 * Wi-Fi station mode, DHCP and SNTP.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_NET_H
#define RW_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/config.h"

typedef enum {
    RW_NET_IDLE = 0, /* no credentials, or not started */
    RW_NET_JOINING,  /* associating, or waiting for DHCP */
    RW_NET_JOINED,   /* associated with an address */
    RW_NET_FAILED,   /* the last attempt failed; a retry is scheduled */
} rw_net_state_t;

/* Bring up cyw43_arch in station mode. Returns false if the radio does not initialise, which
 * is a hardware fault and is fatal. */
bool rw_net_init(void);

/* Begin joining. Safe to call again with different credentials; the current attempt is
 * abandoned. Empty `ssid` puts the module back to RW_NET_IDLE. */
void rw_net_start(const char *ssid, const char *psk, uint8_t wifi_auth);

/*
 * Drive association, retry backoff and SNTP. Must be called from the main loop.
 *
 * Retries are exponential with full jitter and never give up. A router that is rebooting, a
 * house that has lost power, or an SSID that comes back on a different channel are all normal;
 * a dongle that stops trying after n attempts is a dongle somebody has to go and unplug.
 */
void rw_net_task(void);

rw_net_state_t rw_net_state(void);

/* True when associated, addressed, and the wall clock is set — everything TLS needs. */
bool rw_net_ready(void);

/* Short diagnostic string for the last failure, or NULL. Values match the ones usbcfg's
 * STATUS reports: "badauth", "nonet", "failed", "dhcp_timeout", "sntp_timeout". */
const char *rw_net_last_error(void);

/* Current RSSI in dBm, or 0 when not associated. */
int32_t rw_net_rssi(void);

/* Dotted-quad address and netmask; "0.0.0.0" when unaddressed. `out` needs 16 bytes. */
void rw_net_ip_str(char *out, size_t len);
void rw_net_netmask_str(char *out, size_t len);

/* The dongle's own station MAC, canonical form (usbcfg INFO). `out` needs 18 bytes. */
void rw_net_mac_str(char *out, size_t len);

#endif /* RW_NET_H */
