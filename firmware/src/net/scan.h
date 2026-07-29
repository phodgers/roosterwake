/*
 * Wi-Fi scanning, shared by the usbcfg channel and the captive portal.
 *
 * Both surfaces need the same thing — the networks *this device* can see, deduplicated and
 * strongest first — and both would otherwise reimplement the collapse, the sort and the UTF-8
 * rejection. One of the two copies would then acquire a fix the other did not.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_SCAN_H
#define RW_SCAN_H

#include <stdbool.h>
#include <stdint.h>

#include "config/config.h"

/*
 * Enough that a dense block of flats still shows the user's own network, few enough that the
 * JSON stays inside a usbcfg response line. Extras are dropped weakest-first.
 */
#define RW_SCAN_MAX 20

/* usbcfg.md §4: "Takes up to 10 seconds." */
#define RW_SCAN_TIMEOUT_MS 10000

typedef struct {
    char     ssid[RW_CFG_SSID_LEN];
    int16_t  rssi;
    uint16_t channel;
    uint8_t  auth_mode;
} rw_scan_entry_t;

/*
 * Run a blocking scan, filling `out` with at most `max` entries sorted by signal strength.
 *
 * Blocks for up to RW_SCAN_TIMEOUT_MS while pumping the network stack and feeding the watchdog.
 * Returns the number of networks found, or -1 if a scan is already running.
 */
int rw_scan_run(rw_scan_entry_t *out, int max);

/*
 * Name the scan result's auth byte: "open", "wpa", "wpa2" or "secured".
 *
 * This is the CYW43 scan capability byte, not the CYW43_AUTH_* constants used when joining. It
 * separates open from WPA from WPA2 but **cannot separate WPA2 from WPA3** — both present as an
 * AES-PSK capability and the SAE bit is not carried here. A WPA3 network is reported as wpa2,
 * deliberately: inventing a confident "wpa3" from a byte that cannot express it would be worse.
 *
 * Nothing depends on it being exact. It picks a padlock icon; the join negotiates whatever the
 * router actually offers.
 */
const char *rw_scan_auth_name(uint8_t auth_mode);

#endif /* RW_SCAN_H */
