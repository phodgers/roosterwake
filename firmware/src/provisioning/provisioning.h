/*
 * Setup mode: the Wi-Fi hotspot, its DHCP and DNS servers, and the captive portal behind them.
 *
 * Entered when the device has no usable configuration. Everything here exists so that a person
 * with nothing but a phone can get a dongle onto their network — no app, no cable, no computer.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_PROVISIONING_H
#define RW_PROVISIONING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/config.h"

/* 192.168.4.1/24, the address the portal is reachable at and the one every name resolves to. */
#define RW_AP_IP      0xC0A80401u
#define RW_AP_NETMASK 0xFFFFFF00u

/*
 * Bring up the hotspot and the portal.
 *
 * `live` is borrowed: edits accumulate in a private staged copy and only reach it on a
 * successful commit, exactly as the usbcfg channel works. Returns false if the AP or any of the
 * three servers fails to start, which leaves the device with no way to be configured over the
 * air — the caller should say so on the LED.
 */
bool rw_provisioning_start(rw_config_t *live);

/* Drive the deferred work: the reboot after a commit, and the join attempt's timeout. Must be
 * called from the main loop. */
void rw_provisioning_task(void);

bool rw_provisioning_active(void);

/* Tear down the AP and the three servers. */
void rw_provisioning_stop(void);

/* ── Portal API, called by httpd.c ───────────────────────────────────────────
 *
 * Each writes a single JSON object into `buf` and returns its length, or 0 on overflow. They
 * are declared here rather than in a header of their own because httpd.c is the only caller and
 * the alternative is a header that exists to be included once.
 */

size_t rw_portal_api_info(char *buf, size_t cap);
size_t rw_portal_api_scan(char *buf, size_t cap);

/*
 * Attempt to join `ssid` with `psk`, blocking for up to 20 seconds.
 *
 * Reports `badauth`, `notfound` or `timeout` distinctly, because they are three different
 * problems with three different fixes and "couldn't connect" sends people to the wrong one.
 * On success the credentials are staged, not written — nothing reaches flash before commit.
 */
size_t rw_portal_api_join(const char *body, size_t len, char *buf, size_t cap);

size_t rw_portal_api_config(const char *body, size_t len, char *buf, size_t cap);

/* Validate, write both config slots, and schedule the reboot that leaves setup mode. Returns
 * the device_id and, for self-hosters, the token — the one and only time it is ever shown. */
size_t rw_portal_api_commit(char *buf, size_t cap);

#endif /* RW_PROVISIONING_H */
