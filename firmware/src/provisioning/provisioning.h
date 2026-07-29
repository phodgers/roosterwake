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
 * Start a join attempt and return immediately.
 *
 * This cannot be synchronous, and finding that out cost a hardware session. The CYW43439 holds
 * an AP and a station on **one channel**, so joining a network on a different channel takes the
 * setup hotspot with it — the phone loses its connection to us part-way through, and any
 * response we were holding open dies with it. A blocking join also runs a 20-second wait inside
 * an lwIP receive callback, pumping the stack re-entrantly from within its own callback, which
 * is exactly the re-entrancy this firmware's poll-mode design exists to prevent.
 *
 * So the attempt is a state machine driven by rw_provisioning_task(), and the *result is
 * stored*. The phone can lose the hotspot, reconnect once it comes back, poll again and still
 * learn what happened. Nothing is written to flash either way — a successful join only stages
 * the credentials.
 */
size_t rw_portal_api_join_start(const char *body, size_t len, char *buf, size_t cap);

/*
 * Report the current attempt: joining, ok, badauth, notfound or timeout.
 *
 * The last three are kept distinct because they are three different problems with three
 * different fixes, and "couldn't connect" sends people to check the wrong one.
 */
size_t rw_portal_api_join_status(char *buf, size_t cap);

size_t rw_portal_api_config(const char *body, size_t len, char *buf, size_t cap);

/* Validate, write both config slots, and schedule the reboot that leaves setup mode. Returns
 * the device_id and, for self-hosters, the token — the one and only time it is ever shown. */
size_t rw_portal_api_commit(char *buf, size_t cap);

#endif /* RW_PROVISIONING_H */
