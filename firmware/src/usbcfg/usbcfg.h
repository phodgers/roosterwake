/*
 * The device half of the USB serial command channel (firmware/docs/usbcfg.md).
 *
 * Moves bytes over USB CDC and performs the commands that need hardware — a radio scan, a flash
 * write, a reset. Everything that can be decided without hardware lives in cmdline.c and is
 * covered by the host tests.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_USBCFG_H
#define RW_USBCFG_H

#include <stdbool.h>

#include "config/config.h"

/*
 * Bind the channel to the device's live configuration.
 *
 * `live` is borrowed, not copied. Staged edits accumulate in a private working copy and only
 * reach `live` on a successful COMMIT, so abandoning a half-finished provisioning session
 * leaves a running device exactly as it was.
 */
void rw_usbcfg_init(rw_config_t *live);

/*
 * Drain whatever the host has sent and answer it. Must be called from the main loop.
 *
 * Reads are non-blocking, so an unplugged dongle costs one failed getchar per iteration. The
 * exceptions are SCAN and TEST_WAKE, which block for as long as the radio needs while pumping
 * the network stack and the watchdog; usbcfg.md §7 warns hosts that SCAN can take ten seconds.
 */
void rw_usbcfg_task(void);

/*
 * True once a COMMIT, REBOOT or FACTORY_RESET has been acknowledged and the reboot is pending.
 *
 * The main loop uses this to stop starting new work in the last second of the device's life,
 * so a reboot never lands in the middle of a flash write or a TLS handshake.
 */
bool rw_usbcfg_reboot_pending(void);

#endif /* RW_USBCFG_H */
