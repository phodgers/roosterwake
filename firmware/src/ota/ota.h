/*
 * The application's half of the update machinery.
 *
 * The loader decides which slot to enter; this decides what to tell it next time. Two things
 * happen here: a slot that has been written and verified is staged, and a slot that is on trial
 * is confirmed once it has proved itself.
 *
 * ── WHAT COUNTS AS PROOF ─────────────────────────────────────────────────────
 *
 * Reaching the relay. Not booting, not joining Wi-Fi, not "main() returned no error" — an image
 * that starts and cannot talk to us is exactly the failure a rollback exists for, and it is
 * indistinguishable from a good one by every earlier test. So the confirmation is wired to the
 * relay handshake completing, and nothing sooner.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_H
#define RW_OTA_H

#include <stdbool.h>
#include <stdint.h>

#include "ota/state.h"

/* Read the state record at start-up. Safe to call before anything else; a device that has never
 * been updated gets the defaults and writes nothing. */
void rw_ota_init(void);

/* The slot this image is running from, derived from where the code actually is rather than from
 * the record — so a record that disagrees with reality cannot make the device stage over
 * itself. */
uint8_t rw_ota_running_slot(void);

/* The slot an update should be written into: the one not running. */
uint8_t rw_ota_spare_slot(void);

/* True while this image still owes a confirmation. */
bool rw_ota_on_trial(void);

/* How many boots are left before the loader gives up on this image. */
uint8_t rw_ota_trials_left(void);

/* What the record says is active, and the version it believes is there. */
const rw_ota_state_t *rw_ota_state(void);

/*
 * Called when the relay handshake completes. Clears the trial and persists, once.
 *
 * Cheap and idempotent after the first call, because it is invoked from the connection path and
 * a device that reconnects every few hours must not rewrite flash each time.
 */
void rw_ota_confirm_running_image(void);

/*
 * Make `slot` the one the loader enters next, on trial. The caller must already have written and
 * verified an image there.
 *
 * Refuses the running slot: staging over the image currently executing would destroy the only
 * known-good copy, and there is no situation in which it is the right thing to do.
 */
bool rw_ota_stage_slot(uint8_t slot, const char *version);

#endif /* RW_OTA_H */
