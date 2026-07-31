/*
 * Which slot boots, and what happens when a new one does not work.
 *
 * Read by the loader before anything else runs and written by the application, so it is kept
 * deliberately small and separate from the configuration record: the loader must be able to
 * parse it without linking config.c, and a factory reset must not be able to make a device
 * unbootable by clearing which image is good.
 *
 * ── THE TRIAL ────────────────────────────────────────────────────────────────
 *
 * An update that installs perfectly and then cannot reach the relay is indistinguishable, from
 * the device's side, from one that was never installed. So a freshly written slot boots on
 * trial: the loader decrements a counter on each boot, and the application clears it once it has
 * proved itself. If the counter reaches zero without that happening — because the image crashes,
 * or hangs, or connects to nothing — the loader goes back to the slot that was working.
 *
 * A confirmed state costs no flash write at boot, which matters on a device that may be power
 * cycled daily for years.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_STATE_H
#define RW_OTA_STATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ota/layout.h"

#define RW_OTA_STATE_MAGIC   "RWST"
#define RW_OTA_STATE_VERSION 1
#define RW_OTA_STATE_LEN     40

#define RW_OTA_SLOT_A 0u
#define RW_OTA_SLOT_B 1u

/* Boots a new image gets to prove itself before the loader gives up on it. Three covers a
 * transient failure to reach the relay — a router still coming up after the same power cut that
 * rebooted the dongle — without leaving a genuinely broken image in place for long. */
#define RW_OTA_TRIAL_BOOTS 3u

typedef struct {
    uint32_t seq;      /* increases on every write; the higher of the two copies wins */
    uint8_t  active;   /* the slot the loader enters */
    uint8_t  fallback; /* where to go if the trial fails */
    uint8_t  trial;    /* boots left before reverting; meaningless once confirmed */
    bool     confirmed;
    char     version[RW_OTA_VERSION_LEN]; /* what `active` is believed to contain */
} rw_ota_state_t;

/* The state a device has before it has ever been updated: slot A, confirmed, nothing pending. */
void rw_ota_state_default(rw_ota_state_t *s, const char *version);

/* Serialise into `out`, which needs RW_OTA_STATE_LEN bytes. Returns bytes written, or 0. */
size_t rw_ota_state_encode(const rw_ota_state_t *s, uint8_t *out, size_t cap);

/* Parse and check magic, version, slot numbers and CRC. False if the record is not usable. */
bool rw_ota_state_decode(const uint8_t *raw, size_t len, rw_ota_state_t *out);

/*
 * Choose between the two stored copies: the valid one with the higher sequence number.
 *
 * Sequence numbers are compared as unsigned differences so the counter can wrap without the
 * older copy suddenly winning. False when neither copy parses, which is what a factory-fresh
 * device looks like and is not an error.
 */
bool rw_ota_state_pick(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                       rw_ota_state_t *out);

typedef enum {
    RW_OTA_BOOT_ACTIVE = 0, /* enter s->active */
    RW_OTA_BOOT_REVERTED,   /* the trial expired; s->active has been moved back */
} rw_ota_boot_t;

/*
 * What the loader should do now. Mutates `s` into the state to be written back, and sets
 * `write_back` only when something actually changed — a confirmed device writes nothing.
 */
rw_ota_boot_t rw_ota_state_on_boot(rw_ota_state_t *s, bool *write_back);

/* The application, having written and verified an image into the other slot: make it next. */
void rw_ota_state_stage(rw_ota_state_t *s, uint8_t slot, const char *version);

/* The application, having proved itself: stop the trial. No-op once confirmed. */
void rw_ota_state_confirm(rw_ota_state_t *s);

/* True while `active` is unproven, so the application knows it owes a confirmation. */
bool rw_ota_state_on_trial(const rw_ota_state_t *s);

uint8_t rw_ota_other_slot(uint8_t slot);

#endif /* RW_OTA_STATE_H */
