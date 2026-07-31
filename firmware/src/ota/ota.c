/*
 * The application's half of the update machinery. See ota.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ota/ota.h"

#include "brand.h"
#include "ota/layout.h"
#include "ota/ota_flash.h"
#include "rw_log.h"

static rw_ota_state_t s_state;
static bool           s_loaded;

/*
 * Which slot is this code in?
 *
 * Answered from the address of a function in this image rather than from the state record. The
 * record is what the loader intended; this is what actually happened, and where they disagree —
 * a record written by an older firmware, a slot entered by the loader's own fallback because the
 * recorded one was empty — every decision below has to follow reality. Staging over the running
 * image because a record said something else is the one mistake that cannot be undone remotely.
 */
uint8_t rw_ota_running_slot(void) {
    uintptr_t here = (uintptr_t)&rw_ota_running_slot;
    return (here >= RW_SLOT_XIP(RW_OTA_SLOT_B)) ? RW_OTA_SLOT_B : RW_OTA_SLOT_A;
}

uint8_t rw_ota_spare_slot(void) {
    return rw_ota_other_slot(rw_ota_running_slot());
}

void rw_ota_init(void) {
    if (!rw_ota_flash_load(&s_state)) {
        /* Never updated. The defaults describe what is true of a factory device, and nothing is
         * written: a device that boots has no reason to start writing flash. */
        rw_ota_state_default(&s_state, RW_FW_VERSION);
        s_state.active = rw_ota_running_slot();
        s_state.fallback = s_state.active;
    }
    s_loaded = true;

    if (s_state.confirmed) {
        RW_LOG_INFO("ota: slot %u, confirmed, version %s", (unsigned)rw_ota_running_slot(),
                    s_state.version[0] ? s_state.version : RW_FW_VERSION);
    } else {
        RW_LOG_WARN("ota: slot %u on trial, %u boot(s) left before the loader reverts to slot %u",
                    (unsigned)rw_ota_running_slot(), (unsigned)s_state.trial,
                    (unsigned)s_state.fallback);
    }
}

bool rw_ota_on_trial(void) {
    return s_loaded && rw_ota_state_on_trial(&s_state);
}

uint8_t rw_ota_trials_left(void) {
    return s_loaded ? s_state.trial : 0;
}

const rw_ota_state_t *rw_ota_state(void) {
    return &s_state;
}

void rw_ota_confirm_running_image(void) {
    if (!s_loaded || s_state.confirmed) {
        return;
    }

    rw_ota_state_t next = s_state;
    rw_ota_state_confirm(&next);
    /* The record should already name the running slot, but the confirmation is what makes it the
     * fallback for every future update, so it is worth being explicit rather than inheriting a
     * value from whatever wrote the record. */
    next.active   = rw_ota_running_slot();
    next.fallback = next.active;

    if (!rw_ota_flash_save(&next)) {
        /* Not fatal, and deliberately not retried in a loop: the image keeps running, and the
         * worst case is that the loader reverts to a slot that also works. */
        RW_LOG_ERROR("ota: could not record the confirmation; this image may be rolled back");
        return;
    }
    s_state = next;
    RW_LOG_INFO("ota: slot %u confirmed", (unsigned)next.active);
}

bool rw_ota_stage_slot(uint8_t slot, const char *version) {
    if (!s_loaded || slot > RW_OTA_SLOT_B) {
        return false;
    }
    if (slot == rw_ota_running_slot()) {
        RW_LOG_ERROR("ota: refusing to stage slot %u - it is the one running", (unsigned)slot);
        return false;
    }

    rw_ota_state_t next = s_state;
    /* Anchored to reality for the same reason as above: the fallback has to be the slot that is
     * demonstrably working, which is this one. */
    next.active    = rw_ota_running_slot();
    next.confirmed = true;
    rw_ota_state_stage(&next, slot, version);

    if (!rw_ota_flash_save(&next)) {
        RW_LOG_ERROR("ota: could not write the state record; the update will not be entered");
        return false;
    }
    s_state = next;
    RW_LOG_INFO("ota: slot %u staged (%s), %u trial boot(s), falling back to slot %u",
                (unsigned)slot, version != NULL ? version : "?", (unsigned)next.trial,
                (unsigned)next.fallback);
    return true;
}
