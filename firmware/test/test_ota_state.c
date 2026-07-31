/*
 * The OTA state record and the trial/rollback rules.
 *
 * These are the rules that decide whether a device comes back after a bad update, so the tests
 * walk whole sequences of boots rather than checking fields one at a time.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "ota/state.h"
#include "rw_test.h"

/* One boot through the loader: decide, and persist if the decision changed anything. */
static rw_ota_boot_t boot_once(rw_ota_state_t *s) {
    bool          write_back = false;
    rw_ota_boot_t what       = rw_ota_state_on_boot(s, &write_back);

    if (write_back) {
        /* Round-trip through the encoded form, because that is what really happens and it is
         * where a field that is not persisted would show up. */
        uint8_t raw[RW_OTA_STATE_LEN];
        RW_CHECK_EQ_INT(rw_ota_state_encode(s, raw, sizeof(raw)), RW_OTA_STATE_LEN);
        rw_ota_state_t back;
        RW_CHECK(rw_ota_state_decode(raw, sizeof(raw), &back));
        *s = back;
    }
    return what;
}

static void test_round_trip(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");

    uint8_t raw[RW_OTA_STATE_LEN];
    RW_CHECK_EQ_INT(rw_ota_state_encode(&s, raw, sizeof(raw)), RW_OTA_STATE_LEN);

    rw_ota_state_t back;
    RW_CHECK(rw_ota_state_decode(raw, sizeof(raw), &back));
    RW_CHECK_EQ_INT(back.active, RW_OTA_SLOT_A);
    RW_CHECK_EQ_INT(back.fallback, RW_OTA_SLOT_A);
    RW_CHECK_EQ_INT(back.confirmed, 1);
    RW_CHECK_EQ_INT(back.trial, 0);
    RW_CHECK_EQ_STR(back.version, "1.5.0");
}

static void test_rejects_corruption(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");
    uint8_t good[RW_OTA_STATE_LEN];
    rw_ota_state_encode(&s, good, sizeof(good));

    rw_ota_state_t out;
    for (size_t i = 0; i < RW_OTA_STATE_LEN; i++) {
        uint8_t raw[RW_OTA_STATE_LEN];
        memcpy(raw, good, sizeof(raw));
        raw[i] ^= 0xFF;
        /* Every single-byte change must be caught. The CRC covers bytes 0..35 and the last four
         * ARE the CRC, so a flip there fails the comparison from the other side. */
        RW_CHECK(!rw_ota_state_decode(raw, sizeof(raw), &out));
    }

    /* A record whose CRC is correct but which names a slot that does not exist must still be
     * refused: the loader turns `active` into an address and jumps to it. */
    rw_ota_state_t bad = s;
    bad.active = 7;
    uint8_t raw[RW_OTA_STATE_LEN];
    RW_CHECK_EQ_INT(rw_ota_state_encode(&bad, raw, sizeof(raw)), 0);
}

static void test_picks_the_newer_copy(void) {
    rw_ota_state_t older;
    rw_ota_state_t newer;
    rw_ota_state_default(&older, "1.0.0");
    rw_ota_state_default(&newer, "2.0.0");
    newer.seq = older.seq + 1;

    uint8_t a[RW_OTA_STATE_LEN];
    uint8_t b[RW_OTA_STATE_LEN];
    rw_ota_state_encode(&older, a, sizeof(a));
    rw_ota_state_encode(&newer, b, sizeof(b));

    rw_ota_state_t got;
    RW_CHECK(rw_ota_state_pick(a, sizeof(a), b, sizeof(b), &got));
    RW_CHECK_EQ_STR(got.version, "2.0.0");
    /* Order of the arguments must not matter. */
    RW_CHECK(rw_ota_state_pick(b, sizeof(b), a, sizeof(a), &got));
    RW_CHECK_EQ_STR(got.version, "2.0.0");

    /* A torn write leaves one copy unreadable; the other still boots the device. */
    uint8_t torn[RW_OTA_STATE_LEN];
    memset(torn, 0xFF, sizeof(torn));
    RW_CHECK(rw_ota_state_pick(torn, sizeof(torn), b, sizeof(b), &got));
    RW_CHECK_EQ_STR(got.version, "2.0.0");

    /* Both unreadable is a factory-fresh device, not an error to report. */
    RW_CHECK(!rw_ota_state_pick(torn, sizeof(torn), torn, sizeof(torn), &got));
}

static void test_sequence_wrap(void) {
    rw_ota_state_t older;
    rw_ota_state_t newer;
    rw_ota_state_default(&older, "1.0.0");
    rw_ota_state_default(&newer, "2.0.0");
    older.seq = 0xFFFFFFFEu;
    newer.seq = 1u; /* wrapped past the end */

    uint8_t a[RW_OTA_STATE_LEN];
    uint8_t b[RW_OTA_STATE_LEN];
    rw_ota_state_encode(&older, a, sizeof(a));
    rw_ota_state_encode(&newer, b, sizeof(b));

    rw_ota_state_t got;
    RW_CHECK(rw_ota_state_pick(a, sizeof(a), b, sizeof(b), &got));
    RW_CHECK_EQ_STR(got.version, "2.0.0");
}

static void test_confirmed_boot_writes_nothing(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");

    for (int i = 0; i < 100; i++) {
        bool write_back = true;
        RW_CHECK_EQ_INT(rw_ota_state_on_boot(&s, &write_back), RW_OTA_BOOT_ACTIVE);
        /* A device that is simply switched on and off must not erase a flash sector each time. */
        RW_CHECK(!write_back);
    }
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_A);
}

static void test_a_good_update_sticks(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");

    rw_ota_state_stage(&s, rw_ota_other_slot(s.active), "1.6.0");
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_B);
    RW_CHECK_EQ_INT(s.fallback, RW_OTA_SLOT_A);
    RW_CHECK(rw_ota_state_on_trial(&s));

    RW_CHECK_EQ_INT(boot_once(&s), RW_OTA_BOOT_ACTIVE);
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_B);

    /* The new image reaches the relay and says so. */
    rw_ota_state_confirm(&s);
    RW_CHECK(!rw_ota_state_on_trial(&s));
    RW_CHECK_EQ_INT(s.fallback, RW_OTA_SLOT_B);

    for (int i = 0; i < 10; i++) {
        RW_CHECK_EQ_INT(boot_once(&s), RW_OTA_BOOT_ACTIVE);
        RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_B);
    }
    RW_CHECK_EQ_STR(s.version, "1.6.0");
}

static void test_an_image_that_never_confirms_is_reverted(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");
    rw_ota_state_stage(&s, RW_OTA_SLOT_B, "1.6.0");

    /* It boots, and each time fails to reach the relay. */
    for (unsigned i = 0; i < RW_OTA_TRIAL_BOOTS; i++) {
        RW_CHECK_EQ_INT(boot_once(&s), RW_OTA_BOOT_ACTIVE);
        RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_B);
    }

    /* One boot later the loader gives up on it. */
    RW_CHECK_EQ_INT(boot_once(&s), RW_OTA_BOOT_REVERTED);
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_A);
    RW_CHECK(!rw_ota_state_on_trial(&s));

    /* And stays there, without further writes. */
    for (int i = 0; i < 5; i++) {
        bool write_back = true;
        RW_CHECK_EQ_INT(rw_ota_state_on_boot(&s, &write_back), RW_OTA_BOOT_ACTIVE);
        RW_CHECK(!write_back);
        RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_A);
    }
}

/* An image that hard-faults before it can confirm burns its trials at whatever rate the
 * watchdog reboots it, which is exactly the intended behaviour: it must not loop for ever. */
static void test_an_image_that_crashes_immediately_is_reverted(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");
    rw_ota_state_stage(&s, RW_OTA_SLOT_B, "1.6.0");

    int boots = 0;
    while (boot_once(&s) == RW_OTA_BOOT_ACTIVE) {
        boots++;
        RW_CHECK(boots <= (int)RW_OTA_TRIAL_BOOTS + 1); /* must terminate */
    }
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_A);
    RW_CHECK_EQ_INT(boots, (int)RW_OTA_TRIAL_BOOTS);
}

/* Staging twice before either boots must not leave the fallback pointing at the slot currently
 * being written into. */
static void test_staging_twice_keeps_a_working_fallback(void) {
    rw_ota_state_t s;
    rw_ota_state_default(&s, "1.5.0");

    rw_ota_state_stage(&s, RW_OTA_SLOT_B, "1.6.0");
    RW_CHECK_EQ_INT(s.fallback, RW_OTA_SLOT_A);

    /* Superseded before it ever ran: the next image goes back into B, and the fallback must not
     * become B as well. */
    rw_ota_state_stage(&s, RW_OTA_SLOT_B, "1.7.0");
    RW_CHECK_EQ_INT(s.active, RW_OTA_SLOT_B);
    RW_CHECK(s.fallback != s.active);
    RW_CHECK_EQ_INT(s.fallback, RW_OTA_SLOT_A);
}

void test_ota_state(void) {
    rw_test_begin("state round trip");
    test_round_trip();
    rw_test_begin("rejects corruption");
    test_rejects_corruption();
    rw_test_begin("picks the newer copy");
    test_picks_the_newer_copy();
    rw_test_begin("sequence wrap");
    test_sequence_wrap();
    rw_test_begin("a confirmed boot writes nothing");
    test_confirmed_boot_writes_nothing();
    rw_test_begin("a good update sticks");
    test_a_good_update_sticks();
    rw_test_begin("an image that never confirms is reverted");
    test_an_image_that_never_confirms_is_reverted();
    rw_test_begin("an image that crashes immediately is reverted");
    test_an_image_that_crashes_immediately_is_reverted();
    rw_test_begin("staging twice keeps a working fallback");
    test_staging_twice_keeps_a_working_fallback();
}
