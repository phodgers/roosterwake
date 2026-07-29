/*
 * Magic packet construction.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "rw_test.h"
#include "wol/magic.h"

void test_wol(void) {
    rw_test_begin("magic packet layout");

    const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t       packet[RW_WOL_MAGIC_LEN];

    /* Poison the buffer first so a builder that writes fewer than 102 bytes is caught rather
     * than passing on whatever happened to be zero already. */
    memset(packet, 0x5A, sizeof(packet));
    rw_wol_build_magic(mac, packet);

    RW_CHECK_EQ_INT(RW_WOL_MAGIC_LEN, 102);

    for (int i = 0; i < 6; i++) {
        RW_CHECK_MSG(packet[i] == 0xFF, "sync byte %d is 0x%02x, expected 0xFF", i, packet[i]);
    }
    for (int rep = 0; rep < 16; rep++) {
        RW_CHECK_MSG(memcmp(packet + 6 + rep * 6, mac, 6) == 0,
                     "MAC repetition %d does not match", rep);
    }

    /* An all-zero MAC is still a well-formed packet: validation belongs at the input boundary,
     * and a builder that second-guesses its caller hides the real bug. */
    const uint8_t zero[6] = {0};
    rw_wol_build_magic(zero, packet);
    for (int i = 0; i < 6; i++) {
        RW_CHECK(packet[i] == 0xFF);
    }
    for (int i = 6; i < RW_WOL_MAGIC_LEN; i++) {
        RW_CHECK(packet[i] == 0x00);
    }

    /* A byte pattern that would expose an off-by-one in the repetition loop. */
    const uint8_t seq[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    rw_wol_build_magic(seq, packet);
    RW_CHECK_EQ_INT(packet[6], 0x01);
    RW_CHECK_EQ_INT(packet[11], 0x06);
    RW_CHECK_EQ_INT(packet[RW_WOL_MAGIC_LEN - 6], 0x01);
    RW_CHECK_EQ_INT(packet[RW_WOL_MAGIC_LEN - 1], 0x06);
}
