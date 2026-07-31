/*
 * The signed image format, checked against the tool that writes it.
 *
 * The fixtures are produced at configure time by test/tools/make_fixture.py using the real
 * tools/sign_image.py and a throwaway key, so these tests fail if either side of the format
 * changes without the other.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "ota/image.h"
#include "ota_fixture.h"
#include "rw_test.h"

#define SLOT_MAX (768u * 1024u)

/* A mutable copy, so a test can corrupt one byte without disturbing the next test. */
static unsigned char g_img[sizeof(k_ota_image)];

static void reset(void) {
    memcpy(g_img, k_ota_image, sizeof(k_ota_image));
}

static rw_ota_status_t open_header(rw_ota_header_t *out) {
    return rw_ota_header_open(g_img, sizeof(g_img), "PW", SLOT_MAX, out);
}

static void test_accepts_a_signed_image(void) {
    reset();
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(open_header(&h), RW_OTA_OK);
    RW_CHECK_EQ_INT(h.format, RW_OTA_FORMAT_VERSION);
    RW_CHECK_EQ_INT(h.payload_len, RW_FIXTURE_PAYLOAD_LEN);
    RW_CHECK_EQ_STR(h.version, RW_FIXTURE_VERSION);
    RW_CHECK_EQ_STR(h.board, "PW");
}

static void test_payload_digest_matches(void) {
    reset();
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(open_header(&h), RW_OTA_OK);

    /* Fed in uneven chunks, because the real caller streams whatever the socket hands it. */
    rw_ota_digest_t d;
    rw_ota_digest_init(&d);
    const unsigned char *p = g_img + RW_OTA_HEADER_LEN;
    size_t remaining = h.payload_len;
    size_t chunk = 1;
    while (remaining > 0) {
        size_t n = chunk < remaining ? chunk : remaining;
        rw_ota_digest_update(&d, p, n);
        p += n;
        remaining -= n;
        chunk = chunk * 3 + 1;
    }
    RW_CHECK_EQ_INT(rw_ota_digest_finish(&d, &h), RW_OTA_OK);
}

static void test_rejects_a_flipped_payload_bit(void) {
    reset();
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(open_header(&h), RW_OTA_OK);

    g_img[RW_OTA_HEADER_LEN + 100] ^= 0x01;

    rw_ota_digest_t d;
    rw_ota_digest_init(&d);
    rw_ota_digest_update(&d, g_img + RW_OTA_HEADER_LEN, h.payload_len);
    RW_CHECK_EQ_INT(rw_ota_digest_finish(&d, &h), RW_OTA_ERR_DIGEST);
}

static void test_rejects_a_truncated_payload(void) {
    reset();
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(open_header(&h), RW_OTA_OK);

    rw_ota_digest_t d;
    rw_ota_digest_init(&d);
    rw_ota_digest_update(&d, g_img + RW_OTA_HEADER_LEN, h.payload_len - 1);
    RW_CHECK_EQ_INT(rw_ota_digest_finish(&d, &h), RW_OTA_ERR_LENGTH);
}

/* Every signed field, one at a time. Changing any of them must break the signature — that is
 * the whole point of signing the header rather than only the payload. */
static void test_rejects_header_tampering(void) {
    const size_t fields[] = {4 /*format*/, 6 /*flags*/, 8 /*length*/, 12 /*version*/,
                             28 /*board*/, 32 /*payload sha*/, 63 /*last signed byte*/};
    for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
        reset();
        g_img[fields[i]] ^= 0xFF;
        rw_ota_header_t h;
        rw_ota_status_t got = open_header(&h);
        /* Some edits are caught by a cheaper check before the signature is reached; what matters
         * is that none of them is accepted. */
        RW_CHECK(got != RW_OTA_OK);
    }
}

static void test_rejects_a_tampered_signature(void) {
    reset();
    g_img[64] ^= 0x01;
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(open_header(&h), RW_OTA_ERR_SIGNATURE);
}

static void test_rejects_the_wrong_board(void) {
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(rw_ota_header_open(k_ota_image_other_board,
                                       sizeof(k_ota_image_other_board), "PW", SLOT_MAX, &h),
                    RW_OTA_ERR_BOARD);
    /* ...and the same bytes are accepted by the board they were built for. */
    RW_CHECK_EQ_INT(rw_ota_header_open(k_ota_image_other_board,
                                       sizeof(k_ota_image_other_board), "P2W", SLOT_MAX, &h),
                    RW_OTA_OK);
}

static void test_rejects_an_image_larger_than_the_slot(void) {
    reset();
    rw_ota_header_t h;
    RW_CHECK_EQ_INT(
        rw_ota_header_open(g_img, sizeof(g_img), "PW", RW_FIXTURE_PAYLOAD_LEN - 1, &h),
        RW_OTA_ERR_LENGTH);
}

static void test_rejects_rubbish(void) {
    rw_ota_header_t h;
    unsigned char   junk[RW_OTA_HEADER_LEN] = {0};

    RW_CHECK_EQ_INT(rw_ota_header_open(junk, sizeof(junk), "PW", SLOT_MAX, &h),
                    RW_OTA_ERR_MAGIC);

    reset();
    RW_CHECK_EQ_INT(rw_ota_header_open(g_img, RW_OTA_HEADER_LEN - 1, "PW", SLOT_MAX, &h), RW_OTA_ERR_SHORT);
}

void test_ota_image(void) {
    rw_test_begin("accepts a signed image");
    test_accepts_a_signed_image();
    rw_test_begin("payload digest matches");
    test_payload_digest_matches();
    rw_test_begin("rejects a flipped payload bit");
    test_rejects_a_flipped_payload_bit();
    rw_test_begin("rejects a truncated payload");
    test_rejects_a_truncated_payload();
    rw_test_begin("rejects header tampering");
    test_rejects_header_tampering();
    rw_test_begin("rejects a tampered signature");
    test_rejects_a_tampered_signature();
    rw_test_begin("rejects the wrong board");
    test_rejects_the_wrong_board();
    rw_test_begin("rejects an image larger than the slot");
    test_rejects_an_image_larger_than_the_slot();
    rw_test_begin("rejects rubbish");
    test_rejects_rubbish();
}
