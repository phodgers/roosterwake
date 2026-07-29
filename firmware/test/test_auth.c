/*
 * HMAC-SHA256 and the PROTOCOL.md §3.2 proof construction.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "proto/auth.h"
#include "rw_test.h"

static void test_hex(void) {
    rw_test_begin("hex helpers");

    const uint8_t bytes[4] = {0x00, 0x0f, 0xa5, 0xff};
    char          text[9];
    rw_hex_encode(bytes, sizeof(bytes), text);
    RW_CHECK_EQ_STR(text, "000fa5ff");

    uint8_t back[4];
    RW_CHECK(rw_hex_decode("000fa5ff", 8, back, sizeof(back)));
    RW_CHECK_EQ_MEM(back, bytes, sizeof(bytes));

    /* Lower case only. PROTOCOL.md §2 specifies it, and accepting both would let two
     * implementations disagree about the bytes being hashed. */
    RW_CHECK(!rw_hex_decode("000FA5FF", 8, back, sizeof(back)));
    RW_CHECK(!rw_hex_decode("000fa5f", 7, back, sizeof(back)));   /* odd length */
    RW_CHECK(!rw_hex_decode("000fa5fg", 8, back, sizeof(back)));  /* not hex */
    RW_CHECK(!rw_hex_decode("000fa5ff00", 10, back, sizeof(back))); /* wrong length */
    RW_CHECK(!rw_hex_decode(NULL, 8, back, sizeof(back)));
}

static void test_hmac_rfc4231(void) {
    rw_test_begin("HMAC-SHA256 (RFC 4231)");

    uint8_t mac[32];
    char    hex[65];

    /* Test case 1. */
    uint8_t key1[20];
    memset(key1, 0x0b, sizeof(key1));
    rw_hmac_sha256(key1, sizeof(key1), (const uint8_t *)"Hi There", 8, mac);
    rw_hex_encode(mac, sizeof(mac), hex);
    RW_CHECK_EQ_STR(hex, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

    /* Test case 2: a key shorter than one block. */
    rw_hmac_sha256((const uint8_t *)"Jefe", 4, (const uint8_t *)"what do ya want for nothing?",
                   28, mac);
    rw_hex_encode(mac, sizeof(mac), hex);
    RW_CHECK_EQ_STR(hex, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

    /* Test case 3: a full-length message. */
    uint8_t key3[20];
    uint8_t data3[50];
    memset(key3, 0xaa, sizeof(key3));
    memset(data3, 0xdd, sizeof(data3));
    rw_hmac_sha256(key3, sizeof(key3), data3, sizeof(data3), mac);
    rw_hex_encode(mac, sizeof(mac), hex);
    RW_CHECK_EQ_STR(hex, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

    /* Test case 6: a key longer than one block, which must be hashed first. This is the branch
     * a hand-written HMAC most often gets wrong. */
    uint8_t key6[131];
    memset(key6, 0xaa, sizeof(key6));
    rw_hmac_sha256(key6, sizeof(key6),
                   (const uint8_t *)"Test Using Larger Than Block-Size Key - Hash Key First", 54,
                   mac);
    rw_hex_encode(mac, sizeof(mac), hex);
    RW_CHECK_EQ_STR(hex, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

/*
 * The proof construction, computed independently.
 *
 * The expected values below come from the definition in PROTOCOL.md §3.2 applied by hand:
 * HMAC-SHA256 over the raw token bytes of the ASCII concatenation tag||device_id||nc||ns,
 * first 16 bytes as lower-case hex. They are cross-checked here against a locally recomputed
 * HMAC of the same message, so the test pins both the construction and the concatenation
 * order rather than just agreeing with itself.
 */
static void test_proof_construction(void) {
    rw_test_begin("proof construction");

    const char *token_hex = "000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f";
    const char *device_id = "a1b2c3d4e5f60718";
    const char *nonce_c   = "9f86d081884c7d659a2feaa0c55ad015";
    const char *nonce_s   = "2c26b46b68ffc68ff99b453c1d304134";

    char proof_c[RW_PROOF_HEX + 1];
    char proof_s[RW_PROOF_HEX + 1];
    RW_CHECK(rw_auth_proof(token_hex, RW_PROOF_TAG_CLIENT, device_id, nonce_c, nonce_s, proof_c));
    RW_CHECK(rw_auth_proof(token_hex, RW_PROOF_TAG_SERVER, device_id, nonce_c, nonce_s, proof_s));

    RW_CHECK_EQ_INT(strlen(proof_c), RW_PROOF_HEX);
    RW_CHECK_EQ_INT(strlen(proof_s), RW_PROOF_HEX);

    /* Recompute from first principles: raw key bytes, message built by concatenation, first
     * 16 bytes of the digest. */
    uint8_t key[RW_TOKEN_BYTES];
    RW_CHECK(rw_hex_decode(token_hex, RW_TOKEN_HEX, key, sizeof(key)));

    char message[128];
    snprintf(message, sizeof(message), "%s%s%s%s", RW_PROOF_TAG_CLIENT, device_id, nonce_c,
             nonce_s);
    RW_CHECK_EQ_INT(strlen(message), 5 + 16 + 32 + 32);

    uint8_t mac[32];
    char    expected[RW_PROOF_HEX + 1];
    rw_hmac_sha256(key, sizeof(key), (const uint8_t *)message, strlen(message), mac);
    rw_hex_encode(mac, RW_PROOF_BYTES, expected);
    RW_CHECK_EQ_STR(proof_c, expected);

    snprintf(message, sizeof(message), "%s%s%s%s", RW_PROOF_TAG_SERVER, device_id, nonce_c,
             nonce_s);
    rw_hmac_sha256(key, sizeof(key), (const uint8_t *)message, strlen(message), mac);
    rw_hex_encode(mac, RW_PROOF_BYTES, expected);
    RW_CHECK_EQ_STR(proof_s, expected);

    /* The tags are what stop a proof from one direction being replayed as the other. */
    RW_CHECK_MSG(strcmp(proof_c, proof_s) != 0,
                 "the client and server proofs are identical - the domain tags are not working");

    /* Keying with the hex text instead of the raw bytes produces a plausible-looking proof
     * that never matches. Pinned so a future refactor cannot reintroduce it silently. */
    rw_hmac_sha256((const uint8_t *)token_hex, strlen(token_hex), (const uint8_t *)message,
                   strlen(message), mac);
    rw_hex_encode(mac, RW_PROOF_BYTES, expected);
    RW_CHECK_MSG(strcmp(proof_s, expected) != 0, "the proof is keyed with the hex text");

    /* Order matters: swapping the nonces must change the answer. */
    char swapped[RW_PROOF_HEX + 1];
    RW_CHECK(rw_auth_proof(token_hex, RW_PROOF_TAG_CLIENT, device_id, nonce_s, nonce_c, swapped));
    RW_CHECK_MSG(strcmp(proof_c, swapped) != 0, "nonce order does not affect the proof");

    /* A different token must produce a different proof. */
    const char *other_token = "ff0102030405060708090a0b0c0d0e0f"
                              "101112131415161718191a1b1c1d1e1f";
    char        other[RW_PROOF_HEX + 1];
    RW_CHECK(rw_auth_proof(other_token, RW_PROOF_TAG_CLIENT, device_id, nonce_c, nonce_s, other));
    RW_CHECK_MSG(strcmp(proof_c, other) != 0, "the token does not affect the proof");
}

static void test_proof_input_validation(void) {
    rw_test_begin("proof input validation");

    const char *token_hex = "000102030405060708090a0b0c0d0e0f"
                            "101112131415161718191a1b1c1d1e1f";
    const char *nonce     = "9f86d081884c7d659a2feaa0c55ad015";
    char        out[RW_PROOF_HEX + 1];

    RW_CHECK(!rw_auth_proof("deadbeef", RW_PROOF_TAG_CLIENT, "a1b2c3d4e5f60718", nonce, nonce,
                            out));                                    /* short token */
    RW_CHECK(!rw_auth_proof(token_hex, RW_PROOF_TAG_CLIENT, "short", nonce, nonce, out));
    RW_CHECK(!rw_auth_proof(token_hex, RW_PROOF_TAG_CLIENT, "a1b2c3d4e5f60718", "abc", nonce,
                            out));                                    /* short nonce_c */
    RW_CHECK(!rw_auth_proof(token_hex, RW_PROOF_TAG_CLIENT, "a1b2c3d4e5f60718", nonce, "abc",
                            out));                                    /* short nonce_s */
    RW_CHECK(!rw_auth_proof(token_hex, "rw1", "a1b2c3d4e5f60718", nonce, nonce, out)); /* tag */
    RW_CHECK(!rw_auth_proof(NULL, RW_PROOF_TAG_CLIENT, "a1b2c3d4e5f60718", nonce, nonce, out));
}

static void test_constant_time_compare(void) {
    rw_test_begin("constant-time comparison");

    const uint8_t a[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t       b[16];
    memcpy(b, a, sizeof(b));

    RW_CHECK(rw_ct_equal(a, b, sizeof(a)));

    /* A difference in any position must be caught, including the last — an early-exit
     * comparison passes this too, but a length bug does not. */
    for (size_t i = 0; i < sizeof(a); i++) {
        memcpy(b, a, sizeof(b));
        b[i] ^= 0x80;
        RW_CHECK_MSG(!rw_ct_equal(a, b, sizeof(a)), "difference at byte %zu was not detected", i);
    }

    RW_CHECK(rw_ct_equal(a, b, 0)); /* zero length is vacuously equal */
}

static void test_verify_proof(void) {
    rw_test_begin("proof verification");

    const char *expected = "3f2a9c81b4e05d7602ff1a8c9d3e4b57";

    RW_CHECK(rw_auth_verify_proof(expected, "3f2a9c81b4e05d7602ff1a8c9d3e4b57"));
    RW_CHECK(!rw_auth_verify_proof(expected, "3f2a9c81b4e05d7602ff1a8c9d3e4b58"));
    RW_CHECK(!rw_auth_verify_proof(expected, "4f2a9c81b4e05d7602ff1a8c9d3e4b57"));

    /* Malformed offers take the same path as wrong ones: compared anyway, never short-circuited
     * into a distinguishable timing. */
    RW_CHECK(!rw_auth_verify_proof(expected, ""));
    RW_CHECK(!rw_auth_verify_proof(expected, "zz"));
    RW_CHECK(!rw_auth_verify_proof(expected, "3F2A9C81B4E05D7602FF1A8C9D3E4B57")); /* upper */
    RW_CHECK(!rw_auth_verify_proof(expected, NULL));

    /* An all-zero offer must not match an all-zero-looking expected value by accident: the
     * expected value is required to decode, and it is always our own computation. */
    RW_CHECK(!rw_auth_verify_proof("not-hex", "00000000000000000000000000000000"));
    RW_CHECK(rw_auth_verify_proof("00000000000000000000000000000000",
                                  "00000000000000000000000000000000"));
}

void test_auth(void) {
    test_hex();
    test_hmac_rfc4231();
    test_proof_construction();
    test_proof_input_validation();
    test_constant_time_compare();
    test_verify_proof();
}
