/*
 * The PROTOCOL.md §3.2 mutual challenge-response. See auth.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "proto/auth.h"

#include <string.h>

#include "mbedtls/sha256.h"

#define SHA256_BLOCK_LEN  64
#define SHA256_DIGEST_LEN 32

/*
 * HMAC-SHA256 built directly on mbedTLS's SHA-256 rather than on mbedtls_md.
 *
 * mbedtls_md drags in the cipher/digest registry and, in 3.x, the PSA shims — several
 * kilobytes of dispatch machinery to reach one hash we already have a direct handle on. RFC
 * 2104 is twenty lines and is exercised by an RFC 4231 vector in the host tests.
 */
void rw_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[SHA256_DIGEST_LEN]) {
    uint8_t k[SHA256_BLOCK_LEN];
    uint8_t pad[SHA256_BLOCK_LEN];
    uint8_t inner[SHA256_DIGEST_LEN];

    mbedtls_sha256_context ctx;

    memset(k, 0, sizeof(k));
    if (key_len > SHA256_BLOCK_LEN) {
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, key, key_len);
        mbedtls_sha256_finish(&ctx, k);
        mbedtls_sha256_free(&ctx);
    } else {
        memcpy(k, key, key_len);
    }

    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    }
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pad, SHA256_BLOCK_LEN);
    mbedtls_sha256_update(&ctx, msg, msg_len);
    mbedtls_sha256_finish(&ctx, inner);
    mbedtls_sha256_free(&ctx);

    for (size_t i = 0; i < SHA256_BLOCK_LEN; i++) {
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    }
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, pad, SHA256_BLOCK_LEN);
    mbedtls_sha256_update(&ctx, inner, SHA256_DIGEST_LEN);
    mbedtls_sha256_finish(&ctx, out);
    mbedtls_sha256_free(&ctx);

    /* The derived key block and the inner digest are key-equivalent material. Clear them
     * rather than leave them on a stack that the next TLS handshake will reuse. */
    memset(k, 0, sizeof(k));
    memset(pad, 0, sizeof(pad));
    memset(inner, 0, sizeof(inner));
}

void rw_hex_encode(const uint8_t *in, size_t in_len, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out[i * 2]     = hex[in[i] >> 4];
        out[i * 2 + 1] = hex[in[i] & 0x0f];
    }
    out[in_len * 2] = '\0';
}

bool rw_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len) {
    if (hex == NULL || hex_len != out_len * 2) {
        return false;
    }
    for (size_t i = 0; i < out_len; i++) {
        int hi = -1, lo = -1;
        char a = hex[i * 2], b = hex[i * 2 + 1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        if (hi < 0 || lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool rw_auth_proof(const char *token_hex, const char *tag, const char *device_id,
                   const char *nonce_c, const char *nonce_s, char *out) {
    if (token_hex == NULL || tag == NULL || device_id == NULL || nonce_c == NULL ||
        nonce_s == NULL || out == NULL) {
        return false;
    }
    if (strlen(device_id) != RW_DEVICE_ID_HEX || strlen(nonce_c) != RW_NONCE_HEX ||
        strlen(nonce_s) != RW_NONCE_HEX) {
        return false;
    }

    uint8_t token[RW_TOKEN_BYTES];
    if (!rw_hex_decode(token_hex, strlen(token_hex), token, sizeof(token))) {
        return false;
    }

    /* tag(5) + device_id(16) + nonce_c(32) + nonce_s(32) = 85 bytes, concatenated as ASCII
     * with no separator, in exactly this order. */
    char   msg[5 + RW_DEVICE_ID_HEX + RW_NONCE_HEX + RW_NONCE_HEX];
    size_t n = 0;
    size_t tag_len = strlen(tag);
    if (tag_len != 5) {
        memset(token, 0, sizeof(token));
        return false;
    }
    memcpy(msg + n, tag, tag_len);
    n += tag_len;
    memcpy(msg + n, device_id, RW_DEVICE_ID_HEX);
    n += RW_DEVICE_ID_HEX;
    memcpy(msg + n, nonce_c, RW_NONCE_HEX);
    n += RW_NONCE_HEX;
    memcpy(msg + n, nonce_s, RW_NONCE_HEX);
    n += RW_NONCE_HEX;

    uint8_t mac[SHA256_DIGEST_LEN];
    rw_hmac_sha256(token, sizeof(token), (const uint8_t *)msg, n, mac);
    memset(token, 0, sizeof(token));

    /* Transmitted as the first 16 bytes only. */
    rw_hex_encode(mac, RW_PROOF_BYTES, out);
    return true;
}

bool rw_ct_equal(const void *a, const void *b, size_t len) {
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    volatile uint8_t        diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return diff == 0;
}

bool rw_auth_verify_proof(const char *expected_hex, const char *offered_hex) {
    uint8_t expected[RW_PROOF_BYTES];
    uint8_t offered[RW_PROOF_BYTES];

    if (expected_hex == NULL || offered_hex == NULL) {
        return false;
    }
    if (!rw_hex_decode(expected_hex, strlen(expected_hex), expected, sizeof(expected))) {
        return false;
    }

    /* A malformed offer becomes all-zero and is still compared, so "wrong length" and "wrong
     * value" cost the same time. An all-zero expected proof would make this trivially true,
     * which is why the expected value is required to decode and is our own computation. */
    if (!rw_hex_decode(offered_hex, strlen(offered_hex), offered, sizeof(offered))) {
        memset(offered, 0, sizeof(offered));
    }

    return rw_ct_equal(expected, offered, RW_PROOF_BYTES);
}
