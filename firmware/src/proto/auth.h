/*
 * The PROTOCOL.md §3.2 mutual challenge-response.
 *
 * The device token never leaves the device. Both directions prove possession of it with an
 * HMAC over both nonces and a direction-specific tag, and both sides compare in constant time.
 *
 * Host-portable: this file and auth.c compile into the native test binary against the same
 * mbedTLS SHA-256 the device uses, so the proof vectors are exercised without hardware.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_AUTH_H
#define RW_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define RW_TOKEN_BYTES  32
#define RW_TOKEN_HEX    64
#define RW_DEVICE_ID_HEX 16
#define RW_NONCE_BYTES  16
#define RW_NONCE_HEX    32
#define RW_PROOF_BYTES  16
#define RW_PROOF_HEX    32

/* Domain-separation tags. Reusing one tag for both directions would let an eavesdropper replay
 * a device's proof back at it as the relay's (PROTOCOL.md §3.2). */
#define RW_PROOF_TAG_CLIENT "rw1:c"
#define RW_PROOF_TAG_SERVER "rw1:s"

/* HMAC-SHA256, RFC 2104, over mbedTLS's SHA-256. */
void rw_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *msg, size_t msg_len,
                    uint8_t out[32]);

/* Lower-case hex, NUL-terminated. `out` needs 2*in_len+1 bytes. */
void rw_hex_encode(const uint8_t *in, size_t in_len, char *out);

/* Strict: rejects upper case, odd lengths and any non-hex byte. Returns false without writing
 * a partial result. Lower-case-only is deliberate — PROTOCOL.md §2 specifies lower case, and
 * accepting both would let two implementations disagree about what to hash. */
bool rw_hex_decode(const char *hex, size_t hex_len, uint8_t *out, size_t out_len);

/*
 * Compute a proof.
 *
 * proof = first 16 bytes of HMAC-SHA256(token_bytes, tag + device_id + nonce_c + nonce_s),
 * lower-case hex. `tag` is RW_PROOF_TAG_CLIENT or RW_PROOF_TAG_SERVER. `token_hex` is the
 * 64-character stored form; it is decoded to the raw 32 bytes before use, because HMAC keyed
 * with the ASCII text produces a plausible-looking proof that never matches.
 *
 * `out` needs RW_PROOF_HEX + 1 bytes. Returns false if any input is malformed.
 */
bool rw_auth_proof(const char *token_hex, const char *tag, const char *device_id,
                   const char *nonce_c, const char *nonce_s, char *out);

/* Constant-time equality. Returns true when the buffers match. */
bool rw_ct_equal(const void *a, const void *b, size_t len);

/*
 * Verify a hex proof received from the relay against `expected_hex`, in constant time.
 *
 * A wrong-length or non-hex proof takes the same path as a wrong one: it is compared against
 * the expected value anyway, so a malformed proof is not distinguishable from an incorrect
 * proof by timing.
 */
bool rw_auth_verify_proof(const char *expected_hex, const char *offered_hex);

#endif /* RW_AUTH_H */
