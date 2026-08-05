/*
 * mbedTLS configuration for Rooster Wake.
 *
 * Picked up through the SDK's pico_mbedtls_config.h, which does `#include "mbedtls_config.h"`
 * and finds this file because firmware/src/tls is on the include path.
 *
 * The shape of this file is a size/attack-surface decision, not a preference. Every algorithm
 * enabled here is one this device actually negotiates against the public CAs in
 * tls/ca_bundle.c; everything else is off, so it cannot be downgraded into, and does not cost
 * flash.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_MBEDTLS_CONFIG_H
#define RW_MBEDTLS_CONFIG_H

/* ── Platform ──────────────────────────────────────────────────────────────── */

#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_NO_PLATFORM_ENTROPY

/*
 * lwIP's altcp_tls_mbedtls.c reads mbedtls_ssl_context::out_left and mbedtls_ssl_session::start
 * directly to work out how many bytes are still queued in the record layer. Those members are
 * MBEDTLS_PRIVATE in 3.x, so the glue does not compile without this. It is mbedTLS's own
 * documented escape hatch, not a workaround of ours, and there is no version of this build in
 * which lwIP's TLS layer works without it.
 */
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/*
 * Certificate expiry is checked, and that needs a wall clock (PROTOCOL.md §1.1). The clock is
 * supplied at runtime by mbedtls_platform_set_time() over the SNTP-disciplined counter in
 * sys/wallclock.c. Leaving MBEDTLS_HAVE_TIME_DATE undefined would make mbedTLS skip validity
 * checking silently, which the protocol document explicitly forbids.
 */
#define MBEDTLS_HAVE_TIME
#define MBEDTLS_HAVE_TIME_DATE
#define MBEDTLS_PLATFORM_TIME_ALT

/*
 * MBEDTLS_HAVE_TIME also obliges the platform to provide a monotonic millisecond clock, and
 * mbedTLS's own implementations are POSIX- and Windows-only. tls/tls.c supplies one over the
 * RP2350's 64-bit microsecond timer, which is exactly the monotonic source this wants.
 */
#define MBEDTLS_PLATFORM_MS_TIME_ALT

/* Numeric mbedTLS error codes are unreadable in a support conversation. The string table costs
 * a few kilobytes of a 4 MB part and turns "-0x2700" into "X509 - Certificate verification
 * failed", which is the difference between a fixable report and a shrug. */
#define MBEDTLS_ERROR_C

/*
 * Full handshake tracing, and known-answer tests for the primitives. Compiled out of release
 * builds: several kilobytes of strings, and it prints handshake material.
 */
#ifdef RW_TLS_TRACE
#define MBEDTLS_DEBUG_C
/* Known-answer tests for the primitives, run at boot. A TLS session that fails on its first
 * ENCRYPTED record while every plaintext step succeeded is either a key-derivation or a
 * cipher fault, and these say which - on this silicon, not on a workstation. */
#define MBEDTLS_SELF_TEST
#endif

/* ── Entropy and RNG ───────────────────────────────────────────────────────── */

/* mbedtls_hardware_poll() is provided by pico_mbedtls and is fed by pico_rand, which on the
 * RP2350 is seeded and continuously re-mixed from the hardware TRNG. */
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_CTR_DRBG_C

/* ── Hashes ────────────────────────────────────────────────────────────────── */

#define MBEDTLS_MD_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C

/*
 * SHA-1 is here for exactly one reason: RFC 6455 §4.1 defines Sec-WebSocket-Accept as a SHA-1
 * digest. It is not enabled for certificate signatures — MBEDTLS_X509_ALLOW_UNSUPPORTED_
 * CRITICAL_EXTENSION and the SHA-1-in-certificates option stay off — so no CA path can be
 * validated with it.
 */
#define MBEDTLS_SHA1_C

/*
 * The SHA-256 hardware accelerator on the RP2350 is deliberately not used. It is a single
 * shared unit that has to be locked, and this firmware hashes from two places that can be
 * live at once: the TLS record layer and the HMAC proof in proto/auth.c. Serialising them
 * correctly would cost more than the accelerator saves at four hashes per connection.
 */
#undef MBEDTLS_SHA256_ALT

/* ── Symmetric crypto ──────────────────────────────────────────────────────── */

#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CIPHER_C

/* ── Public key ────────────────────────────────────────────────────────────── */

#define MBEDTLS_BIGNUM_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21 /* rsa_pss_rsae_* signature schemes, which public CAs now emit */

#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C

/*
 * X25519 first: it is what Cloudflare and Google front ends prefer and the cheapest of the
 * three. P-256 and P-384 cover the ECDSA roots in the bundle (ISRG Root X2 and GTS Root R4
 * are both P-384).
 */
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_NIST_OPTIM

/* ── X.509 ─────────────────────────────────────────────────────────────────── */

#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* ── TLS ───────────────────────────────────────────────────────────────────── */

#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_EXTENDED_MASTER_SECRET

/*
 * SNI. Not optional: PROTOCOL.md §1.1 makes it mandatory because relays — ours included —
 * sit behind virtual hosting and cannot select a certificate without it.
 */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION

#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/*
 * ECDHE with AES-GCM only. Forward secrecy is not negotiable for a link that carries a
 * challenge-response over a long-lived credential, and AEAD removes the entire family of
 * CBC padding-oracle problems from the code that has to run unattended for years.
 */
#define MBEDTLS_SSL_CIPHERSUITES                          \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,      \
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,        \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,      \
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

/*
 * Record buffers.
 *
 * Outbound is 4 KB, which is generous: PROTOCOL.md §1 caps any frame at 2048, and only
 * `scan_result` comes near that.
 *
 * Inbound is the full 16 KB a TLS 1.2 record is allowed to be, and that is a deliberate
 * change from the 4 KB this was originally specified at. The reason is lwIP: `struct
 * altcp_tls_config` is private to altcp_tls_mbedtls.c, so there is no way to reach the
 * mbedtls_ssl_config and call mbedtls_ssl_conf_max_frag_len(). Without that call the
 * max_fragment_length extension is never offered, and a 4 KB input buffer would then fail
 * against any server that chose to emit a larger record — most often the Certificate message
 * during the handshake, whose size is the server's choice and not ours.
 *
 * A device that cannot connect because it asked the server to be considerate and the server
 * declined is a worse outcome than 12 KB of a 520 KB part. MBEDTLS_SSL_MAX_FRAGMENT_LENGTH is
 * left undefined rather than enabled-but-unreachable: code that cannot be exercised is worse
 * than code that is absent.
 */
#define MBEDTLS_SSL_IN_CONTENT_LEN  16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN 4096

#endif /* RW_MBEDTLS_CONFIG_H */
