/*
 * The smallest mbedTLS configuration that builds SHA-256, SHA-1 and base64 for the host tests.
 *
 * The device's configuration is firmware/src/tls/mbedtls_config.h and is much larger, because
 * it also has to do TLS. This one exists so the tests exercise the same hash and base64 code
 * the device runs, rather than a substitute that could agree with the tests and disagree with
 * the hardware.
 *
 * MBEDTLS_PLATFORM_C is required on Windows by mbedTLS's own check_config.h, and is harmless
 * everywhere else, so it is unconditional rather than guarded — a config that differs between
 * CI and a developer's laptop is a config that will eventually only fail on one of them.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_HOST_MBEDTLS_CONFIG_H
#define RW_HOST_MBEDTLS_CONFIG_H

#define MBEDTLS_PLATFORM_C

#define MBEDTLS_SHA1_C   /* RFC 6455 Sec-WebSocket-Accept */
#define MBEDTLS_SHA224_C /* mbedTLS builds SHA-224 alongside SHA-256 */
#define MBEDTLS_SHA256_C /* HMAC in proto/auth.c */
#define MBEDTLS_BASE64_C /* the accept value and the key */

#endif /* RW_HOST_MBEDTLS_CONFIG_H */
