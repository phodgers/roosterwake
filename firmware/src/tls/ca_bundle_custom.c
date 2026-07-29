/*
 * The RW_TLS_CUSTOM_CA half of the bundle.
 *
 * When the build is configured with -DRW_TLS_CUSTOM_CA=/path/to/roots.pem, CMake emits
 * rw_custom_ca.h into the build directory as a byte array and this translation unit provides
 * the bundle instead of the curated one in ca_bundle.c.
 *
 * Emitted as bytes rather than a C string literal on purpose: a PEM pasted into a string
 * literal is one stray backslash away from a bundle that parses to something other than what
 * the operator supplied, and this is the file where that would matter most.
 *
 * SPDX-License-Identifier: MIT
 */
#include "tls/ca_bundle.h"

#ifdef RW_TLS_CUSTOM_CA

#include "rw_custom_ca.h"

const char *rw_ca_bundle(void) {
    return (const char *)k_rw_custom_ca;
}

size_t rw_ca_bundle_len(void) {
    return sizeof(k_rw_custom_ca); /* the generator appends the NUL mbedTLS needs */
}

#endif /* RW_TLS_CUSTOM_CA */
