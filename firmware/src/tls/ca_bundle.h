/*
 * Root CA bundle.
 *
 * Two build options change what this returns:
 *
 *   RW_TLS_CUSTOM_CA=<path>  Replaces the curated bundle with a PEM file of the operator's
 *                            choosing, embedded at build time. For a homelab relay behind a
 *                            private CA.
 *   RW_TLS_INSECURE=1        Disables certificate verification entirely. The bundle is then
 *                            never consulted. Off by default, and the firmware flashes the
 *                            error LED pattern continuously and logs on every connection
 *                            while it is on (PROTOCOL.md §1.1).
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_CA_BUNDLE_H
#define RW_CA_BUNDLE_H

#include <stddef.h>

/* Concatenated PEM, NUL-terminated. */
const char *rw_ca_bundle(void);

/* Length including the terminating NUL, which is what mbedtls_x509_crt_parse() expects for
 * PEM input. */
size_t rw_ca_bundle_len(void);

#endif /* RW_CA_BUNDLE_H */
