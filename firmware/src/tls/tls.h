/*
 * TLS client configuration over altcp_tls + mbedTLS.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_TLS_H
#define RW_TLS_H

#include <stdbool.h>

#include "lwip/altcp.h"

/*
 * Build the shared client configuration: parse the CA bundle, pin the verification mode, and
 * install the wall clock mbedTLS uses for certificate validity.
 *
 * `config_insecure` is the TLS_INSECURE flag from flash. It is OR-ed with the RW_TLS_INSECURE
 * build option; either one turns verification off, and neither can turn it back on.
 *
 * Returns false if the CA bundle does not parse, which is a build defect rather than a runtime
 * condition and is treated as fatal by the caller.
 */
bool rw_tls_init(bool config_insecure);

/* True when certificate verification is disabled, from either source. */
bool rw_tls_insecure(void);

/*
 * Create a TLS-layered altcp pcb with SNI set to `host`.
 *
 * SNI is mandatory (PROTOCOL.md §1.1) and setting it is also what arms mbedTLS's hostname
 * check against the certificate's SAN list. A connection whose SNI cannot be set is refused
 * rather than made without it — a certificate that is never matched against a name is a
 * certificate that proves nothing.
 *
 * Returns NULL on failure; the caller retries with backoff.
 */
struct altcp_pcb *rw_tls_new(const char *host);

/* Human-readable mbedTLS error, for logs. Never NULL. */
const char *rw_tls_strerror(int code);

#endif /* RW_TLS_H */
