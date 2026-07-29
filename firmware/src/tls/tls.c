/*
 * TLS client configuration. See tls.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "tls/tls.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "lwip/altcp_tls.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/ssl.h"
#include "pico/time.h"

#include "rw_log.h"
#include "sys/wallclock.h"
#include "tls/ca_bundle.h"

static struct altcp_tls_config *s_config;
static bool                     s_insecure;

/*
 * mbedTLS's clock. Returns 0 until SNTP has answered, which makes every certificate fail its
 * notBefore check — the loud failure PROTOCOL.md §1.1 asks for, rather than the silent pass
 * that comes from compiling without MBEDTLS_HAVE_TIME_DATE.
 */
static mbedtls_time_t rw_tls_time(mbedtls_time_t *t) {
    mbedtls_time_t now = (mbedtls_time_t)rw_wallclock_now();
    if (t != NULL) {
        *t = now;
    }
    return now;
}

/*
 * Monotonic milliseconds, required by MBEDTLS_HAVE_TIME for its own internal timers (session
 * lifetimes, DTLS retransmission). Deliberately not the wall clock: this must not jump when
 * SNTP disciplines the clock, and time since boot never does.
 */
mbedtls_ms_time_t mbedtls_ms_time(void) {
    return (mbedtls_ms_time_t)(to_us_since_boot(get_absolute_time()) / 1000);
}

bool rw_tls_init(bool config_insecure) {
    mbedtls_platform_set_time(rw_tls_time);

#ifdef RW_TLS_INSECURE
    s_insecure = true;
#else
    s_insecure = config_insecure;
#endif

    if (s_config != NULL) {
        altcp_tls_free_config(s_config);
        s_config = NULL;
    }

    /*
     * The CA bundle is supplied even in insecure mode. mbedTLS still builds the chain and
     * computes the verification flags; the per-connection callback installed by rw_tls_new()
     * then reports exactly what would have failed before clearing them. An operator running
     * without verification should still be able to see that the certificate was, say, merely
     * expired rather than issued by nobody at all.
     *
     * Note what is NOT configurable here: lwIP keeps `struct altcp_tls_config` private to
     * altcp_tls_mbedtls.c, so the mbedtls_ssl_config inside it is unreachable and neither the
     * authmode nor the max_fragment_length extension can be set through it. Both are therefore
     * handled elsewhere — the authmode per connection below, the record size by compiling a
     * 16 KB input buffer (see tls/mbedtls_config.h).
     */
    s_config = altcp_tls_create_config_client((const u8_t *)rw_ca_bundle(), rw_ca_bundle_len());
    if (s_config == NULL) {
        RW_LOG_ERROR("tls: CA bundle failed to parse");
        return false;
    }

    if (s_insecure) {
        RW_LOG_ERROR("tls: CERTIFICATE VERIFICATION IS DISABLED - this link can be intercepted");
    }
    return true;
}

bool rw_tls_insecure(void) {
    return s_insecure;
}

/*
 * Verification callback used only when verification is disabled.
 *
 * mbedTLS calls this for each certificate in the chain with the flags it computed. Clearing
 * them makes the handshake proceed. Logging them first is the point: "disabled" should still
 * mean "and here is precisely what it would have objected to", so a homelab operator who
 * turned this on for a self-signed certificate finds out the day their chain breaks for a
 * different reason.
 */
static int permissive_verify(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
    (void)ctx;
    (void)crt;
    if (*flags != 0) {
        RW_LOG_ERROR("tls: certificate at depth %d would have FAILED (flags 0x%08lx); accepted "
                     "because verification is disabled",
                     depth, (unsigned long)*flags);
        *flags = 0;
    }
    return 0;
}

struct altcp_pcb *rw_tls_new(const char *host) {
    if (s_config == NULL) {
        RW_LOG_ERROR("tls: not initialised");
        return NULL;
    }
    if (host == NULL || host[0] == '\0') {
        RW_LOG_ERROR("tls: refusing a connection with no SNI hostname");
        return NULL;
    }

    if (s_insecure) {
        /* Repeated on every connection, by design. A device left in this state months ago
         * should say so in every log a support conversation might reach for. */
        RW_LOG_ERROR("tls: connecting to %s with verification DISABLED", host);
    }

    struct altcp_pcb *pcb = altcp_tls_new(s_config, IPADDR_TYPE_V4);
    if (pcb == NULL) {
        RW_LOG_ERROR("tls: out of memory allocating the TLS pcb");
        return NULL;
    }

    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)altcp_tls_context(pcb);
    if (ssl == NULL) {
        RW_LOG_ERROR("tls: no ssl context on a fresh pcb");
        altcp_close(pcb);
        return NULL;
    }

    int rc = mbedtls_ssl_set_hostname(ssl, host);
    if (rc != 0) {
        RW_LOG_ERROR("tls: set_hostname failed: %s", rw_tls_strerror(rc));
        altcp_close(pcb);
        return NULL;
    }

    if (s_insecure) {
        /* The shared config stays on MBEDTLS_SSL_VERIFY_REQUIRED (lwipopts.h), so a connection
         * that forgets this call fails closed rather than open. */
        mbedtls_ssl_set_verify(ssl, permissive_verify, NULL);
    }

    return pcb;
}

const char *rw_tls_strerror(int code) {
    static char buf[96];
    mbedtls_strerror(code, buf, sizeof(buf));
    if (buf[0] == '\0') {
        snprintf(buf, sizeof(buf), "mbedtls error %d", code);
    }
    return buf;
}
