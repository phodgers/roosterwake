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
#include "mbedtls/aes.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/gcm.h"
#include "mbedtls/sha256.h"
#include "mbedtls/error.h"
#include "mbedtls/platform.h"
#include "mbedtls/platform_time.h"
#include "mbedtls/ssl.h"
#include "pico/time.h"

#include "rw_log.h"
#include "sys/sys.h"
#include "sys/wallclock.h"
#include "tls/ca_bundle.h"

/*
 * The two constants that have to agree, asserted in the one file that can see both.
 *
 * lwIP hands mbedTLS its own allocator, and that allocator refuses any single request larger
 * than MEM_SIZE before it even reaches the heap. So MBEDTLS_SSL_IN_CONTENT_LEN is not merely a
 * buffer size, it is a claim about lwipopts.h — and the two live in different files, are read by
 * different libraries, and produced no diagnostic at all when they disagreed: TLS simply never
 * started, and the failure surfaced as a relay that stayed at "connecting" for ever.
 *
 * The headroom is the rest of what has to be resident at the same moment: the parsed root
 * bundle, the peer's certificate chain during the handshake, and the PBUF_RAM pbufs carrying
 * the traffic. See the MEM_SIZE comment in lwipopts.h for the full budget.
 */
#define RW_TLS_HEAP_HEADROOM 16384
_Static_assert(MEM_SIZE >= MBEDTLS_SSL_IN_CONTENT_LEN + MBEDTLS_SSL_OUT_CONTENT_LEN +
                               RW_TLS_HEAP_HEADROOM,
               "lwIP's MEM_SIZE must hold both mbedTLS record buffers and the root bundle at "
               "once: lwIP allocates mbedTLS from its own heap and rejects anything bigger than "
               "MEM_SIZE outright. Raise MEM_SIZE in lwipopts.h or lower the record sizes in "
               "mbedtls_config.h.");

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

/*
 * One AES-128-GCM known-answer test, run before TLS is offered at all.
 *
 * ── WHY A LIBRARY'S OWN CIPHER IS TESTED AT EVERY BOOT ───────────────────────
 *
 * Because it has already been wrong once, and the way it was wrong was undetectable from
 * anywhere above it. GCC 14.2 at -O3 miscompiles mbedTLS's GCM for this target (see the
 * optimisation note in CMakeLists.txt): correct for a zero-length message, wrong for anything
 * carrying data. GCM is the only cipher this device negotiates, so the effect was that every
 * TLS handshake ran flawlessly through certificate verification and key agreement and then had
 * its first encrypted record rejected by the peer. Nothing in the resulting trace pointed at
 * the compiler; the visible symptom was a relay that would not connect.
 *
 * This is the check that would have found it in one line. It costs a few hundred microseconds
 * once per boot and stays in release builds precisely because the fault it catches is one a
 * release build is no less likely to have.
 *
 * NIST GCM test case 2: 128-bit zero key, 96-bit zero IV, one block of zero plaintext, no
 * additional data. Chosen because it is the exact vector the broken build failed.
 */
static bool gcm_known_answer_ok(void) {
    static const unsigned char key[16] = {0};
    static const unsigned char iv[12]  = {0};
    static const unsigned char pt[16]  = {0};
    static const unsigned char want_ct[16] = {0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
                                              0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78};
    static const unsigned char want_tag[16] = {0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
                                               0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf};

    unsigned char       ct[16]  = {0};
    unsigned char       tag[16] = {0};
    mbedtls_gcm_context ctx;

    mbedtls_gcm_init(&ctx);
    bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128) == 0 &&
              mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, sizeof(pt), iv, sizeof(iv),
                                        NULL, 0, pt, ct, sizeof(tag), tag) == 0 &&
              memcmp(ct, want_ct, sizeof(want_ct)) == 0 &&
              memcmp(tag, want_tag, sizeof(want_tag)) == 0;
    mbedtls_gcm_free(&ctx);
    return ok;
}

bool rw_tls_init(bool config_insecure) {
    mbedtls_platform_set_time(rw_tls_time);

    if (!gcm_known_answer_ok()) {
        /*
         * Fail here rather than at the first handshake. A device that cannot encrypt correctly
         * cannot be made to work by retrying, and every layer above this one would report the
         * failure as something it is not.
         */
        RW_LOG_ERROR("tls: AES-GCM FAILS ITS KNOWN-ANSWER TEST - this build's crypto is broken "
                     "and no TLS connection it makes can succeed. Check the compiler "
                     "optimisation level (see CMakeLists.txt).");
        return false;
    }

#ifdef RW_TLS_TRACE
    /*
     * Do the primitives actually work on this part?
     *
     * Everything in a TLS handshake up to the first encrypted record is asymmetric and
     * hashing; the record layer is the first use of AES-GCM, and the key schedule is the
     * first use of HMAC. A handshake that verifies a certificate, agrees a key and then has
     * its very first encrypted byte rejected implicates exactly the two primitives these
     * tests cover, and nothing that came before.
     */
    RW_LOG_INFO("tls: self-test starting");
    RW_LOG_INFO("tls: sha256 %s", mbedtls_sha256_self_test(0) == 0 ? "ok" : "FAILED");
    RW_LOG_INFO("tls: aes    %s", mbedtls_aes_self_test(0) == 0 ? "ok" : "FAILED");
    RW_LOG_INFO("tls: gcm    %s", mbedtls_gcm_self_test(0) == 0 ? "ok" : "FAILED");
    RW_LOG_INFO("tls: ctr_drbg %s", mbedtls_ctr_drbg_self_test(0) == 0 ? "ok" : "FAILED");
    RW_LOG_INFO("tls: entropy  %s", mbedtls_entropy_self_test(0) == 0 ? "ok" : "FAILED");
#endif

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

#ifdef RW_TLS_TRACE
/* mbedTLS hands these over one line at a time, already newline-terminated, with the source file
 * and line it came from. Only the message is kept: the library's own file names say nothing a
 * support conversation can use. */
static void rw_tls_debug(void *ctx, int level, const char *file, int line, const char *str) {
    (void)ctx;
    (void)level;
    (void)file;
    (void)line;
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        len--;
    }
    printf("# tls %.*s\n", (int)len, str);
}
#endif

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

    /*
     * altcp_tls_new() calls mbedtls_ssl_setup() inside itself, so this one call allocates both
     * record buffers - MBEDTLS_SSL_IN_CONTENT_LEN plus MBEDTLS_SSL_OUT_CONTENT_LEN plus headers,
     * in single contiguous pieces. It is by a wide margin the largest allocation the firmware
     * makes, and on the 264 KB RP2040 it is the one that fails. The free figure goes into the
     * message because "out of memory" without a number is the start of a guessing game.
     */
    uint32_t heap_before = rw_sys_heap_free();

    struct altcp_pcb *pcb = altcp_tls_new(s_config, IPADDR_TYPE_V4);
    if (pcb == NULL) {
        RW_LOG_ERROR("tls: no memory for the TLS pcb - needed ~%u, had %lu free",
                     (unsigned)(MBEDTLS_SSL_IN_CONTENT_LEN + MBEDTLS_SSL_OUT_CONTENT_LEN),
                     (unsigned long)heap_before);
        return NULL;
    }

    mbedtls_ssl_context *ssl = (mbedtls_ssl_context *)altcp_tls_context(pcb);
    if (ssl == NULL) {
        RW_LOG_ERROR("tls: no ssl context on a fresh pcb");
        altcp_close(pcb);
        return NULL;
    }

    /*
     * The server name, logged because getting it wrong is invisible from this end and fatal at
     * the other. A host that reaches mbedTLS empty, truncated or carrying a port produces no
     * local error at all — the extension simply goes out wrong, and the peer answers with a
     * fatal handshake_failure alert that arrives here as one opaque number.
     */
    RW_LOG_INFO("tls: sni \"%s\"", host);

#ifdef RW_TLS_TRACE
    /*
     * Attach mbedTLS's own tracing to this connection.
     *
     * lwIP keeps `struct altcp_tls_config` private, so the mbedtls_ssl_config inside it cannot
     * be configured through any lwIP API — but the context altcp just handed us points at it,
     * and MBEDTLS_ALLOW_PRIVATE_ACCESS makes that pointer reachable. Casting away const to
     * install a debug callback is a diagnostic build's privilege and nothing else's, which is
     * why it is compiled out otherwise rather than gated at runtime.
     */
    mbedtls_debug_set_threshold(3);
    mbedtls_ssl_conf_dbg((mbedtls_ssl_config *)ssl->conf, rw_tls_debug, NULL);
#endif

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
