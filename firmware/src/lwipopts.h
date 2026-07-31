/*
 * lwIP configuration for Remote Wake.
 *
 * NO_SYS, poll mode: there is no TCP/IP thread and no locking. Every lwIP callback runs on the
 * main loop because the main loop is the only thing that calls cyw43_arch_poll(). See
 * firmware/docs/architecture.md for why that was chosen over threadsafe_background.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_LWIPOPTS_H
#define RW_LWIPOPTS_H

/* ── Core ──────────────────────────────────────────────────────────────────── */

#define NO_SYS                      1
#define LWIP_SOCKET                 0
#define LWIP_NETCONN                0
#define SYS_LIGHTWEIGHT_PROT        0

#define MEM_LIBC_MALLOC             0
#define MEM_ALIGNMENT               4

/*
 * lwIP's own heap.
 *
 * ── THIS IS WHERE mbedTLS ALLOCATES, AND IT IS NOT OBVIOUS ───────────────────
 *
 * The previous value here was 16000, chosen on the belief that mbedTLS took its record buffers
 * from the C heap. It does not. lwIP installs its own allocator into mbedTLS
 * (`tls_malloc` in altcp_tls_mbedtls_mem.c), which calls `mem_malloc` and additionally refuses
 * outright any single allocation larger than MEM_SIZE. MBEDTLS_SSL_IN_CONTENT_LEN is 16384, so
 * the inbound record buffer alone was larger than the entire heap it had to come from, and
 * `altcp_tls_new()` could never succeed. Every dongle reached the internet, failed to allocate,
 * and reported nothing more specific than a relay stuck at "connecting" — on both boards, since
 * this constant does not vary by chip.
 *
 * What has to fit here, all at once:
 *
 *   the parsed root bundle   ~10 KB, permanent, allocated once at rw_tls_init()
 *   inbound record buffer     16 KB, MBEDTLS_SSL_IN_CONTENT_LEN
 *   outbound record buffer     4 KB, MBEDTLS_SSL_OUT_CONTENT_LEN
 *   the peer's chain          ~4 KB during the handshake
 *   PBUF_RAM pbufs             every outbound frame passes through one
 *
 * A live handshake against the production relay measured `lwip_mem_max` at 44028 bytes, so 48 KB
 * was only 10% clear of the peak and 64 KB is the size that leaves real headroom — for a second
 * concurrent connection during a reconnect, and for a server whose certificate chain is larger
 * than Cloudflare's. tls.c carries a _Static_assert tying this constant to the mbedTLS ones so
 * the two can never drift apart in silence again, and STATUS reports `lwip_mem_max` and
 * `lwip_mem_err` so the headroom stays a measurement rather than a belief.
 */
#define MEM_SIZE                    65536

#define MEMP_NUM_TCP_SEG            32
#define MEMP_NUM_ARP_QUEUE          10
#define MEMP_NUM_UDP_PCB            6
#define MEMP_NUM_TCP_PCB            4
#define MEMP_NUM_TCP_PCB_LISTEN     1
#define MEMP_NUM_SYS_TIMEOUT        (LWIP_NUM_SYS_TIMEOUT_INTERNAL + 4)

#define PBUF_POOL_SIZE              24

/* ── Protocols ─────────────────────────────────────────────────────────────── */

#define LWIP_ARP                    1
#define LWIP_ETHERNET               1
#define LWIP_ICMP                   1
#define LWIP_RAW                    1
#define LWIP_IPV4                   1

/* IPv6 is off. It roughly doubles the stack's flash and RAM footprint, and no part of this
 * product needs it: WoL is an IPv4 broadcast by definition, and every relay is reachable over
 * IPv4. net/url.c rejects IPv6 literals for the same reason, rather than accepting them and
 * failing later. */
#define LWIP_IPV6                   0

#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_DHCP                   1
#define LWIP_DNS                    1
#define LWIP_NETIF_HOSTNAME         1

/* Enough for a WoL broadcast plus the relay connection's own retransmissions. */
#define TCP_MSS                     1460

/*
 * The receive window has to be at least as large as the TLS record being decrypted into.
 *
 * altcp_tls checks this at start-up and says so — "TCP_WND is smaller than the RX decryption
 * buffer, connection RX might stall" — because a record larger than the window can never be
 * fully delivered: lwIP stops advertising space before the last fragment arrives, and the
 * handshake hangs rather than failing. At 8 * MSS the window was 11680 against a 16384-byte
 * inbound buffer, so any server sending a maximum-size record would have hung the connection.
 * Twelve segments clears MBEDTLS_SSL_IN_CONTENT_LEN with a margin.
 */
#define TCP_WND                     (12 * TCP_MSS)
#define TCP_SND_BUF                 (4 * TCP_MSS)
#define TCP_SND_QUEUELEN            ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))

/* A DHCP server that hands out an address already in use costs one extra round trip to find
 * out; the alternative is a device that silently fights another host for an address. */
#define LWIP_DHCP_DOES_ACD_CHECK    1

#define DHCP_DOES_ARP_CHECK         0
#define LWIP_NETIF_STATUS_CALLBACK  1
#define LWIP_NETIF_LINK_CALLBACK    1
#define LWIP_NETIF_TX_SINGLE_PBUF   1

/* ── altcp / TLS ───────────────────────────────────────────────────────────── */

#define LWIP_ALTCP                  1
#define LWIP_ALTCP_TLS              1
#define LWIP_ALTCP_TLS_MBEDTLS      1

/*
 * Verification is required by default. tls.c overrides this per configuration when the
 * TLS_INSECURE flag or the RW_TLS_INSECURE build option is set; having the default here be
 * REQUIRED rather than lwIP's OPTIONAL means a code path that forgets to call the override
 * fails closed.
 */
#include "mbedtls/ssl.h"
#define ALTCP_MBEDTLS_AUTHMODE      MBEDTLS_SSL_VERIFY_REQUIRED

/* ── SNTP ──────────────────────────────────────────────────────────────────── */

/*
 * Servers are named, not addressed, so the device follows the pool rather than pinning one
 * host. Two of them: a device that cannot reach either has no route to a relay anyway, but
 * the second covers a network that blocks one and not the other.
 *
 * DHCP-supplied NTP servers are deliberately not used. lwIP's DHCP integration replaces the
 * whole server list when the lease offers any, which would silently discard the fallbacks on
 * a router that advertises an NTP server it does not actually run — a failure that presents
 * as "TLS never works" and points nowhere near the clock.
 */
#define SNTP_SERVER_DNS             1
#define SNTP_MAX_SERVERS            2
#define SNTP_SUPPORT_MULTIPLE_SERVERS 1
#define SNTP_CHECK_RESPONSE         1
#define SNTP_UPDATE_DELAY           3600000 /* one hour; drift on the RP2350 XOSC is small */

#ifndef __ASSEMBLER__
/* Defined in net/net.c. Declared here because SNTP_SET_SYSTEM_TIME expands inside lwIP's own
 * translation unit, which includes this file and nothing of ours. */
#include <stdint.h>
void rw_sntp_set_system_time(uint32_t sec);
#endif

#define SNTP_SET_SYSTEM_TIME(sec)   rw_sntp_set_system_time(sec)

/* ── Diagnostics ───────────────────────────────────────────────────────────── */

/*
 * Memory accounting only.
 *
 * `lwip_stats.mem.max` is the high-water mark of the heap above, and `.err` counts allocations
 * that were refused. Those two numbers are the difference between sizing MEM_SIZE from evidence
 * and sizing it from a hunch, and the whole reason the TLS failure above went undiagnosed for as
 * long as it did is that nobody could see either of them. STATUS reports them.
 *
 * The protocol counters are left off: they cost code and RAM on a part that has little of
 * either, and nothing in this product has ever needed to know how many ICMP echoes it sent.
 */
#define LWIP_STATS                  1
#define LWIP_STATS_DISPLAY          0
#define MEM_STATS                   1
#define MEMP_STATS                  1
#define SYS_STATS                   0
#define LINK_STATS                  0
#define ETHARP_STATS                0
#define IP_STATS                    0
#define IPFRAG_STATS                0
#define ICMP_STATS                  0
#define UDP_STATS                   0
#define TCP_STATS                   0

/*
 * TLS handshake failures, in a build that asked for diagnostics.
 *
 * lwIP keeps `struct altcp_tls_config` private, so there is no way to install an mbedTLS debug
 * callback from our side — altcp's own LWIP_DEBUGF at altcp_tls_mbedtls.c:300 is the only place
 * the handshake's return code is ever visible. Without it a rejected handshake reaches us as
 * ERR_CLSD on the error callback and nothing else, which is indistinguishable from the peer
 * simply hanging up.
 *
 * Only the altcp_tls channel is switched on. LWIP_DEBUG gates the machinery; every other
 * module's flag stays at its LWIP_DBG_OFF default, so this does not turn the cable into a
 * firehose of packet traces.
 */
#ifdef RW_TLS_TRACE
#define LWIP_DEBUG                  1
#define LWIP_DBG_MIN_LEVEL          LWIP_DBG_LEVEL_ALL
#define LWIP_DBG_TYPES_ON           LWIP_DBG_ON
#define ALTCP_MBEDTLS_DEBUG         LWIP_DBG_ON
#else
#define LWIP_DEBUG                  0
#endif

#endif /* RW_LWIPOPTS_H */
