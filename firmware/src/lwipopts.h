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
 * lwIP's own heap. Holds pbufs allocated with PBUF_RAM (every outbound frame passes through
 * one) and altcp's TLS bookkeeping. mbedTLS's 4 KB record buffers come from the C heap, not
 * from here.
 */
#define MEM_SIZE                    16000

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
#define TCP_WND                     (8 * TCP_MSS)
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

#define LWIP_STATS                  0
#define LWIP_STATS_DISPLAY          0
#define LWIP_DEBUG                  0

#endif /* RW_LWIPOPTS_H */
