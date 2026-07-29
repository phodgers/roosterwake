/*
 * DHCPv4 message parsing and construction — the pure half of the setup-hotspot DHCP server.
 *
 * Written from scratch rather than vendored so that everything under firmware/ is MIT and the
 * public repo carries exactly one licence. It implements only what a captive-portal hotspot
 * needs: the DISCOVER/OFFER/REQUEST/ACK exchange, RFC 2131 §4.3, with RELEASE and DECLINE
 * handled so a client that walks away frees its address.
 *
 * No lwIP, no SDK, no allocation: this compiles into the host test binary, which is where the
 * option encoding and the malformed-packet handling are pinned.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_DHCP_MSG_H
#define RW_DHCP_MSG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 2131 §2: the fixed BOOTP part is 236 bytes, then a 4-byte magic cookie, then options. */
#define RW_DHCP_FIXED_LEN  236
#define RW_DHCP_COOKIE_LEN 4
#define RW_DHCP_MIN_LEN    (RW_DHCP_FIXED_LEN + RW_DHCP_COOKIE_LEN)

/* A response never needs more than this: our option set is fixed and short. 548 keeps us inside
 * the 576-byte minimum IPv4 datagram every client must accept without fragmentation. */
#define RW_DHCP_MSG_MAX 548

#define RW_DHCP_PORT_SERVER 67
#define RW_DHCP_PORT_CLIENT 68

/* op */
#define RW_DHCP_OP_REQUEST 1
#define RW_DHCP_OP_REPLY   2

/* Option 53 message types (RFC 2131 §9.6). */
typedef enum {
    RW_DHCP_UNKNOWN  = 0,
    RW_DHCP_DISCOVER = 1,
    RW_DHCP_OFFER    = 2,
    RW_DHCP_REQUEST  = 3,
    RW_DHCP_DECLINE  = 4,
    RW_DHCP_ACK      = 5,
    RW_DHCP_NAK      = 6,
    RW_DHCP_RELEASE  = 7,
    RW_DHCP_INFORM   = 8,
} rw_dhcp_type_t;

/* Options this server reads or writes. */
#define RW_DHCP_OPT_SUBNET_MASK   1
#define RW_DHCP_OPT_ROUTER        3
#define RW_DHCP_OPT_DNS           6
#define RW_DHCP_OPT_REQUESTED_IP  50
#define RW_DHCP_OPT_LEASE_TIME    51
#define RW_DHCP_OPT_MSG_TYPE      53
#define RW_DHCP_OPT_SERVER_ID     54
#define RW_DHCP_OPT_END           255

/* What we need from an inbound message. Addresses are host byte order throughout this module;
 * the network-order conversion happens once, at the lwIP boundary. */
typedef struct {
    rw_dhcp_type_t type;
    uint32_t       xid;
    uint16_t       flags;
    uint8_t        chaddr[16];
    uint8_t        hlen;
    uint32_t       ciaddr;
    uint32_t       requested_ip; /* option 50, or 0 */
    uint32_t       server_id;    /* option 54, or 0 */
    bool           broadcast;    /* the client set the broadcast flag */
} rw_dhcp_request_t;

/*
 * Parse an inbound message.
 *
 * Returns false for anything that is not a well-formed BOOTP request with the DHCP magic
 * cookie: wrong op, short packet, missing cookie, or an option field that runs off the end.
 * Options are walked defensively because this is unauthenticated input from any device in
 * radio range of a setup hotspot.
 */
bool rw_dhcp_parse(const uint8_t *buf, size_t len, rw_dhcp_request_t *out);

/* Everything a reply needs, so the builder stays a pure function of its inputs. */
typedef struct {
    uint32_t server_ip;   /* our address; also router and DNS, which is the captive-portal trick */
    uint32_t subnet_mask;
    uint32_t offered_ip;
    uint32_t lease_secs;
} rw_dhcp_reply_cfg_t;

/*
 * Build an OFFER, ACK or NAK into `out`.
 *
 * Returns the length written, or 0 if `type` is not one of those three or the buffer is too
 * small. A NAK carries no address or lease, per RFC 2131 §4.3.2.
 */
size_t rw_dhcp_build_reply(const rw_dhcp_request_t *req, const rw_dhcp_reply_cfg_t *cfg,
                           rw_dhcp_type_t type, uint8_t *out, size_t out_len);

/*
 * Where a reply should be sent (RFC 2131 §4.1).
 *
 * A client that has no address yet cannot receive a unicast reply, so the broadcast flag and an
 * empty ciaddr both force 255.255.255.255. Getting this wrong produces a hotspot that works on
 * one phone and silently fails on another, which is the worst shape of bug to debug in a field
 * where the user just says "it didn't connect".
 */
uint32_t rw_dhcp_reply_dest(const rw_dhcp_request_t *req, uint32_t offered_ip);

#endif /* RW_DHCP_MSG_H */
