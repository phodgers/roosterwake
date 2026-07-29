/*
 * DHCPv4 message codec. See dhcp_msg.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/dhcp_msg.h"

#include <string.h>

/* Field offsets in the fixed BOOTP part (RFC 2131 §2). */
#define OFF_OP     0
#define OFF_HTYPE  1
#define OFF_HLEN   2
#define OFF_XID    4
#define OFF_FLAGS  10
#define OFF_CIADDR 12
#define OFF_YIADDR 16
#define OFF_SIADDR 20
#define OFF_CHADDR 28

static const uint8_t k_cookie[RW_DHCP_COOKIE_LEN] = {0x63, 0x82, 0x53, 0x63};

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

bool rw_dhcp_parse(const uint8_t *buf, size_t len, rw_dhcp_request_t *out) {
    if (buf == NULL || out == NULL || len < RW_DHCP_MIN_LEN) {
        return false;
    }
    if (buf[OFF_OP] != RW_DHCP_OP_REQUEST) {
        return false;
    }
    if (memcmp(buf + RW_DHCP_FIXED_LEN, k_cookie, RW_DHCP_COOKIE_LEN) != 0) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->xid    = rd32(buf + OFF_XID);
    out->flags  = rd16(buf + OFF_FLAGS);
    out->ciaddr = rd32(buf + OFF_CIADDR);
    out->hlen   = buf[OFF_HLEN];
    if (out->hlen > sizeof(out->chaddr)) {
        out->hlen = sizeof(out->chaddr);
    }
    memcpy(out->chaddr, buf + OFF_CHADDR, sizeof(out->chaddr));
    out->broadcast = (out->flags & 0x8000u) != 0;

    /*
     * Walk the options. Every step is bounds-checked against `len` before it reads, because
     * this is unauthenticated input from anything in radio range of an open hotspot and a
     * length byte is entirely under the sender's control.
     */
    size_t i = RW_DHCP_MIN_LEN;
    while (i < len) {
        uint8_t code = buf[i];

        if (code == RW_DHCP_OPT_END) {
            break;
        }
        if (code == 0) {
            i++; /* pad */
            continue;
        }
        if (i + 2 > len) {
            break; /* truncated: a code with no length byte */
        }

        uint8_t optlen = buf[i + 1];
        if (i + 2 + optlen > len) {
            break; /* the option claims more bytes than the datagram holds */
        }
        const uint8_t *val = buf + i + 2;

        switch (code) {
            case RW_DHCP_OPT_MSG_TYPE:
                if (optlen == 1) {
                    out->type = (rw_dhcp_type_t)val[0];
                }
                break;
            case RW_DHCP_OPT_REQUESTED_IP:
                if (optlen == 4) {
                    out->requested_ip = rd32(val);
                }
                break;
            case RW_DHCP_OPT_SERVER_ID:
                if (optlen == 4) {
                    out->server_id = rd32(val);
                }
                break;
            default:
                break;
        }
        i += 2u + optlen;
    }

    /* A BOOTP packet with no option 53 is not DHCP. Returning true with type UNKNOWN would make
     * every caller repeat the same check. */
    return out->type != RW_DHCP_UNKNOWN;
}

/* Append one option, refusing rather than truncating if it does not fit. */
static bool put_opt(uint8_t *out, size_t out_len, size_t *pos, uint8_t code, const uint8_t *val,
                    uint8_t len) {
    if (*pos + 2u + len > out_len) {
        return false;
    }
    out[(*pos)++] = code;
    out[(*pos)++] = len;
    memcpy(out + *pos, val, len);
    *pos += len;
    return true;
}

static bool put_opt32(uint8_t *out, size_t out_len, size_t *pos, uint8_t code, uint32_t value) {
    uint8_t v[4];
    wr32(v, value);
    return put_opt(out, out_len, pos, code, v, sizeof(v));
}

size_t rw_dhcp_build_reply(const rw_dhcp_request_t *req, const rw_dhcp_reply_cfg_t *cfg,
                           rw_dhcp_type_t type, uint8_t *out, size_t out_len) {
    if (req == NULL || cfg == NULL || out == NULL) {
        return 0;
    }
    if (type != RW_DHCP_OFFER && type != RW_DHCP_ACK && type != RW_DHCP_NAK) {
        return 0;
    }
    if (out_len < RW_DHCP_MIN_LEN + 32) {
        return 0;
    }

    memset(out, 0, out_len);
    out[OFF_OP]    = RW_DHCP_OP_REPLY;
    out[OFF_HTYPE] = 1; /* Ethernet */
    out[OFF_HLEN]  = 6;
    wr32(out + OFF_XID, req->xid);
    out[OFF_FLAGS]     = (uint8_t)(req->flags >> 8);
    out[OFF_FLAGS + 1] = (uint8_t)req->flags;
    memcpy(out + OFF_CHADDR, req->chaddr, sizeof(req->chaddr));

    /* A NAK carries no address: RFC 2131 §4.3.2 says yiaddr and the lease are meaningless when
     * we are telling the client its request is wrong. */
    if (type != RW_DHCP_NAK) {
        wr32(out + OFF_YIADDR, cfg->offered_ip);
        wr32(out + OFF_SIADDR, cfg->server_ip);
    }

    memcpy(out + RW_DHCP_FIXED_LEN, k_cookie, RW_DHCP_COOKIE_LEN);
    size_t pos = RW_DHCP_MIN_LEN;

    uint8_t type_byte = (uint8_t)type;
    if (!put_opt(out, out_len, &pos, RW_DHCP_OPT_MSG_TYPE, &type_byte, 1)) {
        return 0;
    }
    /* Option 54 is on every reply including the NAK, so a client on a network with more than
     * one server can tell whose answer this is. */
    if (!put_opt32(out, out_len, &pos, RW_DHCP_OPT_SERVER_ID, cfg->server_ip)) {
        return 0;
    }

    if (type != RW_DHCP_NAK) {
        if (!put_opt32(out, out_len, &pos, RW_DHCP_OPT_SUBNET_MASK, cfg->subnet_mask) ||
            !put_opt32(out, out_len, &pos, RW_DHCP_OPT_ROUTER, cfg->server_ip) ||
            /*
             * We are the DNS server as well as the router. That is what makes the captive
             * portal work: every name the phone looks up resolves to us, so whatever URL its
             * connectivity check reaches for lands on our HTTP server and the portal opens by
             * itself.
             */
            !put_opt32(out, out_len, &pos, RW_DHCP_OPT_DNS, cfg->server_ip) ||
            !put_opt32(out, out_len, &pos, RW_DHCP_OPT_LEASE_TIME, cfg->lease_secs)) {
            return 0;
        }
    }

    if (pos + 1 > out_len) {
        return 0;
    }
    out[pos++] = RW_DHCP_OPT_END;

    /*
     * Pad to the 300-byte BOOTP minimum. Some clients — and some cheap switches in the middle —
     * drop DHCP frames shorter than this, and the failure looks exactly like a hotspot that
     * never answers.
     */
    while (pos < 300 && pos < out_len) {
        out[pos++] = 0;
    }
    return pos;
}

uint32_t rw_dhcp_reply_dest(const rw_dhcp_request_t *req, uint32_t offered_ip) {
    if (req == NULL) {
        return 0xFFFFFFFFu;
    }
    /* An address it already holds, and no broadcast demand: unicast is fine. */
    if (!req->broadcast && req->ciaddr != 0) {
        return req->ciaddr;
    }
    /* Otherwise the client has no configured address and cannot receive a unicast reply,
     * whatever we put in yiaddr. */
    (void)offered_ip;
    return 0xFFFFFFFFu;
}
