/*
 * Wi-Fi station mode, DHCP and SNTP. See net.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/net.h"

#include <stdio.h>
#include <string.h>

#include "lwip/apps/sntp.h"
#include "lwip/dhcp.h"
#include "lwip/netif.h"
#include "pico/cyw43_arch.h"
#include "pico/rand.h"
#include "pico/time.h"

#include "diag/radio_trace.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "sys/wallclock.h"

/* Association backoff. Starts short because the common case is a router that came back up a
 * second ago; caps at a minute because a house that has lost power will not be fixed by
 * asking more often. Full jitter for the same reason PROTOCOL.md §8 requires it of the relay
 * connection: a neighbourhood power cut otherwise brings every dongle back in lockstep. */
#define JOIN_BACKOFF_MIN_MS 2000u
#define JOIN_BACKOFF_MAX_MS 60000u

/* An association that has not produced a link in this long is stuck. The cyw43 driver reports
 * CYW43_LINK_JOIN indefinitely against some access points that accept the association and
 * never complete the four-way handshake. */
#define JOIN_TIMEOUT_MS 20000u

/* DHCP on a domestic network answers in well under a second. Thirty is generous enough to
 * cover a router still booting and short enough to retry within a sensible time. */
#define DHCP_TIMEOUT_MS 30000u

/* SNTP has to answer before the first TLS connection can verify anything. Retried
 * indefinitely; this is only how long we wait before saying so in the log. */
#define SNTP_TIMEOUT_MS 45000u

static rw_net_state_t s_state;
static char           s_ssid[RW_CFG_SSID_LEN];
static char           s_psk[RW_CFG_PSK_LEN];
static uint8_t        s_auth = RW_WIFI_AUTH_AUTO;
static const char    *s_last_error;

static uint32_t        s_backoff_ms = JOIN_BACKOFF_MIN_MS;
static absolute_time_t s_retry_at;
static absolute_time_t s_join_deadline;
static absolute_time_t s_dhcp_deadline;
static absolute_time_t s_sntp_deadline;
static bool            s_sntp_started;
static bool            s_sntp_warned;
static bool            s_initialised;

/*
 * lwIP calls this from sntp.c through the SNTP_SET_SYSTEM_TIME hook in lwipopts.h.
 *
 * Non-static and unprefixed by any header because the hook is a macro expanded inside lwIP's
 * own translation unit; the prototype lives in lwipopts.h for the same reason.
 */
void rw_sntp_set_system_time(uint32_t sec) {
    if (rw_wallclock_set(sec)) {
        RW_LOG_INFO("sntp: clock set to %lu", (unsigned long)sec);
    }
}

/*
 * Handshakes tried, in order, when the configuration says "auto".
 *
 * The transitional mode covers both WPA2 and WPA3 and suits most access points, but it is not
 * universal: some WPA2-only routers refuse it outright because it advertises SAE and management
 * frame protection they do not implement, and the refusal arrives as CYW43_LINK_FAIL rather than
 * anything more specific. s_auth_attempt advances on that failure alone.
 */
static const uint32_t k_auto_auth[] = {
    CYW43_AUTH_WPA3_WPA2_AES_PSK,
    CYW43_AUTH_WPA2_AES_PSK,
    CYW43_AUTH_WPA3_SAE_AES_PSK,
};

/* Which of the above the next join uses. Advanced only by an association failure. */
static size_t s_auth_attempt;

/* Numbers the attempts in the radio trace, so the events belonging to one join can be told from
 * the events belonging to the next. */
static uint32_t s_join_seq;

static uint32_t auth_to_cyw43(uint8_t wifi_auth, const char *psk) {
    if (psk[0] == '\0') {
        return CYW43_AUTH_OPEN;
    }
    switch (wifi_auth) {
        case RW_WIFI_AUTH_OPEN:
            return CYW43_AUTH_OPEN;
        case RW_WIFI_AUTH_WPA2:
            return CYW43_AUTH_WPA2_AES_PSK;
        case RW_WIFI_AUTH_WPA3:
            return CYW43_AUTH_WPA3_SAE_AES_PSK;
        default:
            return k_auto_auth[s_auth_attempt % (sizeof(k_auto_auth) / sizeof(k_auto_auth[0]))];
    }
}

/** The mode about to be tried, named for the log. */
static const char *auth_attempt_name(uint8_t wifi_auth, const char *psk) {
    if (psk[0] == '\0') return "open";
    switch (auth_to_cyw43(wifi_auth, psk)) {
        case CYW43_AUTH_OPEN:             return "open";
        case CYW43_AUTH_WPA2_AES_PSK:     return "wpa2";
        case CYW43_AUTH_WPA3_SAE_AES_PSK: return "wpa3";
        default:                          return "wpa2/wpa3";
    }
}

/* Full jitter: random(0, backoff). Halving the window and adding half back — "equal jitter" —
 * still leaves a floor that every device shares, which is the thing being avoided. */
static uint32_t jittered(uint32_t backoff_ms) {
    if (backoff_ms == 0) {
        return 0;
    }
    return (uint32_t)(get_rand_32() % backoff_ms);
}

static void schedule_retry(const char *why) {
    s_last_error = why;
    s_state      = RW_NET_FAILED;
    uint32_t delay = jittered(s_backoff_ms);
    s_retry_at     = make_timeout_time_ms(delay);

    /*
     * js is the driver's join-state bitmask: 0x0200 authenticated, 0x0400 linked, 0x0800 keyed,
     * low nibble the outcome. It separates a refusal before authentication from one during the
     * four-way handshake, which both arrive here as "failed".
     */
    rw_radio_trace_note("result %s js=%04x", why,
                        (unsigned)(cyw43_state.wifi_join_state & 0xffffu));
    RW_LOG_WARN("wifi: %s, retrying in %lu ms", why, (unsigned long)delay);

    s_backoff_ms = (s_backoff_ms > JOIN_BACKOFF_MAX_MS / 2) ? JOIN_BACKOFF_MAX_MS
                                                            : s_backoff_ms * 2;
}

bool rw_net_init(void) {
    if (s_initialised) {
        return true;
    }
    if (cyw43_arch_init() != 0) {
        RW_LOG_ERROR("wifi: cyw43_arch_init failed");
        return false;
    }
    cyw43_arch_enable_sta_mode();

    /* Before the first join, so the very first attempt after a power-up is recorded. That is the
     * attempt that matters: a dongle that never associates has already failed once by the time
     * anybody thinks to plug a cable into it. */
    rw_radio_trace_enable();

    /*
     * CYW43_PERFORMANCE_PM, never CYW43_AGGRESSIVE_PM.
     *
     * The aggressive profile parks the radio between beacons and drops inbound frames that
     * arrive in the gap. For a device whose entire job is to be reachable, that turns wakes
     * into a coin flip and the resulting bug report — "it works sometimes" — is close to
     * undiagnosable. The power saved is milliwatts on a mains-powered dongle.
     */
    int rc = cyw43_wifi_pm(&cyw43_state, CYW43_PERFORMANCE_PM);
    if (rc != 0) {
        /* Not fatal: the radio still works on the default profile, which is the same value. */
        RW_LOG_WARN("wifi: could not set power mode (%d)", rc);
    }

    s_initialised = true;
    rw_sys_set_network_ready(true);
    return true;
}

void rw_net_start(const char *ssid, const char *psk, uint8_t wifi_auth) {
    snprintf(s_ssid, sizeof(s_ssid), "%s", ssid != NULL ? ssid : "");
    snprintf(s_psk, sizeof(s_psk), "%s", psk != NULL ? psk : "");
    s_auth         = wifi_auth;
    s_backoff_ms   = JOIN_BACKOFF_MIN_MS;
    s_last_error   = NULL;
    s_auth_attempt = 0;
    s_join_seq     = 0;

    if (s_ssid[0] == '\0') {
        s_state = RW_NET_IDLE;
        return;
    }

    /* Named once. Each attempt below carries only its number and its handshake, because an SSID
     * repeated on every line costs more of the ring than it explains. */
    rw_radio_trace_note("target ssid=%s", s_ssid);
    s_state    = RW_NET_FAILED;
    s_retry_at = get_absolute_time(); /* attempt immediately */
}

static void begin_join(void) {
    s_join_seq++;
    rw_radio_trace_note("join #%lu auth=%s", (unsigned long)s_join_seq,
                        auth_attempt_name(s_auth, s_psk));
    RW_LOG_INFO("wifi: joining %s (%s)", s_ssid, auth_attempt_name(s_auth, s_psk));
    int rc = cyw43_arch_wifi_connect_async(s_ssid, s_psk[0] ? s_psk : NULL,
                                           auth_to_cyw43(s_auth, s_psk));
    if (rc != 0) {
        schedule_retry("connect_failed");
        return;
    }
    s_state         = RW_NET_JOINING;
    s_join_deadline = make_timeout_time_ms(JOIN_TIMEOUT_MS);
    s_dhcp_deadline = make_timeout_time_ms(JOIN_TIMEOUT_MS + DHCP_TIMEOUT_MS);
}

static void start_sntp_once(void) {
    if (s_sntp_started) {
        return;
    }
    /*
     * Poll mode against two named pools. Names rather than addresses so the device follows the
     * pool instead of pinning one host for the life of the product; two of them so a network
     * that blocks one still gets a clock. See lwipopts.h for why the DHCP-supplied server is
     * not used.
     */
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    sntp_setservername(1, "time.cloudflare.com");
    sntp_init();
    s_sntp_started  = true;
    s_sntp_warned   = false;
    s_sntp_deadline = make_timeout_time_ms(SNTP_TIMEOUT_MS);
    RW_LOG_INFO("sntp: started");
}

void rw_net_task(void) {
    if (!s_initialised || s_ssid[0] == '\0') {
        return;
    }

    if (s_state == RW_NET_FAILED) {
        if (time_reached(s_retry_at)) {
            begin_join();
        }
        return;
    }

    /*
     * cyw43_tcpip_link_status(), not cyw43_wifi_link_status().
     *
     * The wifi one reports only the radio link and tops out at CYW43_LINK_JOIN — it can never
     * return CYW43_LINK_UP. Polling it meant this loop waited for a value that does not exist,
     * so a device that had associated *and* been given an address by DHCP still sat in
     * RW_NET_JOINING until the DHCP deadline expired, then dropped a perfectly good association
     * and reported "dhcp_timeout" for ever. Observed on hardware holding a valid lease.
     *
     * The tcpip one layers the netif's view on top: NOIP while DHCP is outstanding, UP once an
     * address is held, and the negative error codes passed through unchanged.
     */
    int link = cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA);

    switch (link) {
        case CYW43_LINK_BADAUTH:
            /* The password is wrong. Still retried, because "wrong" can also mean the access
             * point rejected the association while it was still booting, and a device that
             * latches this state needs a power cycle after the user fixes the router. */
            schedule_retry("badauth");
            return;
        case CYW43_LINK_NONET:
            schedule_retry("nonet");
            return;
        case CYW43_LINK_FAIL:
            /*
             * Advance the ladder. Only here: `badauth` means the password is wrong and `nonet`
             * means the network is not there, and neither is fixed by a different handshake -
             * cycling modes for those would relabel one failure three times and make the log
             * harder to read.
             */
            s_auth_attempt++;
            schedule_retry("failed");
            return;
        default:
            break;
    }

    if (s_state == RW_NET_JOINING) {
        if (link == CYW43_LINK_UP) {
            char ip[16], mask[16];
            rw_net_ip_str(ip, sizeof(ip));
            rw_net_netmask_str(mask, sizeof(mask));
            rw_radio_trace_note("joined ip=%s", ip);
            RW_LOG_INFO("wifi: joined %s, ip %s mask %s", s_ssid, ip, mask);
            s_state      = RW_NET_JOINED;
            s_backoff_ms = JOIN_BACKOFF_MIN_MS;
            s_last_error = NULL;
            start_sntp_once();
            return;
        }
        if (link == CYW43_LINK_JOIN || link == CYW43_LINK_NOIP) {
            /* Associated but not addressed yet. DHCP has its own, longer deadline. */
            if (time_reached(s_dhcp_deadline)) {
                /* Associated but never addressed. Drop the association explicitly: rejoining
                 * on top of a live one leaves the driver and the DHCP client disagreeing about
                 * which attempt they are servicing. */
                cyw43_wifi_leave(&cyw43_state, CYW43_ITF_STA);
                schedule_retry("dhcp_timeout");
            }
            return;
        }
        if (time_reached(s_join_deadline)) {
            schedule_retry("join_timeout");
        }
        return;
    }

    /* s_state == RW_NET_JOINED */
    if (link != CYW43_LINK_UP) {
        RW_LOG_WARN("wifi: link lost");
        s_backoff_ms = JOIN_BACKOFF_MIN_MS;
        schedule_retry("link_lost");
        return;
    }

    if (!rw_wallclock_valid() && !s_sntp_warned && time_reached(s_sntp_deadline)) {
        /* Said once, not every loop. SNTP keeps retrying on its own schedule; without a clock
         * every TLS connection will fail certificate validity, and this is the line that
         * explains why. */
        RW_LOG_ERROR("sntp: no answer yet - TLS cannot verify certificates without a clock");
        s_last_error  = "sntp_timeout";
        s_sntp_warned = true;
    }
}

rw_net_state_t rw_net_state(void) {
    return s_state;
}

bool rw_net_ready(void) {
    return s_state == RW_NET_JOINED && rw_wallclock_valid() && netif_default != NULL &&
           ip4_addr_get_u32(netif_ip4_addr(netif_default)) != 0;
}

const char *rw_net_last_error(void) {
    return s_last_error;
}

int32_t rw_net_rssi(void) {
    if (s_state != RW_NET_JOINED) {
        return 0;
    }
    int32_t rssi = 0;
    if (cyw43_wifi_get_rssi(&cyw43_state, &rssi) != 0) {
        return 0;
    }
    return rssi;
}

void rw_net_ip_str(char *out, size_t len) {
    if (netif_default == NULL) {
        snprintf(out, len, "0.0.0.0");
        return;
    }
    snprintf(out, len, "%s", ip4addr_ntoa(netif_ip4_addr(netif_default)));
}

void rw_net_netmask_str(char *out, size_t len) {
    if (netif_default == NULL) {
        snprintf(out, len, "0.0.0.0");
        return;
    }
    snprintf(out, len, "%s", ip4addr_ntoa(netif_ip4_netmask(netif_default)));
}

void rw_net_mac_str(char *out, size_t len) {
    uint8_t mac[6] = {0};
    if (cyw43_wifi_get_mac(&cyw43_state, CYW43_ITF_STA, mac) != 0) {
        snprintf(out, len, "00:00:00:00:00:00");
        return;
    }
    char text[18];
    rw_mac_format(mac, text);
    snprintf(out, len, "%s", text);
}
