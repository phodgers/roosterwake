/*
 * Setup mode. See provisioning.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "provisioning/provisioning.h"

#include <stdio.h>
#include <string.h>

#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "brand.h"
#include "config/config_flash.h"
#include "net/scan.h"
#include "proto/json.h"
#include "provisioning/dhcpserver.h"
#include "provisioning/dnsserver.h"
#include "provisioning/httpd.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "usbcfg/cmdline.h"

/* The portal shows a result before the device restarts, so the user sees "done" rather than a
 * hotspot vanishing under them. */
#define COMMIT_REBOOT_MS 2500

/* Long enough for DHCP on a slow router, short enough that the portal's spinner does not look
 * hung. The plan's figure. */
#define JOIN_TIMEOUT_MS 20000

static rw_config_t *s_live;
static rw_stage_t   s_stage;
static bool         s_active;
static bool         s_reboot_pending;
static absolute_time_t s_reboot_at;

/* ── Hotspot ─────────────────────────────────────────────────────────────── */

static void build_ssid(char *out, size_t cap) {
    /* Suffix from the low 16 bits of the device_id so two dongles powered up in the same room
     * are distinguishable on a phone's Wi-Fi list. */
    const char *id  = s_live->device_id;
    size_t      len = strlen(id);
    const char *tail = len >= 4 ? id + len - 4 : "0000";
    snprintf(out, cap, "%s-%.4s", RW_SETUP_SSID_PREFIX, tail);
}

static void ap_set_address(void) {
    struct netif *ap = &cyw43_state.netif[CYW43_ITF_AP];
    ip4_addr_t    ip, mask, gw;
    ip4_addr_set_u32(&ip, lwip_htonl(RW_AP_IP));
    ip4_addr_set_u32(&mask, lwip_htonl(RW_AP_NETMASK));
    ip4_addr_set_u32(&gw, lwip_htonl(RW_AP_IP));
    netif_set_addr(ap, &ip, &mask, &gw);
}

bool rw_provisioning_start(rw_config_t *live) {
    s_live = live;
    rw_stage_init(&s_stage, live);

    char ssid[33];
    build_ssid(ssid, sizeof(ssid));

    /*
     * Open, with no password.
     *
     * A WPA2 hotspot would need its passphrase printed on the device or the box, and a
     * passphrase on a device that hands out no secrets buys nothing: the portal never reveals
     * the Wi-Fi password it is given, and the only thing an eavesdropper on this hotspot could
     * capture is the setup traffic of whoever is standing next to it. What it would cost is
     * every user who cannot find the card. Open is the honest trade, and the AP exists for
     * minutes.
     */
    cyw43_arch_enable_ap_mode(ssid, NULL, CYW43_AUTH_OPEN);
    ap_set_address();

    if (!rw_dhcpserver_start(RW_AP_IP, RW_AP_NETMASK)) {
        RW_LOG_ERROR("portal: dhcp server failed to start");
        return false;
    }
    if (!rw_dnsserver_start(RW_AP_IP)) {
        RW_LOG_ERROR("portal: dns server failed to start");
        rw_dhcpserver_stop();
        return false;
    }
    if (!rw_httpd_start(RW_AP_IP)) {
        RW_LOG_ERROR("portal: http server failed to start");
        rw_dnsserver_stop();
        rw_dhcpserver_stop();
        return false;
    }

    s_active         = true;
    s_reboot_pending = false;
    RW_LOG_INFO("portal: hotspot \"%s\" up on 192.168.4.1", ssid);
    return true;
}

void rw_provisioning_stop(void) {
    if (!s_active) {
        return;
    }
    rw_httpd_stop();
    rw_dnsserver_stop();
    rw_dhcpserver_stop();
    cyw43_arch_disable_ap_mode();
    s_active = false;
}

bool rw_provisioning_active(void) {
    return s_active;
}

void rw_provisioning_task(void) {
    if (s_reboot_pending && time_reached(s_reboot_at)) {
        RW_LOG_INFO("portal: committed, restarting");
        rw_provisioning_stop();
        rw_sys_reboot(50);
        s_reboot_pending = false;
    }
}

/* ── Small JSON helpers ──────────────────────────────────────────────────── */

static size_t json_err(char *buf, size_t cap, const char *code) {
    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "false,");
    rw_jw_key(&w, "err");
    rw_jw_str(&w, code);
    rw_jw_raw(&w, "}");
    return rw_jw_finish(&w);
}

/* Pull a top-level string out of a JSON body. Returns false if absent or too long. */
static bool body_str(const char *body, size_t len, const char *key, char *out, size_t out_len) {
    jsmn_parser parser;
    jsmntok_t   tokens[64];
    jsmn_init(&parser);
    int n = jsmn_parse(&parser, body, len, tokens, sizeof(tokens) / sizeof(tokens[0]));
    if (n < 1 || tokens[0].type != JSMN_OBJECT) {
        return false;
    }
    int idx = rw_json_find(body, tokens, n, key);
    if (idx < 0) {
        return false;
    }
    return rw_json_str(body, &tokens[idx], out, out_len);
}

/* ── API ─────────────────────────────────────────────────────────────────── */

size_t rw_portal_api_info(char *buf, size_t cap) {
    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "product");
    rw_jw_str(&w, RW_PRODUCT_NAME);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "device_id");
    rw_jw_str(&w, s_live->device_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "fw");
    rw_jw_str(&w, RW_FW_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "board");
    rw_jw_str(&w, RW_BOARD_NAME);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "configured");
    rw_jw_raw(&w, s_live->ssid[0] ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ssid");
    rw_jw_str(&w, s_live->ssid);
    rw_jw_raw(&w, "}");
    return rw_jw_finish(&w);
}

size_t rw_portal_api_scan(char *buf, size_t cap) {
    rw_scan_entry_t nets[RW_SCAN_MAX];
    int             count = rw_scan_run(nets, RW_SCAN_MAX);
    if (count < 0) {
        return json_err(buf, cap, "busy");
    }

    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "networks");
    rw_jw_raw(&w, "[");
    for (int i = 0; i < count; i++) {
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        rw_jw_raw(&w, "{");
        rw_jw_key(&w, "ssid");
        rw_jw_str(&w, nets[i].ssid);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "rssi");
        rw_jw_int(&w, nets[i].rssi);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "auth");
        rw_jw_str(&w, rw_scan_auth_name(nets[i].auth_mode));
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "channel");
        rw_jw_int(&w, nets[i].channel);
        rw_jw_raw(&w, "}");
    }
    rw_jw_raw(&w, "]}");
    return rw_jw_finish(&w);
}

size_t rw_portal_api_join(const char *body, size_t len, char *buf, size_t cap) {
    char ssid[RW_CFG_SSID_LEN];
    char psk[RW_CFG_PSK_LEN];

    if (!body_str(body, len, "ssid", ssid, sizeof(ssid))) {
        return json_err(buf, cap, "bad_arg");
    }
    if (!body_str(body, len, "psk", psk, sizeof(psk))) {
        psk[0] = '\0'; /* open network */
    }

    /*
     * The hotspot stays up through the attempt. The CYW43439 can hold an AP and a station at
     * once, but only on one channel — so if the target network is on a different channel the
     * radio follows it and the phone's connection to the portal drops for a few seconds. The
     * portal's fetch survives a brief drop; the alternative, tearing the AP down first, loses
     * the page outright and gives the user nothing to come back to.
     */
    int rc = cyw43_arch_wifi_connect_async(ssid, psk[0] ? psk : NULL,
                                           psk[0] ? CYW43_AUTH_WPA2_AES_PSK : CYW43_AUTH_OPEN);
    if (rc != 0) {
        return json_err(buf, cap, "internal");
    }

    absolute_time_t deadline = make_timeout_time_ms(JOIN_TIMEOUT_MS);
    int             status   = CYW43_LINK_DOWN;
    while (!time_reached(deadline)) {
        status = cyw43_wifi_link_status(&cyw43_state, CYW43_ITF_STA);
        if (status == CYW43_LINK_UP || status == CYW43_LINK_FAIL ||
            status == CYW43_LINK_NONET || status == CYW43_LINK_BADAUTH) {
            break;
        }
        rw_sys_pump_ms(100);
    }

    /*
     * Three distinct answers, because they are three different problems: a wrong password, a
     * network that is not there, and an association that succeeded but produced no address.
     * Collapsing them into "couldn't connect" sends people to check the wrong thing, and this
     * screen is the whole support surface of setup.
     */
    switch (status) {
        case CYW43_LINK_BADAUTH:
            return json_err(buf, cap, "badauth");
        case CYW43_LINK_NONET:
            return json_err(buf, cap, "notfound");
        case CYW43_LINK_UP:
            break;
        default:
            return json_err(buf, cap, "timeout");
    }

    /* Joined. Stage the credentials — nothing reaches flash before commit. */
    if (rw_stage_set_wifi(&s_stage, ssid, psk[0] ? psk : NULL) != RW_UERR_NONE) {
        return json_err(buf, cap, "bad_arg");
    }

    char ip[16];
    const ip4_addr_t *addr = netif_ip4_addr(&cyw43_state.netif[CYW43_ITF_STA]);
    snprintf(ip, sizeof(ip), "%s", ip4addr_ntoa(addr));

    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true,");
    rw_jw_key(&w, "ip");
    rw_jw_str(&w, ip);
    rw_jw_raw(&w, "}");
    return rw_jw_finish(&w);
}

size_t rw_portal_api_config(const char *body, size_t len, char *buf, size_t cap) {
    jsmn_parser parser;
    jsmntok_t   tokens[96];
    jsmn_init(&parser);
    int n = jsmn_parse(&parser, body, len, tokens, sizeof(tokens) / sizeof(tokens[0]));
    if (n < 1 || tokens[0].type != JSMN_OBJECT) {
        return json_err(buf, cap, "bad_arg");
    }

    /* Optional relay override and claim code. An empty string means "leave it alone", which is
     * what the portal sends when the advanced section was never opened. */
    char scratch[RW_CFG_RELAY_URL_LEN];
    if (body_str(body, len, "relay", scratch, sizeof(scratch)) && scratch[0] != '\0') {
        if (rw_stage_set_relay(&s_stage, scratch) != RW_UERR_NONE) {
            return json_err(buf, cap, "bad_relay");
        }
    }
    if (body_str(body, len, "claim", scratch, sizeof(scratch)) && scratch[0] != '\0') {
        if (rw_stage_set_claim(&s_stage, scratch) != RW_UERR_NONE) {
            return json_err(buf, cap, "bad_claim");
        }
    }

    int targets = rw_json_find(body, tokens, n, "targets");
    if (targets >= 0 && tokens[targets].type == JSMN_ARRAY) {
        /* Replace wholesale rather than append: the portal sends the complete list it wants,
         * and appending would duplicate every entry if the user went back a step. */
        rw_stage_clear_targets(&s_stage);

        int idx = targets + 1;
        for (int i = 0; i < tokens[targets].size; i++) {
            if (idx >= n || tokens[idx].type != JSMN_OBJECT) {
                return json_err(buf, cap, "bad_arg");
            }
            char name[RW_CFG_TARGET_NAME_LEN] = {0};
            char mac[24]                      = {0};

            int fields = tokens[idx].size;
            int f      = idx + 1;
            for (int k = 0; k < fields && f + 1 < n; k++) {
                if (rw_json_eq(body, &tokens[f], "name")) {
                    if (!rw_json_str(body, &tokens[f + 1], name, sizeof(name))) {
                        return json_err(buf, cap, "bad_name");
                    }
                } else if (rw_json_eq(body, &tokens[f], "mac")) {
                    if (!rw_json_str(body, &tokens[f + 1], mac, sizeof(mac))) {
                        return json_err(buf, cap, "bad_mac");
                    }
                }
                f = rw_json_skip(tokens, n, f + 1);
            }

            rw_uerr_t err = rw_stage_add_target(&s_stage, name, mac);
            if (err != RW_UERR_NONE) {
                return json_err(buf, cap, err == RW_UERR_TOO_MANY ? "too_many" : "bad_mac");
            }
            idx = rw_json_skip(tokens, n, idx);
        }
    }

    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true,");
    rw_jw_key(&w, "targets");
    rw_jw_int(&w, s_stage.cfg.target_count);
    rw_jw_raw(&w, "}");
    return rw_jw_finish(&w);
}

size_t rw_portal_api_commit(char *buf, size_t cap) {
    rw_uerr_t verr = rw_stage_validate(&s_stage);
    if (verr != RW_UERR_NONE) {
        return json_err(buf, cap, rw_uerr_code(verr));
    }

    rw_config_t       to_save = s_stage.cfg;
    rw_flash_status_t st      = rw_config_flash_save(&to_save);
    if (st != RW_FLASH_OK) {
        RW_LOG_ERROR("portal: commit failed (%d)", (int)st);
        return json_err(buf, cap, "flash_error");
    }

    *s_live       = to_save;
    s_stage.cfg   = to_save;
    s_stage.dirty = false;

    /* Deferred, not immediate: the response has to reach the phone before the hotspot goes
     * away, or the user is left looking at a failed request having actually succeeded. */
    s_reboot_pending = true;
    s_reboot_at      = make_timeout_time_ms(COMMIT_REBOOT_MS);

    rw_jw_t w;
    rw_jw_init(&w, buf, cap);
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true,");
    rw_jw_key(&w, "seq");
    rw_jw_int(&w, (long)to_save.seq);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "device_id");
    rw_jw_str(&w, to_save.device_id);
    /*
     * The token, exactly once, and only if there is one.
     *
     * usbcfg's GET_CONFIG never returns it and neither does anything else — a self-hoster
     * pointing the device at their own relay needs it, and this is their one chance to copy it.
     * That is a deliberate asymmetry with the USB channel: this page is being read by the
     * person holding the device, on a network that exists for the next two seconds.
     */
    if (to_save.token[0] != '\0') {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "token");
        rw_jw_str(&w, to_save.token);
    }
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "reboot_in_ms");
    rw_jw_int(&w, COMMIT_REBOOT_MS);
    rw_jw_raw(&w, "}");
    return rw_jw_finish(&w);
}
