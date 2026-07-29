/*
 * Device half of the usbcfg channel. See usbcfg.h and firmware/docs/usbcfg.md.
 *
 * SPDX-License-Identifier: MIT
 */
#include "usbcfg/usbcfg.h"

#include <stdio.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "brand.h"
#include "config/config_flash.h"
#include "net/net.h"
#include "proto/json.h"
#include "proto/proto.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "usbcfg/cmdline.h"
#include "wol/wol.h"

/*
 * Response buffer. GET_CONFIG with eight maximum-length targets is the largest object this
 * channel emits, at a little under 900 bytes; SCAN is capped to fit alongside it. The writer
 * reports overflow rather than truncating, so a future field that does not fit produces
 * `ERR internal` instead of a malformed line.
 */
#define RESP_MAX 1600

/* usbcfg.md §4: "Takes up to 10 seconds." */
#define SCAN_TIMEOUT_MS 10000

/* Enough networks that a dense block of flats still shows the user's own, few enough that the
 * response stays inside RESP_MAX. Extras are dropped weakest-first, never truncated mid-object. */
#define SCAN_MAX_NETWORKS 20

/* usbcfg.md §4: the response goes out before the port disappears, so the host sees the outcome
 * rather than a disconnect. */
#define REBOOT_DELAY_MS         1000
#define REBOOT_DELAY_SHORT_MS   250

typedef struct {
    char    ssid[RW_CFG_SSID_LEN];
    int16_t rssi;
    uint16_t channel;
    uint8_t auth_mode;
} scan_entry_t;

static rw_config_t *s_live;
static rw_stage_t   s_stage;
static bool         s_reboot_pending;

/* Line assembly. */
static char   s_line[RW_USBCFG_MAX_LINE];
static size_t s_line_len;
static bool   s_overflowed;

/* Scan state. The cyw43 callback runs on the main context in poll mode, so no locking. */
static scan_entry_t s_scan[SCAN_MAX_NETWORKS];
static int          s_scan_count;

/* ── Output ──────────────────────────────────────────────────────────────── */

static void respond_ok_bare(void) {
    printf("OK\n");
}

static void respond_ok_json(const char *json) {
    printf("OK %s\n", json);
}

static void respond_err(rw_uerr_t err) {
    printf("ERR %s %s\n", rw_uerr_code(err), rw_uerr_message(err));
}

/* ── Helpers ─────────────────────────────────────────────────────────────── */

static bool is_configured(const rw_config_t *cfg) {
    return cfg->ssid[0] != '\0';
}

/*
 * Map the scan result's auth byte.
 *
 * This is the CYW43 scan capability byte, which is not the same encoding as the CYW43_AUTH_*
 * constants used when joining. It distinguishes open from WPA from WPA2, but **not WPA2 from
 * WPA3** — both present as an AES-PSK capability here, and the SAE bit that would separate them
 * is not carried in this field. Reporting "wpa2" for a WPA3 network is therefore possible and
 * deliberate; inventing a confident "wpa3" from a byte that cannot express it would be worse.
 *
 * Nothing depends on getting this exactly right: SET_WIFI stages RW_WIFI_AUTH_AUTO regardless,
 * and the join negotiates whatever the router actually offers. It is a display hint for the
 * lock icon in a setup UI, and it is documented as such.
 */
static const char *scan_auth_name(uint8_t auth_mode) {
    if (auth_mode == 0) {
        return "open";
    }
    if (auth_mode & 0x04u) {
        return "wpa2";
    }
    if (auth_mode & 0x02u) {
        return "wpa";
    }
    return "secured";
}

/* ── SCAN ────────────────────────────────────────────────────────────────── */

static int scan_result_cb(void *env, const cyw43_ev_scan_result_t *result) {
    (void)env;
    if (result == NULL || result->ssid_len == 0) {
        /* A hidden network. usbcfg.md §4 says these appear with an empty ssid, but only once —
         * every beacon from every hidden AP would otherwise fill the list with blanks. */
        return 0;
    }

    char ssid[RW_CFG_SSID_LEN];
    size_t len = result->ssid_len;
    if (len >= sizeof(ssid)) {
        len = sizeof(ssid) - 1;
    }
    memcpy(ssid, result->ssid, len);
    ssid[len] = '\0';

    /* An SSID the radio reports with a NUL or invalid UTF-8 in it would travel into a JSON
     * response and out to a browser. Drop it rather than repair it. */
    if (strlen(ssid) != len || !rw_utf8_valid(ssid)) {
        return 0;
    }

    /* Collapse duplicates to the strongest: every band and every mesh node beacons separately,
     * and a picker listing "HomeNet" six times is worse than useless. */
    for (int i = 0; i < s_scan_count; i++) {
        if (strcmp(s_scan[i].ssid, ssid) == 0) {
            if (result->rssi > s_scan[i].rssi) {
                s_scan[i].rssi      = result->rssi;
                s_scan[i].channel   = result->channel;
                s_scan[i].auth_mode = result->auth_mode;
            }
            return 0;
        }
    }

    int slot;
    if (s_scan_count < SCAN_MAX_NETWORKS) {
        slot = s_scan_count++;
    } else {
        /* Full: displace the weakest, but only if this one beats it. The list is then the
         * strongest N the radio heard rather than the first N, which matters in a block of
         * flats where the user's own router is rarely the first to answer. */
        slot = 0;
        for (int i = 1; i < s_scan_count; i++) {
            if (s_scan[i].rssi < s_scan[slot].rssi) {
                slot = i;
            }
        }
        if (result->rssi <= s_scan[slot].rssi) {
            return 0;
        }
    }

    snprintf(s_scan[slot].ssid, sizeof(s_scan[slot].ssid), "%s", ssid);
    s_scan[slot].rssi      = result->rssi;
    s_scan[slot].channel   = result->channel;
    s_scan[slot].auth_mode = result->auth_mode;
    return 0;
}

static void scan_sort_by_rssi(void) {
    /* Insertion sort over at most 20 entries: the obvious algorithm at this size, and it keeps
     * equal-strength networks in discovery order. */
    for (int i = 1; i < s_scan_count; i++) {
        scan_entry_t key = s_scan[i];
        int          j   = i - 1;
        while (j >= 0 && s_scan[j].rssi < key.rssi) {
            s_scan[j + 1] = s_scan[j];
            j--;
        }
        s_scan[j + 1] = key;
    }
}

static void cmd_scan(void) {
    if (cyw43_wifi_scan_active(&cyw43_state)) {
        respond_err(RW_UERR_BUSY);
        return;
    }

    s_scan_count = 0;
    cyw43_wifi_scan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    if (cyw43_wifi_scan(&cyw43_state, &opts, NULL, scan_result_cb) != 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }

    absolute_time_t deadline = make_timeout_time_ms(SCAN_TIMEOUT_MS);
    while (cyw43_wifi_scan_active(&cyw43_state) && !time_reached(deadline)) {
        /* Pumps the stack and feeds the watchdog: an eight-second scan would otherwise trip it. */
        rw_sys_pump_ms(50);
    }

    scan_sort_by_rssi();

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "networks");
    rw_jw_raw(&w, "[");
    for (int i = 0; i < s_scan_count; i++) {
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        rw_jw_raw(&w, "{");
        rw_jw_key(&w, "ssid");
        rw_jw_str(&w, s_scan[i].ssid);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "rssi");
        rw_jw_int(&w, s_scan[i].rssi);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "auth");
        rw_jw_str(&w, scan_auth_name(s_scan[i].auth_mode));
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "channel");
        rw_jw_int(&w, s_scan[i].channel);
        rw_jw_raw(&w, "}");
    }
    rw_jw_raw(&w, "]}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/* ── INFO / GET_CONFIG / STATUS ──────────────────────────────────────────── */

static void cmd_info(void) {
    char mac[18];
    rw_net_mac_str(mac, sizeof(mac));

    rw_info_view_t view = {
        .device_id    = s_live->device_id,
        .mac          = mac,
        .reset_reason = rw_sys_reset_reason(),
        .uptime_s     = rw_sys_uptime_s(),
        .configured   = is_configured(s_live),
    };

    char buf[RESP_MAX];
    if (rw_usbcfg_info_json(&view, buf, sizeof(buf)) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

static void cmd_get_config(void) {
    char buf[RESP_MAX];
    /*
     * The staged copy, not the live one: a host that has just sent SET_WIFI should see what it
     * is about to commit. Secrets are stripped by the encoder either way.
     */
    if (rw_usbcfg_config_json(&s_stage.cfg, buf, sizeof(buf)) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

static const char *net_state_name(void) {
    switch (rw_net_state()) {
        case RW_NET_IDLE:    return "idle";
        case RW_NET_JOINING: return "joining";
        case RW_NET_JOINED:  return "joined";
        case RW_NET_FAILED:  return "failed";
    }
    return "idle";
}

static void cmd_status(void) {
    char ip[16];
    char netmask[16];
    rw_net_ip_str(ip, sizeof(ip));
    rw_net_netmask_str(netmask, sizeof(netmask));

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "wifi");
    rw_jw_str(&w, net_state_name());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ssid");
    rw_jw_str(&w, s_live->ssid);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "rssi");
    rw_jw_int(&w, rw_net_rssi());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ip");
    rw_jw_str(&w, ip);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "netmask");
    rw_jw_str(&w, netmask);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "relay");
    rw_jw_str(&w, rw_relay_state_name());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "last_error");
    {
        const char *err = rw_net_last_error();
        if (err == NULL) {
            rw_jw_raw(&w, "null");
        } else {
            rw_jw_str(&w, err);
        }
    }
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "uptime_s");
    rw_jw_int(&w, (long)rw_sys_uptime_s());
    rw_jw_raw(&w, "}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/* ── TEST_WAKE ───────────────────────────────────────────────────────────── */

static void cmd_test_wake(const rw_cmdline_t *cl) {
    if (cl->argc > 2) {
        respond_err(RW_UERR_BAD_ARGS);
        return;
    }
    if (rw_net_state() != RW_NET_JOINED) {
        respond_err(RW_UERR_NOT_JOINED);
        return;
    }

    uint8_t mac[6];
    if (cl->argc == 2) {
        if (!rw_mac_parse(cl->argv[1], mac)) {
            respond_err(RW_UERR_BAD_ARG);
            return;
        }
    } else {
        if (s_live->target_count == 0) {
            respond_err(RW_UERR_BAD_ARG);
            return;
        }
        memcpy(mac, s_live->targets[0].mac, 6);
    }

    rw_wol_result_t res;
    rw_wol_status_t st = rw_wol_send(mac, RW_WOL_BURSTS_DEFAULT,
                                     (s_live->flags & RW_CFG_FLAG_WOL_UNICAST) != 0, &res);
    if (st != RW_WOL_OK) {
        respond_err(st == RW_WOL_ERR_NO_LINK ? RW_UERR_NOT_JOINED : RW_UERR_INTERNAL);
        return;
    }

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "sent");
    rw_jw_int(&w, res.sent);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ifaces");
    rw_jw_raw(&w, "[");
    for (int i = 0; i < res.iface_count; i++) {
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        rw_jw_str(&w, res.ifaces[i]);
    }
    rw_jw_raw(&w, "]}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/* ── COMMIT / FACTORY_RESET / REBOOT / BOOTSEL ───────────────────────────── */

static void cmd_commit(void) {
    rw_uerr_t err = rw_stage_validate(&s_stage);
    if (err != RW_UERR_NONE) {
        respond_err(err);
        return;
    }

    rw_config_t to_save = s_stage.cfg;
    rw_flash_status_t st = rw_config_flash_save(&to_save);
    if (st != RW_FLASH_OK) {
        /* Nothing changed: rw_config_flash_save leaves the live slot alone on failure, so the
         * device keeps running on the configuration it already had. */
        RW_LOG_ERROR("usbcfg: commit failed (%d)", (int)st);
        respond_err(st == RW_FLASH_ERR_ENCODE ? RW_UERR_BAD_ARG : RW_UERR_FLASH_ERROR);
        return;
    }

    *s_live      = to_save;
    s_stage.cfg  = to_save;
    s_stage.dirty = false;

    char    buf[128];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "saved");
    rw_jw_raw(&w, "true");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "seq");
    rw_jw_int(&w, (long)to_save.seq);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "reboot_in_ms");
    rw_jw_int(&w, REBOOT_DELAY_MS);
    rw_jw_raw(&w, "}");
    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);

    s_reboot_pending = true;
    rw_sys_reboot(REBOOT_DELAY_MS);
}

static void cmd_factory_reset(const rw_cmdline_t *cl) {
    /* usbcfg.md §4: the literal argument CONFIRM, and it is case-sensitive by convention with
     * the rest of the document's literals. There is no undo. */
    if (cl->argc != 2 || strcmp(cl->argv[1], "CONFIRM") != 0) {
        respond_err(RW_UERR_NEEDS_CONFIRM);
        return;
    }

    if (rw_config_flash_erase_all() != RW_FLASH_OK) {
        respond_err(RW_UERR_FLASH_ERROR);
        return;
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "{\"erased\":true,\"reboot_in_ms\":%d}", REBOOT_DELAY_MS);
    respond_ok_json(buf);

    s_reboot_pending = true;
    rw_sys_reboot(REBOOT_DELAY_MS);
}

static void cmd_reboot(void) {
    char buf[48];
    snprintf(buf, sizeof(buf), "{\"reboot_in_ms\":%d}", REBOOT_DELAY_SHORT_MS);
    respond_ok_json(buf);

    s_reboot_pending = true;
    rw_sys_reboot(REBOOT_DELAY_SHORT_MS);
}

static void cmd_bootsel(void) {
    char buf[48];
    snprintf(buf, sizeof(buf), "{\"reboot_in_ms\":%d}", REBOOT_DELAY_SHORT_MS);
    respond_ok_json(buf);

    /*
     * Flush before entering the bootloader. rw_sys_reboot_to_bootloader() does not return, so
     * the response has to be on the wire first — a host that never sees the OK cannot tell a
     * successful transition from a hung device, and this is the command the whole browser
     * reflashing flow depends on.
     */
    s_reboot_pending = true;
    fflush(stdout);
    rw_sys_pump_ms(REBOOT_DELAY_SHORT_MS);
    rw_sys_reboot_to_bootloader();
}

/* ── Dispatch ────────────────────────────────────────────────────────────── */

/* Argument-count check shared by the staging commands, so each handler states its own arity
 * once and a miscount is `bad_args` rather than a read past argv. */
static bool arity(const rw_cmdline_t *cl, int min_args, int max_args) {
    int args = cl->argc - 1;
    return args >= min_args && args <= max_args;
}

static void dispatch(const rw_cmdline_t *cl) {
    rw_cmd_id_t id = rw_cmd_lookup(cl->argv[0]);

    switch (id) {
        case RW_CMD_NONE:
            return; /* unreachable: a blank line never reaches dispatch */

        case RW_CMD_UNKNOWN:
            respond_err(RW_UERR_UNKNOWN_CMD);
            return;

        case RW_CMD_INFO:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_info();
            return;

        case RW_CMD_SCAN:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_scan();
            return;

        case RW_CMD_SET_WIFI: {
            if (!arity(cl, 1, 2)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_set_wifi(&s_stage, cl->argv[1],
                                              cl->argc == 3 ? cl->argv[2] : NULL);
            if (err != RW_UERR_NONE) { respond_err(err); return; }
            respond_ok_bare();
            return;
        }

        case RW_CMD_SET_RELAY: {
            if (!arity(cl, 1, 1)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_set_relay(&s_stage, cl->argv[1]);
            if (err != RW_UERR_NONE) { respond_err(err); return; }
            respond_ok_bare();
            return;
        }

        case RW_CMD_ADD_TARGET: {
            if (!arity(cl, 2, 2)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_add_target(&s_stage, cl->argv[1], cl->argv[2]);
            if (err != RW_UERR_NONE) { respond_err(err); return; }
            char buf[32];
            snprintf(buf, sizeof(buf), "{\"targets\":%u}", s_stage.cfg.target_count);
            respond_ok_json(buf);
            return;
        }

        case RW_CMD_CLEAR_TARGETS: {
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_stage_clear_targets(&s_stage);
            respond_ok_json("{\"targets\":0}");
            return;
        }

        case RW_CMD_SET_CLAIM: {
            if (!arity(cl, 1, 1)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_set_claim(&s_stage, cl->argv[1]);
            if (err != RW_UERR_NONE) { respond_err(err); return; }
            respond_ok_bare();
            return;
        }

        case RW_CMD_GET_CONFIG:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_get_config();
            return;

        case RW_CMD_COMMIT:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_commit();
            return;

        case RW_CMD_STATUS:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_status();
            return;

        case RW_CMD_TEST_WAKE:
            cmd_test_wake(cl);
            return;

        case RW_CMD_FACTORY_RESET:
            cmd_factory_reset(cl);
            return;

        case RW_CMD_REBOOT:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_reboot();
            return;

        case RW_CMD_BOOTSEL:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_bootsel();
            return;
    }

    respond_err(RW_UERR_UNKNOWN_CMD);
}

static void handle_line(void) {
    if (s_overflowed) {
        /* usbcfg.md §1: the rest of an over-long line is discarded and answered once. */
        s_overflowed = false;
        s_line_len   = 0;
        respond_err(RW_UERR_TOO_LONG);
        return;
    }

    s_line[s_line_len] = '\0';
    /* §1: a trailing CR is stripped, so a host sending CRLF is not a special case. */
    if (s_line_len > 0 && s_line[s_line_len - 1] == '\r') {
        s_line[s_line_len - 1] = '\0';
    }
    s_line_len = 0;

    rw_cmdline_t cl;
    rw_uerr_t    err = rw_cmdline_parse(s_line, &cl);
    if (err != RW_UERR_NONE) {
        respond_err(err);
        return;
    }
    if (cl.argc == 0) {
        return; /* §2: empty lines produce no response */
    }
    dispatch(&cl);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

void rw_usbcfg_init(rw_config_t *live) {
    s_live           = live;
    s_line_len       = 0;
    s_overflowed     = false;
    s_reboot_pending = false;
    rw_stage_init(&s_stage, live);
}

bool rw_usbcfg_reboot_pending(void) {
    return s_reboot_pending;
}

void rw_usbcfg_task(void) {
    if (s_live == NULL || s_reboot_pending) {
        return;
    }

    /*
     * Bounded per call. A host that pastes a whole provisioning script arrives as one burst, and
     * draining it unboundedly here would stall the relay session and the LED for as long as the
     * burst lasted. Anything left over is picked up on the next loop iteration, microseconds
     * later.
     */
    for (int i = 0; i < 256; i++) {
        int c = getchar_timeout_us(0);
        if (c == PICO_ERROR_TIMEOUT || c < 0) {
            return;
        }

        if (c == '\n') {
            handle_line();
            if (s_reboot_pending) {
                return;
            }
            continue;
        }

        if (s_line_len + 1 >= RW_USBCFG_MAX_LINE) {
            /* Latch, keep consuming, and answer once at the newline. Answering here would emit
             * one error per byte for the rest of the line. */
            s_overflowed = true;
            continue;
        }
        s_line[s_line_len++] = (char)c;
    }
}
