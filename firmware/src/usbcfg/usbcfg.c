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
#include "net/scan.h"
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

/* usbcfg.md §4: the response goes out before the port disappears, so the host sees the outcome
 * rather than a disconnect. */
#define REBOOT_DELAY_MS         1000
#define REBOOT_DELAY_SHORT_MS   250

static rw_config_t *s_live;
static rw_stage_t   s_stage;
static bool         s_reboot_pending;

/* Line assembly. */
static char   s_line[RW_USBCFG_MAX_LINE];
static size_t s_line_len;
static bool   s_overflowed;

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

/* ── SCAN ────────────────────────────────────────────────────────────────── */

static void cmd_scan(void) {
    rw_scan_entry_t nets[RW_SCAN_MAX];
    int             count = rw_scan_run(nets, RW_SCAN_MAX);
    if (count < 0) {
        respond_err(RW_UERR_BUSY);
        return;
    }

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
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
    /* Same as the portal: a device with no token cannot authenticate to any relay. `ensure` is
     * the operative word — a token staged by SET_TOKEN is left exactly as the host chose it, and
     * one is minted only when nothing was staged. Either way the value is never echoed back
     * here, which usbcfg.md §4 forbids; a host that did not choose the token has to read it from
     * its relay's records or use tools/mkconfig, which prints it. */
    rw_config_ensure_token(&to_save);

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

    if (rw_config_flash_factory_reset() != RW_FLASH_OK) {
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

        case RW_CMD_SET_EMAIL: {
            if (!arity(cl, 1, 1)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_set_email(&s_stage, cl->argv[1]);
            if (err != RW_UERR_NONE) { respond_err(err); return; }
            respond_ok_bare();
            return;
        }

        case RW_CMD_SET_TOKEN: {
            if (!arity(cl, 1, 1)) { respond_err(RW_UERR_BAD_ARGS); return; }
            rw_uerr_t err = rw_stage_set_token(&s_stage, cl->argv[1]);
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
