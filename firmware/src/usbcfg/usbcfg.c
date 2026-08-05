/*
 * Device half of the usbcfg channel. See usbcfg.h and firmware/docs/usbcfg.md.
 *
 * SPDX-License-Identifier: MIT
 */
#include "usbcfg/usbcfg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lwip/stats.h"
#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "brand.h"
#include "config/config_flash.h"
#include "diag/radio_trace.h"
#include "net/net.h"
#include "mbedtls/sha256.h"

#include "hardware/flash.h"
#include "hardware/sync.h"

#include "ota/layout.h"
#include "ota/ota.h"
#include "ota/ota_write.h"
#include "net/lanscan.h"
#include "net/scan.h"
#include "proto/json.h"
#include "proto/proto.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "usbcfg/cmdline.h"
#include "wol/wol.h"

/*
 * Response buffer. LAN_SCAN with its full 24 hosts is the largest object this channel emits;
 * SCAN's 20 networks are capped to fit the same buffer. The writer reports overflow rather than
 * truncating, so a future field that does not fit produces `ERR internal` instead of a
 * malformed line.
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
        /* Not `busy`: nothing is competing for the radio, and saying so sent people looking for a
         * conflicting operation that was never there. Both codes are worth retrying, and
         * `scan_incomplete` says so specifically enough that a caller can retry rather than
         * report the network missing. */
        respond_err(count == RW_SCAN_ERR_INCOMPLETE ? RW_UERR_SCAN_INCOMPLETE
                                                    : RW_UERR_SCAN_FAILED);
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

/* ── LAN_SCAN ────────────────────────────────────────────────────────────── */

static void cmd_lan_scan(void) {
    rw_lan_host_t hosts[RW_LAN_SCAN_MAX];
    int           count = rw_lan_scan(hosts, RW_LAN_SCAN_MAX);
    if (count < 0) {
        /* No address of our own means no subnet to sweep, which is the same condition every other
         * network command reports as not_joined. */
        respond_err(RW_UERR_NOT_JOINED);
        return;
    }

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    /*
     * The gateway, so a caller can label the one row in the list it can be certain about. Nothing
     * here identifies a PC — that needs a name, and a name is not on the wire — but ruling out the
     * router is one fewer address to think about.
     */
    char gateway[16];
    rw_net_gateway_str(gateway, sizeof(gateway));
    rw_jw_key(&w, "gateway");
    rw_jw_str(&w, gateway);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "hosts");
    rw_jw_raw(&w, "[");
    for (int i = 0; i < count; i++) {
        /*
         * Stop while the closing brackets still fit rather than let the writer overflow and turn
         * a good answer into an error. A named host is about seventy bytes and the response is
         * capped, so a crowded network is reported as far as it fits.
         */
        if (w.cap - w.len < 96) {
            break;
        }
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        char mac[18];
        rw_mac_format(hosts[i].mac, mac);
        rw_jw_raw(&w, "{");
        rw_jw_key(&w, "ip");
        rw_jw_str(&w, ip4addr_ntoa(&hosts[i].ip));
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "mac");
        rw_jw_str(&w, mac);
        if (hosts[i].name[0] != '\0') {
            rw_jw_raw(&w, ",");
            rw_jw_key(&w, "name");
            rw_jw_str(&w, hosts[i].name);
        }
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
    rw_jw_raw(&w, ",");

    /*
     * lwip_mem_max is the high-water mark of the heap mbedTLS allocates from and lwip_mem_err
     * counts refusals; a non-zero err means TLS could not get its record buffers.
     */
    rw_jw_key(&w, "heap_free");
    rw_jw_int(&w, (long)rw_sys_heap_free());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "lwip_mem_max");
    rw_jw_int(&w, (long)lwip_stats.mem.max);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "lwip_mem_err");
    rw_jw_int(&w, (long)lwip_stats.mem.err);
    rw_jw_raw(&w, "}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/* ── WIFI_TRACE ──────────────────────────────────────────────────────────────
 *
 * The radio's own event stream (diag/radio_trace.h). Paged: `from` indexes from the oldest entry
 * held, and the response carries `total` so a host knows whether to ask again. Entries shift as
 * new events evict old ones, so a page read during an active retry loop may skip or repeat.
 */
static void cmd_wifi_trace(const rw_cmdline_t *cl) {
    size_t total = rw_radio_trace_count();
    size_t from  = 0;

    if (cl->argc == 2) {
        char  *end = NULL;
        long   n   = strtol(cl->argv[1], &end, 10);
        if (end == cl->argv[1] || *end != '\0' || n < 0) {
            respond_err(RW_UERR_BAD_ARG);
            return;
        }
        from = (size_t)n;
    }

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "from");
    rw_jw_int(&w, (long)from);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "total");
    rw_jw_int(&w, (long)total);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "lines");
    rw_jw_raw(&w, "[");
    for (size_t i = 0; i < RW_RADIO_TRACE_PAGE; i++) {
        const char *line = rw_radio_trace_at(from + i);
        if (line == NULL) {
            break;
        }
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        rw_jw_str(&w, line);
    }
    rw_jw_raw(&w, "]}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/* ── OTA_STATE / OTA_STAGE ───────────────────────────────────────────────────
 *
 * The slot the device is running from, and the ability to point the loader at the other one.
 * Present on this channel because an update has to be installable without a relay: a
 * bring-your-own board, a device on a network that cannot reach us, and every test of the
 * rollback path all need it.
 */
static void cmd_ota_state(void) {
    const rw_ota_state_t *st = rw_ota_state();

    char    buf[RESP_MAX];
    rw_jw_t w;
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "running_slot");
    rw_jw_int(&w, (long)rw_ota_running_slot());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "spare_slot");
    rw_jw_int(&w, (long)rw_ota_spare_slot());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "recorded_active");
    rw_jw_int(&w, (long)st->active);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "fallback");
    rw_jw_int(&w, (long)st->fallback);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "on_trial");
    rw_jw_raw(&w, rw_ota_on_trial() ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "trials_left");
    rw_jw_int(&w, (long)rw_ota_trials_left());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "seq");
    rw_jw_int(&w, (long)st->seq);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "version");
    rw_jw_str(&w, st->version);

    /* An update in flight. Zero unless one is actually arriving, so a stalled transfer is
     * distinguishable from an idle device without a diagnostic build. */
    bool     receiving = false;
    uint32_t got = 0, total = 0;
    rw_relay_ota_progress(&receiving, &got, &total);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "receiving");
    rw_jw_raw(&w, receiving ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "received");
    rw_jw_int(&w, (long)got);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "expected");
    rw_jw_int(&w, (long)total);
    rw_jw_raw(&w, "}");

    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);
}

/*
 * Copy the running slot into the spare one through the update writer.
 *
 * Everything an update does to flash, without a relay: sector erase, page program, read-back and
 * the digest check, at the sizes and offsets the real thing uses. The length is deliberately not
 * a multiple of the page or sector size, so the partial final page is exercised too, and the
 * chunks are fed in an awkward size because that is what a socket delivers.
 *
 * The result is never staged. An image linked to run in one slot cannot run from the other, and
 * the loader rejects it on exactly that basis.
 */
#define SELFTEST_LEN 200000u
#define SELFTEST_CHUNK 997u

/*
 * How long clearing a slot costs, done the two ways available.
 *
 * The OTA path erases 4 KB immediately before the first page written into it. The SDK's
 * flash_range_erase hands the bootrom a block size and a block-erase command, and the bootrom
 * uses 64 KB block erases for whole blocks and 4 KB sectors only at the edges — so erasing 4 KB
 * at a time asks for the slowest form there is, once per sector, and there are 176 of them in a
 * slot.
 *
 * Both numbers are wanted rather than one: the question is not what an erase costs but what the
 * difference is worth, and the difference decides whether restructuring the accept path is
 * justified at all.
 *
 * Destroys the spare slot, which is the fallback image, so it is refused while the running image
 * is still on trial — the same rule an incoming update follows.
 */
static void cmd_flash_bench(void) {
    if (rw_ota_write_active()) {
        respond_err(RW_UERR_BUSY);
        return;
    }
    if (rw_ota_on_trial()) {
        respond_err(RW_UERR_BUSY);
        return;
    }

    const uint32_t base = RW_SLOT_OFFSET(rw_ota_spare_slot());

    /* One call for the whole slot: the bootrom picks block erases for the bulk of it. */
    rw_sys_feed_watchdog();
    absolute_time_t started = get_absolute_time();
    uint32_t        ints    = save_and_disable_interrupts();
    flash_range_erase(base, RW_SLOT_SIZE);
    restore_interrupts(ints);
    const int32_t whole_ms = (int32_t)(absolute_time_diff_us(started, get_absolute_time()) / 1000);
    rw_sys_feed_watchdog();

    /* The same region again, a sector at a time, which is what the OTA path does today. The
     * watchdog is fed between sectors because nothing else is running to feed it. */
    started = get_absolute_time();
    for (uint32_t off = 0; off < RW_SLOT_SIZE; off += RW_FLASH_SECTOR) {
        rw_sys_feed_watchdog();
        ints = save_and_disable_interrupts();
        flash_range_erase(base + off, RW_FLASH_SECTOR);
        restore_interrupts(ints);
    }
    const int32_t sector_ms = (int32_t)(absolute_time_diff_us(started, get_absolute_time()) / 1000);
    rw_sys_feed_watchdog();

    char buf[192];
    snprintf(buf, sizeof(buf),
             "{\"slot\":%u,\"bytes\":%u,\"whole_ms\":%ld,\"sectors\":%u,\"sector_ms\":%ld}",
             (unsigned)rw_ota_spare_slot(), (unsigned)RW_SLOT_SIZE, (long)whole_ms,
             (unsigned)(RW_SLOT_SIZE / RW_FLASH_SECTOR), (long)sector_ms);
    respond_ok_json(buf);
}

static void cmd_ota_selftest(void) {
    if (rw_ota_write_active()) {
        respond_err(RW_UERR_BUSY);
        return;
    }

    const uint8_t *src = (const uint8_t *)(uintptr_t)RW_SLOT_XIP(rw_ota_running_slot());

    rw_ota_header_t header;
    memset(&header, 0, sizeof(header));
    header.payload_len = SELFTEST_LEN;
    if (mbedtls_sha256(src, SELFTEST_LEN, header.payload_sha256, 0) != 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }

    absolute_time_t started = get_absolute_time();
    rw_ota_status_t status  = rw_ota_write_begin(&header, rw_ota_spare_slot());
    for (uint32_t off = 0; status == RW_OTA_OK && off < SELFTEST_LEN; off += SELFTEST_CHUNK) {
        uint32_t n = SELFTEST_LEN - off;
        if (n > SELFTEST_CHUNK) {
            n = SELFTEST_CHUNK;
        }
        status = rw_ota_write_chunk(src + off, n);
    }
    if (status == RW_OTA_OK) {
        status = rw_ota_write_end();
    } else {
        rw_ota_write_abort();
    }
    int32_t ms = (int32_t)(absolute_time_diff_us(started, get_absolute_time()) / 1000);

    char buf[160];
    snprintf(buf, sizeof(buf), "{\"bytes\":%u,\"slot\":%u,\"ms\":%ld,\"status\":\"%s\"}",
             (unsigned)SELFTEST_LEN, (unsigned)rw_ota_spare_slot(), (long)ms,
             rw_ota_status_str(status));
    if (status != RW_OTA_OK) {
        printf("ERR internal %s\n", buf);
        return;
    }
    respond_ok_json(buf);
}

static void cmd_ota_stage(const rw_cmdline_t *cl) {
    char  *end = NULL;
    long   n   = strtol(cl->argv[1], &end, 10);
    if (end == cl->argv[1] || *end != '\0' || n < 0 || n > (long)RW_OTA_SLOT_B) {
        respond_err(RW_UERR_BAD_ARG);
        return;
    }
    if (!rw_ota_stage_slot((uint8_t)n, cl->argc == 3 ? cl->argv[2] : "unknown")) {
        respond_err(RW_UERR_BAD_ARG);
        return;
    }

    char buf[96];
    snprintf(buf, sizeof(buf), "{\"staged\":%ld,\"trials\":%u,\"reboot_in_ms\":%d}", n,
             (unsigned)RW_OTA_TRIAL_BOOTS, REBOOT_DELAY_MS);
    respond_ok_json(buf);

    s_reboot_pending = true;
    rw_sys_reboot(REBOOT_DELAY_MS);
}

/* ── TEST_WAKE ───────────────────────────────────────────────────────────── */

/* The MAC is the argument, not a default: the device holds no list of machines to pick one
 * from, and a diagnostic that guessed which machine you meant would not be one. It is held to
 * PROTOCOL.md §2's wakeable-address rule, because a group or broadcast address sends
 * successfully and wakes nothing — the failure this command exists to rule out. */
static void cmd_test_wake(const rw_cmdline_t *cl) {
    if (cl->argc != 2) {
        respond_err(RW_UERR_BAD_ARGS);
        return;
    }
    if (rw_net_state() != RW_NET_JOINED) {
        respond_err(RW_UERR_NOT_JOINED);
        return;
    }

    uint8_t mac[6];
    if (!rw_mac_parse(cl->argv[1], mac) || !rw_mac_wakeable(mac)) {
        respond_err(RW_UERR_BAD_ARG);
        return;
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

    const rw_config_t before = *s_live;

    rw_config_t to_save = s_stage.cfg;
    /* Same as the portal: a device with no token cannot authenticate to any relay. `ensure` is
     * the operative word — a token staged by SET_TOKEN is left exactly as the host chose it, and
     * one is minted only when nothing was staged. Either way the value is never echoed back
     * here, which usbcfg.md §4 forbids; a host that did not choose the token has to read it from
     * its relay's records or use tools/mkconfig, which prints it. */
    rw_config_ensure_token(&to_save);

    rw_config_carry_runtime_flags(&to_save, &before);

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

    const bool restart = rw_config_needs_restart(&before, &to_save);

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
    /* Zero when nothing was applied that needs one. usbcfg.md §4: a host reads this to decide
     * whether to wait for the port to disappear, and waiting for a reboot that is not coming is
     * a setup flow that stalls on its last step. */
    rw_jw_key(&w, "reboot_in_ms");
    rw_jw_int(&w, restart ? REBOOT_DELAY_MS : 0);
    rw_jw_raw(&w, "}");
    if (rw_jw_finish(&w) == 0) {
        respond_err(RW_UERR_INTERNAL);
        return;
    }
    respond_ok_json(buf);

    if (restart) {
        s_reboot_pending = true;
        rw_sys_reboot(REBOOT_DELAY_MS);
        return;
    }

    /*
     * Reopen the session rather than leave it on the old credentials. The relay borrows the
     * configuration by pointer, so the new URL and token are already visible to it, but the live
     * connection authenticated with what it had at the handshake.
     *
     * `rw_relay_stop` is what makes this work after a refusal: a token the relay rejected leaves
     * the session STOPPED, which `rw_relay_start` alone will not clear.
     */
    rw_relay_stop();
    rw_relay_start();
    RW_LOG_INFO("usbcfg: seq %lu applied without a restart", (unsigned long)to_save.seq);
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

        case RW_CMD_LAN_SCAN:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_lan_scan();
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

        case RW_CMD_WIFI_TRACE:
            if (!arity(cl, 0, 1)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_wifi_trace(cl);
            return;

        case RW_CMD_OTA_STATE:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_ota_state();
            return;

        case RW_CMD_OTA_STAGE:
            if (!arity(cl, 1, 2)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_ota_stage(cl);
            return;

        case RW_CMD_FLASH_BENCH:
            cmd_flash_bench();
            break;

        case RW_CMD_OTA_SELFTEST:
            if (!arity(cl, 0, 0)) { respond_err(RW_UERR_BAD_ARGS); return; }
            cmd_ota_selftest();
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
