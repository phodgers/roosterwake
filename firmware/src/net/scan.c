/*
 * Wi-Fi scanning. See scan.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "net/scan.h"

#include <stdio.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "sys/sys.h"
#include "usbcfg/cmdline.h" /* rw_utf8_valid */

static rw_scan_entry_t s_results[RW_SCAN_MAX];
static int             s_count;

const char *rw_scan_auth_name(uint8_t auth_mode) {
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

static int on_result(void *env, const cyw43_ev_scan_result_t *result) {
    (void)env;
    if (result == NULL || result->ssid_len == 0) {
        /* Hidden networks beacon without a name. Listing them would fill the picker with
         * indistinguishable blanks, so they are dropped and typed in by hand instead. */
        return 0;
    }

    char   ssid[RW_CFG_SSID_LEN];
    size_t len = result->ssid_len;
    if (len >= sizeof(ssid)) {
        len = sizeof(ssid) - 1;
    }
    memcpy(ssid, result->ssid, len);
    ssid[len] = '\0';

    /* An SSID carrying an embedded NUL or invalid UTF-8 would travel into a JSON response and
     * out to a browser. Drop it rather than try to repair it. */
    if (strlen(ssid) != len || !rw_utf8_valid(ssid)) {
        return 0;
    }

    /* Collapse duplicates to the strongest. Every band and every mesh node beacons separately,
     * and a picker listing "HomeNet" six times is worse than useless. */
    for (int i = 0; i < s_count; i++) {
        if (strcmp(s_results[i].ssid, ssid) == 0) {
            if (result->rssi > s_results[i].rssi) {
                s_results[i].rssi      = result->rssi;
                s_results[i].channel   = result->channel;
                s_results[i].auth_mode = result->auth_mode;
            }
            return 0;
        }
    }

    int slot;
    if (s_count < RW_SCAN_MAX) {
        slot = s_count++;
    } else {
        /* Full: displace the weakest, but only if this one beats it, so the list ends up the
         * strongest N rather than the first N heard. */
        slot = 0;
        for (int i = 1; i < s_count; i++) {
            if (s_results[i].rssi < s_results[slot].rssi) {
                slot = i;
            }
        }
        if (result->rssi <= s_results[slot].rssi) {
            return 0;
        }
    }

    snprintf(s_results[slot].ssid, sizeof(s_results[slot].ssid), "%s", ssid);
    s_results[slot].rssi      = result->rssi;
    s_results[slot].channel   = result->channel;
    s_results[slot].auth_mode = result->auth_mode;
    return 0;
}

int rw_scan_run(rw_scan_entry_t *out, int max) {
    if (cyw43_wifi_scan_active(&cyw43_state)) {
        return -1;
    }

    s_count = 0;
    cyw43_wifi_scan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    if (cyw43_wifi_scan(&cyw43_state, &opts, NULL, on_result) != 0) {
        return -1;
    }

    absolute_time_t deadline = make_timeout_time_ms(RW_SCAN_TIMEOUT_MS);
    while (cyw43_wifi_scan_active(&cyw43_state) && !time_reached(deadline)) {
        /* Pumps lwIP and feeds the watchdog: an eight-second scan would otherwise trip it. */
        rw_sys_pump_ms(50);
    }

    /* Insertion sort, strongest first. Twenty entries at most, and it keeps equal-strength
     * networks in discovery order. */
    for (int i = 1; i < s_count; i++) {
        rw_scan_entry_t key = s_results[i];
        int             j   = i - 1;
        while (j >= 0 && s_results[j].rssi < key.rssi) {
            s_results[j + 1] = s_results[j];
            j--;
        }
        s_results[j + 1] = key;
    }

    int n = s_count < max ? s_count : max;
    for (int i = 0; i < n; i++) {
        out[i] = s_results[i];
    }
    return n;
}
