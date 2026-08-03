/*
 * The host list of a `scan_result`, and what it does when the hosts do not fit.
 *
 * The size arithmetic is the reason this file exists. A frame over PROTOCOL.md §1's 2048 bytes
 * is closed with 1009 by the other end, so "one host too many" is not a cosmetic fault — it
 * takes the connection down, and it only happens on a segment busy enough that nobody testing
 * by hand would see it.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "proto/scan_json.h"
#include "rw_test.h"

static rw_scan_host_t host(const char *ip, uint8_t last, const char *name) {
    rw_scan_host_t h = {0};
    snprintf(h.ip, sizeof(h.ip), "%s", ip);
    const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, last};
    memcpy(h.mac, mac, sizeof(mac));
    snprintf(h.name, sizeof(h.name), "%s", name);
    return h;
}

/* Counts non-overlapping occurrences of `needle`. */
static int occurrences(const char *haystack, const char *needle) {
    int    n   = 0;
    size_t len = strlen(needle);
    for (const char *p = strstr(haystack, needle); p != NULL; p = strstr(p + len, needle)) {
        n++;
    }
    return n;
}

void test_scan_json(void) {
    rw_test_begin("scan_json");

    /* ── The ordinary case: everything fits, in the order given ─────────────── */
    {
        rw_scan_host_t hosts[3] = {
            host("192.168.1.1", 0x01, ""),
            host("192.168.1.20", 0x14, "DESKTOP"),
            host("192.168.1.33", 0x21, ""),
        };
        char    buf[512];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        rw_jw_raw(&w, "{");
        const bool all = rw_scan_json_hosts(&w, hosts, 3, 1);
        rw_jw_raw(&w, "}");
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(all);
        RW_CHECK(strcmp(buf,
                        "{\"hosts\":["
                        "{\"ip\":\"192.168.1.1\",\"mac\":\"AA:BB:CC:DD:EE:01\"},"
                        "{\"ip\":\"192.168.1.20\",\"mac\":\"AA:BB:CC:DD:EE:14\",\"name\":\"DESKTOP\"},"
                        "{\"ip\":\"192.168.1.33\",\"mac\":\"AA:BB:CC:DD:EE:21\"}"
                        "]}") == 0);
    }

    /* An empty scan is an empty array, not a missing field. */
    {
        char    buf[64];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        const bool all = rw_scan_json_hosts(&w, NULL, 0, 1);
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(all);
        RW_CHECK(strcmp(buf, "\"hosts\":[]") == 0);
    }

    /* ── Truncation ─────────────────────────────────────────────────────────── */

    /* A buffer that fits two of the three. The third is dropped and the return says so. */
    {
        rw_scan_host_t hosts[3] = {
            host("10.0.0.1", 0x01, ""),
            host("10.0.0.2", 0x02, ""),
            host("10.0.0.3", 0x03, ""),
        };
        /* `"hosts":[` is 9, each entry 44, separators 1 each, `]` 1, terminator 1. */
        char    buf[9 + 44 + 1 + 44 + 1 + 1 + 1];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        const bool all = rw_scan_json_hosts(&w, hosts, 3, 1);
        RW_CHECK(!all);
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(occurrences(buf, "\"ip\"") == 2);
        RW_CHECK(strstr(buf, "10.0.0.1") != NULL);
        RW_CHECK(strstr(buf, "10.0.0.2") != NULL);
        RW_CHECK(strstr(buf, "10.0.0.3") == NULL);
    }

    /*
     * A named host late in the list survives when unnamed ones earlier do not — the whole point
     * of the preference — and the surviving entries stay in the order they were given rather
     * than coming back named-first.
     */
    {
        rw_scan_host_t hosts[4] = {
            host("10.0.0.1", 0x01, ""),
            host("10.0.0.2", 0x02, ""),
            host("10.0.0.3", 0x03, ""),
            host("10.0.0.4", 0x04, "PC"),
        };
        char    buf[9 + 44 + 1 + 53 + 1 + 1 + 1];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        const bool all = rw_scan_json_hosts(&w, hosts, 4, 1);
        RW_CHECK(!all);
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(occurrences(buf, "\"ip\"") == 2);
        RW_CHECK(strstr(buf, "PC") != NULL);
        RW_CHECK(strstr(buf, "10.0.0.4") != NULL);
        /* Address order, not selection order: the named host is last in the frame. */
        RW_CHECK(strstr(buf, "10.0.0.1") < strstr(buf, "10.0.0.4"));
    }

    /* Nothing fits at all: still valid JSON, still an array, and truncated. */
    {
        rw_scan_host_t hosts[1] = {host("10.0.0.1", 0x01, "")};
        char           buf[16];
        rw_jw_t        w;
        rw_jw_init(&w, buf, sizeof(buf));
        const bool all = rw_scan_json_hosts(&w, hosts, 1, 1);
        RW_CHECK(!all);
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(strcmp(buf, "\"hosts\":[]") == 0);
    }

    /*
     * `reserve` is respected: the caller still has fields to write after the array, and a host
     * that fits the buffer but not the buffer-minus-reserve must be dropped.
     */
    {
        rw_scan_host_t hosts[1] = {host("10.0.0.1", 0x01, "")};
        char           buf[9 + 44 + 1 + 1];
        rw_jw_t        w;
        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(rw_scan_json_hosts(&w, hosts, 1, 1)); /* fits with one byte spare */

        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(!rw_scan_json_hosts(&w, hosts, 1, 32)); /* does not, with 32 reserved */
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(strcmp(buf, "\"hosts\":[]") == 0);
    }

    /* ── Names are escaped, not passed through ──────────────────────────────── */

    /*
     * The parser in nbns.c refuses anything but printable ASCII, so a quote should never reach
     * here — but this frame is built from what an unauthenticated peer said, and the cost of
     * being wrong about that is a frame the relay cannot parse. Sized by measurement, so an
     * escape that doubles a character cannot silently overrun.
     */
    {
        rw_scan_host_t h = host("10.0.0.1", 0x01, "");
        snprintf(h.name, sizeof(h.name), "%s", "A\"B\\C");
        char    buf[256];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(rw_scan_json_hosts(&w, &h, 1, 1));
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(strstr(buf, "\"name\":\"A\\\"B\\\\C\"") != NULL);
    }

    /* ── The ceiling the frame actually has to live under ───────────────────── */

    /*
     * A full sweep of the worst case the device can produce: RW_SCAN_JSON_MAX hosts, the longest
     * address, and a name on every one of them. This is the case that decides whether the frame
     * can exceed PROTOCOL.md §1's 2048 bytes, and the answer must be that it cannot.
     */
    {
        rw_scan_host_t hosts[RW_SCAN_JSON_MAX];
        for (int i = 0; i < RW_SCAN_JSON_MAX; i++) {
            hosts[i] = host("255.255.255.255", (uint8_t)i, "ABCDEFGHIJKLMNO");
        }
        char    buf[2048];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        rw_jw_raw(&w, "{\"t\":\"scan_result\",\"req_id\":");
        rw_jw_str(&w, "123e4567-e89b-12d3-a456-426614174000");
        rw_jw_raw(&w, ",\"ok\":true,\"gateway\":\"255.255.255.255\",");
        /* What the caller still has to write: `,"truncated":false}` and the terminator. */
        const bool all = rw_scan_json_hosts(&w, hosts, RW_SCAN_JSON_MAX, 20);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "truncated");
        rw_jw_raw(&w, all ? "false" : "true");
        rw_jw_raw(&w, "}");
        const size_t len = rw_jw_finish(&w);
        RW_CHECK_MSG(len > 0, "worst-case frame did not build");
        RW_CHECK_MSG(len <= 2048, "worst-case frame is %u bytes, over the 2048 limit",
                     (unsigned)len);
        RW_CHECK(buf[len - 1] == '}');
    }

    /* More hosts than the module will look at are ignored rather than read past. */
    {
        rw_scan_host_t hosts[RW_SCAN_JSON_MAX];
        for (int i = 0; i < RW_SCAN_JSON_MAX; i++) {
            hosts[i] = host("10.0.0.1", (uint8_t)i, "");
        }
        char    buf[2048];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(rw_scan_json_hosts(&w, hosts, RW_SCAN_JSON_MAX + 8, 1));
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(occurrences(buf, "\"ip\"") == RW_SCAN_JSON_MAX);
    }
}
