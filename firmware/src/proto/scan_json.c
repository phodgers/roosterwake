/*
 * The host list of a `scan_result`, bounded to fit. See scan_json.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "proto/scan_json.h"

#include <stdio.h>
#include <string.h>

/* The writer is a buffer and a length, so a write can be undone by putting the length back.
 * Nothing else in it carries state, and `ok` is restored with it so that a host which ran past
 * the end of the buffer leaves the writer exactly as it was found. */
typedef struct {
    size_t len;
    bool   ok;
} mark_t;

static mark_t mark(const rw_jw_t *w) {
    return (mark_t){.len = w->len, .ok = w->ok};
}

static void rewind_to(rw_jw_t *w, mark_t m) {
    w->len = m.len;
    w->ok  = m.ok;
}

static void write_host(rw_jw_t *w, const rw_scan_host_t *h, bool first) {
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X", h->mac[0], h->mac[1], h->mac[2],
             h->mac[3], h->mac[4], h->mac[5]);

    if (!first) {
        rw_jw_raw(w, ",");
    }
    rw_jw_raw(w, "{");
    rw_jw_key(w, "ip");
    rw_jw_str(w, h->ip);
    rw_jw_raw(w, ",");
    rw_jw_key(w, "mac");
    rw_jw_str(w, mac);
    /* §4: omitted rather than empty when nothing answered. An empty string would read as a host
     * called "", and a dashboard would have to know to treat the two the same. */
    if (h->name[0] != '\0') {
        rw_jw_raw(w, ",");
        rw_jw_key(w, "name");
        rw_jw_str(w, h->name);
    }
    rw_jw_raw(w, "}");
}

/*
 * Try to append `h`, and undo it if the result would leave less than `reserve` bytes free.
 *
 * Sizing by writing and measuring, rather than by predicting the length: a prediction is a
 * second implementation of the writer's escaping rules, and the two would drift.
 */
static bool try_host(rw_jw_t *w, const rw_scan_host_t *h, bool first, size_t reserve) {
    const mark_t before = mark(w);
    write_host(w, h, first);
    /* The writer keeps one byte back for the terminator, so what has to fit is len + reserve +
     * that byte — hence `>=` against the capacity rather than `>`. */
    if (!w->ok || w->len + reserve >= w->cap) {
        rewind_to(w, before);
        return false;
    }
    return true;
}

bool rw_scan_json_hosts(rw_jw_t *w, const rw_scan_host_t *hosts, int count, size_t reserve) {
    rw_jw_key(w, "hosts");
    rw_jw_raw(w, "[");

    const mark_t start = mark(w);

    /*
     * Which hosts fit is decided by writing them, then the array is written again with only
     * those — because the two answers are wanted in different orders. Selection takes named
     * hosts first so that a crowded segment does not push the machine somebody is looking for
     * off the end; the frame itself stays in the order the caller supplied, which is by address,
     * because a list that reorders itself according to which entries answered a name query is
     * hard to read and impossible to predict.
     *
     * The second pass writes a subset of what the first pass already fitted, in a different
     * order but with the same separators, so it cannot fail to fit.
     */
    bool keep[RW_SCAN_JSON_MAX] = {false};
    if (count > RW_SCAN_JSON_MAX) {
        count = RW_SCAN_JSON_MAX;
    }

    bool first   = true;
    bool dropped = false;
    for (int pass = 0; pass < 2; pass++) {
        const bool want_named = (pass == 0);
        for (int i = 0; i < count; i++) {
            if ((hosts[i].name[0] != '\0') != want_named) {
                continue;
            }
            if (try_host(w, &hosts[i], first, reserve)) {
                keep[i] = true;
                first   = false;
            } else {
                dropped = true;
            }
        }
    }

    rewind_to(w, start);
    first = true;
    for (int i = 0; i < count; i++) {
        if (!keep[i]) {
            continue;
        }
        write_host(w, &hosts[i], first);
        first = false;
    }

    rw_jw_raw(w, "]");
    return !dropped;
}
