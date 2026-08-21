/*
 * The Shelly half of the plug driver. See shelly.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "plug/shelly.h"

#include <stdio.h>
#include <string.h>

#include "config/config.h" /* rw_mac_parse */

/*
 * Token budget for a device body. A Gen1 `/status` is the largest thing parsed here — around a
 * hundred tokens on a Plug S — and a body that overruns this is refused the same way an
 * oversized one is: it is not a shape this driver claims to understand. Static because 4 KB
 * does not belong on the stack, and safe because one body is parsed at a time — the driver
 * runs one command and the sweep classifies completions one by one, both on the main loop.
 */
#define SHELLY_MAX_TOKENS 256
static jsmntok_t s_tok[SHELLY_MAX_TOKENS];

/* ── HTTP response splitting ───────────────────────────────────────────────── */

/* Case-insensitive "does this header line name this field", RFC 7230's rule. */
static bool header_is(const char *line, const char *name) {
    size_t n = strlen(name);
    for (size_t i = 0; i < n; i++) {
        char a = line[i];
        char b = name[i];
        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b) {
            return false;
        }
    }
    return line[n] == ':';
}

bool rw_shelly_http_split(const char *resp, size_t len, int *status, const char **body,
                          size_t *body_len) {
    /* The status line: "HTTP/1.x NNN …". Anything else is not HTTP answering us. */
    if (len < 12 || memcmp(resp, "HTTP/1.", 7) != 0 || resp[8] != ' ') {
        return false;
    }
    int code = 0;
    for (int i = 9; i < 12; i++) {
        if (resp[i] < '0' || resp[i] > '9') {
            return false;
        }
        code = code * 10 + (resp[i] - '0');
    }

    /* Walk header lines to the blank one, reading the two that matter. */
    long   content_length = -1;
    bool   chunked        = false;
    size_t at             = 0;
    /* Past the status line first. */
    while (at + 1 < len && !(resp[at] == '\r' && resp[at + 1] == '\n')) {
        at++;
    }
    if (at + 1 >= len) {
        return false;
    }
    at += 2;

    while (at + 1 < len && !(resp[at] == '\r' && resp[at + 1] == '\n')) {
        const char *line = resp + at;
        if (header_is(line, "content-length")) {
            content_length = 0;
            const char *p = line + strlen("content-length:");
            while (*p == ' ') {
                p++;
            }
            while (*p >= '0' && *p <= '9') {
                content_length = content_length * 10 + (*p - '0');
                if (content_length > (long)RW_SHELLY_BODY_MAX) {
                    return false; /* refused before the digits are even finished */
                }
                p++;
            }
        } else if (header_is(line, "transfer-encoding")) {
            /* No de-chunking here, deliberately. Every Shelly answers these requests with
             * Content-Length or a plain close-delimited body; a chunked response is a peer
             * this driver does not claim to understand, refused rather than half-read. */
            chunked = true;
        }
        while (at + 1 < len && !(resp[at] == '\r' && resp[at + 1] == '\n')) {
            at++;
        }
        if (at + 1 >= len) {
            return false; /* header section never terminated */
        }
        at += 2;
    }
    if (at + 1 >= len) {
        return false; /* no blank line, so no body was ever delimited */
    }
    at += 2;
    if (chunked) {
        return false;
    }

    size_t have = len - at;
    if (content_length >= 0) {
        if ((size_t)content_length > have) {
            return false; /* the connection closed short of what the header promised */
        }
        have = (size_t)content_length;
    }
    if (have > RW_SHELLY_BODY_MAX) {
        return false;
    }

    *status   = code;
    *body     = resp + at;
    *body_len = have;
    return true;
}

/* ── jsmn helpers for non-flat bodies ─────────────────────────────────────────
 *
 * rw_json_find reads only the top level, which is right for relay frames and wrong for a
 * device body with arrays in it. These two walk from any token, using rw_json_skip's extent
 * rule, and exist here rather than in json.c because relay frames must stay flat — a general
 * finder there would be an invitation to make them otherwise.
 */
static int obj_find(const char *js, const jsmntok_t *t, int count, int obj, const char *key) {
    if (obj < 0 || obj >= count || t[obj].type != JSMN_OBJECT) {
        return -1;
    }
    int i = obj + 1;
    for (int n = 0; n < t[obj].size && i < count; n++) {
        int value = i + 1;
        if (value >= count) {
            return -1;
        }
        if (rw_json_eq(js, &t[i], key)) {
            return value;
        }
        i = rw_json_skip(t, count, value);
    }
    return -1;
}

static int arr_at(const jsmntok_t *t, int count, int arr, int index) {
    if (arr < 0 || arr >= count || t[arr].type != JSMN_ARRAY || index < 0 ||
        index >= t[arr].size) {
        return -1;
    }
    int i = arr + 1;
    for (int n = 0; n < index; n++) {
        i = rw_json_skip(t, count, i);
    }
    return (i < count) ? i : -1;
}

/*
 * A JSON number as thousandths. Plain decimal notation only — Shellys emit nothing else, and
 * accepting exponents would mean multiplying, which is how a hostile body turns a parser into
 * an overflow. Digits past the third decimal place are dropped, not rounded: the values are
 * metering reads, where a fixed truncation beats a rule with a carry in it.
 */
static bool num_milli(const char *js, const jsmntok_t *tok, long *out) {
    if (tok->type != JSMN_PRIMITIVE) {
        return false;
    }
    const char *p   = js + tok->start;
    const char *end = js + tok->end;
    bool        neg = false;
    if (p < end && *p == '-') {
        neg = true;
        p++;
    }
    if (p >= end || *p < '0' || *p > '9') {
        return false; /* also rejects true/false/null, whose first byte is a letter */
    }
    long whole = 0;
    while (p < end && *p >= '0' && *p <= '9') {
        if (whole > (0x7fffffffL / 10)) {
            return false;
        }
        whole = whole * 10 + (*p - '0');
        p++;
    }
    long frac = 0;
    if (p < end && *p == '.') {
        p++;
        long scale = 100;
        while (p < end && *p >= '0' && *p <= '9') {
            if (scale > 0) {
                frac += (*p - '0') * scale;
                scale /= 10;
            }
            p++;
        }
    }
    if (p != end) {
        return false; /* an exponent, or trailing bytes that are not a number */
    }
    if (whole > (0x7fffffffL - 999) / 1000) {
        return false;
    }
    long value = whole * 1000 + frac;
    *out       = neg ? -value : value;
    return true;
}

static void copy_str(const char *js, const jsmntok_t *t, int count, int obj, const char *key,
                     char *out, size_t out_len) {
    out[0]  = '\0';
    int idx = obj_find(js, t, count, obj, key);
    if (idx >= 0) {
        /* A failed copy leaves the field empty rather than half-written; rw_json_str already
         * guarantees that. */
        (void)rw_json_str(js, &t[idx], out, out_len);
    }
}

static int parse_body(const char *body, size_t len) {
    if (len > RW_SHELLY_BODY_MAX) {
        return -1;
    }
    jsmn_parser parser;
    jsmn_init(&parser);
    int count = jsmn_parse(&parser, body, len, s_tok, SHELLY_MAX_TOKENS);
    if (count < 1 || s_tok[0].type != JSMN_OBJECT) {
        return -1;
    }
    return count;
}

/* ── Identification ────────────────────────────────────────────────────────── */

bool rw_shelly_identify(const char *body, size_t len, rw_shelly_id_t *out) {
    int count = parse_body(body, len);
    if (count < 0) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->channels = 1;

    /*
     * The generations are told apart by shape, because that is the one thing each is committed
     * to: Gen2+ answers `/shelly` with Shelly.GetDeviceInfo, which always carries `gen`; Gen1
     * predates the field and always carries `type`. A body with neither is whatever else on
     * the segment happened to answer port 80.
     */
    int gen_idx = obj_find(body, s_tok, count, 0, "gen");
    if (gen_idx >= 0) {
        long gen;
        if (!rw_json_int(body, &s_tok[gen_idx], &gen) || gen < 2 || gen > 99) {
            return false;
        }
        out->gen = (int)gen;
        copy_str(body, s_tok, count, 0, "model", out->model, sizeof(out->model));
        copy_str(body, s_tok, count, 0, "name", out->name, sizeof(out->name));
        if (out->name[0] == '\0') {
            /* `name` is null until an owner sets one; `id` ("shellyplusplugs-…") is always
             * there and is at least recognisable across the room. */
            copy_str(body, s_tok, count, 0, "id", out->name, sizeof(out->name));
        }
        if (out->model[0] == '\0') {
            return false;
        }
    } else {
        int type_idx = obj_find(body, s_tok, count, 0, "type");
        if (type_idx < 0) {
            return false;
        }
        out->gen = 1;
        copy_str(body, s_tok, count, 0, "type", out->model, sizeof(out->model));
        if (out->model[0] == '\0') {
            return false;
        }
        int n_idx = obj_find(body, s_tok, count, 0, "num_outputs");
        long n;
        if (n_idx >= 0 && rw_json_int(body, &s_tok[n_idx], &n) && n >= 1 && n <= 8) {
            out->channels = (int)n;
        }
    }

    /* Both generations state their MAC as bare hex; rw_mac_parse takes it either way. A body
     * that gets this wrong is not a Shelly. */
    char mac_text[20];
    copy_str(body, s_tok, count, 0, "mac", mac_text, sizeof(mac_text));
    if (!rw_mac_parse(mac_text, out->mac)) {
        return false;
    }
    return true;
}

/* ── Requests ──────────────────────────────────────────────────────────────── */

static size_t finish_req(size_t cap, int written) {
    if (written <= 0 || (size_t)written >= cap) {
        return 0;
    }
    return (size_t)written;
}

size_t rw_shelly_req_identify(char *buf, size_t cap, const char *host) {
    return finish_req(cap,
                      snprintf(buf, cap,
                               "GET /shelly HTTP/1.1\r\n"
                               "Host: %s\r\n"
                               "Connection: close\r\n\r\n",
                               host));
}

size_t rw_shelly_req_set(char *buf, size_t cap, const char *host, int gen, int channel,
                         bool on) {
    if (gen == 1) {
        return finish_req(cap,
                          snprintf(buf, cap,
                                   "GET /relay/%d?turn=%s HTTP/1.1\r\n"
                                   "Host: %s\r\n"
                                   "Connection: close\r\n\r\n",
                                   channel, on ? "on" : "off", host));
    }
    char body[80];
    int  body_len = snprintf(body, sizeof(body),
                             "{\"id\":1,\"method\":\"Switch.Set\","
                             "\"params\":{\"id\":%d,\"on\":%s}}",
                             channel, on ? "true" : "false");
    if (body_len <= 0 || (size_t)body_len >= sizeof(body)) {
        return 0;
    }
    return finish_req(cap,
                      snprintf(buf, cap,
                               "POST /rpc HTTP/1.1\r\n"
                               "Host: %s\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: %d\r\n"
                               "Connection: close\r\n\r\n%s",
                               host, body_len, body));
}

size_t rw_shelly_req_status(char *buf, size_t cap, const char *host, int gen, int channel) {
    if (gen == 1) {
        return finish_req(cap,
                          snprintf(buf, cap,
                                   "GET /status HTTP/1.1\r\n"
                                   "Host: %s\r\n"
                                   "Connection: close\r\n\r\n",
                                   host));
    }
    char body[80];
    int  body_len = snprintf(body, sizeof(body),
                             "{\"id\":1,\"method\":\"Switch.GetStatus\","
                             "\"params\":{\"id\":%d}}",
                             channel);
    if (body_len <= 0 || (size_t)body_len >= sizeof(body)) {
        return 0;
    }
    return finish_req(cap,
                      snprintf(buf, cap,
                               "POST /rpc HTTP/1.1\r\n"
                               "Host: %s\r\n"
                               "Content-Type: application/json\r\n"
                               "Content-Length: %d\r\n"
                               "Connection: close\r\n\r\n%s",
                               host, body_len, body));
}

/* ── Responses ─────────────────────────────────────────────────────────────── */

/*
 * The object a Gen2 RPC's payload lives in. `POST /rpc` wraps every answer in an envelope —
 * `result` on success, `error` on refusal — and a refusal arrives as HTTP 200, so the envelope
 * is the only place it can be seen.
 */
static int rpc_result(const char *body, int count) {
    if (obj_find(body, s_tok, count, 0, "error") >= 0) {
        return -1;
    }
    int r = obj_find(body, s_tok, count, 0, "result");
    return (r >= 0 && s_tok[r].type == JSMN_OBJECT) ? r : -1;
}

static bool tok_bool(const char *js, const jsmntok_t *tok, bool *out) {
    if (tok->type != JSMN_PRIMITIVE) {
        return false;
    }
    if (rw_json_eq(js, tok, "true")) {
        *out = true;
        return true;
    }
    if (rw_json_eq(js, tok, "false")) {
        *out = false;
        return true;
    }
    return false;
}

/* A metering member is optional twice over: absent on unmetered hardware, and refused here
 * when it is not a plain number. Either way the field stays reported-absent. */
static void read_milli(const char *js, const jsmntok_t *t, int count, int obj, const char *key,
                       bool *have, long *out) {
    int idx = obj_find(js, t, count, obj, key);
    if (idx >= 0 && num_milli(js, &t[idx], out)) {
        *have = true;
    }
}

bool rw_shelly_parse_status(const char *body, size_t len, int gen, int channel,
                            rw_shelly_status_t *out) {
    int count = parse_body(body, len);
    if (count < 0) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    if (gen == 1) {
        int relay = arr_at(s_tok, count, obj_find(body, s_tok, count, 0, "relays"), channel);
        int ison  = obj_find(body, s_tok, count, relay, "ison");
        if (ison < 0 || !tok_bool(body, &s_tok[ison], &out->on)) {
            return false; /* no such relay: the channel does not exist on this device */
        }
        int meter = arr_at(s_tok, count, obj_find(body, s_tok, count, 0, "meters"), channel);
        if (meter >= 0) {
            read_milli(body, s_tok, count, meter, "power", &out->have_apower, &out->apower_mw);
            long total_mwmin = 0;
            bool have_total  = false;
            read_milli(body, s_tok, count, meter, "total", &have_total, &total_mwmin);
            if (have_total) {
                /* Gen1 counts watt-minutes. Sixty of those are a watt-hour, and the division
                 * happens here so that only one unit ever crosses this interface. */
                out->energy_mwh  = total_mwmin / 60;
                out->have_energy = true;
            }
        }
        /* No voltage: Gen1 plugs do not measure it, and inventing 230 would be a reading. */
        return true;
    }

    int result = rpc_result(body, count);
    if (result < 0) {
        return false;
    }
    int output = obj_find(body, s_tok, count, result, "output");
    if (output < 0 || !tok_bool(body, &s_tok[output], &out->on)) {
        return false;
    }
    read_milli(body, s_tok, count, result, "apower", &out->have_apower, &out->apower_mw);
    read_milli(body, s_tok, count, result, "voltage", &out->have_voltage, &out->voltage_mv);
    int aenergy = obj_find(body, s_tok, count, result, "aenergy");
    if (aenergy >= 0) {
        read_milli(body, s_tok, count, aenergy, "total", &out->have_energy, &out->energy_mwh);
    }
    return true;
}

bool rw_shelly_parse_set(const char *body, size_t len, int gen, bool *have_state,
                         bool *state_on) {
    *have_state = false;
    *state_on   = false;

    int count = parse_body(body, len);
    if (count < 0) {
        return false;
    }
    if (gen == 1) {
        /* Gen1 echoes the relay's state AFTER the change — a bad channel is an HTTP error the
         * caller has already checked — so this reply is also the confirming read. */
        int ison = obj_find(body, s_tok, count, 0, "ison");
        if (ison < 0 || !tok_bool(body, &s_tok[ison], state_on)) {
            return false;
        }
        *have_state = true;
        return true;
    }
    /* Gen2's `result` carries `was_on` — the state BEFORE the change. Deliberately not read:
     * the driver's confirming Switch.GetStatus is the only source of "current". */
    return rpc_result(body, count) >= 0;
}

/* ── The scan list ─────────────────────────────────────────────────────────── */

/* The scan_json arrangement: a write is undone by putting the length back, and `ok` travels
 * with it so a host that latched the writer leaves it exactly as found. Sizing is by writing
 * and measuring, never by predicting — a prediction is a second implementation of the
 * writer's escaping rules, and the two would drift. */
static void write_plug(rw_jw_t *w, const rw_shelly_plug_t *p, bool first) {
    if (!first) {
        rw_jw_raw(w, ",");
    }
    rw_jw_raw(w, "{");
    rw_jw_key(w, "mac");
    rw_jw_str(w, p->mac);
    rw_jw_raw(w, ",");
    rw_jw_key(w, "ip");
    rw_jw_str(w, p->ip);
    rw_jw_raw(w, ",");
    rw_jw_key(w, "model");
    rw_jw_str(w, p->model);
    rw_jw_raw(w, ",");
    rw_jw_key(w, "gen");
    rw_jw_int(w, p->gen);
    /* Omitted rather than empty when the device offered none, the scan_result rule: an empty
     * string would read as a plug called "", and every dashboard would have to know better. */
    if (p->name[0] != '\0') {
        rw_jw_raw(w, ",");
        rw_jw_key(w, "name");
        rw_jw_str(w, p->name);
    }
    rw_jw_raw(w, ",");
    rw_jw_key(w, "channels");
    rw_jw_int(w, p->channels);
    rw_jw_raw(w, "}");
}

bool rw_shelly_json_plugs(rw_jw_t *w, const rw_shelly_plug_t *plugs, int count, size_t reserve) {
    rw_jw_key(w, "plugs");
    rw_jw_raw(w, "[");

    bool all   = true;
    bool first = true;
    for (int i = 0; i < count; i++) {
        const size_t before_len = w->len;
        const bool   before_ok  = w->ok;
        write_plug(w, &plugs[i], first);
        /* The writer keeps one byte back for the terminator, hence `>=` not `>`. Entries keep
         * their order and there is no preference pass: unlike scan hosts, everything here has
         * already identified itself as a plug, so no entry outranks another. */
        if (!w->ok || w->len + reserve >= w->cap) {
            w->len = before_len;
            w->ok  = before_ok;
            all    = false;
            continue;
        }
        first = false;
    }
    rw_jw_raw(w, "]");
    return all;
}
