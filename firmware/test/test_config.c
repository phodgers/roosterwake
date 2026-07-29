/*
 * Config codec against the golden vectors.
 *
 * This is the test that matters most in the suite. The flash record format is implemented
 * three times — here in C, in tools/mkconfig/lib/config.mjs, and in the hosted dashboard — and
 * if any two of them disagree by one byte a customer's device loses its configuration. The
 * vectors are the arbiter; this file makes the C implementation answer to them.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "config/config.h"
#include "rw_test.h"
#include "vectors_json.h"

static uint8_t wifi_auth_from_name(const char *name) {
    if (strcmp(name, "open") == 0) return RW_WIFI_AUTH_OPEN;
    if (strcmp(name, "wpa2") == 0) return RW_WIFI_AUTH_WPA2;
    if (strcmp(name, "wpa3") == 0) return RW_WIFI_AUTH_WPA3;
    return RW_WIFI_AUTH_AUTO;
}

static const char *wifi_auth_name(uint8_t value) {
    switch (value) {
        case RW_WIFI_AUTH_OPEN: return "open";
        case RW_WIFI_AUTH_WPA2: return "wpa2";
        case RW_WIFI_AUTH_WPA3: return "wpa3";
        default:                return "auto";
    }
}

/* Build an rw_config_t from a vector's `config` object — the same input the JS encoder gets. */
static bool build_config(const rw_doc_t *doc, int cfg_obj, rw_config_t *out) {
    rw_config_init(out);
    out->seq = rw_doc_u32(doc, cfg_obj, "seq", RW_CFG_GENERATED_SEQ);

    rw_doc_str(doc, cfg_obj, "ssid", out->ssid, sizeof(out->ssid));
    rw_doc_str(doc, cfg_obj, "psk", out->psk, sizeof(out->psk));
    rw_doc_str(doc, cfg_obj, "relay_url", out->relay_url, sizeof(out->relay_url));
    rw_doc_str(doc, cfg_obj, "device_id", out->device_id, sizeof(out->device_id));
    rw_doc_str(doc, cfg_obj, "token", out->token, sizeof(out->token));
    rw_doc_str(doc, cfg_obj, "claim_code", out->claim_code, sizeof(out->claim_code));

    char auth[16] = "auto";
    rw_doc_str(doc, cfg_obj, "wifi_auth", auth, sizeof(auth));
    out->wifi_auth = wifi_auth_from_name(auth[0] ? auth : "auto");

    out->flags = rw_doc_u32(doc, cfg_obj, "flags", 0);

    int targets = rw_doc_member(doc, cfg_obj, "targets");
    if (targets >= 0 && doc->tokens[targets].type == JSMN_ARRAY) {
        int n = doc->tokens[targets].size;
        if (n > RW_CFG_MAX_TARGETS) {
            return false;
        }
        for (int i = 0; i < n; i++) {
            int entry = rw_doc_elem(doc, targets, i);
            char mac_text[32] = {0};
            if (!rw_doc_str(doc, entry, "name", out->targets[i].name,
                            sizeof(out->targets[i].name))) {
                return false;
            }
            if (!rw_doc_str(doc, entry, "mac", mac_text, sizeof(mac_text))) {
                return false;
            }
            if (!rw_mac_parse(mac_text, out->targets[i].mac)) {
                return false;
            }
        }
        out->target_count = (uint8_t)n;
    }
    return true;
}

/* Compare a decoded record against the vector's `decoded` object. */
static void check_decoded(const rw_doc_t *doc, int dec_obj, const rw_config_t *got,
                          const char *vector_name) {
    char expect[RW_CFG_RELAY_URL_LEN];

    rw_doc_str(doc, dec_obj, "ssid", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->ssid, expect) == 0, "%s: ssid \"%s\" != \"%s\"", vector_name,
                 got->ssid, expect);

    rw_doc_str(doc, dec_obj, "psk", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->psk, expect) == 0, "%s: psk mismatch", vector_name);

    rw_doc_str(doc, dec_obj, "relay_url", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->relay_url, expect) == 0, "%s: relay_url \"%s\" != \"%s\"",
                 vector_name, got->relay_url, expect);

    rw_doc_str(doc, dec_obj, "device_id", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->device_id, expect) == 0, "%s: device_id \"%s\" != \"%s\"",
                 vector_name, got->device_id, expect);

    rw_doc_str(doc, dec_obj, "token", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->token, expect) == 0, "%s: token mismatch", vector_name);

    rw_doc_str(doc, dec_obj, "claim_code", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(got->claim_code, expect) == 0, "%s: claim_code \"%s\" != \"%s\"",
                 vector_name, got->claim_code, expect);

    rw_doc_str(doc, dec_obj, "wifi_auth", expect, sizeof(expect));
    RW_CHECK_MSG(strcmp(wifi_auth_name(got->wifi_auth), expect) == 0,
                 "%s: wifi_auth \"%s\" != \"%s\"", vector_name, wifi_auth_name(got->wifi_auth),
                 expect);

    RW_CHECK_MSG(got->flags == rw_doc_u32(doc, dec_obj, "flags", 0), "%s: flags mismatch",
                 vector_name);
    RW_CHECK_MSG(got->seq == rw_doc_u32(doc, dec_obj, "seq", 0), "%s: seq mismatch",
                 vector_name);

    int targets = rw_doc_member(doc, dec_obj, "targets");
    RW_CHECK_MSG(targets >= 0 && doc->tokens[targets].size == got->target_count,
                 "%s: target_count %u != %d", vector_name, got->target_count,
                 targets >= 0 ? doc->tokens[targets].size : -1);

    for (uint8_t i = 0; i < got->target_count; i++) {
        int entry = rw_doc_elem(doc, targets, i);
        rw_doc_str(doc, entry, "name", expect, sizeof(expect));
        RW_CHECK_MSG(strcmp(got->targets[i].name, expect) == 0, "%s: target %u name \"%s\" != \"%s\"",
                     vector_name, i, got->targets[i].name, expect);

        char mac[18];
        rw_mac_format(got->targets[i].mac, mac);
        rw_doc_str(doc, entry, "mac", expect, sizeof(expect));
        RW_CHECK_MSG(strcmp(mac, expect) == 0, "%s: target %u mac \"%s\" != \"%s\"", vector_name,
                     i, mac, expect);
    }
}

static void test_crc32_check_value(const rw_doc_t *doc) {
    rw_test_begin("crc32 check value");

    /* The standard proof that this is CRC-32/ISO-HDLC and not one of the several other things
     * people call CRC32. If this is wrong, every vector below it is wrong. */
    RW_CHECK_EQ_INT(rw_crc32("123456789", 9), 0xCBF43926u);

    char stated[16];
    rw_doc_str(doc, 0, "crc32_check_value", stated, sizeof(stated));
    RW_CHECK_EQ_STR(stated, "0xcbf43926");
}

static void test_layout_constants(const rw_doc_t *doc) {
    rw_test_begin("layout constants agree with the vector file");
    RW_CHECK_EQ_INT(rw_doc_u32(doc, 0, "format_version", 0), RW_CFG_VERSION);
    RW_CHECK_EQ_INT(rw_doc_u32(doc, 0, "header_len", 0), RW_CFG_HEADER_LEN);
    RW_CHECK_EQ_INT(rw_doc_u32(doc, 0, "payload_len", 0), RW_CFG_PAYLOAD_LEN);
    RW_CHECK_EQ_INT(rw_doc_u32(doc, 0, "record_len", 0), RW_CFG_RECORD_LEN);
}

static void test_vectors(const rw_doc_t *doc) {
    int vectors = rw_doc_member(doc, 0, "vectors");
    RW_CHECK_MSG(vectors >= 0 && doc->tokens[vectors].type == JSMN_ARRAY,
                 "the vector file has no `vectors` array");
    if (vectors < 0) {
        return;
    }

    const int n = doc->tokens[vectors].size;
    RW_CHECK_MSG(n >= 5, "expected at least five vectors, found %d", n);

    for (int v = 0; v < n; v++) {
        int  entry = rw_doc_elem(doc, vectors, v);
        char name[64];
        rw_doc_str(doc, entry, "name", name, sizeof(name));

        char label[96];
        snprintf(label, sizeof(label), "vector %s", name);
        rw_test_begin(label);

        uint8_t expected[RW_CFG_RECORD_LEN];
        int     hex_tok = rw_doc_member(doc, entry, "record_hex");
        size_t  got_len = rw_doc_hex(doc, hex_tok, expected, sizeof(expected));
        RW_CHECK_MSG(got_len == RW_CFG_RECORD_LEN, "%s: record_hex decoded to %zu bytes, want %d",
                     name, got_len, RW_CFG_RECORD_LEN);
        if (got_len != RW_CFG_RECORD_LEN) {
            continue;
        }

        /* ── Encode ── */
        rw_config_t cfg;
        int         cfg_obj = rw_doc_member(doc, entry, "config");
        RW_CHECK_MSG(build_config(doc, cfg_obj, &cfg), "%s: could not build the config", name);

        uint8_t actual[RW_CFG_RECORD_LEN];
        size_t  written = rw_config_encode(&cfg, actual, sizeof(actual));
        RW_CHECK_EQ_INT(written, RW_CFG_RECORD_LEN);
        RW_CHECK_EQ_MEM(actual, expected, RW_CFG_RECORD_LEN);

        /* ── CRC ── */
        char crc_text[16];
        rw_doc_str(doc, entry, "crc32", crc_text, sizeof(crc_text));
        char computed[16];
        snprintf(computed, sizeof(computed), "0x%08x",
                 rw_crc32(expected + RW_CFG_HEADER_LEN, RW_CFG_PAYLOAD_LEN));
        RW_CHECK_MSG(strcmp(computed, crc_text) == 0, "%s: crc %s != %s", name, computed,
                     crc_text);

        /* ── Decode ── */
        rw_config_t decoded;
        RW_CHECK_MSG(rw_config_decode(expected, RW_CFG_RECORD_LEN, &decoded),
                     "%s: the golden record did not decode", name);
        check_decoded(doc, rw_doc_member(doc, entry, "decoded"), &decoded, name);

        /* ── Round trip ── */
        uint8_t again[RW_CFG_RECORD_LEN];
        RW_CHECK_EQ_INT(rw_config_encode(&decoded, again, sizeof(again)), RW_CFG_RECORD_LEN);
        RW_CHECK_EQ_MEM(again, expected, RW_CFG_RECORD_LEN);

        /* ── Corruption is detected ── */
        uint8_t corrupt[RW_CFG_RECORD_LEN];
        memcpy(corrupt, expected, sizeof(corrupt));
        corrupt[RW_CFG_HEADER_LEN + 5] ^= 0x01; /* one bit, in the payload */
        rw_config_t scratch;
        RW_CHECK_MSG(!rw_config_decode(corrupt, sizeof(corrupt), &scratch),
                     "%s: a single flipped payload bit was not caught by the CRC", name);

        memcpy(corrupt, expected, sizeof(corrupt));
        corrupt[0] = 'X';
        RW_CHECK_MSG(!rw_config_decode(corrupt, sizeof(corrupt), &scratch),
                     "%s: a wrong magic was accepted", name);

        memcpy(corrupt, expected, sizeof(corrupt));
        corrupt[4] = 2; /* version 2 */
        RW_CHECK_MSG(!rw_config_decode(corrupt, sizeof(corrupt), &scratch),
                     "%s: a future version was accepted rather than refused", name);

        memcpy(corrupt, expected, sizeof(corrupt));
        corrupt[12] = 0x00; /* payload_len 580 -> 512 */
        corrupt[13] = 0x02;
        RW_CHECK_MSG(!rw_config_decode(corrupt, sizeof(corrupt), &scratch),
                     "%s: a wrong payload_len was accepted", name);

        RW_CHECK_MSG(!rw_config_decode(expected, RW_CFG_RECORD_LEN - 1, &scratch),
                     "%s: a truncated record was accepted", name);
    }
}

static void test_seq_comparison(void) {
    rw_test_begin("wrap-safe seq comparison");

    RW_CHECK(rw_seq_newer(2, 1));
    RW_CHECK(!rw_seq_newer(1, 2));
    RW_CHECK(!rw_seq_newer(7, 7));

    /* The case a plain `a > b` gets wrong: 0 is one past 0xFFFFFFFF, not four billion behind
     * it. Without this, the write after a wrap would be discarded in favour of the stale slot
     * for the rest of the device's life. */
    RW_CHECK_MSG(rw_seq_newer(0u, 0xFFFFFFFFu), "0 must be newer than 0xFFFFFFFF after wrap");
    RW_CHECK_MSG(!rw_seq_newer(0xFFFFFFFFu, 0u), "0xFFFFFFFF must not be newer than 0");
    RW_CHECK(rw_seq_newer(0x80000000u, 0x7FFFFFFFu));
    RW_CHECK(!rw_seq_newer(0x7FFFFFFFu, 0x80000000u));
    RW_CHECK(rw_seq_newer(5u, 0xFFFFFFF0u));
}

static void test_slot_selection(void) {
    rw_test_begin("slot selection");

    rw_config_t a, b, winner;
    rw_config_init(&a);
    rw_config_init(&b);
    snprintf(a.ssid, sizeof(a.ssid), "slot-a");
    snprintf(b.ssid, sizeof(b.ssid), "slot-b");

    uint8_t sector_a[RW_CFG_SECTOR_SIZE];
    uint8_t sector_b[RW_CFG_SECTOR_SIZE];

    /* Erased flash reads 0xFF; neither slot is valid and the device is unprovisioned. */
    memset(sector_a, 0xFF, sizeof(sector_a));
    memset(sector_b, 0xFF, sizeof(sector_b));
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 0);
    RW_CHECK_EQ_STR(winner.ssid, "");

    /* Only A valid. */
    memset(sector_a, 0, sizeof(sector_a));
    a.seq = 4;
    rw_config_encode(&a, sector_a, sizeof(sector_a));
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 1);
    RW_CHECK_EQ_STR(winner.ssid, "slot-a");

    /* Both valid, B newer. */
    memset(sector_b, 0, sizeof(sector_b));
    b.seq = 5;
    rw_config_encode(&b, sector_b, sizeof(sector_b));
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 2);
    RW_CHECK_EQ_STR(winner.ssid, "slot-b");

    /* Both valid, A newer. */
    memset(sector_a, 0, sizeof(sector_a));
    a.seq = 6;
    rw_config_encode(&a, sector_a, sizeof(sector_a));
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 1);
    RW_CHECK_EQ_STR(winner.ssid, "slot-a");

    /* Across the wrap: A holds 0xFFFFFFFF, B holds the write that followed it. */
    memset(sector_a, 0, sizeof(sector_a));
    memset(sector_b, 0, sizeof(sector_b));
    a.seq = 0xFFFFFFFFu;
    b.seq = 0u;
    rw_config_encode(&a, sector_a, sizeof(sector_a));
    rw_config_encode(&b, sector_b, sizeof(sector_b));
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 2);
    RW_CHECK_EQ_STR(winner.ssid, "slot-b");

    /* A half-written slot must never win, whatever its seq claims. */
    memset(sector_b, 0, sizeof(sector_b));
    b.seq = 0x40000000u;
    rw_config_encode(&b, sector_b, sizeof(sector_b));
    sector_b[RW_CFG_HEADER_LEN + 100] ^= 0xFF;
    RW_CHECK_EQ_INT(
        rw_config_select(sector_a, sizeof(sector_a), sector_b, sizeof(sector_b), &winner), 1);
    RW_CHECK_EQ_STR(winner.ssid, "slot-a");
}

static void test_encode_limits(void) {
    rw_test_begin("encoder rejects over-long fields");

    rw_config_t cfg;
    uint8_t     out[RW_CFG_RECORD_LEN];

    /* 32 bytes of SSID is the documented maximum and must fit; the field is 33 wide because
     * the NUL is counted. This is the off-by-one the `maximal` vector exists to pin, checked
     * here from the other direction. */
    rw_config_init(&cfg);
    memset(cfg.ssid, 'A', 32);
    cfg.ssid[32] = '\0';
    RW_CHECK_EQ_INT(rw_config_encode(&cfg, out, sizeof(out)), RW_CFG_RECORD_LEN);

    /* Too many targets is refused rather than silently truncated. */
    rw_config_init(&cfg);
    cfg.target_count = RW_CFG_MAX_TARGETS + 1;
    RW_CHECK_EQ_INT(rw_config_encode(&cfg, out, sizeof(out)), 0);

    /* A target with no name would round-trip to something no dashboard can label. */
    rw_config_init(&cfg);
    cfg.target_count = 1;
    RW_CHECK_EQ_INT(rw_config_encode(&cfg, out, sizeof(out)), 0);

    /* A buffer that cannot hold a record is refused, not partially filled. */
    rw_config_init(&cfg);
    RW_CHECK_EQ_INT(rw_config_encode(&cfg, out, RW_CFG_RECORD_LEN - 1), 0);
}

static void test_mac_helpers(void) {
    rw_test_begin("mac parsing and formatting");

    uint8_t mac[6];
    RW_CHECK(rw_mac_parse("AA:BB:CC:DD:EE:FF", mac));
    RW_CHECK_EQ_INT(mac[0], 0xAA);
    RW_CHECK_EQ_INT(mac[5], 0xFF);

    char text[18];
    rw_mac_format(mac, text);
    RW_CHECK_EQ_STR(text, "AA:BB:CC:DD:EE:FF");

    /* usbcfg.md §4 and PROTOCOL.md §2: colons, dashes or nothing, any case. */
    RW_CHECK(rw_mac_parse("aa-bb-cc-dd-ee-ff", mac));
    rw_mac_format(mac, text);
    RW_CHECK_EQ_STR(text, "AA:BB:CC:DD:EE:FF");

    RW_CHECK(rw_mac_parse("aabbccddeeff", mac));
    rw_mac_format(mac, text);
    RW_CHECK_EQ_STR(text, "AA:BB:CC:DD:EE:FF");

    RW_CHECK(!rw_mac_parse("aabbccddee", mac));       /* too short */
    RW_CHECK(!rw_mac_parse("aabbccddeeff11", mac));   /* too long */
    RW_CHECK(!rw_mac_parse("gg:bb:cc:dd:ee:ff", mac));/* not hex */
    RW_CHECK(!rw_mac_parse("", mac));
    RW_CHECK(!rw_mac_parse(NULL, mac));
}

void test_config(void) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/vectors/config-v1.json", rw_test_data_dir);

    rw_doc_t doc;
    if (!rw_doc_load(&doc, path)) {
        rw_test_begin("golden vectors");
        RW_CHECK_MSG(false, "could not load %s", path);
        return;
    }

    test_crc32_check_value(&doc);
    test_layout_constants(&doc);
    test_vectors(&doc);
    rw_doc_free(&doc);

    test_seq_comparison();
    test_slot_selection();
    test_encode_limits();
    test_mac_helpers();
}
