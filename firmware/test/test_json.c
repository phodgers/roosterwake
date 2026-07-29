/*
 * JSON writing and reading — the layer every PROTOCOL.md frame passes through.
 *
 * SPDX-License-Identifier: MIT
 */
#include <string.h>

#include "proto/json.h"
#include "rw_test.h"

static void test_writer(void) {
    rw_test_begin("json writer");

    char    buf[256];
    rw_jw_t w;

    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "wake_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "sent");
    rw_jw_int(&w, 12);
    rw_jw_raw(&w, "}");
    RW_CHECK(rw_jw_finish(&w) > 0);
    RW_CHECK_EQ_STR(buf, "{\"t\":\"wake_result\",\"sent\":12}");

    /* Escaping. Quotes and backslashes are the ones that break a frame; control characters are
     * escaped as \u00XX because a raw one is invalid JSON. */
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_str(&w, "a\"b\\c\nd\te\x01");
    RW_CHECK(rw_jw_finish(&w) > 0);
    RW_CHECK_EQ_STR(buf, "\"a\\\"b\\\\c\\nd\\te\\u0001\"");

    /* UTF-8 passes through unchanged: target names are UTF-8 by contract and re-encoding them
     * would only make the frame larger. */
    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_str(&w, "Bj\xc3\xb6rns B\xc3\xbcro");
    RW_CHECK(rw_jw_finish(&w) > 0);
    RW_CHECK_EQ_STR(buf, "\"Bj\xc3\xb6rns B\xc3\xbcro\"");

    rw_jw_init(&w, buf, sizeof(buf));
    rw_jw_int(&w, -52);
    RW_CHECK(rw_jw_finish(&w) > 0);
    RW_CHECK_EQ_STR(buf, "-52");

    /* Overflow is reported, never truncated into a frame that looks valid. A half-written
     * frame reaching the relay would be worse than none. */
    char small[8];
    rw_jw_init(&w, small, sizeof(small));
    rw_jw_str(&w, "far too long for this buffer");
    RW_CHECK_EQ_INT(rw_jw_finish(&w), 0);
    RW_CHECK(!w.ok);

    /* Exactly filling the buffer, minus the terminator, still succeeds. */
    char exact[6];
    rw_jw_init(&w, exact, sizeof(exact));
    rw_jw_str(&w, "abcd"); /* "abcd" with quotes is 6 chars, +1 NUL = 7 > 6 */
    RW_CHECK_EQ_INT(rw_jw_finish(&w), 0);

    char exact2[6];
    rw_jw_init(&w, exact2, sizeof(exact2));
    rw_jw_str(&w, "abc"); /* 5 chars + NUL = 6 */
    RW_CHECK_EQ_INT(rw_jw_finish(&w), 5);
    RW_CHECK_EQ_STR(exact2, "\"abc\"");
}

#define TOKENS 128

static int parse_doc(const char *js, jsmntok_t *tokens) {
    jsmn_parser p;
    jsmn_init(&p);
    return jsmn_parse(&p, js, strlen(js), tokens, TOKENS);
}

static void test_reader(void) {
    rw_test_begin("json reader");

    jsmntok_t   tokens[TOKENS];
    const char *js =
        "{\"t\":\"wake\",\"req_id\":\"8f14e45f\",\"repeat\":3,\"ok\":true,\"neg\":-7,"
        "\"targets\":[{\"name\":\"Desktop\",\"mac\":\"AA:BB:CC:DD:EE:FF\"},"
        "{\"name\":\"NAS\",\"mac\":\"11:22:33:44:55:66\"}]}";
    int count = parse_doc(js, tokens);
    RW_CHECK(count > 0);

    int idx = rw_json_find(js, tokens, count, "t");
    RW_CHECK(idx > 0);
    RW_CHECK(rw_json_eq(js, &tokens[idx], "wake"));
    RW_CHECK(!rw_json_eq(js, &tokens[idx], "wake_result"));
    RW_CHECK(!rw_json_eq(js, &tokens[idx], "wak"));

    char out[64];
    idx = rw_json_find(js, tokens, count, "req_id");
    RW_CHECK(rw_json_str(js, &tokens[idx], out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "8f14e45f");

    long value = 0;
    idx        = rw_json_find(js, tokens, count, "repeat");
    RW_CHECK(rw_json_int(js, &tokens[idx], &value));
    RW_CHECK_EQ_INT(value, 3);

    idx = rw_json_find(js, tokens, count, "neg");
    RW_CHECK(rw_json_int(js, &tokens[idx], &value));
    RW_CHECK_EQ_INT(value, -7);

    idx = rw_json_find(js, tokens, count, "ok");
    RW_CHECK(rw_json_is_true(js, &tokens[idx]));
    RW_CHECK(!rw_json_int(js, &tokens[idx], &value));

    /* A key that only appears nested must not be found at the top level, or a `config_push`
     * carrying a target named "ssid" would look like an attempt to set Wi-Fi credentials. */
    RW_CHECK_EQ_INT(rw_json_find(js, tokens, count, "name"), -1);
    RW_CHECK_EQ_INT(rw_json_find(js, tokens, count, "missing"), -1);

    /* The array and its elements. */
    idx = rw_json_find(js, tokens, count, "targets");
    RW_CHECK(idx > 0);
    RW_CHECK_EQ_INT(tokens[idx].type, JSMN_ARRAY);
    RW_CHECK_EQ_INT(tokens[idx].size, 2);

    int entry = idx + 1;
    RW_CHECK_EQ_INT(tokens[entry].type, JSMN_OBJECT);
    RW_CHECK(rw_json_eq(js, &tokens[entry + 1], "name"));
    RW_CHECK(rw_json_str(js, &tokens[entry + 2], out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "Desktop");

    int second = rw_json_skip(tokens, count, entry);
    RW_CHECK_EQ_INT(tokens[second].type, JSMN_OBJECT);
    RW_CHECK(rw_json_str(js, &tokens[second + 2], out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "NAS");
}

static void test_string_escapes(void) {
    rw_test_begin("json string escapes");

    jsmntok_t tokens[TOKENS];
    char      out[64];

    const char *simple = "{\"s\":\"a\\\"b\\\\c\\/d\\ne\\tf\\r\\b\\g\"}";
    /* \g is not a valid escape; the whole string must be rejected rather than half-decoded. */
    int count = parse_doc(simple, tokens);
    if (count > 0) {
        int idx = rw_json_find(simple, tokens, count, "s");
        RW_CHECK(!rw_json_str(simple, &tokens[idx], out, sizeof(out)));
    }

    const char *valid = "{\"s\":\"a\\\"b\\\\c\\/d\\ne\\tf\"}";
    count             = parse_doc(valid, tokens);
    RW_CHECK(count > 0);
    int idx = rw_json_find(valid, tokens, count, "s");
    RW_CHECK(rw_json_str(valid, &tokens[idx], out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "a\"b\\c/d\ne\tf");

    /* \u escapes, including a surrogate pair. These arrive from any relay whose JSON encoder
     * escapes non-ASCII, and the result is written into flash — so a wrong decode is
     * permanent. */
    const char *unicode = "{\"s\":\"caf\\u00e9 \\u4ed5\\u4e8b \\ud83c\\udfe0\"}";
    count               = parse_doc(unicode, tokens);
    RW_CHECK(count > 0);
    idx = rw_json_find(unicode, tokens, count, "s");
    RW_CHECK(rw_json_str(unicode, &tokens[idx], out, sizeof(out)));
    RW_CHECK_EQ_STR(out, "caf\xc3\xa9 \xe4\xbb\x95\xe4\xba\x8b \xf0\x9f\x8f\xa0");

    /* A lone high surrogate is not valid Unicode and must be refused, not emitted as broken
     * UTF-8 that then travels back out on the wire. */
    const char *lone_high = "{\"s\":\"\\ud83c\"}";
    count                 = parse_doc(lone_high, tokens);
    RW_CHECK(count > 0);
    idx = rw_json_find(lone_high, tokens, count, "s");
    RW_CHECK(!rw_json_str(lone_high, &tokens[idx], out, sizeof(out)));

    const char *lone_low = "{\"s\":\"\\udfe0\"}";
    count                = parse_doc(lone_low, tokens);
    RW_CHECK(count > 0);
    idx = rw_json_find(lone_low, tokens, count, "s");
    RW_CHECK(!rw_json_str(lone_low, &tokens[idx], out, sizeof(out)));

    const char *bad_hex = "{\"s\":\"\\u00zz\"}";
    count               = parse_doc(bad_hex, tokens);
    if (count > 0) {
        idx = rw_json_find(bad_hex, tokens, count, "s");
        RW_CHECK(!rw_json_str(bad_hex, &tokens[idx], out, sizeof(out)));
    }

    /* A string that does not fit is refused whole. */
    const char *longish = "{\"s\":\"0123456789abcdef\"}";
    count               = parse_doc(longish, tokens);
    idx                 = rw_json_find(longish, tokens, count, "s");
    char tiny[8];
    RW_CHECK(!rw_json_str(longish, &tokens[idx], tiny, sizeof(tiny)));
}

static void test_number_edges(void) {
    rw_test_begin("json number edges");

    jsmntok_t tokens[TOKENS];
    long      value;

    const char *js =
        "{\"a\":2147483647,\"b\":2147483648,\"c\":1.5,\"d\":1e3,\"e\":null,"
        "\"f\":-2147483648,\"g\":-2147483649,\"h\":99999999999999999999}";
    int count = parse_doc(js, tokens);
    RW_CHECK(count > 0);

    RW_CHECK(rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "a")], &value));
    RW_CHECK_EQ_INT(value, 2147483647L);

    /*
     * Above INT32_MAX is refused rather than wrapped into a plausible small number. `long` is
     * 32-bit on ARM newlib and on Windows, so a parser that accumulates into a long and then
     * checks for overflow is checking a value that has already wrapped.
     */
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "b")], &value));
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "g")], &value));
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "h")], &value));

    RW_CHECK(rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "f")], &value));
    RW_CHECK_EQ_INT(value, -2147483647L - 1L);
    /* Fractional and exponent forms are not integers; nothing in the protocol sends them, and
     * silently truncating would hide a peer that does. */
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "c")], &value));
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "d")], &value));
    RW_CHECK(!rw_json_int(js, &tokens[rw_json_find(js, tokens, count, "e")], &value));
}

static void test_keepalive_bytes(void) {
    rw_test_begin("keepalive frames are byte-literal");

    /*
     * PROTOCOL.md §9 specifies these literally, with no whitespace and no extra fields,
     * because a hibernating relay runtime matches on the exact byte sequence to answer without
     * waking. A writer that one day added a space would cost the relay operator money with no
     * visible symptom, so the bytes are pinned here rather than generated.
     */
    const char *ping = "{\"t\":\"ping\"}";
    const char *pong = "{\"t\":\"pong\"}";
    RW_CHECK_EQ_INT(strlen(ping), 12);
    RW_CHECK_EQ_INT(strlen(pong), 12);

    /* And they must still parse as ordinary frames, because a relay that does not implement
     * the fast path handles them normally. */
    jsmntok_t tokens[TOKENS];
    int       count = parse_doc(ping, tokens);
    RW_CHECK(count > 0);
    int idx = rw_json_find(ping, tokens, count, "t");
    RW_CHECK(rw_json_eq(ping, &tokens[idx], "ping"));
}

void test_json(void) {
    test_writer();
    test_reader();
    test_string_escapes();
    test_number_edges();
    test_keepalive_bytes();
}
