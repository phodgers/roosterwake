/*
 * The Shelly layer: HTTP splitting, generation classification, request building, status
 * parsing and the plug list's size arithmetic.
 *
 * The response bodies here are the shapes real devices answer with — a Gen1 Plug S and a
 * Gen2+ Plus Plug — because this parser's whole contract is those two shapes and its whole
 * failure mode is a firmware update on their side that this suite would have caught on ours.
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>

#include "plug/shelly.h"
#include "rw_test.h"

/* A response assembled from parts, NUL-terminated, as httpc delivers it. */
static size_t resp(char *buf, size_t cap, const char *headers, const char *body) {
    int n = snprintf(buf, cap, "%s%s", headers, body);
    return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

static void check_split(void) {
    char        buf[4096];
    int         status;
    const char *body;
    size_t      body_len;

    /* The ordinary case: status, headers, Content-Length, body. */
    {
        size_t len = resp(buf, sizeof(buf),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/json\r\n"
                          "Content-Length: 13\r\n"
                          "Connection: close\r\n\r\n",
                          "{\"ison\":true}");
        RW_CHECK(rw_shelly_http_split(buf, len, &status, &body, &body_len));
        RW_CHECK_EQ_INT(status, 200);
        RW_CHECK_EQ_INT((int)body_len, 13);
        RW_CHECK(memcmp(body, "{\"ison\":true}", 13) == 0);
    }

    /* No Content-Length: the close delimits the body, which is how HTTP/1.0-ish devices
     * answer. */
    {
        size_t len = resp(buf, sizeof(buf), "HTTP/1.1 200 OK\r\n\r\n", "{\"gen\":2}");
        RW_CHECK(rw_shelly_http_split(buf, len, &status, &body, &body_len));
        RW_CHECK_EQ_INT((int)body_len, 9);
    }

    /* Header names are case-insensitive; a body short of its declared length is refused —
     * a connection that died mid-body must not parse as a smaller truth. */
    {
        size_t len = resp(buf, sizeof(buf), "HTTP/1.1 200 OK\r\ncontent-LENGTH: 500\r\n\r\n",
                          "{\"truncated\":");
        RW_CHECK(!rw_shelly_http_split(buf, len, &status, &body, &body_len));
    }

    /* Chunked is refused, not de-chunked. */
    {
        size_t len = resp(buf, sizeof(buf),
                          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                          "d\r\n{\"ison\":true}\r\n0\r\n\r\n");
        RW_CHECK(!rw_shelly_http_split(buf, len, &status, &body, &body_len));
    }

    /* An error status still splits — the caller decides what a 400 means. */
    {
        size_t len = resp(buf, sizeof(buf), "HTTP/1.1 404 Not Found\r\n\r\n", "Not Found");
        RW_CHECK(rw_shelly_http_split(buf, len, &status, &body, &body_len));
        RW_CHECK_EQ_INT(status, 404);
    }

    /* Not HTTP at all, and a header block that never ends. */
    {
        const char *junk = "SSH-2.0-OpenSSH_9.6\r\n";
        RW_CHECK(!rw_shelly_http_split(junk, strlen(junk), &status, &body, &body_len));
        const char *unterminated = "HTTP/1.1 200 OK\r\nContent-Length: 2";
        RW_CHECK(!rw_shelly_http_split(unterminated, strlen(unterminated), &status, &body,
                                       &body_len));
    }

    /* A declared length over RW_SHELLY_BODY_MAX is refused from the header alone. */
    {
        size_t len = resp(buf, sizeof(buf), "HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n",
                          "{}");
        RW_CHECK(!rw_shelly_http_split(buf, len, &status, &body, &body_len));
    }
}

/* MACs below are RFC 7042 documentation addresses (00-00-5E-00-53-xx), per repo policy. */
static const char k_gen1_shelly[] =
    "{\"type\":\"SHPLG-S\",\"mac\":\"00005E005301\",\"auth\":false,\"fw\":\"20230913-112003\","
    "\"longid\":1,\"num_outputs\":1}";

static const char k_gen2_shelly[] =
    "{\"name\":null,\"id\":\"shellyplusplugs-00005e005302\",\"mac\":\"00005E005302\","
    "\"slot\":0,\"model\":\"SNPL-00112UK\",\"gen\":2,\"fw_id\":\"20240625-123456\","
    "\"ver\":\"1.3.3\",\"app\":\"PlusPlugS\",\"auth_en\":false,\"auth_domain\":null}";

static void check_identify(void) {
    rw_shelly_id_t id;

    RW_CHECK(rw_shelly_identify(k_gen1_shelly, strlen(k_gen1_shelly), &id));
    RW_CHECK_EQ_INT(id.gen, 1);
    RW_CHECK_EQ_STR(id.model, "SHPLG-S");
    RW_CHECK_EQ_INT(id.channels, 1);
    RW_CHECK_EQ_STR(id.name, "");
    RW_CHECK_EQ_STR(id.fw, "20230913-112003"); /* Gen1 `fw`, verbatim */
    const uint8_t mac1[6] = {0x00, 0x00, 0x5E, 0x00, 0x53, 0x01};
    RW_CHECK_EQ_MEM(id.mac, mac1, 6);

    RW_CHECK(rw_shelly_identify(k_gen2_shelly, strlen(k_gen2_shelly), &id));
    RW_CHECK_EQ_INT(id.gen, 2);
    RW_CHECK_EQ_STR(id.model, "SNPL-00112UK");
    RW_CHECK_EQ_INT(id.channels, 1);
    /* `name` is null until an owner sets one; `id` stands in. */
    RW_CHECK_EQ_STR(id.name, "shellyplusplugs-00005e005302");
    RW_CHECK_EQ_STR(id.fw, "1.3.3"); /* Gen2 `ver`, verbatim */

    /* A named Gen3 device: `gen` is carried through, the name wins over the id. */
    {
        const char *g3 =
            "{\"name\":\"rack plug\",\"id\":\"shellyplugsg3-00005e005303\","
            "\"mac\":\"00005E005303\",\"model\":\"S3PL-00112EU\",\"gen\":3}";
        RW_CHECK(rw_shelly_identify(g3, strlen(g3), &id));
        RW_CHECK_EQ_INT(id.gen, 3);
        RW_CHECK_EQ_STR(id.name, "rack plug");
        /* A body without `ver` is still a plug; the firmware is best-effort, not a gate. */
        RW_CHECK_EQ_STR(id.fw, "");
    }

    /* Most of what answers port 80 is not a Shelly. */
    {
        const char *router = "{\"status\":\"ok\",\"vendor\":\"router\"}";
        RW_CHECK(!rw_shelly_identify(router, strlen(router), &id));
        const char *html = "<!DOCTYPE html><html></html>";
        RW_CHECK(!rw_shelly_identify(html, strlen(html), &id));
        /* A Shelly shape without a parseable MAC is refused: identity is the whole point. */
        const char *no_mac = "{\"type\":\"SHPLG-S\",\"mac\":\"xx\",\"num_outputs\":1}";
        RW_CHECK(!rw_shelly_identify(no_mac, strlen(no_mac), &id));
    }
}

static void check_requests(void) {
    char buf[256];

    RW_CHECK(rw_shelly_req_identify(buf, sizeof(buf), "192.168.1.60") > 0);
    RW_CHECK_EQ_STR(buf, "GET /shelly HTTP/1.1\r\n"
                         "Host: 192.168.1.60\r\n"
                         "Connection: close\r\n\r\n");

    RW_CHECK(rw_shelly_req_set(buf, sizeof(buf), "192.168.1.60", 1, 0, true) > 0);
    RW_CHECK_EQ_STR(buf, "GET /relay/0?turn=on HTTP/1.1\r\n"
                         "Host: 192.168.1.60\r\n"
                         "Connection: close\r\n\r\n");

    RW_CHECK(rw_shelly_req_status(buf, sizeof(buf), "192.168.1.60", 1, 2) > 0);
    RW_CHECK(strstr(buf, "GET /status HTTP/1.1") == buf);

    /* The RPC body's Content-Length must be the body's actual length — a device reads exactly
     * that many bytes, and one byte short is a request that hangs until its timeout. */
    RW_CHECK(rw_shelly_req_set(buf, sizeof(buf), "10.0.0.9", 2, 1, false) > 0);
    {
        const char *body = strstr(buf, "\r\n\r\n");
        RW_CHECK(body != NULL);
        body += 4;
        RW_CHECK_EQ_STR(body, "{\"id\":1,\"method\":\"Switch.Set\",\"params\":{\"id\":1,\"on\":false}}");
        char expect[32];
        snprintf(expect, sizeof(expect), "Content-Length: %d\r\n", (int)strlen(body));
        RW_CHECK(strstr(buf, expect) != NULL);
    }

    RW_CHECK(rw_shelly_req_status(buf, sizeof(buf), "10.0.0.9", 2, 0) > 0);
    RW_CHECK(strstr(buf, "\"method\":\"Switch.GetStatus\"") != NULL);
    RW_CHECK(strstr(buf, "POST /rpc HTTP/1.1") == buf);

    /* A buffer too small reports 0 rather than a truncated request. */
    RW_CHECK_EQ_INT((int)rw_shelly_req_identify(buf, 10, "192.168.1.60"), 0);

    /* The firmware verbs. Gen1 keeps the whole standing at `/ota`; Gen2+ speaks the
     * direct-path RPC form, whose refusals arrive as non-200 rather than buried in an
     * envelope's HTTP 200. */
    RW_CHECK(rw_shelly_req_fw_info(buf, sizeof(buf), "192.168.1.60", 1) > 0);
    RW_CHECK_EQ_STR(buf, "GET /ota HTTP/1.1\r\n"
                         "Host: 192.168.1.60\r\n"
                         "Connection: close\r\n\r\n");

    RW_CHECK(rw_shelly_req_fw_info(buf, sizeof(buf), "10.0.0.9", 2) > 0);
    RW_CHECK(strstr(buf, "GET /rpc/Shelly.GetDeviceInfo HTTP/1.1") == buf);

    RW_CHECK(rw_shelly_req_fw_check(buf, sizeof(buf), "10.0.0.9") > 0);
    RW_CHECK(strstr(buf, "GET /rpc/Shelly.CheckForUpdate HTTP/1.1") == buf);

    RW_CHECK(rw_shelly_req_fw_update(buf, sizeof(buf), "192.168.1.60", 1) > 0);
    RW_CHECK(strstr(buf, "GET /ota?update=true HTTP/1.1") == buf);

    /* The Gen2 update order: direct-path POST, Content-Length exactly the body's length. */
    RW_CHECK(rw_shelly_req_fw_update(buf, sizeof(buf), "10.0.0.9", 2) > 0);
    RW_CHECK(strstr(buf, "POST /rpc/Shelly.Update HTTP/1.1") == buf);
    {
        const char *body = strstr(buf, "\r\n\r\n");
        RW_CHECK(body != NULL);
        body += 4;
        RW_CHECK_EQ_STR(body, "{\"stage\":\"stable\"}");
        char expect[32];
        snprintf(expect, sizeof(expect), "Content-Length: %d\r\n", (int)strlen(body));
        RW_CHECK(strstr(buf, expect) != NULL);
    }
}

static void check_fw(void) {
    rw_shelly_fw_t fw;

    /* A Gen1 `/ota` with an update available: all three facts. */
    {
        const char *body =
            "{\"status\":\"idle\",\"has_update\":true,"
            "\"new_version\":\"20240625-123456/v1.14.1-gabcdef1\","
            "\"old_version\":\"20230913-112003/v1.14.0-gcb84623\"}";
        RW_CHECK(rw_shelly_parse_ota_report(body, strlen(body), &fw));
        RW_CHECK_EQ_STR(fw.current, "20230913-112003/v1.14.0-gcb84623");
        RW_CHECK_EQ_STR(fw.latest, "20240625-123456/v1.14.1-gabcdef1");
        RW_CHECK(fw.has_update);
    }

    /* Up to date — and `/ota` still echoes `new_version`, which must NOT surface as
     * `latest`: the device's own verdict decides, never a string comparison upstream. */
    {
        const char *body =
            "{\"status\":\"idle\",\"has_update\":false,"
            "\"new_version\":\"20230913-112003/v1.14.0-gcb84623\","
            "\"old_version\":\"20230913-112003/v1.14.0-gcb84623\"}";
        RW_CHECK(rw_shelly_parse_ota_report(body, strlen(body), &fw));
        RW_CHECK_EQ_STR(fw.current, "20230913-112003/v1.14.0-gcb84623");
        RW_CHECK_EQ_STR(fw.latest, "");
        RW_CHECK(!fw.has_update);
    }

    /* Not the report's shape: no verdict, or no running build to name. */
    {
        const char *no_verdict = "{\"status\":\"idle\",\"old_version\":\"x\"}";
        RW_CHECK(!rw_shelly_parse_ota_report(no_verdict, strlen(no_verdict), &fw));
        const char *no_current = "{\"has_update\":false}";
        RW_CHECK(!rw_shelly_parse_ota_report(no_current, strlen(no_current), &fw));
        const char *html = "<!DOCTYPE html>";
        RW_CHECK(!rw_shelly_parse_ota_report(html, strlen(html), &fw));
    }

    /* A direct-path Shelly.GetDeviceInfo: `ver` names the running build. */
    {
        char        ver[RW_SHELLY_FW_LEN];
        const char *body =
            "{\"name\":null,\"id\":\"shellyplusplugs-00005e005302\",\"mac\":\"00005E005302\","
            "\"model\":\"SNPL-00112UK\",\"gen\":2,\"fw_id\":\"20250213-104904/1.4.4-g6d2a586\","
            "\"ver\":\"1.4.4\",\"app\":\"PlusPlugS\"}";
        RW_CHECK(rw_shelly_parse_device_ver(body, strlen(body), ver, sizeof(ver)));
        RW_CHECK_EQ_STR(ver, "1.4.4");

        const char *no_ver = "{\"gen\":2}";
        RW_CHECK(!rw_shelly_parse_device_ver(no_ver, strlen(no_ver), ver, sizeof(ver)));
    }

    /* Shelly.CheckForUpdate: `{}` — no `stable` member at all — IS the up-to-date answer,
     * the real firmware's shape, and must parse as ok rather than as a failure. */
    {
        memset(&fw, 0, sizeof(fw));
        const char *current = "{}";
        RW_CHECK(rw_shelly_parse_update_check(current, strlen(current), &fw));
        RW_CHECK(!fw.has_update);
        RW_CHECK_EQ_STR(fw.latest, "");

        const char *newer =
            "{\"stable\":{\"version\":\"2.0.0\",\"build_id\":\"20250715-104532/2.0.0-gf2d5c\"}}";
        RW_CHECK(rw_shelly_parse_update_check(newer, strlen(newer), &fw));
        RW_CHECK(fw.has_update);
        RW_CHECK_EQ_STR(fw.latest, "2.0.0");

        /* A beta on offer with no stable is still "nothing stable to move to". */
        const char *beta_only = "{\"beta\":{\"version\":\"2.1.0-beta1\"}}";
        RW_CHECK(rw_shelly_parse_update_check(beta_only, strlen(beta_only), &fw));
        RW_CHECK(!fw.has_update);

        const char *not_json = "Not Found";
        RW_CHECK(!rw_shelly_parse_update_check(not_json, strlen(not_json), &fw));
    }
}

static void check_status_gen1(void) {
    /* A Plug S `/status`, trimmed to the members that matter plus the noise around them. */
    const char *body =
        "{\"wifi_sta\":{\"connected\":true,\"ssid\":\"net\",\"ip\":\"192.168.1.60\",\"rssi\":-52},"
        "\"cloud\":{\"enabled\":false,\"connected\":false},\"mqtt\":{\"connected\":false},"
        "\"time\":\"18:20\",\"unixtime\":1755713400,\"serial\":1,\"has_update\":false,"
        "\"mac\":\"00005E005301\","
        "\"relays\":[{\"ison\":true,\"has_timer\":false,\"overpower\":false,\"source\":\"http\"}],"
        "\"meters\":[{\"power\":41.25,\"overpower\":0.00,\"is_valid\":true,\"timestamp\":1755713400,"
        "\"counters\":[41.1,40.9,41.0],\"total\":16500}],"
        "\"temperature\":22.5,\"overtemperature\":false,\"tmp\":{\"tC\":22.5,\"is_valid\":true},"
        "\"update\":{\"status\":\"idle\"},\"ram_total\":50592,\"ram_free\":38904,\"uptime\":86400}";

    rw_shelly_status_t st;
    RW_CHECK(rw_shelly_parse_status(body, strlen(body), 1, 0, &st));
    RW_CHECK(st.on);
    RW_CHECK(st.have_apower);
    RW_CHECK_EQ_INT(st.apower_mw, 41250);
    /* Gen1 counts watt-minutes: 16500 Wmin are 275 Wh. */
    RW_CHECK(st.have_energy);
    RW_CHECK_EQ_INT(st.energy_mwh, 275000);
    RW_CHECK(!st.have_voltage);

    /* A channel the device does not have is a refusal, not channel 0's answer. */
    RW_CHECK(!rw_shelly_parse_status(body, strlen(body), 1, 1, &st));

    /* A relay with no meter behind it: state parses, metering stays absent. */
    {
        const char *bare = "{\"relays\":[{\"ison\":false}],\"meters\":[]}";
        RW_CHECK(rw_shelly_parse_status(bare, strlen(bare), 1, 0, &st));
        RW_CHECK(!st.on);
        RW_CHECK(!st.have_apower && !st.have_energy && !st.have_voltage);
    }
}

static void check_status_gen2(void) {
    /* A `POST /rpc` answer: the Switch.GetStatus payload inside the JSON-RPC envelope. */
    const char *body =
        "{\"id\":1,\"src\":\"shellyplusplugs-00005e005302\","
        "\"result\":{\"id\":0,\"source\":\"HTTP_in\",\"output\":true,\"apower\":8.9,"
        "\"voltage\":237.5,\"current\":0.045,\"aenergy\":{\"total\":6.532,"
        "\"by_minute\":[12.1,11.9,12.0],\"minute_ts\":1755713400},"
        "\"temperature\":{\"tC\":35.5,\"tF\":95.9}}}";

    rw_shelly_status_t st;
    RW_CHECK(rw_shelly_parse_status(body, strlen(body), 2, 0, &st));
    RW_CHECK(st.on);
    RW_CHECK(st.have_apower);
    RW_CHECK_EQ_INT(st.apower_mw, 8900);
    RW_CHECK(st.have_voltage);
    RW_CHECK_EQ_INT(st.voltage_mv, 237500);
    RW_CHECK(st.have_energy);
    RW_CHECK_EQ_INT(st.energy_mwh, 6532);

    /* The RPC's refusal arrives as HTTP 200 with an `error` member — a bad channel id. It
     * must never read as "off". */
    {
        const char *err =
            "{\"id\":1,\"src\":\"shellyplusplugs-00005e005302\","
            "\"error\":{\"code\":-103,\"message\":\"Invalid argument 'id'!\"}}";
        RW_CHECK(!rw_shelly_parse_status(err, strlen(err), 2, 1, &st));
        bool have_state, state_on;
        RW_CHECK(!rw_shelly_parse_set(err, strlen(err), 2, &have_state, &state_on));
    }

    /* Set confirmations. The generations answer opposite halves of "what state now": Gen1's
     * `ison` is the NEW state and is reported; Gen2's `was_on` is the PREVIOUS state and must
     * never be — a driver that echoed it would report every successful `on` as `off`. So a
     * Gen2 acceptance comes back with no state at all, which is what forces the confirming
     * Switch.GetStatus read. */
    {
        bool        have_state, state_on;
        const char *g2 = "{\"id\":1,\"src\":\"x\",\"result\":{\"was_on\":false}}";
        RW_CHECK(rw_shelly_parse_set(g2, strlen(g2), 2, &have_state, &state_on));
        RW_CHECK(!have_state);

        const char *g1 = "{\"ison\":true,\"has_timer\":false}";
        RW_CHECK(rw_shelly_parse_set(g1, strlen(g1), 1, &have_state, &state_on));
        RW_CHECK(have_state);
        RW_CHECK(state_on);

        const char *g1_off = "{\"ison\":false,\"has_timer\":false}";
        RW_CHECK(rw_shelly_parse_set(g1_off, strlen(g1_off), 1, &have_state, &state_on));
        RW_CHECK(have_state);
        RW_CHECK(!state_on);

        const char *not_json = "Bad channel";
        RW_CHECK(!rw_shelly_parse_set(not_json, strlen(not_json), 1, &have_state, &state_on));
    }

    /* An unmetered Gen2 switch: `output` alone is a complete answer. */
    {
        const char *bare = "{\"id\":1,\"src\":\"x\",\"result\":{\"id\":0,\"output\":false}}";
        RW_CHECK(rw_shelly_parse_status(bare, strlen(bare), 2, 0, &st));
        RW_CHECK(!st.on);
        RW_CHECK(!st.have_apower && !st.have_voltage && !st.have_energy);
    }
}

static void check_milli(void) {
    char    buf[64];
    rw_jw_t w;

    static const struct {
        long        milli;
        const char *text;
    } cases[] = {
        {8900, "8.9"}, {1005, "1.005"}, {2000, "2"}, {0, "0"},
        {-500, "-0.5"}, {-2000, "-2"}, {41250, "41.25"}, {237500, "237.5"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        rw_jw_init(&w, buf, sizeof(buf));
        rw_jw_milli(&w, cases[i].milli);
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK_EQ_STR(buf, cases[i].text);
    }
}

static rw_shelly_plug_t plug(const char *ip, uint8_t last, const char *name) {
    rw_shelly_plug_t p = {0};
    snprintf(p.mac, sizeof(p.mac), "00:00:5E:00:53:%02X", last);
    snprintf(p.ip, sizeof(p.ip), "%s", ip);
    snprintf(p.model, sizeof(p.model), "SNPL-00112UK");
    snprintf(p.name, sizeof(p.name), "%s", name);
    p.gen      = 2;
    p.channels = 1;
    return p;
}

static void check_json_plugs(void) {
    /* Everything fits: exact frame text; name and fw omitted where the device offered none,
     * present verbatim where it did. */
    {
        rw_shelly_plug_t plugs[2] = {
            plug("192.168.1.60", 0x02, "rack plug"),
            plug("192.168.1.61", 0x03, ""),
        };
        snprintf(plugs[0].fw, sizeof(plugs[0].fw), "2.0.0");
        char    buf[512];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        rw_jw_raw(&w, "{");
        RW_CHECK(rw_shelly_json_plugs(&w, plugs, 2, 1));
        rw_jw_raw(&w, "}");
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK_EQ_STR(buf,
                        "{\"plugs\":["
                        "{\"mac\":\"00:00:5E:00:53:02\",\"ip\":\"192.168.1.60\","
                        "\"model\":\"SNPL-00112UK\",\"gen\":2,\"name\":\"rack plug\","
                        "\"channels\":1,\"fw\":\"2.0.0\"},"
                        "{\"mac\":\"00:00:5E:00:53:03\",\"ip\":\"192.168.1.61\","
                        "\"model\":\"SNPL-00112UK\",\"gen\":2,\"channels\":1}"
                        "]}");
    }

    /* An empty sweep is an empty array, not a missing field. */
    {
        char    buf[64];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(rw_shelly_json_plugs(&w, NULL, 0, 1));
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK_EQ_STR(buf, "\"plugs\":[]");
    }

    /* A buffer that fits one of two: the second is dropped, the writer stays valid, and the
     * return says so — the scan_json contract. */
    {
        rw_shelly_plug_t plugs[2] = {
            plug("10.0.0.1", 0x01, ""),
            plug("10.0.0.2", 0x02, ""),
        };
        char    buf[128];
        rw_jw_t w;
        rw_jw_init(&w, buf, sizeof(buf));
        RW_CHECK(!rw_shelly_json_plugs(&w, plugs, 2, 1));
        RW_CHECK(rw_jw_finish(&w) > 0);
        RW_CHECK(strstr(buf, "10.0.0.1") != NULL);
        RW_CHECK(strstr(buf, "10.0.0.2") == NULL);
        RW_CHECK(buf[strlen(buf) - 1] == ']');
    }
}

void test_shelly(void) {
    rw_test_begin("shelly");
    check_split();
    check_identify();
    check_requests();
    check_fw();
    check_status_gen1();
    check_status_gen2();
    check_milli();
    check_json_plugs();
}
