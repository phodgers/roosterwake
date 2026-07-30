/*
 * usbcfg protocol tests — firmware/docs/usbcfg.md.
 *
 * usbcfg.md is a public contract that third-party tools are invited to implement against, so
 * the parts of it that can be pinned without hardware are pinned here: the quoting rules, the
 * closed error-code set, the staging validation, and the guarantee that no secret ever leaves
 * over this channel.
 *
 * SPDX-License-Identifier: MIT
 */
#include "rw_test.h"

#include "brand.h"
#include "usbcfg/cmdline.h"

/* Parse and assert success, returning the token list. */
static void parse_ok(rw_cmdline_t *cl, const char *line, int expect_argc) {
    rw_uerr_t err = rw_cmdline_parse(line, cl);
    RW_CHECK_MSG(err == RW_UERR_NONE, "parse(\"%s\"): %s", line, rw_uerr_code(err));
    RW_CHECK_EQ_INT(cl->argc, expect_argc);
}

static void parse_fails(const char *line, rw_uerr_t expect) {
    rw_cmdline_t cl;
    rw_uerr_t    err = rw_cmdline_parse(line, &cl);
    RW_CHECK_MSG(err == expect, "parse(\"%s\"): got %s, expected %s", line, rw_uerr_code(err),
                 rw_uerr_code(expect));
}

static void test_command_lookup(void) {
    rw_test_begin("commands are case-insensitive (§2)");
    RW_CHECK(rw_cmd_lookup("INFO") == RW_CMD_INFO);
    RW_CHECK(rw_cmd_lookup("info") == RW_CMD_INFO);
    RW_CHECK(rw_cmd_lookup("InFo") == RW_CMD_INFO);
    RW_CHECK(rw_cmd_lookup("SET_WIFI") == RW_CMD_SET_WIFI);
    RW_CHECK(rw_cmd_lookup("set_wifi") == RW_CMD_SET_WIFI);

    rw_test_begin("every documented command resolves");
    RW_CHECK(rw_cmd_lookup("SCAN") == RW_CMD_SCAN);
    RW_CHECK(rw_cmd_lookup("SET_RELAY") == RW_CMD_SET_RELAY);
    RW_CHECK(rw_cmd_lookup("ADD_TARGET") == RW_CMD_ADD_TARGET);
    RW_CHECK(rw_cmd_lookup("CLEAR_TARGETS") == RW_CMD_CLEAR_TARGETS);
    RW_CHECK(rw_cmd_lookup("SET_EMAIL") == RW_CMD_SET_EMAIL);
    RW_CHECK(rw_cmd_lookup("SET_TOKEN") == RW_CMD_SET_TOKEN);
    RW_CHECK(rw_cmd_lookup("GET_CONFIG") == RW_CMD_GET_CONFIG);
    RW_CHECK(rw_cmd_lookup("COMMIT") == RW_CMD_COMMIT);
    RW_CHECK(rw_cmd_lookup("STATUS") == RW_CMD_STATUS);
    RW_CHECK(rw_cmd_lookup("TEST_WAKE") == RW_CMD_TEST_WAKE);
    RW_CHECK(rw_cmd_lookup("FACTORY_RESET") == RW_CMD_FACTORY_RESET);
    RW_CHECK(rw_cmd_lookup("REBOOT") == RW_CMD_REBOOT);
    RW_CHECK(rw_cmd_lookup("BOOTSEL") == RW_CMD_BOOTSEL);

    rw_test_begin("unknown and empty are distinguished");
    /* An empty line produces no response at all (§2); an unrecognised word produces
     * ERR unknown_cmd. Collapsing the two would make a stray newline look like an error. */
    RW_CHECK(rw_cmd_lookup("NOPE") == RW_CMD_UNKNOWN);
    RW_CHECK(rw_cmd_lookup("") == RW_CMD_NONE);
    RW_CHECK(rw_cmd_lookup(NULL) == RW_CMD_NONE);

    rw_test_begin("SET_WIFI is not matched by a prefix");
    RW_CHECK(rw_cmd_lookup("SET") == RW_CMD_UNKNOWN);
    RW_CHECK(rw_cmd_lookup("SET_WIFI_EXTRA") == RW_CMD_UNKNOWN);
}

static void test_error_codes(void) {
    rw_test_begin("the §6 code set is complete and stable");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_UNKNOWN_CMD), "unknown_cmd");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_BAD_ARGS), "bad_args");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_BAD_ARG), "bad_arg");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_BAD_FRAME), "bad_frame");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_TOO_LONG), "too_long");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_TOO_MANY), "too_many");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_NOTHING_STAGED), "nothing_staged");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_NEEDS_CONFIRM), "needs_confirm");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_NOT_JOINED), "not_joined");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_BUSY), "busy");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_FLASH_ERROR), "flash_error");
    RW_CHECK_EQ_STR(rw_uerr_code(RW_UERR_INTERNAL), "internal");

    rw_test_begin("codes carry no spaces, so `ERR <code> <message>` stays parseable");
    static const rw_uerr_t all[] = {
        RW_UERR_UNKNOWN_CMD, RW_UERR_BAD_ARGS,      RW_UERR_BAD_ARG,   RW_UERR_BAD_FRAME,
        RW_UERR_TOO_LONG,    RW_UERR_TOO_MANY,      RW_UERR_NOTHING_STAGED,
        RW_UERR_NEEDS_CONFIRM, RW_UERR_NOT_JOINED,  RW_UERR_BUSY,      RW_UERR_FLASH_ERROR,
        RW_UERR_INTERNAL,
    };
    for (size_t i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
        const char *code = rw_uerr_code(all[i]);
        RW_CHECK_MSG(strchr(code, ' ') == NULL, "code \"%s\" contains a space", code);
        RW_CHECK_MSG(code[0] != '\0', "empty code");
        /* The message may change between versions, but it must exist and be one line. */
        const char *msg = rw_uerr_message(all[i]);
        RW_CHECK_MSG(strchr(msg, '\n') == NULL, "message for %s spans lines", code);
    }
}

static void test_tokeniser(void) {
    rw_cmdline_t cl;

    rw_test_begin("a bare command");
    parse_ok(&cl, "INFO", 1);
    RW_CHECK_EQ_STR(cl.argv[0], "INFO");

    rw_test_begin("leading, trailing and repeated spaces collapse");
    parse_ok(&cl, "   INFO   ", 1);
    RW_CHECK_EQ_STR(cl.argv[0], "INFO");
    parse_ok(&cl, "ADD_TARGET    PC     AA:BB:CC:DD:EE:FF", 3);
    RW_CHECK_EQ_STR(cl.argv[1], "PC");
    RW_CHECK_EQ_STR(cl.argv[2], "AA:BB:CC:DD:EE:FF");

    rw_test_begin("an empty line yields no tokens and no error");
    parse_ok(&cl, "", 0);
    parse_ok(&cl, "     ", 0);

    rw_test_begin("quoted arguments keep their spaces (§2)");
    /* The documented example. SSIDs with spaces are the common case, not the edge case. */
    parse_ok(&cl, "SET_WIFI \"Sarah's Wi-Fi 5GHz\" \"p@ss word\\\"with quotes\"", 3);
    RW_CHECK_EQ_STR(cl.argv[0], "SET_WIFI");
    RW_CHECK_EQ_STR(cl.argv[1], "Sarah's Wi-Fi 5GHz");
    RW_CHECK_EQ_STR(cl.argv[2], "p@ss word\"with quotes");

    rw_test_begin("both escapes, and only those two");
    parse_ok(&cl, "SET_WIFI \"a\\\\b\" \"c\\\"d\"", 3);
    RW_CHECK_EQ_STR(cl.argv[1], "a\\b");
    RW_CHECK_EQ_STR(cl.argv[2], "c\"d");

    rw_test_begin("an empty quoted argument is a real, distinct value");
    /* SET_WIFI "OpenNet" "" must mean an open network, not a missing argument. */
    parse_ok(&cl, "SET_WIFI \"OpenNet\" \"\"", 3);
    RW_CHECK_EQ_STR(cl.argv[1], "OpenNet");
    RW_CHECK_EQ_STR(cl.argv[2], "");

    rw_test_begin("malformed quoting is refused, never guessed at");
    parse_fails("SET_WIFI \"unterminated", RW_UERR_BAD_FRAME);
    parse_fails("SET_WIFI \"trailing backslash\\", RW_UERR_BAD_FRAME);
    parse_fails("SET_WIFI \"bad \\escape\"", RW_UERR_BAD_FRAME);
    parse_fails("SET_WIFI \"ab\"cd", RW_UERR_BAD_FRAME);
    /* Bare `"` and `\` must be quoted per §2. Accepting them would make the quoted and
     * unquoted spellings of the same SSID mean different things. */
    parse_fails("SET_WIFI my\"net", RW_UERR_BAD_FRAME);
    parse_fails("SET_WIFI my\\net", RW_UERR_BAD_FRAME);

    rw_test_begin("a line at the 512-byte limit is accepted, one past it is not");
    char at_limit[RW_USBCFG_MAX_LINE];
    memset(at_limit, 'a', sizeof(at_limit));
    at_limit[RW_USBCFG_MAX_LINE - 1] = '\0'; /* 511 bytes of text plus the NUL */
    parse_ok(&cl, at_limit, 1);

    char over_limit[RW_USBCFG_MAX_LINE + 8];
    memset(over_limit, 'a', sizeof(over_limit));
    over_limit[RW_USBCFG_MAX_LINE] = '\0'; /* 512 bytes of text: one too many */
    parse_fails(over_limit, RW_UERR_TOO_LONG);

    rw_test_begin("too many arguments is bad_args, not a buffer overrun");
    parse_fails("A B C D E F G H I", RW_UERR_BAD_ARGS);

    rw_test_begin("invalid UTF-8 is rejected at the door (§1)");
    parse_fails("SET_WIFI \xC3\x28", RW_UERR_BAD_FRAME);       /* bad continuation */
    parse_fails("SET_WIFI \xE2\x82", RW_UERR_BAD_FRAME);       /* truncated 3-byte */
    parse_fails("SET_WIFI \xC0\xAF", RW_UERR_BAD_FRAME);       /* overlong '/' */
    parse_fails("SET_WIFI \xED\xA0\x80", RW_UERR_BAD_FRAME);   /* lone surrogate */
    parse_fails("SET_WIFI \xF5\x80\x80\x80", RW_UERR_BAD_FRAME); /* beyond U+10FFFF */

    rw_test_begin("valid multi-byte UTF-8 passes through unchanged");
    parse_ok(&cl, "ADD_TARGET \"Bj\xC3\xB6rns B\xC3\xBCro\" AABBCCDDEEFF", 3);
    RW_CHECK_EQ_STR(cl.argv[1], "Bj\xC3\xB6rns B\xC3\xBCro");
    parse_ok(&cl, "ADD_TARGET \"\xF0\x9F\x8F\xA0\" AABBCCDDEEFF", 3);
    RW_CHECK_EQ_STR(cl.argv[1], "\xF0\x9F\x8F\xA0");
}

static void test_utf8_validator(void) {
    rw_test_begin("utf8 validator accepts the boundaries");
    RW_CHECK(rw_utf8_valid(""));
    RW_CHECK(rw_utf8_valid("plain ascii"));
    RW_CHECK(rw_utf8_valid("\xC2\x80"));         /* U+0080, shortest 2-byte */
    RW_CHECK(rw_utf8_valid("\xDF\xBF"));         /* U+07FF */
    RW_CHECK(rw_utf8_valid("\xE0\xA0\x80"));     /* U+0800, shortest 3-byte */
    RW_CHECK(rw_utf8_valid("\xEF\xBF\xBD"));     /* U+FFFD */
    RW_CHECK(rw_utf8_valid("\xF0\x90\x80\x80")); /* U+10000, shortest 4-byte */
    RW_CHECK(rw_utf8_valid("\xF4\x8F\xBF\xBF")); /* U+10FFFF, the last code point */

    rw_test_begin("utf8 validator rejects overlongs, surrogates and out-of-range");
    RW_CHECK(!rw_utf8_valid("\xC1\xBF"));         /* overlong U+007F */
    RW_CHECK(!rw_utf8_valid("\xE0\x9F\xBF"));     /* overlong U+07FF */
    RW_CHECK(!rw_utf8_valid("\xF0\x8F\xBF\xBF")); /* overlong U+FFFF */
    RW_CHECK(!rw_utf8_valid("\xED\xBF\xBF"));     /* U+DFFF, high surrogate range */
    RW_CHECK(!rw_utf8_valid("\xF4\x90\x80\x80")); /* U+110000 */
    RW_CHECK(!rw_utf8_valid("\x80"));             /* continuation in lead position */
    RW_CHECK(!rw_utf8_valid("\xFE"));
    RW_CHECK(!rw_utf8_valid("\xFF"));
}

static void test_staging(void) {
    rw_config_t base;
    rw_config_init(&base);
    rw_stage_t st;

    rw_test_begin("a fresh stage is not dirty, so COMMIT refuses it");
    rw_stage_init(&st, &base);
    RW_CHECK(!st.dirty);
    RW_CHECK(rw_stage_validate(&st) == RW_UERR_NOTHING_STAGED);

    rw_test_begin("SET_WIFI with a psk selects auto, not wpa2");
    /* A router in WPA2/WPA3 transition mode is now normal. Pinning wpa2 gives a device that
     * associates today and stops the day the owner turns off the legacy mode. */
    RW_CHECK(rw_stage_set_wifi(&st, "HomeNet", "correct horse") == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.ssid, "HomeNet");
    RW_CHECK_EQ_STR(st.cfg.psk, "correct horse");
    RW_CHECK_EQ_INT(st.cfg.wifi_auth, RW_WIFI_AUTH_AUTO);
    RW_CHECK(st.dirty);

    rw_test_begin("SET_WIFI without a psk selects open and clears any previous secret");
    RW_CHECK(rw_stage_set_wifi(&st, "OpenNet", "") == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.psk, "");
    RW_CHECK_EQ_INT(st.cfg.wifi_auth, RW_WIFI_AUTH_OPEN);
    RW_CHECK(rw_stage_set_wifi(&st, "OpenNet", NULL) == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.psk, "");

    rw_test_begin("an empty ssid is refused");
    RW_CHECK(rw_stage_set_wifi(&st, "", "x") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_wifi(&st, NULL, "x") == RW_UERR_BAD_ARG);

    rw_test_begin("field limits are in bytes and reject rather than truncate");
    rw_stage_init(&st, &base);
    char ssid32[33];
    memset(ssid32, 'a', 32);
    ssid32[32] = '\0';
    RW_CHECK(rw_stage_set_wifi(&st, ssid32, NULL) == RW_UERR_NONE);
    char ssid33[34];
    memset(ssid33, 'a', 33);
    ssid33[33] = '\0';
    RW_CHECK(rw_stage_set_wifi(&st, ssid33, NULL) == RW_UERR_BAD_ARG);
    /* Eleven 3-byte characters is 33 bytes: over the limit even though it is 11 characters.
     * An implementation counting characters would truncate mid-sequence and write broken text
     * to flash for the life of the device. */
    RW_CHECK(rw_stage_set_wifi(&st, "\xE4\xBB\x95\xE4\xBB\x95\xE4\xBB\x95\xE4\xBB\x95"
                                    "\xE4\xBB\x95\xE4\xBB\x95\xE4\xBB\x95\xE4\xBB\x95"
                                    "\xE4\xBB\x95\xE4\xBB\x95\xE4\xBB\x95",
                               NULL) == RW_UERR_BAD_ARG);

    rw_test_begin("SET_RELAY accepts wss anywhere");
    rw_stage_init(&st, &base);
    RW_CHECK(rw_stage_set_relay(&st, "wss://relay.remotewake.com/ws") == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.relay_url, "wss://relay.remotewake.com/ws");

    rw_test_begin("SET_RELAY accepts ws only for private addresses (§4)");
    RW_CHECK(rw_stage_set_relay(&st, "ws://192.168.1.10:8080/ws") == RW_UERR_NONE);
    RW_CHECK(rw_stage_set_relay(&st, "ws://127.0.0.1:8080/ws") == RW_UERR_NONE);
    RW_CHECK(rw_stage_set_relay(&st, "ws://10.0.0.5/ws") == RW_UERR_NONE);
    /* Plaintext to a public host would put the challenge-response in the clear across the
     * internet, so it is refused where it is configured rather than where it is dialled. */
    RW_CHECK(rw_stage_set_relay(&st, "ws://relay.example.com/ws") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_relay(&st, "ws://8.8.8.8/ws") == RW_UERR_BAD_ARG);

    rw_test_begin("SET_RELAY refuses non-websocket schemes and rubbish");
    RW_CHECK(rw_stage_set_relay(&st, "https://relay.remotewake.com/ws") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_relay(&st, "relay.remotewake.com") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_relay(&st, "") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_relay(&st, NULL) == RW_UERR_BAD_ARG);

    rw_test_begin("ADD_TARGET accepts every documented MAC spelling");
    rw_stage_init(&st, &base);
    RW_CHECK(rw_stage_add_target(&st, "Desk", "AA:BB:CC:DD:EE:FF") == RW_UERR_NONE);
    RW_CHECK(rw_stage_add_target(&st, "Desk2", "aa-bb-cc-dd-ee-ff") == RW_UERR_NONE);
    RW_CHECK(rw_stage_add_target(&st, "Desk3", "aabbccddeeff") == RW_UERR_NONE);
    RW_CHECK_EQ_INT(st.cfg.target_count, 3);
    static const uint8_t expect[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    RW_CHECK_EQ_MEM(st.cfg.targets[0].mac, expect, 6);
    RW_CHECK_EQ_MEM(st.cfg.targets[1].mac, expect, 6);
    RW_CHECK_EQ_MEM(st.cfg.targets[2].mac, expect, 6);

    rw_test_begin("ADD_TARGET refuses a bad MAC or an empty name");
    RW_CHECK(rw_stage_add_target(&st, "Bad", "not-a-mac") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_add_target(&st, "Bad", "AA:BB:CC:DD:EE") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_add_target(&st, "", "AABBCCDDEEFF") == RW_UERR_BAD_ARG);
    RW_CHECK_EQ_INT(st.cfg.target_count, 3); /* a rejected target is not half-added */

    rw_test_begin("the ninth target is too_many, not a silent overwrite");
    rw_stage_init(&st, &base);
    for (int i = 0; i < RW_CFG_MAX_TARGETS; i++) {
        RW_CHECK(rw_stage_add_target(&st, "T", "AABBCCDDEEFF") == RW_UERR_NONE);
    }
    RW_CHECK(rw_stage_add_target(&st, "T", "AABBCCDDEEFF") == RW_UERR_TOO_MANY);
    RW_CHECK_EQ_INT(st.cfg.target_count, RW_CFG_MAX_TARGETS);

    rw_test_begin("CLEAR_TARGETS empties the list");
    RW_CHECK(rw_stage_clear_targets(&st) == RW_UERR_NONE);
    RW_CHECK_EQ_INT(st.cfg.target_count, 0);
    RW_CHECK(rw_stage_add_target(&st, "T", "AABBCCDDEEFF") == RW_UERR_NONE);

    rw_test_begin("a 24-byte target name fits, 25 does not");
    rw_stage_init(&st, &base);
    char name24[25];
    memset(name24, 'n', 24);
    name24[24] = '\0';
    RW_CHECK(rw_stage_add_target(&st, name24, "AABBCCDDEEFF") == RW_UERR_NONE);
    char name25[26];
    memset(name25, 'n', 25);
    name25[25] = '\0';
    RW_CHECK(rw_stage_add_target(&st, name25, "AABBCCDDEEFF") == RW_UERR_BAD_ARG);

    rw_test_begin("SET_EMAIL takes an address and refuses what is obviously not one");
    rw_stage_init(&st, &base);
    RW_CHECK(rw_stage_set_email(&st, "philip@example.com") == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.owner_email, "philip@example.com");
    RW_CHECK(rw_stage_set_email(&st, "a.b+tag@sub.example.co.uk") == RW_UERR_NONE);

    /* The mistakes this exists to catch: the SSID or the MAC typed into the wrong box. Either
     * would otherwise be written to flash and offered to the relay on every connection. */
    RW_CHECK(rw_stage_set_email(&st, "HomeNet") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "A0:B1:C2:D3:E4:F5") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "@example.com") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "philip@") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "philip@localhost") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "philip@.com") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "philip@example.") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, "two@at@example.com") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_email(&st, NULL) == RW_UERR_BAD_ARG);

    /* A refused address leaves the last accepted one intact. */
    RW_CHECK_EQ_STR(st.cfg.owner_email, "a.b+tag@sub.example.co.uk");

    rw_test_begin("SET_EMAIL bounds the field rather than truncating into flash");
    char long_local[RW_CFG_OWNER_EMAIL_LEN + 16];
    memset(long_local, 'a', sizeof(long_local) - 1);
    long_local[sizeof(long_local) - 1] = '\0';
    memcpy(long_local + RW_CFG_OWNER_EMAIL_LEN, "@example.com", 13);
    RW_CHECK(rw_stage_set_email(&st, long_local) == RW_UERR_BAD_ARG);

    rw_test_begin("SET_TOKEN takes exactly 64 hex digits and stores them lower-case");
    rw_stage_init(&st, &base);
    const char *upper = "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455667788AA";
    RW_CHECK(rw_stage_set_token(&st, upper) == RW_UERR_NONE);
    RW_CHECK_EQ_STR(st.cfg.token,
                    "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa");
    /* 63 and 65 digits both fail. A short token is not a weak token, it is one that fails every
     * handshake minutes later at the relay with nothing pointing back at the typo. */
    RW_CHECK(rw_stage_set_token(&st, "aabbccddeeff00112233445566778899aabbccddeeff0011223344556677") ==
             RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_token(
                 &st, "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aab") ==
             RW_UERR_BAD_ARG);
    /* 'g' is not hex; the 'x' of an 0x prefix is the mistake a person actually makes here. */
    RW_CHECK(rw_stage_set_token(
                 &st, "gabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa") ==
             RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_token(&st, "") == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_token(&st, NULL) == RW_UERR_BAD_ARG);
    /* A refused token leaves the previously accepted one alone — a validation failure must not
     * half-write the field it was checking. */
    RW_CHECK_EQ_STR(st.cfg.token,
                    "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa");

    rw_test_begin("SET_TOKEN is a staged change like any other");
    rw_stage_init(&st, &base);
    RW_CHECK(rw_stage_validate(&st) == RW_UERR_NOTHING_STAGED);
    RW_CHECK(rw_stage_set_token(&st, upper) == RW_UERR_NONE);
    RW_CHECK(st.dirty);

    rw_test_begin("COMMIT without an ssid is refused rather than writing a dead config");
    rw_stage_init(&st, &base);
    RW_CHECK(rw_stage_add_target(&st, "Desk", "AABBCCDDEEFF") == RW_UERR_NONE);
    RW_CHECK(rw_stage_validate(&st) == RW_UERR_BAD_ARG);
    RW_CHECK(rw_stage_set_wifi(&st, "HomeNet", "pw") == RW_UERR_NONE);
    RW_CHECK(rw_stage_validate(&st) == RW_UERR_NONE);
}

static void test_response_encoders(void) {
    char        buf[1024];
    rw_config_t cfg;
    rw_config_init(&cfg);

    rw_test_begin("INFO carries the §4 fields");
    rw_info_view_t view = {
        .device_id    = "a1b2c3d4e5f60718",
        .mac          = "28:CD:C1:0A:1B:2C",
        .reset_reason = "power_on",
        .uptime_s     = 142,
        .configured   = true,
    };
    size_t n = rw_usbcfg_info_json(&view, buf, sizeof(buf));
    RW_CHECK(n > 0);
    RW_CHECK(strstr(buf, "\"proto\":1") != NULL);
    /* Against RW_BOARD_NAME, not a literal: the firmware supports two boards and the value is
     * derived from the target, so pinning one here would fail the other's build for no reason.
     * What matters is that INFO reports the board it was actually compiled for. */
    RW_CHECK(strstr(buf, "\"board\":\"" RW_BOARD_NAME "\"") != NULL);
    RW_CHECK(strcmp(RW_BOARD_NAME, "pico2_w") == 0 || strcmp(RW_BOARD_NAME, "pico_w") == 0);
    RW_CHECK(strstr(buf, "\"device_id\":\"a1b2c3d4e5f60718\"") != NULL);
    RW_CHECK(strstr(buf, "\"mac\":\"28:CD:C1:0A:1B:2C\"") != NULL);
    RW_CHECK(strstr(buf, "\"configured\":true") != NULL);
    RW_CHECK(strstr(buf, "\"uptime_s\":142") != NULL);
    RW_CHECK(strstr(buf, "\"reset_reason\":\"power_on\"") != NULL);

    rw_test_begin("a response is one line, because the host reads one line");
    RW_CHECK(strchr(buf, '\n') == NULL);
    RW_CHECK(strchr(buf, '\r') == NULL);

    rw_test_begin("GET_CONFIG reports state without secrets");
    snprintf(cfg.ssid, sizeof(cfg.ssid), "HomeNet");
    snprintf(cfg.psk, sizeof(cfg.psk), "SUPERSECRETWIFIPASSWORD");
    snprintf(cfg.token, sizeof(cfg.token), "d34db33fd34db33fd34db33fd34db33f");
    snprintf(cfg.owner_email, sizeof(cfg.owner_email), "philip@example.com");
    snprintf(cfg.relay_url, sizeof(cfg.relay_url), "wss://relay.remotewake.com/ws");
    snprintf(cfg.device_id, sizeof(cfg.device_id), "a1b2c3d4e5f60718");
    cfg.wifi_auth       = RW_WIFI_AUTH_WPA2;
    cfg.target_count    = 1;
    snprintf(cfg.targets[0].name, sizeof(cfg.targets[0].name), "Office Desktop");
    static const uint8_t mac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    memcpy(cfg.targets[0].mac, mac, 6);

    n = rw_usbcfg_config_json(&cfg, buf, sizeof(buf));
    RW_CHECK(n > 0);
    RW_CHECK(strstr(buf, "\"ssid\":\"HomeNet\"") != NULL);
    RW_CHECK(strstr(buf, "\"auth\":\"wpa2\"") != NULL);
    RW_CHECK(strstr(buf, "\"psk_set\":true") != NULL);
    RW_CHECK(strstr(buf, "\"token_set\":true") != NULL);
    RW_CHECK(strstr(buf, "\"email_set\":true") != NULL);
    RW_CHECK(strstr(buf, "\"name\":\"Office Desktop\"") != NULL);
    RW_CHECK(strstr(buf, "\"mac\":\"AA:BB:CC:DD:EE:FF\"") != NULL);

    /*
     * The guarantee in §4, asserted rather than assumed. A dongle plugged into an untrusted
     * machine must not be a way to read the Wi-Fi password or the device token out of it, and
     * this is the test that fails if anyone ever adds a debugging field that leaks one.
     */
    rw_test_begin("no usbcfg response ever contains the psk or the token (§4)");
    RW_CHECK_MSG(strstr(buf, "SUPERSECRETWIFIPASSWORD") == NULL, "GET_CONFIG leaked the psk");
    RW_CHECK_MSG(strstr(buf, "d34db33f") == NULL, "GET_CONFIG leaked the token");
    RW_CHECK_MSG(strstr(buf, "\"psk\":") == NULL, "GET_CONFIG has a psk field at all");
    RW_CHECK_MSG(strstr(buf, "\"token\":") == NULL, "GET_CONFIG has a token field at all");

    rw_test_begin("unset secrets report false, not an empty string");
    rw_config_init(&cfg);
    snprintf(cfg.ssid, sizeof(cfg.ssid), "OpenNet");
    n = rw_usbcfg_config_json(&cfg, buf, sizeof(buf));
    RW_CHECK(n > 0);
    RW_CHECK(strstr(buf, "\"psk_set\":false") != NULL);
    RW_CHECK(strstr(buf, "\"token_set\":false") != NULL);
    RW_CHECK(strstr(buf, "\"email_set\":false") != NULL);
    RW_CHECK(strstr(buf, "\"targets\":[]") != NULL);

    rw_test_begin("an unset relay reports the default rather than an empty string");
    /* A setup tool showing "" here would suggest the device has nowhere to connect, when in
     * fact an empty field means the compiled-in default. */
    RW_CHECK(strstr(buf, "\"relay\":\"" RW_DEFAULT_RELAY_URL "\"") != NULL);

    rw_test_begin("encoders report overflow instead of emitting a truncated object");
    char tiny[16];
    RW_CHECK_EQ_INT(rw_usbcfg_config_json(&cfg, tiny, sizeof(tiny)), 0);
    RW_CHECK_EQ_INT(rw_usbcfg_info_json(&view, tiny, sizeof(tiny)), 0);

    rw_test_begin("names needing JSON escapes survive the round trip");
    rw_config_init(&cfg);
    snprintf(cfg.ssid, sizeof(cfg.ssid), "quote\"and\\slash");
    n = rw_usbcfg_config_json(&cfg, buf, sizeof(buf));
    RW_CHECK(n > 0);
    RW_CHECK(strstr(buf, "\"ssid\":\"quote\\\"and\\\\slash\"") != NULL);
}

void test_usbcfg(void) {
    test_command_lookup();
    test_error_codes();
    test_tokeniser();
    test_utf8_validator();
    test_staging();
    test_response_encoders();
}
