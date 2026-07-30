/*
 * Host-portable half of the usbcfg channel. See cmdline.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "usbcfg/cmdline.h"

#include <string.h>

#include "brand.h"
#include "net/url.h"
#include "proto/json.h"

/* ── Error codes ─────────────────────────────────────────────────────────── */

typedef struct {
    rw_uerr_t   err;
    const char *code;
    const char *message;
} uerr_entry_t;

static const uerr_entry_t k_errors[] = {
    {RW_UERR_NONE,           "ok",             "ok"},
    {RW_UERR_UNKNOWN_CMD,    "unknown_cmd",    "command not recognised"},
    {RW_UERR_BAD_ARGS,       "bad_args",       "wrong number of arguments"},
    {RW_UERR_BAD_ARG,        "bad_arg",        "an argument failed validation"},
    {RW_UERR_BAD_FRAME,      "bad_frame",      "malformed quoting or invalid UTF-8"},
    {RW_UERR_TOO_LONG,       "too_long",       "line exceeded 512 bytes"},
    {RW_UERR_TOO_MANY,       "too_many",       "target limit reached"},
    {RW_UERR_NOTHING_STAGED, "nothing_staged", "no pending changes to commit"},
    {RW_UERR_NEEDS_CONFIRM,  "needs_confirm",  "repeat with the CONFIRM argument"},
    {RW_UERR_NOT_JOINED,     "not_joined",     "wi-fi is not connected"},
    {RW_UERR_BUSY,           "busy",           "a conflicting operation is already running"},
    {RW_UERR_FLASH_ERROR,    "flash_error",    "flash write failed; configuration unchanged"},
    {RW_UERR_INTERNAL,       "internal",       "internal error"},
};

static const uerr_entry_t *find_error(rw_uerr_t err) {
    for (size_t i = 0; i < sizeof(k_errors) / sizeof(k_errors[0]); i++) {
        if (k_errors[i].err == err) {
            return &k_errors[i];
        }
    }
    return NULL;
}

const char *rw_uerr_code(rw_uerr_t err) {
    const uerr_entry_t *e = find_error(err);
    return e ? e->code : "internal";
}

const char *rw_uerr_message(rw_uerr_t err) {
    const uerr_entry_t *e = find_error(err);
    return e ? e->message : "internal error";
}

/* ── Command table ───────────────────────────────────────────────────────── */

typedef struct {
    rw_cmd_id_t id;
    const char *name;
} cmd_entry_t;

static const cmd_entry_t k_commands[] = {
    {RW_CMD_INFO,          "INFO"},
    {RW_CMD_SCAN,          "SCAN"},
    {RW_CMD_SET_WIFI,      "SET_WIFI"},
    {RW_CMD_SET_RELAY,     "SET_RELAY"},
    {RW_CMD_ADD_TARGET,    "ADD_TARGET"},
    {RW_CMD_CLEAR_TARGETS, "CLEAR_TARGETS"},
    {RW_CMD_SET_EMAIL,     "SET_EMAIL"},
    {RW_CMD_SET_TOKEN,     "SET_TOKEN"},
    {RW_CMD_GET_CONFIG,    "GET_CONFIG"},
    {RW_CMD_COMMIT,        "COMMIT"},
    {RW_CMD_STATUS,        "STATUS"},
    {RW_CMD_WIFI_TRACE,    "WIFI_TRACE"},
    {RW_CMD_TEST_WAKE,     "TEST_WAKE"},
    {RW_CMD_FACTORY_RESET, "FACTORY_RESET"},
    {RW_CMD_REBOOT,        "REBOOT"},
    {RW_CMD_BOOTSEL,       "BOOTSEL"},
};

/* ASCII-only, and deliberately not tolower() from <ctype.h>: that is locale-dependent, and in a
 * Turkish locale it maps 'I' to a dotless i, which would stop INFO being recognised. */
static char ascii_upper(char c) {
    return (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
}

static bool iequal(const char *a, const char *b) {
    while (*a && *b) {
        if (ascii_upper(*a) != ascii_upper(*b)) {
            return false;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

rw_cmd_id_t rw_cmd_lookup(const char *word) {
    if (word == NULL || word[0] == '\0') {
        return RW_CMD_NONE;
    }
    for (size_t i = 0; i < sizeof(k_commands) / sizeof(k_commands[0]); i++) {
        if (iequal(word, k_commands[i].name)) {
            return k_commands[i].id;
        }
    }
    return RW_CMD_UNKNOWN;
}

const char *rw_cmd_name(rw_cmd_id_t id) {
    for (size_t i = 0; i < sizeof(k_commands) / sizeof(k_commands[0]); i++) {
        if (k_commands[i].id == id) {
            return k_commands[i].name;
        }
    }
    return "(unknown)";
}

/* ── UTF-8 ───────────────────────────────────────────────────────────────── */

bool rw_utf8_valid(const char *s) {
    const uint8_t *p = (const uint8_t *)s;
    while (*p) {
        uint8_t  c = *p;
        int      extra;
        uint32_t cp;

        if (c < 0x80) {
            p++;
            continue;
        } else if ((c & 0xE0) == 0xC0) {
            extra = 1;
            cp    = c & 0x1Fu;
        } else if ((c & 0xF0) == 0xE0) {
            extra = 2;
            cp    = c & 0x0Fu;
        } else if ((c & 0xF8) == 0xF0) {
            extra = 3;
            cp    = c & 0x07u;
        } else {
            return false; /* a continuation byte in lead position, or 0xF8..0xFF */
        }

        for (int i = 0; i < extra; i++) {
            uint8_t cont = p[1 + i];
            if ((cont & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (cont & 0x3Fu);
        }

        /*
         * Overlong forms, surrogates and out-of-range code points are all rejected. A decoder
         * that accepts overlong sequences is the classic way a length or content check gets
         * bypassed, and a lone surrogate written to flash is invalid text for ever after.
         */
        if (extra == 1 && cp < 0x80) return false;
        if (extra == 2 && cp < 0x800) return false;
        if (extra == 3 && cp < 0x10000) return false;
        if (cp > 0x10FFFF) return false;
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;

        p += 1 + extra;
    }
    return true;
}

/* ── Tokeniser (usbcfg.md §2) ────────────────────────────────────────────── */

rw_uerr_t rw_cmdline_parse(const char *line, rw_cmdline_t *out) {
    out->argc = 0;

    size_t len = strlen(line);
    if (len + 1 > RW_USBCFG_MAX_LINE) {
        return RW_UERR_TOO_LONG;
    }
    if (!rw_utf8_valid(line)) {
        return RW_UERR_BAD_FRAME;
    }

    /*
     * Read from `line`, write unescaped tokens into `storage`. The write cursor can never
     * overtake the read cursor — every input byte yields at most one output byte, and each
     * separating space is replaced by exactly one NUL — so the two buffers may safely alias.
     */
    char  *w = out->storage;
    size_t i = 0;

    while (i < len) {
        while (i < len && line[i] == ' ') {
            i++;
        }
        if (i >= len) {
            break;
        }

        if (out->argc >= RW_USBCFG_MAX_ARGS) {
            return RW_UERR_BAD_ARGS;
        }
        out->argv[out->argc++] = w;

        if (line[i] == '"') {
            i++; /* opening quote */
            bool closed = false;
            while (i < len) {
                char c = line[i];
                if (c == '\\') {
                    if (i + 1 >= len) {
                        return RW_UERR_BAD_FRAME; /* trailing backslash */
                    }
                    char next = line[i + 1];
                    if (next != '"' && next != '\\') {
                        /* §2 names exactly two escapes. Anything else is a mistake worth
                         * surfacing rather than a literal backslash worth guessing at. */
                        return RW_UERR_BAD_FRAME;
                    }
                    *w++ = next;
                    i += 2;
                    continue;
                }
                if (c == '"') {
                    i++;
                    closed = true;
                    break;
                }
                *w++ = c;
                i++;
            }
            if (!closed) {
                return RW_UERR_BAD_FRAME; /* unterminated quote */
            }
            /* `"ab"cd` is ambiguous, so it is refused rather than resolved. */
            if (i < len && line[i] != ' ') {
                return RW_UERR_BAD_FRAME;
            }
        } else {
            while (i < len && line[i] != ' ') {
                char c = line[i];
                if (c == '"' || c == '\\') {
                    /* §2: these must be quoted. Accepting them bare would make
                     * `SET_WIFI my"net` mean something different from the quoted form. */
                    return RW_UERR_BAD_FRAME;
                }
                *w++ = c;
                i++;
            }
        }

        *w++ = '\0';
    }

    return RW_UERR_NONE;
}

/* ── Staging ─────────────────────────────────────────────────────────────── */

void rw_stage_init(rw_stage_t *stage, const rw_config_t *base) {
    stage->cfg   = *base;
    stage->dirty = false;
}

/* Copy with a byte budget that counts the NUL. Returns false if `src` does not fit, which is a
 * rejection rather than a truncation: field limits are in bytes and cutting UTF-8 at a byte
 * boundary produces text that is invalid for the rest of the device's life. */
static bool copy_field(char *dst, size_t dst_len, const char *src) {
    size_t n = strlen(src);
    if (n + 1 > dst_len) {
        return false;
    }
    memcpy(dst, src, n + 1);
    return true;
}

rw_uerr_t rw_stage_set_wifi(rw_stage_t *stage, const char *ssid, const char *psk) {
    if (ssid == NULL || ssid[0] == '\0') {
        return RW_UERR_BAD_ARG;
    }
    if (!copy_field(stage->cfg.ssid, RW_CFG_SSID_LEN, ssid)) {
        return RW_UERR_BAD_ARG;
    }

    if (psk == NULL || psk[0] == '\0') {
        stage->cfg.psk[0]   = '\0';
        stage->cfg.wifi_auth = RW_WIFI_AUTH_OPEN;
    } else {
        if (!copy_field(stage->cfg.psk, RW_CFG_PSK_LEN, psk)) {
            return RW_UERR_BAD_ARG;
        }
        /*
         * AUTO rather than WPA2. The command carries no auth argument, and a router in WPA2/WPA3
         * transition mode is now the common case — pinning WPA2 there produces a device that
         * associates today and stops when the owner turns off the legacy mode.
         */
        stage->cfg.wifi_auth = RW_WIFI_AUTH_AUTO;
    }

    stage->dirty = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_set_relay(rw_stage_t *stage, const char *url) {
    if (url == NULL || url[0] == '\0') {
        return RW_UERR_BAD_ARG;
    }

    rw_url_t parsed;
    if (!rw_url_parse(url, &parsed)) {
        return RW_UERR_BAD_ARG;
    }
    if (!parsed.tls && !rw_url_plaintext_permitted(parsed.host)) {
        /* usbcfg.md §4: ws:// to a public host would send the device's challenge-response in
         * the clear, so it is refused where it is configured, not where it is dialled. */
        return RW_UERR_BAD_ARG;
    }
    if (!copy_field(stage->cfg.relay_url, RW_CFG_RELAY_URL_LEN, url)) {
        return RW_UERR_BAD_ARG;
    }

    stage->dirty = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_add_target(rw_stage_t *stage, const char *name, const char *mac) {
    if (name == NULL || name[0] == '\0' || mac == NULL) {
        return RW_UERR_BAD_ARG;
    }
    if (stage->cfg.target_count >= RW_CFG_MAX_TARGETS) {
        return RW_UERR_TOO_MANY;
    }

    rw_target_t entry;
    memset(&entry, 0, sizeof(entry));
    if (!copy_field(entry.name, RW_CFG_TARGET_NAME_LEN, name)) {
        return RW_UERR_BAD_ARG;
    }
    if (!rw_mac_parse(mac, entry.mac)) {
        return RW_UERR_BAD_ARG;
    }
    /* Refuse addresses no adapter can have. A wake to a multicast or broadcast address leaves
     * the device reporting a perfectly successful send while nothing ever powers on, which is
     * the least debuggable outcome available. */
    if (!rw_mac_wakeable(entry.mac)) {
        return RW_UERR_BAD_ARG;
    }

    stage->cfg.targets[stage->cfg.target_count++] = entry;
    stage->dirty                                  = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_clear_targets(rw_stage_t *stage) {
    memset(stage->cfg.targets, 0, sizeof(stage->cfg.targets));
    stage->cfg.target_count = 0;
    stage->dirty            = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_set_email(rw_stage_t *stage, const char *email) {
    if (email == NULL) {
        return RW_UERR_BAD_ARG;
    }
    if (!rw_utf8_valid(email)) {
        return RW_UERR_BAD_FRAME;
    }

    /*
     * Shape only: something before an `@`, exactly one `@`, and a dot inside the domain with
     * something after it. Deliberately not an RFC 5321 parse — the device cannot tell a
     * deliverable address from a merely well-formed one, the relay revalidates, and the real
     * check is whether anybody answers the invitation.
     *
     * What this does catch is the mistake worth catching at this end: an SSID or a MAC typed
     * into the wrong box. That would otherwise be written to flash and offered to the relay on
     * every connection until somebody factory-resets the device to correct it.
     */
    const char *at = strchr(email, '@');
    if (at == NULL || at == email || strchr(at + 1, '@') != NULL) {
        return RW_UERR_BAD_ARG;
    }
    const char *dot = strchr(at + 1, '.');
    if (dot == NULL || dot == at + 1 || dot[1] == '\0') {
        return RW_UERR_BAD_ARG;
    }

    if (!copy_field(stage->cfg.owner_email, RW_CFG_OWNER_EMAIL_LEN, email)) {
        return RW_UERR_BAD_ARG;
    }
    stage->dirty = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_set_token(rw_stage_t *stage, const char *token) {
    if (token == NULL) {
        return RW_UERR_BAD_ARG;
    }

    /* Exactly 64, not "at most": a short token is not a weaker token, it is a token that will
     * fail every handshake, and the failure surfaces minutes later at the relay as an auth
     * refusal with nothing to connect it back to a typo here. */
    size_t len = strlen(token);
    if (len != RW_CFG_TOKEN_LEN - 1) {
        return RW_UERR_BAD_ARG;
    }

    char normalised[RW_CFG_TOKEN_LEN];
    for (size_t i = 0; i < len; i++) {
        char c = token[i];
        if (c >= '0' && c <= '9') {
            normalised[i] = c;
        } else if (c >= 'a' && c <= 'f') {
            normalised[i] = c;
        } else if (c >= 'A' && c <= 'F') {
            normalised[i] = (char)(c - 'A' + 'a');
        } else {
            return RW_UERR_BAD_ARG;
        }
    }
    normalised[len] = '\0';

    memcpy(stage->cfg.token, normalised, RW_CFG_TOKEN_LEN);
    stage->dirty = true;
    return RW_UERR_NONE;
}

rw_uerr_t rw_stage_validate(const rw_stage_t *stage) {
    if (!stage->dirty) {
        return RW_UERR_NOTHING_STAGED;
    }
    if (stage->cfg.ssid[0] == '\0') {
        /*
         * Committing without an SSID would write a record that boots straight back into setup
         * mode, which to the person doing it is indistinguishable from the commit having failed
         * silently. Refusing here turns that into one clear sentence.
         */
        return RW_UERR_BAD_ARG;
    }
    if (stage->cfg.target_count > RW_CFG_MAX_TARGETS) {
        return RW_UERR_TOO_MANY;
    }
    return RW_UERR_NONE;
}

/* ── Response encoders ───────────────────────────────────────────────────── */

static const char *auth_name(uint8_t wifi_auth) {
    switch (wifi_auth) {
        case RW_WIFI_AUTH_OPEN: return "open";
        case RW_WIFI_AUTH_WPA2: return "wpa2";
        case RW_WIFI_AUTH_WPA3: return "wpa3";
        default:                return "auto";
    }
}

size_t rw_usbcfg_info_json(const rw_info_view_t *view, char *buf, size_t cap) {
    rw_jw_t w;
    rw_jw_init(&w, buf, cap);

    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "proto");
    rw_jw_int(&w, RW_USBCFG_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "fw");
    rw_jw_str(&w, RW_FW_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "board");
    rw_jw_str(&w, RW_BOARD_NAME);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "device_id");
    rw_jw_str(&w, view->device_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "mac");
    rw_jw_str(&w, view->mac);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "configured");
    rw_jw_raw(&w, view->configured ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "uptime_s");
    rw_jw_int(&w, (long)view->uptime_s);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "reset_reason");
    rw_jw_str(&w, view->reset_reason);
    rw_jw_raw(&w, "}");

    return rw_jw_finish(&w);
}

size_t rw_usbcfg_config_json(const rw_config_t *cfg, char *buf, size_t cap) {
    rw_jw_t w;
    rw_jw_init(&w, buf, cap);

    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "ssid");
    rw_jw_str(&w, cfg->ssid);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "auth");
    rw_jw_str(&w, auth_name(cfg->wifi_auth));
    rw_jw_raw(&w, ",");

    /* The two booleans that replace the secrets. There is no code path in this file, or any
     * other, that puts cfg->psk or cfg->token into a usbcfg response. */
    rw_jw_key(&w, "psk_set");
    rw_jw_raw(&w, cfg->psk[0] ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "relay");
    rw_jw_str(&w, cfg->relay_url[0] ? cfg->relay_url : RW_DEFAULT_RELAY_URL);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "device_id");
    rw_jw_str(&w, cfg->device_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "token_set");
    rw_jw_raw(&w, cfg->token[0] ? "true" : "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "email_set");
    rw_jw_raw(&w, cfg->owner_email[0] ? "true" : "false");
    rw_jw_raw(&w, ",");

    rw_jw_key(&w, "targets");
    rw_jw_raw(&w, "[");
    for (uint8_t i = 0; i < cfg->target_count && i < RW_CFG_MAX_TARGETS; i++) {
        if (i > 0) {
            rw_jw_raw(&w, ",");
        }
        char mac[18];
        rw_mac_format(cfg->targets[i].mac, mac);
        rw_jw_raw(&w, "{");
        rw_jw_key(&w, "name");
        rw_jw_str(&w, cfg->targets[i].name);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "mac");
        rw_jw_str(&w, mac);
        rw_jw_raw(&w, "}");
    }
    rw_jw_raw(&w, "],");

    rw_jw_key(&w, "flags");
    rw_jw_int(&w, (long)cfg->flags);
    rw_jw_raw(&w, "}");

    return rw_jw_finish(&w);
}
