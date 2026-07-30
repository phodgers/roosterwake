/*
 * The host-portable half of the USB serial command channel (firmware/docs/usbcfg.md).
 *
 * Tokenising, the error-code set, the command table, the staged configuration and the response
 * encoders all live here and touch no hardware, so the whole protocol surface compiles into the
 * native test binary. usbcfg.c is the thin device half: it moves bytes and performs the actions
 * that need a radio, a flash controller or a reset.
 *
 * The split follows config.c / config_flash.c, and for the same reason. usbcfg.md is a public
 * contract that third-party tools are invited to implement against, so the parts of it that can
 * be pinned by a test are pinned by a test.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_USBCFG_CMDLINE_H
#define RW_USBCFG_CMDLINE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "config/config.h"

/* usbcfg.md §1: 512 bytes including the terminator. */
#define RW_USBCFG_MAX_LINE 512

/*
 * Argument slots, including the command word. The longest command in version 1 is
 * `ADD_TARGET <name> <mac>` at three, so six is headroom rather than a limit anyone meets; a
 * line with more is answered `bad_args` rather than silently truncated.
 */
#define RW_USBCFG_MAX_ARGS 6

/* ── Error codes (usbcfg.md §6) ───────────────────────────────────────────────
 *
 * A closed set for protocol version 1. Adding one is a version bump, which is why this is an
 * enum with a string table rather than free-form text at each call site.
 */
typedef enum {
    RW_UERR_NONE = 0,
    RW_UERR_UNKNOWN_CMD,
    RW_UERR_BAD_ARGS,
    RW_UERR_BAD_ARG,
    RW_UERR_BAD_FRAME,
    RW_UERR_TOO_LONG,
    RW_UERR_TOO_MANY,
    RW_UERR_NOTHING_STAGED,
    RW_UERR_NEEDS_CONFIRM,
    RW_UERR_NOT_JOINED,
    RW_UERR_BUSY,
    RW_UERR_FLASH_ERROR,
    RW_UERR_INTERNAL,
} rw_uerr_t;

/* The wire code, e.g. "bad_arg". Stable; hosts parse this. */
const char *rw_uerr_code(rw_uerr_t err);

/* The human-readable half of `ERR <code> <message>`. Explicitly allowed to change between
 * versions — usbcfg.md §3 tells hosts to parse the code and never the message. */
const char *rw_uerr_message(rw_uerr_t err);

/* ── Commands (usbcfg.md §4) ─────────────────────────────────────────────── */

typedef enum {
    RW_CMD_NONE = 0, /* an empty line: ignored, no response */
    RW_CMD_UNKNOWN,
    RW_CMD_INFO,
    RW_CMD_SCAN,
    RW_CMD_SET_WIFI,
    RW_CMD_SET_RELAY,
    RW_CMD_ADD_TARGET,
    RW_CMD_CLEAR_TARGETS,
    RW_CMD_SET_EMAIL,
    RW_CMD_SET_TOKEN,
    RW_CMD_GET_CONFIG,
    RW_CMD_COMMIT,
    RW_CMD_STATUS,
    RW_CMD_TEST_WAKE,
    RW_CMD_FACTORY_RESET,
    RW_CMD_REBOOT,
    RW_CMD_BOOTSEL,
} rw_cmd_id_t;

/* Case-insensitive lookup. Returns RW_CMD_UNKNOWN for anything not in version 1. */
rw_cmd_id_t rw_cmd_lookup(const char *word);

/* The canonical upper-case spelling, for diagnostics. */
const char *rw_cmd_name(rw_cmd_id_t id);

/* ── Tokenising (usbcfg.md §2) ───────────────────────────────────────────── */

typedef struct {
    int   argc;
    char *argv[RW_USBCFG_MAX_ARGS];
    /* argv points into here. One line in, one buffer; no allocation anywhere in this channel. */
    char  storage[RW_USBCFG_MAX_LINE];
} rw_cmdline_t;

/*
 * Split a line into arguments.
 *
 * `line` is NUL-terminated and must already have had its line ending removed. Returns:
 *
 *   RW_UERR_NONE       success (argc may be 0 for a blank line)
 *   RW_UERR_BAD_FRAME  malformed quoting, a stray backslash, an unquoted `"` or `\`,
 *                      or input that is not valid UTF-8
 *   RW_UERR_TOO_LONG   the line does not fit RW_USBCFG_MAX_LINE
 *   RW_UERR_BAD_ARGS   more than RW_USBCFG_MAX_ARGS tokens
 *
 * Quoting is exactly §2: double quotes, with `\"` and `\\` as the only escapes. A backslash
 * before anything else is an error rather than a literal backslash, because the alternative
 * silently accepts a Windows path someone pasted and stores a mangled SSID.
 */
rw_uerr_t rw_cmdline_parse(const char *line, rw_cmdline_t *out);

/*
 * Whether `s` is well-formed UTF-8.
 *
 * Rejects overlong encodings, surrogates and anything above U+10FFFF, not merely bad lead
 * bytes. These strings are written to flash and then travel to the relay and into a dashboard,
 * so the one place to refuse invalid text is the point of entry.
 */
bool rw_utf8_valid(const char *s);

/* ── Staged configuration (usbcfg.md §4) ─────────────────────────────────────
 *
 * Every SET_* / ADD_TARGET / CLEAR_TARGETS command mutates a working copy and nothing else.
 * COMMIT validates and writes it; anything else discards it at reboot. That is what lets a
 * half-finished provisioning session leave a running device exactly as it was.
 */
typedef struct {
    rw_config_t cfg;
    bool        dirty; /* something has been staged since the last load or commit */
} rw_stage_t;

/* Start from the device's live configuration. */
void rw_stage_init(rw_stage_t *stage, const rw_config_t *base);

/* `psk` may be NULL or empty for an open network, which also sets wifi_auth to open. */
rw_uerr_t rw_stage_set_wifi(rw_stage_t *stage, const char *ssid, const char *psk);

/* Enforces the ws://-only-for-private-addresses policy from usbcfg.md §4 via rw_url_*. */
rw_uerr_t rw_stage_set_relay(rw_stage_t *stage, const char *url);

rw_uerr_t rw_stage_add_target(rw_stage_t *stage, const char *name, const char *mac);
rw_uerr_t rw_stage_clear_targets(rw_stage_t *stage);
/*
 * Stage the account address the device offers with PROTOCOL.md's `adopt` frame.
 *
 * The address names the person, which is the one thing the device cannot learn any other way:
 * the setup access point has no route to the internet, so nothing else in that moment can carry
 * who the owner is.
 *
 * Not a credential and never treated as one. It is a routing hint, erased as soon as the relay
 * acknowledges it.
 */
rw_uerr_t rw_stage_set_email(rw_stage_t *stage, const char *email);

/*
 * Stage a device token chosen by the host: exactly 64 hex digits, stored lower-case.
 *
 * ── WHY A HOST IS ALLOWED TO CHOOSE THE TOKEN ────────────────────────────────
 *
 * A relay can only verify the §3 handshake if it holds the same 32 bytes the device does, and
 * PROTOCOL.md §11 forbids the device from ever transmitting them. So SOMEBODY has to tell the
 * relay, and the device cannot. Without this command the only ways are the config UF2 that
 * tools/mkconfig writes — which already puts a host-chosen token into exactly this field — or
 * reading it off the captive portal and typing it in by hand.
 *
 * This is therefore not a new capability, it is the same capability over a cable: a host that
 * provisions a device end to end (its own relay, or ours) generates the token, registers it, and
 * writes it here. If no token is staged, COMMIT still mints one, so the portal path is unchanged.
 *
 * ── WHAT IT DOES NOT DO ──────────────────────────────────────────────────────
 *
 * It does not make the token readable. usbcfg.md §4's guarantee is about the direction that
 * matters — nothing on this channel ever returns a token, so a dongle plugged into an untrusted
 * machine still cannot have its credentials harvested. Overwriting one requires physical access,
 * and anyone with that can already FACTORY_RESET the device, so no new power is granted.
 *
 * Lower-case because PROTOCOL.md §2 specifies lower-case hex on the wire, and normalising at the
 * point of entry means the relay never has to compare case-insensitively against a secret.
 */
rw_uerr_t rw_stage_set_token(rw_stage_t *stage, const char *token);

/*
 * Final validation before a flash write. Catches the combinations no single command can see —
 * principally a commit with no SSID, which would produce a device that boots into setup mode
 * again and looks to its owner exactly like the commit silently failed.
 */
rw_uerr_t rw_stage_validate(const rw_stage_t *stage);

/* ── Response encoders (usbcfg.md §4) ─────────────────────────────────────────
 *
 * Each writes a single-line JSON object and returns its length, or 0 if it did not fit. The
 * device half owns the `OK `/`ERR ` prefix and the newline.
 */

/* The values INFO reports that only the device can know. */
typedef struct {
    const char *device_id;
    const char *mac;          /* the dongle's own station MAC, canonical form */
    const char *reset_reason;
    uint32_t    uptime_s;
    bool        configured;
} rw_info_view_t;

size_t rw_usbcfg_info_json(const rw_info_view_t *view, char *buf, size_t cap);

/*
 * GET_CONFIG, with the PSK and the token replaced by booleans.
 *
 * usbcfg.md §4 makes this absolute: no command on this channel ever returns either secret. A
 * dongle plugged into an untrusted machine to charge must not be a way to read the Wi-Fi
 * password out of it. The captive portal shows the token once because a self-hoster needs it;
 * this channel has no equivalent need and therefore no equivalent hole.
 */
size_t rw_usbcfg_config_json(const rw_config_t *cfg, char *buf, size_t cap);

#endif /* RW_USBCFG_CMDLINE_H */
