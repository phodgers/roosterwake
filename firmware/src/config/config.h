/*
 * Flash configuration record codec.
 *
 * Implements firmware/docs/config-format.md exactly. The JavaScript twin is
 * tools/mkconfig/lib/config.mjs and the two are held together by the golden vectors in
 * firmware/test/vectors/config-v1.json, which both test suites consume.
 *
 * This translation unit deliberately touches no hardware and no SDK header: it is compiled
 * unchanged into the native host test binary. Everything that knows about flash sectors lives
 * in config_flash.c.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_CONFIG_H
#define RW_CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ── Layout constants (config-format.md §2) ──────────────────────────────── */

#define RW_CFG_MAGIC0 0x52 /* 'R' */
#define RW_CFG_MAGIC1 0x57 /* 'W' */
#define RW_CFG_MAGIC2 0x43 /* 'C' */
#define RW_CFG_MAGIC3 0x46 /* 'F' */

#define RW_CFG_VERSION     1
#define RW_CFG_HEADER_LEN  32
#define RW_CFG_PAYLOAD_LEN 580
#define RW_CFG_RECORD_LEN  (RW_CFG_HEADER_LEN + RW_CFG_PAYLOAD_LEN) /* 612 */
#define RW_CFG_SECTOR_SIZE 4096

#define RW_CFG_MAX_TARGETS      8
#define RW_CFG_TARGET_ENTRY_LEN 31

/* Field widths, including the mandatory NUL terminator. */
#define RW_CFG_SSID_LEN        33
#define RW_CFG_PSK_LEN         65
#define RW_CFG_RELAY_URL_LEN   129
#define RW_CFG_DEVICE_ID_LEN   17
#define RW_CFG_TOKEN_LEN       65
#define RW_CFG_CLAIM_CODE_LEN  17
#define RW_CFG_TARGET_NAME_LEN 25

/* Payload offsets. These never move; new fields are appended (config-format.md §6). */
#define RW_CFG_OFF_SSID         0
#define RW_CFG_OFF_PSK          33
#define RW_CFG_OFF_WIFI_AUTH    98
#define RW_CFG_OFF_RELAY_URL    99
#define RW_CFG_OFF_DEVICE_ID    228
#define RW_CFG_OFF_TOKEN        245
#define RW_CFG_OFF_CLAIM_CODE   310
#define RW_CFG_OFF_FLAGS        327
#define RW_CFG_OFF_TARGET_COUNT 331
#define RW_CFG_OFF_TARGETS      332

/* wifi_auth values (config-format.md §2.2). */
#define RW_WIFI_AUTH_OPEN 0
#define RW_WIFI_AUTH_WPA2 1
#define RW_WIFI_AUTH_WPA3 2
#define RW_WIFI_AUTH_AUTO 255

/* flags bits (config-format.md §2.3). Unknown bits are preserved on read, never rejected. */
#define RW_CFG_FLAG_TLS_INSECURE (1u << 0)
#define RW_CFG_FLAG_DIAG_LOG     (1u << 1)
#define RW_CFG_FLAG_WOL_UNICAST  (1u << 2)

/* Sequence number a generated (mkconfig / dashboard) image carries; see config-format.md §5. */
#define RW_CFG_GENERATED_SEQ 0x40000000u

typedef struct {
    char    name[RW_CFG_TARGET_NAME_LEN]; /* NUL-terminated UTF-8, at most 24 bytes of text */
    uint8_t mac[6];                       /* six raw octets, not the ASCII form */
} rw_target_t;

typedef struct {
    uint16_t    version;
    uint32_t    seq;
    char        ssid[RW_CFG_SSID_LEN];
    char        psk[RW_CFG_PSK_LEN];
    uint8_t     wifi_auth;
    char        relay_url[RW_CFG_RELAY_URL_LEN];
    char        device_id[RW_CFG_DEVICE_ID_LEN];
    char        token[RW_CFG_TOKEN_LEN];
    char        claim_code[RW_CFG_CLAIM_CODE_LEN];
    uint32_t    flags;
    uint8_t     target_count;
    rw_target_t targets[RW_CFG_MAX_TARGETS];
} rw_config_t;

/* CRC-32/ISO-HDLC — zlib/PNG. crc32("123456789") == 0xCBF43926 (config-format.md §4). */
uint32_t rw_crc32(const void *data, size_t len);

/*
 * Wrap-safe sequence comparison. True when `a` is newer than `b`.
 *
 * A plain `a > b` resurrects a stale slot once seq wraps past 2^31. Flash endurance runs out
 * long before that happens, but the correct comparison costs one cast and the wrong one is
 * undebuggable in the field (config-format.md §3).
 */
bool rw_seq_newer(uint32_t a, uint32_t b);

/* Zero a config to the unprovisioned state: no Wi-Fi, no targets, auth auto, seq 0. */
void rw_config_init(rw_config_t *cfg);

/*
 * Encode into a full record. `out_len` must be at least RW_CFG_RECORD_LEN.
 *
 * Returns RW_CFG_RECORD_LEN on success, 0 if any string exceeds its field or target_count
 * exceeds RW_CFG_MAX_TARGETS. Over-long strings are rejected rather than truncated: field
 * limits are in bytes, and truncating UTF-8 at a byte boundary produces an invalid sequence
 * that then travels to the relay and into somebody's dashboard.
 */
size_t rw_config_encode(const rw_config_t *cfg, uint8_t *out, size_t out_len);

/*
 * Decode a record. Returns false for anything that is not a valid v1 record, so callers treat
 * "no config" and "corrupt config" identically, which is what slot selection needs.
 *
 * Applies config-format.md §3 steps 1–4: magic, version, payload_len, CRC.
 */
bool rw_config_decode(const uint8_t *record, size_t len, rw_config_t *out);

/*
 * Slot selection (config-format.md §3 step 5). `a` and `b` are candidate sector images, either
 * of which may be NULL or invalid. Returns 0 if neither is valid, 1 if `a` wins, 2 if `b` wins,
 * and copies the winner into `out`.
 */
int rw_config_select(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                     rw_config_t *out);

/* Parse "AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff" or "aabbccddeeff" into six octets. */
bool rw_mac_parse(const char *text, uint8_t mac[6]);

/*
 * Whether `mac` could plausibly belong to a network adapter that can be woken.
 *
 * Rejects only what is impossible, never what is merely unreachable. A multicast address (low
 * bit of the first octet set) is a group, not an interface, and broadcast and all-zeros are not
 * addresses at all — none of these can ever identify a PC, so accepting them guarantees a wake
 * that silently does nothing.
 *
 * It deliberately does **not** try to establish that the machine exists. The only way to do
 * that is ARP, and a sleeping PC does not answer ARP — which is the entire population this
 * product exists to wake. A liveness check would therefore report "not found" most confidently
 * for exactly the correctly-configured devices, and that is a worse failure than no check.
 */
bool rw_mac_wakeable(const uint8_t mac[6]);

/* Format six octets as the canonical upper-case colon-separated form (PROTOCOL.md §2).
 * `out` must have room for 18 bytes. */
void rw_mac_format(const uint8_t mac[6], char *out);

#endif /* RW_CONFIG_H */
