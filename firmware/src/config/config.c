/*
 * Flash configuration record codec. See config.h and firmware/docs/config-format.md.
 *
 * SPDX-License-Identifier: MIT
 */
#include "config/config.h"

#include <string.h>

/* ── Little-endian accessors ─────────────────────────────────────────────────
 *
 * The RP2350 and every host we test on are little-endian, so memcpy would work. These exist
 * anyway because a format document that says "little-endian" should be implemented by code
 * that says "little-endian", not by code that happens to agree with its compiler.
 */

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}

/* ── CRC-32/ISO-HDLC ─────────────────────────────────────────────────────────
 *
 * Bitwise rather than table-driven. 580 payload bytes is 4640 shift-and-mask iterations, which
 * is microseconds on a 150 MHz core and happens twice per config write. A 1 KB lookup table
 * would buy nothing measurable and would have to be either generated at runtime or transcribed
 * by hand, and a hand-transcribed table is a defect waiting for a code review nobody does.
 */
uint32_t rw_crc32(const void *data, size_t len) {
    const uint8_t *p   = (const uint8_t *)data;
    uint32_t       crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= p[i];
        for (int bit = 0; bit < 8; bit++) {
            /* Branchless: -(crc & 1) is 0xFFFFFFFF when the low bit is set, 0 otherwise. */
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

bool rw_seq_newer(uint32_t a, uint32_t b) {
    return (int32_t)(a - b) > 0;
}

void rw_config_init(rw_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->version   = RW_CFG_VERSION;
    cfg->wifi_auth = RW_WIFI_AUTH_AUTO;
}

/* ── Fixed-width string fields ───────────────────────────────────────────────
 *
 * Padding is NUL, never 0xFF. The erased-flash value would make the CRC depend on which writer
 * produced the record, and three independent implementations have to agree byte for byte.
 */

static bool put_str(uint8_t *payload, size_t off, size_t width, const char *value) {
    size_t n = strlen(value);
    if (n > width - 1) {
        return false;
    }
    memcpy(payload + off, value, n);
    /* Remainder is already zero: the payload buffer is zero-filled before any field is written. */
    return true;
}

/*
 * Read a NUL-terminated field into a buffer of exactly `width` bytes.
 *
 * config-format.md §2.2 requires readers to stop at the first NUL and to make no assumption
 * about bytes after it. A record whose field is `width` bytes of non-NUL text is malformed —
 * no conforming writer can produce one, because the width includes the terminator. We copy
 * width-1 bytes and terminate rather than reject the whole record, so one corrupt string does
 * not cost the user their Wi-Fi credentials; re-encoding then produces a valid record.
 */
static void get_str(const uint8_t *payload, size_t off, size_t width, char *out) {
    size_t n = 0;
    while (n < width - 1 && payload[off + n] != 0) {
        n++;
    }
    memcpy(out, payload + off, n);
    out[n] = '\0';
}

size_t rw_config_encode(const rw_config_t *cfg, uint8_t *out, size_t out_len) {
    if (out_len < RW_CFG_RECORD_LEN) {
        return 0;
    }
    if (cfg->target_count > RW_CFG_MAX_TARGETS) {
        return 0;
    }

    memset(out, 0, RW_CFG_RECORD_LEN);
    uint8_t *payload = out + RW_CFG_HEADER_LEN;

    if (!put_str(payload, RW_CFG_OFF_SSID, RW_CFG_SSID_LEN, cfg->ssid) ||
        !put_str(payload, RW_CFG_OFF_PSK, RW_CFG_PSK_LEN, cfg->psk) ||
        !put_str(payload, RW_CFG_OFF_RELAY_URL, RW_CFG_RELAY_URL_LEN, cfg->relay_url) ||
        !put_str(payload, RW_CFG_OFF_DEVICE_ID, RW_CFG_DEVICE_ID_LEN, cfg->device_id) ||
        !put_str(payload, RW_CFG_OFF_TOKEN, RW_CFG_TOKEN_LEN, cfg->token) ||
        !put_str(payload, RW_CFG_OFF_CLAIM_CODE, RW_CFG_CLAIM_CODE_LEN, cfg->claim_code)) {
        return 0;
    }

    payload[RW_CFG_OFF_WIFI_AUTH] = cfg->wifi_auth;
    wr32(payload + RW_CFG_OFF_FLAGS, cfg->flags);
    payload[RW_CFG_OFF_TARGET_COUNT] = cfg->target_count;

    for (uint8_t i = 0; i < cfg->target_count; i++) {
        size_t base = RW_CFG_OFF_TARGETS + (size_t)i * RW_CFG_TARGET_ENTRY_LEN;
        if (cfg->targets[i].name[0] == '\0') {
            return 0; /* an empty name round-trips to a target nobody can identify in a UI */
        }
        if (!put_str(payload, base, RW_CFG_TARGET_NAME_LEN, cfg->targets[i].name)) {
            return 0;
        }
        memcpy(payload + base + RW_CFG_TARGET_NAME_LEN, cfg->targets[i].mac, 6);
    }
    /* Entries beyond target_count stay all-zero, as required by config-format.md §2.4. */

    out[0] = RW_CFG_MAGIC0;
    out[1] = RW_CFG_MAGIC1;
    out[2] = RW_CFG_MAGIC2;
    out[3] = RW_CFG_MAGIC3;
    wr16(out + 4, RW_CFG_VERSION);
    wr16(out + 6, 0); /* reserved0 */
    wr32(out + 8, cfg->seq);
    wr32(out + 12, RW_CFG_PAYLOAD_LEN);
    wr32(out + 16, rw_crc32(payload, RW_CFG_PAYLOAD_LEN));
    /* bytes 20..31 reserved1, already zero */

    return RW_CFG_RECORD_LEN;
}

bool rw_config_decode(const uint8_t *record, size_t len, rw_config_t *out) {
    if (record == NULL || len < RW_CFG_HEADER_LEN) {
        return false;
    }
    if (record[0] != RW_CFG_MAGIC0 || record[1] != RW_CFG_MAGIC1 || record[2] != RW_CFG_MAGIC2 ||
        record[3] != RW_CFG_MAGIC3) {
        return false;
    }

    uint16_t version = rd16(record + 4);
    /* §3 step 2: a greater version is refused rather than misparsed, so downgrading firmware
     * falls back to the older slot. v1 is the first layout, so there is nothing below it to
     * migrate forward and any other value is simply not a record this build understands. */
    if (version != RW_CFG_VERSION) {
        return false;
    }

    uint32_t seq         = rd32(record + 8);
    uint32_t payload_len = rd32(record + 12);
    uint32_t stored_crc  = rd32(record + 16);

    if (payload_len != RW_CFG_PAYLOAD_LEN) {
        return false;
    }
    if (len < RW_CFG_HEADER_LEN + (size_t)payload_len) {
        return false;
    }

    const uint8_t *payload = record + RW_CFG_HEADER_LEN;
    if (rw_crc32(payload, payload_len) != stored_crc) {
        return false;
    }

    rw_config_init(out);
    out->version = version;
    out->seq     = seq;

    get_str(payload, RW_CFG_OFF_SSID, RW_CFG_SSID_LEN, out->ssid);
    get_str(payload, RW_CFG_OFF_PSK, RW_CFG_PSK_LEN, out->psk);
    get_str(payload, RW_CFG_OFF_RELAY_URL, RW_CFG_RELAY_URL_LEN, out->relay_url);
    get_str(payload, RW_CFG_OFF_DEVICE_ID, RW_CFG_DEVICE_ID_LEN, out->device_id);
    get_str(payload, RW_CFG_OFF_TOKEN, RW_CFG_TOKEN_LEN, out->token);
    get_str(payload, RW_CFG_OFF_CLAIM_CODE, RW_CFG_CLAIM_CODE_LEN, out->claim_code);

    uint8_t auth = payload[RW_CFG_OFF_WIFI_AUTH];
    /* Anything outside the defined set means auto-detect. The alternative — rejecting the whole
     * record — would turn a single byte of corruption into a factory reset. */
    out->wifi_auth = (auth == RW_WIFI_AUTH_OPEN || auth == RW_WIFI_AUTH_WPA2 ||
                      auth == RW_WIFI_AUTH_WPA3)
                         ? auth
                         : RW_WIFI_AUTH_AUTO;

    /* Unknown flag bits are carried through untouched, so a config written by newer firmware
     * or a newer mkconfig survives a round trip through this build (config-format.md §2.3). */
    out->flags = rd32(payload + RW_CFG_OFF_FLAGS);

    uint8_t count = payload[RW_CFG_OFF_TARGET_COUNT];
    if (count > RW_CFG_MAX_TARGETS) {
        count = RW_CFG_MAX_TARGETS;
    }
    out->target_count = count;
    for (uint8_t i = 0; i < count; i++) {
        size_t base = RW_CFG_OFF_TARGETS + (size_t)i * RW_CFG_TARGET_ENTRY_LEN;
        get_str(payload, base, RW_CFG_TARGET_NAME_LEN, out->targets[i].name);
        memcpy(out->targets[i].mac, payload + base + RW_CFG_TARGET_NAME_LEN, 6);
    }

    return true;
}

int rw_config_select(const uint8_t *a, size_t a_len, const uint8_t *b, size_t b_len,
                     rw_config_t *out) {
    rw_config_t ca, cb;
    bool        ok_a = rw_config_decode(a, a_len, &ca);
    bool        ok_b = rw_config_decode(b, b_len, &cb);

    if (ok_a && ok_b) {
        if (rw_seq_newer(cb.seq, ca.seq)) {
            *out = cb;
            return 2;
        }
        /* Equal sequence numbers should not happen. If they do, slot A wins deterministically:
         * an arbitrary but fixed answer means two devices with the same flash image behave the
         * same way, which matters more here than which of two identical records is chosen. */
        *out = ca;
        return 1;
    }
    if (ok_a) {
        *out = ca;
        return 1;
    }
    if (ok_b) {
        *out = cb;
        return 2;
    }
    rw_config_init(out);
    return 0;
}

/* ── MAC helpers ─────────────────────────────────────────────────────────────
 *
 * Parsing lives here, at the input boundary, because the flash layout stores six raw octets
 * precisely so that no other layer has to think about case or separators.
 */

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool rw_mac_parse(const char *text, uint8_t mac[6]) {
    if (text == NULL) {
        return false;
    }
    int nibbles[12];
    int n = 0;
    for (const char *p = text; *p != '\0'; p++) {
        if (*p == ':' || *p == '-' || *p == '.' || *p == ' ') {
            continue;
        }
        int v = hex_nibble(*p);
        if (v < 0 || n >= 12) {
            return false;
        }
        nibbles[n++] = v;
    }
    if (n != 12) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)((nibbles[i * 2] << 4) | nibbles[i * 2 + 1]);
    }
    return true;
}

void rw_mac_format(const uint8_t mac[6], char *out) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < 6; i++) {
        out[i * 3]     = hex[mac[i] >> 4];
        out[i * 3 + 1] = hex[mac[i] & 0x0f];
        out[i * 3 + 2] = (i == 5) ? '\0' : ':';
    }
}
