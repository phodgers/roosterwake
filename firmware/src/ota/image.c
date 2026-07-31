/*
 * Signed firmware image parsing and verification. See image.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ota/image.h"

#include <string.h>

#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"

#include "ota/signing_key.h"

/* Field offsets, from the layout in image.h. */
#define OFF_MAGIC    0
#define OFF_FORMAT   4
#define OFF_FLAGS    6
#define OFF_LENGTH   8
#define OFF_VERSION  12
#define OFF_BOARD    28
#define OFF_SHA      32
#define OFF_SIG      64
#define SIGNED_BYTES 64 /* the signature covers bytes 0..63 */

static uint16_t le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/*
 * Copy a NUL-padded fixed-width field out as a C string.
 *
 * Returns false unless every byte up to the first NUL is printable ASCII and at least one is
 * present. These strings are logged, sent to the relay and shown in a dashboard, so a field
 * carrying control characters or unterminated junk is refused at the point of entry.
 */
static bool field_str(const uint8_t *raw, size_t width, char *out, size_t out_len) {
    if (width + 1 > out_len) {
        return false;
    }
    size_t n = 0;
    while (n < width && raw[n] != '\0') {
        if (raw[n] < 0x20 || raw[n] > 0x7E) {
            return false;
        }
        n++;
    }
    if (n == 0) {
        return false;
    }
    /* Everything after the first NUL must also be NUL: trailing bytes are padding, and anything
     * hidden there would be signed but invisible to every reader. */
    for (size_t i = n; i < width; i++) {
        if (raw[i] != '\0') {
            return false;
        }
    }
    memcpy(out, raw, n);
    out[n] = '\0';
    return true;
}

static rw_ota_status_t verify_signature(const uint8_t *raw) {
    uint8_t digest[RW_OTA_SHA_LEN];
    if (mbedtls_sha256(raw, SIGNED_BYTES, digest, 0) != 0) {
        return RW_OTA_ERR_SIGNATURE;
    }

    /* mbedtls_ecp_point_read_binary wants the uncompressed-point prefix, which the stored key
     * omits because it is constant. */
    uint8_t point[1 + RW_OTA_PUBKEY_LEN];
    point[0] = 0x04;
    memcpy(point + 1, rw_ota_public_key, RW_OTA_PUBKEY_LEN);

    mbedtls_ecp_group grp;
    mbedtls_ecp_point q;
    mbedtls_mpi       r;
    mbedtls_mpi       s;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&q);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    rw_ota_status_t status = RW_OTA_ERR_SIGNATURE;
    if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
        mbedtls_ecp_point_read_binary(&grp, &q, point, sizeof(point)) == 0 &&
        mbedtls_mpi_read_binary(&r, raw + OFF_SIG, 32) == 0 &&
        mbedtls_mpi_read_binary(&s, raw + OFF_SIG + 32, 32) == 0 &&
        mbedtls_ecdsa_verify(&grp, digest, sizeof(digest), &q, &r, &s) == 0) {
        status = RW_OTA_OK;
    }

    mbedtls_mpi_free(&s);
    mbedtls_mpi_free(&r);
    mbedtls_ecp_point_free(&q);
    mbedtls_ecp_group_free(&grp);
    return status;
}

rw_ota_status_t rw_ota_header_open(const uint8_t *raw, size_t len, const char *board,
                                   uint32_t max_payload, rw_ota_header_t *out) {
    if (raw == NULL || out == NULL || board == NULL) {
        return RW_OTA_ERR_SHORT;
    }
    if (len < RW_OTA_HEADER_LEN) {
        return RW_OTA_ERR_SHORT;
    }
    if (memcmp(raw + OFF_MAGIC, RW_OTA_MAGIC, 4) != 0) {
        return RW_OTA_ERR_MAGIC;
    }

    memset(out, 0, sizeof(*out));
    out->format = le16(raw + OFF_FORMAT);
    if (out->format != RW_OTA_FORMAT_VERSION) {
        return RW_OTA_ERR_FORMAT;
    }

    out->flags = le16(raw + OFF_FLAGS);
    if (out->flags != 0) {
        return RW_OTA_ERR_FLAGS;
    }

    out->payload_len = le32(raw + OFF_LENGTH);
    if (out->payload_len == 0 || out->payload_len > max_payload) {
        return RW_OTA_ERR_LENGTH;
    }

    if (!field_str(raw + OFF_VERSION, 16, out->version, sizeof(out->version))) {
        return RW_OTA_ERR_VERSION;
    }
    if (!field_str(raw + OFF_BOARD, 4, out->board, sizeof(out->board))) {
        return RW_OTA_ERR_BOARD;
    }
    if (strcmp(out->board, board) != 0) {
        return RW_OTA_ERR_BOARD;
    }

    memcpy(out->payload_sha256, raw + OFF_SHA, RW_OTA_SHA_LEN);

    /*
     * Signature last, because it is the only expensive check here: an ECDSA verify on a
     * Cortex-M0+ costs tens of milliseconds, and there is no reason to spend that on an image
     * already known to be for the wrong board.
     */
    return verify_signature(raw);
}

void rw_ota_digest_init(rw_ota_digest_t *d) {
    mbedtls_sha256_init(&d->sha);
    mbedtls_sha256_starts(&d->sha, 0);
    d->seen = 0;
}

void rw_ota_digest_update(rw_ota_digest_t *d, const uint8_t *data, size_t len) {
    mbedtls_sha256_update(&d->sha, data, len);
    d->seen += (uint32_t)len;
}

rw_ota_status_t rw_ota_digest_finish(rw_ota_digest_t *d, const rw_ota_header_t *header) {
    uint8_t got[RW_OTA_SHA_LEN];
    int     rc = mbedtls_sha256_finish(&d->sha, got);
    mbedtls_sha256_free(&d->sha);
    if (rc != 0) {
        return RW_OTA_ERR_DIGEST;
    }
    if (d->seen != header->payload_len) {
        return RW_OTA_ERR_LENGTH;
    }
    /* Not constant-time on purpose: this compares a hash of public data against a signed value,
     * so there is no secret here to leak through timing. */
    if (memcmp(got, header->payload_sha256, RW_OTA_SHA_LEN) != 0) {
        return RW_OTA_ERR_DIGEST;
    }
    return RW_OTA_OK;
}

const char *rw_ota_status_str(rw_ota_status_t status) {
    switch (status) {
        case RW_OTA_OK:            return "ok";
        case RW_OTA_ERR_SHORT:     return "short";
        case RW_OTA_ERR_MAGIC:     return "magic";
        case RW_OTA_ERR_FORMAT:    return "format";
        case RW_OTA_ERR_FLAGS:     return "flags";
        case RW_OTA_ERR_LENGTH:    return "length";
        case RW_OTA_ERR_BOARD:     return "board";
        case RW_OTA_ERR_VERSION:   return "version";
        case RW_OTA_ERR_SIGNATURE: return "signature";
        case RW_OTA_ERR_DIGEST:    return "digest";
    }
    return "internal";
}

const char *rw_ota_board_tag(void) {
#if defined(PICO_RP2350) && PICO_RP2350
    return "P2W";
#else
    return "PW";
#endif
}
