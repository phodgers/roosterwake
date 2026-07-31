/*
 * Signed firmware image format.
 *
 * An update arrives over the same TLS connection as everything else, so the transport is already
 * authenticated — but the relay is not the author of the firmware, and a relay that is
 * compromised, or an operator running their own, must not be able to put code on a device. The
 * signature is what separates "this came over our connection" from "we built this", and it is
 * checked on the device against a public key compiled into the running image.
 *
 * Deliberately NOT secure boot: nothing here stops a person with the board from holding BOOTSEL
 * and flashing whatever they like. That is a feature — every device stays recoverable with a
 * cable, so a bad update is an inconvenience rather than dead hardware.
 *
 * ── LAYOUT ───────────────────────────────────────────────────────────────────
 *
 *   0   4   magic "RWFW"
 *   4   2   format version, little-endian
 *   6   2   flags, reserved, must be zero
 *   8   4   payload length in bytes, little-endian
 *  12  16   firmware version string, NUL-padded ("1.6.0")
 *  28   4   board tag, NUL-padded ("PW", "P2W")
 *  32  32   SHA-256 of the payload
 *  64  64   ECDSA P-256 signature (r || s, 32 bytes each) over SHA-256 of bytes 0..63
 * 128   -   payload: the raw flash image, exactly `payload length` bytes
 *
 * The signature covers only the header's first 64 bytes, and those commit to the payload through
 * its digest. That is what makes streaming possible: the signature is checked once, up front,
 * against 64 bytes; the payload is then hashed as it is written to flash and compared at the end,
 * so a 500 KB image never has to be buffered anywhere.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_IMAGE_H
#define RW_OTA_IMAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mbedtls/sha256.h"

#define RW_OTA_MAGIC          "RWFW"
#define RW_OTA_FORMAT_VERSION 1
#define RW_OTA_HEADER_LEN     128

#define RW_OTA_VERSION_LEN 17 /* 16 on the wire plus a terminator this side */
#define RW_OTA_BOARD_LEN   5  /* 4 on the wire plus a terminator this side */
#define RW_OTA_SHA_LEN     32
#define RW_OTA_SIG_LEN     64

/* Uncompressed P-256 point without its 0x04 prefix: X || Y. See ota/signing_key.c. */
#define RW_OTA_PUBKEY_LEN 64

typedef enum {
    RW_OTA_OK = 0,
    RW_OTA_ERR_SHORT,     /* fewer than RW_OTA_HEADER_LEN bytes offered */
    RW_OTA_ERR_MAGIC,     /* not a Remote Wake image */
    RW_OTA_ERR_FORMAT,    /* a format version this build does not understand */
    RW_OTA_ERR_FLAGS,     /* reserved bits set */
    RW_OTA_ERR_LENGTH,    /* empty, or larger than the slot it must fit */
    RW_OTA_ERR_BOARD,     /* built for the other chip */
    RW_OTA_ERR_VERSION,   /* version string absent or not printable ASCII */
    RW_OTA_ERR_SIGNATURE, /* not signed by the key this build trusts */
    RW_OTA_ERR_DIGEST,    /* payload does not hash to what the header claims */
} rw_ota_status_t;

typedef struct {
    uint16_t format;
    uint16_t flags;
    uint32_t payload_len;
    char     version[RW_OTA_VERSION_LEN];
    char     board[RW_OTA_BOARD_LEN];
    uint8_t  payload_sha256[RW_OTA_SHA_LEN];
} rw_ota_header_t;

/*
 * Check everything that can be checked before a byte of payload has arrived: the magic, the
 * format, the declared length against the space available, the board, and the signature.
 *
 * `raw` must hold at least RW_OTA_HEADER_LEN bytes. `board` is this build's RW_BOARD_NAME and
 * `max_payload` the usable size of the slot the image is destined for; both are refused here
 * rather than after half a megabyte has been written to flash.
 */
rw_ota_status_t rw_ota_header_open(const uint8_t *raw, size_t len, const char *board,
                                   uint32_t max_payload, rw_ota_header_t *out);

/* Payload digest, computed as the payload streams past on its way into flash. */
typedef struct {
    mbedtls_sha256_context sha;
    uint32_t               seen;
} rw_ota_digest_t;

void rw_ota_digest_init(rw_ota_digest_t *d);
void rw_ota_digest_update(rw_ota_digest_t *d, const uint8_t *data, size_t len);

/*
 * Compare what streamed past with what the header promised. Checks the byte count as well as the
 * hash: a truncated download that happens to be a prefix would otherwise be caught only by the
 * digest, and reporting "wrong length" is a more useful answer than "wrong hash".
 */
rw_ota_status_t rw_ota_digest_finish(rw_ota_digest_t *d, const rw_ota_header_t *header);

/* Stable short string for logs and for the relay's update_result frame. */
const char *rw_ota_status_str(rw_ota_status_t status);

/* The board tag written into images for this build. */
const char *rw_ota_board_tag(void);

#endif /* RW_OTA_IMAGE_H */
