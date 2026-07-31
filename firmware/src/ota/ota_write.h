/*
 * Writing an image into the spare slot as it arrives.
 *
 * The device has around 100 KB of heap and the image is half a megabyte, so nothing is buffered:
 * bytes go from the socket into flash, and the digest is computed on the way past. The signature
 * has already been checked against the header by the time this starts, and the header commits to
 * the payload by hash, so a stream that finishes with the right digest is the image that was
 * signed.
 *
 * ── WHY THE ERASE IS INCREMENTAL ─────────────────────────────────────────────
 *
 * Erasing 704 KB up front would take several seconds with interrupts disabled, which drops the
 * TLS connection the image is arriving over and starves the watchdog. Instead each 4 KB sector is
 * erased immediately before the first page written into it — around 40 ms, once per sector,
 * spread across the transfer.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_OTA_WRITE_H
#define RW_OTA_WRITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ota/image.h"

/*
 * Begin writing `header`'s payload into `slot`.
 *
 * The caller must have validated the header — magic, board, size and signature — with
 * rw_ota_header_open() first. Refuses the running slot, and refuses to start while another
 * transfer is in progress.
 */
rw_ota_status_t rw_ota_write_begin(const rw_ota_header_t *header, uint8_t slot);

/* Add payload bytes, in whatever sizes they arrive in. */
rw_ota_status_t rw_ota_write_chunk(const uint8_t *data, size_t len);

/*
 * Finish: flush the last partial page and check the digest against the header.
 *
 * Returns RW_OTA_OK only when every byte promised arrived and hashed to what was signed. The
 * slot is not staged here — that is a separate decision, so a verified image can be written now
 * and entered later.
 */
rw_ota_status_t rw_ota_write_end(void);

/* Abandon a transfer. The slot is left partly written and therefore unbootable, which is correct:
 * it is not the running one and nothing will point the loader at it. */
void rw_ota_write_abort(void);

/* True while a transfer is in progress. */
bool rw_ota_write_active(void);

/* Bytes accepted so far, for progress reporting. */
uint32_t rw_ota_write_progress(void);

#endif /* RW_OTA_WRITE_H */
