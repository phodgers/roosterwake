/*
 * Writing an image into the spare slot as it arrives.
 *
 * The device has around 100 KB of heap and the image is half a megabyte, so nothing is buffered:
 * bytes go from the socket into flash, and the digest is computed on the way past. The signature
 * has already been checked against the header by the time this starts, and the header commits to
 * the payload by hash, so a stream that finishes with the right digest is the image that was
 * signed.
 *
 * ── WHY THE ERASE HAPPENS UP FRONT ───────────────────────────────────────────
 *
 * `rw_ota_write_begin()` clears the whole region before any payload is asked for, and nothing is
 * erased once bytes are arriving.
 *
 * It was the other way round until 1.10.3 — a 4 KB sector erased immediately before the first
 * page landing in it — on the reasoning that erasing up front would hold interrupts off for
 * seconds and drop the connection. That reasoning was wrong in both halves. Measured on hardware:
 *
 *   - A sector erase is 37.6 ms, and a half-megabyte image needs 129 of them. The device stops
 *     reading for each. Its receive window is 17.5 KB, a sender at line rate overruns that in
 *     40 ms, and the window hits zero; reopening it costs a persist probe that backs off. Same
 *     image, 13 seconds when it went well and 180 when it did not.
 *   - Up front is not seconds of held interrupts either, because it is done in 64 KB steps with
 *     the watchdog fed between: one block erase is 260 ms against an 8 s timer.
 *   - And it is 2.3x faster in total. The bootrom is given a block size and a block-erase
 *     command, so 64 KB in one call is one block erase where sixteen 4 KB calls are sixteen
 *     sector erases: 2.86 s against 6.60 s for 704 KB (`FLASH_BENCH`).
 *
 * Nothing is streaming while it runs: the caller has not sent `ota_accept` yet, and a relay arms
 * no timeout waiting for one.
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
