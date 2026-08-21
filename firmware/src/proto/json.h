/*
 * Bounded JSON writing and jsmn-based reading.
 *
 * Host-portable and allocation-free. Split out of proto.c so the encoders can be exercised
 * without a network stack, and because "does this frame fit the 2048-byte limit" is a question
 * with one answer that belongs in one place.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_JSON_H
#define RW_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Declarations only here; vendor/jsmn.c is the single translation unit that instantiates the
 * implementation. jsmn is a header with the body inline by default, and including it from more
 * than one place without this would be a link error waiting for the second caller. */
#define JSMN_HEADER
#include "vendor/jsmn.h"

/*
 * A writer that never overflows and never lies about it.
 *
 * Every append checks the remaining space and, on overflow, sets `ok` false and stops writing.
 * Callers check `ok` once at the end rather than after each field: a half-written frame is
 * discarded whole, so there is no state to unwind.
 */
typedef struct {
    char  *buf;
    size_t cap;
    size_t len;
    bool   ok;
} rw_jw_t;

void rw_jw_init(rw_jw_t *w, char *buf, size_t cap);

/* Raw JSON text: punctuation, numbers, literals. Not escaped. */
void rw_jw_raw(rw_jw_t *w, const char *text);

/* A quoted, escaped JSON string. Handles the two-character escapes, control characters as
 * \u00XX, and passes UTF-8 through unchanged — target names are UTF-8 by contract. */
void rw_jw_str(rw_jw_t *w, const char *s);

/* `"key":` */
void rw_jw_key(rw_jw_t *w, const char *key);

void rw_jw_int(rw_jw_t *w, long value);

/*
 * A fixed-point value held as thousandths, written as a plain JSON number: 8900 → `8.9`,
 * 1005 → `1.005`, -500 → `-0.5`, 2000 → `2`.
 *
 * This exists because the firmware carries no floating point across the wire boundary: a
 * metering read is parsed into thousandths and emitted from thousandths, so what goes out is
 * exactly what came in, never a float that has been through printf's rounding.
 */
void rw_jw_milli(rw_jw_t *w, long milli);

/* Finish: NUL-terminates and returns the length, or 0 if anything overflowed. */
size_t rw_jw_finish(rw_jw_t *w);

/* ── Reading ──────────────────────────────────────────────────────────────── */

/*
 * Index of the value token for a top-level key of the object at token 0, or -1.
 *
 * Only top-level keys, deliberately: every frame a device parses is a flat object of scalars.
 */
int rw_json_find(const char *js, const jsmntok_t *tokens, int count, const char *key);

/*
 * Copy a string token into `out`, resolving escapes including \uXXXX surrogate pairs.
 *
 * Returns false if the token is not a string, if it does not fit, or if the escapes are
 * malformed. Unpaired surrogates are rejected rather than emitted as invalid UTF-8: this text
 * ends up in flash and then back on the wire, and one bad sequence there is permanent.
 */
bool rw_json_str(const char *js, const jsmntok_t *tok, char *out, size_t out_len);

/* Parse a primitive token as a long. Returns false for anything that is not a number. */
bool rw_json_int(const char *js, const jsmntok_t *tok, long *out);

/* True when the primitive token is the literal `true`. */
bool rw_json_is_true(const char *js, const jsmntok_t *tok);

/* Compare a string token against a NUL-terminated literal, without unescaping. Used for `t`
 * and for error codes, which are all bare ASCII identifiers. */
bool rw_json_eq(const char *js, const jsmntok_t *tok, const char *literal);

/* Index of the token after the subtree rooted at `index`. */
int rw_json_skip(const jsmntok_t *tokens, int count, int index);

#endif /* RW_JSON_H */
