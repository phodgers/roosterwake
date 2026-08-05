/*
 * Reading the golden vector file.
 *
 * The JSON in vectors/config-v2.json is the source of truth for a format three codebases have
 * to agree on, so the C tests parse that file rather than a generated copy of it. A generated
 * copy is one more artefact that can be stale, and staleness in this particular file is
 * exactly the failure the vectors exist to catch.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_VECTORS_JSON_H
#define RW_VECTORS_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "proto/json.h"

typedef struct {
    char      *text;
    size_t     len;
    jsmntok_t *tokens;
    int        count;
} rw_doc_t;

/* Read and tokenise a JSON file. Exits the process on failure: a test run that cannot read its
 * own fixtures has nothing useful to report. */
bool rw_doc_load(rw_doc_t *doc, const char *path);
void rw_doc_free(rw_doc_t *doc);

/* Member of the object at `obj`, or -1. Unlike rw_json_find this works at any depth. */
int rw_doc_member(const rw_doc_t *doc, int obj, const char *key);

/* Element `index` of the array at `arr`, or -1. */
int rw_doc_elem(const rw_doc_t *doc, int arr, int index);

/* Convenience readers. `def` is returned when the member is absent. */
bool     rw_doc_str(const rw_doc_t *doc, int obj, const char *key, char *out, size_t out_len);
uint32_t rw_doc_u32(const rw_doc_t *doc, int obj, const char *key, uint32_t def);

/* Decode a lower-case hex string token into bytes. Returns the byte count, or 0. */
size_t rw_doc_hex(const rw_doc_t *doc, int tok, uint8_t *out, size_t out_len);

#endif /* RW_VECTORS_JSON_H */
