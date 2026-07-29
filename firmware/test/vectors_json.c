/*
 * Reading the golden vector file. See vectors_json.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "vectors_json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The committed vector file is around 14 KB with five cases; 8192 tokens is several times what
 * it needs and costs 128 KB of host memory for the duration of one test run. */
#define MAX_TOKENS 8192

bool rw_doc_load(rw_doc_t *doc, const char *path) {
    memset(doc, 0, sizeof(*doc));

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return false;
    }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0) {
        fclose(f);
        fprintf(stderr, "%s is empty\n", path);
        return false;
    }

    doc->text = (char *)malloc((size_t)size + 1);
    if (doc->text == NULL) {
        fclose(f);
        return false;
    }
    /* Opened in binary mode on purpose: the file is UTF-8 and one of the vectors carries
     * multi-byte names whose whole point is that they survive unmodified. */
    size_t got = fread(doc->text, 1, (size_t)size, f);
    fclose(f);
    doc->text[got] = '\0';
    doc->len       = got;

    doc->tokens = (jsmntok_t *)malloc(sizeof(jsmntok_t) * MAX_TOKENS);
    if (doc->tokens == NULL) {
        free(doc->text);
        doc->text = NULL;
        return false;
    }

    jsmn_parser parser;
    jsmn_init(&parser);
    doc->count = jsmn_parse(&parser, doc->text, doc->len, doc->tokens, MAX_TOKENS);
    if (doc->count < 1) {
        fprintf(stderr, "%s did not parse as JSON (jsmn returned %d)\n", path, doc->count);
        rw_doc_free(doc);
        return false;
    }
    return true;
}

void rw_doc_free(rw_doc_t *doc) {
    free(doc->text);
    free(doc->tokens);
    memset(doc, 0, sizeof(*doc));
}

int rw_doc_member(const rw_doc_t *doc, int obj, const char *key) {
    if (obj < 0 || obj >= doc->count || doc->tokens[obj].type != JSMN_OBJECT) {
        return -1;
    }
    int i = obj + 1;
    for (int n = 0; n < doc->tokens[obj].size && i < doc->count; n++) {
        int value = i + 1;
        if (value >= doc->count) {
            return -1;
        }
        if (rw_json_eq(doc->text, &doc->tokens[i], key)) {
            return value;
        }
        i = rw_json_skip(doc->tokens, doc->count, value);
    }
    return -1;
}

int rw_doc_elem(const rw_doc_t *doc, int arr, int index) {
    if (arr < 0 || arr >= doc->count || doc->tokens[arr].type != JSMN_ARRAY) {
        return -1;
    }
    if (index < 0 || index >= doc->tokens[arr].size) {
        return -1;
    }
    int i = arr + 1;
    for (int n = 0; n < index; n++) {
        i = rw_json_skip(doc->tokens, doc->count, i);
    }
    return i;
}

bool rw_doc_str(const rw_doc_t *doc, int obj, const char *key, char *out, size_t out_len) {
    int idx = rw_doc_member(doc, obj, key);
    if (idx < 0) {
        if (out_len > 0) {
            out[0] = '\0';
        }
        return false;
    }
    return rw_json_str(doc->text, &doc->tokens[idx], out, out_len);
}

uint32_t rw_doc_u32(const rw_doc_t *doc, int obj, const char *key, uint32_t def) {
    int idx = rw_doc_member(doc, obj, key);
    if (idx < 0 || doc->tokens[idx].type != JSMN_PRIMITIVE) {
        return def;
    }
    /* Parsed here rather than through rw_json_int, which tops out at INT32_MAX by design.
     * `seq` is a uint32 and one of the vectors carries 0xFFFFFFFF precisely to pin the
     * wrap-safe comparison. */
    const char *p   = doc->text + doc->tokens[idx].start;
    const char *end = doc->text + doc->tokens[idx].end;
    uint64_t    v   = 0;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') {
            return def;
        }
        v = v * 10 + (uint64_t)(*p - '0');
        if (v > 0xFFFFFFFFull) {
            return def;
        }
    }
    return (uint32_t)v;
}

size_t rw_doc_hex(const rw_doc_t *doc, int tok, uint8_t *out, size_t out_len) {
    if (tok < 0 || doc->tokens[tok].type != JSMN_STRING) {
        return 0;
    }
    const char *p    = doc->text + doc->tokens[tok].start;
    size_t      len  = (size_t)(doc->tokens[tok].end - doc->tokens[tok].start);
    if ((len & 1) != 0 || len / 2 > out_len) {
        return 0;
    }
    for (size_t i = 0; i < len / 2; i++) {
        int hi = -1, lo = -1;
        char a = p[i * 2], b = p[i * 2 + 1];
        if (a >= '0' && a <= '9') hi = a - '0';
        else if (a >= 'a' && a <= 'f') hi = a - 'a' + 10;
        else if (a >= 'A' && a <= 'F') hi = a - 'A' + 10;
        if (b >= '0' && b <= '9') lo = b - '0';
        else if (b >= 'a' && b <= 'f') lo = b - 'a' + 10;
        else if (b >= 'A' && b <= 'F') lo = b - 'A' + 10;
        if (hi < 0 || lo < 0) {
            return 0;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return len / 2;
}
