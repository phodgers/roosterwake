/*
 * Bounded JSON writing and jsmn-based reading. See json.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "proto/json.h"

#include <stdio.h>
#include <string.h>

void rw_jw_init(rw_jw_t *w, char *buf, size_t cap) {
    w->buf = buf;
    w->cap = cap;
    w->len = 0;
    w->ok  = cap > 0;
    if (w->ok) {
        buf[0] = '\0';
    }
}

static void put(rw_jw_t *w, char c) {
    if (!w->ok) {
        return;
    }
    if (w->len + 1 >= w->cap) { /* +1 leaves room for the terminator */
        w->ok = false;
        return;
    }
    w->buf[w->len++] = c;
}

void rw_jw_raw(rw_jw_t *w, const char *text) {
    for (const char *p = text; *p != '\0'; p++) {
        put(w, *p);
    }
}

void rw_jw_str(rw_jw_t *w, const char *s) {
    put(w, '"');
    for (const unsigned char *p = (const unsigned char *)s; *p != '\0'; p++) {
        switch (*p) {
            case '"':  rw_jw_raw(w, "\\\""); break;
            case '\\': rw_jw_raw(w, "\\\\"); break;
            case '\b': rw_jw_raw(w, "\\b"); break;
            case '\f': rw_jw_raw(w, "\\f"); break;
            case '\n': rw_jw_raw(w, "\\n"); break;
            case '\r': rw_jw_raw(w, "\\r"); break;
            case '\t': rw_jw_raw(w, "\\t"); break;
            default:
                if (*p < 0x20) {
                    char esc[7];
                    snprintf(esc, sizeof(esc), "\\u%04x", *p);
                    rw_jw_raw(w, esc);
                } else {
                    /* Bytes >= 0x80 are passed through. The input is UTF-8 by contract
                     * (PROTOCOL.md §1) and re-encoding it as \u escapes would only make the
                     * frame larger for no reader's benefit. */
                    put(w, (char)*p);
                }
                break;
        }
    }
    put(w, '"');
}

void rw_jw_key(rw_jw_t *w, const char *key) {
    rw_jw_str(w, key);
    put(w, ':');
}

void rw_jw_int(rw_jw_t *w, long value) {
    char text[24];
    snprintf(text, sizeof(text), "%ld", value);
    rw_jw_raw(w, text);
}

void rw_jw_milli(rw_jw_t *w, long milli) {
    /* Sign handled by hand: -500 splits into quotient 0 and remainder 500, and "%ld" of that
     * quotient would print `0.5` for a value that is negative. */
    const bool    neg = milli < 0;
    unsigned long a   = neg ? (unsigned long)-(milli + 1) + 1 : (unsigned long)milli;

    char text[32];
    if (a % 1000 == 0) {
        snprintf(text, sizeof(text), "%s%lu", neg ? "-" : "", a / 1000);
    } else {
        snprintf(text, sizeof(text), "%s%lu.%03lu", neg ? "-" : "", a / 1000, a % 1000);
        /* Trailing zeros carry nothing: 8.900 and 8.9 are the same JSON number, and the frame
         * has a 2048-byte ceiling to respect. */
        size_t end = strlen(text);
        while (text[end - 1] == '0') {
            end--;
        }
        text[end] = '\0';
    }
    rw_jw_raw(w, text);
}

size_t rw_jw_finish(rw_jw_t *w) {
    if (!w->ok) {
        return 0;
    }
    w->buf[w->len] = '\0';
    return w->len;
}

/* ── Reading ──────────────────────────────────────────────────────────────── */

int rw_json_skip(const jsmntok_t *tokens, int count, int index) {
    if (index < 0 || index >= count) {
        return count;
    }
    int end = index + 1;
    /* jsmn does not record subtree sizes directly, but every token carries its byte extent,
     * so "the next token that starts at or after this one ends" is exact and needs no
     * recursion. */
    for (; end < count; end++) {
        if (tokens[end].start >= tokens[index].end) {
            break;
        }
    }
    return end;
}

bool rw_json_eq(const char *js, const jsmntok_t *tok, const char *literal) {
    if (tok->type != JSMN_STRING && tok->type != JSMN_PRIMITIVE) {
        return false;
    }
    size_t len = (size_t)(tok->end - tok->start);
    return len == strlen(literal) && memcmp(js + tok->start, literal, len) == 0;
}

int rw_json_find(const char *js, const jsmntok_t *tokens, int count, const char *key) {
    if (count < 1 || tokens[0].type != JSMN_OBJECT) {
        return -1;
    }
    int i = 1;
    for (int n = 0; n < tokens[0].size && i < count; n++) {
        int value = i + 1;
        if (value >= count) {
            return -1;
        }
        if (rw_json_eq(js, &tokens[i], key)) {
            return value;
        }
        i = rw_json_skip(tokens, count, value);
    }
    return -1;
}

static int hex4(const char *p) {
    int v = 0;
    for (int i = 0; i < 4; i++) {
        int d;
        char c = p[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        v = (v << 4) | d;
    }
    return v;
}

/* Append `cp` as UTF-8. Returns false if it does not fit. */
static bool put_utf8(char *out, size_t out_len, size_t *n, uint32_t cp) {
    char    seq[4];
    size_t  len;
    if (cp < 0x80) {
        seq[0] = (char)cp;
        len    = 1;
    } else if (cp < 0x800) {
        seq[0] = (char)(0xC0 | (cp >> 6));
        seq[1] = (char)(0x80 | (cp & 0x3F));
        len    = 2;
    } else if (cp < 0x10000) {
        seq[0] = (char)(0xE0 | (cp >> 12));
        seq[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        seq[2] = (char)(0x80 | (cp & 0x3F));
        len    = 3;
    } else {
        seq[0] = (char)(0xF0 | (cp >> 18));
        seq[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        seq[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        seq[3] = (char)(0x80 | (cp & 0x3F));
        len    = 4;
    }
    if (*n + len >= out_len) {
        return false;
    }
    memcpy(out + *n, seq, len);
    *n += len;
    return true;
}

bool rw_json_str(const char *js, const jsmntok_t *tok, char *out, size_t out_len) {
    if (tok->type != JSMN_STRING || out_len == 0) {
        return false;
    }

    const char *p   = js + tok->start;
    const char *end = js + tok->end;
    size_t      n   = 0;

    while (p < end) {
        if (*p != '\\') {
            if (n + 1 >= out_len) {
                return false;
            }
            out[n++] = *p++;
            continue;
        }
        if (p + 1 >= end) {
            return false;
        }
        p++;
        char c = *p++;
        char simple;
        switch (c) {
            case '"':  simple = '"'; break;
            case '\\': simple = '\\'; break;
            case '/':  simple = '/'; break;
            case 'b':  simple = '\b'; break;
            case 'f':  simple = '\f'; break;
            case 'n':  simple = '\n'; break;
            case 'r':  simple = '\r'; break;
            case 't':  simple = '\t'; break;
            case 'u': {
                if (p + 4 > end) {
                    return false;
                }
                int hi = hex4(p);
                if (hi < 0) {
                    return false;
                }
                p += 4;
                uint32_t cp = (uint32_t)hi;
                if (hi >= 0xD800 && hi <= 0xDBFF) {
                    /* High surrogate: a low surrogate must follow, or the text is not valid
                     * Unicode and must not be written into flash as if it were. */
                    if (p + 6 > end || p[0] != '\\' || p[1] != 'u') {
                        return false;
                    }
                    int lo = hex4(p + 2);
                    if (lo < 0xDC00 || lo > 0xDFFF) {
                        return false;
                    }
                    p += 6;
                    cp = 0x10000u + (((uint32_t)hi - 0xD800u) << 10) + ((uint32_t)lo - 0xDC00u);
                } else if (hi >= 0xDC00 && hi <= 0xDFFF) {
                    return false; /* lone low surrogate */
                }
                if (!put_utf8(out, out_len, &n, cp)) {
                    return false;
                }
                continue;
            }
            default:
                return false;
        }
        if (n + 1 >= out_len) {
            return false;
        }
        out[n++] = simple;
    }

    out[n] = '\0';
    return true;
}

bool rw_json_int(const char *js, const jsmntok_t *tok, long *out) {
    if (tok->type != JSMN_PRIMITIVE) {
        return false;
    }
    const char *p   = js + tok->start;
    const char *end = js + tok->end;
    bool        neg = false;

    if (p < end && (*p == '-' || *p == '+')) {
        neg = (*p == '-');
        p++;
    }
    if (p >= end) {
        return false;
    }

    /*
     * Accumulated in 64 bits and bounded against the 32-bit range explicitly. `long` is 32-bit
     * on ARM newlib and on Windows, so accumulating in a long and then testing for overflow
     * tests a value that has already wrapped — which reads as correct and is not.
     */
    const uint64_t limit = neg ? 2147483648ull : 2147483647ull;
    uint64_t       value = 0;
    for (; p < end; p++) {
        if (*p < '0' || *p > '9') {
            /* A fractional or exponent form is not an integer. Nothing in PROTOCOL.md sends
             * one, and silently truncating would hide a peer that does. */
            return false;
        }
        value = value * 10 + (uint64_t)(*p - '0');
        if (value > limit) {
            return false;
        }
    }
    *out = neg ? -(long)value : (long)value;
    return true;
}

bool rw_json_is_true(const char *js, const jsmntok_t *tok) {
    return tok->type == JSMN_PRIMITIVE && rw_json_eq(js, tok, "true");
}
