/*
 * The radio event ring. See radio_trace.h for why this exists at all.
 *
 * SPDX-License-Identifier: MIT
 */
#include "diag/radio_trace.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pico/cyw43_arch.h"
#include "pico/time.h"

#include "rw_log.h"

static char     s_ring[RW_RADIO_TRACE_LINES][RW_RADIO_TRACE_LINE];
static uint16_t s_next;  /* the slot the next entry goes into */
static uint16_t s_count; /* entries held, saturating at RW_RADIO_TRACE_LINES */

/* Line under construction. The driver writes one event across four CYW43_PRINTF calls. */
static char   s_partial[RW_RADIO_TRACE_LINE];
static size_t s_partial_len;

static void push(const char *line) {
    if (line[0] == '\0') {
        return;
    }

    /*
     * Scan results are dropped.
     *
     * An escan raises one event per beacon heard, so a single SCAN against a domestic street
     * fills this ring several times over and evicts the join it was meant to explain. The
     * results are not lost — SCAN returns them, parsed, which is a better form of the same
     * information.
     */
    if (strstr(line, "ESCAN_RESULT") != NULL) {
        return;
    }

    snprintf(s_ring[s_next], RW_RADIO_TRACE_LINE, "%s", line);
    s_next = (uint16_t)((s_next + 1) % RW_RADIO_TRACE_LINES);
    if (s_count < RW_RADIO_TRACE_LINES) {
        s_count++;
    }

    /* Also live, when diagnostics are on, so a host watching the cable sees events as they
     * happen rather than only when it thinks to ask. The `# ` prefix is what marks it as a
     * breadcrumb rather than a response (usbcfg.md §1). */
    if (rw_log_enabled()) {
        printf("# radio %s\n", line);
    }
}

void rw_radio_trace_printf(const char *fmt, ...) {
    char    chunk[RW_RADIO_TRACE_LINE];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(chunk, sizeof(chunk), fmt, ap);
    va_end(ap);

    for (const char *p = chunk; *p != '\0'; p++) {
        if (*p == '\n') {
            s_partial[s_partial_len] = '\0';
            push(s_partial);
            s_partial_len = 0;
            continue;
        }
        if (*p == '\r') {
            continue;
        }
        /* Silently stops appending at the limit rather than flushing a fragment: half an event
         * on one line and half on the next reads as two events, which is worse than a truncated
         * one. */
        if (s_partial_len + 1 < sizeof(s_partial)) {
            s_partial[s_partial_len++] = *p;
        }
    }
}

/*
 * What is left of an entry once the timestamp has taken its share.
 *
 * Thirteen bytes: a bracket, up to ten digits of milliseconds — `%8lu` pads short values but
 * does not clip long ones, and a device up for seven weeks reaches ten — a closing bracket and
 * a space. Sizing the body to fit the worst case rather than the usual one is what makes the
 * composition below provably non-truncating, which the compiler checks.
 */
#define NOTE_BODY_MAX (RW_RADIO_TRACE_LINE - 13)

void rw_radio_trace_note(const char *fmt, ...) {
    char    body[NOTE_BODY_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    /* Same column layout as the driver's own dump, so the two interleave into one readable
     * column of timestamps rather than a ragged mixture. */
    char line[RW_RADIO_TRACE_LINE];
    snprintf(line, sizeof(line), "[%8lu] %s",
             (unsigned long)to_ms_since_boot(get_absolute_time()), body);
    push(line);
}

void rw_radio_trace_enable(void) {
    cyw43_state.trace_flags |= CYW43_TRACE_ASYNC_EV;
}

size_t rw_radio_trace_count(void) {
    return s_count;
}

const char *rw_radio_trace_at(size_t i) {
    if (i >= s_count) {
        return NULL;
    }
    /* Until the ring has wrapped, slot 0 is the oldest; afterwards the oldest is whatever the
     * next write is about to overwrite. */
    size_t oldest = (s_count == RW_RADIO_TRACE_LINES) ? s_next : 0;
    return s_ring[(oldest + i) % RW_RADIO_TRACE_LINES];
}
