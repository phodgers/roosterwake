/*
 * A ring of the radio's own WLC events, readable over usbcfg with WIFI_TRACE.
 *
 * `cyw43_tcpip_link_status()` collapses every association failure into BADAUTH, NONET and
 * FAIL. FAIL means only "refused" - a MAC filter, a full client table, a cipher mismatch and
 * a forbidden channel are one value. The radio raises a WLC event per step of a join
 * (SET_SSID, AUTH, ASSOC, LINK, PSK_SUP, PRUNE), each with a status and reason code, and the
 * driver already knows how to print them - but only to printf, and only while
 * `cyw43_state.trace_flags` asks. This captures them so they survive to whenever a cable is
 * attached.
 *
 * CYW43_PRINTF is the only seam available: cyw43_cb_process_async_event() is compiled into
 * the driver's own object beside symbols the link needs, so replacing it is a duplicate
 * symbol rather than an override. Claiming the macro requires being first, hence the
 * force-include in CMakeLists.txt.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_DIAG_RADIO_TRACE_H
#define RW_DIAG_RADIO_TRACE_H

#include <stddef.h>

/*
 * Entries kept, and the bytes each one gets.
 *
 * A join produces four to six events, so this holds the last five or six attempts — long enough
 * to cover the auth ladder in net.c working through every mode it knows, which is the sequence
 * worth reading. Sixty-four bytes fits the driver's longest dump line
 * (`[   12345] ASYNC(0000,SET_SSID,1,0,0)`) with room for the notes net.c interleaves.
 */
#define RW_RADIO_TRACE_LINES 32
#define RW_RADIO_TRACE_LINE  64

/* Entries returned by one WIFI_TRACE response. Twelve of them plus JSON quoting sits inside the
 * channel's 1600-byte response buffer with room to spare; the host pages through the rest. */
#define RW_RADIO_TRACE_PAGE 12

/*
 * The CYW43_PRINTF target. Called by the driver, in fragments, with no newline until the end of
 * a line — so this buffers rather than emitting per call.
 *
 * Fragments longer than an entry are truncated, which loses the tail of a long CYW43_WARN and
 * never the head. The event dumps this exists for are well inside the limit.
 */
void rw_radio_trace_printf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Interleave a line of our own, so the ring reads as a narrative rather than a list of events
 * with no idea which attempt they belong to. Timestamped like the driver's own output. */
void rw_radio_trace_note(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Ask the driver to dump async events. Called once, after cyw43_arch_init(). */
void rw_radio_trace_enable(void);

/* Entries held, oldest first. Never more than RW_RADIO_TRACE_LINES. */
size_t rw_radio_trace_count(void);

/* Entry `i` counting from the oldest, or NULL past the end. The indexing shifts as new events
 * arrive and evict old ones; for a diagnostic read that is acceptable and it is why the response
 * carries the total alongside the page. */
const char *rw_radio_trace_at(size_t i);

/*
 * Claimed before cyw43_config.h can define it as printf. The guard is deliberate: a build that
 * has already chosen its own CYW43_PRINTF keeps it, and this becomes inert rather than a
 * redefinition error.
 */
#ifndef CYW43_PRINTF
#define CYW43_PRINTF(...) rw_radio_trace_printf(__VA_ARGS__)
#endif

#endif /* RW_DIAG_RADIO_TRACE_H */
