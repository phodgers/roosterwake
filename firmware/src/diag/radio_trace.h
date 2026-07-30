/*
 * What the radio actually said.
 *
 * ── WHY THIS EXISTS ──────────────────────────────────────────────────────────
 *
 * `cyw43_tcpip_link_status()` collapses every association failure into three numbers: BADAUTH,
 * NONET and FAIL. FAIL is the interesting one and it is nearly contentless — it means "the
 * association was refused" and nothing about by whom or for what. A router refusing on a MAC
 * filter, a router with no free client slot, a cipher mismatch and a channel the regulatory
 * domain forbids are one value. Diagnosing from that value alone means guessing, and guessing
 * costs a firmware build and a trip to the desk per hypothesis.
 *
 * The radio does say why. The CYW43439 raises a WLC event for each step of a join — SET_SSID,
 * AUTH, ASSOC, LINK, PSK_SUP, PRUNE — each carrying a status and a reason code, and the driver
 * already knows how to print them. It just prints them into `printf` and only when
 * `cyw43_state.trace_flags` asks. Two things stand between that and a support conversation: the
 * output is gone by the time anybody plugs a cable in, and it is unframed text in the middle of
 * a line-oriented command channel.
 *
 * So this claims CYW43_PRINTF, reassembles the driver's piecewise writes into whole lines, and
 * keeps the last few in a ring the host can read back with `WIFI_TRACE`. Nothing is sampled and
 * nothing is inferred: the ring holds what the radio reported, in order, with timestamps.
 *
 * ── WHY A FORCE-INCLUDED HEADER ──────────────────────────────────────────────
 *
 * `cyw43_cb_process_async_event()` — the function that would be the natural hook — is compiled
 * into the driver's own translation unit alongside symbols the link needs, so defining our own
 * is a duplicate-symbol error rather than an override. CYW43_PRINTF is the only seam the driver
 * offers, and it is claimed by whoever defines it before `cyw43_config.h` is reached. A header
 * passed to every C translation unit with `-include` is the one way to be first. See the
 * `-include` block in CMakeLists.txt.
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
