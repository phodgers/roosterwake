/*
 * Diagnostic logging. See rw_log.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "rw_log.h"

#include <stdarg.h>
#include <stdio.h>

/* Long enough for a joined SSID plus a driver error string; anything longer is truncated
 * rather than allowed to grow the stack frame of whatever was unlucky enough to log it. */
#define RW_LOG_MAX 160

static bool          s_enabled;
static rw_log_sink_t s_sink;

static const char *level_name(rw_log_level_t level) {
    switch (level) {
        case RW_LOG_LEVEL_DEBUG: return "debug";
        case RW_LOG_LEVEL_INFO:  return "info";
        case RW_LOG_LEVEL_WARN:  return "warn";
        case RW_LOG_LEVEL_ERROR: return "error";
    }
    return "info";
}

void rw_log_set_enabled(bool enabled) {
    s_enabled = enabled;
}

bool rw_log_enabled(void) {
    return s_enabled;
}

void rw_log_set_sink(rw_log_sink_t sink) {
    s_sink = sink;
}

void rw_log(rw_log_level_t level, const char *fmt, ...) {
    if (!s_enabled) {
        return;
    }

    char    msg[RW_LOG_MAX];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    printf("# %s %s\n", level_name(level), msg);

    /* debug lines stay local. Shipping every debug line to the relay would multiply relay
     * ingress by the number of devices for no diagnostic gain the operator cannot get over
     * USB, and PROTOCOL.md §4 lets relays discard them anyway. */
    if (s_sink != NULL && level >= RW_LOG_LEVEL_WARN) {
        s_sink(level, msg);
    }
}
