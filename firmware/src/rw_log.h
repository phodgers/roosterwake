/*
 * Diagnostic logging.
 *
 * Every line this emits is prefixed with "# " and goes to the USB CDC channel, because that
 * channel is a documented request/response protocol (usbcfg.md §3) and a host is entitled to
 * discard anything starting with "# " while waiting for its response. Emitting an unprefixed
 * line would desynchronise every setup tool on the planet.
 *
 * Logging is off unless the operator enabled it (config flag DIAG_LOG). That is not a
 * performance decision: a device that chatters on a serial port a user has open in a terminal
 * looks broken, and PROTOCOL.md §4 forbids sending `log` frames without opt-in for the same
 * reason.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_LOG_H
#define RW_LOG_H

#include <stdbool.h>

typedef enum {
    RW_LOG_LEVEL_DEBUG = 0,
    RW_LOG_LEVEL_INFO,
    RW_LOG_LEVEL_WARN,
    RW_LOG_LEVEL_ERROR,
} rw_log_level_t;

/* A sink the protocol layer installs so that warnings and errors also reach the relay as
 * `log` frames. Called only when logging is enabled. Must not block. */
typedef void (*rw_log_sink_t)(rw_log_level_t level, const char *msg);

void rw_log_set_enabled(bool enabled);
bool rw_log_enabled(void);
void rw_log_set_sink(rw_log_sink_t sink);

void rw_log(rw_log_level_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define RW_LOG_DEBUG(...) rw_log(RW_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define RW_LOG_INFO(...)  rw_log(RW_LOG_LEVEL_INFO, __VA_ARGS__)
#define RW_LOG_WARN(...)  rw_log(RW_LOG_LEVEL_WARN, __VA_ARGS__)
#define RW_LOG_ERROR(...) rw_log(RW_LOG_LEVEL_ERROR, __VA_ARGS__)

#endif /* RW_LOG_H */
