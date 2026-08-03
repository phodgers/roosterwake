/*
 * Serialising a scan into a frame that cannot exceed PROTOCOL.md §1's 2048-byte ceiling.
 *
 * `scan_result` is the only frame in the protocol whose natural size depends on something
 * neither end controls — how many hosts happen to be switched on. A busy segment answers with
 * more than the frame can carry, so the list is bounded here rather than left to overflow.
 *
 * Kept separate from proto.c, and free of lwIP types, so the part with the arithmetic in it is
 * exercised by the host tests rather than only on a device with a full network behind it.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_SCAN_JSON_H
#define RW_SCAN_JSON_H

#include <stdbool.h>
#include <stdint.h>

#include "net/nbns.h"
#include "proto/json.h"

/* Matches RW_LAN_SCAN_MAX. Stated here rather than included from lanscan.h, which needs an IP
 * stack; proto.c asserts at compile time that the two have not drifted apart. */
#define RW_SCAN_JSON_MAX 24

/* One host, with the address already rendered — the caller owns the conversion so that this
 * file needs no IP stack. */
typedef struct {
    char    ip[16];
    uint8_t mac[6];
    /* Empty when the host answered no name query. */
    char    name[RW_NBNS_NAME_LEN];
} rw_scan_host_t;

/*
 * Append `"hosts":[…]` to `w`, dropping hosts that do not fit.
 *
 * `reserve` is the number of bytes to leave unwritten for whatever the caller still has to add
 * after the array — the remaining fields and the closing brace. Writes at most as many hosts as
 * fit in what is left.
 *
 * Returns true when every host was written, false when any was dropped, which the caller
 * reports as `truncated` (§4).
 *
 * Hosts are written in the order given. When not all of them fit, the ones with a name are kept
 * in preference to the ones without: the list exists so that somebody can find one particular
 * machine on it, and a host that answered a name query is far likelier to be that machine.
 */
bool rw_scan_json_hosts(rw_jw_t *w, const rw_scan_host_t *hosts, int count, size_t reserve);

#endif /* RW_SCAN_JSON_H */
