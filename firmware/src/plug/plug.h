/*
 * The plug driver: scan, set and status against Shelly smart plugs on the local segment.
 *
 * This is the dongle's half of smart-plug power cycling — the recovery rung below wake and
 * below the agent: when a machine is hung past its own agent's reach, a network-controlled
 * relay cuts and restores its AC. The dongle is the actor because it is the one device
 * guaranteed to be on and on the LAN; the plug itself needs no cloud account and no internet
 * route, because the only path to it is this device asking over local HTTP.
 *
 * Shape of the module, and why each half is the shape it is:
 *
 *  - `rw_plug_scan()` BLOCKS, pumping the stack, exactly as rw_lan_scan does for `scan` — it
 *    is the same kind of command with the same relay-side expectations.
 *  - Set and status are a polled state machine (`rw_plug_task()`), the probe.c idiom, because
 *    a `cycle` holds an off-wait of seconds in the middle: a wait that blocked the main loop
 *    would stall the relay socket, the LED and the watchdog feed for its whole duration, for
 *    a command whose entire job during that time is to do nothing.
 *
 * Identity is the plug's MAC; the IP is a hint. DHCP moves addresses, so when the cached IP
 * does not answer — or answers as a different device — the driver re-resolves the MAC and
 * tries once more before giving up. See resolve_by_mac() in plug.c.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_PLUG_H
#define RW_PLUG_H

#include <stdbool.h>
#include <stdint.h>

#include "lwip/ip_addr.h"

#include "plug/shelly.h"

/*
 * Ceiling on a scan's result list. The frame budget decides this, not generosity: an entry
 * with a model, a name and four figures runs to ~120 bytes, and §1's 2048-byte frame ceiling
 * holds around sixteen of those beside the frame's own fields. Collecting more than can ever
 * be sent would only manufacture truncation.
 */
#define RW_PLUG_SCAN_MAX 16

/* Bounds on a cycle's off-time. The floor is the spec's: under three seconds some PSUs still
 * hold enough charge to ride through, and a cut that does not cut is worse than none. The
 * ceiling is ours — a frame could otherwise park the state machine for an hour. */
#define RW_PLUG_OFF_MS_DEFAULT 5000
#define RW_PLUG_OFF_MS_MIN     3000
#define RW_PLUG_OFF_MS_MAX     60000

typedef enum {
    RW_PLUG_ON,
    RW_PLUG_OFF,
    RW_PLUG_CYCLE, /* off, wait, on — the reply comes after the on */
} rw_plug_action_t;

/*
 * How an operation ended. `err` is NULL on success, otherwise a §6 code: `plug_unreachable`,
 * `plug_unsupported`, or `internal`. For a set, `state_on` is the state the plug was left in;
 * for a status, `st` is the parsed channel state; for a firmware check, `fw` is the standing.
 */
typedef struct {
    bool               ok;
    const char        *err;
    bool               state_on;
    rw_shelly_status_t st;
    rw_shelly_fw_t     fw;
} rw_plug_outcome_t;

typedef void (*rw_plug_done_t)(void *ctx, const rw_plug_outcome_t *outcome);

/*
 * Sweep the subnet for Shellys: ARP first to learn who is there at all, then `GET /shelly` to
 * each answering host, two at a time — the TCP pcb pool is four entries with one held by the
 * relay, so two is the whole concurrency budget. Blocks for up to ~20 s worst case while
 * pumping the stack and feeding the watchdog. Returns the number found, or a negative
 * RW_LAN_SCAN_ERR_* when there is no network to sweep.
 */
int rw_plug_scan(rw_shelly_plug_t *out, int max);

/*
 * Start a set or a status. `ip` is the caller's cached address for `mac` and may be stale.
 * Returns false when an operation is already running — one at a time, like every command.
 * The callback fires from rw_plug_task() on the main loop, exactly once per started
 * operation, unless rw_plug_cancel() is called first.
 */
bool rw_plug_set_start(const uint8_t mac[6], const ip4_addr_t *ip, int channel,
                       rw_plug_action_t action, uint32_t off_ms, rw_plug_done_t cb, void *ctx);
bool rw_plug_status_start(const uint8_t mac[6], const ip4_addr_t *ip, int channel,
                          rw_plug_done_t cb, void *ctx);

/*
 * The firmware verbs (PROTOCOL.md §5 `plug_fw_check` / `plug_fw_update`). No channel:
 * firmware is a fact about the device, however many feeds it carries. The check reads the
 * running build and asks the plug ITSELF whether its vendor holds something newer — the
 * device makes that check over its own internet route; this driver still speaks only local
 * HTTP, and a plug firewalled off the internet simply answers "nothing newer", which is an
 * answer, not a fault. The update orders the vendor's stable build and completes on
 * ACCEPTANCE: the flash and reboot run on the plug's own schedule, and a driver that waited
 * through them would report a timeout against an update that is working. Same identity
 * ladder as set/status — cached IP confirmed by MAC, re-resolve on silence or mismatch —
 * because a version read aimed at a reassigned lease would report an innocent device's
 * firmware as the target's.
 */
bool rw_plug_fw_check_start(const uint8_t mac[6], const ip4_addr_t *ip, rw_plug_done_t cb,
                            void *ctx);
bool rw_plug_fw_update_start(const uint8_t mac[6], const ip4_addr_t *ip, rw_plug_done_t cb,
                             void *ctx);

/* Drive the state machine. Call from the main loop; cheap when idle. */
void rw_plug_task(void);

/*
 * Orphan whatever is running — the connection it belonged to is gone, so no callback will
 * fire. A cycle that has already cut power still completes its restore, silently: abandoning
 * the on-leg over a dropped relay connection would leave a machine hard-off, which is the
 * outage this feature exists to end. rw_plug_busy() stays true until that finishes.
 */
void rw_plug_cancel(void);

bool rw_plug_busy(void);

/*
 * Is `ip` a host address on the device's own subnet — not the network or broadcast address,
 * and not the device itself?
 *
 * The frame layer refuses anything else BEFORE any socket is opened. This driver speaks
 * plain unauthenticated HTTP wherever it is pointed, so a relay that could name an arbitrary
 * address would have an HTTP client inside somebody's network perimeter — and beyond it. The
 * commands drive LAN peers; an address that is not one is not a mistake to route, it is a
 * request this device must never make.
 */
bool rw_plug_ip_local(const ip4_addr_t *ip);

#endif /* RW_PLUG_H */
