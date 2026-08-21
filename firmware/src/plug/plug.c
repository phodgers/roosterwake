/*
 * The plug driver. See plug.h.
 *
 * SPDX-License-Identifier: MIT
 */
#include "plug/plug.h"

#include <stdio.h>
#include <string.h>

#include "lwip/netif.h"
#include "pico/time.h"

#include "config/config.h" /* rw_mac_format */
#include "net/arplearn.h"
#include "net/httpc.h"
#include "net/lanscan.h"
#include "rw_log.h"
#include "sys/sys.h"

/*
 * One HTTP exchange with a plug that is known to be there. Generous against a device answering
 * on its own segment — a Shelly replies in tens of milliseconds — and short enough that the
 * unreachable case resolves inside the relay's patience.
 */
#define PLUG_HTTP_TIMEOUT_MS 1500

/* One `GET /shelly` during a sweep. Tighter than the single-target figure: most of what
 * answers ARP does not answer port 80, and every silent host costs this in full. */
#define SCAN_HTTP_TIMEOUT_MS 900

/* Ceiling on the HTTP half of a sweep, after the ARP pass has had RW_LAN_SCAN_BUDGET_MS.
 * Hosts still unprobed when it lands are dropped, counted, and logged. */
#define SCAN_HTTP_BUDGET_MS 12000

/* Both scan slots probe `/shelly` only, whose body is a few hundred bytes; headers ride in
 * the same buffer. The single-target buffer must also hold a Gen1 `/status`, which is the
 * largest body this driver reads — RW_SHELLY_BODY_MAX plus header room. */
#define SCAN_RESP_CAP   1024
#define SINGLE_RESP_CAP (RW_SHELLY_BODY_MAX + 512)

/* ── Scan ──────────────────────────────────────────────────────────────────── */

typedef struct {
    rw_httpc_t http;
    char       req[128];
    char       resp[SCAN_RESP_CAP];
    int        host; /* index into the sweep's host list, or -1 when the slot is free */
} scan_slot_t;

/*
 * Two concurrent probes, and the figure is a constraint, not a tuning knob: MEMP_NUM_TCP_PCB
 * is 4 (lwipopts.h) and the relay connection holds one for the life of the link. Static
 * because 4.5 KB does not belong on the stack, and safe because a sweep runs one at a time
 * from the main loop, like the ARP arrays in proto.c's run_scan().
 */
static scan_slot_t s_slot[2];

/* A completed `GET /shelly`: keep the host if it identified as a Shelly. */
static bool harvest(const scan_slot_t *slot, const rw_lan_host_t *host, rw_shelly_plug_t *out) {
    if (rw_httpc_state(&slot->http) != RW_HTTPC_DONE) {
        return false;
    }
    int         status;
    const char *body;
    size_t      body_len;
    if (!rw_shelly_http_split(slot->resp, slot->http.resp_len, &status, &body, &body_len) ||
        status != 200) {
        return false;
    }
    rw_shelly_id_t id;
    if (!rw_shelly_identify(body, body_len, &id)) {
        return false;
    }

    /*
     * The MAC reported is the ARP one, not the body's. They agree on every real Shelly, but
     * the ARP address is the one a later re-resolve will search by — reporting a MAC the
     * segment cannot be seen to hold would plant an identity no sweep can ever find again.
     */
    rw_mac_format(host->mac, out->mac);
    snprintf(out->ip, sizeof(out->ip), "%s", ip4addr_ntoa(&host->ip));
    snprintf(out->model, sizeof(out->model), "%s", id.model);
    snprintf(out->name, sizeof(out->name), "%s", id.name);
    out->gen      = id.gen;
    out->channels = id.channels;
    return true;
}

int rw_plug_scan(rw_shelly_plug_t *out, int max) {
    static rw_lan_host_t hosts[RW_LAN_SCAN_MAX];

    const int n = rw_lan_sweep(hosts, RW_LAN_SCAN_MAX);
    if (n < 0) {
        return n;
    }

    for (size_t i = 0; i < sizeof(s_slot) / sizeof(s_slot[0]); i++) {
        rw_httpc_abort(&s_slot[i].http);
        s_slot[i].host = -1;
    }

    const absolute_time_t deadline = make_timeout_time_ms(SCAN_HTTP_BUDGET_MS);
    int                   next = 0, done = 0, found = 0;

    while (done < n && found < max) {
        if (time_reached(deadline)) {
            break;
        }
        for (size_t i = 0; i < sizeof(s_slot) / sizeof(s_slot[0]); i++) {
            scan_slot_t *slot = &s_slot[i];
            rw_httpc_poll(&slot->http);

            if (slot->host >= 0 && rw_httpc_state(&slot->http) != RW_HTTPC_ACTIVE) {
                if (found < max && harvest(slot, &hosts[slot->host], &out[found])) {
                    found++;
                }
                rw_httpc_abort(&slot->http);
                slot->host = -1;
                done++;
            }

            if (slot->host < 0 && next < n && found < max) {
                const char  *ip  = ip4addr_ntoa(&hosts[next].ip);
                const size_t len = rw_shelly_req_identify(slot->req, sizeof(slot->req), ip);
                if (len == 0) {
                    done++; /* cannot happen for a dotted quad, but never silently skipped */
                    next++;
                    continue;
                }
                if (rw_httpc_start(&slot->http, &hosts[next].ip, 80, slot->req, len, slot->resp,
                                   sizeof(slot->resp), SCAN_HTTP_TIMEOUT_MS)) {
                    slot->host = next;
                    next++;
                }
                /* A start that failed — the pcb pool momentarily empty — leaves the host for
                 * the next pass rather than consuming it. */
            }
        }
        rw_sys_pump_ms(10);
    }

    for (size_t i = 0; i < sizeof(s_slot) / sizeof(s_slot[0]); i++) {
        rw_httpc_abort(&s_slot[i].http);
        s_slot[i].host = -1;
    }

    if (done < n) {
        RW_LOG_WARN("plug: sweep stopped with %d host(s) unprobed", n - done);
    }
    RW_LOG_INFO("plug: %d host(s) answered ARP, %d identified as plugs", n, found);
    return found;
}

/* ── Set and status ────────────────────────────────────────────────────────── */

typedef enum {
    PHASE_IDLE = 0,
    PHASE_PROBE,  /* GET /shelly — who is at this address, and which generation */
    PHASE_ACT,    /* the set or status request itself (for cycle: the off) */
    PHASE_WAIT,   /* a timer is running: the cycle's dwell, or the gap before a retry */
    PHASE_ACT2,   /* cycle only: the on */
    PHASE_VERIFY, /* Gen2 only: the confirming Switch.GetStatus after a successful set —
                     Switch.Set answers was_on, the PREVIOUS state, which must never be
                     echoed as current */
} phase_t;

/*
 * The restore's second chances. A cycle that has cut power and cannot confirm the restore
 * MUST NOT give up on its first miss — a Shelly rebooting its own radio, a Wi-Fi blip, a
 * single lost segment would each leave a machine off at the wall over a transient. Three
 * fresh attempts a second apart is a short budget, not persistence: after it the honest
 * answer is a failure the caller can see and act on.
 */
#define PLUG_RETRY_MAX    3
#define PLUG_RETRY_GAP_MS 1000

static struct {
    phase_t          phase;
    bool             is_status;
    rw_plug_action_t action;
    uint32_t         off_ms;
    uint8_t          mac[6];
    ip4_addr_t       ip;
    char             ip_text[16];
    int              channel;
    int              gen;
    /* The current address came from a resolve that positively mapped the MAC to it, rather
     * than from the caller's cache. Decides how a failure at it is reported. */
    bool             addr_confirmed;
    bool             resolved_once;
    absolute_time_t  wait_until;
    phase_t          after_wait; /* which leg PHASE_WAIT starts when the timer lands */
    int              retries;
    rw_plug_done_t   cb;
    void            *ctx;
    rw_httpc_t       http;
    char             req[256];
    char             resp[SINGLE_RESP_CAP];
} s;

static void finish(bool ok, const char *err, bool state_on, const rw_shelly_status_t *st) {
    rw_httpc_abort(&s.http);
    s.phase = PHASE_IDLE;

    rw_plug_outcome_t outcome;
    memset(&outcome, 0, sizeof(outcome));
    outcome.ok       = ok;
    outcome.err      = err;
    outcome.state_on = state_on;
    if (st != NULL) {
        outcome.st = *st;
    }
    if (s.cb != NULL) {
        s.cb(s.ctx, &outcome);
    }
}

/* Returns NULL and advances the phase, or the §6 code the attempt failed with — the caller
 * decides whether that failure ends the operation or earns a retry. */
static const char *send_request(size_t len, phase_t next_phase) {
    if (len == 0) {
        return "internal";
    }
    if (!rw_httpc_start(&s.http, &s.ip, 80, s.req, len, s.resp, sizeof(s.resp),
                        PLUG_HTTP_TIMEOUT_MS)) {
        /* No pcb, almost always: the pool is four with one held by the relay. */
        return "plug_unreachable";
    }
    s.phase = next_phase;
    return NULL;
}

static void set_ip(const ip4_addr_t *ip) {
    s.ip = *ip;
    snprintf(s.ip_text, sizeof(s.ip_text), "%s", ip4addr_ntoa(ip));
}

/*
 * Which address holds this MAC now?
 *
 * The cheap answer first: arplearn has been sampling the ARP table since boot, so a plug that
 * has said anything recently is a lookup. Otherwise the mini-sweep — the same ARP pass the
 * scan uses, without the name queries — which BLOCKS for a few seconds while pumping the
 * stack. That is the run_scan() bargain, made here for the same reason: the alternative is
 * failing a power-restore command over a DHCP lease change.
 */
static bool resolve_by_mac(void) {
    ip4_addr_t fresh;
    if (rw_arp_lookup(s.mac, &fresh) &&
        ip4_addr_get_u32(&fresh) != ip4_addr_get_u32(&s.ip)) {
        set_ip(&fresh);
        return true;
    }

    static rw_lan_host_t hosts[RW_LAN_SCAN_MAX];
    const int            n = rw_lan_sweep(hosts, RW_LAN_SCAN_MAX);
    for (int i = 0; i < n; i++) {
        if (memcmp(hosts[i].mac, s.mac, 6) == 0) {
            set_ip(&hosts[i].ip);
            return true;
        }
    }
    return false;
}

static const char *start_probe(void) {
    return send_request(rw_shelly_req_identify(s.req, sizeof(s.req), s.ip_text), PHASE_PROBE);
}

/* The action request for where the operation is now: a status read (`plug_status`, or the
 * confirming read after a Gen2 set), a set to the target state, or the cycle's two legs —
 * ACT is the off, ACT2 the on. */
static const char *start_act(phase_t phase) {
    size_t len;
    if (s.is_status || phase == PHASE_VERIFY) {
        len = rw_shelly_req_status(s.req, sizeof(s.req), s.ip_text, s.gen, s.channel);
    } else {
        const bool on = (phase == PHASE_ACT2) || (s.action == RW_PLUG_ON);
        len = rw_shelly_req_set(s.req, sizeof(s.req), s.ip_text, s.gen, s.channel, on);
    }
    return send_request(len, phase);
}

/*
 * Retry `leg` after a short gap, if the budget allows. Only the legs that run AFTER power has
 * been cut ride this — the restore and its confirming read. Failing those on the first miss
 * would leave a machine off at the wall over one lost segment; failing anything earlier just
 * reports an error about a machine whose power was never touched.
 */
static bool schedule_retry(phase_t leg) {
    if (s.retries >= PLUG_RETRY_MAX) {
        return false;
    }
    s.retries++;
    rw_httpc_abort(&s.http);
    s.wait_until = make_timeout_time_ms(PLUG_RETRY_GAP_MS);
    s.after_wait = leg;
    s.phase      = PHASE_WAIT;
    RW_LOG_WARN("plug: %s failed, attempt %d of %d in %d ms",
                leg == PHASE_VERIFY ? "confirming read" : "restore", s.retries, PLUG_RETRY_MAX,
                PLUG_RETRY_GAP_MS);
    return true;
}

/* True while a failure would leave the machine without power — the cycle has sent its off and
 * not yet confirmed an on. These are the legs that earn a retry. */
static bool past_the_cut(phase_t phase) {
    return s.action == RW_PLUG_CYCLE && !s.is_status &&
           (phase == PHASE_ACT2 || phase == PHASE_VERIFY);
}

/* Start (or restart) a leg, routing its failure: a retry where the machine's power hangs on
 * it, an ended operation everywhere else. */
static void run_leg(phase_t leg) {
    const char *err = (leg == PHASE_PROBE) ? start_probe() : start_act(leg);
    if (err == NULL) {
        return;
    }
    if (past_the_cut(leg) && schedule_retry(leg)) {
        return;
    }
    finish(false, err, false, NULL);
}

static bool start_common(const uint8_t mac[6], const ip4_addr_t *ip, int channel,
                         rw_plug_done_t cb, void *ctx) {
    if (s.phase != PHASE_IDLE) {
        return false;
    }
    memset(&s, 0, sizeof(s));
    memcpy(s.mac, mac, 6);
    set_ip(ip);
    s.channel = channel;
    s.cb      = cb;
    s.ctx     = ctx;
    return true;
}

bool rw_plug_set_start(const uint8_t mac[6], const ip4_addr_t *ip, int channel,
                       rw_plug_action_t action, uint32_t off_ms, rw_plug_done_t cb, void *ctx) {
    if (!start_common(mac, ip, channel, cb, ctx)) {
        return false;
    }
    s.action = action;
    s.off_ms = off_ms;
    /* A probe that cannot even be attempted has already called the callback; the operation
     * still counts as started, because the caller will hear exactly one outcome either way. */
    run_leg(PHASE_PROBE);
    return true;
}

bool rw_plug_status_start(const uint8_t mac[6], const ip4_addr_t *ip, int channel,
                          rw_plug_done_t cb, void *ctx) {
    if (!start_common(mac, ip, channel, cb, ctx)) {
        return false;
    }
    s.is_status = true;
    run_leg(PHASE_PROBE);
    return true;
}

/* Split the finished exchange, demanding HTTP 200. Returns false with `*why` set. */
static bool take_response(const char **body, size_t *body_len, const char **why) {
    if (rw_httpc_state(&s.http) != RW_HTTPC_DONE) {
        *why = "plug_unreachable";
        return false;
    }
    int status;
    if (!rw_shelly_http_split(s.resp, s.http.resp_len, &status, body, body_len)) {
        *why = "plug_unsupported"; /* answered, but not with HTTP this driver reads */
        return false;
    }
    if (status != 200) {
        /* The device is there and refusing — a Gen1 answers 400 for a channel it does not
         * have. Different sentence from silence. */
        *why = "plug_unsupported";
        return false;
    }
    return true;
}

static void probe_done(void) {
    const char *why;
    const char *body;
    size_t      body_len;
    bool        identified = false;
    rw_shelly_id_t id;

    if (take_response(&body, &body_len, &why)) {
        identified = rw_shelly_identify(body, body_len, &id);
        if (identified && memcmp(id.mac, s.mac, 6) == 0) {
            /* The right device answered. Everything after this reports failures as its own,
             * not as a stale address. */
            s.gen            = id.gen;
            s.addr_confirmed = true;
            run_leg(PHASE_ACT);
            return;
        }
        /* Something answered `/shelly` here, but it is not the plug that was named: either
         * not a Shelly at all, or a Shelly whose MAC is somebody else's. Both mean the
         * cached address has moved on — treated exactly like silence. */
    }

    if (!s.resolved_once) {
        s.resolved_once = true;
        rw_httpc_abort(&s.http);
        if (resolve_by_mac()) {
            run_leg(PHASE_PROBE);
            return;
        }
    }

    /*
     * Out of moves. An address the resolver positively pinned to this MAC, answering as
     * something that is not a plug, is `plug_unsupported`; everything else — silence, or a
     * stranger at a stale address the MAC could not be traced from — is `plug_unreachable`.
     */
    const bool pinned_but_wrong = s.addr_confirmed && identified;
    finish(false, pinned_but_wrong ? "plug_unsupported" : "plug_unreachable", false, NULL);
}

static void act_done(phase_t phase) {
    const char *why;
    const char *body;
    size_t      body_len;
    if (!take_response(&body, &body_len, &why)) {
        if (past_the_cut(phase) && schedule_retry(phase)) {
            return;
        }
        finish(false, why, false, NULL);
        return;
    }

    if (s.is_status || phase == PHASE_VERIFY) {
        rw_shelly_status_t st;
        if (!rw_shelly_parse_status(body, body_len, s.gen, s.channel, &st)) {
            if (past_the_cut(phase) && schedule_retry(phase)) {
                return;
            }
            finish(false, "plug_unsupported", false, NULL);
            return;
        }
        /* For a verify this reports what the confirming read SAW, which on a healthy plug is
         * the requested state — and on an unhealthy one (overpower protection re-tripping,
         * say) is the truth the caller needs instead. */
        finish(true, NULL, st.on, &st);
        return;
    }

    bool have_state, state_on;
    if (!rw_shelly_parse_set(body, body_len, s.gen, &have_state, &state_on)) {
        if (past_the_cut(phase) && schedule_retry(phase)) {
            return;
        }
        finish(false, "plug_unsupported", false, NULL);
        return;
    }

    if (s.action == RW_PLUG_CYCLE && phase == PHASE_ACT) {
        /* Power is now cut. The dwell runs on the deadline below, checked from
         * rw_plug_task() — never a blocking sleep, because for its whole duration the main
         * loop still owes the relay its keepalives and the watchdog its feed. */
        s.wait_until = make_timeout_time_ms(s.off_ms);
        s.after_wait = PHASE_ACT2;
        s.phase      = PHASE_WAIT;
        RW_LOG_INFO("plug: channel %d cut, restoring in %lu ms", s.channel,
                    (unsigned long)s.off_ms);
        return;
    }

    /* The set is accepted. Gen1's reply already stated the new state; Gen2's stated the
     * previous one, so the answer comes from a confirming read instead. */
    if (have_state) {
        finish(true, NULL, state_on, NULL);
    } else {
        run_leg(PHASE_VERIFY);
    }
}

void rw_plug_task(void) {
    if (s.phase == PHASE_IDLE) {
        return;
    }
    rw_httpc_poll(&s.http);

    switch (s.phase) {
        case PHASE_IDLE:
            break;
        case PHASE_PROBE:
            if (rw_httpc_state(&s.http) != RW_HTTPC_ACTIVE) {
                probe_done();
            }
            break;
        case PHASE_ACT:
            if (rw_httpc_state(&s.http) != RW_HTTPC_ACTIVE) {
                act_done(PHASE_ACT);
            }
            break;
        case PHASE_WAIT:
            if (time_reached(s.wait_until)) {
                run_leg(s.after_wait);
            }
            break;
        case PHASE_ACT2:
            if (rw_httpc_state(&s.http) != RW_HTTPC_ACTIVE) {
                act_done(PHASE_ACT2);
            }
            break;
        case PHASE_VERIFY:
            if (rw_httpc_state(&s.http) != RW_HTTPC_ACTIVE) {
                act_done(PHASE_VERIFY);
            }
            break;
    }
}

void rw_plug_cancel(void) {
    /*
     * A cycle that has already sent its off MUST run to completion, silently. The instruction
     * was "cut power and restore it", and the restore is the second half of an instruction
     * already accepted — abandoning it because the relay connection dropped would leave a
     * machine hard-off over a WAN blip, which is precisely the outage this feature exists to
     * end. Only the callback is orphaned: the req_id it would have answered belongs to a
     * connection that no longer exists, and the caller's timeout is its signal to ask again.
     */
    if (!s.is_status && s.action == RW_PLUG_CYCLE && s.phase != PHASE_IDLE &&
        s.phase != PHASE_PROBE) {
        RW_LOG_WARN("plug: connection lost mid-cycle; completing the restore unreported");
        s.cb = NULL;
        return;
    }
    rw_httpc_abort(&s.http);
    s.phase = PHASE_IDLE;
    s.cb    = NULL;
}

bool rw_plug_busy(void) {
    return s.phase != PHASE_IDLE;
}

bool rw_plug_ip_local(const ip4_addr_t *ip) {
    struct netif *nif = netif_default;
    if (nif == NULL) {
        return false;
    }
    const uint32_t self = lwip_ntohl(ip4_addr_get_u32(netif_ip4_addr(nif)));
    const uint32_t mask = lwip_ntohl(ip4_addr_get_u32(netif_ip4_netmask(nif)));
    const uint32_t addr = lwip_ntohl(ip4_addr_get_u32(ip));
    if (self == 0 || mask == 0) {
        return false;
    }
    const uint32_t network   = self & mask;
    const uint32_t broadcast = network | ~mask;
    /* Strictly between network and broadcast, and never ourselves — the sweep's own rule for
     * what counts as a host on this segment. */
    return addr > network && addr < broadcast && addr != self;
}
