/*
 * The relay session. See proto.h and PROTOCOL.md.
 *
 * SPDX-License-Identifier: MIT
 */
#include "proto/proto.h"

#include <stdio.h>
#include <string.h>

#include "pico/rand.h"
#include "pico/time.h"

#include "brand.h"
#include "net/lanscan.h"
#include "net/net.h"
#include "proto/auth.h"
#include "proto/json.h"
#include "proto/probe.h"
#include "proto/scan_json.h"
#include "ota/image.h"
#include "ota/ota.h"
#include "ota/ota_write.h"
#include "plug/plug.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "sys/wallclock.h"
#include "wol/wol.h"
#include "ws/ws.h"

/* Frames are capped at 2048 bytes in both directions (PROTOCOL.md §1). */
#define OUT_MAX RW_WS_MAX_OUTBOUND

/*
 * Token budget for jsmn. Every relay→device frame is a flat object of a handful of scalar
 * members — the largest, `ota_offer`, is two, one of them a 256-character hex string that costs
 * a single token. 128 leaves room for unknown fields a future relay adds, which §2 requires us
 * to tolerate rather than fail on.
 */
#define MAX_TOKENS 128

/* One relay→device command runs at a time. Anything that blocks — a wake takes 200 ms of
 * bursts, a config save erases a flash sector, an RSSI read is a round trip to the radio — is
 * queued here and executed from rw_relay_task() on the main loop, never from inside an lwIP
 * callback. That is the whole reason this build uses pico_cyw43_arch_lwip_poll: it makes
 * "never re-enter the stack" a property of the design instead of a rule to remember. */
typedef enum {
    PENDING_NONE = 0,
    PENDING_WAKE,
    PENDING_STATUS,
    PENDING_PROBE,
    PENDING_SCAN,
    PENDING_OTA_BEGIN,
    PENDING_PLUG_SCAN,
    PENDING_PLUG_SET,
    PENDING_PLUG_STATUS,
} pending_kind_t;

#define REQ_ID_MAX 37 /* 36 characters plus NUL (PROTOCOL.md §2) */

static struct {
    rw_relay_state_t state;
    rw_config_t     *cfg;
    rw_relay_hooks_t hooks;
    bool             enabled;

    rw_ws_client_t ws;

    char nonce_c[RW_NONCE_HEX + 1];
    char expected_proof_s[RW_PROOF_HEX + 1];

    uint32_t        backoff_ms;
    absolute_time_t retry_at;
    absolute_time_t next_ping;
    /* When the relay last said anything at all. Any frame counts, not just a pong: the question
     * is whether the socket still carries traffic, and a `wake` proves that as well as a pong
     * does. See RW_RELAY_SILENCE_MS. */
    absolute_time_t last_rx;

    pending_kind_t kind;
    char           req_id[REQ_ID_MAX];
    uint8_t        mac[6];
    int            repeat;
    uint32_t       timeout_s;

    char probe_req_id[REQ_ID_MAX];
    bool probe_owned; /* a probe belonging to the current connection is running */

    /* A plug operation runs like a probe: queued, started from the main loop, answered from a
     * completion callback, and owned by the connection that asked. The parameters ride here
     * between the frame handler and run_pending(); `s.mac` carries the plug's MAC the same way
     * it carries a wake target's. */
    char             plug_req_id[REQ_ID_MAX];
    bool             plug_owned;
    bool             plug_is_status;
    ip4_addr_t       plug_ip;
    int              plug_channel;
    rw_plug_action_t plug_action;
    uint32_t         plug_off_ms;

    /* `enrol` was sent on this connection and its outcome is not yet known. */
    bool enrolling;
    /* A configuration change made in a network callback, to be written on the main loop. */
    bool persist_pending;

    /*
     * Why the previous boot restarted itself (diag/stuck.h), waiting to be reported.
     *
     * Cleared as soon as a `hello` carries it. A device that has reconnected has answered the
     * question, and re-sending it on every subsequent reconnection would turn one incident into
     * a permanent attribute of the device — and would make the relay's copy meaningless, because
     * it could no longer tell "this just happened" from "this happened once in March".
     */
    bool              have_last_stuck;
    rw_stuck_record_t last_stuck;

    /*
     * An offer that has been checked but not yet answered. Clearing the slot takes a couple of
     * seconds, which cannot happen in the frame handler, so the header is held here until
     * run_pending() can do it and send the accept afterwards.
     */
    struct {
        rw_ota_header_t header;
        uint8_t         slot;
        char            id[REQ_ID_MAX];
    } offer;

    /* An update the device accepted and is being streamed. See "Updates" below. */
    struct {
        bool            receiving;
        /* The transfer has ended but the relay may not know yet. Frames already on the wire are
         * accepted and dropped rather than treated as bytes nobody asked for — the relay learns
         * from `ota_result`, and closing the connection over frames it sent before reading it
         * would turn every failed update into a reconnection as well. */
        bool            draining;
        char            id[REQ_ID_MAX];
        char            version[RW_OTA_VERSION_LEN];
        uint8_t         slot;
        uint32_t        total;
        uint32_t        got;
        absolute_time_t started;
    } ota;
    /* Set once a slot has been written, verified and staged. The reboot happens on the main
     * loop so the result frame and the closing handshake go out first. */
    bool reboot_pending;

    char out[OUT_MAX];
} s;

/* ── Small helpers ─────────────────────────────────────────────────────────── */

static void set_state(rw_relay_state_t state) {
    s.state = state;
}

/* Defined with rw_relay_state_name() at the foot of the file, next to the mapping it shares.
 * Declared here because send_hello() names the state a PREVIOUS boot gave up in. */
static const char *relay_state_name_of(rw_relay_state_t state);

static bool send_json(const rw_jw_t *w) {
    if (!w->ok) {
        RW_LOG_ERROR("proto: outbound frame did not fit %u bytes", (unsigned)OUT_MAX);
        return false;
    }
    return rw_ws_send_text(&s.ws, w->buf, w->len);
}

static void make_nonce(char *out_hex) {
    uint8_t bytes[RW_NONCE_BYTES];
    for (size_t i = 0; i < sizeof(bytes); i += 4) {
        uint32_t word = get_rand_32();
        memcpy(bytes + i, &word, 4);
    }
    rw_hex_encode(bytes, sizeof(bytes), out_hex);
}

/* ── Outbound frames ───────────────────────────────────────────────────────── */

static bool send_hello(void) {
    make_nonce(s.nonce_c);

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "hello");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "v");
    rw_jw_int(&w, RW_PROTO_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "device_id");
    rw_jw_str(&w, s.cfg->device_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "nonce_c");
    rw_jw_str(&w, s.nonce_c);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "fw");
    rw_jw_str(&w, RW_FW_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "board");
    rw_jw_str(&w, RW_BOARD_NAME);
    rw_jw_raw(&w, ",");
    /*
     * Which of the two slots this image is running from. An image is linked at the address of
     * the slot it occupies, so a relay offering an update has to choose the variant built for
     * the other one — it cannot work that out from the version, and offering the wrong one
     * wastes half a megabyte to be refused.
     */
    rw_jw_key(&w, "slot");
    rw_jw_int(&w, (long)rw_ota_running_slot());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "caps");
    rw_jw_raw(&w, RW_CAPS_JSON);

    /*
     * PROTOCOL.md §4 `stuck`: present only on the first hello after the device restarted itself
     * for having a network and no relay. Absent on every ordinary boot, which is nearly all of
     * them — a field that were always present would cost every device bytes on every connection
     * to say "nothing happened".
     *
     * Sent before the handshake completes, like everything else in `hello`, so the relay must
     * treat it as a claim by whoever knows a device_id and only record it once the proof
     * verifies. §4 already says that about `macs`; this rides the same rule.
     */
    if (s.have_last_stuck) {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "stuck");
        rw_jw_raw(&w, "{");
        rw_jw_key(&w, "relay");
        rw_jw_str(&w, relay_state_name_of((rw_relay_state_t)s.last_stuck.relay_state));
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "unlinked_s");
        rw_jw_int(&w, (long)s.last_stuck.unlinked_s);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "uptime_s");
        rw_jw_int(&w, (long)s.last_stuck.uptime_s);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "heap_free");
        rw_jw_int(&w, (long)s.last_stuck.heap_free);
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "mem_err");
        rw_jw_int(&w, (long)s.last_stuck.mem_err);
        if (s.last_stuck.last_error[0]) {
            rw_jw_raw(&w, ",");
            rw_jw_key(&w, "err");
            rw_jw_str(&w, s.last_stuck.last_error);
        }
        rw_jw_raw(&w, "}");
    }
    /*
     * No list of machines here, and no frame by which the relay could send one back: the caller
     * names the MAC in every `wake` and every `probe`, so there is nothing for a device to
     * declare and nothing for it to be told (PROTOCOL.md §4).
     *
     * No account information either. An earlier build carried a claim code on every `hello`, which
     * PROTOCOL.md never defined and no relay ever read. Binding is now its own frame, sent after
     * the handshake and acknowledged — which is what the claim field could not do, and why it
     * would have gone on being re-offered for the life of the device.
     */
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    if (!send_json(&w)) {
        return false;
    }

    /*
     * Cleared only once the frame is actually away. Clearing it while building would throw the
     * report away on a send that failed — and a send failing is precisely the situation in which
     * the device is about to reconnect and would have had one more chance to deliver it.
     */
    s.have_last_stuck = false;
    return true;
}

static bool send_auth(const char *nonce_s) {
    char proof_c[RW_PROOF_HEX + 1];
    if (!rw_auth_proof(s.cfg->token, RW_PROOF_TAG_CLIENT, s.cfg->device_id, s.nonce_c, nonce_s,
                       proof_c)) {
        RW_LOG_ERROR("proto: cannot compute proof_c - device_id or token is malformed");
        return false;
    }
    /* Precomputed now, while both nonces are in hand, so verifying hello_ack is a comparison
     * and nothing else. */
    if (!rw_auth_proof(s.cfg->token, RW_PROOF_TAG_SERVER, s.cfg->device_id, s.nonce_c, nonce_s,
                       s.expected_proof_s)) {
        return false;
    }

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "auth");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "proof_c");
    rw_jw_str(&w, proof_c);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    return send_json(&w);
}

/*
 * PROTOCOL.md §4 `enrol`, sent in place of `auth` on first contact.
 *
 * The only frame that carries the token, and §3.1 permits it under two rules this function is
 * responsible for. They are checked by the caller — `may_enrol()` — rather than here, so that a
 * refusal is a decision the connection state machine makes and logs, not a silent no-op inside a
 * serialiser.
 *
 * `expected_proof_s` is still precomputed, because the relay must return `proof_s` keyed with the
 * token it has just stored and the device must verify it. That check is the device's only
 * evidence that the right bytes landed.
 */
static bool send_enrol(const char *nonce_s) {
    if (!rw_auth_proof(s.cfg->token, RW_PROOF_TAG_SERVER, s.cfg->device_id, s.nonce_c, nonce_s,
                       s.expected_proof_s)) {
        RW_LOG_ERROR("proto: cannot compute proof_s - device_id or token is malformed");
        return false;
    }

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "enrol");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "token");
    rw_jw_str(&w, s.cfg->token);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    return send_json(&w);
}

/*
 * PROTOCOL.md §4 `adopt` — offer the address typed into the setup page.
 *
 * Sent once per connection while an address is staged, and stopped the moment `adopt_ack`
 * arrives. Repeating across connections rather than giving up after one is deliberate: the first
 * connection after setup is the one most likely to be cut short by a network still settling.
 */
static bool send_adopt(void) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "adopt");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "email");
    rw_jw_str(&w, s.cfg->owner_email);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    return send_json(&w);
}

static void send_wake_result(const char *req_id, bool ok, const char *err,
                             const rw_wol_result_t *res) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "wake_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, ok ? "true" : "false");
    if (!ok && err != NULL) {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "err");
        rw_jw_str(&w, err);
    }
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "sent");
    rw_jw_int(&w, res != NULL ? res->sent : 0);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ifaces");
    rw_jw_raw(&w, "[");
    if (res != NULL) {
        for (int i = 0; i < res->iface_count; i++) {
            if (i > 0) {
                rw_jw_raw(&w, ",");
            }
            rw_jw_str(&w, res->ifaces[i]);
        }
    }
    rw_jw_raw(&w, "]}");
    rw_jw_finish(&w);
    send_json(&w);
}

static void send_status_result(const char *req_id) {
    char ip[16], mask[16];
    rw_net_ip_str(ip, sizeof(ip));
    rw_net_netmask_str(mask, sizeof(mask));

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "status_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "rssi");
    rw_jw_int(&w, rw_net_rssi());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "uptime_s");
    rw_jw_int(&w, (long)rw_sys_uptime_s());
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ip");
    rw_jw_str(&w, ip);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "netmask");
    rw_jw_str(&w, mask);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "fw");
    rw_jw_str(&w, RW_FW_VERSION);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "reset_reason");
    rw_jw_str(&w, rw_sys_reset_reason());
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

static void send_probe_result_ok(const char *req_id, const char *state, uint32_t elapsed_s) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "probe_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "state");
    rw_jw_str(&w, state);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "elapsed_s");
    rw_jw_int(&w, (long)elapsed_s);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "method");
    rw_jw_str(&w, rw_probe_method());
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

/* PROTOCOL.md §4: a probe that could not start at all reports ok:false with `err` and no
 * `state` — a `probe` naming an unparseable MAC otherwise has nowhere to say so. */
static void send_probe_result_err(const char *req_id, const char *err) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "probe_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "err");
    rw_jw_str(&w, err);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

/*
 * The keepalive and its answer are byte-literal (PROTOCOL.md §9). Not built through the JSON
 * writer: the exact byte sequence is what lets a hibernating relay runtime answer without
 * waking the object behind it, and a writer that one day adds a space would silently cost the
 * relay operator money with no visible symptom.
 */
static const char k_ping_frame[] = "{\"t\":\"ping\"}";
static const char k_pong_frame[] = "{\"t\":\"pong\"}";

static void log_sink(rw_log_level_t level, const char *msg) {
    if (s.state != RW_RELAY_READY || !(s.cfg->flags & RW_CFG_FLAG_DIAG_LOG)) {
        return;
    }
    static bool reentrant;
    if (reentrant) {
        return; /* a log line emitted while sending a log line would not terminate */
    }
    reentrant = true;

    const char *name = (level == RW_LOG_LEVEL_ERROR) ? "error"
                       : (level == RW_LOG_LEVEL_WARN) ? "warn"
                                                      : "info";
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "log");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "level");
    rw_jw_str(&w, name);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "msg");
    rw_jw_str(&w, msg);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "at_s");
    rw_jw_int(&w, (long)rw_sys_uptime_s());
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);

    reentrant = false;
}

/* PROTOCOL.md §4: a scan that could not run at all reports ok:false with `err` and no host
 * list — an empty list means "nothing answered", which is a different thing from "never
 * looked". */
static void send_scan_result_err(const char *req_id, const char *err) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "scan_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "err");
    rw_jw_str(&w, err);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

/* What rw_scan_json_hosts() must leave room for: `,"truncated":false}` and the terminator the
 * writer keeps back. Stated as a constant because getting it wrong costs a frame the relay
 * closes the connection over rather than an error anybody sees. */
#define SCAN_TAIL_RESERVE 20

/*
 * Sweep the segment and answer. Runs from the main loop, never from a callback: it blocks for
 * several seconds, which is why `scan` is queued like every other command that does real work.
 *
 * Both arrays are static rather than automatic. Together they are over 1.5 KB, which is more
 * than belongs on this stack, and only one can ever be in use — `queue()` admits one command at
 * a time and this is the only thing that touches them.
 */
static void run_scan(const char *req_id) {
    static rw_lan_host_t  found[RW_LAN_SCAN_MAX];
    static rw_scan_host_t hosts[RW_SCAN_JSON_MAX];

    /* If these ever disagree the extra hosts would be swept and then silently dropped, which
     * looks exactly like a quiet network. */
    _Static_assert(RW_SCAN_JSON_MAX == RW_LAN_SCAN_MAX,
                   "scan_json and lanscan disagree about how many hosts a sweep returns");
    /* And if these disagree, names get silently truncated at the copy below. */
    _Static_assert(RW_SCAN_JSON_NAME_LEN == RW_LAN_NAME_LEN,
                   "scan_json and lanscan disagree about how long a host name can be");

    const int count = rw_lan_scan(found, RW_LAN_SCAN_MAX);
    if (count < 0) {
        send_scan_result_err(req_id, "no_link");
        return;
    }

    for (int i = 0; i < count; i++) {
        snprintf(hosts[i].ip, sizeof(hosts[i].ip), "%s", ip4addr_ntoa(&found[i].ip));
        memcpy(hosts[i].mac, found[i].mac, sizeof(hosts[i].mac));
        snprintf(hosts[i].name, sizeof(hosts[i].name), "%s", found[i].name);
    }

    char gateway[16];
    rw_net_gateway_str(gateway, sizeof(gateway));

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "scan_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "gateway");
    rw_jw_str(&w, gateway);
    rw_jw_raw(&w, ",");
    const bool all = rw_scan_json_hosts(&w, hosts, count, SCAN_TAIL_RESERVE);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "truncated");
    rw_jw_raw(&w, all ? "false" : "true");
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    RW_LOG_INFO("proto: scan found %d host(s)%s", count, all ? "" : ", list truncated");
    send_json(&w);
}

/* ── Plug frames ───────────────────────────────────────────────────────────── */

/*
 * PROTOCOL.md §4 `plug_result`. Sent AFTER the action completes — the one deliberate
 * inversion of `power`'s reply-before-action rule, and it is honest rather than convenient:
 * the actor is not the machine being acted on, so nothing here destroys the process that
 * replies, and a caller about to trust that a hung machine has been power-cycled deserves the
 * strong claim. `state` is the state the plug was left in, present only on success.
 */
static void send_plug_result(const char *req_id, bool ok, const char *err, bool on) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "plug_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, ok ? "true" : "false");
    if (ok) {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "state");
        rw_jw_str(&w, on ? "on" : "off");
    } else {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "err");
        rw_jw_str(&w, err);
    }
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

/* PROTOCOL.md §4 `plug_status_result`. The metering fields are omitted, not zeroed, where the
 * hardware has none: zero watts is a reading, and "cannot read watts" must not impersonate
 * it. */
static void send_plug_status_result(const char *req_id, bool ok, const char *err,
                                    const rw_shelly_status_t *st) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "plug_status_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, ok ? "true" : "false");
    if (!ok) {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "err");
        rw_jw_str(&w, err);
    } else {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "on");
        rw_jw_raw(&w, st->on ? "true" : "false");
        if (st->have_apower) {
            rw_jw_raw(&w, ",");
            rw_jw_key(&w, "apower_w");
            rw_jw_milli(&w, st->apower_mw);
        }
        if (st->have_voltage) {
            rw_jw_raw(&w, ",");
            rw_jw_key(&w, "voltage");
            rw_jw_milli(&w, st->voltage_mv);
        }
        if (st->have_energy) {
            rw_jw_raw(&w, ",");
            rw_jw_key(&w, "energy_wh");
            rw_jw_milli(&w, st->energy_mwh);
        }
    }
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

static void send_plug_scan_err(const char *req_id, const char *err) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "plug_scan_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "false");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "err");
    rw_jw_str(&w, err);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

/* What rw_shelly_json_plugs() must leave room for: `,"truncated":false}` and the terminator
 * the writer keeps back — the SCAN_TAIL_RESERVE arrangement, priced for the same tail. */
#define PLUG_TAIL_RESERVE 20

/*
 * Sweep for plugs and answer. Runs from the main loop like run_scan(), and blocks longer:
 * the ARP pass, then an HTTP `GET /shelly` to everything that answered. §5 gives it thirty
 * seconds of a relay's patience, which the two budgets stay comfortably inside.
 */
static void run_plug_scan(const char *req_id) {
    static rw_shelly_plug_t plugs[RW_PLUG_SCAN_MAX];

    const int count = rw_plug_scan(plugs, RW_PLUG_SCAN_MAX);
    if (count < 0) {
        send_plug_scan_err(req_id, "no_link");
        return;
    }

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "plug_scan_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "req_id");
    rw_jw_str(&w, req_id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, "true");
    rw_jw_raw(&w, ",");
    const bool all = rw_shelly_json_plugs(&w, plugs, count, PLUG_TAIL_RESERVE);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "truncated");
    rw_jw_raw(&w, all ? "false" : "true");
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    RW_LOG_INFO("proto: plug scan found %d plug(s)%s", count, all ? "" : ", list truncated");
    send_json(&w);
}

/* The plug driver's completion, on the main loop via rw_plug_task(). The ownership rule is
 * probe_report()'s: an outcome whose connection has gone is dropped, not misdelivered. */
static void plug_done(void *ctx, const rw_plug_outcome_t *outcome) {
    (void)ctx;
    if (!s.plug_owned || s.state != RW_RELAY_READY) {
        return;
    }
    s.plug_owned = false;
    if (s.plug_is_status) {
        send_plug_status_result(s.plug_req_id, outcome->ok, outcome->err, &outcome->st);
    } else {
        send_plug_result(s.plug_req_id, outcome->ok, outcome->err, outcome->state_on);
    }
}

/* Defined with the rest of the update frames, below; needed here because clearing the slot runs
 * from the main loop and both outcomes are answered from there. */
static void send_ota_reject(const char *id, const char *code);
static void ota_abandon(const char *code);

/*
 * Clear the slot the offer named, then accept it.
 *
 * Runs on the main loop: clearing half a megabyte holds interrupts off in 64 KB steps for a
 * couple of seconds in total, which is why it is not done in the frame handler that read the
 * offer. Nothing is streaming yet — the relay is waiting for this accept and arms no timeout for
 * it — so the silence costs nothing, which is the whole reason the erase belongs here rather
 * than in the middle of the transfer.
 */
static void run_ota_begin(void) {
    const rw_ota_status_t status = rw_ota_write_begin(&s.offer.header, s.offer.slot);
    if (status != RW_OTA_OK) {
        send_ota_reject(s.offer.id, rw_ota_status_str(status));
        return;
    }

    memset(&s.ota, 0, sizeof(s.ota));
    s.ota.receiving = true;
    s.ota.slot      = s.offer.slot;
    s.ota.total     = s.offer.header.payload_len;
    s.ota.started   = get_absolute_time();
    snprintf(s.ota.id, sizeof(s.ota.id), "%s", s.offer.id);
    snprintf(s.ota.version, sizeof(s.ota.version), "%s", s.offer.header.version);

    RW_LOG_INFO("ota: accepted %s (%lu bytes) into slot %u", s.ota.version,
                (unsigned long)s.ota.total, (unsigned)s.ota.slot);

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "ota_accept");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "id");
    rw_jw_str(&w, s.ota.id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "slot");
    rw_jw_int(&w, (long)s.ota.slot);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    if (!send_json(&w)) {
        ota_abandon("internal");
    }
}

/* ── Deferred command execution ────────────────────────────────────────────── */

static void probe_report(void *ctx, rw_probe_state_t state, uint32_t elapsed_s) {
    (void)ctx;
    if (!s.probe_owned || s.state != RW_RELAY_READY) {
        return;
    }
    const char *name = (state == RW_PROBE_UP)      ? "up"
                       : (state == RW_PROBE_TIMEOUT) ? "timeout"
                                                     : "waiting";
    send_probe_result_ok(s.probe_req_id, name, elapsed_s);
    if (state == RW_PROBE_UP || state == RW_PROBE_TIMEOUT) {
        s.probe_owned = false;
    }
}

static void run_pending(void) {
    switch (s.kind) {
        case PENDING_NONE:
            return;

        case PENDING_WAKE: {
            rw_wol_result_t res;
            rw_wol_status_t st = rw_wol_send(s.mac, s.repeat,
                                             (s.cfg->flags & RW_CFG_FLAG_WOL_UNICAST) != 0, &res);
            if (st == RW_WOL_OK) {
                if (s.hooks.on_wake_sent != NULL) {
                    s.hooks.on_wake_sent();
                }
                send_wake_result(s.req_id, true, NULL, &res);
            } else {
                send_wake_result(s.req_id, false,
                                 st == RW_WOL_ERR_NO_LINK ? "no_link" : "send_failed", &res);
            }
            break;
        }

        case PENDING_STATUS:
            send_status_result(s.req_id);
            break;

        case PENDING_PROBE:
            snprintf(s.probe_req_id, sizeof(s.probe_req_id), "%s", s.req_id);
            s.probe_owned = true;
            if (!rw_probe_start(s.mac, s.timeout_s, probe_report, NULL)) {
                s.probe_owned = false;
                send_probe_result_err(s.req_id, "busy");
            }
            break;

        case PENDING_SCAN:
            run_scan(s.req_id);
            break;

        case PENDING_PLUG_SCAN:
            run_plug_scan(s.req_id);
            break;

        case PENDING_PLUG_SET:
        case PENDING_PLUG_STATUS: {
            /* Started here, answered from plug_done() when the driver finishes — the probe
             * arrangement, because a cycle holds seconds of deliberate waiting that must not
             * happen inside run_pending(). */
            snprintf(s.plug_req_id, sizeof(s.plug_req_id), "%s", s.req_id);
            s.plug_is_status = (s.kind == PENDING_PLUG_STATUS);
            s.plug_owned     = true;
            const bool started =
                s.plug_is_status
                    ? rw_plug_status_start(s.mac, &s.plug_ip, s.plug_channel, plug_done, NULL)
                    : rw_plug_set_start(s.mac, &s.plug_ip, s.plug_channel, s.plug_action,
                                        s.plug_off_ms, plug_done, NULL);
            if (!started) {
                /* The driver is still finishing something — an orphaned cycle restoring its
                 * power survives reconnections by design. */
                s.plug_owned = false;
                if (s.plug_is_status) {
                    send_plug_status_result(s.req_id, false, "busy", NULL);
                } else {
                    send_plug_result(s.req_id, false, "busy", false);
                }
            }
            break;
        }

        case PENDING_OTA_BEGIN:
            run_ota_begin();
            break;
    }
    s.kind = PENDING_NONE;
}

/*
 * Queue a command. Returns false when one is already running, which the caller answers with
 * `busy` — PROTOCOL.md §6 has the code for exactly this, and running two at once would mean
 * two answers carrying one req_id.
 */
static bool queue(pending_kind_t kind, const char *req_id) {
    if (s.kind != PENDING_NONE) {
        return false;
    }
    s.kind = kind;
    snprintf(s.req_id, sizeof(s.req_id), "%s", req_id);
    return true;
}

/* ── Inbound frame handling ────────────────────────────────────────────────── */

static void fail_auth(const char *why) {
    RW_LOG_ERROR("proto: %s", why);
    set_state(RW_RELAY_AUTH_FAILED);
    rw_ws_close(&s.ws, RW_WS_CLOSE_POLICY, "auth");
}

/*
 * May this device send `enrol`? PROTOCOL.md §3.1's two rules, and they live here because the
 * relay cannot check either of them — only the device knows how it connected.
 *
 * 1. The certificate must have been validated. A build with verification disabled, or a
 *    configuration that turns it off, would be handing its token to whatever answered the socket.
 * 2. The relay URL must be the one compiled into this firmware. A device pointed somewhere else
 *    is a self-hosted device, and its operator adds the token to their own relay by hand — which
 *    is exactly why self-hosting is unaffected by any of this.
 */
static bool may_enrol(void) {
    if (s.cfg->flags & RW_CFG_FLAG_TLS_INSECURE) {
        RW_LOG_WARN("proto: not enrolling - certificate verification is disabled");
        return false;
    }
#ifdef RW_TLS_INSECURE
    RW_LOG_WARN("proto: not enrolling - this build does not verify certificates");
    return false;
#else
    if (s.cfg->relay_url[0] != '\0' && strcmp(s.cfg->relay_url, RW_DEFAULT_RELAY_URL) != 0) {
        RW_LOG_INFO("proto: not enrolling - relay URL is not the built-in one");
        return false;
    }
    return true;
#endif
}

static void handle_challenge(const char *js, const jsmntok_t *tok, int count) {
    if (s.state != RW_RELAY_AUTHENTICATING) {
        return; /* unexpected here; §2 says ignore rather than error */
    }
    int idx = rw_json_find(js, tok, count, "nonce_s");
    char nonce_s[RW_NONCE_HEX + 1];
    if (idx < 0 || !rw_json_str(js, &tok[idx], nonce_s, sizeof(nonce_s)) ||
        strlen(nonce_s) != RW_NONCE_HEX) {
        fail_auth("challenge carried no usable nonce_s");
        return;
    }

    /*
     * §3.2: which frame goes here is decided by whether this device has ever been accepted, and
     * by nothing else. Deciding from a rejection instead — trying `auth`, then `enrol` when it
     * fails — is how a device whose record was displaced would talk its way back over the top of
     * whoever holds it now.
     */
    if (s.cfg->flags & RW_CFG_FLAG_ENROLLED) {
        if (!send_auth(nonce_s)) {
            fail_auth("could not send auth");
        }
        return;
    }

    if (!may_enrol()) {
        fail_auth("never enrolled, and enrolment is not permitted on this connection");
        return;
    }
    RW_LOG_INFO("proto: first contact - enrolling");
    s.enrolling = true;
    if (!send_enrol(nonce_s)) {
        fail_auth("could not send enrol");
    }
}

static void handle_hello_ack(const char *js, const jsmntok_t *tok, int count) {
    int ok_idx = rw_json_find(js, tok, count, "ok");
    if (ok_idx < 0 || !rw_json_is_true(js, &tok[ok_idx])) {
        char err[24] = "auth";
        int  e       = rw_json_find(js, tok, count, "err");
        if (e >= 0) {
            rw_json_str(js, &tok[e], err, sizeof(err));
        }
        RW_LOG_ERROR("proto: relay rejected us (%s)", err);
        set_state(RW_RELAY_AUTH_FAILED);
        rw_ws_close(&s.ws, RW_WS_CLOSE_POLICY, "rejected");
        return;
    }

    int  ps_idx = rw_json_find(js, tok, count, "proof_s");
    char proof_s[RW_PROOF_HEX + 1] = {0};
    if (ps_idx < 0 || !rw_json_str(js, &tok[ps_idx], proof_s, sizeof(proof_s))) {
        fail_auth("hello_ack carried no proof_s");
        return;
    }
    /* PROTOCOL.md §3.3: an unverifiable proof_s means close 1008 immediately, send nothing
     * further, and back off. A device that keeps talking to a relay that cannot prove it holds
     * the token is a device that will do whatever that relay asks. */
    if (!rw_auth_verify_proof(s.expected_proof_s, proof_s)) {
        fail_auth("proof_s did not verify - this endpoint does not hold our token");
        return;
    }

    /* `now` is a cross-check only. By the time this frame arrives the certificate has already
     * been accepted, so using it for validity would be theatre (PROTOCOL.md §5). */
    int now_idx = rw_json_find(js, tok, count, "now");
    long now_s;
    if (now_idx >= 0 && rw_json_int(js, &tok[now_idx], &now_s) && rw_wallclock_valid()) {
        long drift = (long)rw_wallclock_now() - now_s;
        if (drift > 300 || drift < -300) {
            RW_LOG_WARN("proto: local clock differs from the relay by %lds", drift);
        }
    }

    RW_LOG_INFO("proto: authenticated");
    set_state(RW_RELAY_READY);

    /* The image has now done the one thing a broken update cannot: reached us. If it was on
     * trial, that trial is over. */
    rw_ota_confirm_running_image();
    /* PROTOCOL.md §8: the reset happens here and nowhere earlier. A relay that accepts TCP and
     * rejects at auth would otherwise be hammered at one-second intervals for ever. */
    s.backoff_ms = RW_RELAY_BACKOFF_MIN_MS;
    s.next_ping  = make_timeout_time_ms(RW_RELAY_PING_INTERVAL_MS);
    /* Armed from the moment the link is live. Without this the silence timer would still hold
     * whatever the previous connection left in it — or, on the first connection of a boot, a zero
     * that reads as "silent since the epoch" and tears the link down immediately. */
    s.last_rx = get_absolute_time();

    /*
     * Enrolment is only complete once `proof_s` has verified, which is why the flag is set here
     * and not when `enrol` was sent. The relay returning a proof keyed with the token it stored
     * is the device's only evidence that the right bytes landed; recording success any earlier
     * would mean a corrupted store left a device that never tries to enrol again.
     */
    if (s.enrolling) {
        s.enrolling = false;
        RW_LOG_INFO("proto: enrolled");
        s.cfg->flags |= RW_CFG_FLAG_ENROLLED;
        s.persist_pending = true;
    }

    /*
     * Offer the account address, if the setup page left one. Once per connection, and only while
     * unacknowledged — see PROTOCOL.md §4 `adopt`.
     */
    if (s.cfg->owner_email[0] != '\0') {
        if (!send_adopt()) {
            RW_LOG_WARN("proto: could not send adopt; will retry on the next connection");
        }
    }
}

/*
 * PROTOCOL.md §5 `adopt_ack`. Either state means the same thing to us: the service has taken
 * responsibility for the request, so stop offering and forget the address.
 *
 * Erasing it is not tidiness. It is a person's email sitting in the flash of a device that may be
 * resold, and it has no further use — the binding it asked for either happened or is now the
 * service's to chase.
 */
static void handle_adopt_ack(const char *js, const jsmntok_t *tok, int count) {
    int ok_idx = rw_json_find(js, tok, count, "ok");
    if (ok_idx < 0 || !rw_json_is_true(js, &tok[ok_idx])) {
        char err[24] = "internal";
        int  e       = rw_json_find(js, tok, count, "err");
        if (e >= 0) {
            rw_json_str(js, &tok[e], err, sizeof(err));
        }
        /* Not retried on this connection: §5 says so, and an address the relay called malformed
         * will not become well-formed by being sent again. It stays in flash so the next
         * connection tries once more, and a factory reset is how a person corrects it. */
        RW_LOG_WARN("proto: adoption refused (%s)", err);
        return;
    }

    char state[16] = "";
    int  st        = rw_json_find(js, tok, count, "state");
    if (st >= 0) {
        rw_json_str(js, &tok[st], state, sizeof(state));
    }
    RW_LOG_INFO("proto: adoption acknowledged (%s)", state[0] ? state : "bound");
    s.cfg->owner_email[0] = '\0';
    s.persist_pending     = true;
}

/*
 * PROTOCOL.md §5: `mac` is required. There is no stored list to fall back to and no way to
 * guess which machine was meant, so a frame without one is a missing required field — which §6
 * spells `bad_frame` — rather than a request to be interpreted.
 *
 * The frame is also the only place a MAC now enters the device, so §2's wakeable-address rule
 * is enforced here. A group or broadcast address is not an interface: sending to one succeeds
 * at every layer and wakes nothing, which reports `ok:true, sent:12` for a wake that could
 * never have worked — the least debuggable answer available.
 */
static void handle_wake(const char *js, const jsmntok_t *tok, int count, const char *req_id) {
    uint8_t mac[6];
    int     mac_idx = rw_json_find(js, tok, count, "mac");

    if (mac_idx < 0) {
        send_wake_result(req_id, false, "bad_frame", NULL);
        return;
    }
    char text[32];
    if (!rw_json_str(js, &tok[mac_idx], text, sizeof(text)) || !rw_mac_parse(text, mac) ||
        !rw_mac_wakeable(mac)) {
        send_wake_result(req_id, false, "bad_mac", NULL);
        return;
    }

    long repeat = RW_WOL_BURSTS_DEFAULT;
    int  r_idx  = rw_json_find(js, tok, count, "repeat");
    if (r_idx >= 0 && !rw_json_int(js, &tok[r_idx], &repeat)) {
        repeat = RW_WOL_BURSTS_DEFAULT;
    }
    /* §5: clamp, do not reject. */
    if (repeat < RW_WOL_BURSTS_MIN) {
        repeat = RW_WOL_BURSTS_MIN;
    } else if (repeat > RW_WOL_BURSTS_MAX) {
        repeat = RW_WOL_BURSTS_MAX;
    }

    if (!rw_net_ready()) {
        send_wake_result(req_id, false, "no_link", NULL);
        return;
    }
    if (!queue(PENDING_WAKE, req_id)) {
        send_wake_result(req_id, false, "busy", NULL);
        return;
    }
    memcpy(s.mac, mac, 6);
    s.repeat = (int)repeat;
}

/*
 * `mac` is required here on the same terms as `wake`, and is held to §2's wakeable-address rule
 * for a further reason: a probe resolves the address by ARP, and no group address is ever an
 * ARP result, so watching for one is watching for something that cannot arrive.
 */
static void handle_probe(const char *js, const jsmntok_t *tok, int count, const char *req_id) {
    int     mac_idx = rw_json_find(js, tok, count, "mac");
    uint8_t mac[6];
    if (mac_idx < 0) {
        send_probe_result_err(req_id, "bad_frame");
        return;
    }
    char text[32];
    if (!rw_json_str(js, &tok[mac_idx], text, sizeof(text)) || !rw_mac_parse(text, mac) ||
        !rw_mac_wakeable(mac)) {
        send_probe_result_err(req_id, "bad_mac");
        return;
    }

    long timeout_s = 90;
    int  t_idx     = rw_json_find(js, tok, count, "timeout_s");
    if (t_idx >= 0 && !rw_json_int(js, &tok[t_idx], &timeout_s)) {
        timeout_s = 90;
    }

    if (!queue(PENDING_PROBE, req_id)) {
        send_probe_result_err(req_id, "busy");
        return;
    }
    memcpy(s.mac, mac, 6);
    s.timeout_s = (uint32_t)(timeout_s < 0 ? 0 : timeout_s);
}

/* ── Plug commands ─────────────────────────────────────────────────────────── */

/*
 * The fields `plug_set` and `plug_status` share: the plug's identity and where it was last
 * seen. `mac` and `ip` are both required — the MAC because it is the identity a re-resolve
 * recovers by, the IP because a sweep per command would put seconds of ARP traffic in front
 * of every status read. A MAC that parses but could never be a device's own — group,
 * broadcast, all-zero — is `bad_mac` on the same grounds as `wake`'s rule: a plug has a
 * unicast address or it does not exist.
 */
static bool parse_plug_target(const char *js, const jsmntok_t *tok, int count, uint8_t mac[6],
                              ip4_addr_t *ip, int *channel, const char **err) {
    int mac_idx = rw_json_find(js, tok, count, "mac");
    if (mac_idx < 0) {
        *err = "bad_frame";
        return false;
    }
    char text[32];
    if (!rw_json_str(js, &tok[mac_idx], text, sizeof(text)) || !rw_mac_parse(text, mac) ||
        !rw_mac_wakeable(mac)) {
        *err = "bad_mac";
        return false;
    }

    int ip_idx = rw_json_find(js, tok, count, "ip");
    if (ip_idx < 0 || !rw_json_str(js, &tok[ip_idx], text, sizeof(text)) ||
        !ip4addr_aton(text, ip)) {
        /* Missing and unparseable land together: there is no bad_ip code, and both mean the
         * caller failed to name where it last saw the plug. */
        *err = "bad_frame";
        return false;
    }

    /* §5: absent means channel 0, out of range is clamped. Almost everything is a
     * single-channel plug; the field exists for the DIN and PDU shapes. */
    long ch     = 0;
    int  ch_idx = rw_json_find(js, tok, count, "channel");
    if (ch_idx >= 0 && !rw_json_int(js, &tok[ch_idx], &ch)) {
        ch = 0;
    }
    if (ch < 0) {
        ch = 0;
    } else if (ch > 7) {
        ch = 7;
    }
    *channel = (int)ch;
    return true;
}

static void handle_plug_set(const char *js, const jsmntok_t *tok, int count, const char *req_id) {
    uint8_t     mac[6];
    ip4_addr_t  ip;
    int         channel;
    const char *err;
    if (!parse_plug_target(js, tok, count, mac, &ip, &channel, &err)) {
        send_plug_result(req_id, false, err, false);
        return;
    }

    /*
     * `state` follows `power.action`'s rule, not `wake.repeat`'s: required, and never
     * defaulted, because there is no safe guess among "on", "off" and "cut this machine's
     * power and restore it" — a device that picked one would be choosing on behalf of a
     * caller who failed to say.
     */
    rw_plug_action_t action;
    int              st_idx = rw_json_find(js, tok, count, "state");
    if (st_idx < 0) {
        send_plug_result(req_id, false, "bad_frame", false);
        return;
    }
    if (rw_json_eq(js, &tok[st_idx], "on")) {
        action = RW_PLUG_ON;
    } else if (rw_json_eq(js, &tok[st_idx], "off")) {
        action = RW_PLUG_OFF;
    } else if (rw_json_eq(js, &tok[st_idx], "cycle")) {
        action = RW_PLUG_CYCLE;
    } else {
        send_plug_result(req_id, false, "bad_frame", false);
        return;
    }

    /* §5: clamp, do not reject — the floor is a safety property (a cut that does not outlast
     * the PSU's hold-up capacitors is not a cut), the ceiling a liveness one. */
    long off_ms = RW_PLUG_OFF_MS_DEFAULT;
    int  o_idx  = rw_json_find(js, tok, count, "off_ms");
    if (o_idx >= 0 && !rw_json_int(js, &tok[o_idx], &off_ms)) {
        off_ms = RW_PLUG_OFF_MS_DEFAULT;
    }
    if (off_ms < RW_PLUG_OFF_MS_MIN) {
        off_ms = RW_PLUG_OFF_MS_MIN;
    } else if (off_ms > RW_PLUG_OFF_MS_MAX) {
        off_ms = RW_PLUG_OFF_MS_MAX;
    }

    if (!rw_net_ready()) {
        send_plug_result(req_id, false, "no_link", false);
        return;
    }
    /* Refused before any socket exists. The driver speaks plain unauthenticated HTTP wherever
     * it is pointed, so an address off this device's own subnet is not a stale hint to chase
     * — it is a request to be an HTTP client somewhere this protocol has no business, and it
     * is answered like any other field that could never legitimately be meant. */
    if (!rw_plug_ip_local(&ip)) {
        send_plug_result(req_id, false, "bad_frame", false);
        return;
    }
    if (s.plug_owned || rw_plug_busy() || !queue(PENDING_PLUG_SET, req_id)) {
        send_plug_result(req_id, false, "busy", false);
        return;
    }
    memcpy(s.mac, mac, 6);
    s.plug_ip      = ip;
    s.plug_channel = channel;
    s.plug_action  = action;
    s.plug_off_ms  = (uint32_t)off_ms;
}

static void handle_plug_status(const char *js, const jsmntok_t *tok, int count,
                               const char *req_id) {
    uint8_t     mac[6];
    ip4_addr_t  ip;
    int         channel;
    const char *err;
    if (!parse_plug_target(js, tok, count, mac, &ip, &channel, &err)) {
        send_plug_status_result(req_id, false, err, NULL);
        return;
    }
    if (!rw_net_ready()) {
        send_plug_status_result(req_id, false, "no_link", NULL);
        return;
    }
    if (!rw_plug_ip_local(&ip)) {
        send_plug_status_result(req_id, false, "bad_frame", NULL);
        return;
    }
    if (s.plug_owned || rw_plug_busy() || !queue(PENDING_PLUG_STATUS, req_id)) {
        send_plug_status_result(req_id, false, "busy", NULL);
        return;
    }
    memcpy(s.mac, mac, 6);
    s.plug_ip      = ip;
    s.plug_channel = channel;
}

/* ── Updates ───────────────────────────────────────────────────────────────── */
/*
 * An update arrives over this connection and no other. A second TLS session does not fit — one
 * already costs 44 KB of the 64 KB lwIP heap — and the image is half a megabyte, so nothing is
 * buffered: bytes go from the socket into flash as they arrive.
 *
 * The relay offers the signed 128-byte header on its own, hex-encoded in a text frame.
 * Everything that decides whether the image is wanted is in those bytes and is covered by the
 * signature: the board it was built for, its length, its version, and the digest of the payload.
 * There is deliberately no second, unsigned copy of any of it in the offer, because the copy is
 * what a relay would have to lie in for the device to start writing something it should not.
 *
 * If the device accepts, the payload follows as binary frames, in order, and the digest the
 * header committed to is what proves the stream arrived whole.
 */

/* 128 header bytes as hex, plus the terminator. */
#define OTA_HDR_HEX (RW_OTA_HEADER_LEN * 2)

static void send_ota_reject(const char *id, const char *code) {
    RW_LOG_WARN("ota: offer refused (%s)", code);
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "ota_reject");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "id");
    rw_jw_str(&w, id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "err");
    rw_jw_str(&w, code);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

static void send_ota_result(bool ok, const char *code) {
    long ms = (long)(absolute_time_diff_us(s.ota.started, get_absolute_time()) / 1000);

    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "ota_result");
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "id");
    rw_jw_str(&w, s.ota.id);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ok");
    rw_jw_raw(&w, ok ? "true" : "false");
    if (!ok) {
        rw_jw_raw(&w, ",");
        rw_jw_key(&w, "err");
        rw_jw_str(&w, code);
    }
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "bytes");
    rw_jw_int(&w, (long)s.ota.got);
    rw_jw_raw(&w, ",");
    rw_jw_key(&w, "ms");
    rw_jw_int(&w, ms);
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);
    send_json(&w);
}

static void ota_abandon(const char *code) {
    rw_ota_write_abort();
    s.ota.receiving = false;
    s.ota.draining  = true;
    send_ota_result(false, code);
}

static void handle_ota_offer(const char *js, const jsmntok_t *tok, int count) {
    char id[REQ_ID_MAX] = {0};
    int  id_idx         = rw_json_find(js, tok, count, "id");
    if (id_idx < 0 || !rw_json_str(js, &tok[id_idx], id, sizeof(id)) || id[0] == '\0') {
        return; /* nothing to answer to */
    }

    /* Decoded straight out of the frame rather than copied to a local first. 256 characters is
     * an eighth of the stack this runs on, and the token already points at them. */
    int hdr_idx = rw_json_find(js, tok, count, "hdr");
    if (hdr_idx < 0 || tok[hdr_idx].end - tok[hdr_idx].start != OTA_HDR_HEX) {
        send_ota_reject(id, "bad_header");
        return;
    }

    uint8_t raw[RW_OTA_HEADER_LEN];
    if (!rw_hex_decode(js + tok[hdr_idx].start, OTA_HDR_HEX, raw, sizeof(raw))) {
        send_ota_reject(id, "bad_header");
        return;
    }

    if (s.ota.receiving || rw_ota_write_active()) {
        send_ota_reject(id, "busy");
        return;
    }
    /*
     * An image that has not yet confirmed itself must not be replaced. The slot it would be
     * written into holds the last image known to work, and overwriting that while the running
     * one is unproven leaves nothing to fall back to.
     */
    if (rw_ota_on_trial()) {
        send_ota_reject(id, "on_trial");
        return;
    }

    rw_ota_header_t header;
    rw_ota_status_t status = rw_ota_header_open(raw, sizeof(raw), RW_SLOT_PAYLOAD_MAX, &header);
    if (status != RW_OTA_OK) {
        send_ota_reject(id, rw_ota_status_str(status));
        return;
    }

    /* The version the relay is offering is the one already running. Accepting it would install a
     * copy of this firmware into the other slot and reboot into it, and the relay — offering on
     * the same rule — would do it again on the next connection. */
    if (strcmp(header.version, RW_FW_VERSION) == 0) {
        send_ota_reject(id, "same_version");
        return;
    }

    /*
     * Everything that can be judged from the header has been. What is left -- clearing the slot --
     * takes a couple of seconds of held interrupts and cannot run here: this is a network
     * callback, and the rule this file is built on is that nothing blocking runs inside one.
     * So it is queued, and `ota_accept` goes out after the slot is clear.
     */
    if (!queue(PENDING_OTA_BEGIN, id)) {
        send_ota_reject(id, "busy");
        return;
    }
    s.offer.header = header;
    s.offer.slot   = rw_ota_spare_slot();
    snprintf(s.offer.id, sizeof(s.offer.id), "%s", id);
}

static bool on_binary(rw_ws_client_t *ws, void *ctx, const uint8_t *data, size_t len) {
    (void)ws;
    (void)ctx;

    if (!s.ota.receiving) {
        /* Bytes nobody asked for. Returning false closes the connection, which is the right
         * answer: this is not an unknown frame type to be tolerated, it is a peer streaming into
         * a device that has not agreed to receive anything. */
        return s.ota.draining;
    }

    if (len > s.ota.total - s.ota.got) {
        ota_abandon("too_long");
        return true;
    }

    rw_ota_status_t status = rw_ota_write_chunk(data, len);
    if (status != RW_OTA_OK) {
        ota_abandon(rw_ota_status_str(status));
        return true;
    }
    s.ota.got += (uint32_t)len;

    if (s.ota.got < s.ota.total) {
        return true;
    }

    status = rw_ota_write_end();
    if (status != RW_OTA_OK) {
        ota_abandon(rw_ota_status_str(status));
        return true;
    }

    s.ota.receiving = false;
    s.ota.draining  = true;
    if (!rw_ota_stage_slot(s.ota.slot, s.ota.version)) {
        send_ota_result(false, "stage_failed");
        return true;
    }

    send_ota_result(true, NULL);
    /* The reboot happens on the main loop: the result frame is still in the send buffer, and a
     * relay that never learns the outcome would offer the same image again. */
    s.reboot_pending = true;
    return true;
}

static void on_text(rw_ws_client_t *ws, void *ctx, char *text, size_t len) {
    (void)ws;
    (void)ctx;

    /* Anything arriving proves the socket is alive, so the silence timer is stamped before the
     * frame is even looked at — including for frames this function goes on to ignore. */
    s.last_rx = get_absolute_time();

    /* §9: answered byte for byte, before anything else looks at the frame. This is the hot
     * path — one frame per device per 25 seconds — and the whole point is that it is cheap. */
    if (len == sizeof(k_ping_frame) - 1 && memcmp(text, k_ping_frame, len) == 0) {
        rw_ws_send_text(&s.ws, k_pong_frame, sizeof(k_pong_frame) - 1);
        return;
    }
    if (len == sizeof(k_pong_frame) - 1 && memcmp(text, k_pong_frame, len) == 0) {
        return; /* the stamp above is the whole point of a pong; there is nothing else to do */
    }

    jsmn_parser parser;
    jsmntok_t   tokens[MAX_TOKENS];
    jsmn_init(&parser);
    int count = jsmn_parse(&parser, text, len, tokens, MAX_TOKENS);
    if (count < 1 || tokens[0].type != JSMN_OBJECT) {
        RW_LOG_WARN("proto: unparseable frame discarded");
        return;
    }

    int t_idx = rw_json_find(text, tokens, count, "t");
    if (t_idx < 0) {
        return;
    }

    /* Frames that are part of the handshake first, because they are the only ones legal before
     * RW_RELAY_READY. */
    if (rw_json_eq(text, &tokens[t_idx], "challenge")) {
        handle_challenge(text, tokens, count);
        return;
    }
    if (rw_json_eq(text, &tokens[t_idx], "hello_ack")) {
        handle_hello_ack(text, tokens, count);
        return;
    }
    if (rw_json_eq(text, &tokens[t_idx], "adopt_ack")) {
        handle_adopt_ack(text, tokens, count);
        return;
    }

    if (s.state != RW_RELAY_READY) {
        /* A command before authentication completes is not trusted input. §2's "ignore
         * silently" applies: no error frame, no close. */
        return;
    }

    char req_id[REQ_ID_MAX] = {0};
    int  r_idx              = rw_json_find(text, tokens, count, "req_id");
    if (r_idx >= 0 && !rw_json_str(text, &tokens[r_idx], req_id, sizeof(req_id))) {
        req_id[0] = '\0';
    }

    if (rw_json_eq(text, &tokens[t_idx], "wake")) {
        if (req_id[0] == '\0') {
            return; /* nothing to answer to */
        }
        handle_wake(text, tokens, count, req_id);
    } else if (rw_json_eq(text, &tokens[t_idx], "status")) {
        if (req_id[0] == '\0') {
            return;
        }
        if (!queue(PENDING_STATUS, req_id)) {
            /* status has no error shape of its own; the relay's own timeout covers it, and
             * inventing a field would be a protocol change nobody agreed to. */
            RW_LOG_WARN("proto: status dropped, another command is running");
        }
    } else if (rw_json_eq(text, &tokens[t_idx], "probe")) {
        if (req_id[0] == '\0') {
            return;
        }
        handle_probe(text, tokens, count, req_id);
    } else if (rw_json_eq(text, &tokens[t_idx], "scan")) {
        if (req_id[0] == '\0') {
            return;
        }
        /* §5: a second scan while one is running is refused rather than queued. The sweep
         * already bounds itself in time; queueing turns one slow command into a backlog. */
        if (!queue(PENDING_SCAN, req_id)) {
            send_scan_result_err(req_id, "busy");
        }
    } else if (rw_json_eq(text, &tokens[t_idx], "plug_scan")) {
        if (req_id[0] == '\0') {
            return;
        }
        /* Refused rather than queued while anything plug-shaped runs, on `scan`'s grounds —
         * and additionally because the sweep and a live set/status would contend for the two
         * TCP pcbs that are the whole budget. */
        if (s.plug_owned || rw_plug_busy() || !queue(PENDING_PLUG_SCAN, req_id)) {
            send_plug_scan_err(req_id, "busy");
        }
    } else if (rw_json_eq(text, &tokens[t_idx], "plug_set")) {
        if (req_id[0] == '\0') {
            return;
        }
        handle_plug_set(text, tokens, count, req_id);
    } else if (rw_json_eq(text, &tokens[t_idx], "plug_status")) {
        if (req_id[0] == '\0') {
            return;
        }
        handle_plug_status(text, tokens, count, req_id);
    } else if (rw_json_eq(text, &tokens[t_idx], "ota_offer")) {
        /* Carries `id` rather than `req_id`: a transfer outlives the exchange that started it,
         * and the frames that follow are not answers to a request. */
        handle_ota_offer(text, tokens, count);
    }
    /* §2 and §10: any other `t` is ignored silently. Not logged as a failure, not answered
     * with an error — that is what makes additive protocol changes safe. */
}

static void on_open(rw_ws_client_t *ws, void *ctx) {
    (void)ws;
    (void)ctx;
    set_state(RW_RELAY_AUTHENTICATING);
    if (!send_hello()) {
        RW_LOG_ERROR("proto: could not send hello");
        rw_ws_abort(&s.ws, RW_WS_FAIL_LOCAL);
    }
}

static void on_close(rw_ws_client_t *ws, void *ctx, rw_ws_fail_t why, uint16_t close_code) {
    (void)ws;
    (void)ctx;

    /* Anything in flight belonged to a req_id on a connection that no longer exists. */
    s.kind = PENDING_NONE;
    if (s.probe_owned) {
        rw_probe_cancel();
        s.probe_owned = false;
    }
    if (s.plug_owned) {
        /* Cancelled, not killed: a cycle that has already cut power still restores it, and
         * only the reply is forfeit. See rw_plug_cancel(). */
        rw_plug_cancel();
        s.plug_owned = false;
    }
    if (s.ota.receiving) {
        /* Half an image is in the spare slot. That is safe — it is not the slot running, and
         * nothing points the loader at it — and the next offer starts again from the top rather
         * than resuming, because resuming means trusting an offset the relay supplies. */
        RW_LOG_WARN("ota: connection lost after %lu of %lu bytes", (unsigned long)s.ota.got,
                    (unsigned long)s.ota.total);
        rw_ota_write_abort();
    }
    memset(&s.ota, 0, sizeof(s.ota));

    if (why == RW_WS_FAIL_DEPROVISIONED || close_code == 4002) {
        /* §7: the only close code that means stop. Reconnecting for ever against a relay that
         * has revoked us is both useless and rude. */
        RW_LOG_ERROR("proto: deprovisioned by the relay; not reconnecting");
        set_state(RW_RELAY_STOPPED);
        return;
    }

    if (s.state == RW_RELAY_AUTH_FAILED || close_code == RW_WS_CLOSE_POLICY) {
        set_state(RW_RELAY_AUTH_FAILED);
    } else {
        set_state(RW_RELAY_BACKOFF);
    }

    uint32_t delay = (s.backoff_ms == 0) ? 0 : (get_rand_32() % s.backoff_ms);
    s.retry_at     = make_timeout_time_ms(delay);
    RW_LOG_INFO("proto: disconnected (close %u), retrying in %lu ms", close_code,
                (unsigned long)delay);

    s.backoff_ms = (s.backoff_ms > RW_RELAY_BACKOFF_MAX_MS / 2) ? RW_RELAY_BACKOFF_MAX_MS
                                                                : s.backoff_ms * 2;
}

static const rw_ws_callbacks_t k_ws_callbacks = {
    .on_open   = on_open,
    .on_text   = on_text,
    .on_binary = on_binary,
    .on_close  = on_close,
};

/* ── Public interface ──────────────────────────────────────────────────────── */

void rw_relay_init(rw_config_t *cfg, const rw_relay_hooks_t *hooks) {
    memset(&s, 0, sizeof(s));
    s.cfg        = cfg;
    s.hooks      = *hooks;
    s.backoff_ms = RW_RELAY_BACKOFF_MIN_MS;
    s.state      = RW_RELAY_OFFLINE;
    rw_ws_init();
    rw_log_set_sink(log_sink);
}

void rw_relay_start(void) {
    if (s.state == RW_RELAY_STOPPED) {
        return; /* 4002 is permanent until the device is reconfigured or rebooted */
    }
    s.enabled  = true;
    s.retry_at = get_absolute_time();
    if (s.state == RW_RELAY_OFFLINE) {
        set_state(RW_RELAY_BACKOFF);
    }
}

void rw_relay_stop(void) {
    s.enabled = false;
    rw_ws_abort(&s.ws, RW_WS_FAIL_LOCAL);
    set_state(RW_RELAY_OFFLINE);
}

void rw_relay_task(void) {
    rw_ws_task(&s.ws);
    rw_probe_task();
    /* Above the connection-state checks on purpose: an orphaned cycle finishes its restore
     * whatever the relay link is doing. */
    rw_plug_task();

    /* Deferred commands run here, on the main loop, where blocking is safe. */
    if (s.state == RW_RELAY_READY) {
        run_pending();
    }

    /*
     * Enrolment and adoption both change the stored configuration, and both are decided inside a
     * network callback where a flash write would stall the stack mid-frame. So the callback sets
     * a flag and the write happens here, on the main loop, where blocking is safe.
     *
     * A failure is logged and dropped rather than retried. Losing the enrolled flag costs one
     * redundant `enrol` on the next connection, which the relay accepts because the token still
     * matches; losing the erased address costs one redundant `adopt`, which is acknowledged
     * again. Neither is worth a retry loop against a flash chip that has just refused a write.
     */
    if (s.persist_pending) {
        s.persist_pending = false;
        if (s.hooks.save_config == NULL || !s.hooks.save_config(s.cfg)) {
            RW_LOG_WARN("proto: could not persist enrolment state; will re-offer next connection");
        }
    }

    /*
     * A slot has been written, verified and staged. Restart into it.
     *
     * The close is a courtesy the relay uses to distinguish an update taking effect from a device
     * that fell off the network, and the delay is what gets the closing handshake onto the wire:
     * rw_sys_reboot() arms the watchdog rather than resetting immediately, so the main loop keeps
     * running and lwIP keeps sending until it fires.
     */
    if (s.reboot_pending) {
        s.reboot_pending = false;
        RW_LOG_INFO("proto: restarting into the staged image");
        rw_ws_close(&s.ws, RW_WS_CLOSE_NORMAL, "updating");
        rw_sys_reboot(1500);
        return;
    }

    if (!s.enabled || s.state == RW_RELAY_STOPPED) {
        return;
    }

    if (s.state == RW_RELAY_READY) {
        /*
         * Checked before the ping is sent, so a socket that has been silent for three intervals
         * is torn down rather than given a fourth frame to swallow. See RW_RELAY_SILENCE_MS —
         * this is the only thing that notices a half-open connection, because sending into one
         * succeeds.
         */
        if (absolute_time_diff_us(s.last_rx, get_absolute_time()) >=
            (int64_t)RW_RELAY_SILENCE_MS * 1000) {
            RW_LOG_WARN("proto: relay silent for %d ms - dropping the link to reconnect",
                        RW_RELAY_SILENCE_MS);
            rw_ws_abort(&s.ws, RW_WS_FAIL_LOCAL);
            return;
        }
        if (time_reached(s.next_ping)) {
            s.next_ping = make_timeout_time_ms(RW_RELAY_PING_INTERVAL_MS);
            if (!rw_ws_send_text(&s.ws, k_ping_frame, sizeof(k_ping_frame) - 1)) {
                RW_LOG_WARN("proto: keepalive could not be sent");
                rw_ws_abort(&s.ws, RW_WS_FAIL_LOCAL);
            }
        }
        return;
    }

    if (s.state != RW_RELAY_BACKOFF && s.state != RW_RELAY_AUTH_FAILED) {
        return; /* a connection attempt is in flight */
    }
    /*
     * The socket has to be fully gone first. After a rejected `auth` the state is
     * RW_RELAY_AUTH_FAILED while the WebSocket is still in its closing handshake; connecting
     * again here would abort that socket and open a new one immediately, which is exactly the
     * one-second hammering PROTOCOL.md §8's backoff-reset rule exists to prevent.
     */
    if (s.ws.state != RW_WS_CLOSED) {
        return;
    }
    if (!time_reached(s.retry_at)) {
        return;
    }
    /* Nothing is attempted without an address and a clock: a TLS handshake against an unset
     * clock fails certificate validity every time and would burn the backoff for nothing. */
    if (!rw_net_ready()) {
        return;
    }
    if (s.cfg->device_id[0] == '\0' || s.cfg->token[0] == '\0') {
        return; /* unprovisioned; main.c runs setup mode instead */
    }

    const char *url = s.cfg->relay_url[0] != '\0' ? s.cfg->relay_url : RW_DEFAULT_RELAY_URL;
    set_state(RW_RELAY_CONNECTING);
    if (!rw_ws_connect(&s.ws, url, &k_ws_callbacks, NULL)) {
        set_state(RW_RELAY_BACKOFF);
        uint32_t delay = (s.backoff_ms == 0) ? 0 : (get_rand_32() % s.backoff_ms);
        s.retry_at     = make_timeout_time_ms(delay);
        s.backoff_ms   = (s.backoff_ms > RW_RELAY_BACKOFF_MAX_MS / 2) ? RW_RELAY_BACKOFF_MAX_MS
                                                                      : s.backoff_ms * 2;
    }
}

rw_relay_state_t rw_relay_state(void) {
    return s.state;
}

void rw_relay_ota_progress(bool *receiving, uint32_t *got, uint32_t *total) {
    if (receiving != NULL) {
        *receiving = s.ota.receiving;
    }
    if (got != NULL) {
        *got = s.ota.receiving ? s.ota.got : 0;
    }
    if (total != NULL) {
        *total = s.ota.receiving ? s.ota.total : 0;
    }
}

/*
 * The externally-visible name of a state, for any state rather than just the current one.
 *
 * Separate from rw_relay_state_name() because a stuck record carries the state the PREVIOUS boot
 * gave up in, and naming it with a function that reads `s.state` would report where the device is
 * now — which is, by construction, "connecting", every time.
 *
 * The mapping deliberately collapses pairs: AUTHENTICATING is part of connecting from the outside,
 * and STOPPED is an auth failure the device has decided not to retry. Callers get the four states
 * that mean something to a person, not the seven the machine has.
 */
static const char *relay_state_name_of(rw_relay_state_t state) {
    switch (state) {
        case RW_RELAY_OFFLINE:         return "idle";
        case RW_RELAY_BACKOFF:         return "backoff";
        case RW_RELAY_CONNECTING:      return "connecting";
        case RW_RELAY_AUTHENTICATING:  return "connecting";
        case RW_RELAY_READY:           return "connected";
        case RW_RELAY_AUTH_FAILED:     return "auth_failed";
        case RW_RELAY_STOPPED:         return "auth_failed";
    }
    return "idle";
}

const char *rw_relay_state_name(void) {
    return relay_state_name_of(s.state);
}

void rw_relay_set_last_stuck(const rw_stuck_record_t *rec) {
    s.last_stuck = *rec;
    s.have_last_stuck = true;
}
