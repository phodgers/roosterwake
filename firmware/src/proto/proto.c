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
#include "net/net.h"
#include "proto/auth.h"
#include "proto/json.h"
#include "proto/probe.h"
#include "rw_log.h"
#include "sys/sys.h"
#include "sys/wallclock.h"
#include "wol/wol.h"
#include "ws/ws.h"

/* Frames are capped at 2048 bytes in both directions (PROTOCOL.md §1). */
#define OUT_MAX RW_WS_MAX_OUTBOUND

/*
 * Token budget for jsmn. The largest frame is `config_push` with eight targets: the outer
 * object, two scalar members, the targets array, and eight three-token objects with two
 * members each — about fifty. 128 leaves room for unknown fields a future relay adds, which
 * §2 requires us to tolerate rather than fail on.
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
    PENDING_CONFIG,
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

    pending_kind_t kind;
    char           req_id[REQ_ID_MAX];
    uint8_t        mac[6];
    int            repeat;
    uint32_t       timeout_s;
    rw_config_t    staged; /* config_push target list, applied on the main loop */

    char probe_req_id[REQ_ID_MAX];
    bool probe_owned; /* a probe belonging to the current connection is running */

    /* `enrol` was sent on this connection and its outcome is not yet known. */
    bool enrolling;
    /* A configuration change made in a network callback, to be written on the main loop. */
    bool persist_pending;

    char out[OUT_MAX];
} s;

/* ── Small helpers ─────────────────────────────────────────────────────────── */

static void set_state(rw_relay_state_t state) {
    s.state = state;
}

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

/* Write `"targets":[{"name":…,"mac":…},…]` from the live config. */
static void write_targets(rw_jw_t *w) {
    rw_jw_key(w, "targets");
    rw_jw_raw(w, "[");
    for (uint8_t i = 0; i < s.cfg->target_count; i++) {
        if (i > 0) {
            rw_jw_raw(w, ",");
        }
        char mac[18];
        rw_mac_format(s.cfg->targets[i].mac, mac);
        rw_jw_raw(w, "{");
        rw_jw_key(w, "name");
        rw_jw_str(w, s.cfg->targets[i].name);
        rw_jw_raw(w, ",");
        rw_jw_key(w, "mac");
        rw_jw_str(w, mac);
        rw_jw_raw(w, "}");
    }
    rw_jw_raw(w, "]");
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
    rw_jw_key(&w, "caps");
    rw_jw_raw(&w, RW_CAPS_JSON);
    rw_jw_raw(&w, ",");
    write_targets(&w);
    /*
     * No account information here. An earlier build carried a claim code on every `hello`, which
     * PROTOCOL.md never defined and no relay ever read. Binding is now its own frame, sent after
     * the handshake and acknowledged — which is what the claim field could not do, and why it
     * would have gone on being re-offered for the life of the device.
     */
    rw_jw_raw(&w, "}");
    rw_jw_finish(&w);

    return send_json(&w);
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
    rw_jw_raw(&w, ",");
    write_targets(&w);
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

static void send_config_ack(const char *req_id, bool ok, const char *err, int targets) {
    rw_jw_t w;
    rw_jw_init(&w, s.out, sizeof(s.out));
    rw_jw_raw(&w, "{");
    rw_jw_key(&w, "t");
    rw_jw_str(&w, "config_ack");
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
    rw_jw_key(&w, "targets");
    rw_jw_int(&w, targets);
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

        case PENDING_CONFIG: {
            uint8_t count = s.staged.target_count;
            memcpy(s.cfg->targets, s.staged.targets, sizeof(s.cfg->targets));
            s.cfg->target_count = count;

            bool saved = s.hooks.save_config != NULL && s.hooks.save_config(s.cfg);
            send_config_ack(s.req_id, saved, saved ? NULL : "internal", count);
            break;
        }
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
    /* PROTOCOL.md §8: the reset happens here and nowhere earlier. A relay that accepts TCP and
     * rejects at auth would otherwise be hammered at one-second intervals for ever. */
    s.backoff_ms = RW_RELAY_BACKOFF_MIN_MS;
    s.next_ping  = make_timeout_time_ms(RW_RELAY_PING_INTERVAL_MS);

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

static void handle_wake(const char *js, const jsmntok_t *tok, int count, const char *req_id) {
    uint8_t mac[6];
    int     mac_idx = rw_json_find(js, tok, count, "mac");

    if (mac_idx >= 0) {
        char text[32];
        if (!rw_json_str(js, &tok[mac_idx], text, sizeof(text)) || !rw_mac_parse(text, mac)) {
            send_wake_result(req_id, false, "bad_mac", NULL);
            return;
        }
    } else if (s.cfg->target_count > 0) {
        memcpy(mac, s.cfg->targets[0].mac, 6);
    } else {
        send_wake_result(req_id, false, "no_target", NULL);
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

static void handle_probe(const char *js, const jsmntok_t *tok, int count, const char *req_id) {
    int mac_idx = rw_json_find(js, tok, count, "mac");
    uint8_t mac[6];
    if (mac_idx >= 0) {
        char text[32];
        if (!rw_json_str(js, &tok[mac_idx], text, sizeof(text)) || !rw_mac_parse(text, mac)) {
            send_probe_result_err(req_id, "bad_mac");
            return;
        }
    } else if (s.cfg->target_count > 0) {
        memcpy(mac, s.cfg->targets[0].mac, 6);
    } else {
        send_probe_result_err(req_id, "no_target");
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

static void handle_config_push(const char *js, const jsmntok_t *tok, int count,
                               const char *req_id) {
    /*
     * PROTOCOL.md §5 and §11: a relay must never push Wi-Fi credentials or a relay URL, and a
     * device must reject any attempt. Enforced by looking for the fields rather than by
     * trusting that they are absent — the point of the rule is that compromising a relay must
     * not let it reconfigure where devices connect or harvest what they connect to.
     */
    if (rw_json_find(js, tok, count, "ssid") >= 0 ||
        rw_json_find(js, tok, count, "psk") >= 0 ||
        rw_json_find(js, tok, count, "relay_url") >= 0 ||
        rw_json_find(js, tok, count, "token") >= 0) {
        RW_LOG_ERROR("proto: config_push tried to set local-only fields; rejected");
        send_config_ack(req_id, false, "bad_frame", s.cfg->target_count);
        return;
    }

    int arr = rw_json_find(js, tok, count, "targets");
    if (arr < 0 || tok[arr].type != JSMN_ARRAY) {
        send_config_ack(req_id, false, "bad_frame", s.cfg->target_count);
        return;
    }
    if (tok[arr].size > RW_CFG_MAX_TARGETS) {
        send_config_ack(req_id, false, "too_many", s.cfg->target_count);
        return;
    }

    rw_config_t staged = *s.cfg;
    memset(staged.targets, 0, sizeof(staged.targets));
    staged.target_count = 0;

    int idx = arr + 1;
    for (int i = 0; i < tok[arr].size; i++) {
        if (idx >= count || tok[idx].type != JSMN_OBJECT) {
            send_config_ack(req_id, false, "bad_frame", s.cfg->target_count);
            return;
        }
        /* The entry is a nested object, so rw_json_find (top-level only) cannot be used. Its
         * members are walked directly. */
        char name[RW_CFG_TARGET_NAME_LEN] = {0};
        char mac_text[32]                 = {0};
        int  member                       = idx + 1;
        for (int m = 0; m < tok[idx].size && member + 1 < count; m++) {
            const jsmntok_t *key = &tok[member];
            const jsmntok_t *val = &tok[member + 1];
            if (rw_json_eq(js, key, "name")) {
                if (!rw_json_str(js, val, name, sizeof(name))) {
                    send_config_ack(req_id, false, "bad_frame", s.cfg->target_count);
                    return;
                }
            } else if (rw_json_eq(js, key, "mac")) {
                if (!rw_json_str(js, val, mac_text, sizeof(mac_text))) {
                    send_config_ack(req_id, false, "bad_mac", s.cfg->target_count);
                    return;
                }
            }
            member = rw_json_skip(tok, count, member + 1);
        }

        if (name[0] == '\0') {
            send_config_ack(req_id, false, "bad_frame", s.cfg->target_count);
            return;
        }
        if (!rw_mac_parse(mac_text, staged.targets[i].mac)) {
            send_config_ack(req_id, false, "bad_mac", s.cfg->target_count);
            return;
        }
        snprintf(staged.targets[i].name, sizeof(staged.targets[i].name), "%s", name);
        staged.target_count++;
        idx = rw_json_skip(tok, count, idx);
    }

    if (!queue(PENDING_CONFIG, req_id)) {
        send_config_ack(req_id, false, "busy", s.cfg->target_count);
        return;
    }
    s.staged = staged;
}

static void on_text(rw_ws_client_t *ws, void *ctx, char *text, size_t len) {
    (void)ws;
    (void)ctx;

    /* §9: answered byte for byte, before anything else looks at the frame. This is the hot
     * path — one frame per device per 25 seconds — and the whole point is that it is cheap. */
    if (len == sizeof(k_ping_frame) - 1 && memcmp(text, k_ping_frame, len) == 0) {
        rw_ws_send_text(&s.ws, k_pong_frame, sizeof(k_pong_frame) - 1);
        return;
    }
    if (len == sizeof(k_pong_frame) - 1 && memcmp(text, k_pong_frame, len) == 0) {
        return; /* liveness is recorded by the transport */
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
    } else if (rw_json_eq(text, &tokens[t_idx], "config_push")) {
        if (req_id[0] == '\0') {
            return;
        }
        handle_config_push(text, tokens, count, req_id);
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
    .on_open  = on_open,
    .on_text  = on_text,
    .on_close = on_close,
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

    /* Deferred commands run here, on the main loop, where blocking is safe. */
    if (s.state == RW_RELAY_READY) {
        run_pending();
    }

    /*
     * Enrolment and adoption both change the stored configuration, and both are decided inside a
     * network callback where a flash write would stall the stack mid-frame. So the callback sets
     * a flag and the write happens here, exactly as `config_push` already does.
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

    if (!s.enabled || s.state == RW_RELAY_STOPPED) {
        return;
    }

    if (s.state == RW_RELAY_READY) {
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

const char *rw_relay_state_name(void) {
    switch (s.state) {
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
