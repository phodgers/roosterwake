/*
 * The Shelly half of the plug driver: everything that can be decided by looking at bytes.
 *
 * A smart plug is driven over plain local HTTP — Gen1 speaks a REST scheme
 * (`/relay/{ch}?turn=on`, `/status`), Gen2 and later speak JSON-RPC over `POST /rpc` — and
 * both generations identify themselves at `GET /shelly`. This file builds those requests and
 * reads their responses; it deliberately contains no socket, no lwIP type and no timing, so
 * the host tests can hold every parser here against captured device bodies.
 *
 * The plug is a third-party device on an unauthenticated local port, so every response is
 * treated as hostile input: bounded, parsed with the same jsmn discipline as relay frames,
 * and rejected rather than guessed at when it is not the shape a Shelly answers with.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef RW_SHELLY_H
#define RW_SHELLY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "proto/json.h"

/*
 * Ceiling on a response body. The two bodies this driver reads by design — `/shelly` and a
 * `Switch.GetStatus` result — are well under 1 KB, and a Gen1 `/status` sits around half of
 * this; anything larger is not a Shelly answering the question it was asked, and parsing an
 * unbounded body on a device with 264 KB of RAM is how a hostile LAN peer would take the
 * dongle down.
 */
#define RW_SHELLY_BODY_MAX 2048

/* Bounded copies of what a device says about itself. A Shelly model id is at most a dozen
 * characters ("SNPL-00112UK"); a Gen2 instance name is whatever its owner typed, truncated. */
#define RW_SHELLY_MODEL_LEN 24
#define RW_SHELLY_NAME_LEN  32

/* A firmware version, verbatim in the device's own dialect. Gen2 speaks plain "1.4.4"; Gen1
 * speaks a long build string ("20230913-112003/v1.14.0-gcb84623"), which sets this bound. */
#define RW_SHELLY_FW_LEN 64

/*
 * Split a raw HTTP/1.1 response into its status code and body.
 *
 * Minimal on purpose: the peer is a Shelly answering a request this driver built, so the only
 * shapes accepted are the ones such a device produces — a status line, headers, a blank line,
 * and a body delimited by Content-Length or by the connection closing (every request carries
 * `Connection: close`). A `Transfer-Encoding: chunked` response is refused rather than
 * de-chunked, and a body over RW_SHELLY_BODY_MAX or short of its declared Content-Length is
 * refused rather than truncated: a partial JSON body parses as garbage, not as a shorter truth.
 *
 * `resp` MUST be NUL-terminated at `resp + len` — the header scan reads C-string style within
 * a line. httpc.c terminates its buffer before handing it over; a test passes a C string.
 */
bool rw_shelly_http_split(const char *resp, size_t len, int *status, const char **body,
                          size_t *body_len);

/* What `GET /shelly` said. Both generations answer the path; the shape says which this is. */
typedef struct {
    int     gen;      /* 1, or the device's own figure for Gen2+ (2, 3, 4…) */
    uint8_t mac[6];   /* the device's own claim; the caller decides what to trust it against */
    char    model[RW_SHELLY_MODEL_LEN]; /* Gen1 `type`, Gen2+ `model` */
    char    name[RW_SHELLY_NAME_LEN];   /* Gen2+ `name`, falling back to `id`; empty on Gen1,
                                           whose name lives in `/settings` — a body too large
                                           to be worth a request per candidate in a sweep */
    int     channels; /* Gen1 `num_outputs`; 1 where the device does not say */
    char    fw[RW_SHELLY_FW_LEN];       /* Gen2+ `ver`, Gen1 `fw`, verbatim; best-effort —
                                           empty where the body offered neither, which is not
                                           a classification failure */
} rw_shelly_id_t;

/*
 * Classify a `/shelly` body. Returns false for anything that is not a Shelly of either
 * generation — which during a sweep is most of what answers port 80.
 */
bool rw_shelly_identify(const char *body, size_t len, rw_shelly_id_t *out);

/* ── Requests ─────────────────────────────────────────────────────────────────
 *
 * Each builder writes a complete HTTP/1.1 request — request line, Host, `Connection: close`,
 * and for the RPC a JSON body with its Content-Length — and returns its length, or 0 when it
 * does not fit. `host` is the dotted-quad the request is addressed to; Shellys ignore the
 * header's value but HTTP/1.1 requires its presence.
 */
size_t rw_shelly_req_identify(char *buf, size_t cap, const char *host);
size_t rw_shelly_req_set(char *buf, size_t cap, const char *host, int gen, int channel, bool on);
size_t rw_shelly_req_status(char *buf, size_t cap, const char *host, int gen, int channel);

/*
 * The firmware verbs. Gen1 keeps the whole standing at one endpoint — `GET /ota` reports it,
 * `GET /ota?update=true` orders the install — so `req_fw_info` is the only Gen1 check request.
 * Gen2+ splits the fact across two calls, both in the direct-path RPC form rather than the
 * `/rpc` envelope: `GET /rpc/Shelly.GetDeviceInfo` names the running build (`req_fw_info`) and
 * `GET /rpc/Shelly.CheckForUpdate` asks the device to ask its vendor (`req_fw_check`, Gen2+
 * only). Direct-path answers carry the payload bare, and a refusal is a non-200 — the shape
 * take_response() already reads — where the envelope would bury it in HTTP 200.
 *
 * `req_fw_update` orders the install: Gen1 `GET /ota?update=true`, Gen2+ `POST
 * /rpc/Shelly.Update {"stage":"stable"}` — direct-path again, deliberately, because
 * Shelly.Update's success answer is a bare JSON `null` with nothing to decode; the 200 IS the
 * acceptance.
 */
size_t rw_shelly_req_fw_info(char *buf, size_t cap, const char *host, int gen);
size_t rw_shelly_req_fw_check(char *buf, size_t cap, const char *host);
size_t rw_shelly_req_fw_update(char *buf, size_t cap, const char *host, int gen);

/*
 * The Wi-Fi signal read, Gen2+ only: `GET /rpc/Wifi.GetStatus`, direct-path like the firmware
 * verbs. Gen1 needs no request of its own — its `/status` states `wifi_sta.rssi` in the same
 * body the status parse already reads.
 */
size_t rw_shelly_req_wifi_status(char *buf, size_t cap, const char *host);

/*
 * One relay channel's state, with thousandths for the metering fields so no float crosses
 * this layer (see rw_jw_milli). A field the hardware does not meter is reported absent, not
 * zero: zero watts is a reading, and "this plug cannot read watts" must not impersonate it.
 * `rssi` is the plug's own Wi-Fi signal — a plain integer of dBm, not thousandths, because
 * the devices report whole decibels and a milli-dBm would be precision nobody measured.
 */
typedef struct {
    bool on;
    bool have_apower;
    bool have_voltage;
    bool have_energy;
    bool have_rssi;
    long apower_mw;   /* milliwatts */
    long voltage_mv;  /* millivolts */
    long energy_mwh;  /* milliwatt-hours; Gen1 counts watt-minutes and is converted here */
    long rssi;        /* dBm, e.g. -52 */
} rw_shelly_status_t;

/*
 * Parse the status response for `channel`: a Gen1 `/status` body (`relays[ch].ison`,
 * `meters[ch].power`, `meters[ch].total`) or a Gen2 `POST /rpc` envelope whose `result` is a
 * `Switch.GetStatus` (`output`, `apower`, `voltage`, `aenergy.total`). Returns false when the
 * body is not that shape, when the channel does not exist, or when the RPC answered with its
 * `error` member — all of which the caller reports as `plug_unsupported`.
 */
bool rw_shelly_parse_status(const char *body, size_t len, int gen, int channel,
                            rw_shelly_status_t *out);

/*
 * Parse a direct-path `Wifi.GetStatus` answer's top-level `rssi`
 * (`{"sta_ip":…,"status":"got ip","ssid":…,"rssi":-52,…}`). Returns false when the body is
 * not an object carrying an integer `rssi` — which the caller treats as "the device did not
 * say", never as a failed status.
 */
bool rw_shelly_parse_wifi_rssi(const char *body, size_t len, long *rssi);

/*
 * A plug's firmware standing, PROTOCOL.md §4 `plug_fw_check_result`'s three facts. `latest`
 * is present only when the vendor named something newer — never an echo of `current` — and
 * `has_update` is its own boolean because the DEVICE saw the vendor's answer and nobody
 * upstream did: a Gen1 `/ota` echoes `new_version` even when nothing is newer, and deriving
 * the flag by comparing version strings would re-learn that mistake one layer up.
 */
typedef struct {
    char current[RW_SHELLY_FW_LEN];
    char latest[RW_SHELLY_FW_LEN];
    bool has_update;
} rw_shelly_fw_t;

/*
 * Parse a Gen1 `/ota` report: `old_version` becomes `current`, `has_update` is the device's
 * own verdict, and `new_version` is repeated as `latest` only when that verdict is true.
 * Returns false when the body is not that shape.
 */
bool rw_shelly_parse_ota_report(const char *body, size_t len, rw_shelly_fw_t *out);

/*
 * Parse a direct-path `Shelly.GetDeviceInfo` answer's `ver` member. Returns false when the
 * body is not an object carrying it — a Gen2+ always does.
 */
bool rw_shelly_parse_device_ver(const char *body, size_t len, char *ver, size_t cap);

/*
 * Parse a direct-path `Shelly.CheckForUpdate` answer into `latest`/`has_update`, leaving
 * `current` untouched. An absent or empty `stable` member is Shelly's real up-to-date answer
 * — the reply to a current device is `{}` — so that parses as ok with `has_update` false;
 * only a body that is not an object at all returns false.
 */
bool rw_shelly_parse_update_check(const char *body, size_t len, rw_shelly_fw_t *out);

/*
 * Did a set request succeed, and did the reply state the relay's NEW state?
 *
 * The generations answer opposite halves of that question, and conflating them is the bug
 * this signature exists to prevent. Gen1 echoes the relay's state after the change —
 * `{"ison":true,…}` — so `*have_state`/`*state_on` report it and no further read is needed.
 * Gen2's `Switch.Set` answers `was_on`, the PREVIOUS state; echoing that as current would
 * report every successful `on` as `off`, so for Gen2 this only checks the RPC envelope
 * (whose `error` member is the one way a well-formed 200 is still a refusal), leaves
 * `*have_state` false, and the driver does a confirming `Switch.GetStatus` read.
 */
bool rw_shelly_parse_set(const char *body, size_t len, int gen, bool *have_state,
                         bool *state_on);

/* ── The scan list ────────────────────────────────────────────────────────────
 *
 * One discovered plug, every field already rendered, so that serialising needs no IP stack
 * and the arithmetic below is host-testable — the same arrangement as scan_json.h, for the
 * same reason: `plug_scan_result` is the second frame in the protocol whose natural size is
 * set by somebody else's network.
 */
typedef struct {
    char mac[18];  /* canonical form, from the ARP sweep — the address a re-resolve will use */
    char ip[16];
    char model[RW_SHELLY_MODEL_LEN];
    int  gen;
    char name[RW_SHELLY_NAME_LEN]; /* empty when the device offered none; omitted from JSON */
    int  channels;
    char fw[RW_SHELLY_FW_LEN];     /* best-effort, same omitted-when-empty rule as `name` */
} rw_shelly_plug_t;

/*
 * Append `"plugs":[…]` to `w`, dropping entries that do not fit. `reserve` is the number of
 * bytes left unwritten for what the caller still has to add after the array. Returns true when
 * every entry was written. Entries are written in the order given; unlike scan hosts there is
 * no preference rule, because every entry here already identified itself as a plug.
 */
bool rw_shelly_json_plugs(rw_jw_t *w, const rw_shelly_plug_t *plugs, int count, size_t reserve);

#endif /* RW_SHELLY_H */
