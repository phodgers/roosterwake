# Remote Wake wire protocol

**Version 1** · Status: **stable** · Last changed: 2026-07-29

This document specifies the protocol between a Remote Wake device (the "dongle") and a relay.
It is the public contract. Our hosted service implements it, the reference relay in
[`relay-reference/`](relay-reference/) implements it, and any third-party firmware or relay
that implements it correctly will interoperate with both.

Two other documents complete the public surface, and are equally binding:
[`firmware/docs/usbcfg.md`](firmware/docs/usbcfg.md) (the USB serial command set) and
[`firmware/docs/config-format.md`](firmware/docs/config-format.md) (the flash config layout).

If you are implementing a relay, read §3 and §9 carefully — the keepalive design and the
authentication handshake are the two places where a reasonable-looking implementation can be
subtly wrong.

---

## 1. Transport

- **WebSocket over TLS** (`wss://`). Plain `ws://` is permitted only for loopback and
  RFC 1918 addresses, and firmware built for production refuses it otherwise.
- Default endpoint: `wss://relay.remotewake.com/ws`. Configurable per device; self-hosters
  point it wherever they like.
- **Subprotocol**: the client sends `Sec-WebSocket-Protocol: remotewake.v1`. A relay that
  understands this protocol MUST echo it. A relay that does not MUST omit the header, and the
  client MUST then close the connection — this is how a device detects that it has been
  pointed at something that is not a Remote Wake relay (a captive portal, a misconfigured
  reverse proxy, someone's Home Assistant) instead of hanging.
  Symmetrically, a relay MUST **refuse the upgrade** (HTTP 400) when the client does not offer
  `remotewake.v1`, rather than accepting the socket and waiting for a `hello` that will never
  come. Both halves are specified because leaving either undefined lets two conforming relays
  behave differently, and a third-party firmware then works against one and hangs against the
  other.
- **Frames are WebSocket text frames** containing a single JSON object. One object per frame;
  no framing of multiple objects, no newline delimiting.
- **Size limits.** **No frame in either direction may exceed 2048 bytes.** A receiver MUST
  reject a larger frame with close code `1009`. Devices are memory-constrained; this limit is
  a hard part of the contract, not a suggestion.
  The largest frame either side sends is `hello` with eight targets, and it does not come
  close: eight entries of a 24-character name plus a 17-character MAC is under 600 bytes, and
  the rest of the frame adds roughly 200 more. A single symmetric bound is easier to implement
  correctly than two, and lets both sides size one receive buffer.
- **Encoding** is UTF-8. Target names may contain any UTF-8; relays MUST NOT assume ASCII.

### 1.1 TLS requirements

- TLS 1.2 or better. Devices ship with a curated root bundle covering the common public CAs.
- **SNI is mandatory.** Relays behind virtual hosting (including ours, behind Cloudflare)
  cannot serve the right certificate without it.
- Certificate validity requires a wall clock. Devices SHOULD synchronise time by SNTP before
  the first connection attempt, and MUST NOT silently skip certificate expiry checks because
  the clock is unset.
- Firmware MAY offer a build-time option to trust a custom root or to skip verification, for
  homelab use with self-signed certificates. It MUST default to off and MUST make the state
  visible at runtime. Reference firmware flashes the error LED pattern continuously while
  verification is disabled.

---

## 2. Identifiers and value formats

| Field | Format |
|---|---|
| `device_id` | 16 lower-case hex characters (8 bytes). Derived from the board's unique ID at manufacture. Stable for the life of the device; survives factory reset. |
| `token` | 32 random bytes, 64 lower-case hex characters. Generated at provisioning. **Never transmitted** — see §3. |
| `mac` | Six octets, upper-case hex, colon-separated: `AA:BB:CC:DD:EE:FF`. Relays MUST accept lower-case and `-` separators on input and MUST normalise to this form on output. |
| `req_id` | Opaque string, 1–36 characters, unique per in-flight request from a given relay. UUIDv4 recommended. Devices echo it verbatim and MUST NOT parse it. |
| `name` | Target display name, 1–24 UTF-8 characters after trimming. |
| `nonce` | 16 random bytes, 32 lower-case hex characters. |

Unknown fields in any frame MUST be ignored. Unknown `t` values MUST be ignored silently —
not answered with an error, not logged as a failure. This is what makes additive protocol
changes safe (§10).

---

## 3. Connection lifecycle and authentication

Authentication is a **mutual challenge-response**. The device token is never sent over the
wire, in either direction, at any point.

### 3.1 Why it is done this way

An earlier draft had the device send its token in the `hello` frame and the relay prove
itself by returning an HMAC over a device nonce. That is simpler and one round trip shorter,
and it was rejected, because it means the device hands its long-lived bearer credential to
whatever answers the socket. That matters in three real situations:

- A device pointed at a hostile or compromised relay by a misconfigured `relay_url`.
- A homelab device built with certificate verification disabled, where a MITM is trivial.
- A relay operator who should be able to *verify* devices without being *able to impersonate*
  them elsewhere.

With challenge-response, a hostile endpoint learns nothing reusable. It can still relay
attacks in real time while the device is connected to it, which no amount of cleverness at
this layer fixes — but it cannot walk away with a credential that wakes someone's machine
for the next year. The cost is one extra round trip at connect. That is a good trade.

### 3.2 The handshake

```
 device                                                    relay
   │                                                         │
   │─ hello {v, device_id, nonce_c, fw, board, caps, targets}►│
   │                                                         │  look up device_id,
   │                                                         │  load token
   │◄─────────── challenge  {nonce_s} ───────────────────────│
   │                                                         │
   │  proof_c = HMAC(token, "rw1:c" ‖ device_id ‖ nc ‖ ns)    │
   │──────────────── auth  {proof_c} ───────────────────────►│
   │                                                         │  verify proof_c
   │                                                         │  (constant time)
   │◄──── hello_ack  {ok:true, proof_s, server, now} ────────│
   │                                                         │
   │  verify proof_s; only now is the link trusted           │
```

**Proof construction.** Both proofs are HMAC-SHA256 keyed with the **raw 32 token bytes**
(not the hex string), over the ASCII concatenation of a domain-separation tag, the
`device_id`, and both nonces in hex, in this exact order:

```
proof_c = HMAC-SHA256(token_bytes, "rw1:c" + device_id + nonce_c + nonce_s)
proof_s = HMAC-SHA256(token_bytes, "rw1:s" + device_id + nonce_c + nonce_s)
```

Transmitted as the **first 16 bytes**, lower-case hex (32 characters). The distinct `rw1:c`
and `rw1:s` tags are what stop a proof from one direction being replayed as the other.

**Both sides MUST compare in constant time.** A byte-by-byte early-exit comparison on the
relay leaks the expected proof to a patient attacker.

**Both nonces MUST be freshly random per connection**, from a real CSPRNG. Devices use the
RP2350 hardware TRNG. A relay that reuses `nonce_s`, or a device that reuses `nonce_c`,
breaks the replay protection for everyone.

### 3.3 Failure handling

- If the relay does not recognise `device_id`, it MUST still send a `challenge` with a random
  `nonce_s`, and fail at the `auth` step with `err: "auth"`. Failing early at `hello` turns
  the relay into an oracle for which device IDs exist. Implementations should back the unknown
  case with a throwaway random token so the two paths do the same HMAC work and take the same
  time, and should run the constant-time comparison *before* any "is this device provisioned"
  branch — otherwise short-circuit evaluation quietly reintroduces the oracle this rule exists
  to close.
- If `hello` is malformed — not valid JSON, or missing a required field — the relay replies
  `hello_ack {ok:false, err:"bad_frame"}` and closes with `1008`. It MUST NOT send a
  `challenge` first, because there is no usable `device_id` to challenge against.
  An **oversized** frame is not this case: the size check in §1 happens before any parse, so an
  over-limit `hello` is closed with `1009` like any other over-limit frame, without a
  `hello_ack`. A receiver cannot report a parse result for bytes it declined to read.
- On `auth` failure the relay sends `hello_ack {ok:false, err:"auth"}` and closes with `1008`.
- If the device cannot verify `proof_s`, it MUST close immediately with `1008`, MUST NOT send
  any further frames, and MUST back off before retrying (§8). It SHOULD surface the error
  locally — reference firmware shows the error LED pattern, because a device that silently
  retries against a hostile relay forever is worse than one that visibly fails.
- A relay MUST allow only **one live connection per `device_id`**. A successful new
  connection replaces the old one, which is closed with `4001` (§7). This makes recovery from
  a half-dead socket automatic rather than requiring a timeout to expire first.

---

## 4. Frames: device → relay

### `hello` — first frame on every connection

```json
{
  "t": "hello",
  "v": 1,
  "device_id": "a1b2c3d4e5f60718",
  "nonce_c": "9f86d081884c7d659a2feaa0c55ad015",
  "fw": "1.0.0",
  "board": "pico2_w",
  "caps": ["wake", "status", "probe"],
  "targets": [
    { "name": "Desktop", "mac": "AA:BB:CC:DD:EE:FF" }
  ]
}
```

`caps` declares what this firmware can do, so relays feature-detect rather than sniff version
numbers. A relay MUST NOT send a command whose capability the device did not advertise.

Defined capabilities, each naming the relay→device command it gates:

| Capability | Gates |
|---|---|
| `wake` | `wake` |
| `status` | `status` |
| `probe` | `probe` |
| `config` | `config_push` |
| `sched` | reserved for device-side scheduling; no command yet |

Unknown entries are ignored.

There is deliberately **no `log` capability**. Diagnostic logging is enabled locally by the
operator and there is no frame by which a relay could turn it on, so advertising it would tell
a relay something it cannot act on. Log frames may arrive from any device whose owner has
enabled diagnostics, and relays MAY discard them.

`targets` is the device's local view. On a claimed device the relay's view is authoritative
and is pushed back with `config_push` (§5).

### `auth`

```json
{ "t": "auth", "proof_c": "3f2a9c81b4e05d7602ff1a8c9d3e4b57" }
```

### `wake_result`

```json
{
  "t": "wake_result",
  "req_id": "8f14e45f-ea0b-4c1a-9f2d-6e3a7c1b5d90",
  "ok": true,
  "sent": 12,
  "ifaces": ["255.255.255.255:9", "192.168.1.255:9", "255.255.255.255:7", "192.168.1.255:7"]
}
```

`ifaces` lists every destination a datagram went to: the limited broadcast address and the
subnet-directed broadcast computed from the device's IP and netmask, each on ports 9 and 7.

**`sent` is exactly `ifaces.length × repeat`** — one datagram per destination per burst, with
`repeat` bursts 100 ms apart (§5, default 3). The example above is four destinations × three
bursts. This relationship is stated rather than left implied because `sent` is the number a
support conversation turns on, and a figure nobody can reproduce from the other fields is
worse than no figure: it looks authoritative and cannot be checked.

**These two fields carry most of the diagnostic value in this protocol.** The dominant
real-world failure is not that the device failed to send — it is that the packet never reached
the segment the target sits on. Twelve datagrams sent, with a subnet broadcast that does not
match the target's subnet, identifies that instantly and turns an unfalsifiable support ticket
into a five-second answer.

On failure: `{"t":"wake_result","req_id":"…","ok":false,"err":"no_link","sent":0,"ifaces":[]}`.

### `status_result`

```json
{
  "t": "status_result",
  "req_id": "…",
  "rssi": -52,
  "uptime_s": 84321,
  "ip": "192.168.1.42",
  "netmask": "255.255.255.0",
  "fw": "1.0.0",
  "reset_reason": "power_on",
  "targets": [{ "name": "Desktop", "mac": "AA:BB:CC:DD:EE:FF" }]
}
```

### `probe_result`

Sent in response to `probe`, and repeated as the probe progresses. `state` is one of
`waiting`, `up`, `timeout`.

```json
{ "t": "probe_result", "req_id": "…", "ok": true, "state": "up", "elapsed_s": 34, "method": "arp" }
```

`ok` is `false` when the probe could not be started at all, with `err` carrying a code from §6
and `state` omitted — a `probe` naming an unparseable MAC otherwise has nowhere to report
`bad_mac`, and would either be answered with a misleading `timeout` or silently dropped:

```json
{ "t": "probe_result", "req_id": "…", "ok": false, "err": "bad_mac" }
```

### `config_ack`

```json
{ "t": "config_ack", "req_id": "…", "ok": true, "targets": 2 }
```

### `pong`

Only in response to a relay-initiated `ping`. See §9 — this is **not** the device's own
keepalive.

### `log` — optional, opt-in

```json
{ "t": "log", "level": "warn", "msg": "join failed: badauth", "at_s": 421 }
```

Devices MUST NOT send `log` frames unless the operator has enabled diagnostics. Levels are
`debug`, `info`, `warn`, `error`. Relays MAY discard them.

---

## 5. Frames: relay → device

### `challenge`

```json
{ "t": "challenge", "nonce_s": "2c26b46b68ffc68ff99b453c1d304134" }
```

### `hello_ack`

```json
{
  "t": "hello_ack",
  "ok": true,
  "proof_s": "b1946ac92492d2347c6235b4d2611184",
  "server": "remotewake-relay/1.0",
  "now": 1785283200
}
```

`now` is relay wall-clock as a Unix timestamp. Devices MAY use it to sanity-check their SNTP
result. Devices MUST NOT use it *instead* of SNTP for certificate validation — by the time
this frame arrives, the certificate has already been accepted.

Rejection: `{ "t": "hello_ack", "ok": false, "err": "auth" }` followed by close `1008`.

### `wake`

```json
{ "t": "wake", "req_id": "…", "mac": "AA:BB:CC:DD:EE:FF", "repeat": 3 }
```

`repeat` is optional, 1–5, default 3 — the number of bursts. Devices MUST clamp out-of-range
values rather than rejecting the request.

If `mac` is omitted, the device wakes its **first configured target**. A device with no
configured targets replies `ok:false, err:"no_target"`.

### `status`

```json
{ "t": "status", "req_id": "…" }
```

### `probe`

```json
{ "t": "probe", "req_id": "…", "mac": "AA:BB:CC:DD:EE:FF", "timeout_s": 90 }
```

Asks the device to watch for the target coming up, by ARP resolution and optionally ICMP.
`timeout_s` is 10–300. The device sends `probe_result` on each state change and a final one
at resolution or timeout. Only sent to devices advertising the `probe` capability.

### `config_push`

```json
{
  "t": "config_push",
  "req_id": "…",
  "targets": [
    { "name": "Desktop", "mac": "AA:BB:CC:DD:EE:FF" },
    { "name": "NAS", "mac": "11:22:33:44:55:66" }
  ]
}
```

Replaces the device's target list wholesale — it is not a merge. Maximum 8 targets. The
device persists them to flash and replies `config_ack`. This is how a dashboard edit reaches
a device that was provisioned months ago.

Relays MUST NOT push Wi-Fi credentials or a relay URL. Those are local-only by design
(see §11) and a device MUST reject any attempt.

### `ping`

```json
{ "t": "ping" }
```

Relay-initiated liveness check. Devices reply `{"t":"pong"}` promptly. See §9 for why this
is the less important direction.

---

## 6. Error codes

Returned in `err` on `wake_result`, `hello_ack` and `config_ack`.

| Code | Meaning |
|---|---|
| `auth` | Authentication failed, or `device_id` unknown |
| `bad_frame` | Malformed JSON, missing required field, or frame too large |
| `bad_mac` | MAC address failed to parse |
| `no_target` | Wake requested with no MAC and no configured targets |
| `no_link` | Wi-Fi link down at the moment of the request |
| `send_failed` | The network stack refused the datagram |
| `busy` | A conflicting operation is already running |
| `unsupported` | Command names a capability this device did not advertise |
| `too_many` | `config_push` exceeded the target limit |
| `internal` | Anything else; the device or relay SHOULD log detail locally |

Error codes are a closed set for v1. New codes require a minor version bump, and receivers
MUST treat an unrecognised code as `internal` rather than failing.

---

## 7. Close codes

| Code | Meaning |
|---|---|
| `1000` | Normal shutdown |
| `1008` | Authentication failed or policy violation |
| `1009` | Frame exceeded the size limit |
| `1011` | Unexpected internal error |
| `4000` | Protocol version not supported by the relay |
| `4001` | Superseded — another connection authenticated for this `device_id` |
| `4002` | Device deprovisioned or token revoked. **The device SHOULD NOT retry**, and reference firmware surfaces the error LED pattern rather than reconnecting forever. |
| `4003` | Idle timeout — no frame received within the liveness window (§9) |

**`4002` MUST NOT be sent until the device's proof has verified.** Closing early — as soon as
the relay recognises a revoked `device_id` — turns the close code itself into an oracle: it
distinguishes "this ID exists but was revoked" from "this ID was never known", which is exactly
the distinction §3.3 goes to some trouble to hide. Complete the handshake, then close `4002`.

`4003` exists so that "you went quiet" is distinguishable from "you failed authentication".
Reusing `1008` for both would collide with the rule in §8 that backoff resets only after a
connection *completes authentication*: a device that could not tell the two apart would either
reset its backoff after an auth rejection, or fail to reset it after a healthy connection that
merely idled out.

`4002` is the only close code that means "stop trying". Everything else is retried with
backoff.

---

## 8. Reconnection

Devices reconnect automatically on any close except `4002`.

- Exponential backoff starting at **1 s**, doubling, capped at **60 s**.
- **Full jitter**: the actual delay is `random(0, computed_backoff)`. Without jitter, a relay
  restart brings every device on the planet back in the same second, and the resulting
  thundering herd looks exactly like the outage it is trying to recover from.
- The backoff resets to 1 s only after a connection **completes authentication**, not merely
  after TCP connects. A relay that accepts sockets and immediately rejects them at `auth`
  would otherwise be hammered at 1 s intervals indefinitely.
- Devices MUST NOT reboot to recover a connection. Reconnection is a normal state, not a
  fault, and a device that reboots itself loses its uptime record and any in-flight state.

---

## 9. Keepalive — read this if you are implementing a relay

**The device sends an application-level `{"t":"ping"}` text frame every 25 seconds and
expects `{"t":"pong"}` back.** Not a WebSocket control-frame ping. This is deliberate and it
is load-bearing.

Cloudflare Durable Objects — and equivalent serverless WebSocket runtimes — can hibernate a
socket that is idle, evicting it from memory while keeping the TCP connection alive, and can
answer a *specific text message* with a *specific text response* without waking the object.
A WebSocket control-frame ping does not qualify: it wakes the object on every heartbeat. With
one heartbeat per device per 25 seconds, that is the difference between a relay whose idle
cost rounds to zero and one that bills continuously for doing nothing.

Because the exact byte sequence matters to that mechanism, the keepalive frames are specified
**literally**, with no whitespace and no additional fields:

```
device → relay:   {"t":"ping"}
relay  → device:  {"t":"pong"}
```

A relay MUST answer with exactly that byte sequence. A relay MAY additionally send its own
`{"t":"ping"}` and expect `{"t":"pong"}`, but SHOULD NOT rely on it — the device-initiated
direction is the one that matters, because the device is the side behind NAT whose idle
connection a router will silently drop.

**Liveness.** A device that receives no frame of any kind for **75 seconds** (three missed
heartbeats) MUST treat the connection as dead, close it, and reconnect. Relays SHOULD apply a
similar rule, biased longer so that the device notices first and reconnects cleanly rather than
racing the relay's teardown.

**Relays should not arm a dedicated timer to enforce that.** A 90-second liveness alarm on a
hibernating object wakes it 960 times a day for the sole purpose of observing that nothing has
happened — which costs more than the heartbeats this section exists to make free. Check
liveness on a wake-up the relay was already going to have: a presence rollup, the next inbound
frame, or a command dispatch. A stale connection lingering for a few minutes costs nothing; it
holds no resource a live one would not, and the device has already given up on it and
reconnected. Detecting it *promptly* is worth far less than detecting it *cheaply*.

Devices MUST still respond correctly to WebSocket control-frame pings, because intermediate
proxies and the reference relay use them.

---

## 10. Versioning and compatibility

`v` in the `hello` frame is the **major** protocol version. It is `1`.

**Additive changes do not bump the major version.** New frame types, new optional fields, new
capability strings and new error codes may all be added within v1. This is safe precisely
because §2 requires unknown frames and unknown fields to be ignored silently. If your
implementation logs an error or closes the connection on an unknown `t`, it is not v1
compliant, and it will break the first time we ship a feature.

**Breaking changes bump the major version**, and are announced in the repository at least 90
days ahead. Our hosted relay supports the previous major version for at least 12 months after
a bump. A relay that does not support the offered version closes with `4000`.

Changes to this document are tracked in §13.

---

## 11. Security model

**What the token protects.** Possession of a device token allows an attacker to make that
dongle broadcast magic packets on its LAN. That means switching on a PC without permission —
irritating, potentially expensive in electricity, and a plausible first step in a physical
intrusion. It does **not** grant any access to the woken machine. Sizing the response to the
actual risk is why this protocol does not attempt device-side PKI.

**Wi-Fi credentials never leave the device.** They are entered locally — captive portal, USB
serial, or a config image — and stored only in the device's flash. No frame in this protocol
carries them, in either direction, and a device MUST reject any attempt by a relay to set
them. This is not merely a privacy nicety: it means compromising a relay, ours or anyone's,
does not yield anyone's Wi-Fi password.

**Tokens should be stored hashed by relays.** Except that they cannot be — the challenge-
response in §3 requires the relay to hold the raw token to compute the HMAC. Relay operators
MUST therefore treat the token store as secret material: encrypted at rest, never logged,
never included in diagnostics. This is a genuine trade-off accepted in exchange for the
token never crossing the wire, and implementers should know they are making it.

**Rate limiting.** Relays SHOULD limit wake requests **per `device_id`**, not per account —
the resource being protected is one LAN's broadcast domain, and an account with ten dongles in
ten buildings should not have them share a budget. Reference behaviour is 30 per minute: far
above any legitimate use, low enough to prevent a compromised account being used to hammer a
LAN with broadcast traffic.

**Reporting.** Security issues in this protocol or its implementations:
[`SECURITY.md`](SECURITY.md). Please do not open a public issue.

---

## 12. Minimal conformance

A relay is v1-conformant if it:

1. Echoes the `remotewake.v1` subprotocol.
2. Implements the §3.2 handshake, including constant-time proof comparison, fresh nonces, and
   sending `challenge` even for unknown device IDs.
3. Answers `{"t":"ping"}` with exactly `{"t":"pong"}`.
4. Sends `wake` and handles `wake_result`, preserving `req_id`.
5. Ignores unknown `t` values and unknown fields without erroring.
6. Never sends a frame larger than 2048 bytes.
7. Enforces one live connection per `device_id`, closing the displaced one with `4001`.

Everything else — `status`, `probe`, `config_push`, `log` — is optional.

[`relay-reference/test/fake-device.js`](relay-reference/test/fake-device.js) speaks this
protocol and is the fastest way to test a relay implementation with no hardware.

---

## 13. Changelog

| Version | Date | Change |
|---|---|---|
| 1 | 2026-07-29 | Initial specification. |
| 1 | 2026-07-29 | Clarifications from the second implementation (the hosted relay, on Cloudflare Durable Objects). Three more gaps, all found by deploying rather than by reading. **§1 and §3.3 contradicted each other on oversized frames** — §1 said close `1009`, §3.3 listed "oversized" among malformed-`hello` cases answered `bad_frame` + `1008`. §1 wins: the size check precedes any parse, and a receiver cannot report a parse result for bytes it declined to read. **`4002` must not be sent until the proof verifies** — closing as soon as a revoked `device_id` is recognised makes the close code an oracle distinguishing "known but revoked" from "never known", undoing §3.3. **§9 now says relays should not arm a dedicated liveness timer**: a 90-second alarm on a hibernating object wakes it 960 times a day to observe that nothing happened, costing more than the heartbeats §9 exists to make free. Detecting a stale connection cheaply beats detecting it promptly. |
| 1 | 2026-07-29 | Clarifications from the first implementation (`relay-reference`). Building against the spec surfaced nine gaps, all closed here. No frame shape changed; two limits narrowed, and one example was wrong. **`sent` is now defined as `ifaces.length × repeat`** and the §4 example corrected from 24 to 12 — the original figure was not derivable from any other field. **Frame size is now a symmetric 2048 bytes**; the device→relay bound was 8192, which no conforming frame approaches. Added close code **`4003`** (idle timeout), which `1008` could not represent without colliding with auth failure and corrupting the §8 backoff-reset rule. Added the **`config`** capability, without which §4's "MUST NOT send a command whose capability the device did not advertise" was unenforceable for `config_push`. **Removed the `log` capability** — no frame could enable it, so declaring it told a relay nothing actionable. Specified the relay's behaviour when a client omits the subprotocol, the response to a malformed `hello`, and `ok`/`err` on `probe_result` (a `probe` with a bad MAC previously had nowhere to report it). Clarified that rate limiting is per `device_id`, and that the unknown-device comparison must run before any provisioned check. |
