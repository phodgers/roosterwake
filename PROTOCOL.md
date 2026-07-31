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
| `mac` | Six octets, upper-case hex, colon-separated: `AA:BB:CC:DD:EE:FF`. Relays MUST accept lower-case and `-` separators on input and MUST normalise to this form on output. MUST be a unicast address — see below. |
| `req_id` | Opaque string, 1–36 characters, unique per in-flight request from a given relay. UUIDv4 recommended. Devices echo it verbatim and MUST NOT parse it. |
| `name` | Target display name, 1–24 UTF-8 characters after trimming. |
| `nonce` | 16 random bytes, 32 lower-case hex characters. |

Unknown fields in any frame MUST be ignored. Unknown `t` values MUST be ignored silently —
not answered with an error, not logged as a failure. This is what makes additive protocol
changes safe (§10).

### Wakeable addresses

A `mac` naming a wake target MUST be a unicast address. Three cases are excluded, and a relay
SHOULD reject them at its own edge with `bad_mac` (§6) rather than forwarding them:

* **Multicast/group** — bit 0 of the first octet set. A group is not an interface, so no machine
  can be woken by naming one. `01:00:5E:…` and `33:33:…` are the common accidents, both of which
  come from reading a packet capture.
* **All zeroes** — `00:00:00:00:00:00` means "unspecified".
* **Broadcast** — `FF:FF:FF:FF:FF:FF`. Also multicast by the rule above, but named separately
  because it is typed deliberately, by someone expecting it to wake every machine at once.

This is stated because the constraint is enforced in practice and an unstated constraint is how
independent implementations diverge: a device that refuses these while a relay forwards them
produces a wake that fails at the far end with nothing useful to report. Note that a
locally-administered address (bit 1 of the first octet) is perfectly wakeable and MUST NOT be
rejected — though a dashboard may reasonably warn that Windows and mobile privacy features
rotate such addresses, which will silently invalidate a saved target.

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

**Enrolment is the one deliberate exception, and it is fenced by the three cases above.**
A device the relay has never seen has no shared secret to prove, so `enrol` (§4) transmits the
token exactly once, on first contact. Read against the list above, that is only safe under two
rules, and both are the device's to enforce because the relay cannot see either:

1. **Only over a connection whose certificate was validated.** A build with verification
   disabled MUST NOT enrol. This is case two, and it is the whole of it.
2. **Only to the relay URL compiled into the firmware.** A device whose `relay_url` has been
   overridden MUST NOT enrol; its operator configures the token on their own relay by hand.
   This is case one, and it is why self-hosting is unaffected by any of this.

Case three then answers itself: the operator of the relay a device enrols with already holds
that token, because §11 requires relays to store it unhashed. Enrolment hands it to nobody who
would not have had it anyway.

After enrolment the token never crosses the wire again, in either direction, for the life of
the device. Every subsequent connection is the challenge-response above.

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

**First contact substitutes `enrol` for `auth`.** A device that has never completed a handshake
with this relay has no proof to offer, so it sends `enrol {token}` where `auth {proof_c}` would
go. Everything either side of that step is unchanged, including `proof_s`:

```
   │─ hello {v, device_id, nonce_c, …} ─────────────────────►│
   │◄─────────── challenge  {nonce_s} ───────────────────────│
   │─────────────── enrol  {token} ─────────────────────────►│  §3.4 rules
   │◄──── hello_ack  {ok:true, proof_s, server, now} ────────│
```

The relay still returns `proof_s`, computed with the token it has just stored, and the device
still verifies it. That is not ceremony: it is the device's only evidence that the relay kept
the right bytes. An enrolment that appeared to succeed but stored a corrupted token would
otherwise present as a device that authenticates once and never again.

A device knows which frame to send from whether it has ever received `hello_ack {ok:true}` —
reference firmware keeps a flag beside the token. It MUST NOT decide by whether the relay
happens to reject it, because retrying `enrol` after a failed `auth` is how a device with a
displaced token would talk its way back over the top of whoever holds it now.

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
- **A refused `enrol` is reported as `err: "auth"`, identically.** The four outcomes in §3.4
  collapse to two on the wire — accepted, or not — and deliberately so. An `enrol`-specific
  refusal would tell a caller that a given `device_id` exists *and is in use*, which is the
  oracle the first rule in this section exists to close, reopened at a different step.

### 3.4 Enrolment rules

A relay receiving `enrol` for `device_id` D with token T decides on what it already holds:

| State of D | Action |
|---|---|
| Not known | Store T. Accept. Nobody could be harmed: the id was unclaimed. |
| Known, stored token equals T | Accept. This is a device that lost its enrolled flag — a factory reset — and is proving it is the same hardware. |
| Known, token differs, **no owner** | Replace with T. Accept. A record nobody adopted is a reservation, not a possession, and it loses to hardware that has actually turned up. |
| Known, token differs, **has an owner** | Refuse, `err: "auth"`. |

The last row is the only one that protects anybody, and it is the reason a relay cannot simply
trust `enrol`: without it, knowing a `device_id` would be enough to take a working device off
its owner from anywhere in the world.

The third row is what stops that protection becoming a denial of service. Without it, anyone
could enrol ids they do not hold and lock out the boards that later arrive carrying them.
Ownership rather than mere connection is the test, because connecting proves only that
somebody holds *a* token — and in that scenario they chose it.

Relays SHOULD rate-limit enrolment by source address. A relay that does not implement `enrol`
at all is conforming; it simply requires its operator to configure tokens by hand, which is the
normal arrangement for a self-hosted deployment.
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
| `ota` | `ota_offer`, and the binary frames that follow it |
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

### `enrol` — sent in place of `auth`, on first contact only

```json
{ "t": "enrol", "token": "a1b2…64 lower-case hex characters…7f" }
```

The **only** frame in this protocol that carries a token, sent at most once in a device's life
against a given relay. §3.1 sets out why the exception is defensible and the two rules a device
MUST satisfy before sending it; §3.4 sets out what a relay does with it. A device that has
already completed a handshake MUST send `auth`.

`token` is the 64-character lower-case hex form, not the raw bytes — the same form
`config-format.md` stores and `usbcfg`'s `SET_TOKEN` accepts. Relays MUST reject any other
length or alphabet as `bad_frame` rather than storing something a later HMAC cannot key with.

### `adopt` — optional, hosted services only

```json
{ "t": "adopt", "email": "someone@example.com" }
```

Sent after a successful handshake by a device that is carrying an account address and has not
yet been told it is adopted. It asks the relay to bind this device to that account.

This exists because the person setting up a device is standing in front of it with a phone and
no route to the internet — the setup access point has no upstream — so the only thing that can
carry their identity out of that moment is the device itself. The address is typed locally,
stored in the device's configuration, and offered on the next connection.

`email` is at most 128 bytes of UTF-8. A relay MUST NOT treat it as authenticated: it is text a
person typed into a captive portal, and establishing that they control that address is the
service's problem, not this protocol's. Relays that offer no accounts SHOULD ignore this frame.

The device repeats it once per connection until acknowledged, and MUST stop and erase the
address once it is. Retrying is deliberate: the first connection after setup is also the one
most likely to be interrupted by a Wi-Fi network still settling.

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

### `ota_accept` / `ota_reject`

```json
{ "t": "ota_accept", "id": "6f1c…", "slot": 1 }
{ "t": "ota_reject", "id": "6f1c…", "err": "board" }
```

The answer to `ota_offer`. `slot` is the inactive slot the image will be written into, reported
so an operator can see which half of the device an update landed in; a relay has no decision to
make with it.

`err` on a rejection is one of the codes in §6, or one of the image-specific ones: `magic`,
`format`, `flags`, `length`, `board`, `version`, `signature`. `same_version` means the offer
names the version already running; `on_trial` means the running image has not yet confirmed
itself and the slot holding the last known-good image must not be overwritten.

### `ota_result`

```json
{ "t": "ota_result", "id": "6f1c…", "ok": true, "bytes": 503040, "ms": 9120 }
{ "t": "ota_result", "id": "6f1c…", "ok": false, "err": "digest", "bytes": 262144, "ms": 4400 }
```

Sent once the last payload byte has been written, or as soon as the transfer fails.

**On success the device stages the slot and restarts, closing with `1000` and reason
`updating`.** A relay SHOULD expect the reconnection to carry the new `fw` in its `hello`, and
SHOULD treat the same version coming back as the update having been rolled back — the device
gets three boots to reach a relay before the loader returns to the previous image, so a failed
update announces itself by the old version reappearing rather than by silence.

A failure leaves a partly written inactive slot, which is harmless: nothing points the loader at
it, and the next offer starts from the beginning. **There is no resume.** Resuming means trusting
an offset supplied by the relay, and the saving is one transfer of half a megabyte.

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

### `adopt_ack`

```json
{ "t": "adopt_ack", "ok": true, "state": "bound" }
```

Answers `adopt`. `state` is one of:

| `state` | Meaning |
|---|---|
| `bound` | The device now belongs to that account. |
| `pending` | The address has no account yet. The service has taken responsibility for the request — typically by inviting the address to create one — and the device's part is over. |

Both are `ok: true` and both mean the same thing to the device: stop offering, erase the
address. `pending` is reported separately only so a device can say something more useful than
"done" on a local status page.

A refusal is `{ "t": "adopt_ack", "ok": false, "err": "bad_frame" }` for an address that is not
plausibly one, or `"internal"`. A device MUST NOT retry a refusal on the same connection; a
relay that does not implement adoption simply never answers, and the device gives up at the
end of the connection.

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
    { "name": "NAS", "mac": "10:22:33:44:55:66" }
  ]
}
```

Replaces the device's target list wholesale — it is not a merge. Maximum 8 targets. The
device persists them to flash and replies `config_ack`. This is how a dashboard edit reaches
a device that was provisioned months ago.

Relays MUST NOT push Wi-Fi credentials or a relay URL. Those are local-only by design
(see §11) and a device MUST reject any attempt.

### `ota_offer`

```json
{
  "t": "ota_offer",
  "id": "6f1c…",
  "hdr": "5257465701000000…"
}
```

Offers a firmware image. Gated by the `ota` capability.

`hdr` is the image's 128-byte signed header, hex-encoded — 256 characters. **It is the only
description of the image in this frame, and that is deliberate**: the board it was built for,
its length, its version and the digest of its payload are all inside those bytes and all covered
by the signature. A relay that repeated any of them alongside would be offering the device a
second, unsigned copy of the same facts, and the unsigned copy is the one an attacker would lie
in. The header layout is `firmware/src/ota/image.h`.

`id` identifies the transfer. It is not a `req_id`: a transfer outlives the exchange that starts
it, and the frames that follow are not answers to a request.

The device replies `ota_accept` or `ota_reject`. It rejects an image built for another board, one
signed by a key it does not trust, one larger than the slot it must occupy, one whose version
equals the version already running, and any offer arriving while the running image is itself
still on trial.

### Update payload — the only binary frames in this protocol

After `ota_accept`, the relay sends the payload as **binary** WebSocket frames, in order, until
exactly `payload length` bytes have been sent. Constraints:

- Each frame carries payload bytes and nothing else. There is no per-frame header; WebSocket
  already guarantees order and delivery, and the device counts.
- **No fragmentation.** Every binary frame has `FIN` set. Reassembly costs a second buffer on a
  device that is going to write the bytes to flash the moment they arrive.
- The 2048-byte cap of §1 applies unchanged.
- A binary frame at any other time is a protocol violation. A device MUST close with `1008` — it
  is not an unknown frame type to be tolerated, it is a peer streaming into a device that has not
  agreed to receive anything.

The device writes each frame straight to the inactive slot and hashes it on the way past. The
digest committed to by the signed header is what proves the stream arrived whole; there is no
per-frame checksum because a per-frame check that passes on every frame still cannot tell you the
image is the one that was signed.

A relay MUST NOT interleave other frames into the stream. A device that receives one MAY handle
it, but a wake in the middle of a flash erase is answered late, so relays SHOULD hold commands
until `ota_result`.

### `ping`

```json
{ "t": "ping" }
```

Relay-initiated liveness check. Devices reply `{"t":"pong"}` promptly. See §9 for why this
is the less important direction.

---

## 6. Error codes

Returned in `err` on `wake_result`, `hello_ack`, `config_ack`, `ota_reject` and `ota_result`.

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

Update-specific codes, on `ota_reject` and `ota_result` only:

| Code | Meaning |
|---|---|
| `magic`, `format`, `flags` | The header is not one this device understands |
| `length` | Empty, or larger than the slot it must occupy |
| `board` | Built for the other chip |
| `version` | Version string absent or not printable ASCII |
| `signature` | Not signed by the key this build trusts |
| `digest` | The payload does not hash to what the signed header claimed |
| `same_version` | The offer names the version already running |
| `on_trial` | The running image has not yet confirmed itself |
| `too_long` | More payload arrived than the header declared |
| `stage_failed` | Written and verified, but the state record could not be updated |

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

**How a relay comes to hold a token.** Four ways, and which apply depends on who is running the
relay:

- **The device enrols itself** on first contact (`enrol`, §4), under the two rules in §3.1.
  This is the ordinary path for a hosted service, and it is what lets a person set a device up
  with nothing but a phone.
- **A config image carries one** that its generator also recorded in the relay's device list
  (`tools/mkconfig`).
- **A USB provisioning session writes one** the host generated and registered first
  (`SET_TOKEN`, `firmware/docs/usbcfg.md`).
- **The device mints its own and shows it** on its setup page, for an operator to add to their
  own relay by hand. This is the self-hosting path and it needs nothing from us.

What is *not* available, and is the thing to keep refusing: issuing a token in exchange for some
weaker credential — a short human-typed code, an email address, a device id on a sticker. That
would make the weaker thing the real secret, and put it on the wire this protocol is careful to
keep tokens off. Note that `enrol` is not that: the device presents the token *itself*, once,
and thereafter proves possession without transmitting it.

**Possession of the hardware is the ownership claim.** A hosted service MAY treat a device that
proves it holds the token as entitled to be re-bound to a different account — the reference
service does, because the alternative is a second-hand buyer holding hardware that cannot be
made to work. The token only reaches flash through physical access: a USB cable, a config image,
or a setup page that only runs after the button has been held down at power-on. Refusing the
transfer would not protect anyone who has already lost that access; it would only make honest
resale, gifting and returns require support.

An `auth` close on a device the relay has never heard of remains correct where enrolment is not
offered.

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

Everything else — `status`, `probe`, `config_push`, `log`, `enrol`, `adopt`, `ota_offer` — is
optional.

**`enrol` and `adopt` are optional on purpose.** A self-hosted relay whose operator adds tokens
to a list by hand needs neither, and requiring them would mean every minimal implementation had
to carry an account model. A relay that ignores them is conforming; a device that offers them
and is ignored simply never becomes enrolled or adopted, which is the correct outcome on a relay
that does not know what an account is. Any relay that DOES implement `enrol` MUST implement all
four rows of §3.4 — the refusal without the replacement is a lockout, and the replacement
without the refusal is a takeover.

[`relay-reference/test/fake-device.js`](relay-reference/test/fake-device.js) speaks this
protocol and is the fastest way to test a relay implementation with no hardware.

---

## 13. Changelog

| Version | Date | Change |
|---|---|---|
| 1 | 2026-07-31 | **Firmware updates over the relay connection.** Four new frames — `ota_offer`, `ota_accept`, `ota_reject`, `ota_result` — and the one exception to §1's "frames are text": the payload of an update the device has agreed to receive arrives as unfragmented binary frames. There is no second connection because there is no room for one; a TLS session costs 44 KB of a 64 KB heap on the reference device, so an image either shares this socket or does not arrive. The offer carries the image's signed header and **nothing else**, which is the whole of the security argument: board, length, version and payload digest are all inside the signature, so there is no unsigned restatement of them for a relay to lie in. A device with two slots writes the inactive one and restarts; the update proves itself by reconnecting, and a failure announces itself by the previous version reappearing rather than by silence. Binary frames outside a transfer close the connection with `1008`. |
| 1 | 2026-07-29 | Initial specification. |
| 1 | 2026-07-30 | **Enrolment and adoption.** Three new frames — `enrol`, `adopt`, `adopt_ack` — and the §3.4 rules a relay applies to the first. Until now a relay could only learn a token out of band, which meant a device nobody had registered in advance could never reach a hosted service at all: no path existed from a board somebody flashed themselves to a relay that would speak to it. `enrol` transmits the token exactly once, on first contact, and §3.1 now sets out why that exception is defensible and the two rules — a validated certificate, and the compiled-in relay URL — that fence it. §3.4's four-row table is the whole of the security argument: refuse only where the id is already owned, replace freely where it is not, so that the protection cannot itself become a way to lock people out of boards they hold. `adopt` carries an account address off a captive portal that has no route to the internet, which is the only moment in setup where the person's identity can be captured. §11 restates how a relay comes to hold a token, and records that possession of the hardware is treated as the ownership claim. |
| 1 | 2026-07-30 | Two rules the specification relied on but never stated, both found by building a surface on top of it rather than by reading it. **§2 now defines a wakeable address** — the relay had been accepting multicast and broadcast MACs that the firmware refuses, so a target saved in the dashboard was one the device silently declined to wake; the §5 example was itself a multicast address and is corrected. **§11 now says how a relay comes to hold a token**: out of band at provisioning time, in all cases, and explains why there is deliberately no enrolment frame — a device presenting a weaker credential to be issued a token would make that credential the real secret and would put it on the wire this protocol keeps tokens off. Neither change alters a frame. |
| 1 | 2026-07-29 | Clarifications from the second implementation (the hosted relay, on Cloudflare Durable Objects). Three more gaps, all found by deploying rather than by reading. **§1 and §3.3 contradicted each other on oversized frames** — §1 said close `1009`, §3.3 listed "oversized" among malformed-`hello` cases answered `bad_frame` + `1008`. §1 wins: the size check precedes any parse, and a receiver cannot report a parse result for bytes it declined to read. **`4002` must not be sent until the proof verifies** — closing as soon as a revoked `device_id` is recognised makes the close code an oracle distinguishing "known but revoked" from "never known", undoing §3.3. **§9 now says relays should not arm a dedicated liveness timer**: a 90-second alarm on a hibernating object wakes it 960 times a day to observe that nothing happened, costing more than the heartbeats §9 exists to make free. Detecting a stale connection cheaply beats detecting it promptly. |
| 1 | 2026-07-29 | Clarifications from the first implementation (`relay-reference`). Building against the spec surfaced nine gaps, all closed here. No frame shape changed; two limits narrowed, and one example was wrong. **`sent` is now defined as `ifaces.length × repeat`** and the §4 example corrected from 24 to 12 — the original figure was not derivable from any other field. **Frame size is now a symmetric 2048 bytes**; the device→relay bound was 8192, which no conforming frame approaches. Added close code **`4003`** (idle timeout), which `1008` could not represent without colliding with auth failure and corrupting the §8 backoff-reset rule. Added the **`config`** capability, without which §4's "MUST NOT send a command whose capability the device did not advertise" was unenforceable for `config_push`. **Removed the `log` capability** — no frame could enable it, so declaring it told a relay nothing actionable. Specified the relay's behaviour when a client omits the subprotocol, the response to a malformed `hello`, and `ok`/`err` on `probe_result` (a `probe` with a bad MAC previously had nowhere to report it). Clarified that rate limiting is per `device_id`, and that the unknown-device comparison must run before any provisioned check. |
