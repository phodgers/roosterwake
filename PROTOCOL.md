# Rooster Wake wire protocol

**Version 2** · Status: **stable** · Last changed: 2026-08-10

This document specifies the protocol between a Rooster Wake device (the "dongle") and a relay.
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
- Default endpoint: `wss://relay.roosterwake.com/ws`. Configurable per device; self-hosters
  point it wherever they like.
- **Subprotocol**: the client sends `Sec-WebSocket-Protocol: roosterwake.v1`. A relay that
  understands this protocol MUST echo it. A relay that does not MUST omit the header, and the
  client MUST then close the connection — this is how a device detects that it has been
  pointed at something that is not a Rooster Wake relay (a captive portal, a misconfigured
  reverse proxy, someone's Home Assistant) instead of hanging.
  **The token names the protocol family, not its major version, and does not change when the
  major version does.** Version negotiation is `v` in `hello` answered by close `4000` (§10),
  and it has to happen there: a relay that refused the upgrade over a version it does not speak
  would tell the device it had been pointed at something that is not a relay at all, which is a
  different fault with a different fix. The token stays `roosterwake.v1` for the life of the
  protocol.
  Symmetrically, a relay MUST **refuse the upgrade** (HTTP 400) when the client does not offer
  `roosterwake.v1`, rather than accepting the socket and waiting for a `hello` that will never
  come. Both halves are specified because leaving either undefined lets two conforming relays
  behave differently, and a third-party firmware then works against one and hangs against the
  other.
- **Frames are WebSocket text frames** containing a single JSON object. One object per frame;
  no framing of multiple objects, no newline delimiting.
- **Size limits.** **No frame in either direction may exceed 2048 bytes.** A receiver MUST
  reject a larger frame with close code `1009`. Devices are memory-constrained; this limit is
  a hard part of the contract, not a suggestion.
  Most frames are nowhere near it: every frame that carries a fixed set of fields is a few
  hundred bytes. The frames that can reach the ceiling are `scan_result` and
  `plug_scan_result`, whose lists are as long as the segment is busy — which is why both are
  specified to drop entries and say so rather than to grow. A single symmetric bound is easier
  to implement correctly than two, and lets both sides size one receive buffer.
- **Encoding** is UTF-8. Relays MUST NOT assume ASCII: the account address in `adopt` is text a
  person typed into a captive portal.

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

A **device MUST refuse them too**, answering `bad_mac`, and since v2 the frame is the only way a
MAC reaches one — there is no stored list any more, so this is the single place the rule can be
applied on that side. Both halves are specified because an unstated constraint is how independent
implementations diverge, and because the failure is silent in the worst way: a magic packet to a
group address is accepted by every layer that touches it, so the device would report `ok:true`
with a full `sent` count for a wake that could never have worked. Note that a
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
   │─ hello {v, device_id, nonce_c, fw, board, caps} ───────►│
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
  "v": 2,
  "device_id": "a1b2c3d4e5f60718",
  "nonce_c": "9f86d081884c7d659a2feaa0c55ad015",
  "fw": "2.0.0",
  "board": "pico2_w",
  "slot": 0,
  "caps": ["wake", "status", "probe"]
}
```

`caps` declares what this firmware can do, so relays feature-detect rather than sniff version
numbers. A relay MUST NOT send a command whose capability the device did not advertise.

`macs` is optional and lists the hardware addresses of the device's own network interfaces, in
§2's output form, at most eight. It exists for one purpose: a device that runs **on** a machine
rather than beside it — a software emitter — is the only thing that can power that machine down,
and a service has to be able to tell which of the account's machines that is. A device with no
such relationship omits the field, and a dongle always does: its own address is not one anybody
would wake.

> **A relay MUST NOT act on `macs` before the handshake completes.** `hello` arrives before
> anything has been proved, so its contents are a claim, not a fact. Storing them is harmless;
> binding a power command to them is not, because a peer that merely knows a `device_id` could
> otherwise name somebody else's machine as its own. The rule is the same one `caps` has always
> been read under — it is written down here because the consequence of breaking it changed from
> a wasted frame to a machine being switched off by a stranger.

`slot` is optional and only meaningful on a device that advertises `ota`: it says which of two
firmware slots the running image occupies, `0` or `1`. An image is linked at the address of the
slot it lives in, so a relay offering an update has to pick the variant built for the *other*
slot; it cannot infer that from the version, and offering the wrong one wastes a transfer to be
refused. A device with a single firmware region omits the field, and a relay that sees no `slot`
MUST NOT offer an update.

`stuck` is optional and reports that the device **restarted itself** because it had a working
network and could not reach a relay. It is sent on the first `hello` after such a restart and
then never again, so its presence means "this just happened" rather than "this once happened".

```json
"stuck": {
  "relay": "connecting",
  "unlinked_s": 900,
  "uptime_s": 143000,
  "heap_free": 41232,
  "mem_err": 0,
  "err": "sntp_timeout"
}
```

`relay` is the state the device gave up in, one of `idle`, `backoff`, `connecting`, `connected`,
`auth_failed`. `unlinked_s` is how long it had been unable to reach a relay and `uptime_s` how
long it had been running, both in seconds. `heap_free`, `mem_err` and `err` are optional
diagnostics: free heap in bytes, the count of allocations the network stack refused, and whatever
short error string the device's own network layer last set.

The field exists because this failure erases its own evidence. A device that cannot reach a relay
is, by definition, a device the relay has no record of — nothing was attempted, so nothing was
refused and nothing was logged — and the fix, a restart, discards whatever the device knew. A
device that carries the account across the restart is the only witness there will ever be.

> **A relay MUST NOT treat `stuck` as fact before the handshake completes**, and MUST bound every
> field before storing it. The rule is `macs`'s, for a weaker reason: nothing here can switch a
> machine off, but these values are shown to a person as our own diagnosis of their hardware, and
> a peer that merely knows a `device_id` must not be able to write that. In particular a relay
> SHOULD distinguish a field it could not parse from a zero — `mem_err: 0` says the allocator
> refused nothing and the fault lay elsewhere, which is a finding, while a missing `mem_err` is
> the absence of one.

A relay that does not understand the field ignores it, per §10.

Defined capabilities, each naming the relay→device command it gates:

| Capability | Gates |
|---|---|
| `wake` | `wake` |
| `power` | `power` |
| `rdp` | `rdp_enable` |
| `awake` | `hold_awake`, `release_awake` |
| `session` | `session_start`, `session_stop`, and the advisory `workspaces` push |
| `ready` | `wake_prepare` |
| `status` | `status` |
| `probe` | `probe` |
| `scan` | `scan` |
| `plug` | `plug_scan`, `plug_set`, `plug_status` |
| `plugfw` | `plug_fw_check`, `plug_fw_update` |
| `ota` | `ota_offer`, and the binary frames that follow it |
| `sched` | reserved for device-side scheduling; no command yet |

`power` is one capability rather than three, and that is deliberate. Sleeping, restarting and
shutting a machine down are the same privilege exercised three ways — a device that can do one
can do all three — so splitting them would let a device advertise a subset that a relay then has
to reason about, for no gain. Where an individual action genuinely is not available (a machine
with no suspend state), the device answers that action `unsupported` when it is asked, which is
the honest place to find out.

**`rdp` is separate from `power` and is not implied by it.** The two are the same order of
privilege — both change somebody's machine rather than merely switching it on — but they are not
the same *availability*: turning Remote Desktop on means Windows registry policy and Windows
Firewall rules, and a device that can suspend its host may have no way to do any of it. Our own
agent advertises `power` on three platforms and `rdp` on Windows alone. Folding the two together
would put an `rdp_enable` on a Linux agent's socket, where §2 requires it to be ignored silently —
so the caller would wait out its timeout and be told the machine did not answer, about a machine
that had answered everything else all day. A separate capability turns that into a refusal before
the frame leaves.

It is one capability rather than one per command for the same reason `power` is: a device that can
turn Remote Desktop on is a device that could turn it off, so splitting them would advertise a
subset a relay then has to reason about, for no gain.

`awake` says the device can hold its host machine out of idle sleep for a bounded time, and gates
both verbs of that arrangement — the hold and its release — as one capability, on `power`'s
reasoning: a device that can stake the hold can clear it. It is gated like `power` and `rdp`
rather than advertised everywhere like `plug`, and for their reason: what it gates changes the
host machine's own behaviour, and our agent implements it on Windows alone. A caller told "this
machine will stay up" about a machine whose agent could only refuse would sleep through exactly
the window the frame existed to protect.

`session` says the device can launch a remote AI coding session — the `claude remote-control`
server — on its host, as the machine's signed-in user, in a workspace directory the account
holder registered in advance. It gates both verbs and the `workspaces` push as one capability,
on `power`'s reasoning: a device that can start the session can stop it, and a list pushed to a
device that could do neither would be configuration for nobody. It is gated like `awake` rather
than advertised everywhere like `plug`, and harder than anything else in this table, because
what it gates runs a process AS THE USER — the launch machinery exists on Windows alone in our
agent, and a platform that advertised it without the machinery would be promising somebody's
coding session with nothing behind the promise.

`ready` says the device can PREPARE its host machine to be woken — switch off the settings
that quietly defeat a magic packet (on Windows: Fast Startup, and the adapter's magic-packet
switch and wake arming) — and gates the one command that does it, `wake_prepare`. It is gated
like `rdp` and for `rdp`'s reason: same order of privilege as `power`, different availability —
the settings it writes exist on Windows alone in our agent — and §4's rule keeps the frame off
every socket whose device could only refuse it. The wake-readiness FACTS a device reports
beside its connect facts need no capability: facts are answers, not commands, and they ride
`status_result` under §10's additive rule whether or not the fix verb is available.

`plug` says the device can drive smart plugs on its own segment over local HTTP — discover
them, switch them, read them. It is one capability rather than three for `power`'s reason: a
device that can send one of these requests can send all of them, and a subset would only give
relays something to reason about. It is separate from `scan` even though discovery rides the
same ARP sweep, because the two enumerate different things for different callers — `scan`
lists wake candidates, `plug_scan` lists actuators — and a device may reasonably implement
either without the other. Unlike `power`, the commands act on a *peer* device, and that does
not break §5's no-powering-down-peers rule: a plug is an actuator whose entire published
contract is to be switched by whoever shares its network, not a machine with an owner's
session on it. The agreement `power` refuses to invent is one the plug's own vendor already
made.

A device advertising `power` or `rdp` SHOULD also advertise `macs`. Without it a service can
dispatch the command but cannot tell which machine it would land on.

Unknown entries are ignored.

There is deliberately **no `log` capability**. Diagnostic logging is enabled locally by the
operator and there is no frame by which a relay could turn it on, so advertising it would tell
a relay something it cannot act on. Log frames may arrive from any device whose owner has
enabled diagnostics, and relays MAY discard them.

**A device holds no list of the machines it can wake.** There is nothing here for it to
declare and no frame by which a relay could give it one: every `wake` and every `probe` names
its MAC, and the caller is the side that knows which machines exist. §13 records why.

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

Two optional fields extend the frame for services that hand out **enrolment tokens** — a
reusable credential an installer flag carries, so a fleet of software emitters can bind to one
account with nobody typing an address into each machine:

```json
{ "t": "adopt", "enrol_token": "rw_enrol_…", "host": "warehouse-07" }
```

`enrol_token` names an account the way `email` cannot: precisely, and with the account holder's
prior consent, because the token was minted by them and handed to the installer on purpose. A
frame carrying **both** a token and an email is a token frame — the token identifies an account
exactly, and the email would be a guess standing beside it. Like `email`, the token is at most
64 bytes and MUST NOT be treated as authenticated transport-side; it is a bearer credential,
and everything about validating it — existence, revocation, what the account's plan permits —
is the service's business.

`host` is advisory naming and nothing more: the machine's own idea of its name, offered so a
service that saves the machine can label it something better than a hardware address. It is
untrusted, like every name in §4 — display text, never an identifier, never matched against
anything.

**Relays without accounts ignore both fields.** They ride §10's rule that unknown fields are
ignored silently: a relay that has no account concept — or one that implements the email path
and nothing more — sees an `adopt` frame it already understands, ignores what it does not, and
answers exactly as it always did. A device offering a token to such a relay simply never
becomes adopted by it, which is the same correct outcome §12 records for `enrol` and `adopt`
as a whole.

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

### `power_result`

```json
{ "t": "power_result", "req_id": "…", "ok": true, "action": "sleep" }
```

Answers `power` (§5). `action` echoes the action the device is carrying out, so a caller reading
a transcript can see what was accepted rather than inferring it from the request it sent.

**`ok: true` means accepted and about to run — never completed — and no implementation can make
the stronger claim.** The action being acknowledged tears down the process that would have sent
the acknowledgement: a suspend stops the machine mid-write, a shutdown ends the program, and a
restart does both. So a device MUST send `power_result` and give it time to reach the wire
*before* it acts, and a relay MUST NOT read `ok: true` as evidence that a machine is now asleep.

What actually confirms the outcome is the connection dropping shortly afterwards, which is the
same evidence a relay already has for every other reason a device goes away. That is weaker than
an acknowledgement and it is the truth: the alternative is a frame that can only be sent by a
process that is still running, which is precisely the state the command exists to end.

On failure: `{"t":"power_result","req_id":"…","ok":false,"err":"no_privilege","action":"shutdown"}`.
A failure is reported before anything is attempted, so it is safe to retry.

### `rdp_enable_result`

```json
{ "t": "rdp_enable_result", "req_id": "…", "ok": true, "note": "firewall group enabled" }
```

Answers `rdp_enable` (§5). On success the only other field is `note`, which names which of the
two firewall paths succeeded — `firewall group enabled` for the built-in Remote Desktop rule
group, `firewall rule added` for the device's own explicit fallback rule (§5 says when the
fallback runs). The two leave different artefacts behind in the machine's firewall console, and
the reply is the only place that answer survives for whoever diagnoses the machine later. There
are no other success fields: the command has one outcome and it either happened or it did not.

**`ok: true` means the change is DONE — the exact opposite of `power_result` above, and the
difference is not an inconsistency between the two.** `power_result` precedes its action only
because the action destroys the process that would otherwise send it; that is the strongest claim
available there, not a preference. Nothing about enabling a listener destroys anything. The device
is still running, still connected, and still able to say which of the settings actually landed —
so a device MUST do the work first and report it, and MUST NOT send this frame as an acceptance.

The reason to insist is what the answer is used for. "Remote Desktop is on" is a sentence somebody
acts on by opening a client against a machine they cannot see; if it means "we asked", the failures
show up as a client that hangs, from a machine that looks switched off. An acceptance here would be
throwing away an answer the device already has.

A relay MUST NOT read `ok: true` as evidence that the machine is reachable *from where the relay
is*. What the device is reporting is the state of the machine's own settings, and reaching it is
still a matter of the network in between.

On failure, `err` carries a §6 code — `unsupported`, `no_privilege`, `busy` or `internal` — and two
optional fields say what a code cannot:

```json
{ "t": "rdp_enable_result", "req_id": "…", "ok": false, "err": "internal", "step": "firewall",
  "note": "the Windows Firewall still blocks Remote Desktop — netsh said: No rules match…" }
```

`step` names which part of the work stopped, and it is worth carrying because **the states these
failures leave behind are genuinely different**:

| `step` | What the machine is left in |
|---|---|
| `policy` | Nothing changed. It stopped at the setting that admits Remote Desktop at all. |
| `nla` | Nothing was opened. The device requires authentication *before* it admits connections (§5), so a stop here leaves the machine no more open than it was found. |
| `firewall` | **Remote Desktop is now ON, and the firewall still drops it.** The machine will accept a connection the moment its firewall lets one through; until then a client sees exactly what it would see if the machine were switched off. |

The `firewall` row is why the field exists. A caller that flattened these three into "it failed"
would send somebody to diagnose a dead machine that is in fact listening — and would leave the
half-changed state unreported, which is the one outcome the owner has to know about to act.

`step` is omitted where the device cannot attribute the failure; a caller MUST NOT infer a state
from its absence, and MUST NOT treat an unrecognised value as one of the three.

`note` is one short sentence for a person: the tool's or the policy's own words, not a paraphrase,
because whoever has to fix the machine is better served by what Windows actually said. It is
untrusted like every string in §4 — a relay SHOULD bound it and MUST NOT interpret it — and a
device MUST keep it well inside §1's 2048-byte frame limit. Reference behaviour is 300 characters.

A device MUST answer a second `rdp_enable` that arrives while one is running with `busy` rather
than queueing it, on the same grounds as `scan`: two interleaved runs could read a half-applied
machine as a settled one.

A device that receives an `rdp_enable` with no `req_id` answers **nothing at all** — `req_id` is
echoed verbatim and a frame without one has nowhere for an answer to go. Same rule as `wake` and
`power`, same silence.

### `wake_prepare_result`

```json
{ "t": "wake_prepare_result", "req_id": "…", "ok": true,
  "steps": { "fast_startup": "done", "adapter": "done" },
  "note": "the driver's magic-packet setting takes effect after the adapter restarts or the next boot" }
```

Answers `wake_prepare` (§5), **after** the work — `rdp_enable_result`'s rule exactly: nothing
about writing power settings destroys the process that replies, so `ok: true` means the
machine's wake settings ARE what the caller asked for, never that a request was accepted.

`steps` is the per-step ledger, always present with both members, each one of three values:

| Value | Meaning |
|---|---|
| `done` | The device changed the setting. |
| `already` | The setting was already right; nothing was written. |
| `failed` | The device could not put the setting right. |

`already` counts toward success — the caller asked for a machine in this state and has one, and
"changed nothing" is the evidence a previous attempt landed. **`ok` is `false` exactly when
either step is `failed`**, with `err` carrying a §6 code (`unsupported`, `no_privilege`, `busy`
or `internal`); both steps still arrive on failure, because a caller must see which half to
diagnose AND whether the other half landed — a machine with Fast Startup now off but an adapter
that will not arm is half-repaired, and flattening that into "it failed" hides a repair that
happened. An unrecognised step value MUST be treated as `failed`, never as a success.

`note` carries the one truth a success must not bury. A changed driver property is read at
driver start, so it takes effect only after the adapter restarts or the machine next boots — and
a device MUST NOT restart the adapter itself, because its own relay connection runs over that
adapter and the restart would cut the socket mid-reply, turning a repair into an outage. The
note says so in a person's words. On failure it carries the failing step's own sentence instead.
Untrusted like every string in §4; bounded well inside §1's ceiling.

A second `wake_prepare` while one runs is answered `busy` rather than queued (`rdp_enable`'s
grounds), and a frame with no `req_id` is answered nothing at all — the same silence as every
acting command here.

### `awake_result`

```json
{ "t": "awake_result", "req_id": "…", "ok": true, "held": true, "until": 1756400000 }
```

Answers both `hold_awake` and `release_awake` (§5) — one frame type, because the two commands
report the same fact: whether a keep-awake hold now stands, and until when.

**Sent after the work, on `rdp_enable_result`'s reasoning rather than `power_result`'s.** Nothing
about staking or clearing an idle hold destroys the process that replies — a machine held awake
is a machine that is conspicuously still running — so `ok: true` means the state is **set**,
never that a request was accepted. The sentence a caller builds from it, "this machine will stay
up until then", has to be true when it is printed.

`held` says which state was set: `true` with `until` for a placed hold, `false` with no `until`
for a release. `until` is unix seconds, the deadline the device actually armed — a caller SHOULD
read it back rather than recomputing `now + seconds` on its own clock, because the device's clock
is the one the deadline lives on.

A release that finds no hold standing is still `ok: true, held: false`: it cleared a state that
was already clear, and there is deliberately no error for it — the caller asked for a machine
that may sleep, and has one.

On failure: `{"t":"awake_result","req_id":"…","ok":false,"err":"bad_frame","held":false}`. A
failed hold changes nothing — no state was set, no deadline armed — so it is safe to retry.

### `session_result`

```json
{ "t": "session_result", "req_id": "…", "ok": true, "running": true,
  "env_url": "https://claude.ai/code?environment=env_01AB23CD", "workspace_id": 7,
  "started_at": 1756480000, "hold_until": 1756494400 }
```

Answers both `session_start` and `session_stop` (§5) — one frame type, the `awake_result`
precedent: the two commands report the same fact, whether a remote AI session now runs on this
machine, and under what URL.

**Sent after the work, on `rdp_enable_result`'s reasoning rather than `power_result`'s.**
Nothing about launching or killing the session destroys the process that replies — the session
is a child, detached on purpose — so `ok: true` on a start means the session is **running** and
`env_url` was read from the CLI's own output, never assembled from anything else. The sentence
a caller builds from it — "continue coding at this URL" — has to be true when it is printed.

`running` says which state was set: `true` with the session's facts for a start, `false` with
none of them for a stop. A stop that finds nothing running is still `ok: true, running: false`
— the caller asked for a machine with no session, and has one; `release_awake`'s idempotence
rule exactly.

`started_at` and `hold_until` are unix seconds on the **device's** clock, the clock the
deadlines live on — read back, never recomputed on the caller's. `hold_until` is the same
deadline the `awake` machinery reports as `awake_until`: a session start stakes the one
keep-awake hold, replacing any hold already standing (§5 `session_start` says why that is the
right rudeness).

On failure: `{"t":"session_result","req_id":"…","ok":false,"err":"…","running":false}`, with
the `err` vocabulary of §6's session table. `detail` rides only on `err: "session_failed"` —
one line of the CLI's own words, the tool's sentence rather than a paraphrase, untrusted like
every string in §4, bounded by the device (reference behaviour is 200 characters) and well
inside §1's frame ceiling. A failed start changes nothing — no process left running, no hold
staked, no state recorded — so it is safe to retry.

### `status_result`

```json
{
  "t": "status_result",
  "req_id": "…",
  "rssi": -52,
  "uptime_s": 84321,
  "ip": "192.168.1.42",
  "netmask": "255.255.255.0",
  "fw": "2.0.0",
  "reset_reason": "power_on"
}
```

`ip` and `netmask` are the two fields worth reading together: the subnet broadcast a wake goes
to is computed from them, so a target on a different subnet is visible here before anybody
sends a packet.

A device that advertises `power` MAY add a `machine` block describing the host it runs on:

```json
"machine": { "host": "studio-pc", "os": "windows 10.0.26200", "wake_from_off": "no",
             "wake_note": "Fast Startup is on", "sessions": 1 }
```

| Field | Meaning |
|---|---|
| `host` | The machine's own name, for display. Untrusted, like every name in §4. |
| `os` | Operating system and version, one short string. |
| `wake_from_off` | `yes`, `no` or `unknown` — can this machine be woken again once it is fully off? |
| `wake_note` | One sentence naming what the device actually found, when it found something. |
| `sessions` | Interactive user sessions, or absent when the device cannot tell. |

`wake_from_off` is the field this block exists for, and it is a **safety** field rather than a
diagnostic one. Waking a machine is harmless; shutting one down can make it unwakeable, because
wake-from-S5 is frequently disabled in firmware and, on Windows, Fast Startup turns a shutdown
into a hybrid hibernate that most adapters will not wake from. A caller that offers "shut down"
without reading this is offering to strand somebody's machine somewhere they cannot reach it.

`unknown` is a first-class answer and MUST NOT be rendered as either of the other two. The tools
that read these settings are not present on every system and do not always answer honestly; a
device that cannot tell says so, and a caller that guesses on its behalf will eventually guess
wrong in the direction that costs a journey.

`sessions` is advisory and exists so a caller can say "somebody is logged in" before it shuts a
machine down. It counts sessions, never people, and never reports who they are.

A device that advertises `awake` adds **`awake_until`** — unix seconds — while a keep-awake hold
stands, and omits it otherwise:

```json
"awake_until": 1756400000
```

This is the honest oracle for a dashboard, and the reason it exists beside `awake_result.until`:
the reply was true when it was sent, but the hold it reported may since have been replaced,
released or expired, and this field says what stands **now**. Absence means no hold — never
"cannot tell", because the device is the side that owns the deadline.

A device that advertises `session` adds a **`session`** block while a remote AI session runs,
and omits it otherwise — `awake_until`'s reasoning, one member over:

```json
"session": { "workspace_id": 7, "env_url": "https://claude.ai/code?environment=env_01AB23CD",
             "started_at": 1756480000, "hold_until": 1756494400 }
```

A `session_result` was true when it was sent, but the session it reported may since have been
stopped, died on its own, or outlived an agent restart — the session deliberately survives one
(§5 `session_start`) — and this block reports what stands at the moment of asking, from state
the device verified against the actual process at startup. Absence means no session; never
"cannot tell".

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

### `scan_result`

Sent once, in answer to `scan`.

```json
{
  "t": "scan_result",
  "req_id": "…",
  "ok": true,
  "gateway": "192.168.1.1",
  "truncated": false,
  "hosts": [
    { "ip": "192.168.1.20", "mac": "AA:BB:CC:DD:EE:FF", "name": "DESKTOP" }
  ]
}
```

`hosts` is ordered by address, lowest first. `name` is present only for a host that answered a
name query — a NetBIOS node status query, which Windows and Samba answer, or an mDNS reverse
lookup, which names macOS, desktop Linux and most phones — and is omitted otherwise. A host
that answers both is reported under its NetBIOS name. It is untrusted input from an
unauthenticated peer on the local segment: a relay or dashboard MUST treat it as text to
display, never as an identifier, and MUST NOT match a device or account against it.

`gateway` is the device's default route where it knows one. It is what lets a caller mark the
one entry on the list that is a router rather than a candidate to wake.

**`truncated` is `true` when hosts were found that did not fit.** §1's 2048-byte ceiling binds
this frame more tightly than any other in the protocol, and a busy segment can answer with more
hosts than it can carry. A device MUST drop hosts rather than exceed the limit, and MUST set
`truncated` when it drops any. A device that drops SHOULD keep named hosts in preference to
unnamed ones: the list exists so that somebody can find one particular machine on it, and a
host that answered a name query is far likelier to be that machine than one that did not.

`ok: false` carries `err` from §6 in place of `hosts` — `no_link` when the device is not
joined to a network, `busy` when another operation holds the radio.

```json
{ "t": "scan_result", "req_id": "…", "ok": false, "err": "no_link" }
```

### `plug_scan_result`

Sent once, in answer to `plug_scan`.

```json
{
  "t": "plug_scan_result",
  "req_id": "…",
  "ok": true,
  "truncated": false,
  "plugs": [
    { "mac": "00:00:5E:00:53:02", "ip": "192.168.1.60", "model": "SNPL-00112UK",
      "gen": 2, "name": "rack plug", "channels": 1, "fw": "2.0.0" }
  ]
}
```

`mac` is in §2's output form and is the plug's identity — the field a caller stores and names
in every later `plug_set` and `plug_status`, because the `ip` beside it is only where that
identity was seen today. `model` and `gen` are the device's own claims from `GET /shelly`
(Gen1 answers with a `type`, Gen2+ with `model` and `gen`), passed through so a registry on
the service side can decide what the hardware is; `gen` is the figure the device reported,
not clamped to 2. `channels` is the device's own figure where it states one (Gen1
`num_outputs`) and `1` otherwise — a caller with a registry knows better than the sweep does.
`name` is present only where the device offered one and is untrusted display text under
exactly `scan_result`'s rule: never an identifier, never matched against.

`fw` is the firmware the device reported in the same answer (`ver` on Gen2+, `fw` on Gen1,
verbatim) and is best-effort: absent where the device offered none, and absent from every
implementation that predates it. A service holding a minimum-version policy reads this to
decide whether to offer or perform an update before the switch is put to work.

`truncated` is `true` when plugs were found that did not fit — this is the other frame §1
names as able to reach the 2048-byte ceiling, and it drops entries rather than exceed it.
There is no named-first preference: everything listed already identified itself as a plug.

`ok: false` carries `err` from §6 in place of `plugs`: `no_link` when the device is not on a
network, `busy` when another plug operation holds the sweep's sockets.

### `plug_result`

Sent once, in answer to `plug_set` — **after the action completes**, which is the one
deliberate inversion of `power_result`'s reply-before-action rule. `power` replies first
because the action destroys the process that would reply; nothing here destroys anything —
the actor is beside the plug, not behind it — so the strong claim is available and a caller
about to trust that a hung machine has been power-cycled deserves it. For `state: "cycle"`
that means the reply arrives only after the *on* leg, several seconds after the frame.

```json
{ "t": "plug_result", "req_id": "…", "ok": true, "state": "on" }
{ "t": "plug_result", "req_id": "…", "ok": false, "err": "plug_unreachable", "presence": "absent" }
```

`state` is the state the plug was left in, present only on success — and it is **observed,
never assumed**. Gen1 devices echo the relay's new state in the set response itself; Gen2's
`Switch.Set` answers `was_on`, the *previous* state, so a device MUST follow a Gen2 set with
a confirming `Switch.GetStatus` and report what that read saw. A driver that echoed `was_on`
would report every successful `on` as `off`; one that echoed the request would report a plug
whose overpower protection re-tripped as happily on. On a healthy plug the confirming read
sees the requested state; when it does not, the caller gets the truth instead.

A `cycle` that has cut power and cannot complete or confirm the restore MUST retry the
restore on a fresh short budget — our firmware makes three further attempts a second apart —
before reporting failure. Past the cut, a first-miss failure is not an error report, it is a
machine left off at the wall over one lost segment. `ok: false` after that budget means the
restore really could not be confirmed, and carries `err` from §6, including the two
plug-specific codes.

When `err` is `plug_unreachable` — and only then — the frame MAY carry **`presence`**, which
says how the reach failed: `"mute"` means the plug's MAC was positively seen on the segment
during this attempt (an identity-confirmed probe answer, or an active ARP answer from the
re-resolve) yet the operation still failed — powered and associated, but not speaking HTTP;
`"absent"` means a re-resolve ran and the MAC was not found on the segment at all. Omitted
means unknown — the failure was local, before any resolve could run. A cached ARP entry MUST
NOT count as seen: passive history is not presence, and a stale entry would report a vanished
plug as merely mute. The field is additive: devices predating it never send it, and a
consumer MUST tolerate its absence.

### `plug_status_result`

Sent once, in answer to `plug_status`.

```json
{ "t": "plug_status_result", "req_id": "…", "ok": true, "on": true,
  "apower_w": 41.25, "voltage": 237.5, "energy_wh": 6.5, "rssi": -52 }
{ "t": "plug_status_result", "req_id": "…", "ok": false, "err": "plug_unreachable" }
```

`on` is the relay channel's state. The metering fields — instantaneous power in watts, mains
voltage in volts, lifetime energy in watt-hours — are **omitted where the hardware does not
measure them**, never sent as zero: zero watts is a reading (a machine off at the wall, which
is a finding), and "this plug cannot read watts" must not impersonate it. Gen1 plugs report
power and energy but not voltage; Gen1 energy counters are converted from the device's
watt-minutes before they get here, so the unit on the wire is always watt-hours. Values are
plain JSON numbers with at most three decimal places.

`rssi` is the plug's own Wi-Fi signal in dBm, a plain integer, present only on successful
results and only when the device reported it — Gen1 states it in the `/status` body itself,
Gen2+ answers a separate `Wifi.GetStatus` read whose failure never fails the status: the
switch state and metering are the product, the signal a bonus fact. Omitted under the same
rule as the metering fields, and additive — older devices never send it, and a consumer MUST
tolerate its absence.

An `err` of `plug_unreachable` carries the optional `presence` field under `plug_result`'s
rules.

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

### `plug_fw_check_result`

Sent once, in answer to `plug_fw_check`.

```json
{ "t": "plug_fw_check_result", "req_id": "…", "ok": true,
  "current": "1.4.4", "latest": "2.0.0", "has_update": true }
{ "t": "plug_fw_check_result", "req_id": "…", "ok": true,
  "current": "2.0.0", "has_update": false }
{ "t": "plug_fw_check_result", "req_id": "…", "ok": false, "err": "plug_unreachable" }
```

`current` is the build the device reports it is running, verbatim in the device's own dialect
(Gen2's plain `1.4.4`, Gen1's long build string). `latest` is present only when the vendor's
check named something newer — never an echo of `current` — and `has_update` travels as its
own boolean because the DEVICE saw the vendor's answer and the relay did not: a Gen1 `/ota`
reply echoes `new_version` even when nothing is newer, and deriving the flag by comparison
upstream would re-learn that mistake.

An `err` of `plug_unreachable` carries the optional `presence` field under `plug_result`'s
rules.

### `plug_fw_update_result`

Sent once, in answer to `plug_fw_update`, on acceptance.

```json
{ "t": "plug_fw_update_result", "req_id": "…", "ok": true }
{ "t": "plug_fw_update_result", "req_id": "…", "ok": false, "err": "plug_unreachable" }
```

`ok: true` means the plug ACCEPTED the update order and nothing more. The flash and the
reboot happen on the device's own schedule; the reads that follow will fail while it does,
and that failing is the update working. `ok: false` carries `err` from §6 including the two
plug-specific codes; an `err` of `plug_unreachable` carries the optional `presence` field
under `plug_result`'s rules.

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

### `bye` — optional

```json
{ "t": "bye", "reason": "suspend" }
```

Deliberate silence, announced. A device that knows it is about to stop talking — the machine
under a software emitter is suspending or shutting down, or the emitter process is being stopped
— MAY say so before it goes, so a relay can tell silence-by-design from a device that died
mid-sentence. `reason` is `suspend`, `shutdown`, `stop` or `uninstall`.

`uninstall` is the one reason that is not about silence. It says this emitter is being removed
from the machine and will never speak again, and it exists because none of the others could
carry that meaning: `stop` is sent on every reboot and every service restart, so a relay acting
on it would retire live emitters nightly. A sender MUST send it only while the software is
actually being removed, and MUST still complete the removal if the frame cannot be delivered —
an uninstall that a network fault could block is a worse failure than a stale record.

Fire-and-forget: no reply, no `req_id`, and the sender MUST NOT wait for anything before
proceeding — the whole point is that the process may be frozen milliseconds later. A relay MAY
ignore the frame entirely (an unknown `t` is already ignorable under §10, which is what makes
this additive). A relay that acts on it SHOULD treat the announcement as spent the next time the
same device completes authentication: the device speaking again is the proof the goodbye no
longer describes the world.

The frame is advisory and unauthenticated in what it CLAIMS (any authenticated device can say
`suspend` while meaning anything), so a relay MUST NOT attach consequences to it beyond
expectation-setting — suppressing a "device went quiet" alarm is the intended use; extending an
entitlement, skipping a check, or holding resources open is not.

`uninstall` is the single exception, and it is safe for a reason worth stating: every other
reason makes a claim about the WORLD, which a device is in no position to prove, while this one
makes a claim about ITSELF. The most it can do is end the device that authenticated to send it,
so the worst a lying device achieves is its own retirement. A relay MAY therefore retire the
sending device on `uninstall` — and MUST NOT let it reach any other device, account or record. A dongle has no reason to send
it: firmware cannot see a power cut coming, and that asymmetry is the signal's value — absence
of a `bye` before silence is what distinguishes a failure worth reporting.

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
  "server": "roosterwake-relay/1.0",
  "now": 1785283200,
  "features": ["wake", "status"]
}
```

`now` is relay wall-clock as a Unix timestamp. Devices MAY use it to sanity-check their SNTP
result. Devices MUST NOT use it *instead* of SNTP for certificate validation — by the time
this frame arrives, the certificate has already been accepted.

`features` is optional and lists the subset of this device's capabilities the service will
currently act on — the intersection of what the device offers with what the operator's
arrangement with the service includes. It exists so a device can tell somebody standing in front
of it *why* nothing happens, instead of leaving them to discover it by trying: "shutdown is not
included on this plan" is an answer, and a command that vanishes silently is not.

**It is advisory and a device MUST NOT enforce it.** A device that refused a command absent from
`features` would be applying a policy it cannot verify, on a machine its operator controls, on
the say-so of whatever it is connected to. The service is the only side that can decide what it
will do, so it decides at the point of sending. A relay that reports no `features` is telling a
device nothing, which is what a self-hosted relay with no account model should say.

Rejection: `{ "t": "hello_ack", "ok": false, "err": "auth" }` followed by close `1008`.

### `features`

```json
{ "t": "features", "features": ["wake", "status", "power"] }
```

Replaces the list last carried by `hello_ack`, for the case where the arrangement changes while
the device is connected. There is no reply and no `req_id`: nothing depends on it arriving, and
a device that never receives one simply keeps reporting what it was told at connection time.

Sent whenever the set changes, not on a schedule — a device on a plan nobody has touched in a
year receives exactly one of these, in its `hello_ack`.

### `workspaces`

```json
{ "t": "workspaces", "list": [
  { "id": 7, "label": "cloud-cut", "path": "C:\\Users\\phili\\Documents\\cloud-cut",
    "provider": "claude" }
] }
```

The directories a remote AI session may be started in, pushed to devices advertising `session`
— the `features` shape exactly: advisory, no reply, no `req_id`, sent whenever the account
holder's list changes and once at connection time, and **`list` REPLACES the previous list
whole**. It is the entire truth, never a delta; an entry the push no longer carries is a
workspace the owner deleted, gone from the device too.

The split between this push and `session_start` is the security arrangement, and it is the
point: the command names only an `id`, and the directory that id resolves to arrived HERE, from
the service, out of the account holder's own configuration — so no command, however confused or
hostile its origin, can aim the device's CLI at a path by naming one. A device SHOULD persist
the list, because the push and the command travel at different times and a start arriving on a
fresh connection must resolve against what the relay said last.

Bounds a device MUST hold the list to: at most 32 entries, `label` at most 64 characters,
`path` at most 512. An entry past any bound is **dropped, with a local log line** — never
truncated, because a truncated path is a different directory and a session started in almost
the right place is worse than one refused. `label` and `path` are the owner's own words and
paths, untrusted like every string in §4; `provider` names whose CLI serves the workspace.

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

An `adopt` that carried an `enrol_token` (§4) is answered `bound` and never `pending` — the
token was minted by an account holder, so the account exists by construction. The ack MAY then
carry one optional field, `machine`, reporting what the service did about saving the device's
host as a wakeable machine:

```json
{ "t": "adopt_ack", "ok": true, "state": "bound", "machine": "created" }
```

| `machine` | Meaning |
|---|---|
| `created` | The host was saved to the account's machine list, named from `host` or its first hardware address. |
| `exists` | A machine with that address was already on the list. Its stored name is untouched — the owner's words, not the installer's. |
| `quota` | The account's machine allowance is full. The bind stands; the machine was not saved. |
| `none` | The device reported no hardware addresses, so there was nothing to save by. |

All four are advisory: the device's part ended at `bound`, and the field exists so an installer
log can say which machines arrived wake-ready. A device that does not understand it ignores it,
per §10.

A refusal is `{ "t": "adopt_ack", "ok": false, "err": "bad_frame" }` for an address that is not
plausibly one, or `"internal"`. The token path adds three refusals of its own — `bad_token`,
`not_entitled`, `device_limit` (§6). A device MUST NOT retry a refusal on the same connection; a
relay that does not implement adoption simply never answers, and the device gives up at the
end of the connection.

### `wake`

```json
{ "t": "wake", "req_id": "…", "mac": "AA:BB:CC:DD:EE:FF", "repeat": 3 }
```

`repeat` is optional, 1–5, default 3 — the number of bursts. Devices MUST clamp out-of-range
values rather than rejecting the request.

**`mac` is required.** A `wake` without one is answered `ok:false, err:"bad_frame"` (§6) —
it is a missing required field, not a request to be interpreted. The caller is the only side
that knows which machines exist, so a device asked to wake nothing in particular has nothing
to fall back to and no way to guess; a relay that lets a caller omit the MAC must resolve one
itself before the frame leaves.

### `power`

```json
{ "t": "power", "req_id": "…", "action": "sleep" }
```

Asks the device to change the power state of the machine it runs on. Only sent to devices
advertising the `power` capability.

`action` is **required** and is one of:

| `action` | Meaning |
|---|---|
| `sleep` | Suspend to RAM. The machine stays wakeable by the same magic packet that woke it. |
| `restart` | Reboot. |
| `shutdown` | Full power off. |

Anything else — a missing `action`, an unknown string, a non-string — is answered
`ok:false, err:"bad_frame"`. It is not clamped and not defaulted: there is no safe guess between
"suspend this machine" and "switch it off", and a device that picked one would be choosing on
behalf of a caller who failed to say.

**`sleep` is the action a caller should reach for first**, and the reason is mechanical rather
than editorial. A sleeping machine wakes reliably; a machine that has been shut down wakes only
if its firmware and adapter were configured for it, which frequently they are not (see
`wake_from_off` in `status_result`). Shutting a machine down can therefore end a caller's ability
to reach it at all, which no other command in this protocol can do.

There is no `power` command for a machine other than the one the device runs on. A device
switches off its own host and nothing else — the address in a `wake` names a peer on the
segment, but powering down a peer would require an agreement with that peer that this protocol
does not have and should not invent.

### `rdp_enable`

```json
{ "t": "rdp_enable", "req_id": "…" }
```

Asks the device to switch Remote Desktop on for the machine it runs on, so that a caller who has
just woken a machine and been told its Remote Desktop is off has something to press. Only sent to
devices advertising the `rdp` capability.

The device answers `rdp_enable_result` (§4) **after** doing the work, unlike every other command
here — that section says why, and the difference is the reason this is a frame of its own rather
than a fourth `power` action. A `power` frame carries an acceptance semantics in its reply that
this command cannot honestly use, and a receiver cannot tell two meanings apart inside one frame
type.

**It takes no parameters, and that is a security property rather than an omission.** The two rules
below are the device's, and a relay has no field with which to soften them:

1. **Network-level authentication MUST be required**, and it MUST be set *before* connections are
   admitted. Consider the two partial failures: authentication first, then the write that admits
   connections fails, and the machine is left exactly as safe as it was with one setting tightened.
   The other order leaves a listener that establishes a session *before* authenticating, on a
   machine whose owner pressed a button in somebody's product. The ordering is the whole safety
   argument, not a preference.
2. **Nothing beyond the local network may be opened.** On Windows that means the firewall rule is
   enabled for the private and domain profiles and **never** for public. Nothing here touches a
   router, a UPnP mapping or a port forward, and no relay may ask it to.

A device that cannot do both MUST answer `unsupported` and change nothing. Doing the part it can
would be worse than refusing: it is exactly the pre-authentication listener rule 1 exists to
prevent, created by a command whose name says it is making things work.

**These rules bind any implementation of this verb, not only ours.** A device that answered
`rdp_enable` by opening a machine to the internet, or by admitting connections without
authentication, would be a materially more dangerous command wearing this one's name — and a
caller cannot tell which it is talking to, because a capability string is all it has to go on.
If your device would do something less safe than the above, do not advertise `rdp` and do not
implement this frame; add your own and let the difference be visible.

Our own agent implements this on Windows only — `fDenyTSConnections`, the RDP-Tcp WinStation's
`UserAuthentication`, and the built-in Remote Desktop firewall rule group — and a build for any
other platform simply does not advertise `rdp`. §4's rule keeps the command off those sockets
rather than leaving the device to refuse a frame it should never have been sent.

The built-in group is matched by display name, and real machines miss it: a Windows in another
display language localises the name, and machines exist whose group has been renamed or
stripped outright. Where the group cannot be matched — and only for that reason, never to route
around a privilege refusal — a device MAY fall back to adding **one explicit inbound rule of
its own** for the configured RDP port, under **exactly the same profile restriction** (private
and domain, never public), idempotently (any previous rule of the same name removed first). The
reply's `note` names which path succeeded (§4), because the two leave different artefacts for
whoever inspects the firewall later. A fallback that widened the scope would make the machine's
safety depend on which error path the command happened to take, which rule 2 exists to forbid.

Where Group Policy already answers the question, a device SHOULD answer `unsupported` rather than
`no_privilege`: a policy is not something elevation overcomes, and sending somebody to run their
agent as an administrator against a decision their organisation made wastes their evening.

There is no `rdp_enable` for a machine other than the one the device runs on, and there is no
frame that turns Remote Desktop off. Switching a listener on is a thing an absent owner asks for
because they cannot reach the machine; switching it off is a thing they can do from the session
this command gave them, and a remote verb for it would be a way to lock somebody out of their own
machine from the internet.

### `wake_prepare`

```json
{ "t": "wake_prepare", "req_id": "…" }
```

Asks the device to prepare its host machine to be WOKEN — to switch off the settings that
quietly defeat the magic packet this whole protocol exists to deliver. Only sent to devices
advertising the `ready` capability, and answered `wake_prepare_result` (§4) **after** the work.

The command exists because the two usual culprits are locally fixable in milliseconds and
remotely undiagnosable forever. On Windows they are, and the two `steps` of the reply name them:

- **`fast_startup`** — `HiberbootEnabled`, the setting that turns "shut down" into a hybrid
  hibernate most adapters will not wake from. The device sets it to 0.
- **`adapter`** — the wake-target adapter's `*WakeOnMagicPacket` driver property, and the power
  manager's arming of the device (`powercfg /deviceenablewake`). The device switches the
  property on and arms the adapter.

The adapter the device prepares is the one carrying the MAC it reports **first** in
`hello.macs` — the address a service registers as the machine's wake target — so the fix lands
on the interface a wake would actually arrive on, not merely some interface.

**It takes no parameters, `rdp_enable`'s reasoning**: there is no field with which a relay
could aim the writes at a different adapter or a different setting, and the two rules are the
device's own. A driver whose property does not exist is a `failed` adapter step with its own
sentence, never a guess — writing a property the driver never exposed configures nothing.

Like `rdp_enable`, this verb changes the machine rather than merely reading it, so the same
posture applies: a device MUST NOT restart the adapter to make the driver property bite (the
reply's `note` tells the truth about when it takes effect instead), MUST answer a concurrent
`wake_prepare` with `busy`, and SHOULD re-read the facts it just changed so its next
`status_result` describes the machine as it now is rather than as it was cached.

A device that advertises `ready` also reports the **wake-readiness facts** beside the connect
facts it already carries in `status_result` — additive members under §2/§10's unknown-field
rule: `fastStartup` (boolean), `wakeReady` (boolean: the wake-target adapter is armed AND its
driver's magic-packet switch is on), and `wakeDetail` (one bounded sentence naming the failing
half, present only beside a false `wakeReady`; reference bound 120 characters). Absent members
mean "could not read", never a guess — the block's standing rule. The facts are what give this
command a button to sit behind; the command is what makes the facts actionable.

There is deliberately no `wake_unprepare`. Preparing a machine to be woken is what an absent
owner asks for because a wake failed; the reverse is a hand-on-the-machine preference, and a
remote verb for it would be a way to strand somebody's machine from the internet.

### `hold_awake`

```json
{ "t": "hold_awake", "req_id": "…", "seconds": 3600 }
```

Asks the device to keep its host machine out of **idle** sleep for a bounded time — the long
download, the overnight render, the remote session that must not die under its user — answered
`awake_result` (§4) after the hold is actually staked. Only sent to devices advertising the
`awake` capability.

`seconds` is **required**: one minute to one day, `60`–`86400` inclusive. Anything else — a
missing field, a value outside the range, a non-integer, a string — is answered
`ok:false, err:"bad_frame"`, **never clamped and never defaulted**, on `power.action`'s
reasoning: a device that silently shortened "keep it up for a week" to a day would leave
somebody's overnight job dead on a machine they were told would stay awake. The ceiling exists
because an unbounded hold is a machine that never sleeps again on the say-so of one frame; a
caller with a longer genuine need re-asks, which keeps the deadline a standing decision rather
than a forgotten one.

**A new hold REPLACES any hold already standing, and that is the extend mechanism.** One
deadline stands at a time — always the most recently asked for, in either direction, so a short
new hold shortens a long old one too. There is no `busy` here and no queue: there is nothing to
interleave when the second request's whole meaning is "forget the first".

The hold restrains the **idle** timers and nothing stronger. A person at the machine — closing
the lid, pressing the power button, picking Sleep from a menu — wins immediately, and a `power`
frame's commanded sleep wins too: the hold is a stay against the machine drifting off on its
own, not an argument with anybody's hand. A device MUST NOT keep the display awake to keep the
system awake.

The bound is enforced on the device, in two layers, and the second is the one to trust. While
the process lives, its own timer releases the hold at the deadline — across relay reconnects,
which the hold deliberately survives, and across a device restart, from which the device
re-arms **the remainder** of the stated bound. And the OS-level state a hold sets **dies with
the process by construction**, so there is no failure mode — crash, kill, update, power cut —
that leaves a machine pinned awake by a promise nobody is keeping. The fail-safe direction is
always toward sleep: the worst a lost timer can cost is a machine that dozed off on schedule
after all.

### `release_awake`

```json
{ "t": "release_awake", "req_id": "…" }
```

Withdraws the hold, answered `awake_result` with `held: false`. **Idempotent**: releasing with
no hold standing clears a state that was already clear, and is answered as a success — the
caller asked for a machine that may sleep, and has one. It takes no parameters; there is exactly
one hold to release, or none.

A device that receives either frame with no `req_id` answers **nothing at all** — the `wake`
rule, the same silence.

### `session_start`

```json
{ "t": "session_start", "req_id": "…", "workspace_id": 7, "provider": "claude",
  "hold_seconds": 14400 }
```

Asks the device to launch a remote AI coding session on its host — `claude remote-control`, run
**as the machine's signed-in user**, in the workspace `workspace_id` names — and answered
`session_result` (§4) after the session is actually running and its environment URL captured.
Only sent to devices advertising the `session` capability, and **one session per machine**: a
start while one runs is answered `already_running`, whichever workspace it names, because the
caller's remedy is the session that exists.

`workspace_id` resolves against the last `workspaces` push and nothing else — the command
carries no path, deliberately (§5 `workspaces` carries the whole argument). An id the synced
list does not hold is `unknown_workspace`, its own code because its remedy (check the workspace
list) is not `bad_frame`'s (fix the frame). `provider` MUST be `claude`; a device answers any
other value `bad_frame` rather than launching the wrong tool under the right reply.

`hold_seconds` is **required**: `60`–`86400` inclusive, whole seconds, refused `bad_frame`
outside — never clamped and never defaulted, `hold_awake.seconds`' rule for `hold_awake`'s
reason. The service is the side that owns the default; a device that invented one would decide
how long somebody's machine stays up on a frame that failed to say. A successful start stakes
**the one keep-awake hold** (the `awake` machinery, same hold, same fail-safes), and the
session's deadline REPLACES any hold already standing — one deadline at a time, always the most
recently asked for, which is §5 `hold_awake`'s replacement rule applied across capabilities. A
remote session on a machine that dozes off mid-thought is the exact fault the hold exists for.

The launched session is **detached from the device's own process on purpose**: an agent update
or crash MUST NOT kill a conversation somebody is mid-thought in. The device records the
session persistently, verifies the process still runs when it restarts, re-adopts one that does
— `status_result.session` keeps reporting it — and buries one that died, releasing its hold: a
dead session's hold serves nobody. The device MUST NOT grant the CLI's own directory trust or
any consent beyond remote control's; a workspace the person never trusted in their own terminal
is answered `not_trusted`, and trust stays theirs to grant.

### `session_stop`

```json
{ "t": "session_stop", "req_id": "…" }
```

Kills the running session's process **tree** — not one PID; the spawn is a shell running a shim
running a server, and killing the root alone would orphan the part that matters — releases the
keep-awake hold, clears the recorded state, and answers `session_result` with `running: false`.
**Idempotent**: stopping with nothing running kills nothing, releases nothing (a hold standing
at that point is `hold_awake`'s, staked by somebody who never mentioned a session), and is
answered as a success — the caller asked for a machine with no session, and has one. It takes
no parameters; there is exactly one session to stop, or none.

A device that receives either frame with no `req_id` answers **nothing at all** — the `wake`
rule, the same silence.

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

**`mac` is required**, on the same terms as `wake`. A `probe` without one is answered
`ok:false, err:"bad_frame"`.

### `scan`

```json
{ "t": "scan", "req_id": "…" }
```

Asks the device which other hosts are on its own segment, so that a caller can offer a list to
choose from instead of asking somebody to read a MAC address off the machine they mean to wake.

It takes no parameters. The range swept is the device's own subnet and the bounds on the sweep
are the device's to choose, because they depend on what the radio and the address space can
stand — a relay that could set them could ask a device to spend an unbounded time off the air.

The device answers exactly once, and may take **up to 15 seconds** to do it: an ARP sweep of
the subnet with a name pass behind it. That is longer than a relay should hold a caller's
request open, so a relay SHOULD acknowledge the command as soon as it is sent and let the
answer be collected separately, as it does for `probe`. Only sent to devices advertising the
`scan` capability.

A device MUST answer a second `scan` that arrives while one is running with `busy` rather than
queueing it: the sweep already bounds itself in time, and queueing turns one slow command into
an unbounded backlog of them.

### `plug_scan`

```json
{ "t": "plug_scan", "req_id": "…" }
```

Asks the device which smart plugs are on its own segment, so a caller can offer a list to
claim from. Only sent to devices advertising the `plug` capability.

It takes no parameters, on `scan`'s grounds: the range and the bounds are the device's to
choose. Our firmware runs the same ARP sweep `scan` uses and then asks everything that
answered `GET /shelly`, two sockets at a time — an identification, not a port scan: one
request to one well-known path, and whatever answers with anything else is dropped without
another byte. The device answers exactly once and may take **up to 25 seconds**; a relay
SHOULD acknowledge and collect, as for `scan`. A second `plug_scan` — or any plug command —
while one is running is answered `busy` rather than queued, and so is a `plug_scan` while a
set or status is in flight: the sweep and a live command would contend for the same two
sockets, which are the whole budget.

### `plug_set`

```json
{ "t": "plug_set", "req_id": "…", "mac": "00:00:5E:00:53:02", "ip": "192.168.1.60",
  "channel": 0, "state": "cycle", "off_ms": 5000 }
```

Switches one relay channel of a plug on the device's own segment. Only sent to devices
advertising the `plug` capability. The device answers `plug_result` (§4) **after** the action
completes — for a `cycle`, after the restoring *on* — so a relay MUST size this command's
patience from the frame rather than using a flat figure: `off_ms + 10000` covers the dwell
plus the driver's own timeouts and retries.

**`mac` and `ip` are both required.** The MAC is the plug's identity — the thing a caller
stores — and MUST be a unicast address, refused `bad_mac` otherwise on `wake`'s reasoning: no
device holds a group address, so naming one is not a request to interpret. The IP is only
where that identity was last seen; DHCP moves it. Before ANY set the device MUST confirm the
identity at the address with `GET /shelly` — a reassigned lease is detected, never driven:
switching whatever lives at a remembered address is how the wrong appliance loses power. When
the address does not answer, or answers as something else, the device re-resolves the MAC
(a targeted ARP mini-sweep here; mDNS where an implementation has it) and tries once more
before failing `plug_unreachable`.

**`ip` MUST name a host on the device's own subnet**, and anything else — a public address,
another RFC 1918 range, the network or broadcast address, the device itself — is answered
`bad_frame` with no socket ever opened. This is a security rule, not a routing nicety: the
plug driver speaks plain unauthenticated HTTP wherever it is pointed, and without this rule a
compromised relay would have an HTTP client inside — and beyond — somebody's network
perimeter. The commands drive LAN peers; an address that is not one is a request this device
must never make.

`channel` is optional, default `0`, clamped into the device's plausible range — it exists for
the DIN-rail and PDU shapes, and nearly everything is a single-channel plug. A channel the
target hardware does not have is answered `plug_unsupported`: the plug itself refuses, and
its refusal is passed on rather than remapped to channel 0's answer.

`state` is **required**: `on`, `off` or `cycle`. Anything else — missing, unknown, a
non-string — is `bad_frame`, not clamped and not defaulted, on `power.action`'s reasoning:
there is no safe guess among "switch it on", "switch it off" and "cut this machine's power",
and a device that picked one would be choosing on behalf of a caller who failed to say.

`cycle` is off → wait `off_ms` → on → confirming read, reply after the on. `off_ms` is
optional, default 5000, **floor 3000, ceiling 60000**, clamped rather than rejected. The
floor is a safety property: below about three seconds a PC power supply's hold-up capacitors
can ride through the cut, and a cut that does not cut reports a power cycle that never
happened. The ceiling is a liveness one: an unbounded dwell holds the target dark and the
device's busy latch closed on the say-so of one frame.

A device whose relay connection drops mid-`cycle` MUST still complete the restore. The reply
is forfeit — its `req_id` belongs to a connection that no longer exists — but the restore is
the second half of an instruction already accepted, and abandoning it would leave a machine
off at the wall over a WAN blip. The caller's timeout is its signal to ask `plug_status`
what actually happened.

### `plug_status`

```json
{ "t": "plug_status", "req_id": "…", "mac": "00:00:5E:00:53:02", "ip": "192.168.1.60",
  "channel": 0 }
```

Reads one relay channel's state and, where the hardware meters, its power figures — answered
`plug_status_result` (§4). Only sent to devices advertising the `plug` capability. `mac`,
`ip` and `channel` are exactly `plug_set`'s fields under exactly its rules, including the
identity confirmation, the re-resolve, and the own-subnet requirement. One command of any
plug kind runs at a time; a second is answered `busy`.

### `plug_fw_check`

```json
{ "t": "plug_fw_check", "req_id": "…", "mac": "00:00:5E:00:53:02", "ip": "192.168.1.60" }
```

Reads the plug's firmware standing — answered `plug_fw_check_result` (§4). Only sent to
devices advertising `plugfw`, which is deliberately its own capability rather than a fourth
frame under `plug`: every `plug` implementation released before these frames existed would
otherwise be sent a question it silently ignores, and a capability refusal is the clean
answer an old actor gives instead. `mac` and `ip` are `plug_set`'s identity fields under its
rules; there is no `channel`, because firmware is a fact about the device — a multi-channel
switch runs one build however many feeds it carries.

### `plug_fw_update`

```json
{ "t": "plug_fw_update", "req_id": "…", "mac": "00:00:5E:00:53:02", "ip": "192.168.1.60" }
```

Tells the plug to install its vendor's current stable build — answered
`plug_fw_update_result` (§4) on ACCEPTANCE, never on completion: the plug downloads the
build from its own vendor over the local network's internet connection, flashes and reboots
on its own, typically inside a minute, and a reply held across a device reboot would arrive
as a transport failure about an update that is working. A caller watches the outcome by
polling `plug_fw_check` until `current` moves. Same identity rules and `plugfw` gate as the
check; one command of any plug kind runs at a time.

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

Returned in `err` on `wake_result`, `power_result`, `rdp_enable_result`, `awake_result`,
`session_result`, `probe_result`, `scan_result`, `plug_scan_result`, `plug_result`,
`plug_status_result`, `hello_ack`, `adopt_ack`, `ota_reject` and `ota_result`.

| Code | Meaning |
|---|---|
| `auth` | Authentication failed, or `device_id` unknown |
| `bad_frame` | Malformed JSON, missing required field, or frame too large. A `wake` or `probe` with no `mac` is this, as is a `power` with no valid `action` |
| `bad_mac` | MAC address failed to parse |
| `no_link` | Wi-Fi link down at the moment of the request |
| `send_failed` | The network stack refused the datagram |
| `no_privilege` | The device is running without the rights the command needs |
| `busy` | A conflicting operation is already running |
| `unsupported` | Command names a capability this device did not advertise, or an action its host cannot perform |
| `internal` | Anything else; the device or relay SHOULD log detail locally |

`no_privilege` is separated from `internal` because it is the one failure here with a remedy the
person reading it can act on: install the device as a system service, or run it with the rights
it needs. Folded into `internal` it would read as a defect in the software and be reported as
one.

Remote-session codes, on `session_result` only, from devices advertising `session`. Each is
separate for `no_privilege`'s reason — it is the code that names the remedy:

| Code | Meaning — and whose move it is |
|---|---|
| `unknown_workspace` | `workspace_id` is not in the synced list. Check the workspace list; the frame itself is well-formed |
| `already_running` | One session per machine, and this machine has one. The remedy is the session that exists — stop it, or use it |
| `no_user_session` | Nobody is signed in at the console, so there is no user to run the CLI as. Somebody signs in at the machine |
| `not_trusted` | The CLI refused the workspace directory. Trust is granted by the person, in their own terminal, once per directory — never by the device |
| `version_old` | The installed CLI predates remote control (needs ≥ 2.1.139). Update the CLI |
| `session_failed` | Everything else. The reply carries `detail` — one line of the CLI's own words — because a launch that failed for none of the named reasons is diagnosed from what the tool actually said |

A relay that predates these folds all six into `internal`, which the rule above this table
makes safe. A failed start leaves nothing behind — no process, no hold, no recorded state — so
none of them poisons a retry.

Adoption-specific codes, on `adopt_ack` only, and only from a relay that implements the §4
token path:

| Code | Meaning |
|---|---|
| `bad_token` | The presented enrolment token binds nothing. One code for every reason — unknown, revoked, malformed — because the presenter is unauthenticated and a distinguishable refusal would let a token be probed for "valid but revoked" |
| `not_entitled` | The account behind the token no longer has a plan that includes enrolment tokens |
| `device_limit` | The account is at its device ceiling |

None of them invites a retry: the device's recovery is a person minting or fixing something at
the service, and a device MUST treat all three exactly as it treats any other `adopt_ack`
refusal.

Plug-specific codes, on `plug_result` and `plug_status_result` only:

| Code | Meaning |
|---|---|
| `plug_unreachable` | The plug answered at neither the cached address nor any address a re-resolve could trace its MAC to. The plug may be unpowered, off the network, or the caller's record stale beyond recovery |
| `plug_unsupported` | Something answered, but not usefully: not a Shelly of a generation this device drives, a channel the hardware does not have, or a device-side refusal. Retrying will not help; a person looking at the hardware might |

The split carries the remedy, `no_privilege`-style: `plug_unreachable` invites checking the
plug's own power and Wi-Fi, `plug_unsupported` invites checking what was claimed. A `plug_set`
that fails after the cut — the restore could not be confirmed within the device's retry
budget — reports `plug_unreachable`, and the honest next move is a `plug_status` once the
plug is reachable again, not an assumption in either direction about a machine's power.

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

Error codes are a closed set for v2. New codes require a minor version bump, and receivers
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

`v` in the `hello` frame is the **major** protocol version. It is `2`.

**Additive changes do not bump the major version.** New frame types, new optional fields, new
capability strings and new error codes may all be added within v2. This is safe precisely
because §2 requires unknown frames and unknown fields to be ignored silently. If your
implementation logs an error or closes the connection on an unknown `t`, it is not v2
compliant, and it will break the first time we ship a feature.

**The subprotocol token does not carry the major version** and stayed `roosterwake.v1` across
this bump — §1 says why. Version negotiation happens at `hello`, where a relay can answer.

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

A relay is v2-conformant if it:

1. Echoes the `roosterwake.v1` subprotocol.
2. Implements the §3.2 handshake, including constant-time proof comparison, fresh nonces, and
   sending `challenge` even for unknown device IDs.
3. Answers `{"t":"ping"}` with exactly `{"t":"pong"}`.
4. Sends `wake` **with a `mac`** and handles `wake_result`, preserving `req_id`.
5. Ignores unknown `t` values and unknown fields without erroring.
6. Never sends a frame larger than 2048 bytes.
7. Enforces one live connection per `device_id`, closing the displaced one with `4001`.

Everything else — `status`, `power`, `rdp_enable`, `probe`, `scan`, `plug_scan`, `plug_set`,
`plug_status`, `log`, `enrol`, `adopt`, `ota_offer` — is optional. A relay that implements `rdp_enable` MUST read `rdp_enable_result` as a
completion rather than an acceptance (§4) and MUST NOT send the command to a device that did not
advertise `rdp`; implementing it as a fourth `power` action is not conformant, because the reply
semantics of the two are opposite.

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
| 2 | 2026-08-30 | **Making the wake actually land.** One new capability, `ready`, the one command it gates — `wake_prepare`, answered by `wake_prepare_result` — and three wake-readiness facts beside the connect facts in `status_result`: `fastStartup`, `wakeReady`, and `wakeDetail` (one bounded sentence naming the failing half). Everything above this row assumes the magic packet works; this row is for the machine where it silently does not, and the two usual culprits are locally fixable in milliseconds and remotely undiagnosable forever — Fast Startup turning "shut down" into a hybrid hibernate most adapters will not wake from, and the adapter's own Wake-on-Magic-Packet being off in the driver or un-armed in the power manager. Born from a live failure: a real desktop ignoring every wake sent to it. The facts diagnose (against the adapter carrying the FIRST `hello.macs` entry — the machine's registered wake target, so the sentence is about the interface a wake would actually arrive on); the command repairs, and its reply is a per-step ledger (`fast_startup`, `adapter`: `done`/`already`/`failed`) because a half-repaired machine must arrive as exactly that, never flattened into "it failed". `already` counts as success; `ok` is false exactly when a step failed. One deliberate physical truth rides the reply's `note`: a changed driver property bites only after the adapter restarts or the next boot, and the device MUST NOT restart the adapter — its own relay connection runs over it. No parameters, no `wake_unprepare` (a remote verb for making a machine unwakeable would be a way to strand it). **The same change hardens `rdp_enable`'s firewall step** for another live failure: where the built-in Remote Desktop rule group cannot be MATCHED (localised or stripped display name — seen on a real machine), the device may fall back to adding one explicit inbound rule of its own on the configured RDP port, same profiles (private and domain, never public), idempotent by delete-then-add — and `rdp_enable_result` gains a success `note` naming which path succeeded (`firewall group enabled` / `firewall rule added`), because the two leave different artefacts in wf.msc. Additive throughout: `v` stays 2. |
| 2 | 2026-09-01 | **A goodbye that ends a device.** One new `bye` reason, `uninstall`, and the first consequence this specification permits a relay to attach to that frame. Every other reason describes SILENCE and makes a claim about the world — a machine suspending, a process stopping — which a device cannot prove, which is why §4 forbids acting on them beyond expectation-setting. This one makes a claim about ITSELF: the emitter is being removed from the machine and will not speak again. That asymmetry is what makes it safe to act on, because the most a lying device can achieve is its own retirement, and a relay MUST NOT let it reach any other device, account or record. It exists because no existing reason could carry the meaning: `stop` is sent on every reboot and every service restart, so a relay retiring on it would revoke live emitters nightly. The sender is the INSTALLER rather than the running agent, on a true uninstall only, and it must send while the identity file it authenticates with still exists — which also bounds the cases it can cover: a machine that is offline when the software is removed leaves its record behind, and that record is the account holder's to delete. A sender MUST complete the removal whether or not the frame is delivered; an uninstall a network fault could block is a worse failure than a stale row. Additive under §10: `v` stays 2, and a relay that ignores the reason simply files it as it always did. |
| 2 | 2026-08-29 | **A coding session on the machine, started from anywhere.** One new capability, `session`, the two commands it gates — `session_start` and `session_stop`, answered by one new frame, `session_result` — and one advisory push, `workspaces`. Everything above this row moves a machine between power states or holds it in one; this is the first frame that starts WORK on it: the device launches `claude remote-control` as the machine's signed-in user, captures the environment URL from the CLI's own output, and hands it back, so the owner continues coding from the mobile app against a machine they may just have woken. **The split between the push and the command is the security arrangement**: `session_start` names only a workspace id, and the directory it resolves to arrived in `workspaces` — the account holder's own configuration, replaced whole on every push, persisted device-side, bounded (32 entries, label 64, path 512, oversize entries dropped never truncated) — so no command can aim the CLI at a path by naming one. The reply follows `rdp_enable_result`'s rule: nothing here destroys the replier, so `ok:true` means the session is RUNNING and `env_url` was read, not assembled. `hold_seconds` is required and bounded (60–86400), refused `bad_frame` outside, never defaulted — the service owns the default — and a successful start stakes the ONE keep-awake hold, replacing any standing deadline, because a remote session on a machine that dozes off mid-thought is the exact fault the hold exists for. The session is deliberately DETACHED from the device process: an agent update must not kill a conversation, so the device persists the session, re-adopts a survivor at startup by checking the actual process, and buries a dead one hold-and-all. One session per machine; stop kills the process TREE, is idempotent, and releases the hold. Six new codes on `session_result` only — `unknown_workspace`, `already_running`, `no_user_session`, `not_trusted`, `version_old`, `session_failed` (with `detail`: the CLI's own line) — each separate because each names a different mover, and directory trust stays the person's to grant: the device never answers the CLI's trust prompt, only remote control's own consent. `status_result` gains a `session` block, present exactly while one runs — the `awake_until` oracle one member over. Additive throughout: `v` stays 2. |
| 2 | 2026-08-29 | **Holding a machine awake, for as long as somebody said.** One new capability, `awake`, and the two commands it gates — `hold_awake` and `release_awake` — answered by one new frame, `awake_result`. Everything above this row changes which power state a machine is IN; this holds it in the one it has, for the download, the render or the remote session that must not die under its user because the idle timer ran out. The reply follows `rdp_enable_result`'s rule, not `power_result`'s: nothing here destroys the replier, so `ok:true` means the hold is SET and `until` is the deadline the device actually armed — read back, never recomputed on the caller's clock. `seconds` is required and bounded (60–86400 inclusive), refused `bad_frame` outside, never clamped: a device that silently shortened a week to a day would leave an overnight job dead on a machine somebody was told would stay up. A new hold REPLACES the standing one — that is the extend mechanism, one deadline at a time and always the most recent — and release is idempotent, because "may sleep now" is not a request that can fail by already being true. The hold restrains the IDLE timers only: a lid, a power button or a commanded `power` sleep wins immediately, and the display is never kept lit. The bound is enforced device-side in two layers — a timer that survives reconnects and re-arms the REMAINDER across a restart, and an OS state that dies with the process by construction — so every failure mode falls toward sleep, never toward a machine pinned awake by a promise nobody is keeping. `status_result` gains `awake_until`, present exactly while a hold stands: the honest oracle, since a reply's `until` can be stale the moment a later hold replaces it. Additive throughout: `v` stays 2. |
| 2 | 2026-08-21 | **Hard power, from beside the machine.** One new capability, `plug`, and the three frame pairs it gates — `plug_scan`/`plug_scan_result`, `plug_set`/`plug_result`, `plug_status`/`plug_status_result` — plus two error codes, `plug_unreachable` and `plug_unsupported`. Everything above this row moves a machine's own switches; this is the rung below all of it, for the machine whose kernel is hung and whose adapter never armed: a smart plug on the same segment cuts and restores the AC, driven by the device over plain local HTTP (Shelly Gen1 REST and Gen2+ JSON-RPC), with no vendor cloud and no internet route to the plug at all. **The reply is the protocol's one deliberate inversion of `power`'s rule**: `power_result` is sent before the action because the action destroys the replier, but a plug's actor stands beside the machine, not behind it, so `plug_result` arrives AFTER the work and its `state` is read back, never assumed — Gen2's `Switch.Set` answers the PREVIOUS state, which is exactly the trap the confirming read exists to step over. `cycle`'s `off_ms` has a floor because a PSU's hold-up capacitors can ride out a short cut, and a ceiling because an unbounded dwell holds a machine dark on one frame's say-so; a device that has cut power retries the restore on a short budget before admitting failure, and completes it even when the relay connection has died under the command — past the cut, giving up is not an error report but a machine left off at the wall. Identity is the plug's MAC with the IP a hint: every set re-confirms who answers at the address before driving it, because DHCP reassigns leases to appliances that must not lose power for it. The target address MUST be on the device's own subnet, refused `bad_frame` before any socket opens — the driver is an unauthenticated HTTP client, and this rule is what keeps a compromised relay from aiming it. Additive throughout: `v` stays 2. |
| 2 | 2026-08-15 | **Deliberate silence, announced.** One new optional device→relay frame, `bye` (`reason`: `suspend`, `shutdown` or `stop`), fire-and-forget with no reply and no capability — capabilities gate relay→device commands, and nothing here invites one. A software emitter runs on a machine whose whole reason for carrying it is to be asleep most of the time, and a relay watching for silence cannot otherwise tell that ordinary night from a crash: the frame is the difference, sent in the milliseconds the OS grants between "the system is suspending" and the freeze. The specification deliberately bounds what a relay may do with it — set expectations, nothing more — because the claim is cheap to make and impossible to verify; and it deliberately notes that a dongle never sends it, because firmware cannot see a power cut coming, which is exactly why absence-of-`bye` stays meaningful. A relay treats the announcement as spent on the device's next completed authentication. Additive under §10: `v` stays 2, old relays ignore it. |
| 2 | 2026-08-11 | **Switching Remote Desktop on.** One new capability, `rdp`, and the frame pair it gates — `rdp_enable` and `rdp_enable_result`. A device that runs *on* a machine can already tell a service that the machine's Remote Desktop is switched off; this is the button beside that sentence, and the alternative it replaces is talking somebody through an elevated registry edit on a machine they cannot see, from a phone. **It is a frame of its own rather than a fourth `power` action, and the reason is the reply.** `power_result` is an acceptance sent BEFORE the action, because the action destroys the process that would otherwise send it — that is the strongest claim available there. Nothing about enabling a listener destroys anything, so `rdp_enable_result` is sent AFTER the work and `ok:true` means the change is made. It has to: "Remote Desktop is on" is a sentence somebody acts on by opening a client against a machine they cannot see, and one frame type cannot carry two opposite meanings for a receiver to tell apart. The reply also carries **`step`** — `policy`, `nla` or `firewall`, which of the three settings stopped it — and **`note`**, the tool's or policy's own sentence. `step` exists for one row of its own table: a `firewall` stop leaves Remote Desktop switched ON behind a firewall that still drops it, which from a client is indistinguishable from a machine that is switched off, and a caller that flattened the three into "it failed" would send somebody to diagnose a dead machine that is in fact listening. **The command takes no parameters, and that is a security property**: network-level authentication MUST be required and MUST be set before connections are admitted (the reverse order leaves a listener that establishes a session before authenticating, created by a button in somebody's product), and nothing beyond the local network may be opened — private and domain firewall profiles only, never public, no router, no UPnP, no port forward. Those rules bind any implementation of this verb, because a capability string is all a caller has to go on: a device that would do something less safe under this name should implement a different frame and let the difference be visible. `rdp` is separate from `power` because the two differ in availability rather than in privilege — our agent implements this on Windows alone — and §4's rule then keeps the command off every other socket, instead of leaving a Linux agent to silently ignore a frame whose caller waits out a timeout. Additive throughout: `v` stays 2. |
| 2 | 2026-08-10 | **Token adoption.** Two optional fields on `adopt` — `enrol_token` and `host` — one optional field on `adopt_ack` — `machine` — and three `adopt_ack`-only error codes: `bad_token`, `not_entitled`, `device_limit`. The email path binds one machine per typed address, which is the right shape for a person and the wrong one for a fleet: twenty installs mean twenty addresses typed and twenty invitations answered. An enrolment token is the account holder's own consent made portable — minted at the service, carried by an installer flag, presented in the frame the device already sends — so a fleet binds with nobody at a desk. A frame carrying both a token and an email is a token frame, because the token names an account precisely and the email would be a guess beside it. `host` is advisory display naming, untrusted like every name in §4; `machine` reports what the service did about saving the host as a wakeable machine (`created`/`exists`/`quota`/`none`), advisory too — the device's part ended at `bound`. The refusal codes are deliberately unhelpful to a probe: `bad_token` is one answer for unknown, revoked and malformed alike, because the presenter is unauthenticated and "valid but revoked" is a fact about somebody's account that a stranger should not be able to enumerate. Everything rides §10's unknown-field rule: a relay without accounts ignores the new fields and answers `adopt` exactly as it always did, and a device offered none of this behaves exactly as before. Additive throughout; `v` stays 2. |
| 2 | 2026-08-08 | **The other half of the power button.** One new capability, `power`, and the frames it gates — `power` and `power_result` — plus three additive fields and one push frame. Every wake in this protocol's history could turn a machine on and nothing could turn one off, which is not a gap in the feature list so much as a gap in the idea: a switch with one position. A device that runs *on* a machine can close it, and the whole of the change is about making that safe rather than making it possible. **`power_result` is specified to be sent before the action runs**, because the action destroys the process that would otherwise send it — so `ok:true` means accepted, the connection dropping is the confirmation, and no implementation can honestly do better. **`hello.macs`** lets a service tell which of an account's machines a software emitter is running on, fenced by a rule that a relay MUST NOT act on it before the handshake completes: the field turns a pre-authentication claim into a power command's destination, which is a different order of consequence from the `fw` string beside it. **`status_result.machine`** carries `wake_from_off`, and it exists because shutting a machine down can make it unwakeable — wake-from-S5 is often disabled in firmware, and Windows Fast Startup turns a shutdown into a hybrid hibernate most adapters will not wake from — so a caller that offers the action without reading the field is offering to strand somebody. Its `unknown` is a first-class answer for the systems whose tools will not say. **`hello_ack.features`** and the **`features`** push tell a device which of its capabilities the service will currently act on, explicitly advisory: a device that enforced a list it cannot verify would be applying somebody else's policy to a machine its own operator controls. One new error code, **`no_privilege`**, separated from `internal` because it is the only failure here whose remedy is something the reader can do. `power` is deliberately one capability rather than one per action — the same privilege exercised three ways — and there is deliberately no way to power down a machine other than the device's own host. Additive throughout: `v` stays 2, and §10's rule that unknown `t` values and unknown fields are ignored is what makes that true. |
| **2** | 2026-08-05 | **The device stops holding a list of the machines it can wake.** The first breaking change, and the whole of it: `config_push` and `config_ack` are **removed from the protocol**, `hello` and `status_result` no longer carry `targets`, the `config` capability is gone, and **`mac` is now required on `wake` and `probe`** — a frame without one is answered `bad_frame`, which §6 already defined as a missing required field. The device stored up to eight addresses and consulted them in exactly one case: a `wake` that named none, where it fell back to the first entry. Every caller — dashboard, API, setup page — already knew the MAC it meant, so the fallback was reachable only by a caller that had thrown that knowledge away, and the fix is for the caller to resolve it before the frame leaves. What the list cost was not the eight entries: it was `config_push` on every dashboard edit, the reconciliation that repaired a push a dongle missed while unplugged, the "which eight get sent" subset logic, a config-format field and a flash write per change — and a dongle carrying the names and addresses of the machines in somebody's house, which matters the day one is stolen, resold or returned. **Removing it also removes the one frame in which a relay writes to a device's persistent configuration**, so the rule in §11 that a relay cannot reconfigure a device is now a property of the frame set rather than a promise the firmware keeps. Two error codes retire with it: `no_target` described a state that can no longer exist, and `too_many` had exactly one producer. The subprotocol token stays `roosterwake.v1` — §1 and §10 say why a major bump does not move it. **§2's wakeable-address rule moved with the MAC**: a device used to apply it where a target was stored, and that path is gone, so it is now applied where the address arrives — a `wake` or `probe` naming a group, broadcast or all-zero address is answered `bad_mac` instead of being sent and reported as a success nothing came of. `firmware/docs/config-format.md` goes to **format version 2** in the same change; the target block is deleted rather than reserved and images of the previous version are not migrated. |
| 1 | 2026-08-03 | **Asking a device who else is on its segment.** One new capability, `scan`, and the frame pair it gates — `scan` and `scan_result`. Adding a target to a device meant reading a MAC address off the machine to be woken and typing it in, which is the least popular thing this product asks of anyone; the device is already on that segment and can go and ask. The capability is separate from `probe` even though both resolve addresses by ARP, because `probe` watches one address the caller already knows and `scan` enumerates ones it does not — a device may reasonably implement either without the other. `scan_result` is the first frame in the protocol whose natural size can reach §1's 2048-byte ceiling, so it is specified to drop hosts and set `truncated` rather than to grow, and to drop unnamed hosts first: the list exists to find one machine, and a host that answered a name query is likelier to be it. Names are carried but explicitly untrusted — they come from an unauthenticated peer on the local network — and §4 forbids matching anything against them. |
| 1 | 2026-07-31 | **Firmware updates over the relay connection.** Four new frames — `ota_offer`, `ota_accept`, `ota_reject`, `ota_result` — and the one exception to §1's "frames are text": the payload of an update the device has agreed to receive arrives as unfragmented binary frames. There is no second connection because there is no room for one; a TLS session costs 44 KB of a 64 KB heap on the reference device, so an image either shares this socket or does not arrive. The offer carries the image's signed header and **nothing else**, which is the whole of the security argument: board, length, version and payload digest are all inside the signature, so there is no unsigned restatement of them for a relay to lie in. A device with two slots writes the inactive one and restarts; the update proves itself by reconnecting, and a failure announces itself by the previous version reappearing rather than by silence. Binary frames outside a transfer close the connection with `1008`. |
| 1 | 2026-07-29 | Initial specification. |
| 1 | 2026-07-30 | **Enrolment and adoption.** Three new frames — `enrol`, `adopt`, `adopt_ack` — and the §3.4 rules a relay applies to the first. Until now a relay could only learn a token out of band, which meant a device nobody had registered in advance could never reach a hosted service at all: no path existed from a board somebody flashed themselves to a relay that would speak to it. `enrol` transmits the token exactly once, on first contact, and §3.1 now sets out why that exception is defensible and the two rules — a validated certificate, and the compiled-in relay URL — that fence it. §3.4's four-row table is the whole of the security argument: refuse only where the id is already owned, replace freely where it is not, so that the protection cannot itself become a way to lock people out of boards they hold. `adopt` carries an account address off a captive portal that has no route to the internet, which is the only moment in setup where the person's identity can be captured. §11 restates how a relay comes to hold a token, and records that possession of the hardware is treated as the ownership claim. |
| 1 | 2026-07-30 | Two rules the specification relied on but never stated, both found by building a surface on top of it rather than by reading it. **§2 now defines a wakeable address** — the relay had been accepting multicast and broadcast MACs that the firmware refuses, so a target saved in the dashboard was one the device silently declined to wake; the §5 example was itself a multicast address and is corrected. **§11 now says how a relay comes to hold a token**: out of band at provisioning time, in all cases, and explains why there is deliberately no enrolment frame — a device presenting a weaker credential to be issued a token would make that credential the real secret and would put it on the wire this protocol keeps tokens off. Neither change alters a frame. |
| 1 | 2026-07-29 | Clarifications from the second implementation (the hosted relay, on Cloudflare Durable Objects). Three more gaps, all found by deploying rather than by reading. **§1 and §3.3 contradicted each other on oversized frames** — §1 said close `1009`, §3.3 listed "oversized" among malformed-`hello` cases answered `bad_frame` + `1008`. §1 wins: the size check precedes any parse, and a receiver cannot report a parse result for bytes it declined to read. **`4002` must not be sent until the proof verifies** — closing as soon as a revoked `device_id` is recognised makes the close code an oracle distinguishing "known but revoked" from "never known", undoing §3.3. **§9 now says relays should not arm a dedicated liveness timer**: a 90-second alarm on a hibernating object wakes it 960 times a day to observe that nothing happened, costing more than the heartbeats §9 exists to make free. Detecting a stale connection cheaply beats detecting it promptly. |
| 1 | 2026-07-29 | Clarifications from the first implementation (`relay-reference`). Building against the spec surfaced nine gaps, all closed here. No frame shape changed; two limits narrowed, and one example was wrong. **`sent` is now defined as `ifaces.length × repeat`** and the §4 example corrected from 24 to 12 — the original figure was not derivable from any other field. **Frame size is now a symmetric 2048 bytes**; the device→relay bound was 8192, which no conforming frame approaches. Added close code **`4003`** (idle timeout), which `1008` could not represent without colliding with auth failure and corrupting the §8 backoff-reset rule. Added the **`config`** capability, without which §4's "MUST NOT send a command whose capability the device did not advertise" was unenforceable for `config_push`. **Removed the `log` capability** — no frame could enable it, so declaring it told a relay nothing actionable. Specified the relay's behaviour when a client omits the subprotocol, the response to a malformed `hello`, and `ok`/`err` on `probe_result` (a `probe` with a bad MAC previously had nowhere to report it). Clarified that rate limiting is per `device_id`, and that the unknown-device comparison must run before any provisioned check. |
