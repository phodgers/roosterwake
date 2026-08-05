# USB serial command channel (`usbcfg`)

**Protocol version 2** · Status: **stable**

A Rooster Wake device exposes a line-based command channel over USB CDC. It is how a computer
configures a dongle without going near the Wi-Fi captive portal, and it is a **public,
versioned contract**.

This channel is open and documented deliberately. Our hosted setup page at
`setup.roosterwake.com` drives it through the browser's Web Serial API — but the *channel* is
open, so anyone can drive it from a terminal, a shell script, a Python tool, or their own web
page. The polished guided experience is ours; the mechanism belongs to everybody.

---

## 1. Connecting

| | |
|---|---|
| Interface | USB CDC-ACM (a virtual serial port) |
| Baud rate | Ignored — USB CDC has no real line rate. Any value works |
| Framing | 8N1 nominally, again ignored |
| Line ending | Commands terminate with `\n`. A preceding `\r` is stripped |
| Encoding | UTF-8. Non-UTF-8 input is rejected with `ERR bad_frame` |
| Max line | 512 bytes including the terminator. Longer lines are discarded to the next `\n` and answered `ERR too_long` |

The device presents as VID `0x2E8A` (Raspberry Pi), with the product string
`Rooster Wake` and the serial number set to the 16-hex-character `device_id`. That serial
number is how a host tells two connected dongles apart without sending a command.

**The USB serial number is upper-case hex; `device_id` everywhere else is lower-case.**
The SDK derives the descriptor from the board's unique ID and emits upper case, while
PROTOCOL.md §2 specifies lower case for `device_id` on the wire and in configuration. Rather
than carry custom USB descriptors purely to change the case of sixteen characters, the two
are allowed to differ and **hosts MUST compare the serial number case-insensitively**. Do not
use it as a dictionary key alongside a wire-format `device_id` without normalising first —
that is the shape this mismatch will bite in.

**In BOOTSEL mode the device is not a serial port at all** — it enumerates as the RP2350 UF2
bootloader (mass storage plus the PICOBOOT vendor interface). A host that finds the bootloader
rather than a CDC port has a device awaiting firmware, not a broken one.

---

## 2. Command syntax

```
COMMAND [arg1 [arg2 ...]]
```

- Commands are **case-insensitive**; they are shown upper-case here by convention.
- Arguments are space-separated.
- An argument containing a space, a double quote, or a backslash **must** be double-quoted,
  with `\"` and `\\` as the only escapes. Wi-Fi SSIDs routinely contain spaces, so this is the
  common case, not an edge case:

```
SET_WIFI "Sarah's Wi-Fi 5GHz" "p@ss word\"with quotes"
```

- Empty lines are ignored and produce no response.

## 3. Responses

Exactly one response line per command:

```
OK [<json>]
ERR <code> <message>
```

- `OK` may carry a single-line JSON object. There is never a trailing newline inside it.
- `ERR` codes are lower-case identifiers from the closed set in §6. The message is
  human-readable and may change between versions — **parse the code, never the message.**
- Responses arrive in order. There is no pipelining and no request ID; send one command, read
  one response.

**Unsolicited output.** The device may emit lines beginning with `# ` at any time — diagnostic
breadcrumbs, only when diagnostics are enabled. A host MUST ignore any line starting with
`# ` when waiting for a response. Nothing else is ever emitted unsolicited.

---

## 4. Commands

### `INFO`

Identity and state. Safe to call at any time; the natural first command.

```
> INFO
< OK {"proto":2,"fw":"2.0.0","board":"pico2_w","device_id":"a1b2c3d4e5f60718",
     "mac":"00:00:5E:00:53:01","configured":true,"uptime_s":142,"reset_reason":"power_on"}
```

`configured` reports whether a valid config record exists. `mac` is the dongle's own Wi-Fi
MAC — useful for router allow-lists, and not to be confused with a wake target's MAC.

### `SCAN`

Scan for Wi-Fi networks and return what **the device** can see. Takes up to 10 seconds.

```
> SCAN
< OK {"networks":[{"ssid":"HomeNet","rssi":-42,"auth":"wpa2","channel":6},
                  {"ssid":"HomeNet-5G","rssi":-58,"auth":"wpa3","channel":44}]}
```

Sorted by signal strength descending, duplicate SSIDs collapsed to the strongest. Hidden
networks appear with `"ssid":""` and must be entered manually. At most 20 networks are
returned; in a dense block of flats the weakest are dropped rather than the response truncated.

**`auth` is a display hint, not a fact.** It is one of `open`, `wpa`, `wpa2`, `wpa3` or
`secured`. The CYW43439's scan results carry a capability byte that distinguishes open from WPA
from WPA2, but **cannot distinguish WPA2 from WPA3** — both present as an AES-PSK capability,
and the SAE bit that would separate them is not in the field. A WPA3 network is therefore
reported as `wpa2`. Use this to pick a padlock icon, never to decide how to authenticate:
`SET_WIFI` stages an automatic auth mode and the join negotiates whatever the router offers, so
nothing depends on this value being exact.

This is the device's view, not the host computer's, and the difference matters constantly: a
laptop on 5 GHz across the house sees a completely different world from a dongle behind the
router. Any setup UI should show *these* results.

Scanning works while the device is associated. It does **not** work while the radio is joining:
the scan cannot complete until the join settles, so it runs to the 10 second limit and hears
nothing. That answers `ERR scan_incomplete` rather than an empty list, because an empty list says
the networks are not there and the caller would pass that on. Wait and ask again — a scan on an
associated device takes well under a second.

A scan that reaches the limit having heard something returns that rather than failing.

`SCAN` never answers `busy`. The command is synchronous, so no second scan can be in flight, and
a driver left believing one is — which the CYW43 does whenever a scan is started and never
reports completion — is recovered from here rather than reported. Before that recovery existed, a
single scan issued during a join left the device unable to scan again until it was rebooted.

`ERR scan_failed` means the radio refused to start a scan at all. Also worth retrying.

### `LAN_SCAN`

Who else is on the network the device has joined. Takes up to 9 seconds.

```
> LAN_SCAN
< OK {"gateway":"192.168.1.1","hosts":[{"ip":"192.168.1.1","mac":"00:00:5E:00:53:10"},
                                       {"ip":"192.168.1.24","mac":"00:00:5E:00:53:11","name":"MARIO"},
                                       {"ip":"192.168.1.37","mac":"00:00:5E:00:53:12","name":"LUIGI"}]}
```

An ARP request to every address in the device's own subnet; whoever answers is listed, lowest
address first. Up to 1024 addresses are probed and at most 24 hosts returned — beyond that the
response would not fit one line, so extras are dropped rather than the JSON truncated.

`gateway` is the device's default route, so a caller can label the one host in the list that is
certainly not a PC.

`name` is present only for hosts that answered a NetBIOS node status query, which Windows and
Samba do and nothing else does. That is a good filter rather than a limitation: the machines that
answer are the machines wake-on-LAN is for, and a phone staying silent is a phone correctly not
being offered as something to wake. The name is the first unique entry with suffix `0x00`, trimmed
of its padding, and is rejected outright unless every remaining byte is printable ASCII — it comes
from an unauthenticated device on the same network and ends up rendered in a browser.

**A name is what the host calls itself, not proof of anything.** Whether wake-on-LAN is armed on
that adapter lives only on the machine, so `getmac` remains the answer when the list is ambiguous
or when a wake does not work.

`ERR not_joined` when the device has no address of its own, since then there is no subnet to
sweep. The setup hotspot is not a network to scan: during portal setup the device is running its
own access point and is not on the user's LAN at all.

### `SET_WIFI <ssid> [psk]`

Stage Wi-Fi credentials. Omit `psk` for an open network.

```
> SET_WIFI "HomeNet" "correct horse battery staple"
< OK
```

Staged only — nothing is written to flash until `COMMIT`.

### `SET_RELAY <url>`

```
> SET_RELAY wss://relay.roosterwake.com/ws
< OK
```

Must be `wss://` or `ws://`, max 128 bytes. `ws://` is accepted only for loopback and RFC 1918
addresses; anything else is rejected with `ERR bad_arg`, because a plaintext relay URL pointing
at the public internet sends the device's credentials in clear.

### `SET_EMAIL <address>`

Stage the account address this device will offer to a hosted relay with PROTOCOL.md's `adopt`
frame, so the service binds it to that account. Max 128 bytes. Self-hosters never need this.

```
> SET_EMAIL philip@example.com
< OK
```

Validated for shape only — something before an `@`, one `@`, and a dot inside the domain. The
device cannot tell a deliverable address from a merely well-formed one; what this catches is an
SSID or a MAC typed into the wrong field, which would otherwise be written to flash and offered
on every connection.

Not a credential, and no relay should treat it as one. It is erased from flash as soon as the
relay acknowledges the adoption.

### `SET_TOKEN <token>`

Stage the device token: exactly 64 hex digits, stored lower-case. Case-insensitive on input.

```
> SET_TOKEN aabbccddeeff00112233445566778899aabbccddeeff001122334455667788aa
< OK
```

**Why a host is allowed to choose the token.** A relay can only verify the PROTOCOL.md §3
handshake if it holds the same 32 bytes the device does, and §11 forbids the device from ever
transmitting them. Something has to tell the relay, and the device cannot. So a host that
provisions a device end to end — against its own relay or against ours — generates the token,
registers it with the relay, and writes it here. This is the same capability `tools/mkconfig`
has always had over a config UF2, over a cable instead.

If no token is staged, `COMMIT` mints one, so the captive-portal path is unchanged. Staging one
on a device that already has a token replaces it, which is what re-provisioning means; the old
token stops working at the moment the new record is live.

**This does not make the token readable.** §4's guarantee is about the direction that matters:
no command on this channel ever *returns* a token, so a dongle plugged into an untrusted machine
still cannot have its credentials harvested. Writing one needs physical access, and anyone with
that can already `FACTORY_RESET` the device.

Exactly 64 digits, not "up to": a short token is not a weaker token, it is one that fails every
handshake, and the failure surfaces minutes later as a relay auth refusal with nothing pointing
back at the typo. Anything else is `ERR bad_arg`.

### `GET_CONFIG`

Return the staged-and-saved configuration **with all secrets omitted**.

```
> GET_CONFIG
< OK {"ssid":"HomeNet","auth":"wpa2","psk_set":true,"relay":"wss://relay.roosterwake.com/ws",
     "device_id":"a1b2c3d4e5f60718","token_set":true,"email_set":false,"flags":0}
```

**There is no list of machines to wake, here or anywhere on the device.** A wake names its MAC
in the frame that asks for it (PROTOCOL.md §5), so a host that wants to know which machines an
account can wake asks the relay, not the dongle.

**The PSK and the token are never returned by this channel, by any command, ever.** Only the
booleans `psk_set` and `token_set`. This is the one guarantee that stops a compromised or
merely nosy host program from harvesting Wi-Fi passwords and device tokens over USB from a
dongle someone plugged in to charge. The captive portal displays the token once at
provisioning because a self-hoster genuinely needs it; this channel never does.

`token_set` is how a host confirms after the `COMMIT` reboot that the token it staged actually
landed, without either side quoting the secret back. `email_set` reports the same for an address
staged with `SET_EMAIL`, and turns itself off once the relay has acknowledged the adoption.

### `COMMIT`

Validate everything staged, write it to flash, respond, and then either reboot or apply the
change to the running device.

```
> COMMIT
< OK {"saved":true,"seq":7,"reboot_in_ms":1000}   # Wi-Fi or flags changed: restarting
> COMMIT
< OK {"saved":true,"seq":8,"reboot_in_ms":0}      # applied in place, the port stays up
```

**`reboot_in_ms` is the contract.** Non-zero means the serial port is about to disappear and the
host should wait for re-enumeration rather than treating it as an error. Zero means nothing
restarted: the port stays open, the Wi-Fi association is untouched, and the session may carry
straight on to `STATUS`.

A restart is needed only for what the running system cannot absorb — `ssid`, `psk`, `wifi_auth`
and `flags`, because the radio is associated with the credentials it booted on and TLS is
configured from the flags at startup. A change to the relay URL, the token or the owner email
is applied by reopening the relay session, which also clears a session left `auth_failed` by a
token the relay had refused.

This is what lets a host prove the Wi-Fi before it has anything else to write: commit the network
on its own and wait for `STATUS` to report `joined`, then commit the token without dropping the
association that was just proved.

Validation failures return `ERR` and change nothing. The response is sent *before* any reboot so
the host sees the outcome rather than a disconnect.

If nothing was staged, `COMMIT` returns `ERR nothing_staged`.

### `STATUS`

Runtime state. Most useful after a `COMMIT` reboot, to confirm the device actually got where
it was meant to go.

```
> STATUS
< OK {"wifi":"joined","ssid":"HomeNet","rssi":-47,"ip":"192.168.1.42",
     "netmask":"255.255.255.0","relay":"connected","last_error":null,"uptime_s":31}
```

`wifi` is one of `idle`, `joining`, `joined`, `failed`. `relay` is one of `idle`,
`connecting`, `connected`, `auth_failed`, `backoff`. `last_error` is a short diagnostic string
or `null`.

Together these turn "it isn't working" into a specific answer: `wifi:"failed"` with
`last_error:"badauth"` is a wrong password, while `wifi:"joined"` plus `relay:"auth_failed"`
is a device that is on the network but not recognised by the relay. Different problems,
different fixes, and the channel distinguishes them rather than making the user guess.

### `WIFI_TRACE [from]`

What the radio reported, verbatim, in order. `STATUS` gives the verdict; this gives the
evidence behind it.

```
> WIFI_TRACE
< OK {"from":0,"total":9,"lines":[
    "[    4120] target ssid=HomeNet",
    "[    4121] join #1 auth=wpa2/wpa3",
    "[    4890] ASYNC(0000,SET_SSID,1,0,0)",
    "[    4891] result failed js=0002", ...]}
```

The `ASYNC(flags,event,status,reason,interface)` lines come from the CYW43439 itself — one per
step of an association — and the `[nnn] word …` lines are the firmware saying which attempt
they belong to. Read together they say where in the handshake a join died, which is the thing
no other command in this channel can tell you.

`js` is the driver's join-state bitmask: `0x0200` authenticated, `0x0400` linked, `0x0800`
keyed, and the low nibble the outcome (`1` active, `2` failed, `3` no network, `4` bad auth).
An association refused before authentication and one that died during the four-way handshake
both report `last_error:"failed"` to `STATUS` and have nothing whatever to do with each other;
here they are two different numbers.

The device holds the last 32 entries and answers 12 at a time, so a host reads from `0` and
asks again while `from + 12 < total`. Scan results are excluded — a single `SCAN` raises one
event per beacon heard and would evict everything worth keeping. Entries shift as new events
arrive, so a page read during an active retry loop may skip or repeat a line.

### `TEST_WAKE <mac>`

Send a magic packet immediately, without going near the relay. Requires Wi-Fi to be joined.
The MAC is required — the device holds no list of machines to choose a default from — and must
be a unicast address by PROTOCOL.md §2. A group, broadcast or all-zero address is `ERR bad_arg`:
it would send perfectly and wake nothing, which is the outcome this command exists to rule out.

```
> TEST_WAKE AA:BB:CC:DD:EE:FF
< OK {"sent":12,"ifaces":["255.255.255.255:9","192.168.1.255:9",
                          "255.255.255.255:7","192.168.1.255:7"]}
```

This is the single most valuable diagnostic command in the set, because it isolates the half
of the system that usually fails. If `TEST_WAKE` powers the PC on but a wake from the
dashboard does not, the problem is the account, the claim or the relay. If `TEST_WAKE` does
not work either, the problem is the router or the target PC, and no amount of cloud debugging
will help.

### `FACTORY_RESET`

```
> FACTORY_RESET CONFIRM
< OK {"erased":true,"reboot_in_ms":1000}
```

Clears everything a person configured — Wi-Fi, relay override, account address, and the
enrolled flag — and reboots into setup mode. The literal argument `CONFIRM` is required; without
it, `ERR needs_confirm`. There is no undo, and the Wi-Fi password is gone.

**`device_id` and `token` survive**, because they identify the hardware rather than its owner.
config-format.md §8 explains why at length; the short version is that a device which came back
with a fresh token would be refused by any relay that already knew it, turning the recovery
action into the thing that needs recovering. Re-running setup afterwards can bind the device to a
different account, which is what makes reset the answer for a mistyped address, a gift or a
resale.

### `REBOOT`

```
> REBOOT
< OK {"reboot_in_ms":250}
```

### `BOOTSEL`

Reboot into the RP2350 UF2 bootloader for reflashing.

```
> BOOTSEL
< OK {"reboot_in_ms":250}
```

This is what makes browser-driven firmware updates possible: a host can move a running device
into the bootloader without anyone reaching behind the router to hold a button while
re-plugging a cable. Configuration in flash is untouched — a firmware image does not erase the
config sectors — so a device reflashed this way comes back already provisioned.

---

## 5. A complete provisioning session

```
> INFO
< OK {"proto":2,"fw":"2.0.0","board":"pico2_w","device_id":"a1b2c3d4e5f60718","configured":false,...}
> SCAN
< OK {"networks":[{"ssid":"HomeNet","rssi":-42,"auth":"wpa2","channel":6}, ...]}
> SET_WIFI "HomeNet" "correct horse battery staple"
< OK
> SET_RELAY wss://relay.roosterwake.com/ws
< OK
> SET_EMAIL philip@example.com
< OK
> COMMIT
< OK {"saved":true,"seq":1,"reboot_in_ms":1000}

  ... device reboots, port re-enumerates, reconnect ...

> GET_CONFIG
< OK {"ssid":"HomeNet","auth":"auto","psk_set":true,"relay":"wss://relay.roosterwake.com/ws",
     "device_id":"a1b2c3d4e5f60718","token_set":true,"email_set":false,"flags":0}
> STATUS
< OK {"wifi":"joined","ssid":"HomeNet","rssi":-47,"ip":"192.168.1.42",
     "netmask":"255.255.255.0","relay":"connected","last_error":null,"uptime_s":8}
```

The token is generated by the host and registered with the relay *before* `COMMIT`, so that the
relay already knows the device when it first dials in. Registering after the commit would leave a
window in which the device is retrying against a relay that refuses it, and §8's backoff means
that window is minutes long rather than seconds.

A host that only needs the device on **its own** relay can send `SET_TOKEN` and add the same
value to that relay's device list by hand — there is nothing hosted-specific about the command.

`SET_TOKEN` is not required against a relay that implements PROTOCOL.md's `enrol`: a device with
a token the relay has never seen presents it on first contact and is recorded then. Setting one
here is for the case where the host wants to choose the value — because it is registering the
device through some other channel, or because it maintains the relay's device list itself.

---

## 6. Error codes

| Code | Meaning |
|---|---|
| `unknown_cmd` | Command not recognised |
| `bad_args` | Wrong number of arguments |
| `bad_arg` | An argument failed validation (bad MAC, bad URL, oversized string) |
| `bad_frame` | Line was not valid UTF-8, or quoting was malformed |
| `too_long` | Line exceeded 512 bytes |
| `nothing_staged` | `COMMIT` with no pending changes |
| `needs_confirm` | `FACTORY_RESET` without the `CONFIRM` argument |
| `not_joined` | Command requires Wi-Fi, which is not connected |
| `busy` | A conflicting operation is already running. Not used by `SCAN`; see §4 |
| `scan_failed` | The radio would not start a scan. Retryable |
| `scan_incomplete` | The scan ran out of time having heard nothing, usually because the radio was joining. Retryable |
| `flash_error` | Flash write or verification failed. Configuration is unchanged |
| `internal` | Anything else |

Error codes are a closed set for protocol version 2. New codes require a version bump, and
hosts MUST treat an unrecognised code as `internal` rather than failing.

---

## 7. Notes for implementers

**Wait for re-enumeration, don't poll blindly.** After `COMMIT`, `REBOOT` or `FACTORY_RESET`
the port disappears. On Web Serial, listen for `disconnect` then `connect`. Reconnecting can
take up to five seconds on Windows, which reliably enumerates more slowly than macOS or Linux.

**Match on the serial number, not the port.** With two dongles attached, `COM4` and `COM5` may
swap between reboots. The USB serial number is the `device_id` and is stable — but compare it
case-insensitively, per §1.

**Never log a `SET_WIFI` or `SET_TOKEN` line.** One contains the user's Wi-Fi password in plain
text and the other the device's relay credential. Setup tooling that logs commands for debugging
must redact both — a habit worth building in before the first support session, not after. Redact
by command name rather than by pattern-matching the argument: the next secret-bearing command
added to this channel is then redacted by default instead of by remembering.

**Diagnostics are opt-in.** `# `-prefixed lines only appear when enabled. Ignore them
unconditionally rather than only when you expect them.

**`SCAN` is slow.** Up to ten seconds, during which the device does not respond to anything
else. Show a progress indicator; do not time out at five seconds and declare the device dead.

---

## 8. Versioning

`proto` in the `INFO` response is this document's version. It is `2`.

New commands, new optional arguments, and new fields in `OK` payloads may be added within
version 2. Hosts MUST ignore unrecognised JSON fields. Removing a command, changing an
argument's meaning, or changing a response field's type requires a version bump.

**Version 2 removed `ADD_TARGET` and `CLEAR_TARGETS`, made `TEST_WAKE`'s MAC required, and
dropped `targets` from `GET_CONFIG` and `too_many` from §6.** A device holds no list of the
machines it can wake — PROTOCOL.md §13 says why — so there was nothing left for those commands
to write to. The unicast check `ADD_TARGET` used to apply moved to `TEST_WAKE`, which is now the
only place a MAC reaches this channel.
