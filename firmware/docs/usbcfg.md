# USB serial command channel (`usbcfg`)

**Protocol version 1** · Status: **stable**

A Remote Wake device exposes a line-based command channel over USB CDC. It is how a computer
configures a dongle without going near the Wi-Fi captive portal, and it is a **public,
versioned contract**.

This channel is open and documented deliberately. Our hosted setup page at
`setup.remotewake.com` drives it through the browser's Web Serial API — but the *channel* is
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
`Remote Wake` and the serial number set to the 16-hex-character `device_id`. That serial
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
< OK {"proto":1,"fw":"1.0.0","board":"pico2_w","device_id":"a1b2c3d4e5f60718",
     "mac":"28:CD:C1:0A:1B:2C","configured":true,"uptime_s":142,"reset_reason":"power_on"}
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
networks appear with `"ssid":""` and must be entered manually.

This is the device's view, not the host computer's, and the difference matters constantly: a
laptop on 5 GHz across the house sees a completely different world from a dongle behind the
router. Any setup UI should show *these* results.

### `SET_WIFI <ssid> [psk]`

Stage Wi-Fi credentials. Omit `psk` for an open network.

```
> SET_WIFI "HomeNet" "correct horse battery staple"
< OK
```

Staged only — nothing is written to flash until `COMMIT`.

### `SET_RELAY <url>`

```
> SET_RELAY wss://relay.remotewake.com/ws
< OK
```

Must be `wss://` or `ws://`, max 128 bytes. `ws://` is accepted only for loopback and RFC 1918
addresses; anything else is rejected with `ERR bad_arg`, because a plaintext relay URL pointing
at the public internet sends the device's credentials in clear.

### `ADD_TARGET <name> <mac>`

```
> ADD_TARGET "Office Desktop" AA:BB:CC:DD:EE:FF
< OK {"targets":1}
```

`mac` accepts `:`, `-` or no separators, in any case. `name` is 1–24 bytes UTF-8. Maximum
eight targets; the ninth returns `ERR too_many`.

### `CLEAR_TARGETS`

```
> CLEAR_TARGETS
< OK {"targets":0}
```

### `SET_CLAIM <code>`

Stage an account claim code, used by the hosted service to bind this device to an account on
its first connection. Max 16 characters. Self-hosters never need this.

### `GET_CONFIG`

Return the staged-and-saved configuration **with all secrets omitted**.

```
> GET_CONFIG
< OK {"ssid":"HomeNet","auth":"wpa2","psk_set":true,"relay":"wss://relay.remotewake.com/ws",
     "device_id":"a1b2c3d4e5f60718","token_set":true,"claim_set":false,
     "targets":[{"name":"Office Desktop","mac":"AA:BB:CC:DD:EE:FF"}],"flags":0}
```

**The PSK and the token are never returned by this channel, by any command, ever.** Only the
booleans `psk_set` and `token_set`. This is the one guarantee that stops a compromised or
merely nosy host program from harvesting Wi-Fi passwords and device tokens over USB from a
dongle someone plugged in to charge. The captive portal displays the token once at
provisioning because a self-hoster genuinely needs it; this channel never does.

### `COMMIT`

Validate everything staged, write it to flash, respond, then reboot after roughly one second.

```
> COMMIT
< OK {"saved":true,"seq":7,"reboot_in_ms":1000}
```

Validation failures return `ERR` and change nothing. The response is sent *before* the reboot
so the host sees the outcome rather than a disconnect. A host should expect the serial port to
disappear shortly after, and should wait for re-enumeration rather than treating it as an
error.

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

### `TEST_WAKE [mac]`

Send a magic packet immediately, without going near the relay. With no argument, uses the
first configured target. Requires Wi-Fi to be joined.

```
> TEST_WAKE
< OK {"sent":24,"ifaces":["255.255.255.255:9","192.168.1.255:9",
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

Erases both config slots and reboots into setup mode. The literal argument `CONFIRM` is
required; without it, `ERR needs_confirm`. There is no undo, and the Wi-Fi password is gone.

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
< OK {"proto":1,"fw":"1.0.0","board":"pico2_w","device_id":"a1b2c3d4e5f60718","configured":false,...}
> SCAN
< OK {"networks":[{"ssid":"HomeNet","rssi":-42,"auth":"wpa2","channel":6}, ...]}
> SET_WIFI "HomeNet" "correct horse battery staple"
< OK
> ADD_TARGET "Office Desktop" AA:BB:CC:DD:EE:FF
< OK {"targets":1}
> SET_RELAY wss://relay.remotewake.com/ws
< OK
> SET_CLAIM 7QX4-9F2B
< OK
> COMMIT
< OK {"saved":true,"seq":1,"reboot_in_ms":1000}

  ... device reboots, port re-enumerates, reconnect ...

> STATUS
< OK {"wifi":"joined","ssid":"HomeNet","rssi":-47,"ip":"192.168.1.42",
     "netmask":"255.255.255.0","relay":"connected","last_error":null,"uptime_s":8}
```

---

## 6. Error codes

| Code | Meaning |
|---|---|
| `unknown_cmd` | Command not recognised |
| `bad_args` | Wrong number of arguments |
| `bad_arg` | An argument failed validation (bad MAC, bad URL, oversized string) |
| `bad_frame` | Line was not valid UTF-8, or quoting was malformed |
| `too_long` | Line exceeded 512 bytes |
| `too_many` | Target limit reached |
| `nothing_staged` | `COMMIT` with no pending changes |
| `needs_confirm` | `FACTORY_RESET` without the `CONFIRM` argument |
| `not_joined` | Command requires Wi-Fi, which is not connected |
| `busy` | A conflicting operation (a scan, a join) is already running |
| `flash_error` | Flash write or verification failed. Configuration is unchanged |
| `internal` | Anything else |

Error codes are a closed set for protocol version 1. New codes require a version bump, and
hosts MUST treat an unrecognised code as `internal` rather than failing.

---

## 7. Notes for implementers

**Wait for re-enumeration, don't poll blindly.** After `COMMIT`, `REBOOT` or `FACTORY_RESET`
the port disappears. On Web Serial, listen for `disconnect` then `connect`. Reconnecting can
take up to five seconds on Windows, which reliably enumerates more slowly than macOS or Linux.

**Match on the serial number, not the port.** With two dongles attached, `COM4` and `COM5` may
swap between reboots. The USB serial number is the `device_id` and is stable — but compare it
case-insensitively, per §1.

**Never log a `SET_WIFI` line.** It contains the user's Wi-Fi password in plain text. Setup
tooling that logs commands for debugging must redact this one — a habit worth building in
before the first support session, not after.

**Diagnostics are opt-in.** `# `-prefixed lines only appear when enabled. Ignore them
unconditionally rather than only when you expect them.

**`SCAN` is slow.** Up to ten seconds, during which the device does not respond to anything
else. Show a progress indicator; do not time out at five seconds and declare the device dead.

---

## 8. Versioning

`proto` in the `INFO` response is this document's version. It is `1`.

New commands, new optional arguments, and new fields in `OK` payloads may be added within
version 1. Hosts MUST ignore unrecognised JSON fields. Removing a command, changing an
argument's meaning, or changing a response field's type requires a version bump.
