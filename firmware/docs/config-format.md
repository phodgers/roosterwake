# Flash configuration format

**Version 1** · Status: **stable**

This document specifies the on-flash layout of a Rooster Wake device's configuration. It is a
**public, versioned contract**, because three independent implementations must agree on it
byte for byte:

- the firmware, which reads and writes it (`firmware/src/config/`);
- [`tools/mkconfig`](../../tools/mkconfig/), which generates a config-only UF2 image so a
  device can be provisioned without touching the captive portal;
- our hosted dashboard, which generates personalised config images for kit customers.

If these three ever disagree, a customer's device bricks its configuration. That is why the
format is fixed-layout rather than something friendlier like JSON or CBOR, and why the
[golden vectors](#7-golden-vectors) are part of the test suite on both sides.

---

## 1. Where it lives

**The top two 4096-byte sectors of flash**, whatever size the flash is. Slot B is the last
sector, slot A the one below it. That is the rule; the addresses follow from it:

| Board | Flash | Slot A | Slot B | XIP A | XIP B |
|---|---|---|---|---|---|
| Pico 2 W (RP2350) | 4 MB | `0x3FE000` | `0x3FF000` | `0x103FE000` | `0x103FF000` |
| Pico W (RP2040) | 2 MB | `0x1FE000` | `0x1FF000` | `0x101FE000` | `0x101FF000` |

**Do not hardcode either row.** The firmware derives both from `PICO_FLASH_SIZE_BYTES` and
`tools/mkconfig` takes `--board` (or `--flash-size`) for the same reason. A fixed `0x3FE000`
silently assumes 4 MB for ever: on a 2 MB board those addresses are past the end of the chip,
and the symptom is a configuration that appears to save and has vanished after a power cycle.

The firmware image itself is linked to stay below slot A. The build fails if it does not — a
linker assertion, not a runtime check, because discovering this at runtime means discovering it
in a customer's hands. The assertion's threshold is generated per board, so it cannot pass
vacuously on the smaller one.

### Why two slots

A flash sector erase takes milliseconds, during which the sector reads as `0xFF`. Lose power
in that window with a single slot and the device comes back with no configuration at all —
factory-reset by accident, on a shelf, behind a router, with the owner's Wi-Fi password gone.

With two slots the write sequence is: erase the *inactive* slot, program it, read it back and
verify, and only then is it live — because "live" is decided by comparing sequence numbers at
boot, not by write order. Power loss at any point leaves at least one valid slot. The old
configuration survives until the new one is completely written and verified.

---

## 2. Record layout

A record is a 32-byte header followed by a payload. All multi-byte integers are
**little-endian** (the RP2350 is little-endian; no byte swapping anywhere).

### 2.1 Header (32 bytes)

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `RWCF` — bytes `52 57 43 46` |
| 4 | 2 | `version` | `1` |
| 6 | 2 | `reserved0` | Must be `0` |
| 8 | 4 | `seq` | Monotonic. Higher valid slot wins. See §3 |
| 12 | 4 | `payload_len` | Bytes of payload after the header. `580` in v1 |
| 16 | 4 | `crc32` | Over the **payload only**, not the header. See §4 |
| 20 | 12 | `reserved1` | Must be all `0` |

### 2.2 Payload (580 bytes in v1)

All strings are UTF-8, NUL-terminated, and **NUL-padded to their full field width**. Padding
with `0xFF` (the erased-flash value) is invalid — the CRC would not be reproducible across
writers. Readers MUST treat the first NUL as end-of-string and MUST NOT assume anything after
it is zero.

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 33 | `ssid` | Max 32 bytes + NUL. Empty means unprovisioned |
| 33 | 65 | `psk` | Max 64 bytes + NUL. Empty for an open network |
| 98 | 1 | `wifi_auth` | `0` open · `1` WPA2-PSK · `2` WPA3-SAE · `255` auto-detect (default) |
| 99 | 129 | `relay_url` | Max 128 bytes + NUL. e.g. `wss://relay.roosterwake.com/ws` |
| 228 | 17 | `device_id` | 16 lower-case hex chars + NUL |
| 245 | 65 | `token` | 64 lower-case hex chars + NUL |
| 310 | 129 | `owner_email` | Max 128 bytes + NUL. Empty unless an adoption is pending |
| 439 | 4 | `flags` | See §2.3 |
| 443 | 1 | `target_count` | `0`–8 |
| 444 | 248 | `targets` | 8 × 31-byte entries, see §2.4 |

Total: **692 bytes**. Record total: 724 bytes, comfortably inside one 4096-byte sector.

`owner_email` is the address typed into the setup page, carried out to the relay by PROTOCOL.md's
`adopt` frame and erased as soon as it is acknowledged. It is a routing hint for one connection
rather than a stored property of the device: a dongle that changes hands must not carry the
previous owner's address to the next one.

Bytes from `payload_len` to the end of the sector are ignored by readers and SHOULD be written
as `0x00` by writers.

### 2.3 Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `TLS_INSECURE` | Skip TLS certificate verification. **Default off.** Firmware flashes the error LED pattern continuously while this is set, and logs a warning on every connection |
| 1 | `DIAG_LOG` | Send `log` frames to the relay (see PROTOCOL.md §4) |
| 2 | `WOL_UNICAST` | Additionally send magic packets unicast to the target's last-known IP |
| 3 | `ENROLLED` | This device has completed a handshake with its relay at least once. Set after `hello_ack {ok:true}`, cleared only by a factory reset |
| 4–31 | reserved | Must be `0`. Readers MUST ignore unknown bits rather than rejecting the record |

`ENROLLED` decides whether the device sends `auth` or `enrol` on its next connection
(PROTOCOL.md §3.2). A generator writing a record for a device whose token the relay already
knows — `tools/mkconfig` pointed at a self-hosted relay, for instance — SHOULD set it, so the
device authenticates straight away rather than offering a token that endpoint may not want.

### 2.4 Target entry (31 bytes each)

| Offset | Size | Field |
|---|---|---|
| 0 | 25 | `name` — max 24 bytes + NUL, UTF-8 |
| 25 | 6 | `mac` — six raw octets, **not** the ASCII form |

Entries beyond `target_count` MUST be written as all-zero and MUST be ignored by readers.

Storing the MAC as six raw bytes rather than the 18-character ASCII string is deliberate: it
removes every parsing and normalisation question from the flash layer. Case, separators and
validation are handled once, at the input boundary.

---

## 3. Slot selection

At boot the firmware reads both slots and picks a winner:

1. Discard any slot whose `magic` is not `RWCF`.
2. Discard any slot whose `version` is greater than the firmware understands. (A *lower*
   version is migrated forward, see §6.)
3. Discard any slot whose `payload_len` does not match the expected length for its version, or
   which would run past the end of the sector.
4. Discard any slot whose `crc32` does not match the payload.
5. Of what remains, take the **highest `seq`**.
6. If nothing remains, the device is unprovisioned and starts the setup hotspot.

`seq` wrap-around is handled by comparing with signed 32-bit difference (`(int32_t)(a - b) > 0`)
rather than direct `>`, so the 4-billionth write does not resurrect a stale slot. This will
never happen in practice — flash endurance runs out long first — but the correct comparison
costs nothing and the wrong one is impossible to debug.

### Writing

1. Determine the winning slot (§3). Write to the *other* one.
2. New `seq` = winner's `seq` + 1, or `1` if there is no valid slot.
3. Erase the target sector, program the record, read it back and byte-compare.
4. If verification fails, retry once on the same slot; if it fails again, report a config
   error and leave the other slot untouched — the device keeps working on the old config.

Flash writes execute via the SDK's `flash_safe_execute()` so that the second core and any
interrupt handlers are locked out while XIP is disabled.

---

## 4. CRC-32

**CRC-32/ISO-HDLC** — the same algorithm as zlib, PNG and `crc32` in essentially every
language's standard library.

| Parameter | Value |
|---|---|
| Polynomial | `0x04C11DB7` (reflected: `0xEDB88320`) |
| Initial value | `0xFFFFFFFF` |
| Reflect in / out | Yes / Yes |
| Final XOR | `0xFFFFFFFF` |
| Check value (`"123456789"`) | `0xCBF43926` |

Computed over the payload bytes only. The check value is asserted in both the C and the JS
test suites, so a wrong variant fails immediately rather than at integration.

---

## 5. Config-only UF2 images

`tools/mkconfig` emits a UF2 that writes **only** a config sector, so it can be dragged onto
the BOOTSEL drive alongside — or long after — a firmware image.

- Block size 512 bytes, 256 payload bytes per block, standard UF2 framing.
- Target address: slot B — `0x103FF000` on a 4 MB board, `0x101FF000` on a 2 MB one. Writing to
  a fixed slot is safe because the record carries `seq`, and `mkconfig` sets `seq` high enough
  to win (see below).
- Family ID: `0xE48BFF59` (RP2350, Arm secure) or `0xE48BFF56` (RP2040), selected by `--board`
  and overridable with `--family`.

**`--board` sets both at once**, and that pairing matters: a UF2 carrying the right address but
the wrong family is refused by the bootloader, while one carrying the right family and the
wrong address is *accepted* and writes the config into the middle of the firmware image. The
first failure is loud and the second is catastrophic, so the two are never chosen separately.
- `numBlocks` covers the whole 4096-byte sector so the remainder is explicitly zeroed rather
  than left holding whatever was there before.

**`seq` for generated images** defaults to `0x40000000`. A generated image has no way to read
what is already on the device, so it cannot compute *winner + 1*. Picking a large constant
means it reliably wins against normally-incremented sequence numbers, while leaving vast room
below it. Subsequent writes by the firmware increment from there normally.

The bootloader writes whatever address a UF2 block names and does not check that the payload
is executable, which is what makes a data-only image work at all. The family ID is the one
piece of this that is verified against the chip, hence the `--family` escape hatch.

---

## 6. Versioning

`version` is the payload layout version, independent of firmware version and of PROTOCOL.md.

- Firmware MUST read any `version` less than or equal to its own, migrating older layouts
  forward in memory and rewriting at the current version on the next save.
- Firmware MUST refuse a `version` greater than its own and treat that slot as invalid, rather
  than misparsing it. Downgrading firmware therefore falls back to the older slot, which is
  exactly the desired behaviour.
- New fields are appended and `payload_len` grows. Existing offsets never move. Removed fields
  become reserved padding and are never reused for a different purpose.

---

## 7. Golden vectors

[`firmware/test/vectors/config-v1.json`](../test/vectors/config-v1.json) holds canonical
configurations paired with their exact expected encodings (hex) and CRC values.

Both test suites consume this same file:

- **C** — `firmware/test/test_config.c`, run natively on the host in CI.
- **JS** — `tools/mkconfig/test/encode.test.mjs`.

A change to the encoder on either side that is not matched on the other fails CI immediately.
This is the mechanism that keeps a format used by three separate codebases honest, and it is
the reason this file exists rather than a prose description alone.

Vectors cover: a fully-unprovisioned record; a minimal one-target record; a maximal record
with eight targets, a 32-byte SSID, a 64-byte PSK and multi-byte UTF-8 target names; and a
record with every defined flag set.

---

## 8. Factory reset

Two triggers, one behaviour: `FACTORY_RESET CONFIRM` over usbcfg, or **holding BOOTSEL for five
seconds within the first 20 seconds after power-on**. Both clear everything a person configured
and keep the device's identity:

| Cleared | Kept |
|---|---|
| `ssid`, `psk`, `wifi_auth` | `device_id` |
| `relay_url` | `token` |
| `targets`, `target_count` | |
| `owner_email` | |
| `flags`, including `ENROLLED` | |

### The button, and why it is a window rather than a moment

The bootrom claims BOOTSEL at reset: a board powered up with it held enters USB mass storage and
the firmware never runs at all. So the press can only be made **after** boot, and the firmware
polls for it across the first 20 seconds of uptime rather than sampling once.

The distinction is not academic. It was a single sample taken just after the radio came up, which
left one instant to hit whose timing moved with however long the radio took — unhittable by hand
on either board, and the reason this path went unexercised for so long. Anything that reintroduces
a single sample reintroduces that.

A hold already in progress when the window closes is timed to completion, so a press made at
19 seconds still works.

`device_id` is derived from the board's unique flash id and is re-derived on every boot, so it
could not be erased even in principle. **The token is kept deliberately**, and the reason is
worth stating because "factory reset" usually implies otherwise.

A reset that minted a fresh token would leave the device presenting a `device_id` the relay knows
alongside a token it has never seen — which PROTOCOL.md §3.4 requires an *owned* record to
refuse. The board would come back unable to reach the service it was working with minutes
earlier, and the only route back would be a cable and a computer.

That matters because reset is the recovery path for the mistake people actually make: a mistyped
address during setup. Hold the button, do it again, type it correctly. Keeping the token is what
makes that work, and it costs nothing — ownership is recorded by the service, not by the device,
and re-pairing to a different account is allowed precisely because it requires physical
possession.

A device that has never held a token still mints one at the next commit, as before.

## 9. Security note

The device token and the Wi-Fi PSK are stored **in plaintext** in flash.

This is a deliberate, documented decision rather than an oversight. There is nowhere better to
put them: the RP2350 has no secure element, and any key the firmware could use to decrypt them
would itself have to be stored in the same flash. Encrypting with a key kept next to the
ciphertext is theatre — it raises the effort of an attack from *trivial* to *slightly less
trivial* while implying a protection that does not exist.

What this means practically:

- **Physical possession of the device means possession of the Wi-Fi password and the device
  token.** Anyone who can hold the dongle and attach a USB cable can read both.
- Treat a lost or stolen dongle as a Wi-Fi credential compromise. Rotate the network password
  and revoke the device token.
- RP2350 does support flash protection features that would raise the bar against casual
  extraction. They are not used in v1, because the threat they address — an attacker with the
  physical device — is one where the Wi-Fi password is only as safe as the router it is
  written on the back of.
- The `usbcfg` command channel never reads back the PSK or the token
  ([usbcfg.md](usbcfg.md)), so a *software* attack through a compromised host does not extract
  them. That is the boundary this design does defend.

**Factory reset erases both slots**, so wiping before disposal or resale genuinely clears the
credentials. Use `FACTORY_RESET CONFIRM` over the USB command channel, or "Start this dongle from
scratch" on the setup page, which sends it for you.

That leaves the firmware in place, which is what you want for a device staying in service. To put
a board back to the state a new one arrives in — no loader, no firmware, no configuration —
build `firmware/tools/wipe` and drop its UF2 on the board in BOOTSEL. It erases every byte and
returns to the bootloader. The `device_id` survives either way: it is derived from the board's
unique flash ID rather than stored, so a wiped board reports the same identity and the account it
belongs to still recognises it.

> **The BOOTSEL hold does not work.** `check_factory_reset()` in main.c reads the button once at
> start-up, and holding BOOTSEL through a power-on is exactly what makes the ROM bootloader take
> over instead — so the firmware never runs to see it. The button is the only physical input the
> enclosure has and it should be the reset, but making that true means polling it from the main
> loop, which has not been done. Until it is, do not document it as a route: someone will try it,
> nothing will happen, and they will conclude the reset does not work at all.
