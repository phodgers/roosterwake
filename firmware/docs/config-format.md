# Flash configuration format

**Version 1** · Status: **stable**

This document specifies the on-flash layout of a Remote Wake device's configuration. It is a
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

Two 4096-byte sectors at the top of flash. The Pico 2 W has 4 MB, so:

| Slot | Flash offset | XIP address |
|---|---|---|
| A | `0x3FE000` | `0x103FE000` |
| B | `0x3FF000` | `0x103FF000` |

The firmware image itself is linked to stay below `0x3FE000`. The build fails if it does not —
a linker assertion, not a runtime check, because discovering this at runtime means discovering
it in a customer's hands.

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
| 99 | 129 | `relay_url` | Max 128 bytes + NUL. e.g. `wss://relay.remotewake.com/ws` |
| 228 | 17 | `device_id` | 16 lower-case hex chars + NUL |
| 245 | 65 | `token` | 64 lower-case hex chars + NUL |
| 310 | 17 | `claim_code` | Max 16 chars + NUL. Empty if not claiming |
| 327 | 4 | `flags` | See §2.3 |
| 331 | 1 | `target_count` | `0`–`8` |
| 332 | 248 | `targets` | 8 × 31-byte entries, see §2.4 |

Total: **580 bytes**. Record total: 612 bytes, comfortably inside one 4096-byte sector.

Bytes from `payload_len` to the end of the sector are ignored by readers and SHOULD be written
as `0x00` by writers.

### 2.3 Flags

| Bit | Name | Meaning |
|---|---|---|
| 0 | `TLS_INSECURE` | Skip TLS certificate verification. **Default off.** Firmware flashes the error LED pattern continuously while this is set, and logs a warning on every connection |
| 1 | `DIAG_LOG` | Send `log` frames to the relay (see PROTOCOL.md §4) |
| 2 | `WOL_UNICAST` | Additionally send magic packets unicast to the target's last-known IP |
| 3–31 | reserved | Must be `0`. Readers MUST ignore unknown bits rather than rejecting the record |

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
- Target address: `0x103FF000` (slot B). Writing to a fixed slot is safe because the record
  carries `seq`, and `mkconfig` sets `seq` high enough to win (see below).
- Family ID: `0xE48BFF59` (RP2350, Arm secure) by default, overridable with `--family`.
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

## 8. Security note

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
credentials. Hold BOOTSEL for five seconds at power-on; the LED confirms.
