# Quick start

From a board still in its bag to a PC you can wake from anywhere, using nothing but this
repository. No account is required for any step on this page.

## What you need

- A **Raspberry Pi Pico W** or **Pico 2 W**. Nothing else — no soldering, no extra components.
- A **micro USB data cable**. Charge-only cables carry power but no data and are the most common
  reason the board never appears.
- A **target PC**, ideally on wired Ethernet. Wi-Fi targets are best-effort; see
  [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
- The dongle and the target must end up on **the same network segment**. Guest SSIDs, client
  isolation and VLANs all break this.

The Pico W and Pico 2 W are **2.4 GHz only**. A 5 GHz-only SSID will not be found.

## 1. Flash the firmware

Download both UF2 files for your board from
[the latest release](https://github.com/phodgers/roosterwake/releases/latest):

| File | What it is |
|---|---|
| `loader-<version>-<board>.uf2` | The loader. Owns the first 64 KB of flash and is never replaced over the air. |
| `roosterwake-<version>-<board>-install.uf2` | The firmware itself. |

`<board>` is `pico2_w` or `pico_w`. The `.rwfw` files in the same release are signed OTA images
streamed to a running device — they are not flashed by hand.

Hold **BOOTSEL** while plugging the board in. It appears as a USB drive called `RPI-RP2` (or
`RP2350` on a Pico 2 W). Drag the **loader** onto it. The board reboots as the file lands, which
dismounts the drive — that is expected.

Hold BOOTSEL and plug it in again, then drag the **install** file onto the drive. That is the
board programmed.

## 2. Provision it

Three routes, all writing the same configuration. Pick one.

### Captive portal — no tools needed

Power the dongle. With no configuration it raises an open Wi-Fi hotspot called
**`RoosterWake-Setup-XXXX`**. Join it from a phone or laptop and the setup page opens on its own;
if it does not, browse to `http://192.168.4.1`.

The portal scans for networks, takes the password, and lets you set the relay URL and the
account address the dongle should adopt to. Save, and it reboots onto your network.

It does not ask which PC you want to wake. **A dongle holds no list of machines** — every wake
names its MAC in the frame that asks ([`../PROTOCOL.md`](../PROTOCOL.md) §5), so the machines
live with whoever sends the wakes: your account on the hosted service, or your own relay's
records.

### Config image — headless, and good for several devices

[`../tools/mkconfig/`](../tools/mkconfig/) generates a UF2 that provisions the board when you drag
it on, with no browser and no serial session:

```sh
cd tools/mkconfig
node bin/mkconfig.mjs \
  --ssid "Your Network" --psk "your-password" --auth wpa2 \
  --relay "wss://relay.example.com/ws" \
  --out config.uf2
```

Read it back with `node bin/mkconfig.mjs --verify config.uf2`. The password and token are never
printed back out.

### USB serial — a terminal and nothing else

Connect at any baud; USB CDC ignores the line rate.

```
SCAN
SET_WIFI <ssid> <password> wpa2
SET_RELAY wss://relay.example.com/ws
SET_TOKEN <your 32 random bytes, hex>
COMMIT
```

`SET_*` commands stage; only `COMMIT` writes. Read `reboot_in_ms` in the reply rather than
assuming — Wi-Fi changes force a restart, while the relay URL and the token are applied in
place. The full command set is in [`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md).

## 3. Point it at a relay

The device holds an outbound TLS connection to a relay, and it must be `wss://` unless the address
is loopback or RFC 1918 — production firmware refuses plaintext to a public address.

Run your own with [`../relay-reference/`](../relay-reference/); it is a complete implementation of
[`../PROTOCOL.md`](../PROTOCOL.md) and takes about five minutes. See
[`SELF-HOSTING.md`](SELF-HOSTING.md) for the device side and
[`../relay-reference/README.md`](../relay-reference/README.md) for the relay itself.

You will need the **device id** and a **token**. The device id is derived from the board's unique
ID and is not yours to choose — `INFO` over USB serial prints it. The token is 32 random bytes you
generate, write into the device, and put in the relay's config. It is never transmitted, so a
mismatch shows up only as an `auth` failure.

## 4. Prepare the target PC

Wake-on-LAN has to be enabled on the machine you want to wake. On Windows that means four separate
things — firmware, adapter property, wake permission and Fast Startup. On Linux it is `ethtool`;
on macOS, "Wake for network access", and only from sleep.

[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) has the exact commands for each.

While you are at that machine, read its **MAC address** off the adapter you just enabled — every
wake names it, so this is the one thing you cannot get from the dongle:

| | |
|---|---|
| Windows | Settings › Network & internet › your adapter, then `Physical address (MAC)` |
| macOS | System Settings › Network › your adapter › Details › Hardware |
| Linux | `ip link`, and read the `link/ether` line |

Use the **wired** adapter's address if the machine has one. A randomised or virtual address — the
second-lowest bit of the first octet set — changes underneath you and the wake stops working.

## 5. Wake it

Put the target to sleep or shut it down, then ask your relay to wake it:

```sh
curl -s -X POST https://relay.example.com/wake \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"a1b2c3d4e5f60718","mac":"AA:BB:CC:DD:EE:FF"}'
```

A reply with `ok:true` means the dongle sent the packet, and `sent` and `ifaces` say how many went
where. If the PC stays asleep after that, the problem is the PC or the network segment — go to
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

---

## The hosted service

[roosterwake.com](https://roosterwake.com) runs a relay so you do not have to, and
[setup.roosterwake.com](https://setup.roosterwake.com) is a guided flasher that does all of the
above in a browser, including registering the device to your account. It needs an account,
because registering a device to an account is what it is for.

Nothing on this page depends on it. Every mechanism the guided setup drives — the captive portal,
`mkconfig`, and the `usbcfg` command channel including `SET_TOKEN` — is public, documented and
usable against your own relay with a terminal.

Walkthrough: [`HOSTED-SETUP.md`](HOSTED-SETUP.md).

## Where to go next

| | |
|---|---|
| It did not work | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) |
| Run your own relay | [`SELF-HOSTING.md`](SELF-HOSTING.md) |
| The wire protocol | [`../PROTOCOL.md`](../PROTOCOL.md) |
| Talk to the device directly | [`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md) |
| A case for it | [`../case/`](../case/) |
