# Troubleshooting

Work down the chain: the target PC, then the network, then the dongle. Most failures are the first
one.

---

## The target PC will not wake

### Windows

Four things must all be true. The setup page's step 5 checks them and gives you the fix inline;
this is the same list by hand.

**1. Wake-on-LAN enabled in firmware (BIOS/UEFI).** Named "Wake on LAN", "Wake on PCI-E", "Power
On by PCI-E" or "Resume by LAN" depending on vendor. On some boards this only appears when
ErP/EuP power saving is disabled.

**2. Wake on Magic Packet enabled on the adapter.** Read it:

```powershell
Get-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "Wake on Magic Packet"
```

Set it:

```powershell
Set-NetAdapterAdvancedProperty -Name "Ethernet" -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled"
```

This restarts the adapter and the link drops for several seconds. **If you are connected to that
machine remotely over that adapter, this will disconnect you.**

**3. The adapter is allowed to wake the computer.** Reading needs no administrator:

```powershell
powercfg -devicequery wake_programmable
```

Enable it:

```powershell
powercfg /deviceenablewake "Intel(R) Ethernet Connection I219-V"
```

The name must match the one `wake_programmable` printed, exactly.

**4. Fast Startup off.** Windows "shutdown" with Fast Startup on is a hibernation, and the adapter
is powered down in a state that will not wake.

```powershell
powercfg /hibernate off
```

Or leave hibernate available and disable only Fast Startup: Control Panel → Power Options →
Choose what the power buttons do → Change settings that are currently unavailable → clear **Turn
on fast startup**.

Re-run the check after a fix, as a separate step. A report taken while the adapter is still
restarting shows no link and reads as a new fault.

### Linux

Find the interface and check what it supports:

```sh
sudo ethtool eth0 | grep -i wake
```

`Supports Wake-on` lists the modes the hardware has; `Wake-on` is what is active. You want `g`
(magic packet). Enable it:

```sh
sudo ethtool -s eth0 wol g
```

This does not survive a reboot. With NetworkManager:

```sh
nmcli connection modify "Wired connection 1" 802-3-ethernet.wake-on-lan magic
```

Otherwise use a systemd unit or a udev rule that re-runs the `ethtool` command at boot.

**Use the permanent MAC, not the current one.** They differ on bonded, randomised or
MAC-spoofed interfaces, and wake-on-LAN matches the permanent one:

```sh
sudo ethtool -P eth0
```

### macOS

System Settings → **Energy Saver** (desktop) or **Battery → Options** (laptop) → enable **Wake for
network access**.

macOS wakes from **sleep only**. A Mac that has been shut down will not wake, regardless of
settings — this is a macOS limitation, not something the dongle can work around.

---

## Wi-Fi targets

Support varies by adapter and driver. Group-key rekeying interferes with it, and Modern Standby
complicates it further. We do not promise WoWLAN works, and if a wired connection is available it
is worth using it just for this.

---

## The network

The dongle broadcasts a magic packet on its own segment. If the target is not on that segment,
nothing you do to the PC will help.

- **Guest SSIDs** are usually a separate segment.
- **Client isolation** (also "AP isolation") blocks device-to-device traffic on the same SSID.
- **VLANs** separate segments by design.
- Some routers **block directed broadcasts** entirely.

Put the dongle on the same SSID and VLAN as the target. If wake works from a laptop on that
network but not from the dongle, the dongle is on the wrong segment.

---

## The dongle

Connect over USB serial (any baud — USB CDC ignores the line rate) and use the commands in
[`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md).

### The board does not appear at all

Almost always a **charge-only USB cable**. Try a different cable before anything else.

If the board has no firmware it presents a drive rather than a serial port. Hold **BOOTSEL** while
plugging it in to force that state deliberately.

### It will not join Wi-Fi

```
INFO
STATUS
```

Read the failure from **`last_error`, not from `wifi`**. The radio retries for ever on a backoff
ladder, so `wifi` only shows `failed` in the gaps between attempts — often a two-second window.
`last_error` is set for every failure kind and is cleared only by a successful join.

| `last_error` | Means |
|---|---|
| Authentication failure | Wrong password, or wrong auth mode |
| `dhcp_timeout` | Joined successfully; the router refused an address |
| Not found | SSID out of range, or 5 GHz only — the Pico W and Pico 2 W are **2.4 GHz only** |

`WIFI_TRACE` gives the join attempt in detail.

A scan cannot complete while the radio is joining. It runs to the limit and hears nothing; that is
expected, not a fault.

### It joins but never reaches the relay

```
INFO
```

Check `relay_url`. The device refuses plaintext `ws://` to a public address, so a URL that is not
`wss://` will never connect.

An `auth` failure means the token in the device and the token in the relay's config do not match.
The token is never transmitted, so nothing else will tell you.

A relay that does not echo the `roosterwake.v1` subprotocol is not v2-conformant and the device
will close the connection. The token names the protocol family and does not track the major
version, which is why it still reads `v1`. See §1 and §12 of
[`../PROTOCOL.md`](../PROTOCOL.md).

### It reports `ok:false`

The dongle answered and told you what went wrong, which is more useful than silence.

| | Means |
|---|---|
| `no_link` | The dongle's own network dropped at the moment of the request |
| `send_failed` | The broadcast could not be sent |
| `ok:true` but the PC stays asleep | The packet went out. The problem is the PC or the segment — go back to the top of this page |

`sent` and `ifaces` in the reply tell you how many packets went where.

`TEST_WAKE <mac>` sends a packet without going through the relay, which separates a dongle problem
from a relay problem. The address is required — the dongle holds no list of machines to pick a
default from.

### Starting over

Over USB serial:

```
FACTORY_RESET CONFIRM
```

The literal `CONFIRM` is required; without it you get `ERR needs_confirm`. It clears Wi-Fi, the
relay override, the account address and the enrolled flag, then reboots into setup mode. There is
no undo and the Wi-Fi password is gone.

**`device_id` and `token` survive.** They identify the hardware rather than its owner, and a
device that came back with a fresh token would be refused by any relay that already knew it —
which would turn the recovery action into the thing needing recovery. Re-running setup afterwards
can bind the device to a different account, which is what makes reset the right answer for a
mistyped address, a gift or a resale. See §8 of
[`../firmware/docs/config-format.md`](../firmware/docs/config-format.md).

Without a cable, use the button:

**Plug the dongle in, wait a couple of seconds, then hold BOOTSEL for five seconds.** The LED goes
solid while it erases, then confirms for two seconds and reboots into setup mode. Release before
five seconds and nothing happens.

Do not hold the button while plugging in. That is a different feature — the chip's own bootloader
takes the button at power-on and the dongle comes up as a USB drive instead, which is how you
recover a board with no firmware on it. Let go once the reset starts, or you will land there
anyway on the reboot.

The window is the first 20 seconds after power-on. After that the button does nothing.

---

## After hand-flashing

Running the setup page after flashing a build by hand **silently reverts the firmware** to whatever
the registry serves. Confirm what is actually on the board with `INFO` before drawing any
conclusion about a firmware change.

---

## Still stuck

Open an issue: [github.com/phodgers/roosterwake/issues](https://github.com/phodgers/roosterwake/issues).
Include the firmware version, the board, and whether the relay is ours or self-hosted — see
[`../CONTRIBUTING.md`](../CONTRIBUTING.md).

Strip Wi-Fi passwords and device tokens from anything you paste.
