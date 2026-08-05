# Guided setup

[setup.roosterwake.com](https://setup.roosterwake.com) does everything in
[`QUICKSTART.md`](QUICKSTART.md) in a browser — flashing, Wi-Fi, target, and a check that the
target PC can actually be woken — and registers the device to your account on the hosted relay.

It needs an account, because registering a device to an account is what it is for. Sign-up is
free and sign-in is a magic link; there is no password.

If you are running your own relay, use [`QUICKSTART.md`](QUICKSTART.md) instead. Everything this
page drives is public and documented, and none of it requires this site.

## Pick a route

| Route | Needs | Use when |
|---|---|---|
| **Cable** | Chrome or Edge on desktop, USB data cable | Default. Faster, and it can read errors back off the device. |
| **Phone** | Any browser | No desktop to hand, or the cable route cannot see the board. |

Firefox and Safari do not implement WebSerial, so the cable route needs Chrome or Edge.

### Cable route

Press **Connect** and pick the board from the browser's chooser.

If nothing answers, it is almost always one of two things: a charge-only USB cable, or a board
with no firmware on it yet. The page says so and offers the bare-board route for the second.

**The bare-board route.** A board with no firmware presents a USB drive rather than a serial port,
so the page writes the two files onto that drive for you. It reveals one button per file: you
press it, choose the board's drive in the picker, and the page does the writing. There is no
drag-and-drop.

You are asked for the drive twice, once per file. That is not a bug — the board reboots as each
file lands, which invalidates the browser's handle on the drive. After the second file the board
comes back as a serial device with no permission granted to the page, so it offers **Connect**
again. That is the normal path.

Hold **BOOTSEL** while plugging the board in if the drive does not appear on its own.

### Phone route

Power the dongle. It raises an open Wi-Fi hotspot called **`RoosterWake-Setup-XXXX`**. Join it and
the page opens on its own; if it does not, browse to `http://192.168.4.1`.

## The five steps

1. **Connect** — finds the board and reads what is on it.
2. **Firmware** — installs or updates to the current release.
3. **Wi-Fi** — pick your network and enter the password. This step commits and waits for the
   radio, so you find out here whether the credentials work rather than at the end.
4. **Target** — **Find your PC** scans the LAN and lists what it finds by name. Pick the target,
   or enter its MAC address by hand. The machine is saved to **your account**, not to the dongle:
   nothing about your PCs is written to the device, and you can add, rename or remove machines
   later from the dashboard without going near it again.
5. **Prove it** — checks the target can be woken, then sends a real wake.

Step 5 asks where the PC is, because the answer changes what it can show you. On another machine
you watch it wake. On the machine you are sitting at you cannot watch it wake itself, so it sends
a test packet and hands over to your phone.

## The pre-flight

Step 5 asks you to run a command on the target PC and paste the output back. It reports four
conditions:

- Wired adapter with a link
- **Wake on Magic Packet** enabled on the adapter
- The adapter is **allowed to wake the computer**
- **Fast Startup** off

Anything failing comes with the exact command that fixes it, filled in with the adapter you chose
at step 4. Reading the conditions needs no administrator; the fixes do.

Run the fix, then re-run the pre-flight as a separate step. Changing an adapter property restarts
the adapter, so a report taken while the link is still down shows no link and reads as a fresh
fault rather than a fix that worked.

**If you are connected to that machine remotely over the adapter you are changing, this will
disconnect you.**

The pre-flight is Windows only — the paste is PowerShell. Linux and macOS targets skip the step;
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) covers both by hand.

## After setup

Wake the machine from the dashboard at [roosterwake.com](https://roosterwake.com).

If a step failed, [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) covers the device side and the target
PC. One trap worth knowing: flashing a build by hand and then running guided setup reverts the
firmware to whatever the release registry serves. Confirm what is actually on the board with
`INFO` over USB serial before concluding anything about a firmware change.
