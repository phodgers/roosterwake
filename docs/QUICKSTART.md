# Quick start

From a board still in its bag to a PC you can wake from anywhere.

## What you need

- A **Raspberry Pi Pico W** or **Pico 2 W**. Nothing else — no soldering, no extra components.
- A **micro USB data cable**. Charge-only cables carry power but no data and are the most common
  reason the board does not appear.
- A **target PC**, ideally on wired Ethernet. Wi-Fi targets are best-effort; see
  [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).
- The dongle and the target must end up on **the same network segment**. Guest SSIDs, client
  isolation and VLANs all break this.

## 1. Create an account

Sign up at [roosterwake.com](https://roosterwake.com). Sign-in is a magic link; there is no
password. The setup site is behind that sign-in.

## 2. Open the setup page

Go to [setup.roosterwake.com](https://setup.roosterwake.com) and pick a route:

| Route | Needs | Use when |
|---|---|---|
| **Cable** | Chrome or Edge on desktop, USB data cable | Default. Faster, and it can read errors back off the device. |
| **Phone** | Any browser | No desktop to hand, or the cable route cannot see the board. |

Firefox and Safari do not implement WebSerial, so the cable route needs Chrome or Edge.

### Cable route

Press **Connect** and pick the board from the browser's chooser. If nothing answers, it is
almost always one of two things: a charge-only cable, or a board with no firmware yet. The page
offers the bare-board route for the second.

A board with no firmware is programmed by dragging two files onto the drive it presents. Hold
**BOOTSEL** while plugging it in to make that drive appear. The board reboots as each file lands,
so the browser asks for the drive again between them — that is expected, not a failure.

### Phone route

Power the dongle. It raises an open Wi-Fi hotspot called **`RoosterWake-Setup-XXXX`**. Join it
and the setup page opens on its own. If it does not, browse to `http://192.168.4.1`.

## 3. Work through the five steps

1. **Connect** — the page finds the board and reads what is on it.
2. **Firmware** — installs or updates. Current release is **1.11.0**.
3. **Wi-Fi** — pick your network and enter the password. This step commits and waits for the
   radio, so you find out here whether the credentials work, not at the end.
4. **Target** — **Find your PC** scans the LAN and lists what it finds by name. Pick the target,
   or type its MAC by hand.
5. **Prove it** — checks the target PC is actually able to be woken, then sends a real wake.

Step 5 asks where the PC is, because the answer changes what it can show you. On another machine
you watch it wake. On the machine you are sitting at, you cannot watch it wake itself, so it sends
a test packet and hands over to your phone.

## 4. Pre-flight the target PC

Step 5 asks you to run a command on the target and paste the output back. It reports four
conditions:

- Wired adapter with a link
- **Wake on Magic Packet** enabled on the adapter
- The adapter is **allowed to wake the computer**
- **Fast Startup** off

Anything failing comes with the exact command that fixes it. Run the fix, then re-run the
pre-flight as a separate step — changing an adapter property restarts the adapter, and a report
taken while the link is still down reads as a fresh fault.

Note: changing adapter properties drops the link for several seconds. If you are connected to
that machine remotely over the same adapter, you will be disconnected.

The pre-flight is Windows only. Linux and macOS targets skip the step; see
[`TROUBLESHOOTING.md`](TROUBLESHOOTING.md).

## 5. Wake it

From the dashboard at [roosterwake.com](https://roosterwake.com). Put the target to sleep or shut
it down, then send a wake.

## Where to go next

| | |
|---|---|
| It did not work | [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md) |
| Run your own relay | [`SELF-HOSTING.md`](SELF-HOSTING.md) |
| Provision without a browser | [`../tools/mkconfig/`](../tools/mkconfig/) |
| Talk to the device directly | [`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md) |
| A case for it | [`../case/`](../case/) |
