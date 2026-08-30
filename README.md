# Rooster Wake

**A tiny always-on Wi-Fi dongle that wakes your sleeping PC from anywhere.**

Wake-on-LAN magic packets are LAN broadcasts. They cannot cross the internet. So something
inside your network has to send one — and for most people today, that something is a PC they
left switched on.

Rooster Wake is a Raspberry Pi Pico 2 W in a snap case, plugged into any mains socket near
your router. It holds an *outbound* TLS connection to a relay, so there are no ports to
forward and nothing exposed to the internet. When a wake command arrives, it broadcasts the
magic packet on your LAN. Your PC can be properly asleep, and nothing else in the house has
to stay on.

It draws about half a watt.

---

## Three ways to use this

**Build it.** Everything you need is in this repository: the complete firmware, the case, the
bill of materials, and a self-hostable relay. You do not need us for any of it, and you never
will.

**Buy it.** If you would rather not print a case and source parts, we sell a kit —
a Pico 2 W, an official Raspberry Pi power supply, and the case, pre-flashed and ready.
[roosterwake.com](https://roosterwake.com)

**Subscribe.** Our hosted relay is free for basic remote wake — one machine, one emitter, and
voice included: "Alexa, wake my PC" is on every plan, because your own Echo broadcasts the
packet and it costs us almost nothing to arrange. Paid plans add server-side schedules that
retry and report, wake confirmation (did it actually come up), power actions through the agent
(sleep, restart, shutdown), more machines and emitters, account sharing, wake links, webhooks,
and longer history.

The boundary is a service, not a feature list. Everything the *device* does is open and
complete — there is no crippled community firmware and no private premium firmware. What we
charge for is hosted infrastructure: uptime, accounts, apps, support.
Self-hosting is a first-class supported path, and [`relay-reference/`](relay-reference/) is a
real implementation of it, not a toy.

---

## No hardware at all: the agent

If a machine in the house already stays on — a Raspberry Pi, a NAS, a home server — you may
not need the dongle. The **agent** is a free download that turns that machine into an emitter:
a virtual dongle. It is a Go program for Windows, macOS and Linux, including ARM, and it
speaks the same wire protocol as the firmware in this repository
([`PROTOCOL.md`](PROTOCOL.md), including the v2 power extension). On paid plans it also
carries power actions — sleeping, restarting or shutting down the machine it runs on, which is
the one thing a dongle sitting *beside* a machine can never do.
[roosterwake.com/agent](https://roosterwake.com/agent) is its page; the direct download URLs,
platform keys and checksum verification — no account needed, and the builds work against a
self-hosted relay — are documented in [`docs/DOWNLOADS.md`](docs/DOWNLOADS.md).

Like the dongle, the agent only ever dials out: nothing listens on the network, nothing is
forwarded, and nothing is exposed to the internet. The one listener it holds is deliberately
*off* the network — a loopback-only identity beacon on `127.0.0.1:47653` that tells this
machine's **own** browser which emitter it is sitting at, so the dashboard can frame the page
accordingly. It serves nothing but the device id (the public half of the identity, never the
token), and it is unreachable from the LAN, the router, or anywhere else on the wire.

To be precise about what is open here: the protocol is public and
[`relay-reference/`](relay-reference/) is a real implementation of the relay half of it; the
agent itself is ours — closed source, free. If you want an open software emitter,
[`PROTOCOL.md`](PROTOCOL.md) is everything you need to write one, and the reference relay's
fake device is a working example of the device half.

One limit, stated plainly because it is physics rather than pricing: an agent on a sleeping
machine is asleep. While its host is up it can wake the other machines on the segment; once
its host sleeps, something else has to send the packet that wakes it — a dongle, or an agent
on another machine.

---

## Repository layout

| Directory | What it is | Licence |
|---|---|---|
| [`firmware/`](firmware/) | Pico 2 W firmware, C, pico-sdk | MIT |
| [`relay-reference/`](relay-reference/) | Minimal self-host relay, Node + `ws` | AGPL-3.0 |
| [`case/`](case/) | Snap case: STL, print notes | MIT, Adafruit Industries |
| [`tools/mkconfig/`](tools/mkconfig/) | Generate a config UF2 for headless provisioning | MIT |
| [`docs/`](docs/) | Quickstart, provisioning, self-hosting, agent downloads, guided setup, troubleshooting | — |

The contracts that keep forks and our hosted service interoperable are
[`PROTOCOL.md`](PROTOCOL.md) (the dongle↔relay wire protocol),
[`firmware/docs/usbcfg.md`](firmware/docs/usbcfg.md) (the USB serial command set) and
[`firmware/docs/config-format.md`](firmware/docs/config-format.md) (the flash config layout).
All three are versioned and treated as public API.

---

## Quick start

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full walkthrough. In brief:

1. Hold BOOTSEL while plugging a Pico 2 W in, and drag the release's `loader-*.uf2` onto the
   drive that appears. Repeat with `*-install.uf2`.
2. Power it up. It starts a Wi-Fi hotspot called `RoosterWake-Setup-XXXX`.
3. Join that hotspot from your phone. A setup page opens automatically.
4. Pick your network and enter the password. It does not ask which PC to wake — a dongle holds
   no list of machines, and every wake names its MAC in the frame that asks.
5. It reboots, joins your network, and connects to the relay.

Nothing there needs an account. Self-hosting the relay takes about five minutes:
[`docs/SELF-HOSTING.md`](docs/SELF-HOSTING.md).

On the hosted service, [setup.roosterwake.com](https://setup.roosterwake.com) does all of it in a
browser and registers the device to your account: [`docs/HOSTED-SETUP.md`](docs/HOSTED-SETUP.md).

---

## Will this actually wake my PC?

Usually, and the honest answer depends mostly on your PC rather than on us.

**Wired Ethernet targets are reliable.** You will typically need to enable Wake-on-LAN in the
BIOS, enable "Wake on Magic Packet" on the network adapter, and turn off Windows fast
startup. [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) has the click-path for each
operating system.

**Wi-Fi targets (WoWLAN) are best-effort.** Support varies by adapter and driver, group-key
rekeying interferes with it, and Modern Standby complicates it further. We do not promise
this will work, and we would rather say so here than in a support ticket.

The other common failure is not your PC at all: some routers block LAN broadcasts, isolate
clients from each other, or put guest SSIDs on a separate segment. The dongle has to be on
the same segment as the target.

---

## Contributing

Contributions are welcome. We use [DCO](https://developercertificate.org/) sign-off rather
than a CLA — commit with `git commit -s`. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

One thing worth saying up front, kindly: the reference relay is deliberately single-tenant.
Pull requests adding multi-user accounts, billing or a web dashboard to it will be declined —
not because they are bad, but because that is what the hosted service is, and it is what pays
for this repository to exist. Everything else is fair game.

Security issues: please see [`SECURITY.md`](SECURITY.md) rather than opening a public issue.

## Licence and trademark

Firmware and tools are MIT. The reference relay is AGPL-3.0. The case is MIT, Copyright (c) 2016
Adafruit Industries — see [`case/LICENSE`](case/LICENSE). The **code** is free; the **name and
logo** are not — see [`TRADEMARK.md`](TRADEMARK.md), which explains exactly what you can do (a
lot) and what you cannot (call your fork ours).

Rooster Wake is not affiliated with Raspberry Pi Ltd or Adafruit Industries.
