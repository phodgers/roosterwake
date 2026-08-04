# Security policy

## Reporting a vulnerability

Report privately through GitHub:
**[Report a vulnerability](https://github.com/phodgers/roosterwake/security/advisories/new)**.

Please do not open a public issue for a security problem.

Include what you have: affected component and version, what an attacker gains, and the steps or
proof-of-concept needed to reproduce it. A partial report is worth sending — we would rather
triage an incomplete one than not hear about it.

We acknowledge within 3 working days and give an assessment with a fix timeline within 10.

## Scope

In scope:

| Component | Notes |
|---|---|
| `firmware/` | Including the loader, OTA image verification and the flash config format |
| `relay-reference/` | The self-host relay |
| `tools/mkconfig/` | Config image generator |
| `PROTOCOL.md` | Weaknesses in the wire protocol itself, not just an implementation |
| The hosted service at `roosterwake.com` | Report here; it is closed-source but we own it |

Out of scope:

- Vulnerabilities in the pico-sdk, Node, or other dependencies. Report those upstream; tell us if
  we are exposed and have not pinned or patched.
- Findings that require physical access to an unlocked device. See below.

## Design decisions that are not vulnerabilities

These are properties of the system, documented here so a report is not spent on them.

**Wake-on-LAN magic packets are unauthenticated.** That is the WoL standard, not our choice.
Anyone already on the LAN can wake anything on it. The dongle's job is to be the only thing that
can send that packet *from outside* the LAN, and that path is authenticated.

**Physical access is the ownership claim.** A device token only reaches flash over USB, via a
config image, or through the setup page, which runs only after BOOTSEL was held at power-on. A
relay may re-bind a device that proves it holds the token — see the transfer section of
[`PROTOCOL.md`](PROTOCOL.md). Someone holding your unlocked dongle can take it over, and that is
deliberate: the alternative makes honest resale and returns impossible.

**The setup hotspot is open.** It runs only on demand, only until setup completes, and is how
credentials get in on a device with no screen or keyboard.

**LAN scanning and NBNS name lookup are unauthenticated.** They read what the local network
already broadcasts.

## Disclosure

Coordinated. We will agree a date with you, credit you unless you would rather we did not, and
publish an advisory when the fix ships. If we have not fixed a confirmed issue within 90 days of
acknowledging it, publish.

## Firmware signing

OTA images are signed, and every device checks the signature against a key compiled into it. An
unsigned or mis-signed image will not install. If you find a way past that check, it is the
highest-severity report this project can receive — say so in the title.
