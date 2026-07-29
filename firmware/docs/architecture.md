# Firmware architecture

**Target**: Raspberry Pi Pico 2 W — RP2350A (dual Cortex-M33, 150 MHz), 520 KB SRAM, 4 MB
flash, CYW43439 radio. Built against pico-sdk 2.2.0.

This document explains the decisions that are not obvious from reading the code, and the ones
that would be expensive to reverse. The wire protocol is [PROTOCOL.md](../../PROTOCOL.md), the
flash layout is [config-format.md](config-format.md), and the USB command set is
[usbcfg.md](usbcfg.md); all three are contracts, and this document is not.

---

## 1. One thread, one loop

The firmware uses **`pico_cyw43_arch_lwip_poll`**, not `threadsafe_background`.

`main()` runs a single loop that calls `cyw43_arch_poll()`, and that call is the only place the
network stack executes. Every lwIP callback — TCP receive, DNS resolution, altcp's TLS state
machine, SNTP's clock update — therefore runs on the main context, in a known place, with
nothing else in flight.

The alternative, `threadsafe_background`, drives the driver from an alarm interrupt. It is more
convenient for simple programs and it would have been a mistake here. Two of the state machines
in this firmware — TLS and WebSocket framing — are large, stateful, and manipulate buffers that
callbacks also touch. Under `threadsafe_background` every one of those buffers needs a lock or
a re-entrancy argument, and the failure mode of getting one wrong is a corrupted TLS record
once a week on one device in a hundred. Poll mode removes the whole category by construction
rather than by discipline.

The cost is that the main loop must never block for long, because nothing runs while it does.
That is enforced in two ways:

- **Bounded waits pump.** `rw_sys_pump_ms()` (sys/sys.c) polls the driver and feeds the
  watchdog while it waits. The WoL burst gap is the only place that uses it. Nothing calls
  `sleep_ms()` for more than a few milliseconds.
- **Blocking work is deferred out of callbacks.** `proto.c` receives a `wake`, `status`,
  `probe` or `config_push` inside an lwIP receive callback and does not execute it there. It
  queues one pending command and runs it from `rw_relay_task()` on the main loop. A wake takes
  200 ms of bursts, a config save erases a flash sector with interrupts off, and an RSSI read
  is a round trip to the radio — none of those can safely happen underneath the stack that
  delivered the request.

  Only one command runs at a time. A second arriving while one is pending is answered `busy`
  (PROTOCOL.md §6), which is a real answer rather than a queue that can grow.

The loop sleeps with `cyw43_arch_wait_for_work_until()` and a 10 ms cap, so it neither spins
nor lets timers drift.

---

## 2. Module map

```
src/
  brand.h            product name, relay URL, setup SSID, subprotocol — the single rename point
  main.c             boot, state selection, the loop
  lwipopts.h         NO_SYS lwIP, altcp+TLS, SNTP
  rw_log.[ch]        "# "-prefixed diagnostics, off unless the operator enabled them

  config/            the flash record: codec (portable) + dual-slot storage (device)
  crypto             — none. mbedTLS provides SHA-256, SHA-1 and base64; HMAC is in proto/auth.c
  led/               status patterns on the CYW43439's GPIO 0
  net/               station mode, DHCP, SNTP, URL parsing, learned MAC->IP addresses
  proto/             PROTOCOL.md frames, the handshake, JSON, the ARP probe
  sys/               watchdog, uptime, reset reason, BOOTSEL, wall clock
  tls/               mbedTLS configuration, root CA bundle, altcp_tls setup
  vendor/            jsmn, unmodified, with provenance
  wol/               magic packet (portable) + UDP transmission (device)
  ws/                RFC 6455: frame codec and handshake (portable) + client (device)
```

Modules are split along one line: **anything that is a wire format or a policy decision is
host-portable, and anything that touches hardware is not.** The portable half is listed as
`RW_PORTABLE_SOURCES` in both `CMakeLists.txt` files and is compiled unchanged into the native
test binary. That is why the tests exercise the code that ships rather than a copy of it.

---

## 3. Flash configuration

Two 4096-byte sectors at `0x3FE000` and `0x3FF000`, per config-format.md. The reasoning for
dual slots is in that document; what matters here is how the firmware avoids reaching them.

`src/config/flash_reserve.ld` is an extra linker script, appended to the SDK's memmap with a
second `-T`:

```
ASSERT(__flash_binary_end <= 0x103FE000, "...")
```

It is an assertion rather than a vendored copy of the SDK's memmap because a copy goes stale
silently on an SDK update and produces a subtly wrong image; an assertion fails loudly or not
at all. It has been verified to fire: lowering the constant below the real image end makes the
link fail with the message above.

Writes go through `flash_safe_execute()`, and `PICO_FLASH_ASSUME_CORE1_SAFE=1` is set because
core 1 is never launched — without it the helper refuses to run at all, since it cannot know
what a core it has not been introduced to is doing.

---

## 4. TLS

`altcp_tls` over mbedTLS 3.6.2, TLS 1.2, ECDHE with AES-GCM only, SNI mandatory.

The configuration is `src/tls/mbedtls_config.h`, found by the SDK's `pico_mbedtls_config.h`
(which does `#include "mbedtls_config.h"` and expects the application to supply it). Three
things in it are worth knowing:

**The input record buffer is 16 KB, not the 4 KB originally intended.** lwIP keeps
`struct altcp_tls_config` private to `altcp_tls_mbedtls.c`, so the `mbedtls_ssl_config` inside
it cannot be reached and `mbedtls_ssl_conf_max_frag_len()` cannot be called. Without that call
the RFC 6066 `max_fragment_length` extension is never offered, and a 4 KB input buffer would
fail against any server that chose to emit a larger record — most often the Certificate message
during the handshake, whose size is the server's choice. A device that cannot connect is a
worse outcome than 12 KB of a 520 KB part. The output buffer stays at 4 KB; the largest frame
this firmware sends is under 800 bytes.

**Verification is switched per connection, not per configuration.** For the same reason, the
authmode cannot be changed at runtime on the shared config. `ALTCP_MBEDTLS_AUTHMODE` is pinned
to `MBEDTLS_SSL_VERIFY_REQUIRED` in `lwipopts.h`, and the `TLS_INSECURE` config flag installs
a `mbedtls_ssl_set_verify()` callback on the individual connection instead. That is a better
arrangement than blanket `VERIFY_OPTIONAL` anyway: the callback logs exactly which certificate
at which depth would have failed and with which flags, before clearing them. A path that
forgets to install it fails closed.

**Certificate expiry is actually checked.** `MBEDTLS_HAVE_TIME_DATE` is on, and the clock comes
from `sys/wallclock.c` via `mbedtls_platform_set_time()`. Before SNTP answers, that clock reads
zero, every certificate fails its `notBefore`, and no connection is attempted — `rw_net_ready()`
requires a valid clock. This is deliberate: PROTOCOL.md §1.1 forbids silently skipping expiry
checks because the clock is unset, and compiling without `MBEDTLS_HAVE_TIME_DATE` is exactly
that silent skip.

`MBEDTLS_ALLOW_PRIVATE_ACCESS` is required, not optional: lwIP's own glue reads
`mbedtls_ssl_context::out_left` and `mbedtls_ssl_session::start` directly, and both are private
in mbedTLS 3.x.

The SHA-256 hardware accelerator is **not** used (`MBEDTLS_SHA256_ALT` stays off). It is a
single shared unit that must be locked, and this firmware hashes from two places that can be
live at once — the TLS record layer and the HMAC proof. Serialising them correctly would cost
more than the accelerator saves at four hashes per connection.

### Root CAs

Six roots, in `src/tls/ca_bundle.c` with their source URLs, validity windows and SHA-256
fingerprints recorded against each: ISRG Root X1 and X2 (Let's Encrypt), DigiCert Global Root
CA and G2 (Cloudflare), GTS Root R1 and R4 (Google Trust Services). Roughly 8 KB.

A full Mozilla-sized store is about 150 roots, a quarter of a megabyte, and seconds of parsing
per connection on a Cortex-M33. It would also mean a misissuance by any one of 150 CAs is a
misissuance for this device. Six is the set a relay could plausibly sit behind.

`-DRW_TLS_CUSTOM_CA=<file>` replaces the bundle with an operator's PEM, embedded at build time
as bytes rather than as a string literal. `-DRW_TLS_INSECURE=ON` disables verification
entirely; it is off by default, warns at configure time, logs on every connection, and flashes
the error LED continuously.

---

## 5. WebSocket

Hand-rolled, in `ws/`. Nothing off the shelf fits: 2 KB inbound cap, mandatory subprotocol
echo, masking from a hardware TRNG, no allocation after start-up, and a single-threaded
poll-mode event loop.

`ws_frame.c` and `ws_handshake.c` are host-portable and carry the parts that can be got wrong:
the three length encodings, minimal-encoding enforcement, the mask, control-frame limits, and
the response validation. `ws.c` is the connection state machine and the only part that needs a
device.

Two behaviours are worth calling out because they are protocol requirements rather than
choices:

- **A relay that does not echo `remotewake.v1` is closed on** (PROTOCOL.md §1). This is how a
  device detects that it has been pointed at a captive portal, a misconfigured reverse proxy or
  somebody's Home Assistant. Without it the device connects, waits for a `challenge` that never
  arrives, and blinks at a wall for an hour.
- **The 2048-byte cap applies to the reassembled message, not to each fragment.** A relay that
  splits 4 KB into two individually legal frames is still over the limit this device can hold.
  Overflow closes with 1009.

Liveness is the device's own application-level `{"t":"ping"}` every 25 s, and 75 s without any
inbound frame closes the connection with **4003** — the idle-timeout code, kept distinct from
1008 so the backoff-reset rule in §8 cannot confuse "you went quiet" with "you failed
authentication".

---

## 6. Authentication

PROTOCOL.md §3.2, implemented in `proto/auth.c`. The token never leaves the device.

HMAC-SHA256 is built directly on mbedTLS's SHA-256 rather than on `mbedtls_md`, which would
drag in the digest registry and the PSA shims to reach one hash we already hold a handle on.
RFC 2104 is twenty lines and is pinned by four RFC 4231 vectors in the host tests, including
the longer-than-a-block key case that hand-written HMACs usually get wrong.

`proof_s` is computed at the same moment as `proof_c`, while both nonces are in hand, so
verifying `hello_ack` is a constant-time comparison and nothing else. A proof that does not
verify closes with 1008, sends nothing further, and backs off — and lights the error LED,
because a device that silently retries against a hostile relay for ever is worse than one that
visibly fails.

Nonces come from `get_rand_32()`, which on the RP2350 is seeded and continuously re-mixed from
the hardware TRNG. So do the WebSocket masking keys and the `Sec-WebSocket-Key`.

---

## 7. Wake-on-LAN

`sent` is exactly `ifaces.length × repeat` — one datagram per destination per burst, `repeat`
bursts 100 ms apart. PROTOCOL.md §4 fixes that relationship because `sent` is the number a
support conversation turns on, and a figure nobody can reproduce from the other fields looks
authoritative and cannot be checked.

The invariant is enforced rather than approximated. A datagram the stack refuses is retried
once after a short pump; a second refusal abandons the whole wake and answers `send_failed`
with an empty result, because a partial send cannot be reported without breaking the
relationship. The function asserts the arithmetic before returning.

Destinations are the limited broadcast `255.255.255.255` and the subnet-directed broadcast
computed from the device's own IP and netmask, each on ports 9 and 7. Both addresses because
drivers differ on which they deliver; both ports because NIC firmware differs on which it
listens to. Reporting all four back is what lets a support answer be "your dongle broadcast on
192.168.1.255 and your PC is on 192.168.0.x" instead of a guess.

The `WOL_UNICAST` config flag adds the target's last-known address. That address comes from
`net/arplearn.c`, which samples lwIP's ARP table once a second and remembers what it held —
lwIP ages entries out in minutes, and "last known" has to outlive that.

---

## 8. The probe, and what it cannot do

`probe` (PROTOCOL.md §5) answers "did the machine actually come up", which a magic packet
cannot tell you on its own.

The mechanism is ARP: an ARP request to the target's address is answered only by a host that is
awake and on the network. It costs one frame and needs nothing installed on the target. ICMP is
not used, because a large share of Windows machines drop pings by default and a timeout would
mean nothing.

**This requires knowing the target's address**, and the only source a device like this has is
what it has seen on the segment (`net/arplearn.c`). A machine that has never been seen since
boot cannot be probed, and the probe reports `timeout`. That is an honest answer rather than a
misleading one, and it is why `probe` is an optional capability a relay feature-detects rather
than assumes. A `probe` naming an unparseable MAC returns `ok:false, err:"bad_mac"` with no
`state`, per §4.

---

## 9. Power management

`CYW43_PERFORMANCE_PM`, never `CYW43_AGGRESSIVE_PM`.

The aggressive profile parks the radio between beacons and drops inbound frames that arrive in
the gap. For a device whose entire job is to be reachable, that turns wakes into a coin flip,
and the resulting report — "it works sometimes" — is close to undiagnosable. The power saved is
milliwatts on a mains-powered dongle.

---

## 10. Reconnection

Backoff is 1 s doubling to 60 s with **full jitter** (`random(0, backoff)`), reset **only after
authentication completes** — not after TCP connects, or a relay that accepts sockets and
rejects them at `auth` would be hammered at one-second intervals for ever.

The device never reboots to recover a connection. Reconnection is a normal state, not a fault,
and a device that reboots itself loses its uptime record and any in-flight state. The only
close code that stops the loop is 4002 (deprovisioned).

Wi-Fi association has its own backoff, 2 s to 60 s, also fully jittered, and also never gives
up. A router rebooting, a house that has lost power, or an SSID that comes back on a different
channel are all normal; a dongle that stops trying after n attempts is a dongle somebody has to
go and unplug.

---

## 11. Watchdog

8 seconds, fed from the main loop and from every pumping wait. Long enough that a slow DNS
lookup, a TLS handshake on a congested link or a 4 KB flash program never trip it; short enough
that a wedged device recovers before anyone reaches behind the router.

The reset reason is latched in `rw_sys_init()` *before* `watchdog_enable()`, because
`watchdog_enable()` writes the scratch register `watchdog_enable_caused_reboot()` reads — get
the order wrong and every boot after the first looks like a watchdog reset. "watchdog" means
the firmware hung; "software" means somebody asked for a reboot. Different problems.

---

## 12. Scope of this build

This firmware implements the relay side of the product: flash configuration, Wi-Fi, TLS, the
WebSocket protocol, wake, status, probe, and the LED and watchdog around them.

Two things named in the surrounding documents are **not** in this build:

- **The USB serial command channel** ([usbcfg.md](usbcfg.md)). The USB CDC interface is up and
  the config module it drives is complete, but the command parser is a separate component. An
  unprovisioned device shows the setup LED pattern and waits.
- **The Wi-Fi setup hotspot and captive portal.** `RW_SETUP_SSID_PREFIX` in `brand.h` reserves
  the name and asserts at compile time that it leaves room for the `-XXXX` suffix inside the
  32-byte SSID limit, but nothing in this build brings up an access point. Until it exists, a
  device is provisioned over USB or with a config UF2 from `tools/mkconfig`.

`RW_LED_SETUP_AP` is named for where it is going; today it means "unprovisioned".

---

## 13. Building

```sh
export PICO_SDK_PATH=/path/to/pico-sdk        # 2.2.0, submodules checked out
cmake -S firmware -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build                            # -> build/remotewake.uf2
```

The SDK needs `lib/lwip`, `lib/cyw43-driver`, `lib/mbedtls` and `lib/tinyusb`. Without the
first two, `pico_cyw43_arch` does not exist and the build stops with a message saying so rather
than failing later at link time.

CMake 4 removed compatibility with `cmake_minimum_required(VERSION < 3.5)`, which some of the
SDK's vendored dependencies still declare. `CMAKE_POLICY_VERSION_MINIMUM` is set to 3.5 in both
`CMakeLists.txt` files, which is the supported fix; downgrading CMake is not.

Host tests are a separate CMake project, because one tree gets one toolchain:

```sh
cmake -S firmware/test -B build-test -G Ninja
cmake --build build-test
ctest --test-dir build-test --output-on-failure
```
