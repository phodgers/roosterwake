# Remote Wake firmware

C firmware for a Raspberry Pi Pico 2 W, built on pico-sdk 2.2.0. MIT licensed.

The dongle sits on a home LAN, holds a persistent outbound TLS WebSocket to a relay, and
broadcasts Wake-on-LAN magic packets when told to.

## Contracts

Three documents are binding, and the code answers to them rather than the other way round:

| Document | Covers |
|---|---|
| [`../PROTOCOL.md`](../PROTOCOL.md) | the dongle-to-relay wire protocol |
| [`docs/config-format.md`](docs/config-format.md) | the flash configuration layout, byte for byte |
| [`docs/usbcfg.md`](docs/usbcfg.md) | the USB serial command set |

[`docs/architecture.md`](docs/architecture.md) explains the decisions behind the code — poll
mode, the TLS buffer sizes, why the probe works the way it does — and is not binding.

## Building

```sh
export PICO_SDK_PATH=/path/to/pico-sdk
cmake -S . -B ../build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build ../build
```

The result is `remotewake.uf2`. Hold BOOTSEL while plugging the board in, or send `BOOTSEL`
over the USB command channel, and copy the file to the drive that appears.

The SDK needs its `lib/lwip`, `lib/cyw43-driver`, `lib/mbedtls` and `lib/tinyusb` submodules:

```sh
git -C "$PICO_SDK_PATH" submodule update --init
```

### Use a prebuilt picotool

By default the SDK downloads picotool's source and builds it as part of your first configure.
That works, but it is slow, and it puts a large C++ program at the mercy of whatever host
compiler you happen to have. Building it with a very new MinGW (GCC 16) produces a `picotool`
that **segfaults in `coprodis`** while disassembling the SDK's own `boot_stage2` — which fails
the build before a single line of this firmware is compiled, with an error that looks nothing
like its cause.

Point CMake at an official prebuilt instead. Download the `picotool-*-<platform>` archive from
[pico-sdk-tools releases](https://github.com/raspberrypi/pico-sdk-tools/releases) matching your
SDK version, extract it, and set:

```sh
export picotool_DIR=/path/to/picotool        # the directory holding picotoolConfig.cmake
```

`find_package(picotool)` then finds it, the source build is skipped entirely, and configure
takes seconds rather than minutes.

### Build options

| Option | Default | Effect |
|---|---|---|
| `RW_TLS_CUSTOM_CA=<file>` | unset | Replaces the built-in root bundle with a PEM of your own, for a relay behind a private CA |
| `RW_TLS_INSECURE=ON` | `OFF` | Skips certificate verification entirely. Warns at configure time, logs on every connection, and flashes the error LED continuously |

Neither is needed to talk to a relay behind any public CA.

## Tests

The host tests build the portable half of the firmware — the config codec, the WebSocket frame
codec and handshake, the HMAC proof, the JSON layer, URL parsing and the magic packet — with
the host compiler and run them natively. Same source files, no mocks.

```sh
cmake -S test -B ../build-test -G Ninja
cmake --build ../build-test
ctest --test-dir ../build-test --output-on-failure
```

`test/vectors/config-v1.json` is the golden vector file for the flash format. Both this suite
and [`tools/mkconfig`](../tools/mkconfig) consume it, which is what stops the two
implementations drifting apart and bricking a device's configuration.

## Status LED

The board has one LED and usually lives behind a router, so the patterns are meant to be
readable across a room.

| Pattern | Meaning |
|---|---|
| Fast blink | Unprovisioned — the setup hotspot is up |
| Slow blink | Joining Wi-Fi, or connecting to the relay |
| Two pulses every 3 s | Authenticated to the relay; this is the resting state |
| 2 s solid | A wake was just sent |
| SOS | Authentication failed, deprovisioned, or TLS verification is disabled |

## Provisioning

Three ways in, all writing the same flash record. Whichever finishes first wins.

| Path | How |
|---|---|
| **Setup hotspot** | An unconfigured device raises an open AP called `RemoteWake-Setup-XXXX`. Join it from a phone and the captive portal opens by itself — pick a network, enter the password, give it a PC's MAC address |
| **USB serial** | The line protocol in [`docs/usbcfg.md`](docs/usbcfg.md), driven from a terminal, a script, or `setup.remotewake.com` via Web Serial |
| **Config UF2** | [`tools/mkconfig`](../tools/mkconfig) builds an image carrying a whole configuration; drag it onto BOOTSEL and the device comes up provisioned with no interaction at all |

The portal is a single HTML file in [`src/provisioning/portal/`](src/provisioning/portal), gzipped
into flash at build time and served with `Content-Encoding: gzip`. `mock-server.mjs` next to it
serves the same page against a fake API, so the UI can be worked on without a Pico attached.

The DHCP and DNS servers behind it are written from scratch rather than vendored, so everything
under `firmware/` is MIT.

## What is not here yet

No over-the-air firmware update: updates happen by UF2, either drag-and-drop or through the
setup page's WebUSB flashing. This is a deliberate v1 decision rather than a gap — see §12 of
[`docs/architecture.md`](docs/architecture.md).
