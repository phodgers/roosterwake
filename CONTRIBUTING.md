# Contributing

## Where to send what

| | Where |
|---|---|
| Bug, question, feature idea | [GitHub issues](https://github.com/phodgers/roosterwake/issues) |
| Security vulnerability | [`SECURITY.md`](SECURITY.md) — private advisory, not an issue |
| Trademark and brand permission | [`TRADEMARK.md`](TRADEMARK.md) |

Accounts, billing and subscriptions on the hosted service are not handled here; this repository is
the device, the protocol and the self-host relay.

Use issues rather than email for anything about the code. It is public, searchable, and the next
person with the same problem finds the answer.

Before filing a bug, include the firmware version (`INFO` over USB serial, or the setup page),
the board (`pico_w` or `pico2_w`), and whether the relay is ours or self-hosted.

## Sign-off

We use [DCO](https://developercertificate.org/) sign-off rather than a CLA. Commit with
`git commit -s`, which appends a `Signed-off-by` line asserting you have the right to submit the
work under the file's existing licence.

## Scope

The reference relay is deliberately single-tenant. Pull requests adding multi-user accounts,
billing or a web dashboard to it will be declined — that is what the hosted service is, and it is
what pays for this repository to exist. Everything else is open.

[`PROTOCOL.md`](PROTOCOL.md), [`firmware/docs/usbcfg.md`](firmware/docs/usbcfg.md) and
[`firmware/docs/config-format.md`](firmware/docs/config-format.md) are versioned public API. A
change to any of them needs a version bump and a note on what breaks.

## Building

Requires CMake, Ninja, and the ARM GNU toolchain 14.2.rel1 with `PICO_SDK_PATH` set to a
pico-sdk 2.2.0 checkout. CI pins both — see
[`.github/workflows/firmware-build.yml`](.github/workflows/firmware-build.yml).

Firmware is linked at the address of the slot it runs in, so it builds twice per board:

```sh
cmake -S firmware -B build-a -G Ninja -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2_w -DRW_SLOT=a
cmake --build build-a
```

The loader is a separate project and is never replaced over the air:

```sh
cmake -S firmware/loader -B build-loader -G Ninja -DCMAKE_BUILD_TYPE=Release -DPICO_BOARD=pico2_w
cmake --build build-loader
```

Both boards are built on every push. They differ in chip, flash size, where the config sectors
land, and whether there is a hardware TRNG, so a change that builds for one says nothing about
the other. Build both before opening a pull request.

`RW_FW_VERSION` in [`firmware/src/brand.h`](firmware/src/brand.h) must match the release tag; the
release workflow fails if it does not.

## Tests

Host tests for the C side of the flash config format:

```sh
cmake -S firmware/test -B build-test -G Ninja
cmake --build build-test
ctest --test-dir build-test --output-on-failure
```

The JavaScript side, from `tools/mkconfig`:

```sh
npm test
```

Both check the same golden vectors in `firmware/test/vectors/config-v2.json`, so a one-sided
change to the encoder fails in the other suite. If you change the encoder, regenerate the vectors
with `npm run gen-vectors` in `tools/mkconfig` and mirror the change in
`firmware/src/config/config.c`. CI fails if regenerating is not a no-op.

## Style

Match the file you are editing.

Comments state the constraint, not the edit history. Write why the code has to be this way — the
hardware limit, the protocol requirement, the failure it prevents. "Changed to fix bug" and
"previously used X" belong in the commit message.

Never commit a Wi-Fi password, a device token, or a private key. `*.pem` and the local config
files are gitignored; private keys belong in `~/.remotewake/`.
