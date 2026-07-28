# mkconfig

Generate a configuration UF2 for a Remote Wake dongle. Drag it onto the BOOTSEL drive and the
device comes up already provisioned — no hotspot, no captive portal, no phone.

Useful when you are setting up more than one device, when the dongle is going somewhere you
would rather not stand next to with a phone, or when you want provisioning in a script rather
than in a browser.

Zero dependencies. Node 20 or newer.

## Use it

```sh
npx @remotewake/mkconfig \
  --ssid "HomeNet" \
  --psk "hunter2" \
  --target "Desktop=AA:BB:CC:DD:EE:FF" \
  --out remotewake-config.uf2
```

Then hold BOOTSEL while plugging the Pico in, and drag both `remotewake.uf2` (the firmware,
if it is not already flashed) and `remotewake-config.uf2` onto the drive that appears.

Run `mkconfig --help` for the full option list.

## Where the MAC address comes from

The `--target` MAC is the address of the **PC you want to wake**, not the dongle. It must be
the wired Ethernet adapter's MAC if you are waking over Ethernet, which is what you should be
doing — Wi-Fi wake is unreliable for reasons outside anyone's control.

| | |
|---|---|
| Windows | `ipconfig /all`, look for "Physical Address" under your Ethernet adapter |
| macOS | `ifconfig en0 \| grep ether` |
| Linux | `ip link show` |

Any separator works — `AA:BB:CC:DD:EE:FF`, `AA-BB-CC-DD-EE-FF`, or `aabbccddeeff`. It is
normalised on the way in.

## Self-hosting

If you run your own relay, generate the device identity yourself and add it to your relay's
`config.json` before flashing:

```sh
mkconfig --ssid "HomeNet" --psk "hunter2" \
         --relay "wss://wake.example.com/ws" \
         --device-id "$(openssl rand -hex 8)" \
         --token "$(openssl rand -hex 32)" \
         --target "NAS=11:22:33:44:55:66" \
         --out remotewake-config.uf2
```

If you omit `--device-id` or `--token` they are generated for you and printed once. Copy them
before the terminal scrolls; there is no way to recover a token from the UF2's owner later,
and the device will not show it to you again.

For a self-signed certificate, add `--insecure-tls`. The device will flash its error pattern
continuously while that flag is set — deliberately, because a dongle that has silently stopped
verifying certificates should not look identical to one that has not.

## Inspect a file before trusting it

```sh
mkconfig --verify remotewake-config.uf2
```

Prints the address, family ID and every field except the password and token. Worth running on
anything you did not generate yourself.

## This file contains secrets

The generated UF2 holds your **Wi-Fi password and device token in plain text**. That is
inherent to what it is — a flash image, decoded by a device with no secure element and no key
to decrypt anything with.

Treat it like a password file. Do not commit it. Do not email it. Delete it once the device is
provisioned. `.gitignore` in this repository already excludes `remotewake-config.uf2` so an
accidental `git add -A` cannot catch it, but that only helps inside this repository.

## For implementers

- [`lib/config.mjs`](lib/config.mjs) — the record codec. Also the reference implementation
  against which the firmware's C is measured.
- [`lib/uf2.mjs`](lib/uf2.mjs) — UF2 reader/writer.
- The format is specified in [`firmware/docs/config-format.md`](../../firmware/docs/config-format.md).
- [`firmware/test/vectors/config-v1.json`](../../firmware/test/vectors/config-v1.json) holds
  golden vectors consumed by **both** this package's tests and the firmware's C tests. The
  format is implemented three times — here, in the firmware, and in the hosted dashboard's
  generator — and that shared file is what stops the three from drifting apart.

Regenerate the vectors with `npm run gen-vectors`. If the output changes, the firmware's C
implementation must change in the same commit.

```sh
npm test
```

MIT licensed.
