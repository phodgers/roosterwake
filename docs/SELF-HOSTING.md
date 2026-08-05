# Self-hosting

The dongle holds an outbound TLS connection to a relay. Nothing about it requires that relay to be
ours. [`relay-reference/`](../relay-reference/) is a complete implementation of
[`PROTOCOL.md`](../PROTOCOL.md), AGPL-3.0, Node 20+, one dependency.

**[`relay-reference/README.md`](../relay-reference/README.md) is the relay documentation** —
install, config, TLS with Caddy or Cloudflare Tunnel, the HTTP API, Docker, and the software fake
device you can test against with no hardware on the desk. This page covers the parts that sit
either side of it: what you take on, and how to point a dongle at your own relay.

## What you take on

| | Hosted | Self-hosted |
|---|---|---|
| Accounts, sign-in, dashboard | Yes | No — one API key in a config file |
| Multiple users | Yes | No, and it is not planned |
| Apps and voice assistants | Yes | Whatever you build on the HTTP API |
| Scheduled wakes, wake confirmation | Yes | No |
| TLS certificates | Ours | Yours |
| Uptime | Ours | Yours |
| Device tokens | We store them | You store them, in a file you wrote |

The firmware is identical either way. There is no crippled community build and no premium
firmware — the device does everything it can do on both.

## Pointing a dongle at your relay

The device field is `relay_url`, and it must be `wss://` unless the address is loopback or
RFC 1918. Production firmware refuses plaintext to a public address. Three ways to set it, all
writing the same field:

**Setup page.** Works, but it provisions against the hosted service. Use one of the other two if
the device should never touch our infrastructure.

**USB serial.** Connect at any baud — USB CDC ignores the line rate — and send:

```
SET_RELAY wss://relay.example.com/ws
SET_TOKEN <your 32 random bytes, hex>
COMMIT
```

Nothing here names a machine to wake, and there is no command that would: the dongle stores no
such list, and every `wake` your relay sends carries the MAC it means ([`PROTOCOL.md`](../PROTOCOL.md)
§5). Which machines exist is your relay's business, in whatever form you keep it.

`SET_*` commands stage; only `COMMIT` writes. Read `reboot_in_ms` in the reply rather than
assuming — a relay URL and token are applied in place without a restart, whereas Wi-Fi changes
force one. The full command set is in
[`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md).

**Config image.** [`../tools/mkconfig/`](../tools/mkconfig/) generates a UF2 you drag onto the
board, which provisions it with no browser and no serial session. This is the route for flashing
several devices, or for a device that must be configured off the network entirely.

## The two credentials

`device_id` is derived from the board's unique ID at manufacture. It is stable for the life of the
device and is not yours to choose — read it off the dongle with `INFO`, or from the USB serial
number.

The **token** is 32 random bytes you generate. You write it into the device and put the same value
in your relay's config. It is never transmitted — the device proves possession without sending it
— so if the two copies differ, the only symptom is an `auth` failure. Generate it with
`openssl rand -hex 32`.

Treat your relay's config file as secret material: it holds every device token it knows.

## Checking it works

Test the relay with the software fake device before involving hardware. It speaks the whole device
half of the protocol and prints every frame in both directions, so a failure tells you which side
is wrong. See the fake-device section of
[`relay-reference/README.md`](../relay-reference/README.md).

Two failures worth knowing in advance:

- **A proxy read timeout will cut every device off.** Device connections are idle by design
  between heartbeats. Caddy's default of no timeout is correct; an inherited `read_timeout 30s` is
  not.
- **Cloudflare closes an idle WebSocket after about 100 seconds.** The device pings every 25
  seconds, which is why it survives. Firmware that skips the keepalive connects fine and then dies
  every 100 seconds with nothing useful in the logs.

## Interoperability

[`PROTOCOL.md`](../PROTOCOL.md), [`../firmware/docs/usbcfg.md`](../firmware/docs/usbcfg.md) and
[`../firmware/docs/config-format.md`](../firmware/docs/config-format.md) are versioned and treated
as public API. A relay is v2-conformant if it satisfies the §12 list; the reference relay's smoke
suite maps onto those points one-to-one, so you can point it at your own implementation and use it
as an acceptance test.

Forking is a first-class option. The licence is AGPL-3.0 for the relay, MIT for the firmware and
tools. The name and logo are neither — see [`../TRADEMARK.md`](../TRADEMARK.md).
