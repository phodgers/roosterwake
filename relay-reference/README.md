# Rooster Wake reference relay

A complete, self-hostable relay for the Rooster Wake dongle. Node 20+, one dependency, one
file you can read in a sitting. It implements [`../PROTOCOL.md`](../PROTOCOL.md) in full,
including every part of the §12 conformance list.

Your dongle holds an outbound TLS connection to this. You send it an HTTP request. It tells
the dongle to broadcast a magic packet. That is the whole product.

---

## Scope, said plainly and up front

**This relay is deliberately single-tenant.** One API key, one config file, a handful of
devices you provisioned yourself. It has no user accounts, no sign-up, no billing and no web
dashboard, and it is not going to grow them.

That is not an oversight and it is not a crippled build. Everything the *device* does is here
and complete — the full handshake, the full command set, the diagnostics that matter. What is
missing is the *service*: accounts, apps, voice assistant skills, uptime, support. That is
what the hosted relay at [roosterwake.com](https://roosterwake.com) sells, and it is what pays
for this repository — the firmware, the case, the protocol work and this relay — to exist and
keep being maintained.

So, kindly and in advance: **pull requests adding multi-user accounts, billing, or a web
dashboard to this relay will be declined.** Not because they would be bad code. Because that
particular feature set is the one thing keeping the rest of it free, and a fork of this file
with a login page attached would quietly remove the reason any of it gets written.

Everything else is genuinely welcome, and some of it is actively wanted: protocol conformance
fixes, `probe` support, better diagnostics, packaging for more platforms, ports to other
languages. If you are unsure which side of the line an idea falls on, open an issue and ask —
that is a five-minute conversation, and it is a much better use of your time than a rejected
patch.

And if you disagree with any of this: the licence is AGPL-3.0, the protocol is public and
versioned, and forking is a first-class option. You will interoperate with our hardware and
our hosted service either way. That is the point of writing the contract down.

---

## Self-hosting in five minutes

You need Node 20 or newer, and somewhere the dongle can reach over TLS.

### 1. Install

```sh
git clone https://github.com/phodgers/remotewake.git
cd remotewake/relay-reference
npm install
```

### 2. Write a config

```sh
cp config.json.example config.json
```

```json
{
  "port": 8080,
  "api_key": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "devices": {
    "a1b2c3d4e5f60718": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
  }
}
```

- **`api_key`** authenticates *you* to the relay. Generate one and keep it out of shell
  history: `openssl rand -hex 32`.
- **`device_id`** is not yours to choose. It is derived from the board's unique ID at
  manufacture and is stable for the life of the device. Read it off the dongle — it is the USB
  serial number, and `INFO` over the USB serial channel prints it.
- **`token`** is 32 random bytes, `openssl rand -hex 32`. You pick it, you write it into the
  device during provisioning, and you put the same value here. It is never transmitted (§3),
  so if the two copies do not match, nothing tells you except an `auth` failure.

No `openssl` to hand? `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`.

`config.json` is gitignored at the repository root, because it is a file full of credentials.
Keep it that way.

### 3. Run it

```sh
npm start
```

```
2026-07-29T09:41:02.118Z info  remotewake-relay-reference/1.0.0 listening on 0.0.0.0:8080 — ws /ws, 1 device(s) provisioned
```

### 4. Prove it works before you go near hardware

In a second terminal, start the fake device with the same credentials:

```sh
node test/fake-device.js \
  --relay ws://127.0.0.1:8080/ws \
  --device-id a1b2c3d4e5f60718 \
  --token 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 \
  --target Desktop=AA:BB:CC:DD:EE:FF
```

In a third:

```sh
curl -s -X POST http://127.0.0.1:8080/wake \
  -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"a1b2c3d4e5f60718"}'
```

```json
{"device_id":"a1b2c3d4e5f60718","result_type":"wake_result","req_id":"…","ok":true,"sent":24,
 "ifaces":["255.255.255.255:9","192.168.1.255:9","255.255.255.255:7","192.168.1.255:7"]}
```

If that works, the relay is correct and anything that goes wrong next is the network or the
PC — which is a much smaller problem than not knowing which of the three it was.

### 5. Put TLS in front of it

Devices speak `wss://`. Plain `ws://` is permitted only for loopback and RFC 1918 addresses,
and production firmware refuses anything else (§1). Two ways to do it are below.

### 6. Point the dongle at it

Set the device's `relay_url` to `wss://relay.example.com/ws` during provisioning — the
captive portal, the USB serial `SET_RELAY` command, or a generated config image from
[`../tools/mkconfig`](../tools/mkconfig/) all set the same field.

---

## TLS: Caddy

The shortest working configuration. Caddy gets a certificate from Let's Encrypt on its own,
renews it on its own, and proxies WebSockets with no special directives — unlike nginx, which
needs `Upgrade` and `Connection` headers wired up by hand.

```caddyfile
relay.example.com {
	reverse_proxy 127.0.0.1:8080
}
```

That is the entire file. Two things are worth knowing:

- **Do not add a read timeout.** A device connection is idle by design between heartbeats, and
  Caddy's default of no timeout is what you want. If you have inherited a config with
  `transport http { read_timeout 30s }`, that will cut every device off twice a minute.
- **Caddy sets `X-Forwarded-For`**, which is what the relay logs as the device's address. If
  you have another proxy in front of Caddy, the first hop is the one that matters.

Bind the relay itself to loopback so nothing can reach 8080 directly:

```json
{ "host": "127.0.0.1", "port": 8080 }
```

**Not in Docker, though.** Inside a container, `127.0.0.1` is the container's own loopback, so
a published port reaches nothing and the healthcheck fails with an empty reply. Leave `host`
at `0.0.0.0` there and let the compose file's `127.0.0.1:8080:8080` do the restricting — that
binding is on the host side, which is where you wanted it anyway.

---

## TLS: Cloudflare Tunnel

A tunnel is the better choice when the relay is on a home connection: nothing is exposed, no
port is forwarded, and the origin does not need a public IP or a certificate of its own.

**1. Install `cloudflared`** and authenticate. This opens a browser and asks which zone to
authorise.

```sh
cloudflared tunnel login
```

**2. Create the tunnel.** This writes a credentials file under `~/.cloudflared/`.

```sh
cloudflared tunnel create remotewake
```

**3. Write `~/.cloudflared/config.yml`**, substituting the UUID the previous command printed:

```yaml
tunnel: 8f14e45f-ea0b-4c1a-9f2d-6e3a7c1b5d90
credentials-file: /home/you/.cloudflared/8f14e45f-ea0b-4c1a-9f2d-6e3a7c1b5d90.json

ingress:
  - hostname: relay.example.com
    service: http://127.0.0.1:8080
  - service: http_status:404
```

**4. Point DNS at it.** This creates the proxied CNAME for you:

```sh
cloudflared tunnel route dns remotewake relay.example.com
```

**5. Run it**, then install it as a service once you are happy:

```sh
cloudflared tunnel run remotewake
sudo cloudflared service install
```

**6. Check it end to end** from somewhere that is not your LAN:

```sh
curl https://relay.example.com/healthz
```

Three Cloudflare-specific things that will save you an evening:

- **WebSockets are enabled by default** on all plans. If you are on an older zone where
  someone turned them off, it is under Network in the dashboard.
- **Cloudflare closes an idle WebSocket after about 100 seconds.** The device sends
  `{"t":"ping"}` every 25 seconds (§9), which is why this works at all. If you write your own
  firmware and skip the keepalive, it will connect fine and then die every 100 seconds, and
  the logs will not tell you why.
- **Do not put Access in front of `/ws`.** A dongle cannot complete an interactive login. If
  you want Access on the HTTP API, scope the policy to the API paths and leave `/ws` alone.

---

## HTTP API

Everything except `/healthz` and `/source` needs `Authorization: Bearer <api_key>`. The key is
compared in constant time.

| Method | Path | Body | Purpose |
|---|---|---|---|
| `GET` | `/healthz` | — | Liveness. No auth, so an orchestrator does not need a key. |
| `GET` | `/source` | — | Where this relay's source lives. AGPL §13; see below. |
| `GET` | `/devices` | — | Every provisioned device, with online state and last-seen. |
| `POST` | `/wake` | `{device_id, mac?, repeat?}` | Broadcast a magic packet. |
| `POST` | `/status` | `{device_id}` | Signal strength, uptime, IP, firmware. |
| `POST` | `/config` | `{device_id, targets:[{name,mac}]}` | Replace the device's target list. |

`mac` is optional: without it the device wakes its first configured target. `repeat` is 1–5,
default 3. MAC addresses are accepted in any common form and normalised to
`AA:BB:CC:DD:EE:FF` (§2).

### Status codes

| Code | Meaning |
|---|---|
| `200` | The device answered. Read `ok` in the body — a device that reports `ok:false` still answered. |
| `400` | Malformed `device_id`, MAC, target list or JSON. |
| `401` | Missing or wrong API key. |
| `404` | No such `device_id` in `config.json`. |
| `429` | More than 30 wakes a minute for this device (§11). |
| `501` | The device did not advertise the capability this command needs (§4). |
| `503` | The device is provisioned but not connected. |
| `504` | The command went out and nothing came back within `wake_timeout_ms`. |

The distinction between `200 {"ok":false,"err":"no_link"}` and `503` is the useful one, and it
is deliberate. The first means the dongle answered and told you what went wrong. The second
means the dongle is not there. Collapsing both into a 5xx would throw away `sent` and
`ifaces`, which are the two fields that actually diagnose a failed wake (§4).

### Examples

```sh
export RW=https://relay.example.com
export API_KEY=…

curl -s $RW/healthz
curl -s $RW/devices -H "Authorization: Bearer $API_KEY"

curl -s -X POST $RW/wake -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"a1b2c3d4e5f60718","mac":"AA:BB:CC:DD:EE:FF"}'

curl -s -X POST $RW/status -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' -d '{"device_id":"a1b2c3d4e5f60718"}'

curl -s -X POST $RW/config -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"device_id":"a1b2c3d4e5f60718","targets":[
        {"name":"Desktop","mac":"AA:BB:CC:DD:EE:FF"},
        {"name":"NAS","mac":"11:22:33:44:55:66"}]}'
```

---

## Docker

```sh
cp config.json.example config.json   # then edit it
docker compose up -d
curl http://127.0.0.1:8080/healthz
```

The image runs as the unprivileged `node` user with a read-only root filesystem and all
capabilities dropped. `config.json` is mounted read-only at run time and is in
`.dockerignore`, so it never becomes an image layer — it holds every device token this relay
knows, and PROTOCOL.md §11 asks you to treat that store as secret material.

The compose file publishes on `127.0.0.1:8080` rather than `0.0.0.0`, because something else
should be terminating TLS. Change that line only when you know what is in front of it.

---

## The fake device

[`test/fake-device.js`](test/fake-device.js) is a dongle made of software. It speaks the whole
device half of the protocol — handshake, keepalive, wake, status, config, backoff — and prints
every frame in both directions. PROTOCOL.md §12 points implementers at it because it is the
fastest way to test a relay with nothing on the desk.

```
node test/fake-device.js --device-id <hex16> --token <hex64> [options]

  --relay <url>          ws:// or wss:// endpoint  (default ws://127.0.0.1:8080/ws)
  --target <name=mac>    add a target; repeatable, up to 8
  --ip <cidr>            simulated LAN address     (default 192.168.1.42/24)
  --fw <version>         reported firmware version (default 1.0.0)
  --caps <a,b,c>         advertised capabilities   (default wake,status)
  --simulate <mode>      ok | no_link | send_failed | silent   (default ok)
  --no-reconnect         exit after the first close instead of backing off
  --allow-plaintext      permit ws:// to a public address (§1 forbids it)
  --insecure-tls         skip certificate verification for wss:// (self-signed homelab)
  --quiet                no output
```

`--simulate` is how you test the paths that are otherwise hard to reach: `no_link` for a
device whose Wi-Fi dropped at the moment of the request, `silent` for one that never answers
at all, which is the only way to exercise a 504 without unplugging something.

A transcript looks like this, and reading it is usually faster than reading a stack trace:

```
09:41:19.402 . connecting to ws://127.0.0.1:8080/ws
09:41:19.418 . connected (subprotocol remotewake.v1)
09:41:19.419 -> {"t":"hello","v":1,"device_id":"a1b2…","nonce_c":"4c1e…","fw":"1.0.0",…}
09:41:19.423 <- {"t":"challenge","nonce_s":"9d2f…"}
09:41:19.424 -> {"t":"auth","proof_c":"3f2a9c81b4e05d7602ff1a8c9d3e4b57"}
09:41:19.426 <- {"t":"hello_ack","ok":true,"proof_s":"b1946ac9…","server":"…","now":1785283279}
09:41:19.427 . authenticated with remotewake-relay-reference/1.0.0 — link is trusted
09:41:24.881 <- {"t":"wake","req_id":"8f14e45f-…","mac":"AA:BB:CC:DD:EE:FF"}
09:41:24.882 . waking AA:BB:CC:DD:EE:FF: 3 burst(s) to 4 destination(s)
09:41:25.083 -> {"t":"wake_result","req_id":"8f14e45f-…","ok":true,"sent":24,"ifaces":[…]}
```

---

## Tests

```sh
npm test
```

31 tests, `node:test` only, no test framework to install. Each one boots a real relay on an
ephemeral port and drives it over a real socket. The first group maps one-to-one onto the
seven points of PROTOCOL.md §12, so if you are writing your own relay, point
[`test/smoke.mjs`](test/smoke.mjs) at it and you have an acceptance suite.

Set `RW_LOG=debug` to see every frame while the tests run.

---

## What this relay does not do

Said explicitly, so you can decide whether it fits before you deploy it.

- **No persistence.** Device state lives in memory and dies with the process. Devices
  reconnect with backoff (§8), so a restart costs seconds. The only durable state is
  `config.json`, which you wrote by hand.
- **No `probe`.** PROTOCOL.md §12 makes it optional, and it is not implemented. A device that
  advertises the capability simply never receives one.
- **No scheduling and no wake confirmation.** Those live in the hosted service.
- **No TLS.** Terminate it in front. Doing it here would mean certificate management, renewal
  and a second config file, which Caddy and `cloudflared` already do better.
- **No multi-tenancy.** See the top of this file.

---

## Licence

AGPL-3.0-or-later. Full text in [`LICENSE`](LICENSE).

The AGPL matters here specifically because a relay is something people run as a network
service. If you modify this and let others connect to it, section 13 requires you to offer
them the modified source. The relay makes that easy: `GET /source` returns whatever
`source_url` is set to in `config.json`. Point it at your fork and you are done.

The firmware, the case and the tools in this repository are MIT — only the relay is AGPL. The
name and logo are neither; see [`../TRADEMARK.md`](../TRADEMARK.md), which explains what you
can do (a lot) and what you cannot (call your fork ours).
