# Agent downloads

The [agent](https://roosterwake.com/agent) is the free software emitter: a single Go binary that
turns an always-on machine — a Raspberry Pi, a NAS, a home server — into the thing that puts the
magic packet on your network. It is closed source, free, and speaks the same wire protocol as the
firmware in this repository ([`../PROTOCOL.md`](../PROTOCOL.md)), so what it says to a relay is
documented to the frame.

If you use the hosted service, you normally never need this page: sign in and the dashboard
writes the install command for each machine with your email already in it. This page is the
direct-download reference for everyone else — self-hosters pointing the agent at their own
relay, fleet tooling fetching builds by hand, and anyone who wants to verify exactly what they
are running. **None of these URLs needs an account.**

## The URLs

The newest stable build for a platform is always at:

```
https://roosterwake.com/api/agent/download?platform=<key>
```

The URL is deliberately versionless — it resolves to the newest published build at the moment
you fetch it, so a script or a forum post written against it stays right across releases. To pin
a specific version instead, add it:

```
https://roosterwake.com/api/agent/download?platform=<key>&version=<version>
```

The Windows installer also has a stable, unversioned alias — the URL every install one-liner
uses:

```
https://roosterwake.com/agent/roosterwake-agent.msi
```

Every response carries a `Content-Disposition` filename that names the platform and the version
you actually received, and a `Content-Length`, so a progress bar is honest.

## Platform keys

| Key | What it is | How to know it is yours |
|---|---|---|
| `linux-amd64` | Linux, 64-bit Intel or AMD — most home servers, NAS boxes and Docker hosts | `uname -m` says `x86_64` |
| `linux-arm64` | Linux, 64-bit ARM — Raspberry Pi 3, 4, 5 and Zero 2 W running a 64-bit system | `uname -m` says `aarch64` |
| `linux-armv6` | Linux, 32-bit ARM — Pi Zero, Zero W and the original Pi, and any Pi running the 32-bit system | `uname -m` says `armv6l` or `armv7l` |
| `windows-amd64` | Windows, 64-bit — the bare portable executable: no installer, no admin rights, registers no service | |
| `windows-amd64-msi` | The same Windows build packaged as the installer — what the stable MSI URL above serves | |
| `darwin-arm64` | macOS, Apple silicon — M1 and later | |

Every build is a single static file with nothing to unpack and no runtime to install.

## Verifying what you downloaded

Two sources tell you what the bytes should hash to, and they come from the same place the bytes
themselves are served:

- **`https://roosterwake.com/api/agent/releases`** is the authoritative listing — JSON, public,
  one entry per currently published build, each carrying its `platform`, `version`, `sha256` and
  size. If a build is withdrawn it disappears from this list; a checksum you read here always
  names a build we currently stand behind.
- Every download response also carries the digest as an **`X-Agent-SHA256`** header (and the
  version as `X-Agent-Version`), so a script that only ever touches the download endpoint can
  verify without a second request.

A worked example, fetching a build for a 64-bit Pi and checking it:

```sh
curl -fLo roosterwake-agent -D headers.txt \
  'https://roosterwake.com/api/agent/download?platform=linux-arm64'
grep -i x-agent-sha256 headers.txt
sha256sum roosterwake-agent
```

The digest `sha256sum` prints must match the one in the header — and, if you want a second
opinion, the one `/api/agent/releases` lists for that platform and version. On Windows the local
half is `Get-FileHash .\roosterwake-agent.msi -Algorithm SHA256`; on macOS, `shasum -a 256`.

## The binaries are unsigned, for now

The Windows builds carry no code signature yet, so SmartScreen shows *"Windows protected your
PC"* with the real option behind **More info**, then **Run anyway**; the macOS build is likewise
unsigned and un-notarised, so Gatekeeper objects to a double-click — run it from a terminal.
These are reputation prompts, not virus detections: they appear for every binary without an
established signing certificate. The affordable signing route requires a company registered in
the United States or Canada, and ours is not; an EV certificate arrives when sales justify it.
Until then the SHA-256 above is the provenance — it is the thing that actually tells our binary
from somebody else's, which is why this page spends a section on it.

## Using it with your own relay

These downloads are not tied to the hosted service. Every install shape takes a relay of your
own: `--relay wss://relay.example.net/ws` on `install` or `enrol`, or the `RELAYURL=` property
on the MSI's `msiexec` line — held to the same transport rule as the dongle, `wss://` anywhere,
plain `ws://` only to loopback and RFC 1918 addresses. [`SELF-HOSTING.md`](SELF-HOSTING.md)
covers what running your own relay takes, and the reference implementation in
[`../relay-reference/`](../relay-reference/) is a real one.
