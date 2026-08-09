# The hosted REST API

This documents the hosted service's public API at `https://app.roosterwake.com/api/v1/`. It is
what the [Home Assistant integration](https://github.com/phodgers/roosterwake-homeassistant)
speaks, and what your own scripts can. If you self-host the relay instead, this file is not
your surface — the reference relay's own endpoints are documented in
[`relay-reference/`](../relay-reference/).

API keys are minted on the dashboard's API keys page and exist on the paid plans. A key is
shown once, at creation, and sent as a bearer token:

```
Authorization: Bearer rw_live_…
```

## Scopes

A key carries the scopes you grant it, and an endpoint refuses a key without its scope (403):

| Scope | Grants |
|---|---|
| `read` | Listing devices and machines, reading history and wake outcomes |
| `wake` | Sending wakes |
| `power` | Sleep, restart and shut down machines through the agent |
| `manage` | Key management |

`power` is deliberately its own scope and never rides `wake`: a leaked wake key is a nuisance
— the worst it can do is switch something on — while a leaked power key can shut a fleet down.
Grant it only to callers that genuinely order power actions, and only plans that carry power
actions can grant it at all.

## Endpoints

| Method and path | Scope | What it answers |
|---|---|---|
| `GET /devices` | read | Your emitters: id, name, online, last seen, board, firmware |
| `GET /machines` | read | Your stored machines: name, MAC, site, whether an agent is connected, whether power is available, presence, last sighting |
| `POST /wake` | wake | Send a wake: `{"mac": "00:00:5E:00:53:01", "confirm": true}` |
| `GET /wake/{id}` | read | One wake's outcome by the id the wake response returned |
| `POST /power` | power | `{"mac": "…", "action": "sleep" \| "restart" \| "shutdown"}` |
| `GET /devices/{id}/history` | read | One emitter's attempt history, `before` cursor pagination |
| `GET /activity` | read | The whole account's history, `before` cursor pagination |

## The contract

**Refusals are 200 with `ok: false`.** A wake that could not happen — no emitter online, the
machine past the plan's allowance, the relay's rate limit — is an *outcome*, answered in the
body with an `err` code and a human `diagnosis`; HTTP errors are reserved for problems with
the request itself (bad key, missing scope, malformed body). On `err: "rate_limited"` the body
carries `retryAfter` (seconds).

**Confirmation is asynchronous.** `POST /wake` with `"confirm": true` returns immediately with
the send result and an `id`; the machine-actually-came-up answer arrives later. Poll
`GET /wake/{id}` until `probeState` is terminal (`up` or `timeout`) — and the poll always
terminates: the service settles abandoned probes server-side, so an outcome exists even if
nobody asks for minutes.

**A power success is an acceptance.** The agent replies before it acts, because the action
tears down the process that would report success — see [`PROTOCOL.md`](../PROTOCOL.md) §4.
The connection dropping is the confirmation.

MAC addresses in the examples above are RFC 7042 documentation addresses.
