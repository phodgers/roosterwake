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
| `GET /me` | any | What the presented key is: name, scopes, device binding, and the account and plan behind it. Any valid key may ask — it is the smoke test |
| `GET /devices` | read | Your emitters: id, name, online, **entitled** (whether the plan covers the device — an over-quota emitter can be online yet refused by `/wake`), last seen, board, firmware |
| `GET /machines` | read | Your stored machines: name, MAC, site, whether an agent is connected, whether power is available, presence, last sighting |
| `POST /wake` | wake | Send a wake: `{"mac": "00:00:5E:00:53:01", "confirm": true}` |
| `GET /wake/{id}` | read | One wake's outcome by the id the wake response returned |
| `POST /power` | power | `{"mac": "…", "action": "sleep" \| "restart" \| "shutdown"}` |
| `GET /devices/{id}/history` | read | One emitter's attempt history, `before` cursor pagination |
| `GET /activity` | read | The whole account's history, `before` cursor pagination; `?format=csv` downloads it as a file (Pro) |

## Audit export

`GET /activity` answers the account's full event history — every wake and power command,
whoever asked for it and whatever carried it. Both formats page the same rows with the same
`limit` and `before` parameters; the JSON shape is available to every key with `read`, and
`?format=csv` — a stable, documented, SIEM-ready file a compliance pipeline can ingest without
a human in the loop — is a Pro feature. A non-Pro key asking for CSV is refused with
`402 tier_limit`; any `format` other than `csv` or absent is refused with `400 bad_format`.

### The JSON row

Each entry in `activity` carries:

| Field | Meaning |
|---|---|
| `id` | The row's id — also the `before` cursor value |
| `at` | When, as Unix seconds |
| `deviceId` | The emitter that carried it, or `null` when none did (an Echo wake, a refused command) |
| `targetName` | The machine's name as it was saved when the event happened |
| `targetMac` | The machine's MAC |
| `requestedBy` | Who asked — `null` for a schedule, which has nobody to name |
| `source` | Which surface asked: the dashboard, the API, voice, a schedule, a wake link |
| `via` | What carried the packet: a dongle, an agent, or the user's own Echo |
| `linkLabel` | Which wake link, when `source` is `link`; otherwise `null` |
| `action` | `wake`, `sleep`, `restart` or `shutdown` |
| `ok` | Whether it worked |
| `err` | The machine-readable failure code when it did not |
| `sent` | How many magic packets went out |
| `ifaces` | The broadcast destinations they went to |
| `latencyMs` | Round trip to the emitter, milliseconds |
| `probeState` | The confirmation outcome (`up` or `timeout`), `null` when confirmation was not asked for or not settled |
| `probeMs` | How long confirmation took, milliseconds |
| `connectUrl` | The machine's connect link, on confirmed-up rows only |
| `diagnosis` | The same plain-English explanation the dashboard shows, recomputed on read |

### The CSV columns

The CSV flattens the same rows into these columns, in this order:

| Column | Meaning |
|---|---|
| `at_utc` | When, ISO 8601 UTC |
| `action` | `wake`, `sleep`, `restart` or `shutdown` |
| `machine` | The machine's name as it was saved when the event happened |
| `mac` | The machine's MAC |
| `requested_by` | Who asked; empty for a schedule, `link: <label>` for a wake link |
| `source` | Which surface asked for it |
| `via` | What carried the packet |
| `ok` | `yes` or `no` |
| `error` | The machine-readable failure code when `ok` is `no` |
| `packets_sent` | How many magic packets went out |
| `destinations` | The broadcast addresses they went to, space separated |
| `delivered_by_device` | The emitter's device id; empty when no device carried it |
| `latency_ms` | Round trip to the emitter, milliseconds |
| `confirmation` | The confirmation outcome (`up` or `timeout`); empty when not asked for |

`diagnosis` is deliberately not a column: it is prose that improves over time, and exporting it
would make two exports of the same rows differ. The columns are the facts.

The schema is stable and additive: existing columns and fields keep their names and meanings,
and anything new is appended, so an ingest pipeline written against this table keeps working.

### Paging

Both formats default to 50 rows and cap at 200. JSON carries the next page's cursor in the body
as `nextBefore` (`null` at the end). A CSV body cannot carry a cursor, so the CSV response
carries it as an `X-Next-Before` header instead, present exactly when another page exists —
pass its value back as `?before=` to fetch older rows.

### Retention

How far back the history goes is the plan's retention window: Pro keeps twelve months, Plus
keeps 30 days. The numbers mirror the plan matrix (`shared/tiers.js` in the hosted service),
and rows past the window are deleted nightly — a page that comes back short is the policy
speaking, not a gap.

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
