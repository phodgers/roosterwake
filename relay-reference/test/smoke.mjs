// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 the Rooster Wake authors.

/**
 * End-to-end conformance tests for the reference relay.
 *
 * Every test boots a real relay on an ephemeral port and drives it over a real WebSocket and
 * real HTTP. Nothing is mocked, because the parts of PROTOCOL.md that are easy to get wrong —
 * the exact keepalive bytes, the challenge sent to unknown device IDs, the 4001 displacement —
 * are exactly the parts a mock would paper over.
 *
 * The numbered assertions in the "§12 minimal conformance" block below map one-to-one onto the
 * seven-point list in PROTOCOL.md §12. If you are writing your own relay, this file is a
 * ready-made acceptance suite: change `startRelay` to launch yours instead.
 *
 *   node --test test/smoke.mjs
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, createHmac } from 'node:crypto';
import WebSocket from 'ws';

import { createRelay, SUBPROTOCOL, WS_PATH } from '../server.js';
import { FakeDevice, silentLogger } from './fake-device.js';

// ── Harness ─────────────────────────────────────────────────────────────────

const DEVICE_ID = 'a1b2c3d4e5f60718';
const OTHER_ID = '00112233445566aa';

/** Tests are silent unless RW_LOG asks otherwise, so a failure is readable. */
const quietLog =
  process.env.RW_LOG && process.env.RW_LOG !== 'silent'
    ? undefined
    : { level: 'silent', error() {}, warn() {}, info() {}, debug() {} };

async function startRelay(overrides = {}) {
  const apiKey = randomBytes(24).toString('hex');
  const token = randomBytes(32).toString('hex');
  const relay = createRelay(
    {
      port: 0,
      host: '127.0.0.1',
      api_key: apiKey,
      devices: { [DEVICE_ID]: token, ...(overrides.devices ?? {}) },
      wake_timeout_ms: overrides.wake_timeout_ms ?? 2_000,
      request_timeout_ms: overrides.request_timeout_ms ?? 2_000,
    },
    { log: quietLog },
  );
  await relay.listen();
  return {
    relay,
    apiKey,
    token,
    deviceId: DEVICE_ID,
    http: `http://127.0.0.1:${relay.port}`,
    ws: `ws://127.0.0.1:${relay.port}${WS_PATH}`,
    async close() {
      await relay.close();
    },
  };
}

/** Boot a relay, run the body, and always tear it down — including after a failed assertion. */
async function withRelay(overrides, body) {
  const ctx = await startRelay(overrides);
  const devices = [];
  ctx.device = (opts = {}) => {
    const d = new FakeDevice({
      relayUrl: ctx.ws,
      deviceId: opts.deviceId ?? ctx.deviceId,
      token: opts.token ?? ctx.token,
      log: silentLogger,
      reconnect: false,
      burstGapMs: 0,
      ...opts,
    });
    devices.push(d);
    return d;
  };
  try {
    await body(ctx);
  } finally {
    for (const d of devices) d.stop();
    await ctx.close();
  }
}

async function api(ctx, method, path, { key = ctx.apiKey, body, headers = {} } = {}) {
  const res = await fetch(`${ctx.http}${path}`, {
    method,
    headers: {
      ...(key === null ? {} : { authorization: `Bearer ${key}` }),
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* Some responses are deliberately not JSON; the raw text is returned as well. */
  }
  return { status: res.status, json, text, headers: res.headers };
}

/**
 * A WebSocket client with no protocol logic at all, so tests can assert on the exact bytes
 * the relay puts on the wire rather than on what a well-behaved client makes of them.
 */
class RawClient {
  constructor(url, protocols = [SUBPROTOCOL]) {
    this.ws = new WebSocket(url, protocols);
    this.queue = [];
    this.waiters = [];
    this.closed = new Promise((resolve) => {
      this.ws.once('close', (code, reason) => resolve({ code, reason: reason.toString('utf8') }));
    });
    this.opened = new Promise((resolve, reject) => {
      this.ws.once('open', () => resolve(this.ws.protocol));
      this.ws.once('error', reject);
    });
    this.ws.on('message', (data, isBinary) => {
      const message = { data, isBinary, text: data.toString('utf8') };
      const waiter = this.waiters.shift();
      if (waiter) waiter(message);
      else this.queue.push(message);
    });
  }

  send(text) {
    this.ws.send(text);
  }

  /** The next frame, or a rejection if the relay stays quiet. */
  next(timeoutMs = 3_000) {
    if (this.queue.length > 0) return Promise.resolve(this.queue.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((w) => w !== push);
        reject(new Error(`no frame from the relay within ${timeoutMs}ms`));
      }, timeoutMs);
      const push = (message) => {
        clearTimeout(timer);
        resolve(message);
      };
      this.waiters.push(push);
    });
  }

  async nextJson(timeoutMs) {
    return JSON.parse((await this.next(timeoutMs)).text);
  }

  close() {
    this.ws.terminate();
  }
}

const proof = (token, tag, id, nc, ns) =>
  createHmac('sha256', Buffer.from(token, 'hex'))
    .update(`${tag}${id}${nc}${ns}`, 'utf8')
    .digest()
    .subarray(0, 16)
    .toString('hex');

/** Drive the device half of §3.2 by hand, so each step can be inspected. */
async function handshake(client, { deviceId, token, nonceC = randomBytes(16).toString('hex') }) {
  await client.opened;
  client.send(
    JSON.stringify({
      t: 'hello',
      v: 1,
      device_id: deviceId,
      nonce_c: nonceC,
      fw: '1.0.0',
      board: 'pico2_w',
      caps: ['wake', 'status'],
      targets: [],
    }),
  );
  const challenge = await client.nextJson();
  const proofC = proof(token, 'rw1:c', deviceId, nonceC, challenge.nonce_s);
  client.send(JSON.stringify({ t: 'auth', proof_c: proofC }));
  const ack = await client.nextJson();
  return { nonceC, challenge, ack };
}

// ── §12 minimal conformance ─────────────────────────────────────────────────

test('§12.1 the relay echoes the roosterwake.v1 subprotocol', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    assert.equal(await client.opened, SUBPROTOCOL);
    client.close();
  });
});

test('§12.1 an upgrade without the subprotocol is refused, not left hanging', async () => {
  await withRelay({}, async (ctx) => {
    const bare = new WebSocket(ctx.ws); // no Sec-WebSocket-Protocol offered
    const err = await new Promise((resolve) => bare.once('error', resolve));
    assert.match(err.message, /400/, 'expected the upgrade to be refused with HTTP 400');
  });
});

test('§12.2 the handshake completes and both proofs verify', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    const { nonceC, challenge, ack } = await handshake(client, {
      deviceId: ctx.deviceId,
      token: ctx.token,
    });

    assert.equal(challenge.t, 'challenge');
    assert.match(challenge.nonce_s, /^[0-9a-f]{32}$/, 'nonce_s must be 32 lower-case hex chars');

    assert.equal(ack.t, 'hello_ack');
    assert.equal(ack.ok, true);
    assert.match(ack.proof_s, /^[0-9a-f]{32}$/);
    assert.equal(
      ack.proof_s,
      proof(ctx.token, 'rw1:s', ctx.deviceId, nonceC, challenge.nonce_s),
      'proof_s must be HMAC-SHA256 over "rw1:s"+device_id+nonce_c+nonce_s, truncated to 16 bytes',
    );
    assert.notEqual(
      ack.proof_s,
      proof(ctx.token, 'rw1:c', ctx.deviceId, nonceC, challenge.nonce_s),
      'the rw1:c and rw1:s domain tags must produce different proofs',
    );
    assert.ok(Math.abs(ack.now - Math.floor(Date.now() / 1000)) < 30, 'now must be a Unix time');
    assert.equal(typeof ack.server, 'string');

    client.close();
  });
});

test('§12.2 every connection gets a fresh nonce_s', async () => {
  await withRelay({}, async (ctx) => {
    const seen = new Set();
    for (let i = 0; i < 5; i++) {
      const client = new RawClient(ctx.ws);
      await client.opened;
      client.send(
        JSON.stringify({ t: 'hello', v: 1, device_id: ctx.deviceId, nonce_c: 'a'.repeat(32) }),
      );
      const challenge = await client.nextJson();
      assert.ok(!seen.has(challenge.nonce_s), 'a reused nonce_s breaks replay protection for all');
      seen.add(challenge.nonce_s);
      client.close();
    }
    assert.equal(seen.size, 5);
  });
});

test('§12.2 an unknown device_id still receives a challenge, then fails at auth', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    const bogusToken = randomBytes(32).toString('hex');
    const { challenge, ack } = await handshake(client, {
      deviceId: OTHER_ID, // never provisioned on this relay
      token: bogusToken,
    });

    // The whole point of §3.3: an unprovisioned device_id must be indistinguishable from a
    // provisioned one with the wrong token, or the relay is an existence oracle for device IDs.
    assert.equal(challenge.t, 'challenge', 'unknown device IDs must still get a challenge');
    assert.match(challenge.nonce_s, /^[0-9a-f]{32}$/);
    assert.deepEqual(ack, { t: 'hello_ack', ok: false, err: 'auth' });

    const { code } = await client.closed;
    assert.equal(code, 1008);
  });
});

test('§12.2 a known device with the wrong token fails identically', async () => {
  await withRelay({}, async (ctx) => {
    const unknown = new RawClient(ctx.ws);
    const unknownResult = await handshake(unknown, {
      deviceId: OTHER_ID,
      token: randomBytes(32).toString('hex'),
    });
    const unknownClose = await unknown.closed;

    const wrongToken = new RawClient(ctx.ws);
    const wrongResult = await handshake(wrongToken, {
      deviceId: ctx.deviceId, // provisioned, but signed with the wrong key
      token: randomBytes(32).toString('hex'),
    });
    const wrongClose = await wrongToken.closed;

    // Same frame sequence, same rejection body, same close code. Nothing distinguishes them.
    assert.deepEqual(unknownResult.ack, wrongResult.ack);
    assert.equal(unknownClose.code, wrongClose.code);
    assert.equal(Object.keys(unknownResult.challenge).join(), 't,nonce_s');
    assert.equal(Object.keys(wrongResult.challenge).join(), 't,nonce_s');
  });
});

test('§12.2 a malformed proof is rejected like a wrong one', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await client.opened;
    client.send(
      JSON.stringify({ t: 'hello', v: 1, device_id: ctx.deviceId, nonce_c: 'b'.repeat(32) }),
    );
    await client.nextJson();
    client.send(JSON.stringify({ t: 'auth', proof_c: 'not hex at all' }));
    assert.deepEqual(await client.nextJson(), { t: 'hello_ack', ok: false, err: 'auth' });
    assert.equal((await client.closed).code, 1008);
  });
});

test('§12.3 {"t":"ping"} is answered with exactly the bytes {"t":"pong"}', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await handshake(client, { deviceId: ctx.deviceId, token: ctx.token });

    client.send('{"t":"ping"}');
    const reply = await client.next();

    assert.equal(reply.isBinary, false, 'the keepalive answer must be a text frame');
    assert.deepEqual(
      [...reply.data],
      [...Buffer.from('{"t":"pong"}', 'utf8')],
      'byte-exact per §9 — no whitespace, no extra fields, nothing reordered',
    );
    assert.equal(reply.data.length, 12);

    // Twice, because a relay that answers the first one from a handshake-shaped code path and
    // then forgets is a real failure mode.
    client.send('{"t":"ping"}');
    assert.equal((await client.next()).text, '{"t":"pong"}');

    client.close();
  });
});

test('§12.4 wake is forwarded, req_id is preserved, and wake_result comes back', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await handshake(client, { deviceId: ctx.deviceId, token: ctx.token });

    const wakePromise = api(ctx, 'POST', '/wake', {
      body: { device_id: ctx.deviceId, mac: 'aa-bb-cc-dd-ee-ff' },
    });

    const wake = await client.nextJson();
    assert.equal(wake.t, 'wake');
    assert.equal(wake.mac, 'AA:BB:CC:DD:EE:FF', '§2: MACs are normalised on output');
    assert.ok(wake.req_id.length >= 1 && wake.req_id.length <= 36, '§2: req_id is 1–36 characters');

    client.send(
      JSON.stringify({
        t: 'wake_result',
        req_id: wake.req_id,
        ok: true,
        sent: 24,
        ifaces: ['255.255.255.255:9', '192.168.1.255:9'],
      }),
    );

    const res = await wakePromise;
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);
    assert.equal(res.json.sent, 24);
    assert.equal(res.json.req_id, wake.req_id, 'the relay must return the device answer verbatim');
    client.close();
  });
});

test('§12.5 unknown frame types and unknown fields are ignored silently', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await client.opened;

    // A hello carrying a field from some future firmware.
    client.send(
      JSON.stringify({
        t: 'hello',
        v: 1,
        device_id: ctx.deviceId,
        nonce_c: 'c'.repeat(32),
        fw: '9.9.9',
        caps: ['wake', 'status', 'teleport'],
        solar_panels: 4,
      }),
    );
    const challenge = await client.nextJson();
    client.send(
      JSON.stringify({
        t: 'auth',
        proof_c: proof(ctx.token, 'rw1:c', ctx.deviceId, 'c'.repeat(32), challenge.nonce_s),
        signed_by: 'the future',
      }),
    );
    assert.equal((await client.nextJson()).ok, true);

    // Frame types that do not exist yet must not close the connection or produce an answer.
    client.send('{"t":"telemetry","watts":0.48}');
    client.send('{"t":"sched_ack","req_id":"x"}');
    client.send('{"t":"probe_result","req_id":"never-asked","state":"up"}');

    // The link is still usable — which is the actual assertion. §10 depends on this.
    client.send('{"t":"ping"}');
    assert.equal((await client.next()).text, '{"t":"pong"}');
    assert.equal(client.ws.readyState, WebSocket.OPEN);

    client.close();
  });
});

test('§12.6 no frame the relay emits exceeds 2048 bytes', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ caps: ['wake', 'status'] });
    const sizes = [];
    device.on('frame', ({ dir, raw }) => {
      if (dir === 'in') sizes.push(Buffer.byteLength(raw, 'utf8'));
    });
    device.start();
    await device.waitForAuth();

    // Push the largest thing this relay will ever send: eight targets with 24-character names,
    // every character a 4-byte astral one, plus a UUID req_id.
    const targets = Array.from({ length: 8 }, (_, i) => ({
      name: '𝔚'.repeat(24),
      mac: `AA:BB:CC:DD:EE:${i.toString(16).padStart(2, '0').toUpperCase()}`,
    }));
    const res = await api(ctx, 'POST', '/config', { body: { device_id: ctx.deviceId, targets } });
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);

    assert.ok(sizes.length >= 2, 'expected to have observed several relay frames');
    assert.ok(
      Math.max(...sizes) <= 2048,
      `largest relay frame was ${Math.max(...sizes)} bytes; §1 caps it at 2048`,
    );
  });
});

test('§12.7 a second connection displaces the first with close code 4001', async () => {
  await withRelay({}, async (ctx) => {
    const targets = [{ name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' }];
    const first = ctx.device({ targets });
    const firstClose = new Promise((resolve) => first.once('close', resolve));
    first.start();
    await first.waitForAuth();

    const before = await api(ctx, 'GET', '/devices');
    assert.equal(before.json.devices[0].online, true);

    const second = ctx.device({ targets });
    second.start();
    await second.waitForAuth();

    const { code, reason } = await firstClose;
    assert.equal(code, 4001, 'the displaced connection must be closed with 4001');
    assert.equal(reason, 'superseded');

    // And the survivor is the new one: it can still be commanded.
    const wake = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    assert.equal(wake.status, 200);
    assert.equal(wake.json.ok, true);
  });
});

// ── Protocol details beyond the conformance list ────────────────────────────

test('a hello offering an unsupported protocol version is closed with 4000', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await client.opened;
    client.send(JSON.stringify({ t: 'hello', v: 2, device_id: ctx.deviceId, nonce_c: '0'.repeat(32) }));
    assert.equal((await client.closed).code, 4000);
  });
});

test('a malformed hello is answered bad_frame and closed', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await client.opened;
    client.send(JSON.stringify({ t: 'hello', v: 1, device_id: 'NOT-A-DEVICE-ID' }));
    assert.deepEqual(await client.nextJson(), { t: 'hello_ack', ok: false, err: 'bad_frame' });
    assert.equal((await client.closed).code, 1008);
  });
});

test('frames that arrive before authentication are not acted on', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await client.opened;
    // A wake_result for a request nobody made, before hello. Must not crash or authenticate.
    client.send('{"t":"wake_result","req_id":"none","ok":true,"sent":24,"ifaces":[]}');
    client.send('{"t":"auth","proof_c":"' + 'a'.repeat(32) + '"}');
    await handshake(client, { deviceId: ctx.deviceId, token: ctx.token });
    client.send('{"t":"ping"}');
    assert.equal((await client.next()).text, '{"t":"pong"}');
    client.close();
  });
});

test('the fake device reports sent and ifaces the way §4 describes', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ ip: '192.168.1.42/24' });
    device.start();
    await device.waitForAuth();

    const res = await api(ctx, 'POST', '/wake', {
      body: { device_id: ctx.deviceId, mac: 'AA:BB:CC:DD:EE:FF', repeat: 3 },
    });
    assert.equal(res.status, 200);
    assert.equal(res.json.ok, true);
    assert.deepEqual(res.json.ifaces, [
      '255.255.255.255:9',
      '192.168.1.255:9',
      '255.255.255.255:7',
      '192.168.1.255:7',
    ]);
    // Four destinations, three bursts, two datagrams each — the `sent: 24` from PROTOCOL.md §4.
    assert.equal(res.json.sent, 24);
  });
});

test('an out-of-range repeat is clamped by the device, not rejected', async () => {
  await withRelay({}, async (ctx) => {
    const client = new RawClient(ctx.ws);
    await handshake(client, { deviceId: ctx.deviceId, token: ctx.token });

    // The relay validates 1–5 at the HTTP boundary, so drive the device directly to prove the
    // §5 clamp. Anything else would only be testing the relay's input validation twice.
    const device = new FakeDevice({
      relayUrl: ctx.ws,
      deviceId: ctx.deviceId,
      token: ctx.token,
      log: silentLogger,
      reconnect: false,
      burstGapMs: 0,
      targets: [{ name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' }],
    });
    const results = [];
    device.on('wake', (r) => results.push(r));
    device.start();
    await device.waitForAuth();
    client.close();

    device.onWake({ t: 'wake', req_id: 'clamp-high', mac: 'AA:BB:CC:DD:EE:FF', repeat: 99 });
    device.onWake({ t: 'wake', req_id: 'clamp-low', mac: 'AA:BB:CC:DD:EE:FF', repeat: 0 });
    assert.deepEqual(
      results.map((r) => r.repeat),
      [5, 1],
    );
    device.stop();
  });
});

test('the device refuses a config_push that carries Wi-Fi credentials', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device();
    device.start();
    await device.waitForAuth();

    // §11: Wi-Fi credentials never leave the device, and a device MUST reject any attempt by a
    // relay to set them. Driven directly, because this relay will never send such a frame.
    const sent = [];
    device.on('frame', ({ dir, frame }) => dir === 'out' && sent.push(frame));
    device.onConfigPush({
      t: 'config_push',
      req_id: 'hostile',
      targets: [],
      ssid: 'Sarahs Wi-Fi',
      psk: 'hunter2',
    });
    const ack = sent.find((f) => f.t === 'config_ack');
    assert.deepEqual(ack, { t: 'config_ack', req_id: 'hostile', ok: false, err: 'bad_frame', targets: 0 });
  });
});

// ── HTTP API ────────────────────────────────────────────────────────────────

test('GET /healthz needs no authentication and counts online devices', async () => {
  await withRelay({}, async (ctx) => {
    const before = await api(ctx, 'GET', '/healthz', { key: null });
    assert.equal(before.status, 200);
    assert.deepEqual(
      { ok: before.json.ok, online: before.json.devices_online, total: before.json.devices_total },
      { ok: true, online: 0, total: 1 },
    );
    assert.equal(typeof before.json.uptime_s, 'number');

    const device = ctx.device();
    device.start();
    await device.waitForAuth();

    const after = await api(ctx, 'GET', '/healthz', { key: null });
    assert.equal(after.json.devices_online, 1);
  });
});

test('a bad, missing or malformed API key is rejected with 401', async () => {
  await withRelay({}, async (ctx) => {
    for (const [label, options] of [
      ['wrong key', { key: 'definitely-not-the-key' }],
      ['no header', { key: null }],
      ['almost right', { key: `${ctx.apiKey}x` }],
      ['prefix of the real key', { key: ctx.apiKey.slice(0, -1) }],
      ['wrong scheme', { key: null, headers: { authorization: `Basic ${ctx.apiKey}` } }],
    ]) {
      const devices = await api(ctx, 'GET', '/devices', options);
      assert.equal(devices.status, 401, `GET /devices with ${label}`);
      assert.equal(devices.json.err, 'unauthorised');
      const wake = await api(ctx, 'POST', '/wake', { ...options, body: { device_id: ctx.deviceId } });
      assert.equal(wake.status, 401, `POST /wake with ${label}`);
    }

    // And the right one still works, so the test is not passing because everything 401s.
    assert.equal((await api(ctx, 'GET', '/devices')).status, 200);
  });
});

test('GET /devices reports state and never leaks a token', async () => {
  await withRelay({}, async (ctx) => {
    const offline = await api(ctx, 'GET', '/devices');
    assert.equal(offline.json.devices.length, 1);
    assert.deepEqual(
      { id: offline.json.devices[0].device_id, online: offline.json.devices[0].online },
      { id: ctx.deviceId, online: false },
    );
    assert.equal(offline.json.devices[0].last_seen, null);

    const device = ctx.device({
      fw: '1.2.3',
      targets: [{ name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' }],
    });
    device.start();
    await device.waitForAuth();

    const online = await api(ctx, 'GET', '/devices');
    const record = online.json.devices[0];
    assert.equal(record.online, true);
    assert.equal(record.fw, '1.2.3');
    assert.equal(record.board, 'pico2_w');
    assert.deepEqual(record.caps, ['wake', 'status']);
    assert.deepEqual(record.targets, [{ name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' }]);
    assert.ok(Date.now() - Date.parse(record.last_seen) < 5_000, 'last_seen must be recent');

    // §11: the token store is secret material. It must not appear anywhere in the API surface.
    assert.equal(online.text.includes(ctx.token), false, 'the device token leaked into /devices');
  });
});

test('POST /wake maps failures to the right status codes', async () => {
  await withRelay({ wake_timeout_ms: 400 }, async (ctx) => {
    // 404: a device_id this relay has never heard of.
    const unknown = await api(ctx, 'POST', '/wake', { body: { device_id: OTHER_ID } });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.json.err, 'unknown_device');

    // 400: not a device_id at all, and a MAC that does not parse.
    assert.equal((await api(ctx, 'POST', '/wake', { body: { device_id: 'nope' } })).status, 400);

    // 503: provisioned, but nothing is connected.
    const offline = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    assert.equal(offline.status, 503);
    assert.equal(offline.json.err, 'offline');

    // 504: connected, but the device never answers. `--simulate silent` exists for exactly this.
    const mute = ctx.device({ simulate: 'silent', targets: [{ name: 'PC', mac: 'AA:BB:CC:DD:EE:FF' }] });
    mute.start();
    await mute.waitForAuth();

    const badMac = await api(ctx, 'POST', '/wake', {
      body: { device_id: ctx.deviceId, mac: 'ZZ:ZZ:ZZ:ZZ:ZZ:ZZ' },
    });
    assert.equal(badMac.status, 400);
    assert.equal(badMac.json.err, 'bad_mac');

    const timedOut = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    assert.equal(timedOut.status, 504);
    assert.equal(timedOut.json.err, 'timeout');
  });
});

test('a device-reported failure is 200 with ok:false, not a 5xx', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({
      simulate: 'no_link',
      targets: [{ name: 'PC', mac: 'AA:BB:CC:DD:EE:FF' }],
    });
    device.start();
    await device.waitForAuth();

    const res = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    // The relay reached the device and the device answered. Collapsing that into a 502 would
    // hide `err` and `sent`, which are the fields that actually diagnose a failed wake.
    assert.equal(res.status, 200);
    assert.deepEqual(
      { ok: res.json.ok, err: res.json.err, sent: res.json.sent },
      { ok: false, err: 'no_link', sent: 0 },
    );
  });
});

test('a wake with no MAC falls through to the first configured target', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({
      targets: [
        { name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' },
        { name: 'NAS', mac: '11:22:33:44:55:66' },
      ],
    });
    const woken = [];
    device.on('wake', (w) => woken.push(w.mac));
    device.start();
    await device.waitForAuth();

    assert.equal((await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } })).status, 200);
    assert.deepEqual(woken, ['AA:BB:CC:DD:EE:FF']);
  });
});

test('a device with no targets answers no_target', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ targets: [] });
    device.start();
    await device.waitForAuth();
    const res = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    assert.equal(res.status, 200);
    assert.equal(res.json.err, 'no_target');
  });
});

test('POST /status round-trips and updates the cached device record', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ ip: '10.0.5.17/16', fw: '1.4.0' });
    device.start();
    await device.waitForAuth();

    const res = await api(ctx, 'POST', '/status', { body: { device_id: ctx.deviceId } });
    assert.equal(res.status, 200);
    assert.equal(res.json.ip, '10.0.5.17');
    assert.equal(res.json.netmask, '255.255.0.0');
    assert.equal(res.json.fw, '1.4.0');
    assert.equal(typeof res.json.rssi, 'number');
    assert.equal(typeof res.json.uptime_s, 'number');

    const listed = (await api(ctx, 'GET', '/devices')).json.devices[0];
    assert.equal(listed.ip, '10.0.5.17');
    assert.equal(listed.rssi, res.json.rssi);
  });
});

test('POST /config pushes targets, and the cached list only moves on a successful ack', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ targets: [{ name: 'Old', mac: '00:00:00:00:00:01' }] });
    device.start();
    await device.waitForAuth();

    const ok = await api(ctx, 'POST', '/config', {
      body: {
        device_id: ctx.deviceId,
        targets: [
          { name: 'Desktop', mac: 'aa-bb-cc-dd-ee-ff' },
          { name: '  NAS  ', mac: '112233445566' },
        ],
      },
    });
    assert.equal(ok.status, 200);
    assert.equal(ok.json.ok, true);
    assert.equal(ok.json.targets, 2);
    assert.deepEqual(device.targets, [
      { name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' },
      { name: 'NAS', mac: '11:22:33:44:55:66' },
    ]);
    assert.deepEqual((await api(ctx, 'GET', '/devices')).json.devices[0].targets, device.targets);

    // §5 caps the list at eight, and the relay refuses before bothering the device.
    const tooMany = await api(ctx, 'POST', '/config', {
      body: {
        device_id: ctx.deviceId,
        targets: Array.from({ length: 9 }, (_, i) => ({ name: `T${i}`, mac: '00:00:00:00:00:00' })),
      },
    });
    assert.equal(tooMany.status, 400);
    assert.equal(tooMany.json.err, 'too_many');

    const badMac = await api(ctx, 'POST', '/config', {
      body: { device_id: ctx.deviceId, targets: [{ name: 'X', mac: 'oops' }] },
    });
    assert.equal(badMac.status, 400);
    assert.equal(badMac.json.err, 'bad_mac');

    // The device still holds what it acked, and so does the relay's cached view.
    assert.equal(device.targets.length, 2);
  });
});

test('the relay never sends a command the device did not advertise', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ caps: ['wake'] }); // no `status`
    device.start();
    await device.waitForAuth();

    const res = await api(ctx, 'POST', '/status', { body: { device_id: ctx.deviceId } });
    assert.equal(res.status, 501, '§4: a relay MUST NOT send a command the device cannot serve');
    assert.equal(res.json.err, 'unsupported');

    // Wake is advertised, so it still goes through.
    assert.equal(
      (await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId, mac: 'AA:BB:CC:DD:EE:FF' } }))
        .status,
      200,
    );
  });
});

test('wake requests are rate limited to 30 a minute per device', async () => {
  await withRelay({}, async (ctx) => {
    const device = ctx.device({ targets: [{ name: 'PC', mac: 'AA:BB:CC:DD:EE:FF' }] });
    device.start();
    await device.waitForAuth();

    const statuses = [];
    for (let i = 0; i < 31; i++) {
      statuses.push((await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } })).status);
    }
    assert.equal(statuses.filter((s) => s === 200).length, 30, '§11: 30 wakes per minute');
    assert.equal(statuses[30], 429);

    const limited = await api(ctx, 'POST', '/wake', { body: { device_id: ctx.deviceId } });
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get('retry-after'), '60');
  });
});

test('unknown routes, bad bodies and the AGPL source offer', async () => {
  await withRelay({}, async (ctx) => {
    assert.equal((await api(ctx, 'GET', '/nope')).status, 404);
    assert.equal((await api(ctx, 'GET', '/ws')).status, 404, 'GET on the WS path is not an upgrade');

    const badJson = await fetch(`${ctx.http}/wake`, {
      method: 'POST',
      headers: { authorization: `Bearer ${ctx.apiKey}`, 'content-type': 'application/json' },
      body: '{ this is not json',
    });
    assert.equal(badJson.status, 400);

    // AGPL §13: a network user is entitled to the source. Answering with a URL is the cheapest
    // way to discharge that, and it means a fork that changes the code has one field to update.
    const source = await api(ctx, 'GET', '/source', { key: null });
    assert.equal(source.status, 200);
    assert.match(source.json.source, /^https?:\/\//);
    assert.equal(source.json.licence, 'AGPL-3.0-or-later');
  });
});

// ── Configuration validation ────────────────────────────────────────────────

test('the relay refuses to start on a config that would fail later', async () => {
  const { normaliseConfig } = await import('../server.js');
  const good = {
    port: 8080,
    api_key: 'x'.repeat(32),
    devices: { [DEVICE_ID]: 'a'.repeat(64) },
  };
  assert.doesNotThrow(() => normaliseConfig(good));

  for (const [why, mutate] of [
    ['short api_key', (c) => (c.api_key = 'tooshort')],
    ['missing api_key', (c) => delete c.api_key],
    ['device_id not 16 hex', (c) => (c.devices = { NOTHEX: 'a'.repeat(64) })],
    ['token not 64 hex', (c) => (c.devices = { [DEVICE_ID]: 'a'.repeat(63) })],
    ['upper-case token', (c) => (c.devices = { [DEVICE_ID]: 'A'.repeat(64) })],
    ['port out of range', (c) => (c.port = 70000)],
    ['devices is an array', (c) => (c.devices = [])],
  ]) {
    const config = structuredClone(good);
    mutate(config);
    assert.throws(() => normaliseConfig(config), /.*/, `expected "${why}" to be rejected`);
  }
});
