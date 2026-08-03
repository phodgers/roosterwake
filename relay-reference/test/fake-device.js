#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 the Rooster Wake authors.

/**
 * Rooster Wake — fake device.
 *
 * A dongle made of software. It speaks the device half of ../../PROTOCOL.md over a real
 * WebSocket: the mutual challenge-response handshake, the 25-second application-level
 * keepalive, wake/status/config_push, backoff and reconnection. The only thing it does not do
 * is put a magic packet on a wire — it reports exactly what it *would* have sent, in the same
 * shape a real dongle reports it.
 *
 * That is enough to develop and test an entire relay with no hardware on the desk, which is
 * why PROTOCOL.md §12 points implementers here.
 *
 * It is also written to be *read*. If you are implementing firmware or a relay in another
 * language, the handshake below is the shortest complete statement of what §3.2 requires.
 *
 * The proof construction is deliberately implemented again here rather than imported from
 * ../server.js. Two independent implementations that agree are evidence the specification is
 * unambiguous; one shared helper used by both sides would agree with itself even if both were
 * wrong, and would test nothing.
 *
 *   node test/fake-device.js \
 *     --relay ws://127.0.0.1:8080/ws \
 *     --device-id a1b2c3d4e5f60718 \
 *     --token <64 hex chars> \
 *     --target Desktop=AA:BB:CC:DD:EE:FF
 */

import { EventEmitter } from 'node:events';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import WebSocket from 'ws';

// ── Protocol constants (PROTOCOL.md §1, §8, §9) ─────────────────────────────

const SUBPROTOCOL = 'roosterwake.v1';
const PROTOCOL_VERSION = 1;

/** §9: literal bytes. Not JSON.stringify of an object — the byte sequence is the contract. */
const PING_FRAME = '{"t":"ping"}';
const PONG_FRAME = '{"t":"pong"}';

/** §9: the device pings every 25 s and gives up on the link after 75 s of total silence. */
const PING_INTERVAL_MS = 25_000;
const LIVENESS_TIMEOUT_MS = 75_000;

/** §1: a relay MUST NOT send more than this; a device rejects a larger frame with 1009. */
const MAX_RELAY_FRAME_BYTES = 2048;

/** §8: exponential backoff from 1 s to 60 s, with full jitter. */
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 60_000;

/** §7: the one close code that means "stop trying". */
const CLOSE_DEPROVISIONED = 4002;

/** §5: config_push replaces the target list wholesale, capped at eight. */
const MAX_TARGETS = 8;

/**
 * Reference firmware sends two identical datagrams to each destination per burst — the second
 * costs nothing and covers a dropped broadcast, which is the single most common way a wake
 * silently fails. `sent` in a wake_result is destinations × repeat × 2, which is where the
 * `sent: 24` in PROTOCOL.md §4 comes from: four destinations, three bursts, two datagrams.
 */
const PACKETS_PER_DESTINATION = 2;

/** Standard Wake-on-LAN destination ports. Sending to both is free and catches more NICs. */
const WOL_PORTS = [9, 7];

// ── Small helpers ───────────────────────────────────────────────────────────

const RE_MAC = /^[0-9a-fA-F]{12}$/;

/** §2: accept any common separator, emit upper-case colon-separated. */
export function normaliseMac(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[:\-.\s]/g, '');
  if (!RE_MAC.test(hex)) return null;
  return (hex.toUpperCase().match(/../g) ?? []).join(':');
}

/**
 * §3.2: HMAC-SHA256 keyed with the raw 32 token bytes — hex-decoded, not the hex text — over
 * the tag, the device_id and both nonces, truncated to the first 16 bytes.
 */
function computeProof(tokenHex, tag, deviceId, nonceC, nonceS) {
  return createHmac('sha256', Buffer.from(tokenHex, 'hex'))
    .update(`${tag}${deviceId}${nonceC}${nonceS}`, 'utf8')
    .digest()
    .subarray(0, 16);
}

/** §8: full jitter. `random(0, backoff)`, not `backoff ± a bit`. */
function jitter(ms) {
  return Math.floor(Math.random() * ms);
}

/**
 * §1: plain ws:// is permitted only for loopback and RFC 1918 addresses. Firmware built for
 * production refuses anything else, and so does this, because a test tool that quietly does
 * the insecure thing teaches the wrong lesson to whoever copies it.
 */
function isLocalHost(host) {
  if (host === 'localhost' || host === '::1' || host === '[::1]') return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!v4) return false;
  const [a, b] = v4.slice(1).map(Number);
  if (a === 127) return true;
  if (a === 10) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

/** Derive the subnet broadcast address for a simulated `a.b.c.d/prefix`. */
function broadcastFor(cidr) {
  const [addr, prefixText] = cidr.split('/');
  const prefix = prefixText === undefined ? 24 : Number(prefixText);
  const octets = addr.split('.').map(Number);
  if (octets.length !== 4 || octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) {
    return null;
  }
  if (!Number.isInteger(prefix) || prefix < 8 || prefix > 30) return null;
  const value = octets.reduce((acc, o) => ((acc << 8) | o) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const broadcast = (value | (~mask >>> 0)) >>> 0;
  const toDotted = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 0xff).join('.');
  return { ip: addr, netmask: toDotted(mask), broadcast: toDotted(broadcast) };
}

// ── The device ──────────────────────────────────────────────────────────────

/**
 * Events: `connecting`, `open`, `authenticated`, `frame` ({dir, frame, raw}), `wake` (result),
 * `close` ({code, reason}), `error` (Error), `giveup` (reason).
 */
export class FakeDevice extends EventEmitter {
  constructor(opts) {
    super();
    if (!/^[0-9a-f]{16}$/.test(opts.deviceId ?? '')) {
      throw new Error('device-id must be 16 lower-case hex characters');
    }
    if (!/^[0-9a-f]{64}$/.test(opts.token ?? '')) {
      throw new Error('token must be 64 lower-case hex characters');
    }

    this.relayUrl = opts.relayUrl ?? 'ws://127.0.0.1:8080/ws';
    this.deviceId = opts.deviceId;
    this.token = opts.token;
    this.fw = opts.fw ?? '1.0.0';
    this.board = opts.board ?? 'pico2_w';
    this.caps = opts.caps ?? ['wake', 'status'];
    this.targets = opts.targets ?? [];
    this.simulate = opts.simulate ?? 'ok';
    this.burstGapMs = opts.burstGapMs ?? 100;
    this.reconnect = opts.reconnect !== false;
    this.insecureTls = opts.insecureTls === true;
    this.allowPlaintext = opts.allowPlaintext === true;
    this.log = opts.log ?? defaultLogger(opts.quiet === true);

    const net = broadcastFor(opts.ip ?? '192.168.1.42/24');
    if (!net) throw new Error('--ip must look like 192.168.1.42/24');
    this.net = net;

    this.ws = null;
    this.state = 'idle';
    this.backoffMs = BACKOFF_MIN_MS;
    this.startedAt = Date.now();
    this.bootTime = Date.now();
    this.rssi = -52;
    this.stopped = false;
    this.pingTimer = null;
    this.livenessTimer = null;
    this.retryTimer = null;
    this.nonceC = null;
    this.nonceS = null;

    const url = new URL(this.relayUrl);
    if (url.protocol === 'ws:' && !isLocalHost(url.hostname) && !this.allowPlaintext) {
      throw new Error(
        `refusing plaintext ws:// to ${url.hostname} — PROTOCOL.md §1 permits it only for ` +
          'loopback and RFC 1918 addresses. Use wss://, or pass --allow-plaintext if you know ' +
          'exactly what you are doing.',
      );
    }
    if (this.insecureTls && url.protocol === 'wss:') {
      this.log.warn(
        'TLS certificate verification is DISABLED. A real dongle flashes its error LED ' +
          'continuously in this mode, on purpose. Do not leave it on.',
      );
    }
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  start() {
    this.stopped = false;
    this.connect();
    return this;
  }

  stop(code = 1000, reason = 'shutdown') {
    this.stopped = true;
    clearTimeout(this.retryTimer);
    this.clearTimers();
    if (this.ws && this.ws.readyState === WebSocket.OPEN) this.ws.close(code, reason);
    else if (this.ws) this.ws.terminate();
  }

  /** Resolves once the link is authenticated, or rejects if the device gives up first. */
  waitForAuth(timeoutMs = 10_000) {
    return new Promise((resolve, reject) => {
      if (this.state === 'open') {
        resolve();
        return;
      }
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`not authenticated within ${timeoutMs}ms`));
      }, timeoutMs);
      const onAuth = () => {
        cleanup();
        resolve();
      };
      const onGiveup = (why) => {
        cleanup();
        reject(new Error(`device gave up: ${why}`));
      };
      const cleanup = () => {
        clearTimeout(timer);
        this.off('authenticated', onAuth);
        this.off('giveup', onGiveup);
      };
      this.once('authenticated', onAuth);
      this.once('giveup', onGiveup);
    });
  }

  connect() {
    if (this.stopped) return;
    this.state = 'connecting';
    this.nonceC = randomBytes(16).toString('hex');
    this.nonceS = null;
    this.log.info(`connecting to ${this.relayUrl}`);
    this.emit('connecting', this.relayUrl);

    const options = {};
    if (this.insecureTls) options.rejectUnauthorized = false;
    const ws = new WebSocket(this.relayUrl, [SUBPROTOCOL], options);
    this.ws = ws;

    ws.on('open', () => {
      // §1: a relay that understands this protocol MUST echo the subprotocol. One that does
      // not is a captive portal, a misconfigured proxy, or somebody's Home Assistant — and
      // this check is the difference between a clear error and a socket that hangs forever.
      if (ws.protocol !== SUBPROTOCOL) {
        this.log.error(
          `relay did not echo the ${SUBPROTOCOL} subprotocol — this is not a Rooster Wake relay`,
        );
        ws.close(1002, 'subprotocol');
        return;
      }
      this.state = 'hello';
      this.log.info(`connected (subprotocol ${ws.protocol})`);
      this.emit('open');
      this.armLiveness();
      this.sendFrame({
        t: 'hello',
        v: PROTOCOL_VERSION,
        device_id: this.deviceId,
        nonce_c: this.nonceC,
        fw: this.fw,
        board: this.board,
        caps: this.caps,
        targets: this.targets,
      });
    });

    ws.on('message', (data, isBinary) => this.onMessage(data, isBinary));
    ws.on('ping', () => this.log.debug('<- [ws control ping]  (ws answers it for us)'));
    ws.on('error', (err) => {
      this.log.error(`socket error: ${err.message}`);
      this.emit('error', err);
    });
    ws.on('close', (code, reasonBuf) => {
      const reason = reasonBuf?.toString('utf8') ?? '';
      this.clearTimers();
      const wasOpen = this.state === 'open';
      this.state = 'closed';
      this.log.info(`closed: ${code}${reason ? ` (${reason})` : ''}`);
      this.emit('close', { code, reason });

      // §7: 4002 means deprovisioned or revoked. Everything else is retried.
      if (code === CLOSE_DEPROVISIONED) {
        this.log.error('relay says this device is deprovisioned — not retrying');
        this.emit('giveup', 'deprovisioned');
        this.stopped = true;
        return;
      }
      if (this.stopped || !this.reconnect) {
        if (!this.stopped) this.emit('giveup', `closed ${code} and --no-reconnect is set`);
        return;
      }

      // §8: the backoff resets only after a connection completed authentication. A relay that
      // accepts sockets and rejects them at auth must not be hammered at one-second intervals.
      if (!wasOpen) {
        this.backoffMs = Math.min(this.backoffMs * 2, BACKOFF_MAX_MS);
      }
      const delay = jitter(this.backoffMs);
      this.log.info(`reconnecting in ${delay}ms (backoff ceiling ${this.backoffMs}ms)`);
      this.retryTimer = setTimeout(() => this.connect(), delay);
    });
  }

  clearTimers() {
    clearInterval(this.pingTimer);
    clearTimeout(this.livenessTimer);
    this.pingTimer = null;
    this.livenessTimer = null;
  }

  /** §9: no frame of any kind for 75 seconds means the link is dead. Close and reconnect. */
  armLiveness() {
    clearTimeout(this.livenessTimer);
    this.livenessTimer = setTimeout(() => {
      this.log.warn(`no frame from the relay for ${LIVENESS_TIMEOUT_MS / 1000}s — link is dead`);
      if (this.ws) this.ws.terminate();
    }, LIVENESS_TIMEOUT_MS);
    if (typeof this.livenessTimer.unref === 'function') this.livenessTimer.unref();
  }

  // ── Sending ───────────────────────────────────────────────────────────────

  sendFrame(frame) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    const json = JSON.stringify(frame);
    this.log.frame('->', json);
    this.emit('frame', { dir: 'out', frame, raw: json });
    this.ws.send(json);
    return true;
  }

  sendRaw(text) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return false;
    this.log.frame('->', text);
    this.emit('frame', { dir: 'out', frame: JSON.parse(text), raw: text });
    this.ws.send(text);
    return true;
  }

  // ── Receiving ─────────────────────────────────────────────────────────────

  onMessage(data, isBinary) {
    this.armLiveness();

    if (isBinary) {
      this.log.error('relay sent a binary frame; PROTOCOL.md §1 says text only');
      this.ws.close(1008, 'text frames only');
      return;
    }

    // §1: a device MUST reject a frame larger than 2048 bytes with close code 1009. Measured
    // in bytes, not characters — a relay could get under 2048 characters of UTF-8 and still be
    // over the limit that matters to a device with 520 KB of RAM.
    if (data.length > MAX_RELAY_FRAME_BYTES) {
      this.log.error(`relay frame is ${data.length} bytes, over the ${MAX_RELAY_FRAME_BYTES} limit`);
      this.ws.close(1009, 'frame too large');
      return;
    }

    const text = data.toString('utf8');
    this.log.frame('<-', text);

    // §9: the relay MAY send its own ping. Match the exact bytes and answer the exact bytes.
    if (text === PING_FRAME) {
      this.emit('frame', { dir: 'in', frame: { t: 'ping' }, raw: text });
      this.sendRaw(PONG_FRAME);
      return;
    }

    let frame;
    try {
      frame = JSON.parse(text);
    } catch {
      this.log.warn('relay sent unparseable JSON; ignoring the frame');
      return;
    }
    if (!frame || typeof frame !== 'object' || Array.isArray(frame)) return;
    if (typeof frame.t !== 'string') return;
    this.emit('frame', { dir: 'in', frame, raw: text });

    switch (frame.t) {
      case 'challenge':
        this.onChallenge(frame);
        return;
      case 'hello_ack':
        this.onHelloAck(frame);
        return;
      case 'pong':
        return; // Our keepalive came back. armLiveness() above already did the useful part.
      case 'wake':
        if (this.state === 'open') this.onWake(frame);
        return;
      case 'status':
        if (this.state === 'open') this.onStatus(frame);
        return;
      case 'config_push':
        if (this.state === 'open') this.onConfigPush(frame);
        return;
      default:
        // §2 and §10: unknown `t` values are ignored silently. Not an error, not a close —
        // this is exactly what makes it safe for us to add frame types inside v1.
        this.log.debug(`ignoring unknown frame type "${frame.t}"`);
        return;
    }
  }

  onChallenge(frame) {
    if (this.state !== 'hello') return;
    if (!/^[0-9a-f]{32}$/.test(frame.nonce_s ?? '')) {
      this.log.error('challenge carried a malformed nonce_s');
      this.ws.close(1008, 'bad challenge');
      return;
    }
    this.nonceS = frame.nonce_s;
    this.state = 'auth';
    this.sendFrame({
      t: 'auth',
      proof_c: computeProof(
        this.token,
        'rw1:c',
        this.deviceId,
        this.nonceC,
        this.nonceS,
      ).toString('hex'),
    });
  }

  onHelloAck(frame) {
    if (this.state !== 'auth') return;

    if (frame.ok !== true) {
      // The relay will close with 1008 immediately after this. Say something useful first,
      // because "auth" here almost always means the token in flash and the token in the
      // relay's config.json do not match.
      this.log.error(`relay rejected authentication: ${frame.err ?? 'unspecified'}`);
      this.emit('auth_failed', frame.err ?? 'unspecified');
      return;
    }

    const expected = computeProof(this.token, 'rw1:s', this.deviceId, this.nonceC, this.nonceS);
    const offered = /^[0-9a-f]{32}$/.test(frame.proof_s ?? '')
      ? Buffer.from(frame.proof_s, 'hex')
      : Buffer.alloc(16);

    // §3.3: if the device cannot verify proof_s it MUST close immediately with 1008, MUST NOT
    // send any further frames, and MUST back off before retrying. This is the check that stops
    // a device from talking to a relay that does not actually hold its token.
    if (!timingSafeEqual(expected, offered)) {
      this.log.error(
        'relay failed to prove it holds this device token — it does not know the token, ' +
          'or something is sitting in the middle. Closing.',
      );
      this.state = 'closed';
      this.ws.close(1008, 'bad proof_s');
      this.emit('auth_failed', 'proof_s');
      return;
    }

    this.state = 'open';
    this.backoffMs = BACKOFF_MIN_MS; // §8: reset only now, after a *completed* authentication.

    if (typeof frame.now === 'number') {
      // §5: `now` is a sanity check on SNTP, never a substitute for it. Reporting the skew is
      // how you find the dongle whose clock is a year out and whose TLS therefore never works.
      const skew = Math.abs(frame.now - Math.floor(Date.now() / 1000));
      if (skew > 60) this.log.warn(`relay clock differs from ours by ${skew}s`);
    }

    this.log.info(`authenticated with ${frame.server ?? 'relay'} — link is trusted`);
    this.emit('authenticated', frame);

    // §9: the device-initiated keepalive. This is the direction that matters: the device is
    // behind NAT, and it is the device's idle connection that a home router silently drops.
    clearInterval(this.pingTimer);
    this.pingTimer = setInterval(() => this.sendRaw(PING_FRAME), PING_INTERVAL_MS);
    if (typeof this.pingTimer.unref === 'function') this.pingTimer.unref();
  }

  // ── Commands ──────────────────────────────────────────────────────────────

  onWake(frame) {
    if (typeof frame.req_id !== 'string') return;

    if (this.simulate === 'silent') {
      this.log.warn(`--simulate silent: swallowing wake ${frame.req_id} without replying`);
      return;
    }

    const reply = (body) => this.sendFrame({ t: 'wake_result', req_id: frame.req_id, ...body });

    let mac;
    if (frame.mac === undefined || frame.mac === null) {
      // §5: with no MAC, wake the first configured target.
      if (this.targets.length === 0) {
        this.log.warn('wake with no MAC and no configured targets');
        reply({ ok: false, err: 'no_target', sent: 0, ifaces: [] });
        return;
      }
      mac = this.targets[0].mac;
    } else {
      mac = normaliseMac(frame.mac);
      if (!mac) {
        this.log.warn(`wake carried an unparseable MAC: ${JSON.stringify(frame.mac)}`);
        reply({ ok: false, err: 'bad_mac', sent: 0, ifaces: [] });
        return;
      }
    }

    if (this.simulate === 'no_link' || this.simulate === 'send_failed') {
      this.log.warn(`--simulate ${this.simulate}: failing wake ${frame.req_id}`);
      reply({ ok: false, err: this.simulate, sent: 0, ifaces: [] });
      return;
    }

    // §5: repeat is 1–5 with a default of 3, and devices MUST clamp rather than reject.
    const requested = typeof frame.repeat === 'number' ? Math.trunc(frame.repeat) : 3;
    const repeat = Math.min(5, Math.max(1, Number.isFinite(requested) ? requested : 3));
    if (requested !== repeat) this.log.debug(`clamped repeat ${frame.repeat} to ${repeat}`);

    const ifaces = [];
    for (const port of WOL_PORTS) {
      ifaces.push(`255.255.255.255:${port}`);
      ifaces.push(`${this.net.broadcast}:${port}`);
    }
    const sent = ifaces.length * repeat * PACKETS_PER_DESTINATION;

    // Real bursts are spaced out; a NIC that missed the first one gets another chance a
    // moment later. Simulating the delay keeps timeout handling in relays honest.
    const delay = (repeat - 1) * this.burstGapMs;
    this.log.info(`waking ${mac}: ${repeat} burst(s) to ${ifaces.length} destination(s)`);
    const finish = () => {
      if (this.state !== 'open') return;
      // §4: `sent` and `ifaces` carry most of the diagnostic value in this protocol. A wake
      // that "worked" but went to 192.168.1.255 when the PC lives on 192.168.4.0/24 is
      // visible here and nowhere else.
      reply({ ok: true, sent, ifaces });
      this.emit('wake', { mac, repeat, sent, ifaces });
    };
    if (delay > 0) {
      const t = setTimeout(finish, delay);
      if (typeof t.unref === 'function') t.unref();
    } else {
      finish();
    }
  }

  onStatus(frame) {
    if (typeof frame.req_id !== 'string') return;
    // Drift the RSSI a little each time. A constant value looks like a stub, and a dashboard
    // that never changes is one nobody checks.
    this.rssi = Math.max(-90, Math.min(-30, this.rssi + Math.round(Math.random() * 6 - 3)));
    this.sendFrame({
      t: 'status_result',
      req_id: frame.req_id,
      rssi: this.rssi,
      uptime_s: Math.floor((Date.now() - this.bootTime) / 1000),
      ip: this.net.ip,
      netmask: this.net.netmask,
      fw: this.fw,
      reset_reason: 'power_on',
      targets: this.targets,
    });
  }

  onConfigPush(frame) {
    if (typeof frame.req_id !== 'string') return;
    const reply = (body) => this.sendFrame({ t: 'config_ack', req_id: frame.req_id, ...body });

    // §5 and §11: relays MUST NOT push Wi-Fi credentials or a relay URL, and a device MUST
    // reject any attempt. Wi-Fi passwords are entered locally and stay in flash — that is the
    // property that makes compromising a relay, ours or anyone's, not yield anyone's PSK.
    for (const forbidden of ['ssid', 'psk', 'wifi_auth', 'relay_url']) {
      if (frame[forbidden] !== undefined) {
        this.log.error(`relay tried to push "${forbidden}" — refusing (PROTOCOL.md §11)`);
        reply({ ok: false, err: 'bad_frame', targets: this.targets.length });
        return;
      }
    }

    if (!Array.isArray(frame.targets)) {
      reply({ ok: false, err: 'bad_frame', targets: this.targets.length });
      return;
    }
    if (frame.targets.length > MAX_TARGETS) {
      this.log.warn(`config_push carried ${frame.targets.length} targets; the limit is ${MAX_TARGETS}`);
      reply({ ok: false, err: 'too_many', targets: this.targets.length });
      return;
    }

    const accepted = [];
    for (const t of frame.targets) {
      const name = typeof t?.name === 'string' ? t.name.trim() : '';
      const mac = normaliseMac(t?.mac);
      if (name.length < 1 || [...name].length > 24) {
        reply({ ok: false, err: 'bad_frame', targets: this.targets.length });
        return;
      }
      if (!mac) {
        reply({ ok: false, err: 'bad_mac', targets: this.targets.length });
        return;
      }
      accepted.push({ name, mac });
    }

    // §5: wholesale replacement, not a merge. A real device writes this to flash here.
    this.targets = accepted;
    this.log.info(
      `stored ${accepted.length} target(s): ${accepted.map((t) => `${t.name}=${t.mac}`).join(', ') || '(none)'}`,
    );
    reply({ ok: true, targets: accepted.length });
    this.emit('config', accepted);
  }
}

// ── Logging ─────────────────────────────────────────────────────────────────

/**
 * Every frame in both directions, because that is the whole point of this tool. When a relay
 * and a device disagree, the transcript is the argument, and you should not have to add a
 * console.log to see it.
 */
function defaultLogger(quiet) {
  const useColour = process.stdout.isTTY && !process.env.NO_COLOR;
  const dim = (s) => (useColour ? `\u001b[2m${s}\u001b[0m` : s);
  const cyan = (s) => (useColour ? `\u001b[36m${s}\u001b[0m` : s);
  const yellow = (s) => (useColour ? `\u001b[33m${s}\u001b[0m` : s);
  const red = (s) => (useColour ? `\u001b[31m${s}\u001b[0m` : s);
  const stamp = () => dim(new Date().toISOString().slice(11, 23));
  const debugOn = process.env.RW_LOG === 'debug';
  const write = (stream, text) => {
    if (quiet) return;
    stream.write(`${text}\n`);
  };
  return {
    frame: (dir, json) => write(process.stdout, `${stamp()} ${cyan(dir)} ${json}`),
    debug: (m) => debugOn && write(process.stdout, `${stamp()} ${dim(`. ${m}`)}`),
    info: (m) => write(process.stdout, `${stamp()} ${dim('.')} ${m}`),
    warn: (m) => write(process.stderr, `${stamp()} ${yellow('!')} ${m}`),
    error: (m) => write(process.stderr, `${stamp()} ${red('x')} ${m}`),
  };
}

/** A logger that says nothing. Handy for tests and for importing this module as a library. */
export const silentLogger = {
  frame: () => {},
  debug: () => {},
  info: () => {},
  warn: () => {},
  error: () => {},
};

// ── CLI ─────────────────────────────────────────────────────────────────────

const USAGE = `remotewake fake device — speaks PROTOCOL.md with no hardware

  node test/fake-device.js --device-id <hex16> --token <hex64> [options]

Required
  --device-id <hex>      16 lower-case hex characters
  --token <hex>          64 lower-case hex characters

Options
  --relay <url>          ws:// or wss:// endpoint  (default ws://127.0.0.1:8080/ws)
  --target <name=mac>    add a target; repeatable, up to 8
  --ip <cidr>            simulated LAN address     (default 192.168.1.42/24)
  --fw <version>         reported firmware version (default 1.0.0)
  --board <name>         reported board            (default pico2_w)
  --caps <a,b,c>         advertised capabilities   (default wake,status)
  --simulate <mode>      ok | no_link | send_failed | silent   (default ok)
  --burst-gap-ms <n>     delay between wake bursts (default 100)
  --no-reconnect         exit after the first close instead of backing off
  --allow-plaintext      permit ws:// to a public address (PROTOCOL.md §1 forbids it)
  --insecure-tls         skip certificate verification for wss:// (homelab self-signed)
  --quiet                no output
  -h, --help             this message

Environment
  RW_LOG=debug           also log frames this tool decides to ignore

Examples
  # Against a relay running on this machine
  node test/fake-device.js --device-id a1b2c3d4e5f60718 --token $TOKEN \\
    --target Desktop=AA:BB:CC:DD:EE:FF --target NAS=11:22:33:44:55:66

  # Prove your relay's 504 path works
  node test/fake-device.js --device-id a1b2c3d4e5f60718 --token $TOKEN --simulate silent
`;

export function parseArgs(argv) {
  const opts = { targets: [] };
  const need = (i, flag) => {
    if (i >= argv.length) throw new Error(`${flag} needs a value`);
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--relay':
        opts.relayUrl = need(++i, arg);
        break;
      case '--device-id':
        opts.deviceId = need(++i, arg);
        break;
      case '--token':
        opts.token = need(++i, arg);
        break;
      case '--target': {
        const spec = need(++i, arg);
        const split = spec.lastIndexOf('=');
        if (split < 1) throw new Error(`--target wants name=MAC, got "${spec}"`);
        const name = spec.slice(0, split).trim();
        const mac = normaliseMac(spec.slice(split + 1));
        if (!mac) throw new Error(`--target "${spec}" does not end in a MAC address`);
        if ([...name].length < 1 || [...name].length > 24) {
          throw new Error(`--target name must be 1–24 characters, got "${name}"`);
        }
        opts.targets.push({ name, mac });
        break;
      }
      case '--ip':
        opts.ip = need(++i, arg);
        break;
      case '--fw':
        opts.fw = need(++i, arg);
        break;
      case '--board':
        opts.board = need(++i, arg);
        break;
      case '--caps':
        opts.caps = need(++i, arg)
          .split(',')
          .map((c) => c.trim())
          .filter(Boolean);
        break;
      case '--simulate': {
        const mode = need(++i, arg);
        if (!['ok', 'no_link', 'send_failed', 'silent'].includes(mode)) {
          throw new Error(`--simulate must be ok, no_link, send_failed or silent, got "${mode}"`);
        }
        opts.simulate = mode;
        break;
      }
      case '--burst-gap-ms': {
        const n = Number(need(++i, arg));
        if (!Number.isInteger(n) || n < 0 || n > 5000) {
          throw new Error('--burst-gap-ms must be an integer between 0 and 5000');
        }
        opts.burstGapMs = n;
        break;
      }
      case '--no-reconnect':
        opts.reconnect = false;
        break;
      case '--allow-plaintext':
        opts.allowPlaintext = true;
        break;
      case '--insecure-tls':
        opts.insecureTls = true;
        break;
      case '--quiet':
        opts.quiet = true;
        break;
      case '-h':
      case '--help':
        opts.help = true;
        break;
      default:
        throw new Error(`unknown argument "${arg}" (try --help)`);
    }
  }
  if (!opts.help) {
    if (!opts.deviceId) throw new Error('--device-id is required');
    if (!opts.token) throw new Error('--token is required');
    if (opts.targets.length > MAX_TARGETS) {
      throw new Error(`at most ${MAX_TARGETS} targets (got ${opts.targets.length})`);
    }
  }
  return opts;
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n\n${USAGE}`);
    process.exit(2);
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }

  let device;
  try {
    device = new FakeDevice(opts);
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }

  device.on('giveup', () => process.exit(1));
  device.start();

  const bye = () => {
    device.stop();
    setTimeout(() => process.exit(0), 200).unref();
  };
  process.on('SIGINT', bye);
  process.on('SIGTERM', bye);
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) main();
