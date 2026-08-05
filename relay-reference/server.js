#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 the Rooster Wake authors.

/**
 * Rooster Wake — reference relay.
 *
 * A complete, single-tenant implementation of the dongle↔relay protocol specified in
 * ../PROTOCOL.md. It holds one WebSocket per device and exposes a small HTTP API so that
 * something else — a script, Home Assistant, a shortcut on your phone — can ask a device to
 * broadcast a magic packet.
 *
 * Where this file and PROTOCOL.md disagree, the document wins and this file is the bug.
 *
 * Deliberate design choices, so you are not left guessing why:
 *
 *   - One file, one dependency (`ws`). You should be able to read the whole relay in a sitting
 *     and audit what it does with your device tokens. A relay that a homelabber cannot read is
 *     a relay they have to trust, and the point of this repository is that they do not have to.
 *
 *   - State is in memory and dies with the process. Devices reconnect with backoff (§8), so a
 *     restart costs seconds, and there is nothing here worth persisting except the config file
 *     you already wrote by hand.
 *
 *   - Single-tenant on purpose. There are no accounts, no sessions and no dashboard; there is
 *     one API key that can drive every device in config.json. See README.md for why.
 */

import { createServer, STATUS_CODES } from 'node:http';
import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { WebSocketServer } from 'ws';

// ── Protocol constants (PROTOCOL.md §1, §2, §9) ─────────────────────────────

/**
 * §1: the subprotocol token names the protocol *family*, not the major version, and it stays
 * `roosterwake.v1` across major versions on purpose. It is the only thing either side can check
 * before a frame has been sent, and the question it answers is "is there a Rooster Wake relay
 * at this URL at all" — a captive portal, a misrouted proxy and somebody's Home Assistant all
 * fail it. Version negotiation is `hello.v` plus close code 4000 (§10), which is the only
 * mechanism that can tell "an older relay" apart from "not a relay of ours".
 */
export const SUBPROTOCOL = 'roosterwake.v1';
export const WS_PATH = '/ws';
/** §10: the major version this relay speaks. Any other `v` in a hello is closed with 4000. */
export const PROTOCOL_VERSION = 2;

/**
 * §1: no frame in either direction may exceed this, and a receiver MUST reject a larger one
 * with close code 1009. Hard contract, not a suggestion — devices are memory-constrained and
 * will close rather than truncate. One symmetric bound rather than two, because two numbers
 * that must stay equal are two numbers that eventually do not, and it lets both sides size a
 * single receive buffer.
 */
const MAX_FRAME_BYTES = 2048;

/**
 * §9: the keepalive frames are specified literally, byte for byte, because serverless
 * WebSocket runtimes match on the exact bytes to answer without waking the object. We send the
 * string constant rather than JSON.stringify() of an object so that no future refactor can
 * quietly introduce a space or an extra field.
 */
const PONG_FRAME = '{"t":"pong"}';
const PING_FRAME = '{"t":"ping"}';

/** §9: relays SHOULD time out at 90 s, biased longer than the device's 75 s so it reconnects. */
const IDLE_TIMEOUT_MS = 90_000;
/** §9: "the reference relay uses [control-frame pings]" — so it must actually send them. */
const CONTROL_PING_INTERVAL_MS = 30_000;
/** Absolute budget for hello→auth. Not reset by traffic; an unauthenticated socket is not free. */
const HANDSHAKE_TIMEOUT_MS = 10_000;

/** §11: reference rate limit. Far above legitimate use, low enough to stop a LAN being flooded. */
const WAKE_RATE_LIMIT = 30;
const WAKE_RATE_WINDOW_MS = 60_000;

const SERVER_ID = 'remotewake-relay-reference/1.0.0';
const DEFAULT_SOURCE_URL = 'https://github.com/phodgers/roosterwake';

/** Defaults for the config knobs an operator may override. */
const DEFAULT_PORT = 8080;
const DEFAULT_WAKE_TIMEOUT_MS = 5_000;
const DEFAULT_REQUEST_TIMEOUT_MS = 10_000;

/** Cap on an HTTP request body. Nothing this API accepts comes close. */
const MAX_HTTP_BODY_BYTES = 64 * 1024;

// ── Logging ─────────────────────────────────────────────────────────────────

const LEVELS = { silent: 0, error: 1, warn: 2, info: 3, debug: 4 };

/**
 * Deliberately boring: one line per event, level first, no colours, no JSON envelope. This
 * output goes to `docker logs` and to journald far more often than to a human's terminal.
 *
 * Nothing here ever formats a token, a proof or an API key. §11 requires relay operators to
 * treat the token store as secret material, and "never logged" is the part an implementation
 * can actually enforce for them.
 */
function createLogger(level = process.env.RW_LOG || 'info') {
  const threshold = LEVELS[level] ?? LEVELS.info;
  const emit = (lvl, stream, args) => {
    if (LEVELS[lvl] > threshold) return;
    stream.write(`${new Date().toISOString()} ${lvl.padEnd(5)} ${args.join(' ')}\n`);
  };
  return {
    level,
    error: (...a) => emit('error', process.stderr, a),
    warn: (...a) => emit('warn', process.stderr, a),
    info: (...a) => emit('info', process.stdout, a),
    debug: (...a) => emit('debug', process.stdout, a),
  };
}

// ── Value formats (§2) ──────────────────────────────────────────────────────

const RE_DEVICE_ID = /^[0-9a-f]{16}$/;
const RE_TOKEN = /^[0-9a-f]{64}$/;
const RE_NONCE = /^[0-9a-f]{32}$/;
const RE_PROOF = /^[0-9a-f]{32}$/;
const RE_REQ_ID = /^.{1,36}$/s;

const isDeviceId = (v) => typeof v === 'string' && RE_DEVICE_ID.test(v);
const isToken = (v) => typeof v === 'string' && RE_TOKEN.test(v);
const isNonce = (v) => typeof v === 'string' && RE_NONCE.test(v);
const isProof = (v) => typeof v === 'string' && RE_PROOF.test(v);
const isReqId = (v) => typeof v === 'string' && RE_REQ_ID.test(v);

/**
 * §2: relays MUST accept lower-case and `-` separators on input and MUST normalise to
 * upper-case colon-separated on output. Returns null for anything that is not six octets.
 */
export function normaliseMac(mac) {
  if (typeof mac !== 'string') return null;
  const hex = mac.replace(/[:\-.\s]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) return null;
  return (hex.toUpperCase().match(/../g) ?? []).join(':');
}

/**
 * §2: a wake target must be a unicast address, and a relay should reject the three excluded
 * cases at its own edge rather than forwarding them. This is the one class of bad MAC that
 * fails silently: a magic packet to a group address is accepted by every layer that handles it,
 * so a device that sent it would answer `ok:true` with a full `sent` count having woken nothing.
 * A locally-administered address (bit 1) is perfectly wakeable and MUST NOT be rejected.
 */
export function isWakeable(mac) {
  const octets = (mac ?? '').split(':').map((o) => parseInt(o, 16));
  if (octets.length !== 6 || octets.some(Number.isNaN)) return false;
  if (octets[0] & 0x01) return false; // multicast/group, and broadcast with it
  if (octets.every((o) => o === 0x00)) return false; // "unspecified"
  return true;
}

// ── Proofs (§3.2) ───────────────────────────────────────────────────────────

/**
 * proof = HMAC-SHA256(token_bytes, tag + device_id + nonce_c + nonce_s), first 16 bytes.
 *
 * Two things here are load-bearing and easy to get wrong:
 *
 *   1. The key is the *raw 32 token bytes*, not the 64-character hex string. Keying with the
 *      hex text produces a perfectly plausible-looking proof that never matches a correct
 *      implementation, and the failure mode is an authentication error with no other symptom.
 *   2. The tag differs per direction (`rw1:c` from the device, `rw1:s` from the relay). Without
 *      it, an attacker who watched a device authenticate could replay its proof back at it as
 *      the relay's, and a device would believe it was talking to a relay that holds the token.
 */
export function computeProof(tokenHex, tag, deviceId, nonceC, nonceS) {
  return createHmac('sha256', Buffer.from(tokenHex, 'hex'))
    .update(`${tag}${deviceId}${nonceC}${nonceS}`, 'utf8')
    .digest()
    .subarray(0, 16);
}

export const proofClient = (token, id, nc, ns) => computeProof(token, 'rw1:c', id, nc, ns);
export const proofServer = (token, id, nc, ns) => computeProof(token, 'rw1:s', id, nc, ns);

const newNonce = () => randomBytes(16).toString('hex');

/**
 * Constant-time comparison of two secrets of *unrelated* length.
 *
 * `timingSafeEqual` throws when the buffers differ in length, so the naive guard
 * (`a.length === b.length && timingSafeEqual(a, b)`) leaks the expected length. Hashing both
 * sides first gives two 32-byte digests to compare, and the length of the input stops
 * mattering. Used for the API key, where the caller controls the length completely.
 */
function secretEquals(a, b) {
  const ha = createHash('sha256').update(String(a), 'utf8').digest();
  const hb = createHash('sha256').update(String(b), 'utf8').digest();
  return timingSafeEqual(ha, hb);
}

// ── Configuration ───────────────────────────────────────────────────────────

export class ConfigError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Validate and normalise a config object. Strict on purpose: a relay that starts happily with
 * a 6-character API key or a truncated token is a relay that fails at 2 a.m. with an
 * unhelpful `auth` error, and the person debugging it will be you.
 */
export function normaliseConfig(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new ConfigError('config must be a JSON object');
  }

  const port = raw.port ?? DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new ConfigError('port must be an integer 0–65535 (0 asks the OS for a free port)');
  }

  const host = raw.host ?? '0.0.0.0';
  if (typeof host !== 'string' || host.length === 0) {
    throw new ConfigError('host must be a non-empty string');
  }

  if (typeof raw.api_key !== 'string' || raw.api_key.length < 16) {
    throw new ConfigError(
      'api_key must be a string of at least 16 characters — generate one with `openssl rand -hex 32`',
    );
  }

  if (!raw.devices || typeof raw.devices !== 'object' || Array.isArray(raw.devices)) {
    throw new ConfigError('devices must be an object mapping device_id → token');
  }

  const devices = new Map();
  for (const [deviceId, token] of Object.entries(raw.devices)) {
    if (!isDeviceId(deviceId)) {
      throw new ConfigError(
        `devices: "${deviceId}" is not a device_id (16 lower-case hex characters)`,
      );
    }
    if (!isToken(token)) {
      throw new ConfigError(
        `devices["${deviceId}"]: token must be 64 lower-case hex characters (32 bytes)`,
      );
    }
    devices.set(deviceId, token);
  }

  const wakeTimeoutMs = raw.wake_timeout_ms ?? DEFAULT_WAKE_TIMEOUT_MS;
  const requestTimeoutMs = raw.request_timeout_ms ?? DEFAULT_REQUEST_TIMEOUT_MS;
  for (const [name, value] of [
    ['wake_timeout_ms', wakeTimeoutMs],
    ['request_timeout_ms', requestTimeoutMs],
  ]) {
    if (!Number.isInteger(value) || value < 100 || value > 300_000) {
      throw new ConfigError(`${name} must be an integer between 100 and 300000`);
    }
  }

  const sourceUrl = raw.source_url ?? DEFAULT_SOURCE_URL;
  if (typeof sourceUrl !== 'string' || !/^https?:\/\//.test(sourceUrl)) {
    throw new ConfigError('source_url must be an http(s) URL');
  }

  return {
    host,
    port,
    api_key: raw.api_key,
    devices,
    wake_timeout_ms: wakeTimeoutMs,
    request_timeout_ms: requestTimeoutMs,
    source_url: sourceUrl,
  };
}

export function loadConfig(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new ConfigError(`no config at ${path} — copy config.json.example and edit it`);
    }
    throw new ConfigError(`cannot read ${path}: ${err.message}`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new ConfigError(`${path} is not valid JSON: ${err.message}`);
  }
  return normaliseConfig(parsed);
}

// ── Device state ────────────────────────────────────────────────────────────

/**
 * Everything the relay knows about one provisioned device. Lives in memory only.
 *
 * `token` is the one field that must never leave this object: it is not in toJSON(), it is
 * never logged, and it is never returned by the HTTP API.
 */
class DeviceRecord {
  constructor(deviceId, token) {
    this.device_id = deviceId;
    this.token = token;
    this.conn = null;
    this.last_seen = null;
    this.connected_at = null;
    this.caps = [];
    this.fw = null;
    this.board = null;
    this.rssi = null;
    this.ip = null;
    this.remote_addr = null;
    this.wakeTimestamps = [];
  }

  get online() {
    return this.conn !== null && this.conn.state === 'open';
  }

  /** Prunes the sliding window and records a wake. Returns false when over the §11 limit. */
  admitWake(now = Date.now()) {
    this.wakeTimestamps = this.wakeTimestamps.filter((t) => now - t < WAKE_RATE_WINDOW_MS);
    if (this.wakeTimestamps.length >= WAKE_RATE_LIMIT) return false;
    this.wakeTimestamps.push(now);
    return true;
  }

  toJSON() {
    return {
      device_id: this.device_id,
      online: this.online,
      last_seen: this.last_seen === null ? null : new Date(this.last_seen).toISOString(),
      connected_at: this.connected_at === null ? null : new Date(this.connected_at).toISOString(),
      fw: this.fw,
      board: this.board,
      caps: this.caps,
      rssi: this.rssi,
      ip: this.ip,
      remote_addr: this.remote_addr,
    };
  }
}

// ── Connection ──────────────────────────────────────────────────────────────

let connSeq = 0;

/**
 * One device socket and its handshake state machine.
 *
 * States: `hello` → `auth` → `open`, or `closed`. The state is checked before every frame is
 * acted on, so a well-formed frame arriving at the wrong moment is ignored rather than
 * processed out of order.
 */
class Connection {
  constructor(relay, ws, req) {
    this.relay = relay;
    this.ws = ws;
    this.id = `c${++connSeq}`;
    this.state = 'hello';
    this.deviceId = null;
    this.record = null;
    this.candidate = null;
    this.effectiveToken = null;
    this.nonceC = null;
    this.nonceS = null;
    this.caps = [];
    this.lastActivity = Date.now();
    this.pending = new Map();
    this.remoteAddr =
      (req.headers['cf-connecting-ip'] ||
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.socket.remoteAddress) ??
      null;

    this.handshakeTimer = setTimeout(() => {
      this.relay.log.warn(`${this.id} handshake timed out in state=${this.state}`);
      this.close(1008, 'handshake timeout');
    }, HANDSHAKE_TIMEOUT_MS);

    ws.on('message', (data, isBinary) => this.onMessage(data, isBinary));
    ws.on('pong', () => {
      this.lastActivity = Date.now();
    });
    ws.on('error', (err) => {
      this.relay.log.warn(`${this.id} socket error: ${err.message}`);
    });
    ws.on('close', (code, reason) => this.onClose(code, reason));
  }

  get label() {
    return this.deviceId ? `${this.id}/${this.deviceId}` : this.id;
  }

  /**
   * Send one frame. Returns false if it could not go out.
   *
   * §1 and §12.6: a relay MUST NOT emit a frame larger than 2048 bytes. Devices are
   * memory-constrained and will close the connection with 1009 rather than truncate. Every
   * frame this relay constructs is bounded by validation long before it gets here — but the
   * check is on the send path anyway, because that is the only place it cannot be bypassed.
   */
  send(frame) {
    if (this.ws.readyState !== this.ws.OPEN) return false;
    const json = JSON.stringify(frame);
    const bytes = Buffer.byteLength(json, 'utf8');
    if (bytes > MAX_FRAME_BYTES) {
      this.relay.log.error(
        `${this.label} refusing to send ${frame.t}: ${bytes} bytes exceeds the ${MAX_FRAME_BYTES}-byte limit`,
      );
      return false;
    }
    this.relay.log.debug(`${this.label} -> ${json}`);
    this.ws.send(json);
    return true;
  }

  /** The literal keepalive answer. Bypasses send() precisely so nothing can reshape it. */
  sendPong() {
    if (this.ws.readyState !== this.ws.OPEN) return;
    this.relay.log.debug(`${this.label} -> ${PONG_FRAME}`);
    this.ws.send(PONG_FRAME);
  }

  close(code, reason = '') {
    if (this.state === 'closed') return;
    clearTimeout(this.handshakeTimer);
    this.ws.close(code, reason);
    // A socket whose peer has vanished never completes the closing handshake. Give it a few
    // seconds to answer politely, then take the file descriptor back.
    const t = setTimeout(() => this.ws.terminate(), 5_000);
    if (typeof t.unref === 'function') t.unref();
  }

  onMessage(data, isBinary) {
    this.lastActivity = Date.now();
    if (this.record) this.record.last_seen = this.lastActivity;

    if (isBinary) {
      // §1: frames are WebSocket text frames containing a single JSON object. A binary frame
      // is not a frame of ours we failed to understand, it is a peer speaking something else.
      this.relay.log.warn(`${this.label} sent a binary frame`);
      this.close(1008, 'text frames only');
      return;
    }

    const text = data.toString('utf8');
    this.relay.log.debug(`${this.label} <- ${text}`);

    // §9: match the keepalive on the exact bytes, before parsing. This is the hot path — one
    // frame per device per 25 seconds — and answering it without building an object is both
    // faster and a standing reminder that the byte sequence is the contract.
    if (text === PING_FRAME) {
      this.sendPong();
      return;
    }

    let frame;
    try {
      frame = JSON.parse(text);
    } catch {
      // Malformed JSON during the handshake is worth failing loudly, because it almost always
      // means the socket is not talking to a Rooster Wake device at all. Afterwards it is a
      // damaged frame on an otherwise good link, and dropping it is kinder than a reconnect.
      if (this.state !== 'open') {
        this.send({ t: 'hello_ack', ok: false, err: 'bad_frame' });
        this.close(1008, 'bad_frame');
      } else {
        this.relay.log.warn(`${this.label} sent unparseable JSON (${text.length} bytes)`);
      }
      return;
    }

    if (!frame || typeof frame !== 'object' || Array.isArray(frame)) return;
    if (typeof frame.t !== 'string') return;

    switch (frame.t) {
      case 'hello':
        if (this.state === 'hello') this.onHello(frame);
        return;
      case 'auth':
        if (this.state === 'auth') this.onAuth(frame);
        return;
      case 'pong':
        return; // Answer to our own optional ping. Liveness was recorded above.
      default:
        // §2 and §12.5: unknown `t` values MUST be ignored silently. Frames that are only
        // meaningful once authenticated go the same way until then.
        if (this.state === 'open') this.onAppFrame(frame);
        return;
    }
  }

  onHello(frame) {
    if (frame.v !== PROTOCOL_VERSION) {
      // §10: a relay that does not support the offered version closes with 4000. Answering
      // with hello_ack first would be a frame the device's version may not even parse.
      this.relay.log.warn(
        `${this.id} offered protocol v${frame.v}; this relay speaks v${PROTOCOL_VERSION}`,
      );
      this.close(4000, 'protocol version');
      return;
    }
    if (!isDeviceId(frame.device_id) || !isNonce(frame.nonce_c)) {
      this.relay.log.warn(`${this.id} sent a malformed hello`);
      this.send({ t: 'hello_ack', ok: false, err: 'bad_frame' });
      this.close(1008, 'bad_frame');
      return;
    }

    this.deviceId = frame.device_id;
    this.nonceC = frame.nonce_c;
    this.nonceS = newNonce();
    this.helloFw = typeof frame.fw === 'string' ? frame.fw.slice(0, 32) : null;
    this.helloBoard = typeof frame.board === 'string' ? frame.board.slice(0, 32) : null;
    this.caps = Array.isArray(frame.caps) ? frame.caps.filter((c) => typeof c === 'string') : [];

    // §3.3: send a challenge even when device_id is unknown. The relay must not be an oracle
    // for which device IDs exist, so the unknown case is given a random throwaway token and
    // then fails at `auth` exactly like a wrong proof would — same frames, same timing, same
    // close code. Nothing above this line branches on whether the device is provisioned.
    this.candidate = this.relay.devices.get(this.deviceId) ?? null;
    this.effectiveToken = this.candidate ? this.candidate.token : randomBytes(32).toString('hex');

    this.state = 'auth';
    this.send({ t: 'challenge', nonce_s: this.nonceS });
  }

  onAuth(frame) {
    const expected = proofClient(this.effectiveToken, this.deviceId, this.nonceC, this.nonceS);
    const offered = isProof(frame.proof_c) ? Buffer.from(frame.proof_c, 'hex') : Buffer.alloc(16);

    // §3.2 and §12.2: constant time. Both buffers are a fixed 16 bytes — the offered one is
    // validated to 32 lower-case hex characters first and replaced with zeros otherwise — so
    // timingSafeEqual can never throw on a length mismatch, and a wrong proof and a malformed
    // one take the same path.
    //
    // The comparison is evaluated *before* the `candidate` test rather than after it, so that
    // an unprovisioned device_id costs the same HMAC and the same comparison as a real one.
    // Ordering these the other way round would let short-circuit evaluation reintroduce the
    // timing oracle that sending a challenge to unknown IDs exists to close.
    const proofOk = timingSafeEqual(expected, offered);
    const record = this.candidate;
    if (!proofOk || !record) {
      this.relay.log.warn(
        `${this.label} authentication failed (device ${record ? 'known' : 'not provisioned'})`,
      );
      this.send({ t: 'hello_ack', ok: false, err: 'auth' });
      this.close(1008, 'auth');
      return;
    }

    clearTimeout(this.handshakeTimer);
    this.state = 'open';
    this.record = record;

    // §3.3: one live connection per device_id, and it is the *new* one that wins. A device
    // whose socket half-died reconnects and takes over immediately instead of waiting out a
    // 90-second idle timer on a connection that is never going to answer again.
    //
    // The registry is repointed at this connection *before* the old one is told to go, so that
    // the old socket's close handler cannot find itself still registered and null the entry
    // out from under its replacement.
    const previous = record.conn;
    record.conn = this;
    if (previous && previous !== this) {
      this.relay.log.info(`${this.label} supersedes ${previous.id}`);
      previous.supersede();
    }

    record.connected_at = Date.now();
    record.last_seen = Date.now();
    record.caps = this.caps;
    record.remote_addr = this.remoteAddr;
    if (this.helloFw) record.fw = this.helloFw;
    if (this.helloBoard) record.board = this.helloBoard;

    this.send({
      t: 'hello_ack',
      ok: true,
      proof_s: proofServer(this.effectiveToken, this.deviceId, this.nonceC, this.nonceS).toString(
        'hex',
      ),
      server: SERVER_ID,
      now: Math.floor(Date.now() / 1000),
    });

    this.relay.log.info(
      `${this.label} authenticated from ${this.remoteAddr} fw=${record.fw ?? '?'} caps=[${this.caps.join(',')}]`,
    );
  }

  supersede() {
    this.settleAll({ error: 'disconnected' });
    this.close(4001, 'superseded');
  }

  onAppFrame(frame) {
    // Every remaining device→relay frame is either an answer to something we asked for, or a
    // log line. Answers are matched on req_id; anything unmatched is dropped, which is what
    // makes a late reply to a request that already timed out harmless.
    if (frame.t === 'log') {
      // §4: devices only send these when the operator has enabled diagnostics, and relays MAY
      // discard them. This one passes them through at the device's own level so that turning
      // diagnostics on actually gets you something.
      const level = ['debug', 'info', 'warn', 'error'].includes(frame.level) ? frame.level : 'info';
      const msg = typeof frame.msg === 'string' ? frame.msg.slice(0, 200) : '';
      this.relay.log[level](`${this.label} device: ${msg}`);
      return;
    }

    if (!isReqId(frame.req_id)) return;
    const pending = this.pending.get(frame.req_id);
    if (!pending) return;

    if (frame.t === 'status_result') {
      if (typeof frame.rssi === 'number') this.record.rssi = frame.rssi;
      if (typeof frame.ip === 'string') this.record.ip = frame.ip;
      if (typeof frame.fw === 'string') this.record.fw = frame.fw.slice(0, 32);
    }

    if (frame.t === pending.expect) {
      pending.settle({ frame });
    }
  }

  /**
   * Send a request and resolve once the device answers, or the wait gives out.
   *
   * Resolves with `{ frame }` when the device replied, or `{ error }` when it did not. The
   * envelope matters: `send_failed` and `busy` are legitimate values of `err` *inside* a
   * `wake_result`, so a bare error string would make "the device says the NIC refused the
   * datagram" indistinguishable from "the relay could not write to the socket". Those two
   * deserve different HTTP status codes and very different debugging.
   */
  request(frame, expect, timeoutMs) {
    return new Promise((resolve) => {
      const reqId = randomUUID();
      let done = false;
      const settle = (outcome) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        this.pending.delete(reqId);
        resolve(outcome);
      };
      const timer = setTimeout(() => settle({ error: 'timeout' }), timeoutMs);
      this.pending.set(reqId, { expect, settle });

      if (!this.send({ ...frame, req_id: reqId })) {
        settle({ error: 'send_failed' });
      }
    });
  }

  settleAll(outcome) {
    for (const [, pending] of this.pending) pending.settle(outcome);
    this.pending.clear();
  }

  onClose(code, reason) {
    clearTimeout(this.handshakeTimer);
    const wasOpen = this.state === 'open';
    this.state = 'closed';
    this.settleAll({ error: 'disconnected' });
    this.relay.connections.delete(this);
    if (this.record && this.record.conn === this) {
      this.record.conn = null;
    }
    const detail = reason?.length ? ` (${reason.toString('utf8')})` : '';
    if (wasOpen) {
      this.relay.log.info(`${this.label} disconnected: ${code}${detail}`);
    } else {
      this.relay.log.debug(`${this.label} closed before auth: ${code}${detail}`);
    }
  }
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

function sendJson(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(json),
    'cache-control': 'no-store',
    server: SERVER_ID,
  });
  res.end(json);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_HTTP_BODY_BYTES) {
        reject(Object.assign(new Error('body too large'), { status: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function readJsonBody(req) {
  const raw = await readBody(req);
  if (raw.length === 0) return {};
  try {
    const parsed = JSON.parse(raw.toString('utf8'));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw Object.assign(new Error('body must be a JSON object'), { status: 400 });
    }
    return parsed;
  } catch (err) {
    if (err.status) throw err;
    throw Object.assign(new Error('body is not valid JSON'), { status: 400 });
  }
}

/** One-line summary of a request outcome, for the log. */
function describeOutcome(outcome, onSuccess) {
  if (outcome.error) return `no answer (${outcome.error})`;
  return outcome.frame.ok === true ? onSuccess(outcome.frame) : `fail ${outcome.frame.err}`;
}

function abortUpgrade(socket, status, message) {
  if (socket.writable) {
    const body = `${message}\n`;
    socket.write(
      `HTTP/1.1 ${status} ${STATUS_CODES[status]}\r\n` +
        'connection: close\r\n' +
        'content-type: text/plain; charset=utf-8\r\n' +
        `content-length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
  }
  socket.destroy();
}

// ── The relay ───────────────────────────────────────────────────────────────

export function createRelay(rawConfig, options = {}) {
  const config = rawConfig.devices instanceof Map ? rawConfig : normaliseConfig(rawConfig);
  const log = options.log ?? createLogger();
  const startedAt = Date.now();

  const devices = new Map();
  for (const [deviceId, token] of config.devices) {
    devices.set(deviceId, new DeviceRecord(deviceId, token));
  }

  const connections = new Set();
  const relay = { config, log, devices, connections };

  const httpServer = createServer((req, res) => {
    handleHttp(req, res).catch((err) => {
      const status = err.status ?? 500;
      if (status === 500) log.error(`unhandled error on ${req.method} ${req.url}: ${err.stack}`);
      // A client that hangs up mid-request lands here with nothing left to write to.
      if (res.writableEnded || res.destroyed) return;
      if (res.headersSent) res.end();
      else sendJson(res, status, { ok: false, err: err.message });
    });
  });

  const wss = new WebSocketServer({
    noServer: true,
    // §1: a frame over the limit is rejected with 1009, which `ws` does for us at this setting.
    maxPayload: MAX_FRAME_BYTES,
    // §1 and §12.1: echo `roosterwake.v1`. `ws` calls this with the set of protocols the client
    // offered; returning the string adds the response header.
    handleProtocols: (protocols) => (protocols.has(SUBPROTOCOL) ? SUBPROTOCOL : false),
  });

  httpServer.on('upgrade', (req, socket, head) => {
    // A WebSocket upgrade always carries an origin-form request target, so splitting off the
    // query is the whole of the parsing job. Deliberately not `new URL()`: an exception thrown
    // inside an 'upgrade' listener has nowhere to go but an uncaught exception handler, and a
    // relay that can be killed by a malformed request line is not a relay you can leave alone.
    const pathname = req.url.split('?')[0];
    if (pathname !== WS_PATH) {
      abortUpgrade(socket, 404, `no WebSocket endpoint here; devices connect to ${WS_PATH}`);
      return;
    }

    // §1 describes what a device does when the *relay* omits the subprotocol header: it closes,
    // because it has been pointed at something that is not a Rooster Wake relay. The mirror
    // image is handled here. A client that does not offer `roosterwake.v1` is not a Rooster Wake
    // device, and refusing the upgrade outright gives whoever pointed it here a readable error
    // instead of a socket that hangs until the handshake timer fires.
    const offered = (req.headers['sec-websocket-protocol'] ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);
    if (!offered.includes(SUBPROTOCOL)) {
      log.warn(`upgrade from ${req.socket.remoteAddress} without the ${SUBPROTOCOL} subprotocol`);
      abortUpgrade(socket, 400, `this endpoint speaks ${SUBPROTOCOL}`);
      return;
    }

    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });

  wss.on('connection', (ws, req) => {
    const conn = new Connection(relay, ws, req);
    connections.add(conn);
    log.debug(`${conn.id} connected from ${conn.remoteAddr}`);
  });

  /**
   * §9: control-frame pings from the relay, and a 90-second idle cut-off biased longer than
   * the device's own 75-second rule so the device notices first and reconnects cleanly rather
   * than racing our teardown.
   */
  const sweeper = setInterval(() => {
    const now = Date.now();
    for (const conn of connections) {
      if (conn.state === 'closed') continue;
      if (now - conn.lastActivity > IDLE_TIMEOUT_MS) {
        log.warn(`${conn.label} idle for ${Math.round((now - conn.lastActivity) / 1000)}s; closing`);
        conn.close(1000, 'idle');
        continue;
      }
      if (conn.ws.readyState === conn.ws.OPEN) conn.ws.ping();
    }
  }, CONTROL_PING_INTERVAL_MS);
  if (typeof sweeper.unref === 'function') sweeper.unref();

  // ── HTTP API ──────────────────────────────────────────────────────────────

  function authorised(req) {
    const header = req.headers.authorization ?? '';
    const match = /^Bearer (.+)$/.exec(header);
    if (!match) return false;
    return secretEquals(match[1], config.api_key);
  }

  function requireAuth(req, res) {
    if (authorised(req)) return true;
    res.setHeader('www-authenticate', 'Bearer realm="remotewake"');
    sendJson(res, 401, { ok: false, err: 'unauthorised' });
    return false;
  }

  /** Resolve a device_id to a live connection, or send the right HTTP failure. */
  function resolveDevice(res, deviceId, capability) {
    if (!isDeviceId(deviceId)) {
      sendJson(res, 400, { ok: false, err: 'bad_frame', detail: 'device_id must be 16 hex chars' });
      return null;
    }
    const record = devices.get(deviceId);
    if (!record) {
      sendJson(res, 404, { ok: false, err: 'unknown_device' });
      return null;
    }
    if (!record.online) {
      sendJson(res, 503, { ok: false, err: 'offline', last_seen: record.toJSON().last_seen });
      return null;
    }
    // §4: a relay MUST NOT send a command whose capability the device did not advertise.
    if (capability && !record.caps.includes(capability)) {
      sendJson(res, 501, { ok: false, err: 'unsupported', detail: `device lacks "${capability}"` });
      return null;
    }
    return record;
  }

  /** Translate a device answer (or the absence of one) into a status code and body. */
  function replyToOutcome(res, record, outcome, resultType) {
    switch (outcome.error) {
      case 'timeout':
        // The command went out and nothing came back. The device may still act on it.
        sendJson(res, 504, { ok: false, err: 'timeout', device_id: record.device_id });
        return;
      case 'disconnected':
        sendJson(res, 503, { ok: false, err: 'offline', device_id: record.device_id });
        return;
      case 'send_failed':
        sendJson(res, 503, { ok: false, err: 'send_failed', device_id: record.device_id });
        return;
      default:
        break;
    }
    // The device answered. Whether it *succeeded* is in `ok`; the HTTP exchange worked either
    // way, so the status stays 200 and the caller reads the body. Collapsing "the device says
    // the Wi-Fi link was down" into a 5xx would throw away the one diagnostic (§4) this
    // protocol works hardest to deliver.
    const { t: _type, ...rest } = outcome.frame;
    sendJson(res, 200, { device_id: record.device_id, result_type: resultType, ...rest });
  }

  async function handleHttp(req, res) {
    const route = `${req.method} ${req.url.split('?')[0]}`;
    log.debug(`http ${route}`);

    // Unauthenticated. Exists so a container orchestrator, an uptime monitor or a reverse
    // proxy can check liveness without being handed an API key to do it.
    if (route === 'GET /healthz') {
      let online = 0;
      for (const record of devices.values()) if (record.online) online++;
      sendJson(res, 200, {
        ok: true,
        devices_online: online,
        devices_total: devices.size,
        uptime_s: Math.floor((Date.now() - startedAt) / 1000),
      });
      return;
    }

    // AGPL §13: anyone interacting with this relay over a network is entitled to its source.
    // Point `source_url` at your fork if you have modified it — that is the whole obligation,
    // and answering it with a URL is cheaper than answering it with an email.
    if (route === 'GET /source') {
      sendJson(res, 200, { source: config.source_url, licence: 'AGPL-3.0-or-later' });
      return;
    }

    if (route === 'GET /devices') {
      if (!requireAuth(req, res)) return;
      sendJson(res, 200, { devices: [...devices.values()].map((d) => d.toJSON()) });
      return;
    }

    if (route === 'POST /wake') {
      if (!requireAuth(req, res)) return;
      const body = await readJsonBody(req);
      const record = resolveDevice(res, body.device_id, 'wake');
      if (!record) return;

      // §5: `mac` names the machine to wake and is required. The device holds no target list to
      // fall back on, so a `wake` without one is a frame it can only answer `bad_frame` (§6) —
      // and a relay that forwards a frame it already knows is invalid turns a caller's mistake
      // into a round trip, a device-side error and a 200 with `ok:false` to read carefully.
      if (body.mac === undefined || body.mac === null) {
        sendJson(res, 400, { ok: false, err: 'bad_frame', detail: 'mac is required' });
        return;
      }
      const mac = normaliseMac(body.mac);
      if (!mac || !isWakeable(mac)) {
        sendJson(res, 400, { ok: false, err: 'bad_mac' });
        return;
      }
      let repeat;
      if (body.repeat !== undefined) {
        if (!Number.isInteger(body.repeat) || body.repeat < 1 || body.repeat > 5) {
          sendJson(res, 400, { ok: false, err: 'bad_frame', detail: 'repeat must be 1–5' });
          return;
        }
        repeat = body.repeat;
      }

      if (!record.admitWake()) {
        // §11: 30 wakes per minute per device.
        res.setHeader('retry-after', '60');
        sendJson(res, 429, { ok: false, err: 'rate_limited', limit_per_minute: WAKE_RATE_LIMIT });
        return;
      }

      const frame = { t: 'wake', mac };
      if (repeat) frame.repeat = repeat;
      const outcome = await record.conn.request(frame, 'wake_result', config.wake_timeout_ms);
      log.info(
        `wake ${record.device_id} ${mac} -> ${describeOutcome(outcome, (f) => `ok sent=${f.sent} ifaces=${(f.ifaces ?? []).length}`)}`,
      );
      replyToOutcome(res, record, outcome, 'wake_result');
      return;
    }

    if (route === 'POST /status') {
      if (!requireAuth(req, res)) return;
      const body = await readJsonBody(req);
      const record = resolveDevice(res, body.device_id, 'status');
      if (!record) return;
      const outcome = await record.conn.request(
        { t: 'status' },
        'status_result',
        config.request_timeout_ms,
      );
      replyToOutcome(res, record, outcome, 'status_result');
      return;
    }

    sendJson(res, 404, { ok: false, err: 'not_found' });
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  return {
    config,
    log,
    devices,
    httpServer,

    get port() {
      const addr = httpServer.address();
      return typeof addr === 'object' && addr ? addr.port : null;
    },

    listen() {
      return new Promise((resolve, reject) => {
        const onError = (err) => reject(err);
        httpServer.once('error', onError);
        httpServer.listen(config.port, config.host, () => {
          httpServer.off('error', onError);
          resolve(this.port);
        });
      });
    },

    async close() {
      clearInterval(sweeper);
      for (const conn of connections) conn.close(1000, 'relay shutting down');
      // Sockets that never answer the close handshake would otherwise hold the server open.
      for (const ws of wss.clients) ws.terminate();
      wss.close();
      await new Promise((resolve) => httpServer.close(resolve));
    },
  };
}

// ── CLI ─────────────────────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = { config: process.env.RW_CONFIG || './config.json' };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--config' || arg === '-c') args.config = argv[++i];
    else if (arg === '--help' || arg === '-h') args.help = true;
    else throw new ConfigError(`unknown argument "${arg}" (try --help)`);
  }
  if (args.config === undefined) throw new ConfigError('--config needs a path');
  return args;
}

const USAGE = `remotewake reference relay

  node server.js [--config <path>]

Options
  -c, --config <path>   config file (default ./config.json, or $RW_CONFIG)
  -h, --help            this message

Environment
  PORT      overrides "port" from the config file
  RW_LOG    silent | error | warn | info | debug   (default info)
`;

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }
  if (args.help) {
    process.stdout.write(USAGE);
    return;
  }

  let config;
  try {
    config = loadConfig(args.config);
    if (process.env.PORT) {
      const port = Number(process.env.PORT);
      if (!Number.isInteger(port) || port < 0 || port > 65535) {
        throw new ConfigError(`PORT="${process.env.PORT}" is not a valid port`);
      }
      config.port = port;
    }
  } catch (err) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }

  const relay = createRelay(config);
  try {
    await relay.listen();
  } catch (err) {
    process.stderr.write(`cannot listen on ${config.host}:${config.port}: ${err.message}\n`);
    process.exit(1);
  }

  relay.log.info(
    `${SERVER_ID} listening on ${config.host}:${relay.port} — ws ${WS_PATH}, ${config.devices.size} device(s) provisioned`,
  );

  let closing = false;
  const shutdown = async (signal) => {
    if (closing) return;
    closing = true;
    relay.log.info(`${signal} received, shutting down`);
    await relay.close();
    process.exit(0);
  };
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) await main();
