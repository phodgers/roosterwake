/**
 * Reference encoder/decoder for the Remote Wake flash config record.
 *
 * This is the JavaScript half of a format implemented twice — the other half is
 * firmware/src/config/config.c, in C, on the device. The two are kept honest by the golden
 * vectors in firmware/test/vectors/config-v1.json, which BOTH test suites consume. If either
 * side drifts, CI fails on the other.
 *
 * The authoritative specification is firmware/docs/config-format.md. Where this file and that
 * document disagree, the document wins and this file is the bug.
 *
 * Zero dependencies, by design: this ships in a CLI that homelabbers run with `npx`, and a
 * supply chain is a poor thing to inflict on someone who just wants to configure a dongle.
 */

// ── Layout constants (see config-format.md §2) ──────────────────────────────

export const MAGIC = 0x46435752; // "RWCF" read as little-endian u32
export const MAGIC_BYTES = Uint8Array.from([0x52, 0x57, 0x43, 0x46]); // 'R','W','C','F'
export const VERSION = 1;

export const HEADER_LEN = 32;
export const PAYLOAD_LEN_V1 = 580;
export const RECORD_LEN_V1 = HEADER_LEN + PAYLOAD_LEN_V1; // 612
export const SECTOR_SIZE = 4096;

export const MAX_TARGETS = 8;
export const TARGET_ENTRY_LEN = 31;

/** Field offsets within the payload. Never change these; append instead. */
export const OFF = {
  ssid: 0,
  psk: 33,
  wifi_auth: 98,
  relay_url: 99,
  device_id: 228,
  token: 245,
  claim_code: 310,
  flags: 327,
  target_count: 331,
  targets: 332,
};

/** Field widths, including the mandatory NUL terminator for strings. */
export const LEN = {
  ssid: 33,
  psk: 65,
  relay_url: 129,
  device_id: 17,
  token: 65,
  claim_code: 17,
  target_name: 25,
};

export const WIFI_AUTH = { open: 0, wpa2: 1, wpa3: 2, auto: 255 };
export const WIFI_AUTH_NAME = { 0: 'open', 1: 'wpa2', 2: 'wpa3', 255: 'auto' };

export const FLAG = {
  TLS_INSECURE: 1 << 0,
  DIAG_LOG: 1 << 1,
  WOL_UNICAST: 1 << 2,
};

/** Base of the XIP window on every RP2 part. */
export const XIP_BASE = 0x10000000;

/**
 * Supported boards.
 *
 * The config lives in the top two sectors of flash, so its address depends on how much flash
 * the board has — and the UF2 family ID depends on which chip it is. The two are bound together
 * here rather than chosen separately, because the failure modes are wildly asymmetric: a UF2
 * with the wrong family is simply refused by the bootloader, while one with the right family
 * and the wrong address is *accepted* and writes a config record into the middle of the
 * firmware image. One is a loud no-op; the other bricks the device.
 *
 * @type {Record<string, {flashSize: number, family: number, chip: string}>}
 */
export const BOARDS = {
  pico2_w: { flashSize: 4 * 1024 * 1024, family: 0xe48bff59, chip: 'RP2350' },
  pico_w:  { flashSize: 2 * 1024 * 1024, family: 0xe48bff56, chip: 'RP2040' },
};

export const DEFAULT_BOARD = 'pico2_w';

/** XIP addresses of the two config slots for a given flash size. */
export function slotAddresses(flashSize) {
  const slotB = XIP_BASE + flashSize - SECTOR_SIZE;
  return { a: slotB - SECTOR_SIZE, b: slotB };
}

/** Slot addresses for the default board, kept for callers that do not care about the board. */
export const SLOT_A_XIP = slotAddresses(BOARDS[DEFAULT_BOARD].flashSize).a;
export const SLOT_B_XIP = slotAddresses(BOARDS[DEFAULT_BOARD].flashSize).b;

/**
 * Default `seq` for a generated image. A generated config cannot read what is already on the
 * device, so it cannot compute winner+1. A large constant reliably beats normally-incremented
 * sequences while leaving plenty of room below it. See config-format.md §5.
 */
export const GENERATED_SEQ = 0x40000000;

// ── CRC-32/ISO-HDLC ─────────────────────────────────────────────────────────

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[i] = c >>> 0;
  }
  return t;
})();

/** CRC-32/ISO-HDLC (zlib/PNG). Check value for "123456789" is 0xCBF43926. */
export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// ── Helpers ─────────────────────────────────────────────────────────────────

class ConfigError extends Error {
  constructor(field, message) {
    super(`${field}: ${message}`);
    this.name = 'ConfigError';
    this.field = field;
  }
}
export { ConfigError };

const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

/**
 * Write a UTF-8 string into a fixed-width, NUL-padded field.
 *
 * Length is checked in BYTES, not characters, and the check leaves room for the terminator.
 * A target named "Björn's Büro" is 12 characters but 14 bytes; truncating at a character
 * count would silently corrupt the encoding, and truncating mid-sequence would produce
 * invalid UTF-8 on the device. So we reject rather than truncate — callers validate at the
 * input boundary where they can give a useful error.
 */
function putStr(buf, offset, width, value, field) {
  const bytes = enc.encode(value ?? '');
  if (bytes.length > width - 1) {
    throw new ConfigError(field, `${bytes.length} bytes exceeds the ${width - 1}-byte limit`);
  }
  buf.set(bytes, offset);
  // Remainder is already zero — the buffer is zero-filled at allocation, and padding MUST be
  // NUL rather than 0xFF so the CRC is reproducible across writers (config-format.md §2.2).
}

function getStr(buf, offset, width) {
  let end = offset;
  const limit = offset + width;
  while (end < limit && buf[end] !== 0) end++;
  return dec.decode(buf.subarray(offset, end));
}

/** Parse a MAC in any common form to six raw octets. */
export function parseMac(mac, field = 'mac') {
  if (typeof mac !== 'string') throw new ConfigError(field, 'must be a string');
  const hex = mac.replace(/[:\-.\s]/g, '');
  if (!/^[0-9a-fA-F]{12}$/.test(hex)) {
    throw new ConfigError(field, `"${mac}" is not a valid MAC address`);
  }
  const out = new Uint8Array(6);
  for (let i = 0; i < 6; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

/** Format six octets as the canonical upper-case colon-separated form. */
export function formatMac(bytes) {
  return Array.from(bytes, (b) => b.toString(16).toUpperCase().padStart(2, '0')).join(':');
}

function assertHex(value, chars, field) {
  if (typeof value !== 'string' || !new RegExp(`^[0-9a-f]{${chars}}$`).test(value)) {
    throw new ConfigError(field, `must be exactly ${chars} lower-case hex characters`);
  }
}

// ── Encode ──────────────────────────────────────────────────────────────────

/**
 * Encode a configuration object into a full record (header + payload).
 *
 * @param {object} cfg
 * @param {string} [cfg.ssid]
 * @param {string} [cfg.psk]
 * @param {'open'|'wpa2'|'wpa3'|'auto'} [cfg.wifi_auth='auto']
 * @param {string} [cfg.relay_url]
 * @param {string} [cfg.device_id]   16 lower-case hex chars
 * @param {string} [cfg.token]       64 lower-case hex chars
 * @param {string} [cfg.claim_code]
 * @param {number} [cfg.flags=0]
 * @param {Array<{name:string, mac:string}>} [cfg.targets=[]]
 * @param {number} [cfg.seq=GENERATED_SEQ]
 * @returns {Uint8Array} RECORD_LEN_V1 bytes
 */
export function encode(cfg = {}) {
  const payload = new Uint8Array(PAYLOAD_LEN_V1);

  putStr(payload, OFF.ssid, LEN.ssid, cfg.ssid, 'ssid');
  putStr(payload, OFF.psk, LEN.psk, cfg.psk, 'psk');

  const authName = cfg.wifi_auth ?? 'auto';
  if (!(authName in WIFI_AUTH)) {
    throw new ConfigError('wifi_auth', `must be one of ${Object.keys(WIFI_AUTH).join(', ')}`);
  }
  payload[OFF.wifi_auth] = WIFI_AUTH[authName];

  if (cfg.relay_url) {
    if (!/^wss?:\/\//i.test(cfg.relay_url)) {
      throw new ConfigError('relay_url', 'must begin with ws:// or wss://');
    }
    putStr(payload, OFF.relay_url, LEN.relay_url, cfg.relay_url, 'relay_url');
  }

  if (cfg.device_id) {
    assertHex(cfg.device_id, 16, 'device_id');
    putStr(payload, OFF.device_id, LEN.device_id, cfg.device_id, 'device_id');
  }
  if (cfg.token) {
    assertHex(cfg.token, 64, 'token');
    putStr(payload, OFF.token, LEN.token, cfg.token, 'token');
  }
  putStr(payload, OFF.claim_code, LEN.claim_code, cfg.claim_code, 'claim_code');

  const flags = cfg.flags ?? 0;
  if (!Number.isInteger(flags) || flags < 0 || flags > 0xffffffff) {
    throw new ConfigError('flags', 'must be a uint32');
  }
  new DataView(payload.buffer).setUint32(OFF.flags, flags, true);

  const targets = cfg.targets ?? [];
  if (targets.length > MAX_TARGETS) {
    throw new ConfigError('targets', `at most ${MAX_TARGETS} targets (got ${targets.length})`);
  }
  payload[OFF.target_count] = targets.length;
  targets.forEach((t, i) => {
    const base = OFF.targets + i * TARGET_ENTRY_LEN;
    const name = (t.name ?? '').trim();
    if (name.length === 0) throw new ConfigError(`targets[${i}].name`, 'must not be empty');
    putStr(payload, base, LEN.target_name, name, `targets[${i}].name`);
    payload.set(parseMac(t.mac, `targets[${i}].mac`), base + LEN.target_name);
  });

  // Header last — it carries the CRC of the finished payload.
  const record = new Uint8Array(RECORD_LEN_V1);
  const view = new DataView(record.buffer);
  record.set(MAGIC_BYTES, 0);
  view.setUint16(4, VERSION, true);
  view.setUint16(6, 0, true); // reserved0
  view.setUint32(8, (cfg.seq ?? GENERATED_SEQ) >>> 0, true);
  view.setUint32(12, PAYLOAD_LEN_V1, true);
  view.setUint32(16, crc32(payload), true);
  // bytes 20..31 reserved1, already zero
  record.set(payload, HEADER_LEN);
  return record;
}

// ── Decode ──────────────────────────────────────────────────────────────────

/**
 * Decode a record. Returns null for anything that is not a valid v1 record, so callers can
 * treat "no config" and "corrupt config" identically — which is what the device does when
 * choosing between slots (config-format.md §3).
 */
export function decode(bytes) {
  if (!bytes || bytes.length < HEADER_LEN) return null;
  for (let i = 0; i < 4; i++) if (bytes[i] !== MAGIC_BYTES[i]) return null;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint16(4, true);
  if (version !== VERSION) return null;

  const seq = view.getUint32(8, true);
  const payloadLen = view.getUint32(12, true);
  const storedCrc = view.getUint32(16, true);
  if (payloadLen !== PAYLOAD_LEN_V1) return null;
  if (bytes.length < HEADER_LEN + payloadLen) return null;

  const payload = bytes.subarray(HEADER_LEN, HEADER_LEN + payloadLen);
  if (crc32(payload) !== storedCrc) return null;

  const pv = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);
  const count = Math.min(payload[OFF.target_count], MAX_TARGETS);
  const targets = [];
  for (let i = 0; i < count; i++) {
    const base = OFF.targets + i * TARGET_ENTRY_LEN;
    targets.push({
      name: getStr(payload, base, LEN.target_name),
      mac: formatMac(payload.subarray(base + LEN.target_name, base + TARGET_ENTRY_LEN)),
    });
  }

  return {
    version,
    seq,
    ssid: getStr(payload, OFF.ssid, LEN.ssid),
    psk: getStr(payload, OFF.psk, LEN.psk),
    wifi_auth: WIFI_AUTH_NAME[payload[OFF.wifi_auth]] ?? 'auto',
    relay_url: getStr(payload, OFF.relay_url, LEN.relay_url),
    device_id: getStr(payload, OFF.device_id, LEN.device_id),
    token: getStr(payload, OFF.token, LEN.token),
    claim_code: getStr(payload, OFF.claim_code, LEN.claim_code),
    flags: pv.getUint32(OFF.flags, true),
    targets,
  };
}

/**
 * Compare two sequence numbers with wrap-around safety.
 * Returns > 0 when `a` is newer. See config-format.md §3 — direct `>` would resurrect a stale
 * slot after wrap. It will never wrap in practice (flash endurance runs out long first), but
 * the correct comparison costs nothing and the wrong one is undebuggable.
 */
export function seqNewer(a, b) {
  return ((a - b) | 0) > 0;
}
