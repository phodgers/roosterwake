/**
 * Tests for the config codec and the UF2 writer.
 *
 * The golden-vector block is the important one: it asserts that this encoder reproduces
 * firmware/test/vectors/config-v1.json byte for byte. The firmware's C tests assert the same
 * thing against the same file. That is what stops a format implemented three times from
 * quietly diverging — see config-format.md §7.
 *
 * Run: node --test tools/mkconfig/test/
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  encode, decode, crc32, parseMac, formatMac, seqNewer, ConfigError,
  RECORD_LEN_V1, HEADER_LEN, PAYLOAD_LEN_V1, MAGIC_BYTES, FLAG, MAX_TARGETS,
} from '../lib/config.mjs';
import { buildUf2, parseUf2, flattenUf2, FAMILY, BLOCK_SIZE, PAYLOAD_PER_BLOCK } from '../lib/uf2.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(here, '../../../firmware/test/vectors/config-v1.json'), 'utf8')
);

// ── CRC ─────────────────────────────────────────────────────────────────────

test('crc32 matches the ISO-HDLC check value', () => {
  // "CRC32" names several different algorithms. This is the one-line proof we implemented
  // the same one as zlib, PNG, and every other sane implementation.
  assert.equal(crc32(new TextEncoder().encode('123456789')), 0xcbf43926);
});

test('crc32 of empty input is 0', () => {
  assert.equal(crc32(new Uint8Array(0)), 0);
});

// ── Golden vectors ──────────────────────────────────────────────────────────

test('golden vector file is self-consistent', () => {
  assert.equal(vectors.format_version, 1);
  assert.equal(vectors.record_len, RECORD_LEN_V1);
  assert.equal(vectors.header_len, HEADER_LEN);
  assert.equal(vectors.payload_len, PAYLOAD_LEN_V1);
  assert.equal(vectors.crc32_check_value, '0xcbf43926');
  assert.ok(vectors.vectors.length >= 5, 'expected at least 5 vectors');
});

for (const v of vectors.vectors) {
  test(`vector "${v.name}" encodes to the recorded bytes`, () => {
    const encoded = Buffer.from(encode(v.config)).toString('hex');
    assert.equal(encoded, v.record_hex,
      `Encoder output changed for "${v.name}".\n` +
      `If this was intentional, regenerate the vectors AND mirror the change in ` +
      `firmware/src/config/config.c in the same commit.`);
  });

  test(`vector "${v.name}" round-trips through decode`, () => {
    const back = decode(Buffer.from(v.record_hex, 'hex'));
    assert.ok(back, 'failed to decode');
    assert.deepEqual(back, v.decoded);
  });

  test(`vector "${v.name}" has the recorded CRC`, () => {
    const record = Buffer.from(v.record_hex, 'hex');
    const actual = '0x' + crc32(record.subarray(HEADER_LEN)).toString(16).padStart(8, '0');
    assert.equal(actual, v.crc32);
  });
}

// ── Record structure ────────────────────────────────────────────────────────

test('record is exactly 612 bytes with the RWCF magic', () => {
  const r = encode({ ssid: 'x' });
  assert.equal(r.length, RECORD_LEN_V1);
  assert.deepEqual(r.subarray(0, 4), MAGIC_BYTES);
});

test('padding is NUL, never 0xFF', () => {
  // 0xFF is the erased-flash value and would be the lazy choice, but it makes the CRC depend
  // on which writer produced the record. config-format.md §2.2.
  const r = encode({ ssid: 'ab' });
  const payload = r.subarray(HEADER_LEN);
  assert.equal(payload[2], 0, 'byte after the SSID must be NUL');
  assert.ok(payload.subarray(2, 33).every((b) => b === 0), 'SSID field must be NUL-padded');
});

test('decode rejects a corrupted payload', () => {
  const r = encode({ ssid: 'HomeNet', targets: [{ name: 'PC', mac: 'AA:BB:CC:DD:EE:FF' }] });
  assert.ok(decode(r), 'sanity: the pristine record decodes');
  r[HEADER_LEN + 1] ^= 0xff; // flip a bit in the SSID
  assert.equal(decode(r), null, 'CRC must catch a single flipped bit');
});

test('decode rejects bad magic, wrong version, and truncation', () => {
  const good = encode({ ssid: 'x' });

  const badMagic = Uint8Array.from(good); badMagic[0] = 0x00;
  assert.equal(decode(badMagic), null);

  const badVersion = Uint8Array.from(good);
  new DataView(badVersion.buffer).setUint16(4, 99, true);
  assert.equal(decode(badVersion), null);

  assert.equal(decode(good.subarray(0, 100)), null);
  assert.equal(decode(new Uint8Array(0)), null);
  assert.equal(decode(null), null);
});

// ── Validation ──────────────────────────────────────────────────────────────

test('rejects oversized fields by BYTE length, not character count', () => {
  assert.throws(() => encode({ ssid: 'A'.repeat(33) }), ConfigError);
  assert.doesNotThrow(() => encode({ ssid: 'A'.repeat(32) }));

  // 11 emoji = 11 characters but 44 bytes. A character-counting implementation would accept
  // this and then truncate mid-sequence, writing invalid UTF-8 to the device.
  assert.doesNotThrow(() => encode({ ssid: '🏠'.repeat(8) }), '32 bytes is fine');
  assert.throws(() => encode({ ssid: '🏠'.repeat(9) }), ConfigError, '36 bytes must be rejected');
});

test('rejects a ninth target', () => {
  const mk = (n) => Array.from({ length: n }, (_, i) => ({ name: `T${i}`, mac: '00:00:00:00:00:01' }));
  assert.doesNotThrow(() => encode({ targets: mk(MAX_TARGETS) }));
  assert.throws(() => encode({ targets: mk(MAX_TARGETS + 1) }), ConfigError);
});

test('rejects a relay URL that is not ws:// or wss://', () => {
  assert.throws(() => encode({ relay_url: 'https://example.com/ws' }), ConfigError);
  assert.doesNotThrow(() => encode({ relay_url: 'wss://example.com/ws' }));
  assert.doesNotThrow(() => encode({ relay_url: 'ws://192.168.1.10:8080/ws' }));
});

test('rejects malformed device_id and token', () => {
  assert.throws(() => encode({ device_id: 'NOTHEX0123456789' }), ConfigError);
  assert.throws(() => encode({ device_id: 'abc' }), ConfigError);
  assert.throws(() => encode({ device_id: 'A1B2C3D4E5F60718' }), ConfigError, 'upper case is rejected');
  assert.throws(() => encode({ token: 'f'.repeat(63) }), ConfigError);
});

test('rejects an empty target name', () => {
  assert.throws(() => encode({ targets: [{ name: '   ', mac: '00:00:00:00:00:01' }] }), ConfigError);
});

// ── MAC handling ────────────────────────────────────────────────────────────

test('parseMac accepts every common separator and case', () => {
  const expected = Uint8Array.from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
  for (const form of ['AA:BB:CC:DD:EE:FF', 'aa:bb:cc:dd:ee:ff', 'AA-BB-CC-DD-EE-FF', 'aabbccddeeff']) {
    assert.deepEqual(parseMac(form), expected, `failed on ${form}`);
  }
});

test('parseMac rejects rubbish', () => {
  for (const bad of ['', 'AA:BB:CC:DD:EE', 'AA:BB:CC:DD:EE:FF:00', 'ZZ:BB:CC:DD:EE:FF', 'hello']) {
    assert.throws(() => parseMac(bad), ConfigError, `should have rejected "${bad}"`);
  }
});

test('formatMac normalises to upper-case colon-separated', () => {
  assert.equal(formatMac(parseMac('aa-bb-cc-dd-ee-ff')), 'AA:BB:CC:DD:EE:FF');
});

// ── Sequence wrap ───────────────────────────────────────────────────────────

test('seqNewer is wrap-safe', () => {
  assert.ok(seqNewer(2, 1));
  assert.ok(!seqNewer(1, 2));
  assert.ok(!seqNewer(5, 5));
  // The case a naive `a > b` gets wrong: 0 is newer than 0xFFFFFFFF after a wrap.
  assert.ok(seqNewer(0, 0xffffffff), '0 must be newer than 0xFFFFFFFF');
  assert.ok(!seqNewer(0xffffffff, 0));
});

// ── Flags ───────────────────────────────────────────────────────────────────

test('flags round-trip', () => {
  const all = FLAG.TLS_INSECURE | FLAG.DIAG_LOG | FLAG.WOL_UNICAST;
  assert.equal(decode(encode({ flags: all })).flags, all);
  assert.equal(decode(encode({})).flags, 0);
});

// ── UF2 ─────────────────────────────────────────────────────────────────────

test('buildUf2 produces well-formed blocks at the right address', () => {
  const record = encode({ ssid: 'HomeNet', targets: [{ name: 'PC', mac: 'AA:BB:CC:DD:EE:FF' }] });
  const uf2 = buildUf2(record, 0x103ff000, FAMILY.RP2350_ARM_S, 4096);

  assert.equal(uf2.length, (4096 / PAYLOAD_PER_BLOCK) * BLOCK_SIZE, 'a full 4 KB sector');

  const blocks = parseUf2(uf2);
  assert.ok(blocks, 'must parse back');
  assert.equal(blocks.length, 16);
  assert.equal(blocks[0].targetAddr, 0x103ff000);
  assert.equal(blocks[0].familyId, FAMILY.RP2350_ARM_S);
  assert.equal(blocks[15].targetAddr, 0x103ff000 + 15 * PAYLOAD_PER_BLOCK);
  blocks.forEach((b, i) => {
    assert.equal(b.blockNo, i);
    assert.equal(b.numBlocks, 16);
    assert.equal(b.payloadSize, PAYLOAD_PER_BLOCK);
  });
});

test('a UF2 round-trips back to the original config', () => {
  const cfg = {
    ssid: 'HomeNet', psk: 'hunter2', wifi_auth: 'wpa2',
    relay_url: 'wss://relay.roosterwake.com/ws',
    device_id: 'a1b2c3d4e5f60718', token: 'e'.repeat(64),
    targets: [{ name: 'Desktop', mac: 'AA:BB:CC:DD:EE:FF' }, { name: 'NAS', mac: '11:22:33:44:55:66' }],
  };
  const uf2 = buildUf2(encode(cfg), 0x103ff000, FAMILY.RP2350_ARM_S, 4096);
  const flat = flattenUf2(parseUf2(uf2));
  assert.equal(flat.base, 0x103ff000);

  const back = decode(flat.data);
  assert.ok(back);
  assert.equal(back.ssid, cfg.ssid);
  assert.equal(back.psk, cfg.psk);
  assert.equal(back.device_id, cfg.device_id);
  assert.deepEqual(back.targets, cfg.targets.map((t) => ({ name: t.name, mac: t.mac })));
});

test('the sector tail is explicitly zeroed', () => {
  // Not cosmetic: leaving the tail unwritten means the device keeps whatever was there
  // before, which makes a "fresh" provision depend on flash history.
  const uf2 = buildUf2(encode({ ssid: 'x' }), 0x103ff000, FAMILY.RP2350_ARM_S, 4096);
  const flat = flattenUf2(parseUf2(uf2));
  assert.equal(flat.data.length, 4096);
  assert.ok(flat.data.subarray(RECORD_LEN_V1).every((b) => b === 0), 'tail must be all zero');
});

test('parseUf2 rejects malformed input rather than throwing', () => {
  assert.equal(parseUf2(new Uint8Array(0)), null);
  assert.equal(parseUf2(new Uint8Array(511)), null, 'not a block multiple');
  assert.equal(parseUf2(new Uint8Array(512)), null, 'zeroed block has no magic');
});

test('flattenUf2 refuses non-contiguous blocks', () => {
  const uf2 = buildUf2(encode({ ssid: 'x' }), 0x103ff000, FAMILY.RP2350_ARM_S, 4096);
  const blocks = parseUf2(uf2);
  blocks.splice(4, 1); // punch a hole
  assert.equal(flattenUf2(blocks), null, 'a gap must not be silently zero-filled');
});
