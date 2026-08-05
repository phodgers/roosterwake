/**
 * Generate the golden vectors consumed by BOTH the C and JS config test suites.
 *
 * Run:  node tools/mkconfig/scripts/gen-vectors.mjs
 * Out:  firmware/test/vectors/config-v2.json
 *
 * It lives in scripts/ rather than test/ because `node --test <dir>` treats *every* .mjs file
 * under a directory named `test` as a test file. Sitting next to the suite it feeds, this
 * generator was collected as a test, ran its side effects, and failed the run.
 *
 * The generated file is committed. Regenerating it should produce a byte-identical result;
 * if it does not, the encoder changed, and that change must be mirrored in
 * firmware/src/config/config.c in the same commit. That is the entire point of this file —
 * a format implemented three times (firmware C, this CLI, the hosted dashboard) needs a
 * single artefact that all of them are measured against.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { encode, decode, crc32, FLAG, RECORD_LEN_V2, PAYLOAD_LEN_V2, HEADER_LEN } from '../lib/config.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const outPath = resolve(here, '../../../firmware/test/vectors/config-v2.json');

const hex = (bytes) => Buffer.from(bytes).toString('hex');

/**
 * Cases are chosen to pin the things that actually break when two implementations drift:
 * empty/unset handling, exact field boundaries, multi-byte UTF-8, and full occupancy.
 */
const cases = [
  {
    name: 'unprovisioned',
    why: 'A zeroed payload with only the header populated. This is what a factory-reset device writes, and it must round-trip to "no Wi-Fi" rather than to empty-string confusion.',
    config: { seq: 1 },
  },
  {
    name: 'minimal',
    why: 'The ordinary case: one network, one relay, one device identity. If anything at all works, this must.',
    config: {
      seq: 2,
      ssid: 'HomeNet',
      psk: 'correct horse battery staple',
      wifi_auth: 'wpa2',
      relay_url: 'wss://relay.roosterwake.com/ws',
      device_id: 'a1b2c3d4e5f60718',
      token: 'f'.repeat(64),
    },
  },
  {
    name: 'maximal',
    why: 'Every field at its documented maximum. Catches off-by-one errors in the NUL terminator, which is exactly where a hand-written C encoder goes wrong.',
    config: {
      seq: 0x7fffffff,
      ssid: 'A'.repeat(32),
      psk: 'B'.repeat(64),
      wifi_auth: 'wpa3',
      // Exactly 128 bytes: 'wss://' (6) + 107 + '.example.com/ws' (15). Sits precisely on the
      // limit, so an off-by-one in either implementation fails here rather than in the field.
      relay_url: 'wss://' + 'c'.repeat(107) + '.example.com/ws',
      device_id: '0123456789abcdef',
      token: '0123456789abcdef'.repeat(4),
      owner_email: 'philip@example.com',
      flags: FLAG.TLS_INSECURE | FLAG.DIAG_LOG | FLAG.WOL_UNICAST,
    },
  },
  {
    name: 'utf8_strings',
    why: 'Multi-byte SSID and password. Field limits are in BYTES, not characters; an implementation that counts characters silently truncates mid-sequence and emits invalid UTF-8.',
    config: {
      seq: 42,
      ssid: 'Café Münster 🏠',
      psk: 'pässwörd',
      wifi_auth: 'wpa2',
      relay_url: 'ws://192.168.1.10:8080/ws',
      device_id: 'deadbeefcafe0001',
      token: 'a'.repeat(64),
      owner_email: 'björn@example.com',
    },
  },
  {
    name: 'boundary_seq_wrap',
    why: 'seq at the signed-32-bit boundary. Pins the wrap-safe comparison in config-format.md §3 — a naive `a > b` picks the wrong slot here.',
    config: {
      seq: 0xffffffff,
      ssid: 'X',
      wifi_auth: 'open',
      relay_url: 'wss://relay.roosterwake.com/ws',
      device_id: 'ffffffffffffffff',
      token: '0'.repeat(64),
    },
  },
];

const vectors = cases.map((c) => {
  const record = encode(c.config);
  if (record.length !== RECORD_LEN_V2) {
    throw new Error(`${c.name}: record is ${record.length} bytes, expected ${RECORD_LEN_V2}`);
  }
  // Round-trip immediately: a vector that does not decode back to its input is worse than
  // no vector at all, because it enshrines the bug on both sides.
  const back = decode(record);
  if (!back) throw new Error(`${c.name}: failed to decode its own encoding`);
  return {
    name: c.name,
    why: c.why,
    config: c.config,
    seq: c.config.seq,
    crc32: '0x' + crc32(record.subarray(HEADER_LEN)).toString(16).padStart(8, '0'),
    record_hex: hex(record),
    decoded: back,
  };
});

const doc = {
  $comment:
    'GENERATED FILE - do not hand-edit. Produced by tools/mkconfig/scripts/gen-vectors.mjs. ' +
    'Consumed by firmware/test/test_config.c AND tools/mkconfig/test/encode.test.mjs. ' +
    'If you change the encoder, regenerate this and update BOTH implementations in the same commit.',
  format_version: 2,
  header_len: HEADER_LEN,
  payload_len: PAYLOAD_LEN_V2,
  record_len: RECORD_LEN_V2,
  crc32_check_value: '0x' + crc32(new TextEncoder().encode('123456789')).toString(16),
  vectors,
};

// The CRC check value is the standard proof that we implemented CRC-32/ISO-HDLC and not one
// of the several other things people call "CRC32". If this assertion ever fails, every vector
// below it is wrong.
if (doc.crc32_check_value !== '0xcbf43926') {
  throw new Error(`CRC-32 self-check failed: got ${doc.crc32_check_value}, expected 0xcbf43926`);
}

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(doc, null, 2) + '\n');
console.log(`Wrote ${vectors.length} vectors to ${outPath}`);
console.log(`CRC-32 self-check: ${doc.crc32_check_value} OK`);
for (const v of vectors) console.log(`  ${v.name.padEnd(20)} crc=${v.crc32} seq=${v.seq}`);
