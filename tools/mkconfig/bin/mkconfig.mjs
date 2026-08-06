#!/usr/bin/env node
/**
 * mkconfig — generate a data-only UF2 that provisions a Rooster Wake dongle.
 *
 * Drag the resulting file onto the BOOTSEL drive and the device comes up configured, with no
 * captive-portal step. This is the open mechanism behind "Path 3" provisioning; the hosted
 * dashboard's personalised generator is built on exactly this format.
 *
 * Zero dependencies. Run it with `npx`, or clone the repo and run it directly.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import {
  encode,
  decode,
  GENERATED_SEQ,
  SLOT_A_XIP,
  SLOT_B_XIP,
  SECTOR_SIZE,
  BOARDS,
  DEFAULT_BOARD,
  slotAddresses,
  ConfigError,
} from '../lib/config.mjs';
import { buildUf2, parseUf2, flattenUf2, FAMILY, FAMILY_NAME } from '../lib/uf2.mjs';

const USAGE = `
mkconfig — generate a Rooster Wake configuration UF2

USAGE
  mkconfig [options] --out <file.uf2>
  mkconfig --verify <file.uf2>

WI-FI
  --ssid <name>            Wi-Fi network name (max 32 bytes)
  --psk <password>         Wi-Fi password (max 64 bytes; omit for an open network)
  --auth <mode>            open | wpa2 | wpa3 | auto        [default: auto]

RELAY
  --relay <url>            Relay WebSocket URL (ws:// or wss://, max 128 bytes)
                           [default: wss://relay.roosterwake.com/ws]
  --device-id <hex16>      Device ID, 16 lower-case hex chars. Generated if omitted.
  --token <hex64>          Device token, 64 lower-case hex chars. Generated if omitted.
  --email <address>        Account address to adopt to (hosted service only)

FLAGS
  --insecure-tls           Skip TLS certificate verification. For homelab self-signed certs
                           only. The device flashes its error pattern continuously while set.
  --diag-log               Send diagnostic log frames to the relay.
  --wol-unicast            Also send magic packets unicast to the target's last-known IP.

OUTPUT
  --out <file>             Output path. Conventionally roosterwake-config.uf2
  --board <name>           Target board: pico2_w or pico_w       [default: pico2_w]
  --slot <a|b>             Which config slot to write            [default: b]
  --seq <n>                Sequence number                       [default: ${GENERATED_SEQ}]
  --family <name|hex>      UF2 family ID                         [default: RP2350_ARM_S]
  --json                   Print the configuration as JSON instead of writing a UF2
  --verify <file>          Decode an existing UF2 and print what it contains

EXAMPLES
  # Typical: put the dongle on a home network
  mkconfig --ssid "HomeNet" --psk "hunter2" \\
           --out roosterwake-config.uf2

  # Self-hosted relay, credentials you chose yourself
  mkconfig --ssid "HomeNet" --psk "hunter2" \\
           --relay "wss://wake.example.com/ws" \\
           --device-id a1b2c3d4e5f60718 --token $(openssl rand -hex 32) \\
           --out roosterwake-config.uf2

  # Inspect a file someone sent you before trusting it
  mkconfig --verify roosterwake-config.uf2

NOTE
  There is no option here for the machines you want to wake. A device is told which MAC to
  wake in the frame that asks (PROTOCOL.md section 5), so the list lives with whoever sends
  the wakes — your account, or your own relay's records.

  The generated file contains your Wi-Fi password and device token in PLAIN TEXT. Treat it
  like a password file: do not commit it, do not email it, delete it once the device is
  provisioned. See firmware/docs/config-format.md section 8.
`;

function parseArgs(argv) {
  const out = { flags: 0 };
  const wantsValue = new Set([
    'ssid', 'psk', 'auth', 'relay', 'device-id', 'token', 'email',
    'out', 'slot', 'seq', 'family', 'verify', 'board',
  ]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') return { help: true };
    if (!arg.startsWith('--')) throw new Error(`Unexpected argument: ${arg}`);
    const key = arg.slice(2);

    if (wantsValue.has(key)) {
      const value = argv[++i];
      if (value === undefined) throw new Error(`--${key} needs a value`);
      out[key.replace(/-/g, '_')] = value;
      continue;
    }
    switch (key) {
      case 'insecure-tls': out.insecure_tls = true; break;
      case 'diag-log': out.diag_log = true; break;
      case 'wol-unicast': out.wol_unicast = true; break;
      case 'json': out.json = true; break;
      default: throw new Error(`Unknown option: ${arg}`);
    }
  }
  return out;
}

/* Returns null when unspecified, so the caller can fall back to the board's own family rather
 * than a constant that would be wrong for half the boards we support. */
function resolveFamily(spec) {
  if (!spec) return null;
  const named = FAMILY[spec.toUpperCase()];
  if (named !== undefined) return named;
  const n = Number(spec);
  if (Number.isInteger(n) && n > 0) return n >>> 0;
  throw new Error(`Unknown --family "${spec}". Known: ${Object.keys(FAMILY).join(', ')}, or a hex value.`);
}

function doVerify(path) {
  const bytes = new Uint8Array(readFileSync(path));
  const blocks = parseUf2(bytes);
  if (!blocks) {
    console.error(`${path} is not a valid UF2 file.`);
    process.exit(1);
  }
  const flat = flattenUf2(blocks);
  if (!flat) {
    console.error(`${path} contains non-contiguous blocks; refusing to guess at the gaps.`);
    process.exit(1);
  }
  const cfg = decode(flat.data);
  console.log(`File:      ${path}`);
  console.log(`Blocks:    ${blocks.length} (${bytes.length} bytes)`);
  console.log(`Address:   0x${flat.base.toString(16).toUpperCase()}`);
  console.log(`Family:    ${FAMILY_NAME[flat.familyId] ?? 'unknown'} (0x${(flat.familyId ?? 0).toString(16)})`);
  if (!cfg) {
    console.error('\nPayload is not a valid Rooster Wake config record (bad magic, version, or CRC).');
    process.exit(1);
  }
  console.log(`\nConfiguration (v${cfg.version}, seq ${cfg.seq}):`);
  console.log(`  SSID:      ${cfg.ssid || '(unset)'}`);
  console.log(`  Password:  ${cfg.psk ? '(set, ' + cfg.psk.length + ' chars — not shown)' : '(unset)'}`);
  console.log(`  Auth:      ${cfg.wifi_auth}`);
  console.log(`  Relay:     ${cfg.relay_url || '(default)'}`);
  console.log(`  Device ID: ${cfg.device_id || '(unset)'}`);
  console.log(`  Token:     ${cfg.token ? '(set — not shown)' : '(unset)'}`);
  console.log(`  Email:     ${cfg.owner_email || '(none)'}`);
  console.log(`  Flags:     0x${cfg.flags.toString(16).padStart(8, '0')}`);
}

function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e.message + '\n');
    console.error('Run mkconfig --help for usage.');
    process.exit(2);
  }

  if (args.help || process.argv.length === 2) {
    console.log(USAGE.trim());
    process.exit(args.help ? 0 : 2);
  }

  if (args.verify) return doVerify(args.verify);

  const cfg = {
    ssid: args.ssid,
    psk: args.psk,
    wifi_auth: args.auth ?? 'auto',
    relay_url: args.relay ?? 'wss://relay.roosterwake.com/ws',
    device_id: args.device_id ?? randomBytes(8).toString('hex'),
    token: args.token ?? randomBytes(32).toString('hex'),
    owner_email: args.email,
    flags:
      (args.insecure_tls ? 1 : 0) |
      (args.diag_log ? 2 : 0) |
      (args.wol_unicast ? 4 : 0),
    seq: args.seq !== undefined ? Number(args.seq) : GENERATED_SEQ,
  };

  if (!args.json && !args.out) {
    console.error('--out <file.uf2> is required (or use --json to preview).\n');
    process.exit(2);
  }

  let record;
  try {
    record = encode(cfg);
  } catch (e) {
    if (e instanceof ConfigError) {
      console.error(`Invalid configuration — ${e.message}`);
      process.exit(2);
    }
    throw e;
  }

  if (args.json) {
    console.log(JSON.stringify(decode(record), null, 2));
    return;
  }

  const slot = (args.slot ?? 'b').toLowerCase();
  if (slot !== 'a' && slot !== 'b') {
    console.error(`--slot must be "a" or "b", got "${slot}"`);
    process.exit(2);
  }

  const boardName = (args.board ?? DEFAULT_BOARD).toLowerCase();
  const board = BOARDS[boardName];
  if (!board) {
    console.error(`--board must be one of ${Object.keys(BOARDS).join(', ')}, got "${boardName}"`);
    process.exit(2);
  }

  // The config lives in the top two sectors of whatever flash this board has, so the address
  // follows the board. --family still overrides, for anyone doing something we have not thought
  // of; without it the family follows the board too, because an address/family mismatch is the
  // one combination that can write a config record into the middle of the firmware image.
  const { a: slotA, b: slotB } = slotAddresses(board.flashSize);
  const addr = slot === 'a' ? slotA : slotB;

  // Pad to a whole sector so the tail is explicitly zeroed rather than left holding whatever
  // was in flash before. config-format.md §5.
  const uf2 = buildUf2(record, addr, resolveFamily(args.family) ?? board.family, SECTOR_SIZE);
  writeFileSync(args.out, uf2);

  console.log(`Wrote ${args.out}`);
  console.log(`  ${uf2.length} bytes, ${uf2.length / 512} blocks -> 0x${addr.toString(16).toUpperCase()} (slot ${slot.toUpperCase()}, ${boardName} / ${board.chip})`);
  console.log(`  Device ID: ${cfg.device_id}`);
  if (!args.token) {
    console.log(`  Token:     ${cfg.token}`);
    console.log('\n  A token was generated for you. If you are self-hosting, add this device to');
    console.log('  your relay\'s config.json now — you will not be shown it again.');
  }
  console.log('\nHold BOOTSEL while plugging the Pico in, then drag this file onto the drive.');
  if (cfg.psk) {
    console.log('\nThis file contains your Wi-Fi password in plain text. Delete it once the');
    console.log('device is provisioned.');
  }
}

main();
