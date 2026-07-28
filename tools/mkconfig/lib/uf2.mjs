/**
 * Minimal UF2 reader/writer, just enough to emit a data-only config image.
 *
 * UF2 is Microsoft's format for drag-and-drop flashing over USB mass storage. Each block is a
 * self-contained 512-byte record naming its own target address, which is precisely why this
 * works: the RP2350 bootloader writes whatever address a block names and does not check that
 * the payload is executable code. That is what lets us ship a "firmware image" that is really
 * just a configuration record for one flash sector.
 *
 * Reference: https://github.com/microsoft/uf2
 * Zero dependencies — see the note at the top of config.mjs.
 */

export const BLOCK_SIZE = 512;
export const PAYLOAD_PER_BLOCK = 256; // The format allows up to 476; 256 is what the RP2 tools use.

const MAGIC_START0 = 0x0a324655; // "UF2\n"
const MAGIC_START1 = 0x9e5d5157;
const MAGIC_END = 0x0ab16f30;

const FLAG_FAMILY_ID_PRESENT = 0x00002000;
const FLAG_NOT_MAIN_FLASH = 0x00000001;

/**
 * RP2 family IDs.
 *
 * `RP2350_ARM_S` is the default for a config image. There is also a generic `DATA` family
 * (0xe48bff58) which looks like the semantically correct choice, but the RP2350 bootloader's
 * acceptance of it for an arbitrary flash address is not something we have confirmed on real
 * hardware yet — so the default is the family we know the bootloader accepts, and `--family`
 * exists to switch without a code change. See config-format.md §5.
 */
export const FAMILY = {
  RP2040: 0xe48bff56,
  ABSOLUTE: 0xe48bff57,
  DATA: 0xe48bff58,
  RP2350_ARM_S: 0xe48bff59,
  RP2350_RISCV: 0xe48bff5a,
  RP2350_ARM_NS: 0xe48bff5b,
};

export const FAMILY_NAME = Object.fromEntries(Object.entries(FAMILY).map(([k, v]) => [v, k]));

/**
 * Build a UF2 image that writes `data` to `baseAddr`.
 *
 * @param {Uint8Array} data      Bytes to write. Padded with zeros to a whole number of blocks.
 * @param {number} baseAddr      Flash XIP address of the first byte.
 * @param {number} familyId
 * @param {number} [padTo]       Pad to this total length before splitting (e.g. a full 4096-byte
 *                               sector, so the remainder is explicitly zeroed rather than left
 *                               holding whatever was there before).
 * @returns {Uint8Array}
 */
export function buildUf2(data, baseAddr, familyId = FAMILY.RP2350_ARM_S, padTo = 0) {
  const total = Math.max(data.length, padTo);
  const padded = new Uint8Array(Math.ceil(total / PAYLOAD_PER_BLOCK) * PAYLOAD_PER_BLOCK);
  padded.set(data, 0);

  const numBlocks = padded.length / PAYLOAD_PER_BLOCK;
  const out = new Uint8Array(numBlocks * BLOCK_SIZE);
  const view = new DataView(out.buffer);

  for (let i = 0; i < numBlocks; i++) {
    const off = i * BLOCK_SIZE;
    view.setUint32(off + 0x00, MAGIC_START0, true);
    view.setUint32(off + 0x04, MAGIC_START1, true);
    view.setUint32(off + 0x08, FLAG_FAMILY_ID_PRESENT, true);
    view.setUint32(off + 0x0c, baseAddr + i * PAYLOAD_PER_BLOCK, true);
    view.setUint32(off + 0x10, PAYLOAD_PER_BLOCK, true);
    view.setUint32(off + 0x14, i, true);
    view.setUint32(off + 0x18, numBlocks, true);
    view.setUint32(off + 0x1c, familyId, true);
    out.set(padded.subarray(i * PAYLOAD_PER_BLOCK, (i + 1) * PAYLOAD_PER_BLOCK), off + 0x20);
    view.setUint32(off + BLOCK_SIZE - 4, MAGIC_END, true);
  }
  return out;
}

/**
 * Parse a UF2 image back into its blocks. Used by `mkconfig --verify`, and by the tests, so
 * that "we can write it" is never mistaken for "we can write something readable".
 *
 * Returns null if the file is not valid UF2, rather than throwing — callers are inspecting
 * files a user handed them, and a malformed file is an expected input, not an exception.
 */
export function parseUf2(bytes) {
  if (!bytes || bytes.length === 0 || bytes.length % BLOCK_SIZE !== 0) return null;

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const blocks = [];

  for (let off = 0; off < bytes.length; off += BLOCK_SIZE) {
    if (
      view.getUint32(off + 0x00, true) !== MAGIC_START0 ||
      view.getUint32(off + 0x04, true) !== MAGIC_START1 ||
      view.getUint32(off + BLOCK_SIZE - 4, true) !== MAGIC_END
    ) {
      return null;
    }
    const flags = view.getUint32(off + 0x08, true);
    const payloadSize = view.getUint32(off + 0x10, true);
    if (payloadSize > BLOCK_SIZE - 32 - 4) return null;

    blocks.push({
      flags,
      targetAddr: view.getUint32(off + 0x0c, true),
      payloadSize,
      blockNo: view.getUint32(off + 0x14, true),
      numBlocks: view.getUint32(off + 0x18, true),
      familyId: flags & FLAG_FAMILY_ID_PRESENT ? view.getUint32(off + 0x1c, true) : null,
      notMainFlash: Boolean(flags & FLAG_NOT_MAIN_FLASH),
      data: bytes.subarray(off + 0x20, off + 0x20 + payloadSize),
    });
  }
  return blocks;
}

/**
 * Flatten parsed blocks into a contiguous buffer plus its base address.
 * Returns null if the blocks are not contiguous — a gap means we would be inventing bytes we
 * were never given, and silently zero-filling a hole in a config record is exactly the kind of
 * quiet corruption this whole format is designed to make impossible.
 */
export function flattenUf2(blocks) {
  if (!blocks || blocks.length === 0) return null;
  const sorted = [...blocks].sort((a, b) => a.targetAddr - b.targetAddr);
  const base = sorted[0].targetAddr;

  let expected = base;
  let size = 0;
  for (const b of sorted) {
    if (b.targetAddr !== expected) return null;
    expected += b.payloadSize;
    size += b.payloadSize;
  }

  const out = new Uint8Array(size);
  let pos = 0;
  for (const b of sorted) {
    out.set(b.data, pos);
    pos += b.payloadSize;
  }
  return { base, data: out, familyId: sorted[0].familyId };
}
