#!/usr/bin/env python3
"""Combine UF2 files into one, renumbering the blocks.

    python tools/merge_uf2.py factory.uf2 build-loader/loader.uf2 build-slot-a/remotewake.uf2

A factory image is the loader plus an image in slot A, and each is built separately because they
are linked into different regions. Concatenating the files byte-for-byte very nearly works and is
wrong in one way that matters: every block carries its own index and the total count, and the
bootloader uses those to decide when the transfer is finished. A naive join leaves two blocks
numbered 0 and a total that describes only the first file, so the device reboots part-way through
writing the second.

SPDX-License-Identifier: MIT
"""

import argparse
import pathlib
import struct
import sys

BLOCK = 512
MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30


def blocks(data: bytes, name: str):
    if len(data) % BLOCK:
        raise SystemExit(f"{name} is not a whole number of 512-byte blocks")
    for i in range(0, len(data), BLOCK):
        b = bytearray(data[i : i + BLOCK])
        m0, m1 = struct.unpack_from("<II", b, 0)
        (end,) = struct.unpack_from("<I", b, 508)
        if m0 != MAGIC0 or m1 != MAGIC1 or end != MAGIC_END:
            raise SystemExit(f"{name}: block {i // BLOCK} is not a UF2 block")
        yield b


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("output", type=pathlib.Path)
    ap.add_argument("inputs", type=pathlib.Path, nargs="+")
    args = ap.parse_args()

    merged = []
    for src in args.inputs:
        merged.extend(blocks(src.read_bytes(), str(src)))

    total = len(merged)
    for index, b in enumerate(merged):
        struct.pack_into("<I", b, 20, index)
        struct.pack_into("<I", b, 24, total)

    # Report what is being written where, so a mistake in the layout is visible before flashing.
    ranges = []
    for b in merged:
        addr, size = struct.unpack_from("<II", b, 12)
        if ranges and addr == ranges[-1][1]:
            ranges[-1][1] = addr + size
        else:
            ranges.append([addr, addr + size])

    args.output.write_bytes(b"".join(bytes(b) for b in merged))
    print(f"{args.output}: {total} blocks")
    for lo, hi in ranges:
        print(f"  0x{lo:08x} .. 0x{hi:08x}  ({(hi - lo) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
