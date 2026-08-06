#!/usr/bin/env python3
"""Wrap a firmware binary in the signed image header the device accepts.

    python tools/sign_image.py build-pico_w/roosterwake.bin out.rwfw \
        --key ~/.roosterwake/firmware-signing.pem --version 1.6.0 --board PW

The layout is specified in src/ota/image.h; this is the only thing that writes it and
src/ota/image.c is the only thing that reads it, so the two are checked against each other by
firmware/test/test_ota_image.c rather than by inspection.

Depends on `openssl` on PATH, not on a Python crypto package, so the release job needs nothing
installed that it does not already have.

SPDX-License-Identifier: MIT
"""

import argparse
import hashlib
import pathlib
import re
import struct
import subprocess
import sys
import tempfile

HEADER_LEN = 128
MAGIC = b"RWFW"
FORMAT_VERSION = 1
SIGNED_BYTES = 64

BOARD_TAGS = {"pico_w": "PW", "pico2_w": "P2W"}


def der_to_raw(der: bytes) -> bytes:
    """ECDSA signatures come out of openssl as DER SEQUENCE{INTEGER r, INTEGER s}.

    The device compares fixed-width big-endian halves, so r and s are unpacked and re-emitted as
    32 bytes each: DER drops leading zero bytes and adds one when the top bit is set, so a raw
    slice of the DER is wrong roughly half the time and only for some keys — the kind of bug that
    passes every local test and fails in the field.
    """
    if der[0] != 0x30:
        raise ValueError("signature is not a DER SEQUENCE")
    # SEQUENCE header: 0x30, length (short form is enough for a P-256 signature).
    idx = 2
    out = []
    for _ in range(2):
        if der[idx] != 0x02:
            raise ValueError("expected a DER INTEGER in the signature")
        length = der[idx + 1]
        value = der[idx + 2 : idx + 2 + length]
        idx += 2 + length
        value = value.lstrip(b"\x00")
        if len(value) > 32:
            raise ValueError("signature component wider than P-256")
        out.append(value.rjust(32, b"\x00"))
    return b"".join(out)


def sign(digest: bytes, key: pathlib.Path) -> bytes:
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(digest)
        digest_path = f.name
    try:
        der = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", str(key), "-in", digest_path,
             "-pkeyopt", "digest:sha256"],
            check=True, capture_output=True,
        ).stdout
    finally:
        pathlib.Path(digest_path).unlink(missing_ok=True)
    return der_to_raw(der)


def build_header(payload: bytes, version: str, board: str) -> bytes:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise SystemExit(f"version {version!r} is not N.N.N")
    if len(version) > 16:
        raise SystemExit("version string does not fit 16 bytes")
    if len(board) > 4:
        raise SystemExit("board tag does not fit 4 bytes")

    header = bytearray(HEADER_LEN)
    header[0:4] = MAGIC
    struct.pack_into("<HHI", header, 4, FORMAT_VERSION, 0, len(payload))
    header[12 : 12 + len(version)] = version.encode()
    header[28 : 28 + len(board)] = board.encode()
    header[32:64] = hashlib.sha256(payload).digest()
    return bytes(header)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("binary", type=pathlib.Path, help="raw flash image (.bin)")
    ap.add_argument("output", type=pathlib.Path, help="signed image to write (.rwfw)")
    ap.add_argument("--key", type=pathlib.Path, required=True, help="EC P-256 private key (PEM)")
    ap.add_argument("--version", required=True, help="firmware version, N.N.N")
    ap.add_argument("--board", required=True, choices=sorted(BOARD_TAGS) + sorted(BOARD_TAGS.values()))
    args = ap.parse_args()

    board = BOARD_TAGS.get(args.board, args.board)
    payload = args.binary.read_bytes()
    if not payload:
        raise SystemExit(f"{args.binary} is empty")

    header = build_header(payload, args.version, board)
    signature = sign(hashlib.sha256(header[:SIGNED_BYTES]).digest(), args.key)
    if len(signature) != 64:
        raise SystemExit("signature is not 64 bytes")

    args.output.write_bytes(header[:64] + signature + payload)
    print(f"{args.output}: {len(payload)} bytes, version {args.version}, board {board}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
