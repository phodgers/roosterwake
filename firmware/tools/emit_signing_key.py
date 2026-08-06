#!/usr/bin/env python3
"""Emit src/ota/signing_key.c from a public key.

    python tools/emit_signing_key.py ~/.roosterwake/firmware-signing.pem > src/ota/signing_key.c

Takes either half of the pair: a private key file works, and only its public point is used. The
generated file is committed, because a build must not depend on anyone holding a key — only
signing does.

SPDX-License-Identifier: MIT
"""

import argparse
import pathlib
import subprocess
import sys


def public_point(key: pathlib.Path) -> bytes:
    """The 64-byte X||Y of a P-256 public key.

    A DER SubjectPublicKeyInfo for P-256 ends with the 0x04 uncompressed marker followed by the
    two 32-byte coordinates, so the last 64 bytes are the point without its prefix. Verified
    against the marker rather than assumed.
    """
    der = subprocess.run(
        ["openssl", "ec", "-in", str(key), "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    if len(der) < 65 or der[-65] != 0x04:
        raise SystemExit("not an uncompressed P-256 public key")
    return der[-64:]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("key", type=pathlib.Path)
    ap.add_argument("--name", default="development", help="what this key is, for the comment")
    args = ap.parse_args()

    point = public_point(args.key)
    rows = "\n".join(
        "    " + " ".join(f"0x{b:02x}," for b in point[i : i + 8]) for i in range(0, 64, 8)
    )
    fingerprint = subprocess.run(
        ["openssl", "ec", "-in", str(args.key), "-pubout", "-outform", "DER"],
        check=True, capture_output=True,
    ).stdout
    import hashlib

    sys.stdout.write(
        "/*\n"
        " * The public key firmware updates are checked against. Generated; do not edit.\n"
        " *\n"
        f" *   tools/emit_signing_key.py <key.pem> > src/ota/signing_key.c\n"
        " *\n"
        f" * Key: {args.name}\n"
        f" * SPKI SHA-256: {hashlib.sha256(fingerprint).hexdigest()}\n"
        " *\n"
        " * Only the public half is here, and it is safe to publish. Changing this key means\n"
        " * devices already in the field stop accepting updates signed by the old one, so a\n"
        " * rotation has to ship in a release signed by the OLD key first.\n"
        " *\n"
        " * SPDX-License-Identifier: MIT\n"
        " */\n"
        '#include "ota/signing_key.h"\n'
        "\n"
        "const uint8_t rw_ota_public_key[RW_OTA_PUBKEY_LEN] = {\n"
        f"{rows}\n"
        "};\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
