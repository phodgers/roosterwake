#!/usr/bin/env python3
"""
Compress a file and emit it as a C array.

Used by the firmware build to turn src/provisioning/portal/portal.html into portal_html.h. The
output is deterministic: mtime is forced to zero in the gzip header, so two builds of the same
commit produce byte-identical firmware. Without that, every rebuild would change the image and
a reproducible-build check would be impossible.

    gzip_header.py <input> <output.h> <symbol>

SPDX-License-Identifier: MIT
"""
import gzip
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2

    src, dst, symbol = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    raw = src.read_bytes()

    # mtime=0 for reproducibility; level 9 because this runs once per build and the result sits
    # in flash for the life of the device.
    blob = gzip.compress(raw, compresslevel=9, mtime=0)

    lines = [
        "/*",
        f" * Generated from {src.name} by tools/gzip_header.py. Do not edit.",
        " *",
        f" * {len(raw)} bytes of source compressed to {len(blob)}"
        f" ({100 * len(blob) // max(len(raw), 1)}%).",
        " *",
        " * SPDX-License-Identifier: MIT",
        " */",
        "#ifndef RW_PORTAL_HTML_H",
        "#define RW_PORTAL_HTML_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"static const size_t {symbol}_len = {len(blob)};",
        "",
        # `const` at file scope in a header included once puts this straight into .rodata, which
        # is exactly where a 6 KB constant belongs on a device with 520 KB of SRAM.
        f"static const uint8_t {symbol}[] = {{",
    ]

    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        lines.append("    " + " ".join(f"0x{b:02x}," for b in chunk))

    lines += ["};", "", "#endif /* RW_PORTAL_HTML_H */", ""]

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text("\n".join(lines), encoding="utf-8")

    print(f"portal: {len(raw)} -> {len(blob)} bytes gzipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
