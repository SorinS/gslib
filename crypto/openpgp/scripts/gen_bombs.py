#!/usr/bin/env python3
"""Makes the decompression bombs in test/vectors, for test/roundtrip.goose:

  bomb_zip.gpg     a Compressed Data packet (ZIP) holding another, which
                   holds a literal of 1000 MiB of zeros: 1,777 bytes
  bomb_bzip2.gpg   a Compressed Data packet (BZip2) of 1000 MiB of zeros
                   and no literal: 760 bytes

    python3 scripts/gen_bombs.py
"""

import bz2
import os
import zlib

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "test", "vectors")
N = 1000 << 20
CHUNK = b"\0" * (1 << 24)


def packet(tag, body):
    # New format, five-octet length.
    return bytes([0xC0 | tag, 0xFF]) + len(body).to_bytes(4, "big") + body


def zeros(c):
    out = b""
    left = N
    while left:
        k = min(left, len(CHUNK))
        out += c.compress(CHUNK[:k])
        left -= k
    return out


def main():
    # The literal's header (format 'b', no name, date 0), then its zeros,
    # deflated in pieces.
    n = 6 + N
    lit_hdr = bytes([0xCB, 0xFF]) + n.to_bytes(4, "big") + b"b\0\0\0\0\0"
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    inner = c.compress(lit_hdr) + zeros(c) + c.flush()
    p1 = packet(8, b"\x01" + inner)
    c2 = zlib.compressobj(9, zlib.DEFLATED, -15)
    outer = c2.compress(p1) + c2.flush()
    with open(os.path.join(OUT, "bomb_zip.gpg"), "wb") as f:
        f.write(packet(8, b"\x01" + outer))

    b = bz2.BZ2Compressor(9)
    body = b"\x03" + zeros(b) + b.flush()
    with open(os.path.join(OUT, "bomb_bzip2.gpg"), "wb") as f:
        f.write(packet(8, body))
    print("wrote", OUT)


if __name__ == "__main__":
    main()
