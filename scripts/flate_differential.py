#!/usr/bin/env python3
"""DEFLATE, zlib and gzip decoding: compress.flate/zlib/gzip against Go.

Makes streams with Python's zlib (every level, the strategies that give
stored, fixed-Huffman, Huffman-only, RLE and dynamic blocks, small windows
and memory levels, many sync and full flushes, preset dictionaries) of data
that is random, repetitive, text-like and empty; wraps them as raw DEFLATE,
zlib (with and without a dictionary) and gzip (with the optional FEXTRA,
FNAME, FCOMMENT and FHCRC fields, reserved flag bits, names past Go's
limit, several members in a row); and corrupts a quarter of them (a flipped
bit, a cut end, a wrong CRC-32, Adler-32 or length, trailing bytes), and
replaces some with noise.
tools/flateverdict.goose decodes each, fed in chunks of 1 byte upward into
output buffers of 1 byte upward, and its result must be Go's (gooracle
inflate): the same bytes, or the same class of error after the same
bytes (Go hands out everything it decoded before an error, and so do we).

zlib's own verdict is reported beside, for information: Go and zlib differ
on a few inputs (gzip's reserved flags, Go's 511-byte name limit, bytes
after a gzip stream), and there Go is the reference.

    python3 scripts/flate_differential.py [--goose PATH] [--seed N] [--count N] [-v]
"""

import argparse
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def build_tools(goose, tmp):
    """The verdict tool built natively (the JIT where that fails), and gooracle."""
    exe = os.path.join(tmp, "flateverdict")
    p = subprocess.run([goose, "build", "-o", exe, "tools/flateverdict.goose"], cwd=ROOT,
                       capture_output=True, text=True)
    verdict = [exe] if p.returncode == 0 else [goose, "-O2", "tools/flateverdict.goose", "--"]
    oracle = os.path.join(tmp, "gooracle")
    p = subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("cannot build gooracle:\n" + p.stderr)
    return verdict, oracle


def payload(rng):
    kind = rng.randrange(6)
    n = rng.choice([0, 1, 2, 10, 100, 258, 1000, 5000, 32768, 40000, 70000, 140000])
    if kind == 0:
        return rng.randbytes(n)
    if kind == 1:
        return bytes([rng.randrange(4)]) * n
    if kind == 2:
        words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog", b"\n", b"<div>", b"</div>"]
        out = b" ".join(rng.choice(words) for _ in range(n // 4 + 1))
        return out[:n]
    if kind == 3:
        unit = rng.randbytes(rng.randrange(1, 300))
        return (unit * (n // len(unit) + 1))[:n]
    if kind == 4:
        # Skewed bytes: long Huffman codes for the rare ones.
        return bytes(min(255, int(rng.expovariate(0.15))) for _ in range(n))
    return bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))


def raw_deflate(rng, data, zdict=None, wbits=-15):
    level = rng.choice([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1])
    strategy = rng.choice([zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED, zlib.Z_HUFFMAN_ONLY, zlib.Z_RLE, zlib.Z_FILTERED])
    if zdict is not None:
        c = zlib.compressobj(level, zlib.DEFLATED, wbits, rng.choice([1, 8, 9]), strategy, zdict)
    else:
        c = zlib.compressobj(level, zlib.DEFLATED, wbits, rng.choice([1, 8, 9]), strategy)
    out = b""
    pos = 0
    while pos < len(data):
        step = rng.choice([len(data), 1, 7, 1000, 20000])
        out += c.compress(data[pos:pos + step])
        if rng.random() < 0.3:
            out += c.flush(rng.choice([zlib.Z_SYNC_FLUSH, zlib.Z_FULL_FLUSH]))
        pos += step
    return out + c.flush()


def gzip_member(rng, data):
    flg = 0
    extra = b""

    def field_len():
        return rng.choice([0, 1, 40, 300, 510, 511, 512, 3000])

    if rng.random() < 0.3:
        flg |= 4
        x = rng.randbytes(rng.choice([0, 1, 40, 3000, 65535]))
        extra += struct.pack("<H", len(x)) + x
    if rng.random() < 0.3:
        flg |= 8
        extra += bytes(rng.randrange(1, 256) for _ in range(field_len())) + b"\x00"
    if rng.random() < 0.3:
        flg |= 16
        extra += bytes(rng.randrange(1, 256) for _ in range(field_len())) + b"\x00"
    if rng.random() < 0.05:
        flg |= 0x20 << rng.randrange(3)    # reserved: Go ignores them, zlib refuses
    if rng.random() < 0.3:
        flg |= 2
    head = b"\x1f\x8b\x08" + bytes([flg]) + struct.pack("<I", rng.randrange(1 << 32)) + bytes(
        [rng.randrange(256), rng.randrange(256)]) + extra
    if flg & 2:
        head += struct.pack("<H", zlib.crc32(head) & 0xffff)
    return head + raw_deflate(rng, data) + struct.pack("<II", zlib.crc32(data), len(data) & 0xffffffff)


def zlib_stream(rng, data, zdict):
    if zdict is not None:
        wbits = rng.choice([9, 12, 15])
        return raw_deflate(rng, data, zdict, wbits)
    if rng.random() < 0.3:
        return zlib.compress(data, rng.choice([0, 1, 6, 9]))
    wbits = rng.choice([9, 10, 12, 15])
    return raw_deflate(rng, data, None, wbits)


def zlib_verdict(fmt, stream, zdict):
    """Python zlib's result, for information: bytes, or None for an error."""
    try:
        if fmt in ("gzip", "gzip1"):
            out = b""
            rest = stream
            first = True
            while first or rest:
                d = zlib.decompressobj(31)
                out += d.decompress(rest)
                if not d.eof:
                    return None
                rest = d.unused_data
                first = False
                if fmt == "gzip1":
                    break
            return out
        if fmt == "zlib":
            d = zlib.decompressobj(15, zdict) if zdict else zlib.decompressobj(15)
        else:
            d = zlib.decompressobj(-15, zdict) if zdict else zlib.decompressobj(-15)
        out = d.decompress(stream)
        if not d.eof:
            return None
        return out
    except (zlib.error, ValueError):
        return None


def corrupt(rng, s):
    k = rng.randrange(6)
    if not s:
        return s
    if k == 0:
        i = rng.randrange(len(s))
        return s[:i] + bytes([s[i] ^ (1 << rng.randrange(8))]) + s[i + 1:]
    if k == 1:
        return s[:rng.randrange(len(s))]
    if k == 2:
        return s[:-8] + bytes([s[-8] ^ 1]) + s[-7:] if len(s) > 8 else s[:-1]
    if k == 3:
        return s[:-1] + bytes([s[-1] ^ 0x80])
    if k == 4:
        i = rng.randrange(len(s))
        return s[:i] + rng.randbytes(rng.randrange(1, 9)) + s[i:]
    return s + rng.choice([b"\x00", b"junk", b"\x1f\x8b", b"0123456789abcdef", b"\x1f\x8b\x08\x00"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    cases = []
    for i in range(args.count):
        data = payload(rng)
        fmt = rng.choice(["gzip", "gzip", "gzip1", "zlib", "zlib", "raw", "raw"])
        zdict = None
        if fmt in ("zlib", "raw") and rng.random() < 0.25:
            zdict = payload(rng)[:rng.choice([1, 100, 32768, 40000])] or b"x"
        if fmt in ("gzip", "gzip1"):
            s = gzip_member(rng, data)
            if rng.random() < 0.2:
                s += gzip_member(rng, payload(rng))
        elif fmt == "zlib":
            s = zlib_stream(rng, data, zdict)
            if zdict is not None and rng.random() < 0.1:
                zdict = zdict[1:] + b"!"         # the wrong dictionary
        else:
            s = raw_deflate(rng, data, zdict)
        bad = rng.random() < 0.25
        if bad:
            s = corrupt(rng, s)
        if rng.random() < 0.03:
            # Noise: after a valid header, or none.
            noise = rng.randbytes(rng.choice([1, 10, 100, 3000]))
            s = (s[:rng.choice([0, 2, 10])] if fmt != "raw" else b"") + noise
            bad = True
        chunk = rng.choice([1, 2, 3, 7, 64, 1000, 65536, 1 << 20])
        room = rng.choice([1, 2, 3, 100, 258, 4096, 65536, 1 << 20])
        cases.append((fmt, chunk, room, s, zdict, bad))
    with tempfile.TemporaryDirectory() as tmp:
        verdict, oracle = build_tools(goose, tmp)
        ours_path = os.path.join(tmp, "ours.txt")
        go_path = os.path.join(tmp, "go.txt")
        with open(ours_path, "w") as f, open(go_path, "w") as g:
            for fmt, chunk, room, s, zdict, _ in cases:
                d = "" if zdict is None else " " + (zdict.hex() or "-")
                f.write(f"{fmt} {chunk} {room} {s.hex() or '-'}{d}\n")
                g.write(f"{fmt} {s.hex() or '-'}{d}\n")
        p = subprocess.run(verdict + [ours_path], cwd=ROOT, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("flateverdict failed:\n" + p.stderr)
        ours = p.stdout.splitlines()
        p = subprocess.run([oracle, "inflate", go_path], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("gooracle failed:\n" + p.stderr)
        gos = p.stdout.splitlines()
    if len(ours) != len(cases) or len(gos) != len(cases):
        sys.exit(f"{len(ours)} and {len(gos)} results for {len(cases)} cases")
    diffs = 0
    go_errors = 0
    zlib_disagree = 0
    for (fmt, chunk, room, s, zdict, bad), got, want in zip(cases, ours, gos):
        if not want.startswith("ok"):
            go_errors += 1
        z = zlib_verdict(fmt, s, zdict)
        zv = "err" if z is None else f"ok {len(z)} {zlib.crc32(z):08x}"
        if (zv == "err") != (not want.startswith("ok")) or (z is not None and zv != want):
            zlib_disagree += 1
        if got != want and want.startswith("err eof") and got.startswith("err truncated") and not s:
            # Go's gzip.NewReader says io.EOF for no input at all; this
            # package says ERR_TRUNCATED (README, departures).
            continue
        if got != want:
            diffs += 1
            if args.v or diffs <= 20:
                print(f"DIFF {fmt} chunk={chunk} room={room} bad={bad} len={len(s)} dict={zdict is not None}: "
                      f"ours {got!r}, Go {want!r}, zlib {zv!r}")
    print(f"{len(cases)} streams ({go_errors} Go refuses; zlib's verdict differs from Go's on {zlib_disagree}), "
          f"{diffs} differ from Go")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
