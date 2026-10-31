#!/usr/bin/env python3
"""bzip2, compress.bzip2 against Go's compress/bzip2, Python's bz2 and the
bzip2 program.

Decoding: streams made by Python's bz2 and the bzip2 program at every
block size, of data that is random, repetitive, text-like, made of long
runs, periodic, sawtooth or empty; one stream or several in a row; and
corrupted ones (a flipped bit, a byte changed, a cut end, bytes after the
end). tools/bzip2verdict.goose decodes each fed in pieces of 1 byte up with
output room of 1 byte up; its verdict must be Go's: the same bytes, or an
error (or an unfinished stream) where Go has an error. Where Python's bz2
disagrees with Go, that is counted and shown, not failed.

Encoding: our writer's output (every level, written in pieces of 1 byte
up) must decode to the input with Python's bz2, with Go, and with the
bzip2 program; its size is compared with bz2's at the same level.

    python3 scripts/bzip2_differential.py [--goose PATH] [--seed N] [--count N] [--debug] [-v]
"""

import argparse
import bz2
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zlib

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def payload(rng):
    kind = rng.randrange(8)
    n = rng.choice([0, 1, 2, 3, 4, 5, 10, 100, 1000, 5000, 40000, 120000, 250000])
    if kind == 0:
        return rng.randbytes(n)
    if kind == 1:
        return bytes([rng.randrange(4)]) * n
    if kind == 2:
        words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog", b"\n", b"<div>", b"</div>"]
        return b" ".join(rng.choice(words) for _ in range(n // 4 + 1))[:n]
    if kind == 3:
        unit = rng.randbytes(rng.randrange(1, 300))
        return (unit * (n // len(unit) + 1))[:n]
    if kind == 4:
        out = bytearray()
        while len(out) < n:
            out += bytes([rng.randrange(256)]) * rng.choice([1, 2, 3, 4, 5, 6, 250, 255, 256, 259, 260, 1000])
        return bytes(out[:n])
    if kind == 5:
        return bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))
    if kind == 6:
        return bytes(rng.randrange(256) for _ in range(min(n, 300)))
    return bytes(rng.choice(b"ab") for _ in range(n))


def compress(rng, data):
    level = rng.randrange(1, 10)
    if rng.random() < 0.15 and len(data) < 300000:
        p = subprocess.run(["bzip2", "-c", f"-{level}"], input=data, capture_output=True, check=True)
        return p.stdout
    return bz2.compress(data, level)


def corrupt(rng, s):
    k = rng.randrange(5)
    if len(s) == 0:
        return s + b"x"
    if k == 0:
        i = rng.randrange(len(s))
        return s[:i] + bytes([s[i] ^ (1 << rng.randrange(8))]) + s[i + 1:]
    if k == 1:
        i = rng.randrange(len(s))
        return s[:i] + bytes([rng.randrange(256)]) + s[i + 1:]
    if k == 2:
        return s[:rng.randrange(len(s))]
    if k == 3:
        return s + rng.choice([b"\x00", b"B", b"BZ", b"BZh", b"junk", b"\x00\x00\x00\x00"])
    # A bit flipped inside the block header, where the tables are.
    i = rng.randrange(4, min(len(s), 80))
    return s[:i] + bytes([s[i] ^ (1 << rng.randrange(8))]) + s[i + 1:]


def py_verdict(s):
    try:
        d = bz2.BZ2Decompressor()
        out = d.decompress(s)
        rest = d.unused_data
        # bz2.decompress takes streams one after another, as Go does.
        while d.eof and rest:
            d = bz2.BZ2Decompressor()
            out += d.decompress(rest)
            rest = d.unused_data
        if not d.eof:
            return "err"
        return f"ok {len(out)} {zlib.crc32(out):08x}"
    except Exception:
        return "err"


def build(goose, src, out, tmp, debug=False):
    exe = os.path.join(tmp, out)
    p = subprocess.run([goose, "build", *(["--debug"] if debug else []), "-o", exe, src], cwd=ROOT, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"building {src} failed:\n{p.stdout}{p.stderr}")
    return exe


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("-v", action="store_true")
    ap.add_argument("--debug", action="store_true", help="build the verdict tool with --debug (checked arithmetic)")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory() as tmp:
        verdict = build(goose, "tools/bzip2verdict.goose", "bzip2verdict", tmp, args.debug)
        oracle = os.path.join(tmp, "gooracle")
        subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"), check=True)

        # Decoding.
        streams = []
        for i in range(args.count):
            parts = [compress(rng, payload(rng)) for _ in range(1 if rng.random() < 0.8 else rng.randrange(2, 4))]
            s = b"".join(parts)
            if rng.random() < 0.35:
                s = corrupt(rng, s)
            streams.append(s)
        streams.append(b"")
        dcases = os.path.join(tmp, "d.txt")
        gcases = os.path.join(tmp, "g.txt")
        with open(dcases, "w") as f, open(gcases, "w") as g:
            for s in streams:
                h = s.hex() or "-"
                chunk = rng.choice([1, 2, 7, 100, 4096, 1 << 30]) if len(s) < 20000 else rng.choice([4096, 65536, 1 << 30])
                room = rng.choice([1, 3, 64, 65536]) if len(s) < 5000 else 65536
                f.write(f"d {chunk} {room} {h}\n")
                g.write(h + "\n")
        ours = subprocess.run([verdict, dcases], capture_output=True, text=True, check=True).stdout.split("\n")
        gos = subprocess.run([oracle, "bzip2", "-cases", gcases], capture_output=True, text=True, check=True).stdout.split("\n")
        fails = 0
        py_differs = 0
        accepted = refused = 0
        for i, s in enumerate(streams):
            o = ours[i]
            want = gos[i]
            got = "err" if o.startswith("err") or o == "short" else o
            if got != want:
                fails += 1
                if fails <= 10:
                    print(f"FAIL decode case {i} ({len(s)} bytes): ours {o!r}, Go {want!r}")
            if want == "err":
                refused += 1
            else:
                accepted += 1
            pv = py_verdict(s)
            if pv != want:
                py_differs += 1
                if args.v:
                    print(f"note: case {i}: Python {pv!r}, Go {want!r}")
        print(f"decode: {len(streams)} streams ({accepted} decoded, {refused} refused by Go), {fails} differ from Go; "
              f"Python's bz2 differs from Go on {py_differs}")

        # Encoding.
        payloads = [payload(rng) for _ in range(max(50, args.count // 4))]
        ecases = os.path.join(tmp, "e.txt")
        levels = []
        with open(ecases, "w") as f:
            for p in payloads:
                level = rng.randrange(1, 10)
                levels.append(level)
                chunk = rng.choice([1, 3, 1000, 1 << 30]) if len(p) < 50000 else rng.choice([4096, 1 << 30])
                f.write(f"c {level} {chunk} {p.hex() or '-'}\n")
        enc = subprocess.run([verdict, ecases], capture_output=True, text=True, check=True).stdout.split("\n")
        efails = 0
        same = 0
        ours_total = py_total = 0
        zs = []
        for i, p in enumerate(payloads):
            z = bytes.fromhex(enc[i])
            zs.append(z)
            ref = bz2.compress(p, levels[i])
            ours_total += len(z)
            py_total += len(ref)
            if z == ref:
                same += 1
            try:
                back = bz2.decompress(z)
            except Exception as e:
                back = None
            if back != p:
                efails += 1
                if efails <= 10:
                    print(f"FAIL encode case {i} ({len(p)} bytes, level {levels[i]}): Python's bz2 does not read it back")
        # Go reads each.
        gz = os.path.join(tmp, "gz.txt")
        with open(gz, "w") as g:
            for z in zs:
                g.write(z.hex() + "\n")
        gv = subprocess.run([oracle, "bzip2", "-cases", gz], capture_output=True, text=True, check=True).stdout.split("\n")
        for i, p in enumerate(payloads):
            if gv[i] != f"ok {len(p)} {zlib.crc32(p):08x}":
                efails += 1
                if efails <= 10:
                    print(f"FAIL encode case {i}: Go reads {gv[i]!r}")
        # The bzip2 program reads them all, one stream after another.
        cli = subprocess.run(["bzip2", "-dc"], input=b"".join(zs), capture_output=True)
        if cli.returncode != 0 or cli.stdout != b"".join(payloads):
            efails += 1
            print("FAIL encode: bzip2 -dc does not read the streams back")
        print(f"encode: {len(payloads)} inputs, {efails} failures; {same} byte-identical to bz2's output at the same level; "
              f"total {ours_total} bytes vs bz2's {py_total}")

        if fails or efails:
            sys.exit(1)
        print("bzip2 differential: all agree")


if __name__ == "__main__":
    main()
