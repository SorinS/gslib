#!/usr/bin/env python3
"""DEFLATE, zlib and gzip compression: compress.deflate/zlib/gzip's output
read back by Go and by Python's zlib, and its size against Go's.

For thousands of inputs (random, repetitive, text-like, skewed, long runs,
empty; up to 300 KB) at every level (-2 HuffmanOnly, -1, 0-9), as raw
DEFLATE, zlib and gzip, with and without a preset dictionary (raw and
zlib), written by tools/deflateverdict.goose in pieces of 1 byte upward
with Flush at random intervals: Go's readers (gooracle inflate) and
Python's zlib (and, for up to 300 gzip streams, the gzip program) must
give back exactly the input, and at each Flush the
stream so far must decode (zlib's decompressobj, no flush of its own) to
everything written so far. Go's own compressor compresses the same inputs
(gooracle deflate, without the flushes), and the totals per level are
reported, ours against Go's.

    python3 scripts/deflate_differential.py [--goose PATH] [--seed N] [--count N] [-v]
"""

import argparse
import collections
import os
import random
import shutil
import subprocess
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(__file__))
from flate_differential import ROOT, find_goose  # noqa: E402

LEVELS = [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]


def payload(rng):
    kind = rng.randrange(8)
    n = rng.choice([0, 1, 2, 3, 4, 10, 100, 258, 259, 1000, 5000, 32768, 32769, 65535, 65536, 70000, 140000, 300000])
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
        return bytes(min(255, int(rng.expovariate(0.15))) for _ in range(n))
    if kind == 5:
        # Runs of random lengths, matches at every distance.
        out = bytearray()
        while len(out) < n:
            if out and rng.random() < 0.6:
                d = rng.randrange(1, min(len(out), 32768) + 1)
                l = rng.randrange(3, 300)
                for _ in range(l):
                    out.append(out[-d])
            else:
                out += rng.randbytes(rng.randrange(1, 20))
        return bytes(out[:n])
    if kind == 6:
        return bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))
    return open(os.path.join(ROOT, "deflate.goose"), "rb").read()[:n]


def go_decode(oracle, tmp, items):
    path = os.path.join(tmp, "go_in.txt")
    with open(path, "w") as f:
        for fmt, stream, zdict in items:
            d = "" if zdict is None else " " + (zdict.hex() or "-")
            f.write(f"{fmt} {stream.hex() or '-'}{d}\n")
    p = subprocess.run([oracle, "inflate", path], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("gooracle failed:\n" + p.stderr)
    return p.stdout.splitlines()


def zlib_decode(fmt, stream, zdict, partial=False):
    wbits = {"raw": -15, "zlib": 15, "gzip": 31}[fmt]
    d = zlib.decompressobj(wbits, zdict) if zdict is not None else zlib.decompressobj(wbits)
    out = d.decompress(stream)
    if not partial and not d.eof:
        raise zlib.error("not at the end")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=1500)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    cases = []
    for i in range(args.count):
        data = payload(rng)
        fmt = rng.choice(["raw", "zlib", "gzip"])
        level = rng.choice(LEVELS)
        zdict = None
        if fmt != "gzip" and level not in (0, -2) and rng.random() < 0.2:
            zdict = payload(rng)[:rng.choice([1, 100, 32768, 40000])] or b"x"
        chunk = rng.choice([1, 2, 7, 100, 4096, 65536, 1 << 30]) if len(data) < 100000 else rng.choice([4096, 1 << 30])
        flush = rng.choice([0, 0, 0, 1, 100, 5000, 40000])
        if flush and len(data) // flush > 300:
            flush = len(data) // 300 + 1
        cases.append((fmt, level, chunk, flush, data, zdict))
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "deflateverdict")
        p = subprocess.run([goose, "build", "-o", exe, "tools/deflateverdict.goose"], cwd=ROOT, capture_output=True,
                           text=True)
        verdict = [exe] if p.returncode == 0 else [goose, "-O2", "tools/deflateverdict.goose", "--"]
        oracle = os.path.join(tmp, "gooracle")
        subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"), check=True)
        path = os.path.join(tmp, "cases.txt")
        with open(path, "w") as f:
            for fmt, level, chunk, flush, data, zdict in cases:
                d = "" if zdict is None else " " + zdict.hex()
                f.write(f"{fmt} {level} {chunk} {flush} {data.hex() or '-'}{d}\n")
        p = subprocess.run(verdict + [path], cwd=ROOT, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("deflateverdict failed:\n" + p.stderr)
        ours = p.stdout.splitlines()
        if len(ours) != len(cases):
            sys.exit(f"{len(ours)} results for {len(cases)} cases")
        streams = []
        failures = 0
        for case, line in zip(cases, ours):
            if line.startswith("err"):
                failures += 1
                print(f"FAIL {case[0]} level {case[1]}: {line}")
                streams.append(b"")
                continue
            h, marks, inmarks = line.split(" ")
            streams.append(bytes.fromhex(h) if h != "-" else b"")
        gos = go_decode(oracle, tmp, [(c[0], s, c[5]) for c, s in zip(cases, streams)])
        # Go's compressor on the same inputs, for the sizes.
        path = os.path.join(tmp, "go_deflate.txt")
        with open(path, "w") as f:
            for fmt, level, chunk, flush, data, zdict in cases:
                d = "" if zdict is None or fmt == "gzip" else " " + zdict.hex()
                f.write(f"{fmt} {level} {data.hex() or '-'}{d}\n")
        p = subprocess.run([oracle, "deflate", path], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("gooracle deflate failed:\n" + p.stderr)
        go_sizes = [len(l) // 2 for l in p.stdout.splitlines()]
    sizes = collections.defaultdict(lambda: [0, 0, 0, 0])   # level: ours, Go's, input, cases (no flushes)
    flush_checks = 0
    cli_checks = 0
    for i, ((fmt, level, chunk, flush, data, zdict), line, s, g) in enumerate(zip(cases, ours, streams, gos)):
        if line.startswith("err"):
            continue
        want = f"ok {len(data)} {zlib.crc32(data):08x}"
        problems = []
        if g != want:
            problems.append(f"Go reads {g!r}, want {want!r}")
        try:
            if zlib_decode(fmt, s, zdict) != data:
                problems.append("zlib reads other bytes")
        except zlib.error as e:
            problems.append(f"zlib: {e}")
        _, marks, inmarks = line.split(" ")
        if marks != "-":
            for m, n in zip(marks.split(","), inmarks.split(",")):
                flush_checks += 1
                try:
                    got = zlib_decode(fmt, s[:int(m)], zdict, partial=True)
                except zlib.error as e:
                    got = None
                if got != data[:int(n)]:
                    problems.append(f"after the flush at {n} bytes, the stream decodes to "
                                    f"{'an error' if got is None else len(got)}")
                    break
        if fmt == "gzip" and cli_checks < 300 and shutil.which("gzip"):
            cli_checks += 1
            p = subprocess.run(["gzip", "-dc"], input=s, capture_output=True)
            if p.returncode != 0 or p.stdout != data:
                problems.append("gzip -dc does not read it back")
        if problems:
            failures += 1
            if args.v or failures <= 20:
                print(f"FAIL {fmt} level {level} chunk {chunk} flush {flush} len {len(data)} "
                      f"dict {zdict is not None}: {'; '.join(problems)}")
        if flush == 0:
            t = sizes[level]
            t[0] += len(s)
            t[1] += go_sizes[i]
            t[2] += len(data)
            t[3] += 1
    print("level   cases      input       ours         Go   ours/Go")
    for level in LEVELS:
        o, g, n, c = sizes[level]
        if c:
            print(f"{level:5} {c:7} {n:10} {o:10} {g:10}   {o / g if g else 0:.4f}")
    print(f"{len(cases)} streams, {flush_checks} flush points checked, {cli_checks} read by gzip -dc too: "
          f"{failures} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
