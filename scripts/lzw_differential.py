#!/usr/bin/env python3
"""LZW, compress.lzw against Go's compress/lzw (tools/gooracle lzw).

Makes inputs (empty, one byte, runs, random, text-like, periodic, long
enough to fill the 4096-code table and make the writer clear it), at both
bit orders and every literal width from 2 to 8, with bytes masked to fit
the width (and some that do not, which both writers must refuse). Then:

* encoding: compress.lzw's output must be Go's, byte for byte, written in
  pieces of 1 byte up;
* decoding: Go's streams, corrupted ones (a flipped bit, a cut end, a
  changed byte, bytes after the end code) and random bytes, decoded by
  compress.lzw fed 1 byte at a time into 1 byte of room up, must give what
  Go gives: the same output, or the same error after the same output.

    python3 scripts/lzw_differential.py [--goose PATH] [--seed N] [--count N] [-v]
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def payload(rng, lw):
    kind = rng.randrange(7)
    n = rng.choice([0, 1, 2, 3, 10, 100, 1000, 5000, 20000, 70000, 200000])
    mask = (1 << lw) - 1
    if kind == 0:
        b = rng.randbytes(n)
    elif kind == 1:
        b = bytes([rng.randrange(256)]) * n
    elif kind == 2:
        words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog", b"\n", b"<div>", b"</div>"]
        b = b" ".join(rng.choice(words) for _ in range(n // 4 + 1))[:n]
    elif kind == 3:
        unit = rng.randbytes(rng.randrange(1, 300))
        b = (unit * (n // len(unit) + 1))[:n]
    elif kind == 4:
        b = bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))
    elif kind == 5:
        # Few symbols: long matches, table fills with long strings.
        b = bytes(rng.choice([0, 1]) for _ in range(n))
    else:
        b = bytes(rng.randrange(4) * rng.randrange(2) for _ in range(n))
    if rng.random() < 0.95:
        b = bytes(x & mask for x in b)
    return b


def corrupt(rng, s):
    k = rng.randrange(5)
    if k == 0 and s:
        i = rng.randrange(len(s))
        return s[:i] + bytes([s[i] ^ (1 << rng.randrange(8))]) + s[i + 1:]
    if k == 1 and s:
        return s[:rng.randrange(len(s))]
    if k == 2 and s:
        i = rng.randrange(len(s))
        return s[:i] + bytes([rng.randrange(256)]) + s[i + 1:]
    if k == 3:
        return s + rng.randbytes(rng.randrange(1, 10))
    return rng.randbytes(rng.randrange(0, 2000))


def code_stream(rng, order, lw):
    """Codes as a decoder would take them, chosen at random among the valid
    ones, rarely cleared: the table fills and stays full (Go's writer clears
    before that), and the highest codes are used."""
    clear, eof = 1 << lw, (1 << lw) + 1
    width, hi = lw + 1, eof
    bits = nbits = 0
    out = bytearray()

    def put(c):
        nonlocal bits, nbits
        if order == "lsb":
            bits |= c << nbits
            nbits += width
            while nbits >= 8:
                out.append(bits & 0xff)
                bits >>= 8
                nbits -= 8
        else:
            bits = (bits << width) | c
            nbits += width
            while nbits >= 8:
                out.append((bits >> (nbits - 8)) & 0xff)
                nbits -= 8
                bits &= (1 << nbits) - 1

    for _ in range(rng.choice([10, 1000, 5000, 9000])):
        r = rng.random()
        if r < 0.0005:
            c = clear
        elif r < 0.5 or hi <= eof:
            c = rng.randrange(clear)
        elif r < 0.6:
            c = hi
        else:
            c = rng.randrange(eof + 1, hi + 1)
        put(c)
        if c == clear:
            width, hi = lw + 1, eof
            continue
        hi += 1
        if hi >= 1 << width:
            if width == 12:
                hi -= 1
            else:
                width += 1
    if rng.random() < 0.9:
        put(eof)
    if nbits:
        put(0) if False else None
        out.append((bits << (8 - nbits)) & 0xff if order == "msb" else bits & 0xff)
    return bytes(out)


def run(cmd):
    p = subprocess.run(cmd, capture_output=True)
    if p.returncode != 0:
        sys.exit(f"{cmd[0]} failed: {p.stderr.decode(errors='replace')}")
    return p.stdout.decode().splitlines()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory() as tmp:
        oracle = os.path.join(tmp, "gooracle")
        subprocess.run(["go", "build", "-o", oracle, "."], cwd=os.path.join(ROOT, "tools", "gooracle"), check=True)
        verdict = os.path.join(tmp, "lzwverdict")
        p = subprocess.run([goose, "build", "-o", verdict, os.path.join(ROOT, "tools", "lzwverdict.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("building lzwverdict failed:\n" + p.stdout + p.stderr)

        enc_cases = []
        for _ in range(args.count):
            lw = rng.randrange(2, 9)
            order = rng.choice(["lsb", "msb"])
            enc_cases.append((order, lw, payload(rng, lw)))
        path = os.path.join(tmp, "enc.txt")
        with open(path, "w") as f:
            for order, lw, data in enc_cases:
                f.write(f"enc {order} {lw} {data.hex() or '-'}\n")
        go_enc = run([oracle, "lzw", path])
        failures = 0
        for chunk in ["1", "7", "4096", "1000000000"]:
            ours = run([verdict, path, chunk])
            for i, (g, o) in enumerate(zip(go_enc, ours)):
                if g != o:
                    failures += 1
                    if failures < 10:
                        order, lw, data = enc_cases[i]
                        print(f"FAIL enc case {i} ({order} lw {lw}, {len(data)} bytes, chunk {chunk}): go {g[:80]} ours {o[:80]}")
            if len(go_enc) != len(ours):
                sys.exit("enc: line counts differ")
        nerr = sum(1 for g in go_enc if g.startswith("err"))

        dec_cases = []
        for i, (order, lw, data) in enumerate(enc_cases):
            line = go_enc[i]
            if not line.startswith("ok "):
                continue
            s = b"" if line[3:] == "-" else bytes.fromhex(line[3:])
            dec_cases.append((order, lw, s))
            for _ in range(2):
                dec_cases.append((order, lw, corrupt(rng, s)))
        for _ in range(args.count // 10):
            lw = rng.randrange(2, 9)
            order = rng.choice(["lsb", "msb"])
            dec_cases.append((order, lw, code_stream(rng, order, lw)))
        path = os.path.join(tmp, "dec.txt")
        with open(path, "w") as f:
            for order, lw, s in dec_cases:
                f.write(f"dec {order} {lw} {s.hex() or '-'}\n")
        go_dec = run([oracle, "lzw", path])
        kinds = {}
        for g in go_dec:
            k = " ".join(g.split()[:2]) if g.startswith("err") else "ok"
            kinds[k] = kinds.get(k, 0) + 1
        for chunk, room in [("1", "1"), ("3", "7"), ("1000000000", "4096"), ("5000", "65536")]:
            ours = run([verdict, path, chunk, room])
            if len(go_dec) != len(ours):
                sys.exit("dec: line counts differ")
            for i, (g, o) in enumerate(zip(go_dec, ours)):
                if g != o:
                    failures += 1
                    if failures < 20:
                        order, lw, s = dec_cases[i]
                        print(f"FAIL dec case {i} ({order} lw {lw}, {len(s)} bytes, in {chunk} room {room}): go {g[:80]} ours {o[:80]}")
        print(f"lzw differential: {len(enc_cases)} encodings ({nerr} refused for wide bytes) x 4 chunkings, "
              f"{len(dec_cases)} decodings x 4 chunkings {dict(sorted(kinds.items()))}: {failures} mismatches")
        sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
