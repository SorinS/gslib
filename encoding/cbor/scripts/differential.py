#!/usr/bin/env python3
"""cbor against Python's cbor2, both ways, on random items.

1. Random values (integers of every size, both signs to -2^64, byte and
   text strings, floats from random bits, simple values, tags, arrays and
   maps nested) are written by this script's own encoder in random
   non-deterministic forms: longer heads than needed, indefinite lengths
   with random chunks, wider floats, maps in random order. Each must decode
   (with indefinite lengths allowed) and come back, written
   deterministically with keys length-first, exactly as cbor2 writes the
   value with canonical=True (cbor2 sorts length-first, RFC 7049's rule);
   and bytewise-first as the same pairs sorted by their encodings.
2. Those encodings mutated at random (bytes changed, cut, inserted): both
   must agree on whether each is CBOR, and on its value when it is.
   Differences that come from rules cbor2 does not have are counted, not
   failed: duplicate map keys (cbor2 keeps the last; cbor refuses), and
   cbor2's semantic tags (0-5, 21-37, 256-270, ...) that it decodes or
   refuses by their content where cbor passes every tag through.

    python3 encoding/cbor/scripts/differential.py [-n 2000] [--seed S] [--goose PATH]

Needs cbor2 in the Python that runs it (CBOR_PYTHON in the Makefile).
"""

import argparse
import io
import math
import os
import random
import shutil
import struct
import subprocess
import sys

import cbor2

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOOL = os.path.join(ROOT, "tools", "cbor.goose")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


# --- Random values ---------------------------------------------------------------

def rand_int(r):
    k = r.choice([5, 8, 16, 32, 64, 64])
    v = r.getrandbits(k) if k < 64 else r.getrandbits(64)
    if r.random() < 0.5:
        v = -1 - v
    return v


def rand_text(r):
    n = r.choice([0, 1, 3, 10, 30])
    out = []
    for _ in range(n):
        c = r.choice([r.randrange(0x20, 0x7f), r.randrange(0x80, 0x800), r.randrange(0x800, 0xd800),
                      r.randrange(0xe000, 0x10000), r.randrange(0x10000, 0x110000)])
        out.append(chr(c))
    return "".join(out)


def rand_float(r):
    k = r.random()
    if k < 0.2:
        return r.choice([0.0, -0.0, 1.0, -1.5, 65504.0, float("inf"), float("-inf"), float("nan"), 5e-324, 1e300])
    if k < 0.5:
        return struct.unpack(">e", struct.pack(">H", r.getrandbits(16)))[0]
    if k < 0.75:
        return struct.unpack(">f", struct.pack(">I", r.getrandbits(32)))[0]
    return struct.unpack(">d", struct.pack(">Q", r.getrandbits(64)))[0]


def rand_value(r, depth=0):
    kinds = ["int", "bytes", "text", "float", "simple", "bool", "none"]
    if depth < 4:
        kinds += ["array", "map", "tag"]
    k = r.choice(kinds)
    if k == "int":
        return rand_int(r)
    if k == "bytes":
        return bytes(r.getrandbits(8) for _ in range(r.choice([0, 1, 5, 30])))
    if k == "text":
        return rand_text(r)
    if k == "float":
        return rand_float(r)
    if k == "simple":
        return cbor2.CBORSimpleValue(r.choice([0, 5, 16, 19, 32, 100, 255]))
    if k == "bool":
        return r.random() < 0.5
    if k == "none":
        return None
    if k == "array":
        return [rand_value(r, depth + 1) for _ in range(r.choice([0, 1, 3, 6]))]
    if k == "tag":
        # Tag numbers cbor2 has no meaning for, so that it keeps them.
        return cbor2.CBORTag(r.choice([40000, 1000000, 2 ** 40]), rand_value(r, depth + 1))
    m = {}
    for _ in range(r.choice([0, 1, 3, 6])):
        key = r.choice([rand_int(r), rand_text(r), bytes(r.getrandbits(8) for _ in range(r.randrange(4)))])
        m[key] = rand_value(r, depth + 1)
    return m


# --- A lax encoder ----------------------------------------------------------------

def head(r, major, v, lax):
    widths = [w for w, lim in ((0, 24), (1, 1 << 8), (2, 1 << 16), (4, 1 << 32), (8, 1 << 64)) if v < lim]
    w = r.choice(widths) if lax and r.random() < 0.3 else widths[0]
    if w == 0:
        return bytes([major << 5 | v])
    ai = {1: 24, 2: 25, 4: 26, 8: 27}[w]
    return bytes([major << 5 | ai]) + v.to_bytes(w, "big")


def chunks(r, b):
    out, i = [], 0
    while i < len(b):
        n = r.randrange(1, len(b) - i + 1)
        out.append(b[i:i + n])
        i += n
    if r.random() < 0.3:
        out.insert(r.randrange(len(out) + 1), b[:0])
    return out


def float_forms(f):
    forms = []
    for fmt, ai in ((">e", 0xf9), (">f", 0xfa), (">d", 0xfb)):
        try:
            b = struct.pack(fmt, f)
        except (OverflowError, struct.error):
            continue
        g = struct.unpack(fmt, b)[0]
        if (math.isnan(f) and math.isnan(g)) or (g == f and math.copysign(1, g) == math.copysign(1, f)):
            forms.append(bytes([ai]) + b)
    return forms


def enc(r, v, lax=True):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, cbor2.CBORSimpleValue):
        n = v.value
        return bytes([0xe0 | n]) if n < 24 else b"\xf8" + bytes([n])
    if isinstance(v, int):
        return head(r, 0, v, lax) if v >= 0 else head(r, 1, -1 - v, lax)
    if isinstance(v, float):
        forms = float_forms(v)
        return r.choice(forms) if lax else forms[0]
    if isinstance(v, (bytes, str)):
        major = 2 if isinstance(v, bytes) else 3
        b = v if isinstance(v, bytes) else v.encode()
        if lax and r.random() < 0.25:
            # Chunks of text must each be UTF-8: cut between characters.
            if major == 3:
                parts = [p.encode() for p in chunks(r, v)]
            else:
                parts = chunks(r, b)
            return bytes([major << 5 | 31]) + b"".join(head(r, major, len(p), lax) + p for p in parts) + b"\xff"
        return head(r, major, len(b), lax) + b
    if isinstance(v, list):
        body = b"".join(enc(r, x, lax) for x in v)
        if lax and r.random() < 0.25:
            return b"\x9f" + body + b"\xff"
        return head(r, 4, len(v), lax) + body
    if isinstance(v, dict):
        items = list(v.items())
        if lax:
            r.shuffle(items)
        body = b"".join(enc(r, k, lax) + enc(r, x, lax) for k, x in items)
        if lax and r.random() < 0.25:
            return b"\xbf" + body + b"\xff"
        return head(r, 5, len(items), lax) + body
    if isinstance(v, cbor2.CBORTag):
        return head(r, 6, v.tag, lax) + enc(r, v.value, lax)
    raise TypeError(type(v))


def bytewise(v):
    """The core deterministic encoding (§4.2.1): cbor2's canonical form with
    every map's pairs sorted by their keys' encodings."""
    if isinstance(v, list):
        return head(None, 4, len(v), False) + b"".join(bytewise(x) for x in v)
    if isinstance(v, dict):
        pairs = sorted((bytewise(k), bytewise(x)) for k, x in v.items())
        return head(None, 5, len(pairs), False) + b"".join(k + x for k, x in pairs)
    if isinstance(v, cbor2.CBORTag):
        return head(None, 6, v.tag, False) + bytewise(v.value)
    return cbor2.dumps(v, canonical=True)


def run_batch(goose, lines, extra):
    p = subprocess.run([goose, TOOL, "--", "batch", "--indefinite", "--depth", "64", "--items", "1000000", *extra],
                       input="\n".join(lines) + "\n", capture_output=True, text=True)
    out = [l for l in p.stdout.splitlines() if l.startswith(("ok", "err"))]
    if len(out) != len(lines):
        sys.exit(f"cbor batch gave {len(out)} answers for {len(lines)} items:\n{p.stderr[-2000:]}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    r = random.Random(seed)
    print(f"seed {seed}")

    values = [rand_value(r) for _ in range(args.n)]
    encs = [enc(r, v) for v in values]
    lines = [e.hex() for e in encs]
    fails = 0
    for extra, want_of in ((["--length-first"], lambda v: cbor2.dumps(v, canonical=True)), ([], bytewise)):
        out = run_batch(goose, lines, extra)
        for v, e, o in zip(values, encs, out):
            want = want_of(v).hex()
            if o.split(" ")[0] != "ok" or o.split(" ")[1] != want:
                fails += 1
                if fails <= 10:
                    print(f"FAIL {e.hex()}\n  cbor:  {o[:300]}\n  want:  {want[:300]}")
    print(f"random values: {args.n} items, {'length-first and bytewise'}, {fails} failed")

    # Mutations.
    muts = []
    for e in encs:
        b = bytearray(e)
        k = r.random()
        if k < 0.4 and b:
            b[r.randrange(len(b))] = r.getrandbits(8)
        elif k < 0.6 and len(b) > 1:
            del b[r.randrange(1, len(b)):]
        elif k < 0.8:
            b.insert(r.randrange(len(b) + 1), r.getrandbits(8))
        else:
            i = r.randrange(len(b))
            b[i] = r.choice([0x1c, 0x5f, 0x7f, 0x9f, 0xbf, 0xff, 0xf8, 0xc2, 0xd8])
        muts.append(bytes(b))
    out = run_batch(goose, [m.hex() for m in muts], ["--length-first"])
    agree = dup = semantic = mfails = 0
    for m, o in zip(muts, out):
        try:
            fp = io.BytesIO(m)
            v = cbor2.load(fp)
            if fp.tell() != len(m):
                raise ValueError("trailing bytes")
            theirs = cbor2.dumps(v, canonical=True).hex()
        except Exception as ex:
            v, theirs = None, "error: " + str(ex)
        ours_ok = o.startswith("ok")
        if ours_ok and not theirs.startswith("error") and o.split(" ")[1] == theirs:
            agree += 1
        elif not ours_ok and theirs.startswith("error"):
            agree += 1
        elif o == "err 5":
            dup += 1
        elif "tag" in theirs or (ours_ok and "(" in o.split(" ", 2)[2]):
            semantic += 1
        else:
            mfails += 1
            if mfails <= 10:
                print(f"FAIL mutation {m.hex()}\n  cbor:  {o[:300]}\n  cbor2: {theirs[:300]}")
    print(f"mutations: {len(muts)} items, {agree} agree, {dup} duplicate keys refused (cbor2 keeps the last), "
          f"{semantic} semantic tags, {mfails} failed")
    total = fails + mfails
    print(f"\n{2 * args.n + len(muts) - total} passed, {total} failed")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
