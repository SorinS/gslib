#!/usr/bin/env python3
"""xz and .lzma decoding, compress.xz against xz (liblzma).

Makes streams with Python's lzma module and the xz CLI: every preset 0-9
and -e, every check (None, CRC-32, CRC-64, SHA-256), LZMA2 options (lc, lp,
pb, dictionary sizes), filter chains (Delta and the BCJ filters before
LZMA2), several blocks, several streams with stream padding, .lzma files
and raw LZMA2, of data that is random, repetitive, text-like, executable-
like and empty; and corrupts some (a flipped bit, a cut end, bytes after
the end, padding that is not a multiple of four). tools/xzverdict.goose
decodes each fed in pieces of 1 byte up and with output room of 1 byte
up; its verdict must be xz's (`xz -dc`): the same bytes, or a refusal
where xz refuses.

With --encode it checks the other way: tools/xzencode.goose compresses
the same kinds of data (every level, check, block size, filter, written in
pieces with flushes between) as .xz, .lzma and raw LZMA2, and xz (`xz -t`
and `xz -dc`), Python's lzma and compress.xz's reader must all give back
the input; sizes against xz -1 and -6 are reported.

    python3 scripts/xz_differential.py [--goose PATH] [--seed N] [--count N] [--encode] [-v]
"""

import argparse
import lzma
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


def payload(rng):
    kind = rng.randrange(7)
    n = rng.choice([0, 1, 2, 5, 100, 1000, 5000, 40000, 70000, 140000, 300000])
    if kind == 0:
        return rng.randbytes(n)
    if kind == 1:
        return bytes([rng.randrange(4)]) * n
    if kind == 2:
        words = [b"the", b"quick", b"brown", b"fox", b"jumps", b"over", b"lazy", b"dog", b"\n", b"<div>", b"</div>"]
        return b" ".join(rng.choice(words) for _ in range(n // 4 + 1))[:n]
    if kind == 3:
        unit = rng.randbytes(rng.randrange(1, 300))
        return (unit * (n // max(1, len(unit)) + 1))[:n]
    if kind == 4:
        # Executable-like: call/branch opcodes with nearby targets.
        out = bytearray()
        while len(out) < n:
            r = rng.randrange(10)
            if r == 0:
                out += bytes([0xe8]) + struct.pack("<i", rng.randrange(-5000, 5000))
            elif r == 1:
                out += struct.pack("<I", 0x94000000 | rng.randrange(1 << 20))      # ARM64 BL
            elif r == 2:
                out += struct.pack("<I", 0xeb000000 | rng.randrange(1 << 16))      # ARM BL
            elif r == 3:
                out += struct.pack(">I", 0x48000001 | (rng.randrange(1 << 16) << 2))   # PowerPC bl
            else:
                out += rng.randbytes(rng.randrange(1, 8))
        return bytes(out[:n])
    if kind == 5:
        return bytes((i * 7 + (i >> 8)) & 0xff for i in range(n))
    # Mostly zeros with some structure (delta-friendly).
    return bytes(((i // 3) * 5) & 0xff if (i % 17) else 0 for i in range(n))


CHECKS = [lzma.CHECK_NONE, lzma.CHECK_CRC32, lzma.CHECK_CRC64, lzma.CHECK_SHA256]
BCJ = [lzma.FILTER_X86, lzma.FILTER_POWERPC, lzma.FILTER_IA64, lzma.FILTER_ARM, lzma.FILTER_ARMTHUMB,
       lzma.FILTER_SPARC]


def lzma2_filter(rng):
    f = {"id": lzma.FILTER_LZMA2, "preset": rng.choice([0, 1, 6, 9, 6 | lzma.PRESET_EXTREME])}
    if rng.random() < 0.4:
        lc = rng.randrange(5)
        lp = rng.randrange(5 - lc)
        f.update(lc=lc, lp=lp, pb=rng.randrange(5))
    if rng.random() < 0.3:
        f["dict_size"] = rng.choice([4096, 65536, 1 << 20, 3 << 19])
    return f


def make_xz(rng, data):
    """A stream of data, and a description."""
    check = rng.choice(CHECKS)
    r = rng.random()
    if r < 0.4:
        preset = rng.randrange(10) | (lzma.PRESET_EXTREME if rng.random() < 0.2 else 0)
        return lzma.compress(data, check=check, preset=preset), f"preset {preset} check {check}"
    chain = []
    if r < 0.8:
        k = rng.randrange(1, 3)
        for _ in range(k):
            if rng.random() < 0.4:
                chain.append({"id": lzma.FILTER_DELTA, "dist": rng.choice([1, 2, 4, 7, 256])})
            else:
                f = {"id": rng.choice(BCJ)}
                if rng.random() < 0.3:
                    f["start_offset"] = rng.choice([0, 4, 16, 1 << 20])
                chain.append(f)
    chain.append(lzma2_filter(rng))
    try:
        return lzma.compress(data, check=check, filters=chain), f"filters {chain} check {check}"
    except lzma.LZMAError:
        return lzma.compress(data, check=check), f"default check {check}"


def make_xz_cli(rng, data, tmp):
    args = ["xz", "-c", "-q", f"-{rng.randrange(10)}"]
    if rng.random() < 0.3:
        args.append("-e")
    args.append("--check=" + rng.choice(["none", "crc32", "crc64", "sha256"]))
    if rng.random() < 0.5:
        args.append(f"--block-size={rng.choice([1000, 5000, 65536, 100000])}")
    if rng.random() < 0.3:
        args.append(rng.choice(["--x86", "--arm64", "--arm", "--sparc", "--powerpc", "--ia64", "--armthumb",
                                "--delta=dist=2"]))
        args.append("--lzma2=preset=" + str(rng.randrange(10)))
    p = subprocess.run(args, input=data, capture_output=True)
    if p.returncode != 0:
        return None, ""
    return p.stdout, " ".join(args)


def corrupt(rng, s):
    if not s:
        return s, "empty"
    r = rng.randrange(6)
    if r == 0:
        b = bytearray(s)
        i = rng.randrange(len(b))
        b[i] ^= 1 << rng.randrange(8)
        return bytes(b), f"bit flip at {i}"
    if r == 1:
        n = rng.randrange(len(s))
        return s[:n], f"cut to {n}"
    if r == 2:
        return s + rng.randbytes(rng.randrange(1, 20)), "junk after"
    if r == 3:
        return s + b"\0" * rng.choice([1, 2, 3, 5, 6]), "bad padding"
    if r == 4:
        b = bytearray(s)
        i = rng.randrange(min(len(b), 64))
        b[i] = rng.randrange(256)
        return bytes(b), f"header byte {i}"
    b = bytearray(s)
    i = len(b) - 1 - rng.randrange(min(len(b), 40))
    b[i] ^= 0xff
    return bytes(b), f"tail byte {i}"


def reference(path, mode):
    """xz's verdict: ('ok', data) or ('err', None)."""
    args = ["xz", "-dc", "-q", "-q"]
    if mode == "lzma" or mode.startswith("lzma2:"):
        # liblzma's own .lzma decoder (as Python uses it): the xz CLI adds
        # its format-detection checks of the header (a dictionary size of
        # 2^n or 2^n + 2^(n-1), a known size under 2^38), which a reader of
        # .lzma files need not.
        data = open(path, "rb").read()
        try:
            if mode == "lzma":
                d = lzma.LZMADecompressor(lzma.FORMAT_ALONE)
            else:
                d = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2,
                                                                     "dict_size": int(mode[6:])}])
            out = d.decompress(data)
            if not d.eof:
                return "err", None
            if d.unused_data:
                return "trailing", out
            return "ok", out
        except lzma.LZMAError:
            return "err", None
    if mode == "xz1":
        args.append("--single-stream")
    else:
        args.append("--format=xz")
    args.append(path)
    p = subprocess.run(args, capture_output=True)
    # 2 is a warning (an unsupported check): the data is still good.
    if p.returncode in (0, 2):
        return "ok", p.stdout
    return "err", None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--count", type=int, default=600)
    ap.add_argument("--encode", action="store_true")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if args.encode:
        sys.exit(encode_main(args, goose))
    rng = random.Random(args.seed)
    tmp = tempfile.mkdtemp(prefix="xzdiff")
    exe = os.path.join(tmp, "xzverdict")
    p = subprocess.run([goose, "build", "-o", exe, os.path.join(ROOT, "tools", "xzverdict.goose")],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("building xzverdict failed:\n" + p.stdout + p.stderr)

    cases = []          # (mode, chunk, room, path, desc, corrupted)
    for i in range(args.count):
        data = payload(rng)
        r = rng.random()
        if r < 0.45:
            s, desc = make_xz(rng, data)
            mode = "xz"
        elif r < 0.6:
            s, desc = make_xz_cli(rng, data, tmp)
            if s is None:
                continue
            mode = "xz"
        elif r < 0.7:
            # Several streams, with padding between and after.
            parts = []
            for k in range(rng.randrange(2, 4)):
                parts.append(lzma.compress(payload(rng)[:5000], check=rng.choice(CHECKS)))
                parts.append(b"\0" * (4 * rng.randrange(3)))
            s, desc = b"".join(parts), "multistream"
            mode = rng.choice(["xz", "xz", "xz1"])
        elif r < 0.85:
            if rng.random() < 0.5:
                f = lzma2_filter(rng)
                f = {k: v for k, v in f.items() if k != "dict_size"}
                f["id"] = lzma.FILTER_LZMA1
                s = lzma.compress(data, format=lzma.FORMAT_ALONE, filters=[f])
                desc = f"alone {f}"
            else:
                p = subprocess.run(["xz", "-c", "--format=lzma", f"-{rng.randrange(10)}"], input=data,
                                   capture_output=True)
                s, desc = p.stdout, "xz --format=lzma"
            mode = "lzma"
        else:
            f = lzma2_filter(rng)
            dsz = f.get("dict_size", 1 << 23)
            f["dict_size"] = dsz
            s = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[f])
            desc = f"raw {f}"
            mode = f"lzma2:{dsz}"
        corrupted = False
        if rng.random() < 0.3:
            s, cdesc = corrupt(rng, s)
            desc += " / " + cdesc
            corrupted = True
        path = os.path.join(tmp, f"c{i}")
        with open(path, "wb") as f:
            f.write(s)
        chunk = rng.choice([1, 2, 3, 7, 64, 1000, 1 << 20])
        room = rng.choice([1, 2, 5, 100, 4096, 1 << 20])
        if len(s) > 20000 and chunk < 7:
            chunk = rng.choice([7, 13, 64])
        cases.append((mode, chunk, room, path, desc, corrupted))

    with open(os.path.join(tmp, "cases.txt"), "w") as f:
        for c in cases:
            f.write(f"{c[0]} {c[1]} {c[2]} {c[3]}\n")
    p = subprocess.run([exe, os.path.join(tmp, "cases.txt")], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("xzverdict failed:\n" + p.stdout + p.stderr)
    lines = p.stdout.splitlines()
    if len(lines) != len(cases):
        sys.exit(f"xzverdict gave {len(lines)} lines for {len(cases)} cases")

    fails = 0
    counts = {"ok": 0, "refused": 0}
    for c, line in zip(cases, lines):
        mode, chunk, room, path, desc, corrupted = c
        kind, out = reference(path, mode)
        got = line.split()
        ok = False
        if kind == "ok":
            want = f"ok {len(out)} {zlib.crc32(out):08x}"
            ok = line == want
            # xz --single-stream reads the first stream and ignores the rest.
            if not ok and mode == "xz1" and got[0] == "trailing":
                ok = got[1:3] == want.split()[1:3]
        elif kind == "trailing":
            ok = got[0] == "trailing" and got[1] == str(len(out)) and got[2] == f"{zlib.crc32(out):08x}"
        else:
            ok = got[0] in ("err", "short")
        # A .lzma header declaring a dictionary past our memory limit (256 MiB).
        if not ok and mode == "lzma" and line == "err -7":
            ok = struct.unpack("<I", open(path, "rb").read()[1:5])[0] > (1 << 28)
        if ok:
            counts["ok" if kind != "err" else "refused"] += 1
        else:
            fails += 1
            print(f"FAIL {mode} chunk {chunk} room {room} [{desc}]: ours '{line}', xz {kind}"
                  + (f" {len(out)} {zlib.crc32(out):08x}" if out is not None else ""))
            if fails > 20:
                break
        if args.v:
            print(f"{line:40} {desc}")
    print(f"{len(cases)} cases: {counts['ok']} decoded alike, {counts['refused']} refused alike, {fails} differ")
    if fails == 0:
        shutil.rmtree(tmp)
    sys.exit(1 if fails else 0)


FILTER_IDS = {"x86": 4, "powerpc": 5, "ia64": 6, "arm": 7, "armthumb": 8, "sparc": 9, "arm64": 10}


def build(goose, name, tmp):
    exe = os.path.join(tmp, name)
    p = subprocess.run([goose, "build", "-o", exe, os.path.join(ROOT, "tools", name + ".goose")],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"building {name} failed:\n" + p.stdout + p.stderr)
    return exe


def encode_main(args, goose):
    rng = random.Random(args.seed)
    tmp = tempfile.mkdtemp(prefix="xzenc")
    enc = build(goose, "xzencode", tmp)
    ver = build(goose, "xzverdict", tmp)
    cases = []
    for i in range(args.count):
        data = payload(rng)
        if rng.random() < 0.02:
            # Past a chunk's 2 MiB and the window: the window slides.
            data = b"".join(payload(rng) for _ in range(30))[:rng.choice([2500000, 5000000])]
        mode = rng.choice(["xz", "xz", "xz", "lzma", "lzma-1", "raw"])
        level = rng.choice([0, 1, 2, 3, 4, 5, 6, 6, 1, 0, 2, 7, 8, 9]) if len(data) < 100000 else rng.randrange(7)
        check = rng.choice([0, 1, 4, 10])
        block = rng.choice([0, 0, 0, 1, 1000, 4096, 100000])
        filt, opt = 0, 0
        if mode == "xz" and rng.random() < 0.3:
            name = rng.choice(list(FILTER_IDS) + ["delta"])
            if name == "delta":
                filt, opt = 3, rng.choice([1, 2, 4, 256])
            else:
                filt, opt = FILTER_IDS[name], rng.choice([0, 0, 16, 4096])
        chunk = rng.choice([1, 7, 1000, 65536, 1 << 30]) if len(data) < 50000 else rng.choice([1000, 65536, 1 << 30])
        flush = rng.choice([0, 0, 0, 100, 5000, 70000])
        if block == 1 and len(data) > 3000:
            block = 1000
        inp = os.path.join(tmp, f"in{i}")
        outp = os.path.join(tmp, f"out{i}")
        with open(inp, "wb") as f:
            f.write(data)
        cases.append((mode, level, check, block, filt, opt, chunk, flush, inp, outp, data))
    with open(os.path.join(tmp, "cases.txt"), "w") as f:
        for c in cases:
            f.write(" ".join(str(x) for x in c[:10]) + "\n")
    p = subprocess.run([enc, os.path.join(tmp, "cases.txt")], capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("xzencode failed:\n" + p.stdout + p.stderr)
    lines = p.stdout.splitlines()
    if len(lines) != len(cases):
        sys.exit(f"xzencode gave {len(lines)} lines for {len(cases)} cases")
    fails = 0
    vcases = []
    ours = theirs1 = theirs6 = 0
    for c, line in zip(cases, lines):
        mode, level, check, block, filt, opt, chunk, flush, inp, outp, data = c
        desc = f"{mode} level {level} check {check} block {block} filter {filt}/{opt} chunk {chunk} flush {flush} n {len(data)}"
        got = line.split()
        if got[0] != "ok":
            print(f"FAIL {desc}: {line}")
            fails += 1
            continue
        s = open(outp, "rb").read()
        try:
            if mode == "xz":
                back = lzma.decompress(s, format=lzma.FORMAT_XZ)
                t = subprocess.run(["xz", "-dc", outp], capture_output=True)
                if t.returncode != 0 or t.stdout != data:
                    raise lzma.LZMAError("xz -dc: " + t.stderr.decode())
                vcases.append(("xz", outp, data))
            elif mode in ("lzma", "lzma-1"):
                back = lzma.decompress(s, format=lzma.FORMAT_ALONE)
                t = subprocess.run(["xz", "-dc", "--format=lzma", outp], capture_output=True)
                if t.returncode != 0 or t.stdout != data:
                    raise lzma.LZMAError("xz -dc --format=lzma: " + t.stderr.decode())
                vcases.append(("lzma", outp, data))
            else:
                back = lzma.decompress(s, format=lzma.FORMAT_RAW,
                                       filters=[{"id": lzma.FILTER_LZMA2, "dict_size": int(got[2])}])
                vcases.append((f"lzma2:{got[2]}", outp, data))
            if back != data:
                raise lzma.LZMAError("different data")
        except lzma.LZMAError as e:
            print(f"FAIL {desc}: {e} ({inp})")
            fails += 1
            continue
        if mode == "xz" and block == 0 and filt == 0 and flush == 0 and level in (1, 6) and len(data) > 1000:
            ours += len(s)
            ref = lzma.compress(data, preset=level)
            if level == 1:
                theirs1 += len(ref)
            else:
                theirs6 += len(ref)
        if args.v:
            print(f"ok {len(s):8} {desc}")
    # Our reader on our output, a few bytes at a time.
    with open(os.path.join(tmp, "vcases.txt"), "w") as f:
        for i, (m, path, data) in enumerate(vcases):
            f.write(f"{m} {rng.choice([1, 13, 4096, 1 << 20])} {rng.choice([1, 100, 1 << 20])} {path}\n")
    p = subprocess.run([ver, os.path.join(tmp, "vcases.txt")], capture_output=True, text=True)
    for (m, path, data), line in zip(vcases, p.stdout.splitlines()):
        if line != f"ok {len(data)} {zlib.crc32(data):08x}":
            print(f"FAIL our reader on {path} ({m}): {line}")
            fails += 1
    print(f"{len(cases)} cases encoded, {len(vcases)} decoded by xz, Python and compress.xz alike, {fails} failed")
    if theirs1 + theirs6:
        print(f"sizes (one block, levels 1 and 6, inputs over 1000 bytes): ours {ours}, xz's {theirs1 + theirs6}"
              f" ({100.0 * ours / (theirs1 + theirs6):.1f}%)")
    if fails == 0:
        shutil.rmtree(tmp)
    return 1 if fails else 0


if __name__ == "__main__":
    main()
