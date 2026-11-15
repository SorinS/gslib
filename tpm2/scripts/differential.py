#!/usr/bin/env python3
"""tpm2 against go-tpm (github.com/google/go-tpm v0.9.8, its tpm2 package) on
random cases: KDFa and KDFe (every hash, odd bit counts), the Names of
random TPMT_PUBLIC areas (RSA, ECC, keyed-hash, symmetric; every scheme,
symmetric definition and KDF) and that each marshals back to the same
bytes, NV indices' Names, and policy digests of random sequences of
PolicyPCR, PolicySecret, PolicySigned, PolicyAuthValue, PolicyCommandCode,
PolicyOR and PolicyAuthorize. go-tpm is an independent implementation: both
must give the same answer to every case.

scripts/gotpm (go.mod pins go-tpm) is built with Go; the module cache is
used when it has go-tpm (GOFLAGS=-mod=mod), else Go fetches it.

    python3 scripts/differential.py [-n CASES] [--seed S] [--goose PATH]
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HASHES = [0x0004, 0x000B, 0x000C, 0x000D]
HLEN = {0x0004: 20, 0x000B: 32, 0x000C: 48, 0x000D: 64}


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def u16(v):
    return v.to_bytes(2, "big")


def u32(v):
    return v.to_bytes(4, "big")


def b2(r, data):
    return u16(len(data)) + data


def rb(r, lo, hi):
    return bytes(r.randrange(256) for _ in range(r.randint(lo, hi)))


def h(b):
    return b.hex() if b else "-"


def sym(r, allow_null=True):
    if allow_null and r.random() < 0.4:
        return u16(0x0010)
    return u16(0x0006) + u16(r.choice([128, 192, 256])) + u16(0x0043)


def public(r):
    kind = r.choice(["rsa", "ecc", "keyedhash", "symcipher"])
    out = b""
    name_alg = r.choice(HASHES)
    attrs = r.getrandbits(32)
    head = lambda k: u16(k) + u16(name_alg) + u32(attrs) + b2(r, rb(r, 0, 64))
    if kind == "rsa":
        scheme = r.choice([0x0010, 0x0014, 0x0016, 0x0017, 0x0015])
        sc = u16(scheme) + (u16(r.choice(HASHES)) if scheme in (0x0014, 0x0016, 0x0017) else b"")
        out = head(0x0001) + sym(r) + sc + u16(r.choice([1024, 2048, 3072, 4096])) \
            + u32(r.choice([0, 65537, 3, r.getrandbits(32)])) + b2(r, rb(r, 0, 512))
    elif kind == "ecc":
        # go-tpm has no ECSchnorr or SM2 in TPMU_ASYM_SCHEME; tpm2 reads both.
        scheme = r.choice([0x0010, 0x0018, 0x0019, 0x001A, 0x001D])
        sc = u16(scheme)
        if scheme != 0x0010:
            sc += u16(r.choice(HASHES))
        if scheme == 0x001A:
            sc += u16(r.getrandbits(16))
        kdf = r.choice([0x0010, 0x0020, 0x0021, 0x0022])
        kd = u16(kdf) + (u16(r.choice(HASHES)) if kdf != 0x0010 else b"")
        out = head(0x0023) + sym(r) + sc + u16(r.choice([1, 2, 3, 4, 5])) + kd + b2(r, rb(r, 0, 66)) + b2(r, rb(r, 0, 66))
    elif kind == "keyedhash":
        scheme = r.choice([0x0010, 0x0005, 0x000A])
        sc = u16(scheme)
        if scheme == 0x0005:
            sc += u16(r.choice(HASHES))
        if scheme == 0x000A:
            sc += u16(r.choice(HASHES)) + u16(r.choice([0x0020, 0x0021, 0x0022]))
        out = head(0x0008) + sc + b2(r, rb(r, 0, 64))
    else:
        out = head(0x0025) + sym(r, allow_null=False) + b2(r, rb(r, 0, 64))
    return out


def nvpublic(r):
    return u32(0x01000000 | r.getrandbits(24)) + u16(r.choice(HASHES)) + u32(r.getrandbits(32)) \
        + b2(r, rb(r, 0, 64)) + u16(r.getrandbits(16))


def pcrsel(r):
    n = r.randint(1, 3)
    out = u32(n)
    for _ in range(n):
        out += u16(r.choice(HASHES)) + bytes([3]) + bytes([r.getrandbits(8), r.getrandbits(8), r.getrandbits(8)])
    return out


def name(r):
    if r.random() < 0.3:
        return u32(r.choice([0x40000001, 0x4000000B, 0x4000000C, 0x40000007]))
    a = r.choice(HASHES)
    return u16(a) + rb(r, HLEN[a], HLEN[a])


def policy(r):
    alg = r.choice(HASHES)
    ops = []
    if r.random() < 0.3:
        ops.append(f"authorize:{h(name(r))}:{h(rb(r, 0, 32))}")
    for _ in range(r.randint(0, 5)):
        k = r.choice(["pcr", "secret", "signed", "authvalue", "cc", "or"])
        if k == "pcr":
            ops.append(f"pcr:{pcrsel(r).hex()}:{h(rb(r, 0, 64))}")
        elif k in ("secret", "signed"):
            ops.append(f"{k}:{h(name(r))}:{h(rb(r, 0, 64))}")
        elif k == "authvalue":
            ops.append("authvalue")
        elif k == "cc":
            ops.append(f"cc:{r.getrandbits(32)}")
        else:
            ds = [rb(r, HLEN[alg], HLEN[alg]).hex() for _ in range(r.randint(2, 8))]
            ops.append("or:" + ".".join(ds))
    return f"policy {alg:04x} " + " ".join(ops)


def label(r):
    return bytes(r.choice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(r.randint(1, 12)))


def cases(r, n):
    out = []
    for i in range(n):
        k = i % 5
        if k == 0:
            a = r.choice(HASHES)
            out.append(f"kdfa {a:04x} {h(rb(r, 1, 80))} {h(label(r))} {h(rb(r, 0, 64))} {h(rb(r, 0, 64))} {r.randint(1, 1200)}")
        elif k == 1:
            a = r.choice(HASHES)
            out.append(f"kdfe {a:04x} {h(rb(r, 1, 66))} {h(label(r))} {h(rb(r, 0, 66))} {h(rb(r, 0, 66))} {8 * r.randint(1, 100)}")
        elif k == 2:
            out.append(f"pubname {public(r).hex()}")
        elif k == 3:
            out.append(f"nvname {nvpublic(r).hex()}")
        else:
            out.append(policy(r))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    go = shutil.which("go")
    if not go:
        print("skip: no Go")
        return
    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    r = random.Random(seed)
    tmp = tempfile.mkdtemp(prefix="tpm2-diff-")
    try:
        exe = os.path.join(tmp, "gotpm")
        env = dict(os.environ, GOFLAGS="-mod=mod")
        b = subprocess.run([go, "build", "-o", exe, "."], cwd=os.path.join(ROOT, "scripts", "gotpm"),
                           env=env, capture_output=True, text=True)
        if b.returncode != 0:
            sys.exit("cannot build scripts/gotpm:\n" + b.stderr)
        cs = cases(r, args.n)
        path = os.path.join(tmp, "cases")
        with open(path, "w") as f:
            f.write("\n".join(cs) + "\n")
        g = subprocess.run([exe, path], capture_output=True, text=True)
        o = subprocess.run([goose, "-O2", os.path.join("scripts", "oracle.goose"), "--", path], cwd=ROOT,
                           capture_output=True, text=True)
        if g.returncode != 0 or o.returncode != 0:
            sys.exit(f"a side failed:\n{g.stderr[-500:]}\n{o.stderr[-500:]}")
        ga = g.stdout.splitlines()
        oa = [l for l in o.stdout.splitlines() if l]
        if len(ga) != len(cs) or len(oa) != len(cs):
            sys.exit(f"answers: go-tpm {len(ga)}, tpm2 {len(oa)}, cases {len(cs)}")
        bad = 0
        kinds = {}
        for c, x, y in zip(cs, ga, oa):
            kind = c.split()[0]
            n = kinds.setdefault(kind, [0, 0])
            n[0] += 1
            if x == y and x != "error":
                continue
            if x == "error" and y == "error":
                n[1] += 1
                continue
            bad += 1
            if bad <= 10:
                print(f"DIFF  {c[:200]}\n  go-tpm {x[:160]}\n  tpm2   {y[:160]}")
        for k, (n, both) in sorted(kinds.items()):
            print(f"{k:8} {n} cases" + (f" ({both} refused by both)" if both else ""))
        print(f"\nseed {seed}: {len(cs) - bad} agree, {bad} differ")
        sys.exit(1 if bad else 0)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
