#!/usr/bin/env python3
"""Vectors for SLH-DSA (FIPS 205): test/vectors/slhdsa.txt from the openssl
command (3.5 or later) and test/vectors/slhdsa_acvp.txt from NIST's ACVP
JSON files.

Signing an "s" set takes seconds, so a signature is either made again by
the test and compared by its SHA3-256, or only verified (and in the file
whole). The "f" sets are signed once from slhdsa.txt and twice from the
ACVP file; SHA2-128s once from slhdsa.txt and SHAKE-128s once from the
ACVP file; the other four "s" sets are only verified.

slhdsa.txt, for each set:

    key <set> <seed> <pk>                        openssl's key from the seed
    sig <ctx> <msg> <signature|sha3>             deterministic, by openssl
    bad <ctx> <msg> <offset> <mask>              the last sig line's signature
                                                 changed (offset -1: a byte
                                                 short, -2: a byte long), which
                                                 openssl refuses

slhdsa_acvp.txt, from the internalProjection.json files of
SLH-DSA-keyGen-FIPS205 and SLH-DSA-sigGen-FIPS205 in
github.com/usnistgov/ACVP-Server (gen-val/json-files), in the directory
$SLHDSA_ACVP_DIR (without it the file is left as it is):

    akey <set> <skSeed||skPrf||pkSeed> <sk>      the "f" sets
    asig <set> <iface> <hash> <sk> <ctx> <msg> <addrnd|-> <signature|sha3>

iface is pure, prehash or internal; hash is ACVP's hashAlg name or none.
Per set: one HashSLH-DSA case (a different pre-hash for each set, so all
twelve are covered) and, for the "f" sets and SHAKE-128s, an
internal-interface and a hedged pure one.

    python3 scripts/slhdsa_vectors.py
"""

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from crypto_vectors import OPENSSL  # noqa: E402

TMP = tempfile.mkdtemp()

# Set numbers as slhdsa.goose has them: 1-6 SHA2, 7-12 SHAKE; 128s, 128f,
# 192s, 192f, 256s, 256f.
NAMES = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
         "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
         "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"]
N = {1: 16, 2: 16, 3: 24, 4: 24, 5: 32, 6: 32}
FAST = {2, 4, 6, 8, 10, 12}
OSSL_SIGNED = FAST | {1}
ACVP_SIGNED = FAST | {7}
PREHASHES = ["SHA2-224", "SHA2-256", "SHA2-384", "SHA2-512", "SHA2-512/224", "SHA2-512/256",
             "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512", "SHAKE-128", "SHAKE-256"]


def n_of(s):
    return N[(s - 1) % 6 + 1]


def path(name, data=None):
    p = os.path.join(TMP, name)
    if data is not None:
        with open(p, "wb") as f:
            f.write(data)
    return p


def run(args, ok=True):
    p = subprocess.run([OPENSSL, *args], capture_output=True)
    if ok and p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p


def ctx_opts(ctx):
    return ["-pkeyopt", f"hexcontext-string:{ctx.hex()}"] if ctx else []


def sign(pem, msg, ctx, opts):
    return run(["pkeyutl", "-sign", "-rawin", "-inkey", pem, "-in", path("msg", msg), *opts, *ctx_opts(ctx)]).stdout


def verifies(pem, msg, sig, ctx):
    p = run(["pkeyutl", "-verify", "-rawin", "-inkey", pem, "-in", path("msg", msg), "-sigfile", path("sig", sig),
             *ctx_opts(ctx)], ok=False)
    return p.returncode == 0


def sha3(b):
    return hashlib.sha3_256(b).hexdigest()


def openssl_vectors():
    rng = random.Random(20261114)
    rb = lambda k: bytes(rng.getrandbits(8) for _ in range(k))
    lines = []
    for s in range(1, 13):
        n = n_of(s)
        seed = rb(3 * n)
        pem = path(f"slh{s}.pem")
        run(["genpkey", "-algorithm", NAMES[s - 1], "-pkeyopt", f"hexseed:{seed.hex()}", "-out", pem])
        pk = run(["pkey", "-in", pem, "-pubout", "-outform", "DER"]).stdout[-2 * n:]
        signed = s in OSSL_SIGNED
        lines.append(f"key {s} {seed.hex()} {pk.hex()}")
        # openssl pkeyutl reads no empty file, so messages have a byte at least.
        for i, ctx in enumerate((b"", rb(255)) if signed else (rb(rng.randrange(1, 40)),)):
            msg = rb(rng.choice([1, 33, rng.randrange(1, 300)]))
            sig = sign(pem, msg, ctx, ["-pkeyopt", "deterministic:1"])
            assert verifies(pem, msg, sig, ctx)
            here = signed and i == 0
            lines.append(f"sig {ctx.hex() or '-'} {msg.hex()} {sha3(sig) if here else sig.hex()}")
            # Changes openssl refuses: in R, in FORS, in the hypertree, at
            # the end; a byte short and a byte long.
            fl = len(sig)
            for off in (rng.randrange(n), n + rng.randrange(fl // 3), fl // 2 + rng.randrange(fl // 2), fl - 1, -1, -2):
                mask = 1 << rng.randrange(8)
                if off >= 0:
                    b = bytearray(sig)
                    b[off] ^= mask
                    bad = bytes(b)
                else:
                    bad = sig[:-1] if off == -1 else sig + b"\0"
                assert not verifies(pem, msg, bad, ctx), "openssl accepted a changed signature"
                lines.append(f"bad {ctx.hex() or '-'} {msg.hex()} {off} {mask}")
    print(f"SLH-DSA: {len(lines)} lines from openssl")
    return lines


def acvp_vectors(d):
    lines = []
    kg = json.load(open(os.path.join(d, "SLH-DSA-keyGen-FIPS205.json")))
    for g in kg["testGroups"]:
        s = NAMES.index(g["parameterSet"]) + 1
        if s % 2 == 0:
            t = g["tests"][0]
            lines.append(f"akey {s} {(t['skSeed'] + t['skPrf'] + t['pkSeed']).lower()} {t['sk'].lower()}")
    sg = json.load(open(os.path.join(d, "SLH-DSA-sigGen-FIPS205.json")))
    picked = {}
    for g in sg["testGroups"]:
        s = NAMES.index(g["parameterSet"]) + 1
        iface = "internal" if g["signatureInterface"] == "internal" else ("prehash" if g["preHash"] == "preHash" else "pure")
        det = g["deterministic"]
        # A pre-hash per set, each set's a different one; for the sets
        # signed from here, an internal deterministic case (verified) and a
        # hedged pure one (signed).
        want = (iface == "prehash" and det) or (s in ACVP_SIGNED and ((iface == "internal" and det) or (iface == "pure" and not det)))
        if not want or (s, iface) in picked:
            continue
        tests = g["tests"]
        t = tests[0]
        if iface == "prehash":
            t = next((x for x in tests if x["hashAlg"] == PREHASHES[s - 1]), t)
        picked[(s, iface)] = True
        sig = bytes.fromhex(t["signature"])
        here = (s in FAST and iface != "internal") or (s in ACVP_SIGNED and iface == "pure")
        out = sha3(sig) if here else sig.hex()
        ctx = t.get("context", "").lower() or "-"
        rnd = t.get("additionalRandomness", "").lower() or "-"
        lines.append(f"asig {s} {iface} {t['hashAlg']} {t['sk'].lower()} {ctx} {t['message'].lower() or '-'} {rnd} {out}")
    hashes = {l.split()[3] for l in lines if l.startswith("asig") and l.split()[2] == "prehash"}
    print(f"SLH-DSA: {len(lines)} ACVP lines, pre-hashes {sorted(hashes)}")
    return lines


def generate():
    out = {"slhdsa.txt": openssl_vectors()}
    d = os.environ.get("SLHDSA_ACVP_DIR")
    if d:
        out["slhdsa_acvp.txt"] = acvp_vectors(d)
    return out


if __name__ == "__main__":
    import gen_vectors
    for name, lines in generate().items():
        gen_vectors.write(name, lines)
