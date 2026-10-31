#!/usr/bin/env python3
"""Run Wycheproof's test vectors (github.com/C2SP/wycheproof) against bignum.

    python3 scripts/wycheproof.py [--wycheproof DIR] [--goose PATH] [--native] [--list] [file ...]

Each Wycheproof JSON file this package has an API for is converted to the
line format test/wycheproof/wycheproof.goose reads (one test a line), and
run. A valid test must succeed with Wycheproof's output, an invalid one must
fail; acceptable ones may go either way and are counted apart. Groups this
package does not implement (a hash, an MGF or a size it has no API for) are
counted as unsupported, with the reason. The Wycheproof checkout is
--wycheproof, else $WYCHEPROOF, else ../wycheproof.git beside this
repository; the compiler as for run_tests.py. Exit status 1 if any test
failed.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

HASHES = {"SHA-1": 160, "SHA-224": 224, "SHA-256": 256, "SHA-384": 384, "SHA-512": 512,
          "SHA-512/224": 5224, "SHA-512/256": 5256, "SHA3-224": 3224, "SHA3-256": 3256,
          "SHA3-384": 3384, "SHA3-512": 3512}
CURVES = {"secp224r1": 224, "secp256r1": 256, "secp384r1": 384, "secp521r1": 521}
MLKEM = {"ML-KEM-512": 2, "ML-KEM-768": 3, "ML-KEM-1024": 4}


class Unsupported(Exception):
    pass


def h(x):
    return x if x else "-"


def hash_id(name):
    if name not in HASHES:
        raise Unsupported(f"hash {name}")
    return HASHES[name]


def primes_of(n, e, d):
    """p and q from n, e and d (the standard randomized method)."""
    import random
    k = d * e - 1
    t = 0
    while k % 2 == 0:
        k //= 2
        t += 1
    rnd = random.Random(1)
    for _ in range(1000):
        g = rnd.randrange(2, n - 1)
        y = pow(g, k, n)
        for _ in range(t):
            x = pow(y, 2, n)
            if x == 1 and y not in (1, n - 1):
                import math
                p = math.gcd(y - 1, n)
                q = n // p
                return max(p, q), min(p, q)
            y = x
    raise Unsupported("cannot factor n")


def hexint(v, size=None):
    s = format(v, "x")
    if len(s) % 2:
        s = "0" + s
    return s


def rsa_private(k):
    n = int(k["modulus"], 16)
    e = int(k["publicExponent"], 16)
    d = int(k["privateExponent"], 16)
    if "prime1" in k:
        p, q = int(k["prime1"], 16), int(k["prime2"], 16)
    else:
        p, q = primes_of(n, e, d)
    return [hexint(n), hexint(e), hexint(d), hexint(p), hexint(q)]


def convert(name, d):
    """The lines for one file, and a Counter of unsupported tests by reason."""
    lines, skipped = [], Counter()
    for g in d["testGroups"]:
        tests = g["tests"]
        try:
            rows = group_rows(name, d, g)
        except Unsupported as u:
            skipped[str(u)] += len(tests)
            continue
        for t in tests:
            try:
                fields = rows(t)
            except Unsupported as u:
                skipped[str(u)] += 1
                continue
            except KeyError as e:
                skipped[f"{g['type']} test without field {e}"] += 1
                continue
            lines.append(" ".join([fields[0], str(t["tcId"]), t["result"]] + [h(x) for x in fields[1:]]))
    return lines, skipped


def group_rows(name, d, g):
    typ = g["type"]
    alg = d["algorithm"]
    # bignum takes RSA keys of 1024 to 8192 bits (rsa_public_from).
    if typ.startswith("Rsa") and g.get("keySize", 0) > 8192:
        raise Unsupported("RSA keys above 8192 bits")
    if typ == "AeadTest":
        kind = {"AES-GCM": "aead_gcm", "CHACHA20-POLY1305": "aead_chacha", "XCHACHA20-POLY1305": "aead_xchacha"}.get(alg)
        if not kind:
            raise Unsupported(f"AEAD {alg}")
        if g["tagSize"] != 128:
            raise Unsupported(f"{alg} with {g['tagSize']}-bit tags")
        return lambda t: [kind, t["key"], t["iv"], t["aad"], t["msg"], t["ct"], t["tag"]]
    if typ == "IndCpaTest" and alg == "AES-CBC-PKCS5":
        return lambda t: ["cbc", t["key"], t["iv"], t["msg"], t["ct"]]
    if typ == "IndCpaTest" and alg == "AES-XTS":
        def xts(t):
            if len(t["msg"]) % 32 != 0 or len(t["msg"]) == 0:
                raise Unsupported("XTS ciphertext stealing (partial blocks)")
            if len(t["iv"]) != 16:
                raise Unsupported("XTS tweak not 64 bits")
            return ["xts", t["key"], t["iv"], t["msg"], t["ct"]]
        return xts
    if typ == "MacTest" and alg.startswith("HMAC"):
        hn = {"HMACSHA1": "SHA-1", "HMACSHA224": "SHA-224", "HMACSHA256": "SHA-256", "HMACSHA384": "SHA-384",
              "HMACSHA512": "SHA-512", "HMACSHA512/224": "SHA-512/224", "HMACSHA512/256": "SHA-512/256",
              "HMACSHA3-224": "SHA3-224", "HMACSHA3-256": "SHA3-256", "HMACSHA3-384": "SHA3-384",
              "HMACSHA3-512": "SHA3-512"}.get(alg)
        if not hn:
            raise Unsupported(f"MAC {alg}")
        hid = hash_id(hn)
        return lambda t: ["mac", str(hid), t["key"], t["msg"], t["tag"]]
    if typ == "HkdfTest":
        hid = hash_id(alg.replace("HKDF-", ""))
        return lambda t: ["hkdf", str(hid), t["ikm"], t["salt"], t["info"], str(t["size"]), t["okm"]]
    if typ == "PbkdfTest":
        hid = hash_id(alg.replace("PBKDF2-HMAC", "").replace("SHA", "SHA-"))
        return lambda t: ["pbkdf2", str(hid), t["password"], t["salt"], str(t["iterationCount"]), str(t["dkLen"]), t["dk"]]
    if typ == "EcdhEcpointTest":
        if g["curve"] not in CURVES:
            raise Unsupported(f"curve {g['curve']}")
        c = str(CURVES[g["curve"]])
        size = (CURVES[g["curve"]] + 7) // 8
        # Wycheproof's private keys are integers (a leading 00 at times);
        # ecdh_shared takes them as wide as the curve.
        def ecdh(t):
            v = int(t["private"] or "0", 16)
            if v.bit_length() > 8 * size:
                raise Unsupported("ECDH private key wider than the curve")
            return ["ecdh", c, t["public"], v.to_bytes(size, "big").hex(), t["shared"]]
        return ecdh
    if typ in ("EcdsaVerify", "EcdsaP1363Verify"):
        if g["publicKey"]["curve"] not in CURVES:
            raise Unsupported(f"curve {g['publicKey']['curve']}")
        c = str(CURVES[g["publicKey"]["curve"]])
        hid = str(hash_id(g["sha"]))
        pk = g["publicKey"]["uncompressed"]
        enc = "der" if typ == "EcdsaVerify" else "p1363"
        return lambda t: ["ecdsa", c, hid, pk, t["msg"], t["sig"], enc]
    if typ == "EddsaVerify":
        if g["publicKey"]["curve"] != "edwards25519":
            raise Unsupported(f"EdDSA on {g['publicKey']['curve']}")
        pk = g["publicKey"]["pk"]
        return lambda t: ["ed25519", pk, t["msg"], t["sig"]]
    if typ == "XdhComp":
        if g["curve"] != "curve25519":
            raise Unsupported(f"XDH on {g['curve']}")
        return lambda t: ["x25519", t["public"], t["private"], t["shared"]]
    if typ == "RsassaPkcs1Verify":
        hid = str(hash_id(g["sha"]))
        n, e = g["publicKey"]["modulus"], g["publicKey"]["publicExponent"]
        return lambda t: ["rsa_pkcs1_verify", hid, n, e, t["msg"], t["sig"]]
    if typ == "RsassaPssVerify":
        if g["mgf"] != "MGF1" or g["mgfSha"] != g["sha"]:
            raise Unsupported(f"PSS with {g['mgf']} {g.get('mgfSha')} under {g['sha']}")
        hid = str(hash_id(g["sha"]))
        n, e = g["publicKey"]["modulus"], g["publicKey"]["publicExponent"]
        return lambda t: ["rsa_pss_verify", hid, str(g["sLen"]), n, e, t["msg"], t["sig"]]
    if typ == "RsassaPkcs1Generate":
        hid = str(hash_id(g["sha"]))
        key = rsa_private(g["privateKey"])
        return lambda t: ["rsa_pkcs1_sign", hid] + key + [t["msg"], t["sig"]]
    if typ == "RsaesOaepDecrypt":
        if g["mgf"] != "MGF1" or g["mgfSha"] != g["sha"]:
            raise Unsupported(f"OAEP with {g['mgf']} {g.get('mgfSha')} under {g['sha']}")
        hid = str(hash_id(g["sha"]))
        if "prime1" not in g["privateKey"]:
            raise Unsupported("OAEP key without primes")
        key = rsa_private(g["privateKey"])
        return lambda t: ["rsa_oaep", hid] + key + [t["msg"], t["ct"], t["label"]]
    if typ == "RsaesPkcs1Decrypt":
        key = rsa_private(g["privateKey"])
        return lambda t: ["rsa_pkcs1_dec"] + key + [t["msg"], t["ct"]]
    if typ in ("DsaVerify", "DsaP1363Verify"):
        hid = str(hash_id(g["sha"]))
        k = g["publicKey"]
        enc = "der" if typ == "DsaVerify" else "p1363"
        return lambda t: ["dsa", hid, k["p"], k["q"], k["g"], k["y"], t["msg"], t["sig"], enc]
    if typ == "MLKEMKeyGen":
        kk = str(MLKEM[g["parameterSet"]])
        return lambda t: ["mlkem_keygen", kk, t["seed"], t["ek"], t["dk"]]
    if typ == "MLKEMTest":
        kk = str(MLKEM[g["parameterSet"]])
        return lambda t: ["mlkem_dec", kk, t["seed"], t.get("ek", ""), t["c"], t["K"]]
    if typ == "MLKEMEncapsTest":
        kk = str(MLKEM[g["parameterSet"]])
        return lambda t: ["mlkem_encaps", kk, t["m"], t["ek"], t["c"], t["K"]]
    if typ == "MLKEMDecapsValidationTest" or (typ.startswith("MLKEM") and "semi" in name):
        kk = str(MLKEM[g["parameterSet"]])
        return lambda t: ["mlkem_semi", kk, t["dk"], t["c"], t["K"]]
    if typ == "MlDsaVerify":
        s = name.split("_")[1]
        return lambda t: ["mldsa_verify", s, g["publicKey"], t["msg"], t["sig"], t.get("ctx", "")]
    if typ == "MlDsaSign":
        if "privateSeed" not in g:
            raise Unsupported("ML-DSA signing from an expanded key (bignum signs from seeds)")
        s = name.split("_")[1]
        # "msg" absent: an external mu, signed as given.
        return lambda t: ["mldsa_sign", s, g["privateSeed"], g["publicKey"], t.get("msg", ""), t.get("ctx", ""),
                          t.get("mu", ""), t.get("rnd", ""), t["sig"], "1" if "msg" in t else "0"]
    if typ == "PrimalityTest":
        return lambda t: ["prime", t["value"]]
    raise Unsupported(f"{typ} ({alg})")


# The files this package has an API for, by pattern; others are not tried.
WANTED = ("aes_gcm_test", "chacha20_poly1305_test", "xchacha20_poly1305_test", "aes_cbc_pkcs5_test",
          "aes_xts_test", "hmac_", "hkdf_", "pbkdf2_", "ecdh_secp224r1_ecpoint", "ecdh_secp256r1_ecpoint",
          "ecdh_secp384r1_ecpoint", "ecdh_secp521r1_ecpoint", "ecdsa_secp224r1_", "ecdsa_secp256r1_",
          "ecdsa_secp384r1_", "ecdsa_secp521r1_", "ed25519_test", "x25519_test", "rsa_signature_", "rsa_pss_",
          "rsa_pkcs1_", "rsa_oaep_", "dsa_", "mlkem_", "mldsa_", "primality_test")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wycheproof", default=os.environ.get("WYCHEPROOF") or os.path.join(ROOT, "..", "wycheproof.git"))
    ap.add_argument("--goose")
    ap.add_argument("--list", action="store_true", help="only list the files that would run")
    ap.add_argument("files", nargs="*", help="Wycheproof file names (without _test.json); all wanted ones by default")
    args = ap.parse_args()
    vdir = os.path.join(args.wycheproof, "testvectors_v1")
    if not os.path.isdir(vdir):
        sys.exit(f"no Wycheproof at {args.wycheproof}: pass --wycheproof or set WYCHEPROOF")
    names = sorted(f[:-len("_test.json")] for f in os.listdir(vdir) if f.endswith("_test.json"))
    if args.files:
        names = [n for n in names if n in args.files]
    else:
        names = [n for n in names if any((n + "_test").startswith(w) or w in n + "_test" for w in WANTED)
                 and not n.startswith("rsa_three_primes") and "_brainpool" not in n]
    if args.list:
        print("\n".join(names))
        return
    goose = find_goose(args.goose)
    totals = Counter()
    unsupported = Counter()
    bad = []
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "wycheproof")
        p = subprocess.run([goose, "build", "-O2", "-o", exe, os.path.join(ROOT, "test", "wycheproof", "wycheproof.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        print(f"| File | Tests | Valid passed | Invalid refused | Acceptable (taken/refused) | Failed | Unsupported |")
        print(f"|---|---:|---:|---:|---:|---:|---:|")
        for n in names:
            d = json.load(open(os.path.join(vdir, n + "_test.json")))
            lines, skipped = convert(n, d)
            unsupported.update({f"{n}: {r}": c for r, c in skipped.items()})
            nsk = sum(skipped.values())
            if not lines:
                print(f"| {n} | {d['numberOfTests']} | | | | | {nsk} |")
                continue
            path = os.path.join(tmp, n + ".txt")
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            r = subprocess.run([exe, path], capture_output=True, text=True)
            out = r.stdout.splitlines()
            if r.returncode != 0 or not out:
                print(f"| {n} | {d['numberOfTests']} | CRASH | | | | |")
                bad.append(f"{n}: exit {r.returncode}: {(r.stderr or r.stdout)[-300:]}")
                totals["crash"] += 1
                continue
            vo, vb, io, ib, at, ar = map(int, out[0].split())
            fails = vb + ib
            totals.update(tests=len(lines), valid=vo, invalid=io, taken=at, refused=ar, failed=fails, unsupported=nsk)
            print(f"| {n} | {d['numberOfTests']} | {vo} | {io} | {at}/{ar} | {fails} | {nsk} |")
            for l in out[1:]:
                if l.strip():
                    bad.append(f"{n}: {l.strip()}")
    print()
    print(f"{len(names)} files: {totals['tests']} tests run, {totals['valid']} valid passed, "
          f"{totals['invalid']} invalid refused, {totals['taken']}/{totals['refused']} acceptable taken/refused, "
          f"{totals['failed']} failed, {totals['crash']} crashed; {totals['unsupported']} unsupported")
    if unsupported:
        print("\nUnsupported:")
        for r, c in sorted(unsupported.items()):
            print(f"  {r}: {c}")
    if bad:
        print("\nFailures:")
        for b in bad[:200]:
            print("  " + b)
    sys.exit(1 if totals["failed"] or totals["crash"] else 0)


if __name__ == "__main__":
    main()
