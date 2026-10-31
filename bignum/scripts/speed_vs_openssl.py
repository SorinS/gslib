"""Every primitive's speed against openssl's on this machine.

Builds examples/speed.goose natively, runs it, measures the same
operations with `openssl speed` (16 KiB buffers, the EVP interface, so
openssl uses its assembly and the CPU's crypto instructions where it has
them), PBKDF2 and scrypt through hashlib (which calls OpenSSL), and
Argon2id with `openssl kdf`, then prints a Markdown table: the Goose
figure, openssl's, and Goose / openssl (above 1 is faster).

    python3 scripts/speed_vs_openssl.py [--goose PATH] [--seconds S] [prefix]
"""

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SECS = 1

# Goose name -> how openssl measures it.
EVP = ["md5", "sha1", "sha256", "sha512", "sha3-256", "blake2b512", "blake2s256",
       "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20", "aes-128-ctr", "aes-256-ctr",
       "aes-128-cbc", "aes-256-cbc", "aes-128-cfb", "aes-128-ofb", "des-ede3-cbc"]
LEGACY = ["des-cbc", "rc4"]


def speed(*args):
    out = subprocess.run(["openssl", "speed", "-mr", "-seconds", str(SECS), *args],
                         capture_output=True, text=True)
    lines = (out.stdout + out.stderr).splitlines()        # some counts go to stderr
    return [l.split(":") for l in lines if l.startswith("+")]


def openssl_figures(want):
    got = {}
    for name in EVP + LEGACY:
        if not want(name):
            continue
        extra = ["-provider", "legacy", "-provider", "default"] if name in LEGACY else []
        for f in speed("-bytes", "16384", *extra, "-evp", name):
            if f[0] == "+F":
                got[name] = float(f[3]) / 1e6
    if want("hmac-sha256"):
        for f in speed("-bytes", "16384", "-hmac", "sha256"):
            if f[0] == "+F":
                got["hmac-sha256"] = float(f[3]) / 1e6
    if want("x25519"):
        for f in speed("ecdhx25519"):
            if f[0] == "+F5":
                got["x25519"] = float(f[3])
    if want("ed25519"):
        for f in speed("ed25519"):
            if f[0] == "+F6":                    # OpenSSL 3
                got["ed25519-sign"], got["ed25519-verify"] = float(f[4]), float(f[5])
            elif f[0] == "+F4":                  # OpenSSL 4
                got["ed25519-sign"], got["ed25519-verify"] = float(f[3]), float(f[4])
    for c in ("p224", "p256", "p384", "p521"):
        if want(f"ecdh-{c}"):
            for f in speed(f"ecdh{c}"):
                if f[0] == "+F5":
                    got[f"ecdh-{c}"] = float(f[3])
        if want(f"ecdsa-{c}-sign") or want(f"ecdsa-{c}-verify"):
            for f in speed(f"ecdsa{c}"):
                if f[0] == "+F4":
                    got[f"ecdsa-{c}-sign"], got[f"ecdsa-{c}-verify"] = float(f[3]), float(f[4])
    for b in (2048, 3072, 4096):
        if want(f"rsa{b}"):
            for f in speed(f"rsa{b}"):
                if f[0] == "+F2":
                    got[f"rsa{b}-sign"], got[f"rsa{b}-verify"] = float(f[3]), float(f[4])
    for n in (512, 768, 1024):
        if want(f"mlkem{n}"):
            for f in speed(f"ML-KEM-{n}"):
                phase = {"+R15": "keygen", "+R16": "encaps", "+R17": "decaps"}.get(f[0])
                if phase:
                    got[f"mlkem{n}-{phase}"] = float(f[1]) / float(f[3])
    if want("pbkdf2"):
        got["pbkdf2-sha256-100k"] = rate(lambda: hashlib.pbkdf2_hmac("sha256", b"password", b"saltsaltsaltsalt",
                                                                     100000, 32))
    if want("scrypt"):
        got["scrypt-n15-r8"] = rate(lambda: hashlib.scrypt(b"password", salt=b"saltsaltsaltsalt", n=1 << 15, r=8,
                                                           p=1, maxmem=1 << 26, dklen=32))
    if want("argon2"):
        # The command's start-up, timed on an 8 KiB run, is taken off.
        def kdf(m):
            return lambda: subprocess.run(["openssl", "kdf", "-keylen", "32", "-kdfopt", "pass:password",
                                           "-kdfopt", "salt:saltsaltsaltsalt", "-kdfopt", "iter:1",
                                           "-kdfopt", f"memcost:{m}", "-kdfopt", "lanes:4", "-kdfopt", "threads:1",
                                           "ARGON2ID"], capture_output=True, check=True)
        base = 1 / rate(kdf(32))
        got["argon2id-t1-64m-p4"] = 1 / (1 / rate(kdf(65536)) - base)
    return got


def rate(fn):
    n, t0 = 0, time.perf_counter()
    while n == 0 or time.perf_counter() - t0 < SECS:
        fn()
        n += 1
    return n / (time.perf_counter() - t0)


def main():
    global SECS
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose", default=os.path.join(ROOT, "..", "goose.git", "build", "goose"))
    ap.add_argument("--seconds", type=float, default=1)
    ap.add_argument("prefix", nargs="?", default="")
    args = ap.parse_args()
    SECS = args.seconds
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "speed")
        subprocess.run([args.goose, "build", "-o", exe, os.path.join(ROOT, "examples", "speed.goose")],
                       check=True, capture_output=True)
        out = subprocess.run([exe, args.prefix], check=True, capture_output=True, text=True).stdout
    goose = []
    for line in out.splitlines():
        name, value, unit = line.split()
        goose.append((name, float(value), unit))
    ours = {g[0] for g in goose}
    theirs = openssl_figures(lambda n: any(o.startswith(n) or n.startswith(o) for o in ours))
    print(f"| Operation | Goose | OpenSSL {subprocess.run(['openssl', 'version'], capture_output=True, text=True).stdout.split()[1]} | Goose / OpenSSL |")
    print("|---|---:|---:|---:|")
    for name, value, unit in goose:
        o = theirs.get(name)
        ratio = f"{value / o:.2f}" if o else "-"
        fmt = (lambda v: f"{v:,.0f} {unit}") if unit == "op/s" and value >= 100 else (lambda v: f"{v:,.1f} {unit}")
        print(f"| {name} | {fmt(value)} | {fmt(o) if o else '-'} | {ratio} |")


if __name__ == "__main__":
    main()
