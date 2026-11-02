#!/usr/bin/env python3
"""MIT's krb5 crypto as an oracle for krb5.crypto: test/vectors/mit_crypto.txt.

Builds a small C program against MIT's libk5crypto (Homebrew's keg-only
krb5 unless --mit names another prefix) and asks it, for every encryption
type krb5.crypto has, on random keys and inputs:

    s2k   etype password salt params key        krb5_c_string_to_key_with_params
    prf   etype key input output                krb5_c_prf
    cksum etype ctype key usage data checksum   krb5_c_make_checksum
    enc   etype key usage plain ciphertext      krb5_c_encrypt (MIT's confounder)

test/crypto.goose must give the same keys, PRF outputs and checksums, and
decrypt MIT's ciphertexts. MIT picks its confounders at random, so the enc
lines change on every run; the rest are fixed by the seed.

    python3 scripts/mit_crypto.py [--mit PREFIX]
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

ETYPES = [16, 17, 18, 19, 20, 23, 25, 26]
KEYLEN = {16: 24, 17: 16, 18: 32, 19: 16, 20: 32, 23: 16, 25: 16, 26: 32}
# The checksum type of each encryption type (RFC 3961 §4's required one).
CKSUM = {16: 12, 17: 15, 18: 16, 19: 19, 20: 20, 23: -138, 25: 17, 26: 18}

PROGRAM = r"""
#include <krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static krb5_context ctx;

static int unhex(const char *s, unsigned char *out) {
    size_t n = strlen(s);
    if (strcmp(s, "-") == 0) return 0;
    for (size_t i = 0; i < n / 2; i++) sscanf(s + 2 * i, "%2hhx", &out[i]);
    return (int)(n / 2);
}

static void hex(const unsigned char *p, size_t n) {
    if (n == 0) printf("-");
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static void die(const char *what, krb5_error_code e) {
    fprintf(stderr, "%s: %s\n", what, krb5_get_error_message(ctx, e));
    exit(1);
}

int main(void) {
    char op[16], a[4096], b[4096], c[4096], d[4096];
    int et, ct, usage;
    static unsigned char kb[64], x[2048], y[2048];
    if (krb5_init_context(&ctx)) return 1;
    while (scanf("%15s", op) == 1) {
        if (strcmp(op, "s2k") == 0) {
            scanf("%d %4095s %4095s %4095s", &et, a, b, c);
            unsigned char pw[2048], salt[2048], params[16];
            int pl = unhex(a, pw), sl = unhex(b, salt), ql = unhex(c, params);
            krb5_data pd = { 0, pl, (char *)pw }, sd = { 0, sl, (char *)salt }, qd = { 0, ql, (char *)params };
            krb5_keyblock k;
            krb5_error_code e = krb5_c_string_to_key_with_params(ctx, et, &pd, &sd, ql ? &qd : NULL, &k);
            if (e) die("string_to_key", e);
            hex(k.contents, k.length); printf("\n");
            krb5_free_keyblock_contents(ctx, &k);
        } else if (strcmp(op, "prf") == 0) {
            scanf("%d %4095s %4095s", &et, a, b);
            krb5_keyblock k = { 0, et, unhex(a, kb), kb };
            int il = unhex(b, x);
            size_t ol;
            krb5_error_code e = krb5_c_prf_length(ctx, et, &ol);
            if (e) die("prf_length", e);
            krb5_data in = { 0, il, (char *)x }, out = { 0, ol, (char *)y };
            e = krb5_c_prf(ctx, &k, &in, &out);
            if (e) die("prf", e);
            hex(y, ol); printf("\n");
        } else if (strcmp(op, "cksum") == 0) {
            scanf("%d %d %4095s %d %4095s", &et, &ct, a, &usage, b);
            krb5_keyblock k = { 0, et, unhex(a, kb), kb };
            int dl = unhex(b, x);
            krb5_data in = { 0, dl, (char *)x };
            krb5_checksum sum;
            krb5_error_code e = krb5_c_make_checksum(ctx, ct, &k, usage, &in, &sum);
            if (e) die("make_checksum", e);
            hex(sum.contents, sum.length); printf("\n");
            krb5_free_checksum_contents(ctx, &sum);
        } else if (strcmp(op, "enc") == 0) {
            scanf("%d %4095s %d %4095s", &et, a, &usage, b);
            krb5_keyblock k = { 0, et, unhex(a, kb), kb };
            int pl = unhex(b, x);
            size_t cl;
            krb5_error_code e = krb5_c_encrypt_length(ctx, et, pl, &cl);
            if (e) die("encrypt_length", e);
            krb5_data in = { 0, pl, (char *)x };
            krb5_enc_data out;
            memset(&out, 0, sizeof out);
            out.ciphertext.length = cl;
            out.ciphertext.data = (char *)y;
            e = krb5_c_encrypt(ctx, &k, usage, NULL, &in, &out);
            if (e) die("encrypt", e);
            hex(y, out.ciphertext.length); printf("\n");
        } else {
            fprintf(stderr, "unknown op %s\n", op);
            return 1;
        }
        fflush(stdout);
    }
    krb5_free_context(ctx);
    return 0;
}
"""


def hx(b):
    return b.hex() if b else "-"


def mit_prefix(arg):
    if arg:
        return arg
    brew = shutil.which("brew")
    if brew:
        p = subprocess.run([brew, "--prefix", "krb5"], capture_output=True, text=True)
        if p.returncode == 0:
            return p.stdout.strip()
    sys.exit("no MIT krb5: pass --mit PREFIX")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mit")
    args = ap.parse_args()
    prefix = mit_prefix(args.mit)
    cfg = os.path.join(prefix, "bin", "krb5-config")
    flags = subprocess.run([cfg, "--cflags", "--libs", "krb5"], capture_output=True, text=True, check=True).stdout.split()
    rng = random.Random(20261102)

    def rb(n):
        return bytes(rng.getrandbits(8) for _ in range(n))

    def rkey(et):
        # DES3 keys with odd parity in every byte, as MIT requires.
        k = rb(KEYLEN[et])
        if et != 16:
            return k
        return bytes((x & 0xfe) | (bin(x >> 1).count("1") + 1) % 2 for x in k)

    queries = []   # (kind, fields..., the request line)
    for et in ETYPES:
        # String-to-key: ASCII and UTF-8 passwords, empty and binary salts,
        # explicit iteration counts (none for DES3 and RC4, which take no
        # parameters).
        for pw, salt in ((b"password", b"ATHENA.MIT.EDUraeburn"), ("pässwörd \U0001d11e".encode(), b"EXAMPLE.COMuser"),
                         (b"x" * 70, b""), (b"short", rb(12))):
            # MIT refuses counts below the type's default (4096, or 32768
            # for RFC 8009 and 6803): the default, and above it.
            base = 4096 if et in (17, 18) else 32768
            for params in ((b"",) if et in (16, 23) else (b"", base.to_bytes(4, "big"), (base + 1001).to_bytes(4, "big"))):
                if et == 16 and not pw + salt:
                    continue
                queries.append(("s2k", et, pw, salt, params, f"s2k {et} {hx(pw)} {hx(salt)} {hx(params)}"))
        for i in range(6):
            key = rkey(et)
            inp = rb([0, 1, 15, 16, 17, 100][i])
            queries.append(("prf", et, key, inp, f"prf {et} {hx(key)} {hx(inp)}"))
        for i in range(6):
            key, usage = rkey(et), rng.choice([1, 2, 3, 7, 11, 22, 1026])
            data = rb([0, 1, 16, 31, 64, 200][i])
            queries.append(("cksum", et, CKSUM[et], key, usage, data, f"cksum {et} {CKSUM[et]} {hx(key)} {usage} {hx(data)}"))
        for n in (0, 1, 7, 8, 15, 16, 17, 31, 32, 33, 100):
            key, usage = rkey(et), rng.choice([1, 3, 9, 23, 1026])
            plain = rb(n)
            queries.append(("enc", et, key, usage, plain, f"enc {et} {hx(key)} {usage} {hx(plain)}"))

    with tempfile.TemporaryDirectory() as tmp:
        src, exe = os.path.join(tmp, "mit_crypto.c"), os.path.join(tmp, "mit_crypto")
        with open(src, "w") as f:
            f.write(PROGRAM)
        p = subprocess.run(["cc", "-O1", "-o", exe, src] + flags, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        env = dict(os.environ, KRB5_CONFIG=os.devnull)
        p = subprocess.run([exe], input="\n".join(q[-1] for q in queries) + "\n", capture_output=True, text=True, env=env)
        if p.returncode != 0:
            sys.exit(p.stderr)
        answers = p.stdout.split()
    assert len(answers) == len(queries), (len(answers), len(queries))

    lines = []
    for q, a in zip(queries, answers):
        if q[0] == "s2k":
            _, et, pw, salt, params, _ = q
            lines.append(f"s2k {et} {hx(pw)} {hx(salt)} {hx(params)} {a}")
        elif q[0] == "prf":
            _, et, key, inp, _ = q
            lines.append(f"prf {et} {hx(key)} {hx(inp)} {a}")
        elif q[0] == "cksum":
            _, et, ct, key, usage, data, _ = q
            lines.append(f"cksum {et} {ct} {hx(key)} {usage} {hx(data)} {a}")
        else:
            _, et, key, usage, plain, _ = q
            lines.append(f"enc {et} {hx(key)} {usage} {hx(plain)} {a}")
    path = os.path.join(ROOT, "test", "vectors", "mit_crypto.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} lines from MIT's krb5 ({prefix}) to {os.path.relpath(path)}")


if __name__ == "__main__":
    main()
