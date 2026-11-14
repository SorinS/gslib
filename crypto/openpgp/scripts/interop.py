#!/usr/bin/env python3
"""OpenPGP interop with gpg, both ways, through tools/pgp.goose (goose-pgp).

gpg makes test keys (Ed25519 + Curve25519, its default, RSA-3072,
ECDSA + ECDH on P-521, and Ed25519 with a post-quantum ky768_cv25519 subkey:
LibrePGP's ML-KEM-768+X25519 on a v5 key) in a throwaway GNUPGHOME;
goose-pgp makes one of each of its own default and post-quantum kinds, which
gpg imports, secrets and all.
Then each side reads what the other writes:

  goose-pgp -> gpg   detached, inline (each compression) and cleartext
                     signatures; encryption to each key, to two keys at
                     once, signed and not, armored and binary; to a
                     passphrase; signatures by the key goose-pgp made
  gpg -> goose-pgp   the same from gpg (its OCB packet to its own keys,
                     SEIPD v1 to goose-pgp's key and to a passphrase),
                     and its protected secret key exports (a Kyber
                     subkey's in gpg's mode 1003, under its agent's OCB)
  post-quantum       both ways, to gpg's Kyber key and to goose-pgp's

    python3 scripts/interop.py [--goose PATH] [--tool PATH] [-k NAME]

It skips (exit 0) when gpg is not installed. The agent it starts is
stopped with gpgconf --kill gpg-agent under that GNUPGHOME, and the
directory is removed. goose-pgp is built into the same temp directory
unless --tool names one.
"""

import argparse
import os
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gpghome import GpgHome, GPG  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
PASS = b"interop-test-passphrase"
TEXT = b"Interop text.\nA line with trailing spaces   \n- starts with a dash\nFrom here\n\nlast\n"


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


class Run:
    def __init__(self, g, tool, filt):
        self.g = g
        self.tool = tool
        self.filt = filt
        self.passed = 0
        self.failed = []
        self.d = g.dir
        self.pf = self.path("pass")
        self.write("pass", PASS)
        self.lp = ["--pinentry-mode", "loopback", "--passphrase-file", self.pf, "--trust-model", "always"]

    def path(self, name):
        return os.path.join(self.d, name)

    def write(self, name, data):
        with open(self.path(name), "wb") as f:
            f.write(data)

    def read(self, name):
        with open(self.path(name), "rb") as f:
            return f.read()

    def goose(self, *args):
        return subprocess.run([self.tool, *args], capture_output=True, cwd=self.d)

    def gpg(self, *args, check=False):
        return self.g.gpg(*self.lp, *args, check=check)

    def case(self, name, ok, detail=b""):
        if self.filt and self.filt not in name:
            return
        print(("ok    " if ok else "FAIL  ") + name)
        if ok:
            self.passed += 1
        else:
            self.failed.append(name)
            if detail:
                print("      " + detail.decode(errors="replace").strip().replace("\n", "\n      ")[:2000])

    def want(self, name):
        return not self.filt or self.filt in name


def setup(r):
    g = r.g
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
          "Interop Ed <ed@example.com>", "default", "default", "never")
    spec = ("%no-protection\nKey-Type: RSA\nKey-Length: 3072\nSubkey-Type: RSA\nSubkey-Length: 3072\n"
            "Name-Real: Interop RSA\nName-Email: rsa@example.com\nExpire-Date: 0\n%commit\n")
    g.gpg("--gen-key", input=spec.encode())
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
          "Interop NIST <nist@example.com>", "nistp521", "sign,cert", "never")
    fpr = [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", "nist@example.com")
           .stdout.decode().splitlines() if l.startswith("fpr:")][0]
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", fpr, "nistp521", "encr", "never")
    r.write("nist.pub", g.gpg("--export", "nist@example.com").stdout)
    r.write("nist.sec", g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys", "nist@example.com").stdout)
    r.write("ed.pub", g.gpg("--export", "ed@example.com").stdout)
    r.write("rsa.pub", g.gpg("--export", "rsa@example.com").stdout)
    r.write("ed.sec", g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys", "ed@example.com").stdout)
    r.write("rsa.sec", g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys", "rsa@example.com").stdout)
    # goose-pgp's own key, protected by the passphrase, into gpg.
    p = r.goose("genkey", "--pass-file", r.pf, "Interop Goose <goose@example.com>", "goose.sec", "goose.pub")
    r.case("genkey", p.returncode == 0, p.stderr)
    p = r.gpg("--import", r.path("goose.sec"))
    r.case("gpg imports goose-pgp's key", p.returncode == 0 and b"secret keys imported: 1" in p.stderr, p.stderr)
    # Post-quantum: gpg's Ed25519 + ky768_cv25519 (its default "pqc" key is
    # Brainpool, which goose-pgp does not do), and goose-pgp's own.
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
          "Interop PQC <pqc@example.com>", "ed25519", "cert,sign", "never")
    fpr = [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", "pqc@example.com")
           .stdout.decode().splitlines() if l.startswith("fpr:")][0]
    g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", fpr, "ky768_cv25519", "encr", "never")
    r.write("pqc.pub", g.gpg("--export", "pqc@example.com").stdout)
    r.write("pqc.sec", g.gpg("--pinentry-mode", "loopback", "--passphrase", "", "--export-secret-keys",
                             "pqc@example.com").stdout)
    p = r.goose("genkey", "--type", "pqc", "--pass-file", r.pf, "Interop Goose PQC <gpq@example.com>", "gpq.sec", "gpq.pub")
    r.case("genkey --type pqc", p.returncode == 0, p.stderr)
    p = r.gpg("--import", r.path("gpq.sec"))
    r.case("gpg imports goose-pgp's PQC key", p.returncode == 0 and b"secret keys imported: 1" in p.stderr, p.stderr)
    p = r.gpg("--with-colons", "--list-keys", "gpq@example.com")
    r.case("gpg lists goose-pgp's PQC key as ky768_cv25519", p.returncode == 0 and b"ky768_cv25519" in p.stdout,
           p.stdout + p.stderr)
    r.write("text.txt", TEXT)
    r.write("bin.dat", bytes((i * 37 + (i >> 7)) & 255 for i in range(5000)))


def ours_to_gpg(r):
    keys = ["-k", "ed.sec", "-k", "rsa.sec", "-k", "goose.sec", "-k", "nist.sec", "-k", "pqc.sec", "-k", "gpq.sec",
            "--pass-file", r.pf]
    for signer in ("ed", "rsa", "goose", "nist"):
        who = signer + "@example.com"
        for armor in ("armor", "binary"):
            name = f"gpg verifies our detached {signer} {armor}"
            if r.want(name):
                extra = [] if armor == "armor" else ["--binary"]
                p = r.goose("sign", *keys, "-u", who, "--detach", *extra, "bin.dat", "o.sig")
                q = r.gpg("--verify", r.path("o.sig"), r.path("bin.dat"))
                r.case(name, p.returncode == 0 and q.returncode == 0 and b"Good signature" in q.stderr, p.stderr + q.stderr)
        for z in ("none", "zip", "zlib", "bzip2"):
            name = f"gpg reads our inline {signer} -z {z}"
            if r.want(name):
                p = r.goose("sign", *keys, "-u", who, "-z", z, "text.txt", "o.asc")
                q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
                ok = q.returncode == 0 and b"Good signature" in q.stderr and r.read("o.out") == TEXT
                r.case(name, p.returncode == 0 and ok, p.stderr + q.stderr)
        name = f"gpg verifies our cleartext {signer}"
        if r.want(name):
            p = r.goose("sign", *keys, "-u", who, "--clear", "text.txt", "o.asc")
            q = r.gpg("--verify", r.path("o.asc"))
            r.case(name, p.returncode == 0 and q.returncode == 0 and b"Good signature" in q.stderr, p.stderr + q.stderr)
        name = f"gpg verifies our text-mode detached {signer}"
        if r.want(name):
            p = r.goose("sign", *keys, "-u", who, "--detach", "--text", "text.txt", "o.sig")
            q = r.gpg("--verify", r.path("o.sig"), r.path("text.txt"))
            r.case(name, p.returncode == 0 and q.returncode == 0 and b"Good signature" in q.stderr, p.stderr + q.stderr)
    for rcpt in ("ed", "rsa", "goose", "nist"):
        for z, armor in (("none", "armor"), ("zlib", "binary"), ("zip", "armor"), ("bzip2", "binary")):
            name = f"gpg decrypts ours to {rcpt} -z {z} {armor}"
            if r.want(name):
                extra = [] if armor == "armor" else ["--binary"]
                p = r.goose("encrypt", *keys, "-r", rcpt + "@example.com", "-z", z, *extra, "bin.dat", "o.gpg")
                q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.gpg"))
                ok = q.returncode == 0 and r.read("o.out") == r.read("bin.dat")
                r.case(name, p.returncode == 0 and ok, p.stderr + q.stderr)
    name = "gpg decrypts ours to ed and rsa, signed by goose"
    if r.want(name):
        p = r.goose("encrypt", *keys, "-r", "ed@example.com", "-r", "rsa@example.com", "--sign", "-u", "goose@example.com",
                    "-z", "zlib", "text.txt", "o.asc")
        q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
        ok = q.returncode == 0 and b"Good signature" in q.stderr and r.read("o.out") == TEXT
        r.case(name, p.returncode == 0 and ok, p.stderr + q.stderr)
    for rcpt in ("ed", "rsa"):
        name = f"gpg decrypts ours to {rcpt} with AES-128"
        if r.want(name):
            p = r.goose("encrypt", *keys, "-r", rcpt + "@example.com", "--cipher", "aes128", "text.txt", "o.asc")
            q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
            r.case(name, p.returncode == 0 and q.returncode == 0 and r.read("o.out") == TEXT, p.stderr + q.stderr)
    # Post-quantum: to gpg's Kyber key and to goose-pgp's (gpg has its secret).
    for rcpt in ("pqc", "gpq"):
        for z, armor in (("none", "armor"), ("zlib", "binary")):
            name = f"gpg decrypts ours to {rcpt} (Kyber) -z {z} {armor}"
            if r.want(name):
                extra = [] if armor == "armor" else ["--binary"]
                p = r.goose("encrypt", *keys, "-r", rcpt + "@example.com", "-z", z, *extra, "bin.dat", "o.gpg")
                q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.gpg"))
                ok = q.returncode == 0 and r.read("o.out") == r.read("bin.dat") and b"ky768_cv25519" in q.stderr
                r.case(name, p.returncode == 0 and ok, p.stderr + q.stderr)
    name = "gpg decrypts ours to pqc (Kyber) and ed, signed by gpq"
    if r.want(name):
        p = r.goose("encrypt", *keys, "-r", "pqc@example.com", "-r", "ed@example.com", "--sign", "-u", "gpq@example.com",
                    "text.txt", "o.asc")
        q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
        ok = q.returncode == 0 and b"Good signature" in q.stderr and r.read("o.out") == TEXT
        r.case(name, p.returncode == 0 and ok, p.stderr + q.stderr)
    name = "gpg decrypts ours to pqc (Kyber) with AES-128"
    if r.want(name):
        p = r.goose("encrypt", *keys, "-r", "pqc@example.com", "--cipher", "aes128", "text.txt", "o.asc")
        q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
        r.case(name, p.returncode == 0 and q.returncode == 0 and r.read("o.out") == TEXT, p.stderr + q.stderr)
    for cipher in ("aes128", "aes256"):
        name = f"gpg decrypts our passphrase message {cipher}"
        if r.want(name):
            p = r.goose("encrypt", "--symmetric", "--pass-file", r.pf, "--cipher", cipher, "-z", "zip", "text.txt", "o.asc")
            q = r.gpg("-o", r.path("o.out"), "--decrypt", r.path("o.asc"))
            r.case(name, p.returncode == 0 and q.returncode == 0 and r.read("o.out") == TEXT, p.stderr + q.stderr)


def gpg_to_ours(r):
    keys = ["-k", "ed.sec", "-k", "rsa.sec", "-k", "goose.sec", "-k", "nist.sec", "-k", "pqc.sec", "-k", "gpq.sec",
            "--pass-file", r.pf]
    pubs = ["-k", "ed.pub", "-k", "rsa.pub", "-k", "goose.pub", "-k", "nist.pub", "-k", "pqc.pub", "-k", "gpq.pub"]
    for signer in ("ed", "rsa", "goose", "nist"):
        who = signer + "@example.com"
        name = f"we verify gpg's detached {signer}"
        if r.want(name):
            q = r.gpg("-u", who, "-o", r.path("g.sig"), "-b", r.path("bin.dat"))
            p = r.goose("verify", *pubs, "bin.dat", "g.sig")
            r.case(name, q.returncode == 0 and p.returncode == 0 and b"good signature" in p.stdout, q.stderr + p.stdout + p.stderr)
        for z in ("0", "1", "2", "3"):
            name = f"we verify gpg's inline {signer} -z algo {z}"
            if r.want(name):
                q = r.gpg("-u", who, "--compress-algo", z, "-a", "-o", r.path("g.asc"), "-s", r.path("text.txt"))
                p = r.goose("verify", *pubs, "g.asc")
                r.case(name, q.returncode == 0 and p.returncode == 0 and b"good signature" in p.stdout, q.stderr + p.stdout + p.stderr)
        name = f"we verify gpg's cleartext {signer}"
        if r.want(name):
            q = r.gpg("-u", who, "-o", r.path("g.asc"), "--clearsign", r.path("text.txt"))
            p = r.goose("verify", *pubs, "g.asc")
            r.case(name, q.returncode == 0 and p.returncode == 0 and b"good signature" in p.stdout, q.stderr + p.stdout + p.stderr)
        name = f"we verify gpg's text-mode detached {signer}"
        if r.want(name):
            q = r.gpg("-u", who, "--textmode", "-o", r.path("g.sig"), "-b", r.path("text.txt"))
            p = r.goose("verify", *pubs, "text.txt", "g.sig")
            r.case(name, q.returncode == 0 and p.returncode == 0 and b"good signature" in p.stdout, q.stderr + p.stdout + p.stderr)
    for rcpt in ("ed", "rsa", "goose", "nist"):
        for z, armor in (("0", True), ("1", False), ("2", True), ("3", False)):
            name = f"we decrypt gpg's to {rcpt} -z algo {z} {'armor' if armor else 'binary'}"
            if r.want(name):
                extra = ["-a"] if armor else []
                q = r.gpg("-r", rcpt + "@example.com", "--compress-algo", z, *extra, "-o", r.path("g.gpg"), "-e", r.path("bin.dat"))
                p = r.goose("decrypt", *keys, "g.gpg", "g.out")
                ok = p.returncode == 0 and r.read("g.out") == r.read("bin.dat")
                r.case(name, q.returncode == 0 and ok, q.stderr + p.stderr)
    for rcpt in ("ed", "goose"):
        name = f"we decrypt gpg's to {rcpt} with AES-128"
        if r.want(name):
            q = r.gpg("-r", rcpt + "@example.com", "--cipher-algo", "AES128", "-o", r.path("g.gpg"), "-e", r.path("text.txt"))
            p = r.goose("decrypt", *keys, "g.gpg", "g.out")
            r.case(name, q.returncode == 0 and p.returncode == 0 and r.read("g.out") == TEXT, q.stderr + p.stderr)
    name = "we decrypt gpg's to ed, rsa and goose, signed by rsa"
    if r.want(name):
        q = r.gpg("-r", "ed@example.com", "-r", "rsa@example.com", "-r", "goose@example.com", "-u", "rsa@example.com",
                  "-o", r.path("g.gpg"), "-s", "-e", r.path("text.txt"))
        for k in ("ed.sec", "rsa.sec", "goose.sec"):
            p = r.goose("decrypt", "-k", k, *pubs, "--pass-file", r.pf, "g.gpg", "g.out")
            ok = p.returncode == 0 and r.read("g.out") == TEXT and b"good signature" in p.stderr
            r.case(f"{name} (with {k})", q.returncode == 0 and ok, q.stderr + p.stderr)
    for cipher in ("AES128", "AES256", "CAST5"):
        name = f"we decrypt gpg's passphrase message {cipher}"
        if r.want(name):
            q = r.gpg("--allow-old-cipher-algos", "--cipher-algo", cipher, "-o", r.path("g.gpg"), "-c", r.path("bin.dat"))
            p = r.goose("decrypt", "--pass-file", r.pf, "g.gpg", "g.out")
            r.case(name, q.returncode == 0 and p.returncode == 0 and r.read("g.out") == r.read("bin.dat"), q.stderr + p.stderr)
    name = "we read gpg's protected secret key export"
    if r.want(name):
        q = r.gpg("-o", r.path("g.sec"), "--export-secret-keys", "goose@example.com")
        p = r.goose("sign", "-k", "g.sec", "--pass-file", r.pf, "--detach", "text.txt", "g2.sig")
        v = r.gpg("--verify", r.path("g2.sig"), r.path("text.txt"))
        r.case(name, q.returncode == 0 and p.returncode == 0 and b"Good signature" in v.stderr, q.stderr + p.stderr + v.stderr)
    # Post-quantum: gpg's OCB packet to its Kyber key, SEIPD v1 to ours.
    for rcpt in ("pqc", "gpq"):
        for z, armor in (("0", True), ("2", False)):
            name = f"we decrypt gpg's to {rcpt} (Kyber) -z algo {z} {'armor' if armor else 'binary'}"
            if r.want(name):
                extra = ["-a"] if armor else []
                q = r.gpg("-r", rcpt + "@example.com", "--compress-algo", z, *extra, "-o", r.path("g.gpg"), "-e",
                          r.path("bin.dat"))
                p = r.goose("decrypt", *keys, "g.gpg", "g.out")
                ok = p.returncode == 0 and r.read("g.out") == r.read("bin.dat")
                r.case(name, q.returncode == 0 and ok, q.stderr + p.stderr)
    name = "we decrypt gpg's to pqc and gpq (Kyber), signed by pqc"
    if r.want(name):
        q = r.gpg("-r", "pqc@example.com", "-r", "gpq@example.com", "-u", "pqc@example.com",
                  "-o", r.path("g.gpg"), "-s", "-e", r.path("text.txt"))
        for k in ("pqc.sec", "gpq.sec"):
            p = r.goose("decrypt", "-k", k, *pubs, "--pass-file", r.pf, "g.gpg", "g.out")
            ok = p.returncode == 0 and r.read("g.out") == TEXT and b"good signature" in p.stderr
            r.case(f"{name} (with {k})", q.returncode == 0 and ok, q.stderr + p.stderr)
    name = "we read gpg's protected Kyber secret key export"
    if r.want(name):
        q = r.gpg("-o", r.path("g.sec"), "--export-secret-keys", "gpq@example.com")
        e = r.gpg("-r", "gpq@example.com", "-o", r.path("g.gpg"), "-e", r.path("text.txt"))
        p = r.goose("decrypt", "-k", "g.sec", "--pass-file", r.pf, "g.gpg", "g.out")
        ok = p.returncode == 0 and r.read("g.out") == TEXT
        r.case(name, q.returncode == 0 and e.returncode == 0 and ok, q.stderr + e.stderr + p.stderr)
    name = "we refuse gpg's Kyber message after a changed byte"
    if r.want(name):
        q = r.gpg("-r", "pqc@example.com", "-o", r.path("g.gpg"), "-e", r.path("bin.dat"))
        data = bytearray(r.read("g.gpg"))
        data[600] ^= 1                   # in the ML-KEM ciphertext
        r.write("g.bad", bytes(data))
        p = r.goose("decrypt", *keys, "g.bad", "g.out")
        r.case(name, q.returncode == 0 and p.returncode != 0, q.stderr + p.stderr)
    name = "we refuse gpg's message after a changed byte"
    if r.want(name):
        q = r.gpg("-r", "ed@example.com", "-o", r.path("g.gpg"), "-e", r.path("bin.dat"))
        data = bytearray(r.read("g.gpg"))
        data[-20] ^= 1
        r.write("g.bad", bytes(data))
        p = r.goose("decrypt", *keys, "g.bad", "g.out")
        r.case(name, q.returncode == 0 and p.returncode != 0 and b"integrity" in p.stderr, q.stderr + p.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--tool", help="a goose-pgp already built")
    ap.add_argument("-k", help="only cases whose name contains this")
    args = ap.parse_args()
    if not GPG:
        print("gpg not found: interop skipped")
        return 0
    with GpgHome() as g:
        tool = args.tool
        if not tool:
            tool = os.path.join(g.dir, "goose-pgp")
            goose = find_goose(args.goose)
            p = subprocess.run([goose, "build", "-o", tool, "pgp.goose"], cwd=os.path.join(ROOT, "tools"),
                               capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit("building goose-pgp failed:\n" + p.stdout + p.stderr)
        tool = os.path.abspath(tool)
        r = Run(g, tool, args.k)
        print(GPG, subprocess.run([GPG, "--version"], capture_output=True, text=True).stdout.splitlines()[0])
        setup(r)
        ours_to_gpg(r)
        gpg_to_ours(r)
        print(f"\n{r.passed} passed, {len(r.failed)} failed")
        return 1 if r.failed else 0


if __name__ == "__main__":
    sys.exit(main())
