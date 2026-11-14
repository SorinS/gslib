#!/usr/bin/env python3
"""Makes test/vectors with gpg: three test keys and messages gpg writes with
them, for test/gpg_vectors.goose. The keys are for tests only; the
passphrase of the protected ones is in vectors/passphrase.txt.

    python3 scripts/gen_vectors.py

Keys (user IDs at example.com):
  ed.pub, ed.sec        Ed25519 + Curve25519, gpg's default, unprotected
  prot.pub, prot.sec    the same kind, protected by the passphrase
  rsa.pub, rsa.sec      RSA-3072 + RSA-3072, protected by the passphrase
  nist.pub, nist.sec    ECDSA P-384 + ECDH P-384, unprotected
keys.txt lists each key's fingerprints. msg.txt and text.txt are what the
messages carry; the messages are named for how gpg was asked to make them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gpghome import GpgHome, GPG  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "test", "vectors")
PASS = b"test-passphrase-not-secret"
MSG = b"Hello, world!\nSecond line.\n"
TEXT = b"- a line that starts with a dash\nFrom the start  \ntrailing spaces and tabs \t\n\nlast line\n"


def main():
    if not GPG:
        sys.exit("gpg not found")
    os.makedirs(OUT, exist_ok=True)
    with GpgHome() as g:
        def w(name, data):
            with open(os.path.join(OUT, name), "wb") as f:
                f.write(data)

        pf = os.path.join(g.dir, "pass")
        with open(pf, "wb") as f:
            f.write(PASS)
        lp = ["--pinentry-mode", "loopback", "--passphrase-file", pf]
        g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
              "Test <test@example.com>", "default", "default", "never")
        g.gpg(*lp, "--quick-gen-key", "Test Protected <prot@example.com>", "default", "default", "never")
        spec = ("Key-Type: RSA\nKey-Length: 3072\nSubkey-Type: RSA\nSubkey-Length: 3072\n"
                "Name-Real: Test RSA\nName-Email: rsa@example.com\nExpire-Date: 0\n"
                "Passphrase: %s\n%%commit\n" % PASS.decode())
        g.gpg("--gen-key", input=spec.encode())
        keys = g.gpg("--with-colons", "--fingerprint", "--list-keys").stdout.decode()
        w("keys.txt", "".join(l + "\n" for l in keys.splitlines() if l.startswith(("fpr:", "uid:"))).encode())
        g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-gen-key",
              "Test NIST <nist@example.com>", "nistp384", "sign,cert", "never")
        fpr = [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", "nist@example.com")
               .stdout.decode().splitlines() if l.startswith("fpr:")][0]
        g.gpg("--passphrase", "", "--pinentry-mode", "loopback", "--quick-add-key", fpr, "nistp384", "encr", "never")
        for name, uid in (("ed", "test@example.com"), ("prot", "prot@example.com"), ("rsa", "rsa@example.com"),
                          ("nist", "nist@example.com")):
            w(name + ".pub", g.gpg("--export", uid).stdout)
            w(name + ".sec", g.gpg(*lp, "--export-secret-keys", uid).stdout)
        w("msg.txt", MSG)
        w("text.txt", TEXT)
        w("passphrase.txt", PASS + b"\n")
        msg = os.path.join(OUT, "msg.txt")
        text = os.path.join(OUT, "text.txt")
        t = ["--trust-model", "always"]

        def out(name, *args, src=msg):
            g.gpg(*t, *lp, "-o", os.path.join(OUT, name), *args, src)

        out("enc_ed.gpg", "-r", "test@example.com", "-e")
        out("enc_rsa.asc", "-r", "rsa@example.com", "-a", "-e")
        out("enc_signed.gpg", "-r", "test@example.com", "-r", "rsa@example.com", "-u", "test@example.com", "-s", "-e")
        out("enc_bzip2.gpg", "-r", "test@example.com", "--compress-algo", "bzip2", "-e")
        out("enc_nocomp.gpg", "-r", "rsa@example.com", "-z", "0", "-e")
        out("sym.gpg", "--s2k-count", "65536", "-c")
        out("sym_aes128_zlib.asc", "--s2k-count", "65536", "--cipher-algo", "AES128", "--compress-algo", "zlib", "-a", "-c")
        out("sig_inline.gpg", "-u", "test@example.com", "-s")
        out("sig_inline_rsa.asc", "-u", "rsa@example.com", "-a", "-s")
        out("det.sig", "-u", "test@example.com", "-b")
        out("det_rsa.asc", "-u", "rsa@example.com", "-a", "-b")
        out("det_text.asc", "-u", "test@example.com", "--textmode", "-a", "-b", src=text)
        out("clear.asc", "-u", "test@example.com", "--clearsign")
        out("clear_rsa.asc", "-u", "rsa@example.com", "--clearsign", src=text)
        out("det_nist.sig", "-u", "nist@example.com", "-b")
        out("enc_nist.gpg", "-r", "nist@example.com", "-e")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
