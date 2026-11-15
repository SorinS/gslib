#!/usr/bin/env python3
"""Makes the post-quantum vectors of test/vectors with gpg 2.5, for
test/pqc.goose, beside (not instead of) what gen_vectors.py makes: a key as
gpg makes its LibrePGP Kyber keys, and what gpg writes to it. The keys are
for tests only; the protected one's passphrase is vectors/passphrase.txt's.

    python3 scripts/gen_pqc_vectors.py

  pqc.pub, pqc.sec        Ed25519 (v4) + ky768_cv25519 (v5 Kyber subkey,
                          ML-KEM-768+X25519), unprotected: gpg exports the
                          subkey's secret in its agent's format (mode 1003)
  pqc_prot.pub, .sec      the same kind, protected: the X25519 half under
                          the agent's OCB, the ML-KEM half as gpg leaves it
  keys_pqc.txt            their fingerprints (gpg --with-colons)
  enc_pqc.gpg             msg.txt to pqc (gpg's OCB packet, tag 20)
  enc_pqc_prot.asc        msg.txt to pqc_prot, armored
  enc_pqc_signed.gpg      msg.txt to pqc and pqc_prot, signed by pqc

gpg's default "pqc" key (brainpoolP384r1 with ky768_bp256) is made by
gen_curve_vectors.py, with the other newer curves. The RFC 9980 vectors
(rfc9980_a*.asc) are its Appendix A, copied as they are; gpg 2.5 does not
read them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from gpghome import GpgHome, GPG  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "test", "vectors")


def main():
    if not GPG:
        sys.exit("gpg not found")
    with open(os.path.join(OUT, "passphrase.txt"), "rb") as f:
        passphrase = f.read().rstrip(b"\r\n")
    with GpgHome() as g:
        def w(name, data):
            with open(os.path.join(OUT, name), "wb") as f:
                f.write(data)

        pf = os.path.join(g.dir, "pass")
        with open(pf, "wb") as f:
            f.write(passphrase)
        lp = ["--pinentry-mode", "loopback", "--passphrase-file", pf]
        none = ["--pinentry-mode", "loopback", "--passphrase", ""]

        def make(uid, prot):
            opts = lp if prot else none
            g.gpg(*opts, "--quick-gen-key", uid, "ed25519", "cert,sign", "never")
            fpr = [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", uid)
                   .stdout.decode().splitlines() if l.startswith("fpr:")][0]
            g.gpg(*opts, "--quick-add-key", fpr, "ky768_cv25519", "encr", "never")

        make("Test PQC <pqc@example.com>", False)
        make("Test PQC Protected <pqcprot@example.com>", True)
        keys = g.gpg("--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys").stdout.decode()
        w("keys_pqc.txt", "".join(l + "\n" for l in keys.splitlines() if l.startswith(("fpr:", "uid:"))).encode())
        for name, uid in (("pqc", "pqc@example.com"), ("pqc_prot", "pqcprot@example.com")):
            w(name + ".pub", g.gpg("--export", uid).stdout)
            w(name + ".sec", g.gpg(*lp, "--export-secret-keys", uid).stdout)
        msg = os.path.join(OUT, "msg.txt")
        t = ["--trust-model", "always"]

        def out(name, *args):
            g.gpg(*t, *lp, "-o", os.path.join(OUT, name), *args, msg)

        out("enc_pqc.gpg", "-r", "pqc@example.com", "-e")
        out("enc_pqc_prot.asc", "-r", "pqcprot@example.com", "-a", "-e")
        out("enc_pqc_signed.gpg", "-r", "pqc@example.com", "-r", "pqcprot@example.com", "-u", "pqc@example.com",
            "-s", "-e")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
