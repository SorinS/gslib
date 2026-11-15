#!/usr/bin/env python3
"""Makes the vectors of test/vectors for the newer curves with gpg 2.5, for
test/curves.goose, beside what gen_vectors.py and gen_pqc_vectors.py make:
Brainpool, Ed448 and cv448 (which gpg makes as v5 keys, signing v5
signatures), and gpg's default post-quantum key (brainpoolP384r1 with a
ky768_bp256 subkey) with its ky1024 kinds. The keys are for tests only; the
protected ones' passphrase is vectors/passphrase.txt's.

    python3 scripts/gen_curve_vectors.py

  bp256.pub/.sec, bp384, bp512   ECDSA + ECDH on brainpoolP256r1/P384r1/
                                 P512r1 (v4), unprotected
  ed448.pub/.sec                 Ed448 (v5 EdDSALegacy) + cv448 (v5 ECDH),
                                 unprotected; ed448_prot the same, protected
  pqcbp.pub/.sec                 gpg's default "pqc": brainpoolP384r1 (v4)
                                 with ky768_bp256 (v5 Kyber, mode 1003);
                                 pqcbp_prot the same, protected
  ky1024cv.pub/.sec              Ed448 with a ky1024_cv448 subkey, and
  ky1024bp.pub/.sec              brainpoolP384r1 with a ky1024_bp384 one,
                                 unprotected (gpg 2.5.22's agent fails to
                                 export one key with both: "Cannot allocate
                                 memory")
  keys_curves.txt                their fingerprints (gpg --with-colons)
  det_X.sig, sig_X.gpg           msg.txt signed by X, detached and inline
                                 (bp256, bp384, bp512, ed448, pqcbp)
  sigt_ed448.gpg, dett_ed448.asc text mode, inline and detached
  clear_ed448.asc, clear_bp256.asc  cleartext
  enc_X.gpg                      msg.txt to X (bp256, bp384, bp512, ed448,
                                 pqcbp), gpg's OCB packet
  enc_ed448_prot.asc, enc_pqcbp_prot.asc   to the protected keys, armored
  enc_ky1024cv.gpg, enc_ky1024bp.gpg   to each ky1024 key
  enc_curves_signed.gpg          to bp256, ed448 and pqcbp, signed by ed448
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

        def fpr(uid):
            return [l.split(":")[9] for l in g.gpg("--with-colons", "--fingerprint", "--list-keys", uid)
                    .stdout.decode().splitlines() if l.startswith("fpr:")][0]

        def make(uid, algo, usage, subs, prot=False):
            opts = lp if prot else none
            g.gpg(*opts, "--quick-gen-key", uid, algo, usage, "never")
            for sub in subs:
                g.gpg(*opts, "--quick-add-key", fpr(uid), sub, "encr", "never")

        make("Test BP256 <bp256@example.com>", "brainpoolP256r1", "cert,sign", ["brainpoolP256r1"])
        make("Test BP384 <bp384@example.com>", "brainpoolP384r1", "cert,sign", ["brainpoolP384r1"])
        make("Test BP512 <bp512@example.com>", "brainpoolP512r1", "cert,sign", ["brainpoolP512r1"])
        make("Test Ed448 <ed448@example.com>", "ed448", "cert,sign", ["cv448"])
        make("Test Ed448 Protected <ed448prot@example.com>", "ed448", "cert,sign", ["cv448"], True)
        make("Test PQC BP <pqcbp@example.com>", "pqc", "default", [])
        make("Test PQC BP Protected <pqcbpprot@example.com>", "pqc", "default", [], True)
        make("Test Kyber1024 X448 <ky1024cv@example.com>", "ed448", "cert,sign", ["ky1024_cv448"])
        make("Test Kyber1024 BP384 <ky1024bp@example.com>", "brainpoolP384r1", "cert,sign", ["ky1024_bp384"])
        keys = g.gpg("--with-colons", "--fingerprint", "--with-subkey-fingerprints", "--list-keys").stdout.decode()
        w("keys_curves.txt", "".join(l + "\n" for l in keys.splitlines() if l.startswith(("fpr:", "uid:"))).encode())
        names = {"bp256": "bp256@example.com", "bp384": "bp384@example.com", "bp512": "bp512@example.com",
                 "ed448": "ed448@example.com", "ed448_prot": "ed448prot@example.com", "pqcbp": "pqcbp@example.com",
                 "pqcbp_prot": "pqcbpprot@example.com", "ky1024cv": "ky1024cv@example.com",
                 "ky1024bp": "ky1024bp@example.com"}
        for name, uid in names.items():
            w(name + ".pub", g.gpg("--export", uid).stdout)
            w(name + ".sec", g.gpg(*lp, "--export-secret-keys", uid).stdout)
        msg = os.path.join(OUT, "msg.txt")
        t = ["--trust-model", "always"]

        def out(name, *args):
            g.gpg(*t, *lp, "-o", os.path.join(OUT, name), *args, msg)

        for name in ("bp256", "bp384", "bp512", "ed448", "pqcbp"):
            out("det_%s.sig" % name, "-u", names[name], "-b")
            out("sig_%s.gpg" % name, "-u", names[name], "-s")
            out("enc_%s.gpg" % name, "-r", names[name], "-e")
        out("sigt_ed448.gpg", "-u", names["ed448"], "--textmode", "-s")
        out("dett_ed448.asc", "-u", names["ed448"], "--textmode", "-a", "-b")
        out("clear_ed448.asc", "-u", names["ed448"], "--clearsign")
        out("clear_bp256.asc", "-u", names["bp256"], "--clearsign")
        out("enc_ed448_prot.asc", "-r", names["ed448_prot"], "-a", "-e")
        out("enc_pqcbp_prot.asc", "-r", names["pqcbp_prot"], "-a", "-e")
        out("enc_ky1024cv.gpg", "-r", names["ky1024cv"], "-e")
        out("enc_ky1024bp.gpg", "-r", names["ky1024bp"], "-e")
        out("enc_curves_signed.gpg", "-r", names["bp256"], "-r", names["ed448"], "-r", names["pqcbp"],
            "-u", names["ed448"], "-s", "-e")
    print("wrote", OUT)


if __name__ == "__main__":
    main()
