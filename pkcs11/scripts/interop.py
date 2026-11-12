#!/usr/bin/env python3
"""pkcs11 against OpenSC's pkcs11-tool and OpenSSL, on a fresh SoftHSM2
token (scripts/run_tests.py's setup):

1. Goose makes keys (RSA, P-256, Ed25519, AES; tools/interop.goose keys);
   pkcs11-tool lists them.
2. Goose signs (RSA PKCS #1 v1.5 and PSS, ECDSA over a digest and with
   SHA-256, EdDSA); pkcs11-tool verifies each with the key Goose made.
3. pkcs11-tool reads the RSA public key Goose made out of the token, and
   OpenSSL verifies Goose's RSA signature with it, PKCS#11 out of the loop.
4. pkcs11-tool makes keys (RSA, P-256, Ed25519) and signs with them by the
   same mechanisms; Goose verifies.

    python3 scripts/interop.py [--goose PATH]

Needs softhsm2-util, pkcs11-tool and openssl; a missing one is reported and
the run skipped.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_tests  # noqa: E402

ROOT = run_tests.ROOT


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = run_tests.find_goose(args.goose)
    module, util = run_tests.find_module(), run_tests.softhsm_util()
    tool, openssl = shutil.which("pkcs11-tool"), shutil.which("openssl")
    if not (module and util and tool and openssl):
        print("skipped: needs SoftHSM2, pkcs11-tool (OpenSC) and openssl")
        return
    passed, failed = 0, []
    with tempfile.TemporaryDirectory() as tmp:
        env = run_tests.token_env(tmp, module, util)
        base = [tool, "--module", module, "--token-label", run_tests.LABEL, "--login", "--pin", run_tests.PIN]
        msg = os.path.join(tmp, "msg")
        with open(msg, "wb") as f:
            f.write(b"interoperate with the rest of the world\n")

        def run(what, cmd, want=None, cwd=tmp):
            nonlocal passed
            p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
            out = p.stdout + p.stderr
            ok = p.returncode == 0 and (want is None or want in out)
            print(("ok    " if ok else "FAIL  ") + what)
            if ok:
                passed += 1
            else:
                failed.append(what)
                print(f"      exit {p.returncode}: " + out.strip()[-1500:].replace("\n", "\n      "))
            return ok

        def g(*words):
            return [goose, "-O2", os.path.join(ROOT, "tools", "interop.goose"), "--", *words]

        run("goose makes keys", g("keys"), "keys made", cwd=ROOT)
        p = subprocess.run(base + ["--list-objects"], env=env, capture_output=True, text=True)
        for label in ["goose-rsa", "goose-ec", "goose-ed", "goose-aes"]:
            ok = label in p.stdout
            print(("ok    " if ok else "FAIL  ") + f"pkcs11-tool lists {label}")
            passed += ok
            if not ok:
                failed.append(label)

        # pkcs11-tool is told keys by ID and type: a pair's two halves share
        # their label, SoftHSM lists objects in no fixed order, and
        # pkcs11-tool given a label takes whichever half comes first (and has
        # crashed on landing on the wrong one).
        ids = {"goose-rsa": "10", "goose-ec": "11", "goose-ed": "12",
               "tool-rsa": "20", "tool-pss": "21", "tool-ec": "22", "tool-ecdsa": "23", "tool-ed": "24"}
        tool_mechs = {"RSA-SHA256": "SHA256-RSA-PKCS", "RSA-PSS-SHA256": "SHA256-RSA-PKCS-PSS",
                      "ECDSA": "ECDSA", "ECDSA-SHA256": "ECDSA-SHA256", "EDDSA": "EDDSA"}
        digest = os.path.join(tmp, "msg.sha256")
        with open(msg, "rb") as f, open(digest, "wb") as d:
            d.write(hashlib.sha256(f.read()).digest())
        for label, mech, data in [("goose-rsa", "RSA-SHA256", msg), ("goose-rsa", "RSA-PSS-SHA256", msg),
                                  ("goose-ec", "ECDSA", digest), ("goose-ec", "ECDSA-SHA256", msg),
                                  ("goose-ed", "EDDSA", msg)]:
            sig = os.path.join(tmp, f"{label}-{mech}.sig")
            extra = ["--mgf", "MGF1-SHA256", "--salt-len", "32"] if mech == "RSA-PSS-SHA256" else []
            if run(f"goose signs {mech}", g("sign", label, mech, data, sig), "signed", cwd=ROOT):
                run(f"pkcs11-tool verifies goose's {mech}",
                    base + ["--verify", "--mechanism", tool_mechs[mech], "--id", ids[label], "--type", "pubkey",
                            "--input-file", data, "--signature-file", sig] + extra, "Signature is valid")

        # PKCS#11 out of the loop: OpenSSL checks Goose's RSA signature with
        # the public key pkcs11-tool reads from the token.
        der, pem = os.path.join(tmp, "rsa.der"), os.path.join(tmp, "rsa.pem")
        run("pkcs11-tool reads goose's public key",
            base + ["--read-object", "--type", "pubkey", "--id", ids["goose-rsa"], "--output-file", der])
        run("openssl converts it", [openssl, "pkey", "-pubin", "-inform", "DER", "-in", der, "-out", pem])
        run("openssl verifies goose's RSA signature",
            [openssl, "dgst", "-sha256", "-verify", pem, "-signature",
             os.path.join(tmp, "goose-rsa-RSA-SHA256.sig"), msg], "Verified OK")

        for key_type, label, mech, data in [("RSA:2048", "tool-rsa", "RSA-SHA256", msg),
                                            ("RSA:2048", "tool-pss", "RSA-PSS-SHA256", msg),
                                            ("EC:prime256v1", "tool-ec", "ECDSA", digest),
                                            ("EC:prime256v1", "tool-ecdsa", "ECDSA-SHA256", msg),
                                            ("EC:edwards25519", "tool-ed", "EDDSA", msg)]:
            sig = os.path.join(tmp, f"{label}.sig")
            extra = ["--mgf", "MGF1-SHA256", "--salt-len", "32"] if mech == "RSA-PSS-SHA256" else []
            if run(f"pkcs11-tool makes {key_type} ({label})",
                   base + ["--keypairgen", "--key-type", key_type, "--label", label, "--id", ids[label],
                           "--usage-sign"]) \
                    and run(f"pkcs11-tool signs {tool_mechs[mech]}",
                            base + ["--sign", "--mechanism", tool_mechs[mech], "--id", ids[label], "--type",
                                    "privkey", "--input-file", data, "--output-file", sig] + extra):
                run(f"goose verifies pkcs11-tool's {mech}", g("verify", label, mech, data, sig),
                    "signature is valid", cwd=ROOT)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
