#!/usr/bin/env python3
"""goose-ts against openssl ts and a Go TSA (github.com/digitorus/timestamp),
both ways, on 127.0.0.1. A root and TSA certificates (P-256 and RSA-2048,
with the critical extended key usage id-kp-timeStamping) are made by
openssl in a temporary directory.

1. openssl's queries, goose-ts's replies, checked by `openssl ts -verify`:
   SHA-256 with certReq, against the query and the data; SHA-384 without
   certReq or nonce (the TSA's certificate given with -untrusted); SHA-512
   under another policy the TSA takes; an RSA TSA; a policy not taken and
   SHA-1 refused (unacceptedPolicy, badAlg), SHA-1 taken with --sha1.
2. goose-ts's queries, openssl's replies (`openssl ts -reply`), checked by
   goose-ts verify: signingCertificateV2 (SHA-256) and signingCertificate
   (ESSCertID, SHA-1), against the query, the data and a bare token
   (-token_out), an RSA TSA, without certReq (refused until the TSA's
   certificate is given), and refusals: other data, other roots.
3. goose-ts serve over HTTP: curl posting openssl's query (the reply
   checked by openssl), goose-ts request, a GET (405) and the wrong
   Content-Type (415).
4. RFC 3161 Appendix A: openssl cms -sign, goose-ts stamp against goose-ts
   serve, the signature still verified by openssl cms -verify, the token
   by goose-ts verify-stamp.
5. With Go: scripts/gotsa (digitorus/timestamp) as a TSA over HTTP for
   goose-ts request, and its client's query answered by goose-ts reply
   and its reply read back by it.

Needs openssl 3 or later; curl and Go are each skipped if absent.

    python3 scripts/interop.py [--goose PATH] [--openssl PATH]
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = os.path.normpath(os.path.join(ROOT, ".."))
GOTSA = os.path.join(ROOT, "scripts", "gotsa")
POLICY = "1.3.6.1.4.1.99999.1"
POLICY2 = "1.3.6.1.4.1.99999.2"

failures = 0


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(TOP, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_openssl(arg):
    """An openssl of version 3 or later, or None."""
    for cand in [arg, os.environ.get("OPENSSL"), "/opt/homebrew/bin/openssl", "/usr/local/opt/openssl/bin/openssl",
                 shutil.which("openssl")]:
        if cand and os.path.isfile(cand):
            p = subprocess.run([cand, "version"], capture_output=True, text=True)
            v = p.stdout.split()
            if len(v) > 1 and v[0] == "OpenSSL" and v[1][:1].isdigit() and int(v[1].split(".")[0]) >= 3:
                return cand
    return None


def check(what, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures += 1
        if detail:
            print("     " + detail.strip()[-1500:].replace("\n", "\n     "))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


def run(cmd, cwd, timeout=120):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


TS_CNF = """[ tsa ]
default_tsa = ec_v2

[ ec_v2 ]
serial = ./openssl_serial
crypto_device = builtin
signer_cert = ./tsa.pem
certs = ./ca.pem
signer_key = ./tsa.key
signer_digest = sha256
default_policy = {policy}
other_policies = {policy2}
digests = sha256, sha384, sha512
accuracy = secs:1, millisecs:500, microsecs:100
clock_precision_digits = 3
ordering = yes
tsa_name = yes
ess_cert_id_chain = no
ess_cert_id_alg = sha256

[ ec_v1 ]
serial = ./openssl_serial
crypto_device = builtin
signer_cert = ./tsa.pem
certs = ./ca.pem
signer_key = ./tsa.key
signer_digest = sha384
default_policy = {policy}
digests = sha256, sha384, sha512
ess_cert_id_alg = sha1

[ rsa ]
serial = ./openssl_serial
crypto_device = builtin
signer_cert = ./tsa_rsa.pem
certs = ./ca.pem
signer_key = ./tsa_rsa.key
signer_digest = sha256
default_policy = {policy}
digests = sha256, sha384, sha512
ess_cert_id_alg = sha256
"""

TSA_EXT = """basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""

SIGNER_EXT = """basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = emailProtection
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
"""


def make_pki(ossl, d):
    def o(*args):
        p = subprocess.run([ossl, *args], cwd=d, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(f"openssl {' '.join(args)}:\n{p.stderr}")
    o("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "ca.key")
    o("req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=Example TSA Root/O=Example", "-days", "3650",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "ca.pem")
    with open(os.path.join(d, "tsa.ext"), "w") as f:
        f.write(TSA_EXT)
    with open(os.path.join(d, "signer.ext"), "w") as f:
        f.write(SIGNER_EXT)
    for name, alg, subj, ext in [("tsa", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "/CN=Example TSA/O=Example", "tsa.ext"),
                                 ("tsa_rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"], "/CN=Example RSA TSA/O=Example", "tsa.ext"),
                                 ("signer", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"], "/CN=Example Signer/O=Example", "signer.ext")]:
        o("genpkey", *alg, "-out", f"{name}.key")
        o("req", "-new", "-key", f"{name}.key", "-subj", subj, "-out", f"{name}.csr")
        o("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "365",
          "-extfile", ext, "-out", f"{name}.pem")
    # Another root of the same name, for a path that must not be found.
    o("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "other.key")
    o("req", "-x509", "-new", "-key", "other.key", "-subj", "/CN=Example TSA Root/O=Example", "-days", "3650",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", "other.pem")
    with open(os.path.join(d, "ts.cnf"), "w") as f:
        f.write(TS_CNF.format(policy=POLICY, policy2=POLICY2))
    with open(os.path.join(d, "openssl_serial"), "w") as f:
        f.write("01\n")
    with open(os.path.join(d, "data.txt"), "w") as f:
        f.write("hello, time-stamped world\n")
    with open(os.path.join(d, "other.txt"), "w") as f:
        f.write("some other data\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--openssl")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    ossl = find_openssl(args.openssl)
    if not ossl:
        print("skip: no openssl 3 or later")
        print("\n0 failed")
        return
    with tempfile.TemporaryDirectory() as d:
        ts = os.path.join(d, "goose-ts")
        p = subprocess.run([goose, "build", "-o", ts, "ts.goose"], cwd=os.path.join(ROOT, "tools"),
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(f"cannot build goose-ts:\n{p.stdout}{p.stderr}")
        make_pki(ossl, d)
        tsa = ["--signer", "tsa.pem", "--key", "tsa.key", "--chain", "ca.pem", "--policy", POLICY]

        def g(*a):
            return run([ts, *a], d)

        def o(*a):
            return run([ossl, *a], d)

        # 1. openssl's queries, goose-ts's replies, openssl's verdict.
        print("-- openssl ts -query, goose-ts reply, openssl ts -verify")
        o("ts", "-query", "-data", "data.txt", "-sha256", "-cert", "-out", "q1.tsq")
        rc, out = g("reply", "--queryfile", "q1.tsq", *tsa, "--accuracy", "1", "--accuracy-ms", "500", "--precision", "3",
                    "--ordering", "--tsa-name", "--serial-file", "goose_serial", "--out", "r1.tsr")
        check("goose-ts reply to openssl's query", rc == 0, out)
        rc, out = o("ts", "-verify", "-in", "r1.tsr", "-queryfile", "q1.tsq", "-CAfile", "ca.pem")
        check("openssl verifies it against the query", rc == 0 and "Verification: OK" in out, out)
        rc, out = o("ts", "-verify", "-in", "r1.tsr", "-data", "data.txt", "-CAfile", "ca.pem")
        check("openssl verifies it against the data", rc == 0 and "Verification: OK" in out, out)
        rc, out = o("ts", "-reply", "-in", "r1.tsr", "-text")
        check("openssl reads its TSTInfo", "Ordering: yes" in out and "TSA: DirName:/CN=Example TSA/O=Example" in out
              and "0x01F4 millis" in out and "Serial number: 0x01" in out, out)
        g("reply", "--queryfile", "q1.tsq", *tsa, "--serial-file", "goose_serial", "--out", "r1b.tsr")
        rc, out = o("ts", "-reply", "-in", "r1b.tsr", "-text")
        check("the serial file counts on", "Serial number: 0x02" in out and open(os.path.join(d, "goose_serial")).read() == "03\n", out)

        o("ts", "-query", "-data", "data.txt", "-sha384", "-no_nonce", "-out", "q2.tsq")
        rc, out = g("reply", "--queryfile", "q2.tsq", *tsa, "--out", "r2.tsr")
        rc, out = o("ts", "-verify", "-in", "r2.tsr", "-queryfile", "q2.tsq", "-CAfile", "ca.pem", "-untrusted", "tsa.pem")
        check("no certReq, no nonce: openssl verifies with -untrusted", rc == 0 and "Verification: OK" in out, out)

        o("ts", "-query", "-data", "data.txt", "-sha512", "-cert", "-tspolicy", POLICY2, "-out", "q3.tsq")
        rc, out = g("reply", "--queryfile", "q3.tsq", *tsa, "--other-policy", POLICY2, "--out", "r3.tsr")
        rc2, out2 = o("ts", "-verify", "-in", "r3.tsr", "-queryfile", "q3.tsq", "-CAfile", "ca.pem")
        check("SHA-512 under another policy taken", rc == 0 and rc2 == 0 and "Verification: OK" in out2, out + out2)

        rc, out = g("reply", "--queryfile", "q1.tsq", "--signer", "tsa_rsa.pem", "--key", "tsa_rsa.key", "--chain", "ca.pem",
                    "--policy", POLICY, "--out", "r4.tsr")
        rc2, out2 = o("ts", "-verify", "-in", "r4.tsr", "-queryfile", "q1.tsq", "-CAfile", "ca.pem")
        check("an RSA TSA", rc == 0 and rc2 == 0 and "Verification: OK" in out2, out + out2)

        o("ts", "-query", "-data", "data.txt", "-sha256", "-tspolicy", "1.2.3.4", "-out", "q5.tsq")
        rc, out = g("reply", "--queryfile", "q5.tsq", *tsa, "--out", "r5.tsr")
        rc2, out2 = o("ts", "-reply", "-in", "r5.tsr", "-text")
        check("a policy not taken: refused", rc == 1 and "Rejected" in out2 and "policy is not supported" in out2, out + out2)
        o("ts", "-query", "-data", "data.txt", "-sha1", "-cert", "-out", "q6.tsq")
        rc, out = g("reply", "--queryfile", "q6.tsq", *tsa, "--out", "r6.tsr")
        rc2, out2 = o("ts", "-reply", "-in", "r6.tsr", "-text")
        check("SHA-1 refused", rc == 1 and "unrecognized or unsupported algorithm" in out2, out + out2)
        rc, out = g("reply", "--queryfile", "q6.tsq", *tsa, "--sha1", "--out", "r6b.tsr")
        rc2, out2 = o("ts", "-verify", "-in", "r6b.tsr", "-queryfile", "q6.tsq", "-CAfile", "ca.pem")
        check("SHA-1 taken with --sha1", rc == 0 and rc2 == 0, out + out2)

        # 2. goose-ts's queries, openssl's replies, goose-ts's verdict.
        print("-- goose-ts query, openssl ts -reply, goose-ts verify")
        rc, out = g("query", "--data", "data.txt", "--hash", "sha384", "--cert", "--out", "g1.tsq")
        rc2, out2 = o("ts", "-query", "-in", "g1.tsq", "-text")
        check("openssl reads goose-ts's query", rc == 0 and "Certificate required: yes" in out2 and "sha384" in out2, out + out2)
        for section, label in [("ec_v2", "signingCertificateV2"), ("ec_v1", "signingCertificate (ESSCertID, SHA-1)"),
                               ("rsa", "an RSA TSA")]:
            o("ts", "-reply", "-config", "ts.cnf", "-section", section, "-queryfile", "g1.tsq", "-out", f"o_{section}.tsr")
            rc, out = g("verify", "--in", f"o_{section}.tsr", "--queryfile", "g1.tsq", "--ca-file", "ca.pem")
            check(f"openssl's reply, {label}, against the query", rc == 0 and "Verification: OK" in out, out)
            rc, out = g("verify", "--in", f"o_{section}.tsr", "--data", "data.txt", "--ca-file", "ca.pem")
            check(f"openssl's reply, {label}, against the data", rc == 0 and "Verification: OK" in out, out)
        o("ts", "-reply", "-config", "ts.cnf", "-queryfile", "g1.tsq", "-token_out", "-out", "o_token.tst")
        rc, out = g("verify", "--token", "o_token.tst", "--data", "data.txt", "--ca-file", "ca.pem")
        check("openssl's bare token against the data", rc == 0 and "Verification: OK" in out, out)
        rc, out = g("verify", "--in", "o_ec_v2.tsr", "--data", "other.txt", "--ca-file", "ca.pem")
        check("other data refused", rc == 1 and "message imprint" in out, out)
        rc, out = g("verify", "--in", "o_ec_v2.tsr", "--queryfile", "g1.tsq", "--ca-file", "other.pem")
        check("other roots refused", rc == 1 and "does not chain" in out, out)
        rc, out = g("verify", "--in", "o_ec_v2.tsr", "--queryfile", "g1.tsq", "--ca-file", "ca.pem", "--policy", POLICY2)
        check("another policy wanted: refused", rc == 1 and "policy" in out, out)
        g("query", "--data", "data.txt", "--out", "g2.tsq")
        o("ts", "-reply", "-config", "ts.cnf", "-queryfile", "g2.tsq", "-out", "o_nocert.tsr")
        rc, out = g("verify", "--in", "o_nocert.tsr", "--queryfile", "g2.tsq", "--ca-file", "ca.pem")
        check("no certReq: refused without the TSA's certificate", rc == 1, out)
        rc, out = g("verify", "--in", "o_nocert.tsr", "--queryfile", "g2.tsq", "--ca-file", "ca.pem", "--untrusted", "tsa.pem")
        check("no certReq: verified with it", rc == 0 and "Verification: OK" in out, out)
        o("ts", "-query", "-data", "data.txt", "-sha256", "-tspolicy", "1.2.3.4", "-out", "q7.tsq")
        o("ts", "-reply", "-config", "ts.cnf", "-queryfile", "q7.tsq", "-out", "o_refused.tsr")
        rc, out = g("show", "--in", "o_refused.tsr")
        check("openssl's refusal read", rc == 0 and "rejection" in out and "unacceptedPolicy" in out, out)

        # 3. goose-ts serve over HTTP.
        print("-- goose-ts serve")
        port = free_port()
        srv = subprocess.Popen([ts, "serve", "--port", str(port), *tsa, "--tsa-name"], cwd=d,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            check("goose-ts serve listens", wait_port(port))
            url = f"http://127.0.0.1:{port}/tsa"
            curl = shutil.which("curl")
            if curl:
                rc, out = run([curl, "-s", "-H", "Content-Type: application/timestamp-query", "--data-binary", "@q1.tsq",
                               "-o", "h1.tsr", "-w", "%{http_code} %{content_type}", url], d)
                rc2, out2 = o("ts", "-verify", "-in", "h1.tsr", "-queryfile", "q1.tsq", "-CAfile", "ca.pem")
                check("curl's POST, openssl verifies the reply", out.startswith("200 application/timestamp-reply") and rc2 == 0,
                      out + out2)
                rc, out = run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", url], d)
                check("GET: 405", out == "405", out)
                rc, out = run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", "-H", "Content-Type: text/plain",
                               "--data", "x", url], d)
                check("the wrong Content-Type: 415", out == "415", out)
            else:
                print("skip: no curl")
            rc, out = g("request", "--url", url, "--data", "data.txt", "--hash", "sha512", "--cert", "--ca-file", "ca.pem",
                        "--out", "h2.tsr")
            check("goose-ts request to goose-ts serve", rc == 0 and "Verification: OK" in out, out)

            # 4. Appendix A.
            print("-- a CMS signature time-stamped (RFC 3161 Appendix A)")
            o("cms", "-sign", "-in", "data.txt", "-signer", "signer.pem", "-inkey", "signer.key", "-binary", "-nodetach",
              "-outform", "DER", "-out", "sig.p7s")
            rc, out = g("stamp", "--in", "sig.p7s", "--url", url, "--ca-file", "ca.pem", "--out", "stamped.p7s")
            check("goose-ts stamps openssl's signature", rc == 0, out)
            rc, out = o("cms", "-verify", "-in", "stamped.p7s", "-inform", "DER", "-CAfile", "ca.pem", "-binary",
                        "-purpose", "any", "-out", os.devnull)
            check("openssl still verifies the signature", rc == 0 and "Verification successful" in out, out)
            rc, out = o("cms", "-cmsout", "-in", "stamped.p7s", "-inform", "DER", "-print")
            check("openssl sees the unsigned attribute", "id-smime-aa-timeStampToken" in out or "1.2.840.113549.1.9.16.2.14" in out,
                  out[-600:])
            rc, out = g("verify-stamp", "--in", "stamped.p7s", "--ca-file", "ca.pem")
            check("goose-ts verifies the signature's time-stamp", rc == 0 and "Verification: OK" in out, out)
            rc, out = g("verify-stamp", "--in", "sig.p7s", "--ca-file", "ca.pem")
            check("an unstamped signature has none", rc == 1 and "no signature time-stamp token" in out, out)
        finally:
            stop(srv)

        # 5. The Go TSA.
        print("-- digitorus/timestamp (Go)")
        if not shutil.which("go"):
            print("skip: no Go")
        else:
            gotsa = os.path.join(d, "gotsa")
            p = subprocess.run(["go", "build", "-o", gotsa, "."], cwd=GOTSA, capture_output=True, text=True)
            if p.returncode != 0:
                print("skip: cannot build scripts/gotsa (needs the module, from the network the first time):\n" + p.stderr[-500:])
            else:
                port = free_port()
                srv = subprocess.Popen([gotsa, "serve", "-addr", f"127.0.0.1:{port}", "-cert", "tsa.pem", "-key", "tsa.key",
                                        "-policy", POLICY], cwd=d, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    check("the Go TSA listens", wait_port(port))
                    rc, out = g("request", "--url", f"http://127.0.0.1:{port}/", "--data", "data.txt", "--cert",
                                "--ca-file", "ca.pem")
                    check("goose-ts request to the Go TSA", rc == 0 and "Verification: OK" in out, out)
                    rc, out = g("request", "--url", f"http://127.0.0.1:{port}/", "--data", "data.txt", "--hash", "sha384",
                                "--ca-file", "ca.pem", "--untrusted", "tsa.pem")
                    check("the Go TSA without certReq", rc == 0 and "Verification: OK" in out, out)
                finally:
                    stop(srv)
                rc, out = run([gotsa, "query", "-data", "data.txt", "-hash", "sha512", "-out", "go.tsq"], d)
                rc2, out2 = g("reply", "--queryfile", "go.tsq", *tsa, "--accuracy", "2", "--ordering", "--precision", "6",
                              "--out", "go.tsr")
                rc3, out3 = run([gotsa, "verify", "-reply", "go.tsr", "-query", "go.tsq"], d)
                check("the Go client's query, goose-ts's reply read by it", rc == 0 and rc2 == 0 and rc3 == 0
                      and out3.startswith("ok:"), out + out2 + out3)

    print(f"\n{failures} failed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
