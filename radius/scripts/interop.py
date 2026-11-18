#!/usr/bin/env python3
"""radius against FreeRADIUS 3.2 and wpa_supplicant's eapol_test, in
Docker on this machine (Linux), everything on loopback:

  * gslib's client (tools/radtest) against FreeRADIUS: PAP, CHAP,
    MS-CHAPv2, Status-Server, accounting, EAP-MD5, EAP-MS-CHAPv2, PEAP,
    TTLS/PAP, TTLS/MS-CHAPv2, EAP-TLS (RSA and P-256 certificates) over
    TLS 1.3 and 1.2, RadSec; the MS-MPPE keys checked against the peer's
    MSK; wrong passwords, a wrong secret, an untrusted CA, a wrong name.
  * gslib's server (tools/radiusd) against eapol_test (every EAP method,
    TLS 1.3 and 1.2, the MPPE keys checked by eapol_test) and FreeRADIUS's
    radclient (PAP, CHAP, accounting, Status-Server, Disconnect, CoA).
  * RadSec both ways: gslib's client to gslib's server, and FreeRADIUS
    proxying user@radsec.example over RadSec to gslib's server.

    python3 scripts/interop.py [--goose PATH] [--work DIR] [--no-setup]

The work directory (default: radius-interop in the current directory)
gets the test certificates and FreeRADIUS's configuration; --no-setup
reuses the containers a previous run started. The containers are left
running (gs-radius, gs-radius-proxy); docker rm -f them when done.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HERE = os.path.join(ROOT, "scripts", "interop")
FR = "freeradius/freeradius-server:latest-3.2"
EAPOL = "gs-eapol"

passed = 0
failed = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def run(cmd, stdin=None, timeout=120):
    p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def check(label, ok, out=""):
    global passed
    print(("ok    " if ok else "FAIL  ") + label, flush=True)
    if ok:
        passed += 1
    else:
        failed.append(label)
        tail = "\n".join(out.strip().splitlines()[-6:])
        if tail:
            print("      " + tail.replace("\n", "\n      "))


def eapol_conf(work, name, body):
    path = os.path.join(work, name + ".conf")
    with open(path, "w") as f:
        f.write("network={\n  key_mgmt=WPA-EAP\n" + "".join(f"  {l}\n" for l in body) + "}\n")
    return path


def eapol(work, conf, port, want_keys=True):
    rc, out = run(["docker", "run", "--rm", "--network", "host", "-v", f"{work}/certs:/c",
                   "-v", f"{conf}:/x.conf", EAPOL, "-c", "/x.conf", "-a", "127.0.0.1",
                   "-p", str(port), "-s", "testing123"])
    ok = "CTRL-EVENT-EAP-SUCCESS" in out
    if want_keys:
        ok = ok and "MPPE keys OK: 1" in out
    return ok, out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--work", default=os.path.abspath("radius-interop"))
    ap.add_argument("--no-setup", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)

    if not args.no_setup:
        rc, out = run(["docker", "build", "-q", "-t", EAPOL, "-f", os.path.join(HERE, "eapol.Dockerfile"), HERE],
                      timeout=1800)
        if rc != 0:
            sys.exit("cannot build eapol_test:\n" + out)
        rc, out = run(["sh", os.path.join(HERE, "freeradius.sh"), work], timeout=600)
        if rc != 0:
            sys.exit("cannot start FreeRADIUS:\n" + out)

    radtest = os.path.join(work, "radtest")
    radiusd = os.path.join(work, "radiusd")
    for tool, exe in (("radtest", radtest), ("radiusd", radiusd)):
        p = subprocess.run([goose, "build", "-o", exe, os.path.join("tools", tool + ".goose")],
                           cwd=ROOT, capture_output=True, text=True, timeout=900)
        if p.returncode != 0:
            sys.exit(f"cannot build {tool}:\n{p.stdout}{p.stderr}")

    c = f"{work}/certs"
    ca = ["--ca", f"{c}/ca.pem"]
    rs = ["--radsec", *ca, "--cert", f"{c}/radsec-client.pem", "--key", f"{c}/radsec-client.key"]

    def radtest_ok(label, argv, want=0, needle=None):
        rc, out = run([radtest, *argv])
        ok = rc == want and (needle is None or needle in out)
        check(label, ok, out)

    # --- gslib's client against FreeRADIUS --------------------------------------
    for m in ["pap", "chap", "mschapv2", "status", "acct", "eap-md5"]:
        radtest_ok(f"client {m} -> FreeRADIUS", ["127.0.0.1", m, "alice", "alice-pw"])
    radtest_ok("client eap-mschapv2 -> FreeRADIUS (MPPE keys)", ["127.0.0.1", "eap-mschapv2", "alice", "alice-pw"],
               needle="MPPE keys OK")
    for v, flag in (("1.3", []), ("1.2", ["--tls12"])):
        for m in ["peap", "ttls-pap", "ttls-mschapv2"]:
            radtest_ok(f"client {m} TLS {v} -> FreeRADIUS", [*flag, *ca, "--anon", "anonymous", "127.0.0.1", m, "alice", "alice-pw"],
                       needle=f"MPPE keys OK, TLS {v}")
        for kind in ["client", "client-ec"]:
            radtest_ok(f"client eap-tls ({kind}) TLS {v} -> FreeRADIUS",
                       [*flag, *ca, "--eap-cert", f"{c}/{kind}.pem", "--eap-key", f"{c}/{kind}.key", "127.0.0.1", "eap-tls", "alice"],
                       needle=f"MPPE keys OK, TLS {v}")
        radtest_ok(f"client peap, fragments of 300, TLS {v} -> FreeRADIUS",
                   [*flag, *ca, "--fragment", "300", "127.0.0.1", "peap", "alice", "alice-pw"], needle="MPPE keys OK")
    radtest_ok("client RadSec pap -> FreeRADIUS", [*rs, "127.0.0.1", "pap", "alice", "alice-pw"])
    radtest_ok("client RadSec peap -> FreeRADIUS", [*rs, "127.0.0.1", "peap", "alice", "alice-pw"], needle="MPPE keys OK")
    radtest_ok("client RadSec acct -> FreeRADIUS", [*rs, "127.0.0.1", "acct", "alice"])
    radtest_ok("client wrong password -> rejected", ["127.0.0.1", "pap", "alice", "nope"], want=1, needle="rejected")
    radtest_ok("client peap wrong password -> rejected", [*ca, "127.0.0.1", "peap", "alice", "nope"], want=1, needle="rejected")
    radtest_ok("client wrong secret -> no answer", ["--secret", "wrong", "127.0.0.1", "pap", "alice", "alice-pw"],
               want=1, needle="no response")
    radtest_ok("client untrusted CA -> TLS fails", ["--ca", f"{c}/client.pem", "127.0.0.1", "peap", "alice", "alice-pw"],
               want=1, needle="TLS failed")
    radtest_ok("client wrong server name -> TLS fails", [*ca, "--name", "other.example.com", "127.0.0.1", "peap", "alice", "alice-pw"],
               want=1, needle="TLS failed")

    # --- gslib's server ------------------------------------------------------------
    log = open(os.path.join(work, "radiusd.log"), "w")
    srv = subprocess.Popen([radiusd, "--cert", f"{c}/server.pem", "--key", f"{c}/server.key", *ca,
                            "--port", "11812", "--radsec-port", "12083", "--coa-port", "13799",
                            "--user", "alice:alice-pw"], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        tls13 = ['phase1="tls_disable_tlsv1_3=0"']
        confs = {
            "peap": ['eap=PEAP', 'identity="alice"', 'anonymous_identity="anonymous"', 'password="alice-pw"',
                     'phase2="auth=MSCHAPV2"', 'ca_cert="/c/ca.pem"'],
            "ttls-pap": ['eap=TTLS', 'identity="alice"', 'anonymous_identity="anonymous"', 'password="alice-pw"',
                         'phase2="auth=PAP"', 'ca_cert="/c/ca.pem"'],
            "ttls-mschapv2": ['eap=TTLS', 'identity="alice"', 'anonymous_identity="anonymous"', 'password="alice-pw"',
                              'phase2="auth=MSCHAPV2"', 'ca_cert="/c/ca.pem"'],
            "tls": ['eap=TLS', 'identity="alice"', 'client_cert="/c/client.pem"', 'private_key="/c/client.key"',
                    'ca_cert="/c/ca.pem"'],
        }
        for name, body in confs.items():
            for v, extra in (("1.2", []), ("1.3", tls13)):
                ok, out = eapol(work, eapol_conf(work, f"{name}-{v}", extra + body), 11812)
                check(f"eapol_test {name} TLS {v} -> server", ok and f"TLSv{v}" in out, out)
        ok, out = eapol(work, eapol_conf(work, "mschapv2", ['eap=MSCHAPV2', 'identity="alice"', 'password="alice-pw"']), 11812)
        check("eapol_test eap-mschapv2 -> server (MPPE keys)", ok, out)
        ok, out = eapol(work, eapol_conf(work, "md5", ['eap=MD5', 'identity="alice"', 'password="alice-pw"']), 11812, False)
        check("eapol_test eap-md5 -> server", ok, out)
        ok, out = eapol(work, eapol_conf(work, "peap-bad", ['eap=PEAP', 'identity="alice"', 'password="nope"',
                                                             'phase2="auth=MSCHAPV2"', 'ca_cert="/c/ca.pem"']), 11812, False)
        check("eapol_test peap wrong password -> refused", not ok and "CTRL-EVENT-EAP-FAILURE" in out, out)

        rad = ["docker", "run", "--rm", "-i", "--network", "host", FR]
        for label, cmd, stdin, want in [
            ("radclient pap -> server", ["radtest", "alice", "alice-pw", "127.0.0.1:11812", "0", "testing123"], None, "Access-Accept"),
            ("radclient chap -> server", ["radtest", "-t", "chap", "alice", "alice-pw", "127.0.0.1:11812", "0", "testing123"], None, "Access-Accept"),
            ("radclient wrong password -> server", ["radtest", "alice", "nope", "127.0.0.1:11812", "0", "testing123"], None, "Access-Reject"),
            ("radclient acct -> server", ["radclient", "127.0.0.1:11813", "acct", "testing123"],
             "Acct-Status-Type = Start, Acct-Session-Id = 1, User-Name = alice", "Accounting-Response"),
            ("radclient status -> server", ["radclient", "127.0.0.1:11812", "status", "testing123"],
             "Message-Authenticator = 0x00", "Access-Accept"),
            ("radclient disconnect -> NAS", ["radclient", "127.0.0.1:13799", "disconnect", "testing123"],
             "User-Name = alice, Acct-Session-Id = 1", "Disconnect-ACK"),
            ("radclient disconnect, unknown user -> NAS", ["radclient", "127.0.0.1:13799", "disconnect", "testing123"],
             "User-Name = mallory", "Disconnect-NAK"),
            ("radclient coa -> NAS", ["radclient", "127.0.0.1:13799", "coa", "testing123"],
             "User-Name = alice, Session-Timeout = 60", "CoA-ACK"),
        ]:
            rc, out = run(rad + cmd, stdin=stdin)
            check(label, f"Received {want}" in out, out)

        # CoA and Disconnect: gslib's client to radiusd as a NAS.
        radtest_ok("client disconnect -> NAS", ["--port", "13799", "127.0.0.1", "disconnect", "alice"], needle="Disconnect-ACK")
        radtest_ok("client coa -> NAS", ["--port", "13799", "127.0.0.1", "coa", "alice"], needle="CoA-ACK")
        radtest_ok("client disconnect, unknown user -> NAK", ["--port", "13799", "127.0.0.1", "disconnect", "mallory"],
                   want=1, needle="Error-Cause = 503")

        # RadSec: gslib to gslib, FreeRADIUS to gslib.
        rsg = [*rs, "--port", "12083"]
        radtest_ok("client RadSec pap -> server", [*rsg, "127.0.0.1", "pap", "alice", "alice-pw"])
        radtest_ok("client RadSec peap -> server", [*rsg, "127.0.0.1", "peap", "alice", "alice-pw"], needle="MPPE keys OK")
        radtest_ok("client RadSec eap-tls -> server", [*rsg, "--eap-cert", f"{c}/client-ec.pem", "--eap-key", f"{c}/client-ec.key",
                                                      "127.0.0.1", "eap-tls", "alice"], needle="MPPE keys OK")
        radtest_ok("client RadSec without a certificate -> refused", ["--radsec", *ca, "--port", "12083", "127.0.0.1", "pap", "alice", "alice-pw"],
                   want=1)
        rc, out = run(rad + ["radtest", "alice@radsec.example", "alice-pw", "127.0.0.1:21812", "0", "testing123"])
        check("FreeRADIUS proxy over RadSec -> server, pap", "Received Access-Accept" in out, out)
        rc, out = run(rad + ["radtest", "alice@radsec.example", "nope", "127.0.0.1:21812", "0", "testing123"])
        check("FreeRADIUS proxy over RadSec -> server, wrong password", "Received Access-Reject" in out, out)
        body = [l.replace('anonymous_identity="anonymous"', 'anonymous_identity="anon@radsec.example"') for l in confs["peap"]]
        ok, out = eapol(work, eapol_conf(work, "peap-proxy", body), 21812)
        check("eapol_test peap via FreeRADIUS proxy over RadSec -> server", ok, out)
        body = [l.replace('identity="alice"', 'identity="alice@radsec.example"') for l in confs["tls"]]
        ok, out = eapol(work, eapol_conf(work, "tls-proxy", tls13 + body), 21812)
        check("eapol_test eap-tls via FreeRADIUS proxy over RadSec -> server", ok, out)
    finally:
        srv.terminate()
        srv.wait()
        log.close()

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
