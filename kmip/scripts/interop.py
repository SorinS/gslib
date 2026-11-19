#!/usr/bin/env python3
"""kmip against PyKMIP, in Docker on this machine (Linux), on loopback:

  * gslib's client (test/interop_client.goose, the checks of
    test/scenario.goose) against PyKMIP's server in KMIP 1.0, 1.1, 1.2,
    1.3, 1.4 and 2.0, and with the version negotiated: create, get,
    attributes, locate, the life cycle, AES-CBC and AES-GCM checked against
    gslib's AES, HMAC against gslib's, RSA key pairs signing and verifying,
    registered keys and secrets.
  * gslib's server (tools/kmipd) against the same client, and against
    PyKMIP's client (scripts/interop/pykmip_client.py) in 1.2, 1.4 and 2.0,
    its AES and HMAC checked against Python's cryptography.
  * KMIP over HTTPS: goose-kmipd --http against gslib's client
    (test/interop_https.goose, the same checks) with the messages in TTLV,
    XML and JSON, and against curl posting a request in each.

    python3 scripts/interop.py [--goose PATH] [--work DIR] [--no-setup] [--local]

--local runs what needs no Docker (gslib against itself, curl), on any
machine with openssl and curl.

The work directory (default: kmip-interop in the current directory) gets
the test certificates (a CA, the server's for kmip.example.com, a P-256
client's for "alice") and PyKMIP's configuration and database; --no-setup
reuses the container a previous run started. The container is left
running (gs-pykmip); docker rm -f it when done.

PyKMIP is built from its master (scripts/interop/pykmip.Dockerfile): the
0.10.0 release cannot load public keys for Signature Verify under the
cryptography it installs with.
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HERE = os.path.join(ROOT, "scripts", "interop")
IMAGE = "gs-pykmip"
VERSIONS = ["1.0", "1.1", "1.2", "1.3", "1.4", "2.0", "auto"]

passed = 0
failed = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def run(cmd, timeout=600, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd)
    return p.returncode, p.stdout + p.stderr


def check(label, ok, out=""):
    global passed
    print(("ok    " if ok else "FAIL  ") + label, flush=True)
    if ok:
        passed += 1
    else:
        failed.append(label)
        lines = [l for l in out.strip().splitlines() if l.startswith("FAIL")] or out.strip().splitlines()[-6:]
        if lines:
            print("      " + "\n      ".join(lines[:12]))


def counts(out):
    for line in reversed(out.strip().splitlines()):
        if line.endswith("failures") and "checks" in line:
            return line.strip()
    return "no counts"


def setup(work, docker=True):
    certs = os.path.join(work, "certs")
    shutil.rmtree(certs, ignore_errors=True)
    for d in ("certs", "policies", "data"):
        os.makedirs(os.path.join(work, d), exist_ok=True)

    def ossl(*args):
        rc, out = run(["openssl", *args], cwd=certs)
        if rc != 0:
            sys.exit("openssl " + " ".join(args) + ":\n" + out)

    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650", "-subj", "/CN=gslib KMIP test CA",
         "-keyout", "ca.key", "-out", "ca.pem")

    def leaf(name, newkey, subj, eku):
        ossl("req", "-newkey", newkey, "-nodes", "-subj", subj, "-keyout", f"{name}.key", "-out", f"{name}.csr")
        with open(os.path.join(certs, f"{name}.ext"), "w") as f:
            f.write(f"extendedKeyUsage={eku}\nsubjectAltName=DNS:kmip.example.com,IP:127.0.0.1\n")
        ossl("x509", "-req", "-in", f"{name}.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-days", "3650", "-extfile", f"{name}.ext", "-out", f"{name}.pem")

    leaf("server", "rsa:2048", "/CN=kmip.example.com", "serverAuth")
    # The client's key, P-256, in PKCS #8.
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "client.ec")
    ossl("pkcs8", "-topk8", "-nocrypt", "-in", "client.ec", "-out", "client.key")
    ossl("req", "-new", "-key", "client.key", "-subj", "/CN=alice", "-out", "client.csr")
    with open(os.path.join(certs, "client.ext"), "w") as f:
        f.write("extendedKeyUsage=clientAuth\n")
    ossl("x509", "-req", "-in", "client.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
         "-days", "3650", "-extfile", "client.ext", "-out", "client.pem")
    for f in os.listdir(certs):
        os.chmod(os.path.join(certs, f), 0o644)
    with open(os.path.join(work, "server.conf"), "w") as f:
        f.write("[server]\nhostname=0.0.0.0\nport=5696\ncertificate_path=/w/certs/server.pem\n"
                "key_path=/w/certs/server.key\nca_path=/w/certs/ca.pem\nauth_suite=TLS1.2\n"
                "policy_path=/w/policies\nenable_tls_client_auth=True\nlogging_level=INFO\n"
                "database_path=/w/data/pykmip.db\n")
    for d in ("data", "policies"):
        os.chmod(os.path.join(work, d), 0o777)
    if not docker:
        return

    rc, out = run(["docker", "build", "-q", "-t", IMAGE, "-f", os.path.join(HERE, "pykmip.Dockerfile"), HERE])
    if rc != 0:
        sys.exit("docker build:\n" + out)
    run(["docker", "rm", "-f", IMAGE])
    rc, out = run(["docker", "run", "-d", "--name", IMAGE, "-v", f"{work}:/w", "-p", "127.0.0.1:5696:5696",
                   IMAGE, "-f", "/w/server.conf", "-l", "/w/server.log"])
    if rc != 0:
        sys.exit("docker run:\n" + out)
    time.sleep(5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--work", default="kmip-interop")
    ap.add_argument("--no-setup", action="store_true")
    ap.add_argument("--local", action="store_true", help="only what needs no Docker")
    args = ap.parse_args()
    goose = os.path.abspath(find_goose(args.goose))
    work = os.path.abspath(args.work)
    certs = os.path.join(work, "certs")
    os.makedirs(work, exist_ok=True)
    if not args.no_setup:
        setup(work, docker=not args.local)
    run_id = str(int(time.time()))
    test_dir = os.path.join(ROOT, "test")

    # gslib's client against PyKMIP.
    for v in ([] if args.local else VERSIONS):
        rc, out = run([goose, "interop_client.goose", "--", "127.0.0.1", "5696", certs, v, run_id], cwd=test_dir)
        check(f"client -> PyKMIP, KMIP {v}: {counts(out)}", rc == 0, out)

    # gslib's server: built, then gslib's client and PyKMIP's against it.
    kmipd = os.path.join(work, "goose-kmipd")
    rc, out = run([goose, "build", "-o", kmipd, os.path.join(ROOT, "tools", "kmipd.goose")])
    check("build goose-kmipd", rc == 0, out)
    if rc != 0:
        return finish()
    log = open(os.path.join(work, "kmipd.log"), "w")
    srv = subprocess.Popen([kmipd, "--cert", f"{certs}/server.pem", "--key", f"{certs}/server.key",
                            "--ca", f"{certs}/ca.pem", "--port", "5697"], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        for v in VERSIONS:
            rc, out = run([goose, "interop_client.goose", "--", "127.0.0.1", "5697", certs, v, run_id], cwd=test_dir)
            check(f"client -> goose-kmipd, KMIP {v}: {counts(out)}", rc == 0, out)
        if not args.local:
            rc, out = run(["docker", "run", "--rm", "--network", "host", "-v", f"{HERE}:/s:ro", "-v", f"{certs}:/c:ro",
                           "--entrypoint", "python", IMAGE, "/s/pykmip_client.py", "127.0.0.1", "5697", "/c", run_id])
            check(f"PyKMIP's client -> goose-kmipd, KMIP 1.2, 1.4, 2.0: {counts(out)}", rc == 0, out)
    finally:
        srv.terminate()
        srv.wait(timeout=10)
        log.close()
    https(goose, kmipd, work, certs, test_dir, run_id)
    return finish()


# A Discover Versions request, as each encoding writes it.
DISCOVER = {
    "xml": ("text/xml", '<RequestMessage><RequestHeader><ProtocolVersion>'
            '<ProtocolVersionMajor type="Integer" value="1"/><ProtocolVersionMinor type="Integer" value="1"/>'
            '</ProtocolVersion><BatchCount type="Integer" value="1"/></RequestHeader><BatchItem>'
            '<Operation type="Enumeration" value="DiscoverVersions"/><RequestPayload/></BatchItem></RequestMessage>'),
    "json": ("application/json", '{"tag":"RequestMessage","value":[{"tag":"RequestHeader","value":['
             '{"tag":"ProtocolVersion","value":[{"tag":"ProtocolVersionMajor","type":"Integer","value":1},'
             '{"tag":"ProtocolVersionMinor","type":"Integer","value":1}]},'
             '{"tag":"BatchCount","type":"Integer","value":1}]},{"tag":"BatchItem","value":['
             '{"tag":"Operation","type":"Enumeration","value":"DiscoverVersions"},'
             '{"tag":"RequestPayload","value":[]}]}]}'),
}


def https(goose, kmipd, work, certs, test_dir, run_id):
    """goose-kmipd --http against gslib's client in each encoding, and curl."""
    log = open(os.path.join(work, "kmipd-https.log"), "w")
    srv = subprocess.Popen([kmipd, "--cert", f"{certs}/server.pem", "--key", f"{certs}/server.key",
                            "--ca", f"{certs}/ca.pem", "--port", "5698", "--http"], stdout=log, stderr=subprocess.STDOUT)
    try:
        time.sleep(1)
        for enc in ("ttlv", "xml", "json"):
            for v in ("1.4", "2.0", "auto"):
                rc, out = run([goose, "interop_https.goose", "--", "127.0.0.1", "5698", certs, enc, v,
                               f"{run_id}{enc}"], cwd=test_dir)
                check(f"client -> goose-kmipd over HTTPS, {enc}, KMIP {v}: {counts(out)}", rc == 0, out)
        for enc, (ctype, body) in DISCOVER.items():
            rc, out = run(["curl", "-sS", "--cacert", f"{certs}/ca.pem", "--cert", f"{certs}/client.pem",
                           "--key", f"{certs}/client.key", "--resolve", "kmip.example.com:5698:127.0.0.1",
                           "-H", f"Content-Type: {ctype}", "-H", "Cache-Control: no-cache", "--data-binary", body,
                           "-w", "\\n%{http_code} %{content_type}", "https://kmip.example.com:5698/kmip"])
            good = rc == 0 and out.rstrip().endswith(f"200 {ctype}") and "ProtocolVersionMajor" in out
            check(f"curl -> goose-kmipd over HTTPS, Discover Versions in {enc}", good, out)
        rc, out = run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "--cacert", f"{certs}/ca.pem",
                       "--cert", f"{certs}/client.pem", "--key", f"{certs}/client.key",
                       "--resolve", "kmip.example.com:5698:127.0.0.1", "-H", "Content-Type: text/plain",
                       "--data-binary", "x", "https://kmip.example.com:5698/kmip"])
        check("curl -> goose-kmipd over HTTPS, text/plain refused with 415", out.strip() == "415", out)
    finally:
        srv.terminate()
        srv.wait(timeout=10)
        log.close()


def finish():
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
