#!/usr/bin/env python3
"""goose-scep against SCEP servers and clients, on 127.0.0.1:

1. goose-scep's own test CA (goose-scep serve): GetCACaps, GetCACert,
   PKCSReq with the challenge password, a wrong one refused (badRequest),
   PKIOperation by GET, a CA that holds requests (PENDING, then CertPoll),
   RenewalReq, GetCert, GetCRL; each certificate and the CRL checked by
   openssl against the CA.
2. Hostile servers (Python): a GetCACert of 2 MiB refused as too large,
   junk where a certificate or a CertRep should be refused.
3. micromdm's scepserver: PKCSReq refused without --legacy (its CertRep is
   signed with SHA-1 and encrypted with single DES whatever its caps say),
   then issued with it, by POST and by GET; a wrong challenge refused;
   RenewalReq.
4. micromdm's scepclient against goose-scep serve --legacy: PKCSReq, a
   wrong challenge refused, RenewalReq.

micromdm's tools: `go install github.com/micromdm/scep/v2/cmd/scepserver@latest`
and `.../cmd/scepclient@latest`, found by $SCEPSERVER and $SCEPCLIENT, on
PATH, or in ~/go/bin; each part is skipped when its tool is missing.
Needs openssl.

    python3 scripts/interop.py [--goose PATH]
"""

import argparse
import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = os.path.normpath(os.path.join(ROOT, ".."))
CHALLENGE = "interop-challenge"

failures = 0


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(TOP, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def find_tool(name):
    for cand in [os.environ.get(name.upper()), shutil.which(name), os.path.expanduser(f"~/go/bin/{name}")]:
        if cand and os.path.isfile(cand):
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


def build(goose, src, out):
    p = subprocess.run([goose, "build", "-o", out, os.path.basename(src)], cwd=os.path.dirname(src),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"cannot build {src}:\n{p.stdout}{p.stderr}")


def stop(p):
    p.terminate()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()


def run(cmd, cwd, env=None, timeout=300):
    e = dict(os.environ)
    e.pop("SCEP_CHALLENGE", None)
    if env:
        e.update(env)
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=e, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def openssl_verify(ca, cert, cwd):
    p = subprocess.run(["openssl", "verify", "-CAfile", ca, cert], cwd=cwd, capture_output=True, text=True)
    return p.returncode == 0, p.stdout + p.stderr


def make_ca(d, name, key_usage):
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem",
                    "-days", "30", "-subj", f"/O=Example/CN={name}",
                    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", f"keyUsage=critical,{key_usage}"],
                   cwd=d, check=True, capture_output=True)


def start_ours(exe, d, port, *extra):
    p = subprocess.Popen([exe, "serve", "--ca-cert", "ca.pem", "--ca-key", "ca.key", "--port", str(port), *extra],
                         cwd=d, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                         env={**os.environ, "SCEP_CHALLENGE": CHALLENGE})
    line = p.stdout.readline()
    if not line.startswith("listening on "):
        p.kill()
        sys.exit(f"goose-scep serve did not start: {line}{p.stderr.read()}")
    return p


def ours(exe, tmp):
    print("== goose-scep against goose-scep serve")
    d = os.path.join(tmp, "ours")
    os.makedirs(d)
    make_ca(d, "Goose SCEP Interop CA", "keyCertSign,cRLSign,digitalSignature,keyEncipherment")
    port = free_port()
    srv = start_ours(exe, d, port)
    url = f"http://127.0.0.1:{port}/scep"
    pw = {"SCEP_CHALLENGE": CHALLENGE}
    try:
        rc, out = run([exe, "--url", url, "caps"], d)
        check("GetCACaps", rc == 0 and "SCEPStandard" in out and "POSTPKIOperation" in out, out)
        rc, out = run([exe, "--url", url, "getca", "--out", "got-ca.pem"], d)
        same = rc == 0 and open(os.path.join(d, "got-ca.pem")).read().split() == open(os.path.join(d, "ca.pem")).read().split()
        check("GetCACert", same, out)
        rc, out = run([exe, "--url", url, "enroll", "--key", "a.key", "--subject", "CN=a.example.test,O=Example",
                       "--dns", "a.example.test", "--out", "a.pem"], d, pw)
        ok, vout = openssl_verify("ca.pem", "a.pem", d) if rc == 0 else (False, "")
        check("PKCSReq: issued, openssl verifies it", rc == 0 and ok, out + vout)
        mode = oct(os.stat(os.path.join(d, "a.key")).st_mode & 0o777)
        check("the key file is 0600", mode == "0o600", mode)
        rc, out = run([exe, "--url", url, "enroll", "--key", "b.key", "--subject", "CN=b", "--out", "b.pem"], d,
                      {"SCEP_CHALLENGE": "wrong"})
        check("a wrong challenge: refused, badRequest", rc == 1 and "badRequest" in out, out)
        rc, out = run([exe, "--url", url, "--get", "enroll", "--key", "c.key", "--subject", "CN=c",
                       "--out", "c.pem"], d, pw)
        check("PKIOperation by GET", rc == 0 and openssl_verify("ca.pem", "c.pem", d)[0], out)
        rc, out = run([exe, "--url", url, "renew", "--key", "a.key", "--cert", "a.pem", "--new-key", "a2.key",
                       "--out", "a2.pem"], d)
        check("RenewalReq for a new key", rc == 0 and openssl_verify("ca.pem", "a2.pem", d)[0], out)
        rc, out = run([exe, "--url", url, "getcert", "--key", "a2.key", "--cert", "a2.pem", "--out", "got.pem"], d)
        same = rc == 0 and open(os.path.join(d, "got.pem")).read() == open(os.path.join(d, "a2.pem")).read()
        check("GetCert: the same certificate back", same, out)
        rc, out = run([exe, "--url", url, "getcrl", "--key", "a2.key", "--cert", "a2.pem", "--out", "crl.pem"], d)
        p = subprocess.run(["openssl", "crl", "-in", "crl.pem", "-CAfile", "ca.pem", "-noout"], cwd=d,
                           capture_output=True, text=True)
        check("GetCRL: a CRL openssl verifies", rc == 0 and p.returncode == 0 and "verify OK" in p.stdout + p.stderr,
              out + p.stdout + p.stderr)
    finally:
        stop(srv)
    # A CA that holds each request through two CertPolls.
    port = free_port()
    srv = start_ours(exe, d, port, "--pending", "2")
    try:
        t0 = time.time()
        rc, out = run([exe, "--url", f"http://127.0.0.1:{port}/scep", "--poll-interval", "1", "enroll", "--key",
                       "h.key", "--subject", "CN=held", "--out", "h.pem"], d, pw)
        check("PENDING, then CertPoll until issued", rc == 0 and openssl_verify("ca.pem", "h.pem", d)[0]
              and time.time() - t0 >= 2, out)
        rc, out = run([exe, "--url", f"http://127.0.0.1:{port}/scep", "--poll-interval", "1", "--poll-timeout", "0",
                       "enroll", "--key", "h2.key", "--subject", "CN=held2", "--out", "h2.pem"], d, pw)
        check("held past --poll-timeout: given up, said so", rc == 1 and "in time" in out, out)
    finally:
        stop(srv)
        srv.stdout.close()
        log = srv.stderr.read()
        srv.stderr.close()
    check("the server logged the polls", "CertPoll: still PENDING" in log and "CertPoll: issued" in log, log)


class Hostile(http.server.BaseHTTPRequestHandler):
    mode = "big"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if "GetCACaps" in self.path:
            body, ct = b"AES\nSHA-256\nPOSTPKIOperation\n", "text/plain"
        elif self.mode == "big":
            body, ct = b"\x30" * (2 << 20), "application/x-x509-ca-cert"
        else:
            body, ct = b"this is not a certificate", "application/x-x509-ca-cert"
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass        # the client gave up on a body too large: what is tested


def hostile(exe, tmp):
    print("== goose-scep against hostile servers")
    d = os.path.join(tmp, "hostile")
    os.makedirs(d)
    for mode, what, expect in [("big", "a 2 MiB GetCACert: refused as too large", "larger"),
                               ("junk", "junk for GetCACert: refused", "not SCEP")]:
        handler = type("H", (Hostile,), {"mode": mode})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            rc, out = run([exe, "--url", f"http://127.0.0.1:{server.server_port}/scep", "getca"], d, timeout=60)
            check(what, rc == 1 and expect in out, out)
        finally:
            server.shutdown()
            server.server_close()


def micromdm_server(exe, scepserver, tmp):
    print("== goose-scep against micromdm's scepserver")
    d = os.path.join(tmp, "mdm")
    os.makedirs(d)
    p = subprocess.run([scepserver, "ca", "-init", "-depot", "depot", "-keySize", "2048"], cwd=d,
                       capture_output=True, text=True)
    if p.returncode != 0:
        check("scepserver ca -init", False, p.stdout + p.stderr)
        return
    port = free_port()
    srv = subprocess.Popen([scepserver, "-depot", "depot", "-port", str(port), "-challenge", CHALLENGE,
                            "-allowrenew", "0"], cwd=d, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}/scep"
    pw = {"SCEP_CHALLENGE": CHALLENGE}
    try:
        if not wait_port(port):
            check("scepserver started", False)
            return
        rc, out = run([exe, "--url", url, "getca", "--out", "ca.pem"], d)
        check("GetCACert", rc == 0, out)
        rc, out = run([exe, "--url", url, "enroll", "--key", "a.key", "--subject", "CN=a.example.test,O=Example",
                       "--out", "a.pem"], d, pw)
        check("without --legacy: its SHA-1/DES CertRep refused, said so", rc == 1 and "legacy" in out, out)
        rc, out = run([exe, "--url", url, "--legacy", "enroll", "--key", "a.key", "--subject",
                       "CN=a.example.test,O=Example", "--dns", "a.example.test", "--out", "a.pem"], d, pw)
        check("PKCSReq with --legacy: issued, openssl verifies it",
              rc == 0 and openssl_verify("ca.pem", "a.pem", d)[0], out)
        rc, out = run([exe, "--url", url, "--legacy", "--get", "enroll", "--key", "g.key", "--subject", "CN=g",
                       "--out", "g.pem"], d, pw)
        check("PKCSReq by GET", rc == 0 and openssl_verify("ca.pem", "g.pem", d)[0], out)
        rc, out = run([exe, "--url", url, "--legacy", "enroll", "--key", "w.key", "--subject", "CN=w",
                       "--out", "w.pem"], d, {"SCEP_CHALLENGE": "wrong"})
        check("a wrong challenge: refused, badRequest", rc == 1 and "badRequest" in out, out)
        rc, out = run([exe, "--url", url, "--legacy", "--aes256", "renew", "--key", "a.key", "--cert", "a.pem",
                       "--new-key", "a2.key", "--out", "a2.pem"], d, pw)     # it asks for the challenge here too
        check("RenewalReq (AES-256) for a new key", rc == 0 and openssl_verify("ca.pem", "a2.pem", d)[0], out)
    finally:
        stop(srv)


def micromdm_client(exe, scepclient, tmp):
    print("== micromdm's scepclient against goose-scep serve --legacy")
    d = os.path.join(tmp, "mdmclient")
    os.makedirs(d)
    make_ca(d, "Goose SCEP Interop CA", "keyCertSign,cRLSign,digitalSignature,keyEncipherment")
    port = free_port()
    srv = start_ours(exe, d, port, "--legacy")
    url = f"http://127.0.0.1:{port}/scep"
    try:
        # scepclient keeps its CSR in csr.pem in its directory: one each.
        for sub in ["a", "b"]:
            os.makedirs(os.path.join(d, sub))
        a = os.path.join(d, "a")
        rc, out = run([scepclient, "-server-url", url, "-private-key", "c.key", "-certificate", "c.pem",
                       "-cn", "client.example.test", "-dnsname", "client.example.test", "-challenge", CHALLENGE], a)
        check("PKCSReq: issued, openssl verifies it",
              rc == 0 and openssl_verify(os.path.join(d, "ca.pem"), "c.pem", a)[0], out)
        b = os.path.join(d, "b")
        rc, out = run([scepclient, "-server-url", url, "-private-key", "c.key", "-certificate", "c.pem",
                       "-cn", "other", "-challenge", "wrong"], b)
        check("a wrong challenge: refused, badRequest", rc != 0 and "badRequest" in out, out)
        before = open(os.path.join(a, "c.pem")).read()
        rc, out = run([scepclient, "-server-url", url, "-private-key", "c.key", "-certificate", "c.pem",
                       "-cn", "client.example.test"], a)
        after = open(os.path.join(a, "c.pem")).read()
        check("RenewalReq signed by the certificate: a new one",
              rc == 0 and before != after and openssl_verify(os.path.join(d, "ca.pem"), "c.pem", a)[0], out)
    finally:
        stop(srv)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("openssl"):
        sys.exit("needs openssl")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "goose-scep")
        build(goose, os.path.join(ROOT, "tools", "scep.goose"), exe)
        ours(exe, tmp)
        hostile(exe, tmp)
        scepserver = find_tool("scepserver")
        if scepserver:
            micromdm_server(exe, scepserver, tmp)
        else:
            print("skip micromdm's scepserver: not found ($SCEPSERVER, PATH, ~/go/bin)")
        scepclient = find_tool("scepclient")
        if scepclient:
            micromdm_client(exe, scepclient, tmp)
        else:
            print("skip micromdm's scepclient: not found ($SCEPCLIENT, PATH, ~/go/bin)")
    print(f"\n{'all passed' if failures == 0 else f'{failures} failed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
