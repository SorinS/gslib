#!/usr/bin/env python3
"""goose-est against EST servers and clients, over TLS on 127.0.0.1:

1. goose-est's own test CA (goose-est serve): /cacerts with the server
   checked against the CA (and refused without it), /csrattrs (RFC 7030's
   example), /simpleenroll with HTTP Basic (refused without credentials
   and with the wrong password), a held request (202, Retry-After, then
   issued), under a label, /simplereenroll by TLS client certificate,
   /serverkeygen; each certificate checked by openssl against the CA.
2. Hostile servers (Python, TLS): a /cacerts of 2 MiB refused as too
   large, junk where certs-only should be refused, a CA that holds a
   request forever given up on after --poll-timeout.
3. GlobalSign's estserver (its mock CA from an openssl CA): /cacerts,
   /csrattrs (empty, and RFC 7030's example under the label "csrattrs"),
   /simpleenroll, /simplereenroll by client certificate, /serverkeygen;
   under the label "triggererrors" 403 reported and 202 waited on; under
   "pkcs7" the encrypted key reported as unsupported.
4. GlobalSign's estclient against goose-est serve: cacerts, csrattrs,
   enroll (refused without credentials), reenroll, serverkeygen.

GlobalSign's tools: `go install github.com/globalsign/est/cmd/estserver@latest`
and `.../cmd/estclient@latest`, found by $ESTSERVER and $ESTCLIENT, on
PATH, or in ~/go/bin; each part is skipped when its tool is missing.
Needs openssl.

    python3 scripts/interop.py [--goose PATH]
"""

import argparse
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
TOP = os.path.normpath(os.path.join(ROOT, ".."))
PASSWORD = "interop password"

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
    e.pop("EST_PASSWORD", None)
    if env:
        e.update(env)
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, env=e, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


def verify(cert, cwd):
    p = subprocess.run(["openssl", "verify", "-CAfile", "ca.pem", cert], cwd=cwd, capture_output=True, text=True)
    return p.returncode == 0


def same_key(cert, key, cwd):
    a = subprocess.run(["openssl", "x509", "-in", cert, "-noout", "-pubkey"], cwd=cwd, capture_output=True)
    b = subprocess.run(["openssl", "pkey", "-in", key, "-pubout"], cwd=cwd, capture_output=True)
    return a.returncode == 0 and b.returncode == 0 and a.stdout == b.stdout


def ssl_run(args, cwd):
    subprocess.run(["openssl", *args], cwd=cwd, check=True, capture_output=True)


def make_ca(d):
    """An EC CA, and a TLS server certificate from it for 127.0.0.1."""
    ssl_run(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key",
             "-out", "ca.pem", "-days", "30", "-subj", "/O=Example/CN=Goose EST Interop CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"], d)
    ssl_run(["req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "srv.key",
             "-out", "srv.csr", "-subj", "/CN=localhost"], d)
    with open(os.path.join(d, "ext"), "w") as f:
        f.write("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    ssl_run(["x509", "-req", "-in", "srv.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
             "-out", "srv.pem", "-days", "30", "-extfile", "ext"], d)


def start_ours(exe, d, port, *extra):
    p = subprocess.Popen([exe, "serve", "--ca-cert", "ca.pem", "--ca-key", "ca.key", "--port", str(port), *extra],
                         cwd=d, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                         env={**os.environ, "EST_PASSWORD": PASSWORD})
    line = p.stdout.readline()
    if not line.startswith("listening on "):
        p.kill()
        sys.exit(f"goose-est serve did not start: {line}")
    return p


def ours(exe, tmp):
    print("== goose-est against goose-est serve")
    d = os.path.join(tmp, "ours")
    os.makedirs(d)
    make_ca(d)
    port = free_port()
    srv = start_ours(exe, d, port, "--user", "alice", "--csrattrs-example")
    base = [exe, "--server", f"https://127.0.0.1:{port}", "--ca-file", "ca.pem"]
    pw = {"EST_PASSWORD": PASSWORD}
    try:
        rc, out = run(base + ["cacerts", "--out", "cas.pem"], d)
        check("/cacerts", rc == 0 and open(os.path.join(d, "cas.pem")).read().split()
              == open(os.path.join(d, "ca.pem")).read().split(), out)
        rc, out = run([exe, "--server", f"https://127.0.0.1:{port}", "cacerts"], d)
        check("/cacerts from a server not trusted: refused", rc == 1 and "TLS" in out, out)
        rc, out = run(base + ["csrattrs"], d)
        check("/csrattrs: RFC 7030's example", rc == 0 and "1.2.840.10045.2.1=1.3.132.0.34" in out, out)
        rc, out = run(base + ["enroll", "--key", "a.key", "--subject", "CN=a.example.test", "--dns", "a.example.test",
                              "--out", "a.pem"], d)
        check("/simpleenroll without credentials: 401 reported", rc == 1 and "401" in out, out)
        rc, out = run(base + ["--user", "alice", "enroll", "--key", "a.key", "--subject", "CN=a.example.test",
                              "--out", "a.pem"], d, {"EST_PASSWORD": "wrong"})
        check("/simpleenroll with the wrong password: 401 reported", rc == 1 and "401" in out, out)
        rc, out = run(base + ["--user", "alice", "--label", "devices", "enroll", "--key", "a.key", "--subject",
                              "CN=a.example.test", "--dns", "a.example.test", "--out", "a.pem"], d, pw)
        check("/simpleenroll with Basic, under a label: issued, openssl verifies it", rc == 0 and verify("a.pem", d), out)
        mode = oct(os.stat(os.path.join(d, "a.key")).st_mode & 0o777)
        check("the key file is 0600", mode == "0o600", mode)
        rc, out = run(base + ["reenroll", "--cert", "a.pem", "--key", "a.key", "--new-key", "a2.key",
                              "--out", "a2.pem"], d)
        check("/simplereenroll by client certificate, a new key", rc == 0 and verify("a2.pem", d)
              and same_key("a2.pem", "a2.key", d), out)
        rc, out = run(base + ["--user", "alice", "serverkeygen", "--subject", "CN=kg.example.test", "--out", "kg.pem",
                              "--key-out", "kg.key"], d, pw)
        check("/serverkeygen: the key and its certificate", rc == 0 and verify("kg.pem", d)
              and same_key("kg.pem", "kg.key", d), out)
    finally:
        stop(srv)
    port = free_port()
    srv = start_ours(exe, d, port, "--pending", "2")
    try:
        t0 = time.time()
        rc, out = run([exe, "--server", f"https://127.0.0.1:{port}", "--ca-file", "ca.pem", "enroll", "--key", "h.key",
                       "--subject", "CN=held", "--out", "h.pem"], d)
        check("202 and Retry-After twice, then issued", rc == 0 and verify("h.pem", d) and time.time() - t0 >= 2, out)
    finally:
        stop(srv)


class Hostile(http.server.BaseHTTPRequestHandler):
    mode = "big"

    def log_message(self, *a):
        pass

    def answer(self):
        if self.mode == "big":
            status, body, extra = 200, b"A" * (2 << 20), {}
        elif self.mode == "junk":
            status, body, extra = 200, b"not base64 at all *** \r\n", {}
        else:
            status, body, extra = 202, b"wait", {"Retry-After": "1"}
        self.send_response(status)
        self.send_header("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
        for k, v in extra.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass        # the client gave up on a body too large: what is tested

    def do_GET(self):
        self.answer()

    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        self.answer()


def hostile(exe, tmp):
    print("== goose-est against hostile servers")
    d = os.path.join(tmp, "hostile")
    os.makedirs(d)
    make_ca(d)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(d, "srv.pem"), os.path.join(d, "srv.key"))
    for mode, cmd, what, expect in [
            ("big", ["cacerts"], "a 2 MiB /cacerts: refused as too large", "larger"),
            ("junk", ["cacerts"], "junk for /cacerts: refused", "not EST"),
            ("held", ["--poll-timeout", "2", "enroll", "--key", "x.key", "--subject", "CN=x", "--out", "x.pem"],
             "held forever: given up after --poll-timeout", "in time")]:
        handler = type("H", (Hostile,), {"mode": mode})
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            rc, out = run([exe, "--server", f"https://127.0.0.1:{server.server_port}", "--ca-file", "ca.pem", *cmd], d,
                          timeout=60)
            check(what, rc == 1 and expect in out, out)
        finally:
            server.shutdown()
            server.server_close()


def globalsign_server(exe, estserver, tmp):
    print("== goose-est against GlobalSign's estserver")
    d = os.path.join(tmp, "gs")
    os.makedirs(d)
    make_ca(d)
    port = free_port()
    cfg = {"mock_ca": {"certificates": os.path.join(d, "ca.pem"), "private_key": os.path.join(d, "ca.key")},
           "tls": {"listen_address": f"127.0.0.1:{port}", "certificates": os.path.join(d, "srv.pem"),
                   "private_key": os.path.join(d, "srv.key"), "client_cas": [os.path.join(d, "ca.pem")]},
           "allowed_hosts": ["localhost", "127.0.0.1"], "healthcheck_password": "unused", "rate_limit": 0,
           "timeout": 30}
    with open(os.path.join(d, "cfg.json"), "w") as f:
        json.dump(cfg, f)
    srv = subprocess.Popen([estserver, "-config", "cfg.json"], cwd=d, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
    base = [exe, "--server", f"https://127.0.0.1:{port}", "--ca-file", "ca.pem"]
    try:
        if not wait_port(port):
            check("estserver started", False)
            return
        rc, out = run(base + ["cacerts", "--out", "cas.pem"], d)
        check("/cacerts", rc == 0 and verify("cas.pem", d), out)
        rc, out = run(base + ["csrattrs"], d)
        check("/csrattrs: none", rc == 0 and out.strip() == "", out)
        rc, out = run(base + ["--label", "csrattrs", "csrattrs"], d)
        check("/csrattrs under its label: RFC 7030's example", rc == 0 and "1.2.840.113549.1.9.7" in out
              and "1.2.840.10045.2.1=1.3.132.0.34" in out, out)
        rc, out = run(base + ["enroll", "--key", "a.key", "--subject", "CN=a.example.test", "--dns", "a.example.test",
                              "--out", "a.pem"], d)
        check("/simpleenroll: issued, openssl verifies it", rc == 0 and verify("a.pem", d), out)
        rc, out = run(base + ["--key-type", "rsa2048", "enroll", "--key", "r.key", "--subject", "CN=r.example.test",
                              "--out", "r.pem"], d)
        check("/simpleenroll for an RSA key", rc == 0 and verify("r.pem", d), out)
        rc, out = run(base + ["reenroll", "--cert", "a.pem", "--key", "a.key", "--new-key", "a2.key", "--out", "a2.pem"], d)
        check("/simplereenroll by client certificate", rc == 0 and verify("a2.pem", d) and same_key("a2.pem", "a2.key", d), out)
        rc, out = run(base + ["serverkeygen", "--subject", "CN=kg.example.test", "--out", "kg.pem", "--key-out", "kg.key"], d)
        check("/serverkeygen: the key and its certificate", rc == 0 and verify("kg.pem", d)
              and same_key("kg.pem", "kg.key", d), out)
        rc, out = run(base + ["--label", "triggererrors", "enroll", "--key", "a.key", "--subject",
                              "CN=Trigger Error Forbidden", "--out", "x.pem"], d)
        check("403 reported", rc == 1 and "403" in out, out)
        rc, out = run(base + ["--label", "triggererrors", "--poll-timeout", "2", "enroll", "--key", "a.key",
                              "--subject", "CN=Trigger Error Deferred", "--out", "x.pem"], d)
        check("202 with Retry-After 600: given up after --poll-timeout", rc == 1 and "in time" in out, out)
        rc, out = run(base + ["--label", "pkcs7", "serverkeygen", "--subject", "CN=kg", "--out", "x.pem",
                              "--key-out", "x.key"], d)
        check("an encrypted server-generated key: reported as unsupported", rc == 1 and "encrypted" in out, out)
    finally:
        stop(srv)


def globalsign_client(exe, estclient, tmp):
    print("== GlobalSign's estclient against goose-est serve")
    d = os.path.join(tmp, "gsclient")
    os.makedirs(d)
    make_ca(d)
    port = free_port()
    srv = start_ours(exe, d, port, "--user", "alice", "--csrattrs-example")
    common = ["-server", f"127.0.0.1:{port}", "-explicit", "ca.pem"]
    try:
        ssl_run(["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "k.pem"], d)
        rc, out = run([estclient, "cacerts", *common, "-out", "cas.pem"], d)
        check("cacerts", rc == 0 and verify("cas.pem", d), out)
        rc, out = run([estclient, "csrattrs", *common], d)
        check("csrattrs", rc == 0 and "1.3.132.0.34" in out, out)
        rc, out = run([estclient, "enroll", *common, "-key", "k.pem", "-cn", "c.example.test", "-out", "c.pem"], d)
        check("enroll without credentials: refused", rc != 0, out)
        rc, out = run([estclient, "enroll", *common, "-key", "k.pem", "-cn", "c.example.test", "-user", "alice",
                       "-pass", PASSWORD, "-out", "c.pem"], d)
        check("enroll with Basic: issued, openssl verifies it", rc == 0 and verify("c.pem", d), out)
        rc, out = run([estclient, "reenroll", *common, "-key", "k.pem", "-certs", "c.pem", "-out", "c2.pem"], d)
        check("reenroll by client certificate", rc == 0 and verify("c2.pem", d), out)
        rc, out = run([estclient, "serverkeygen", *common, "-key", "k.pem", "-cn", "kg", "-user", "alice", "-pass",
                       PASSWORD, "-out", "kg.pem", "-keyout", "kgk.pem"], d)
        check("serverkeygen: the key and its certificate", rc == 0 and verify("kg.pem", d)
              and same_key("kg.pem", "kgk.pem", d), out)
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
        exe = os.path.join(tmp, "goose-est")
        build(goose, os.path.join(ROOT, "tools", "est.goose"), exe)
        ours(exe, tmp)
        hostile(exe, tmp)
        estserver = find_tool("estserver")
        if estserver:
            globalsign_server(exe, estserver, tmp)
        else:
            print("skip GlobalSign's estserver: not found ($ESTSERVER, PATH, ~/go/bin)")
        estclient = find_tool("estclient")
        if estclient:
            globalsign_client(exe, estclient, tmp)
        else:
            print("skip GlobalSign's estclient: not found ($ESTCLIENT, PATH, ~/go/bin)")
    print(f"\n{'all passed' if failures == 0 else f'{failures} failed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
