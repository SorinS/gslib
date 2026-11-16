#!/usr/bin/env python3
"""A live check of sspi on Windows: the examples built and run against
real servers.

  - Schannel (examples/sspi/https_get): gslib's own TLS server
    (crypto/tls/tools/peer, relayed to a local socket by this script) with
    the test certificates, TLS 1.3 and 1.2, P-256 and RSA, taken with
    --insecure and refused (its root is not the system's) without; and,
    with --public, public sites: verified at TLS 1.3 and 1.2, and badssl.com's
    self-signed, wrong-name and expired certificates refused.
  - Negotiate (examples/sspi/negotiate_get): gslib's NTLM acceptor
    (ntlm/tools, goose-ntlm serve) with a user and a random password
    made up for the run (never printed), under the Negotiate and NTLM
    schemes; a wrong password refused; the logged-on user's first token.

    python scripts/sspi_check.py [--goose PATH] [--public] [--cc NAME]

Exit status 0 when every step passed. Windows only.
"""

import argparse
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
GSLIB = os.path.normpath(os.path.join(ROOT, ".."))
VEC = os.path.join(GSLIB, "crypto", "tls", "test", "vectors")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(GSLIB, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


class TlsServer:
    """gslib's TLS server (peer.goose's server, over stdin and stdout)
    behind a local socket: each connection gets a peer process, whose
    handshake bytes are relayed; a request is answered "hello from goose"
    and the connection closed with close_notify."""

    def __init__(self, peer_exe, cert, versions=None, key_update=False, big=False):
        self.peer_exe, self.cert, self.versions = peer_exe, cert, versions
        self.key_update, self.big = key_update, big
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.errors = []
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        args = ["server", os.path.join(VEC, f"hs_{self.cert}.pem"), os.path.join(VEC, f"hs_{self.cert}.key")]
        if self.versions:
            args += ["--min-version", self.versions, "--max-version", self.versions]
        p = subprocess.Popen([self.peer_exe, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

        def cmd(line):
            p.stdin.write(line + "\n")
            p.stdin.flush()
            out, app = b"", b""
            while True:
                l = p.stdout.readline().strip()
                if not l:
                    raise RuntimeError("peer exited")
                if l == "END":
                    return out, app
                kind, _, rest = l.partition(" ")
                if kind == "OUT":
                    out += bytes.fromhex(rest)
                elif kind == "APP":
                    app += bytes.fromhex(rest)

        try:
            conn.settimeout(15)
            request = b""
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                out, app = cmd("IN " + data.hex())
                if out:
                    conn.sendall(out)
                request += app
                if b"\r\n\r\n" in request:
                    body = b"hello from goose" * (8192 if self.big else 1)
                    resp = (b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() +
                            b"\r\nConnection: close\r\n\r\n")
                    if self.key_update:
                        # A KeyUpdate (update_requested) between the
                        # header and the body: the client updates its keys
                        # and answers with its own.
                        out, _ = cmd("SEND " + resp.hex())
                        conn.sendall(out)
                        out, _ = cmd("KEYUPDATE")
                        conn.sendall(out)
                        resp = b""
                    resp += body
                    out, _ = cmd("SEND " + resp.hex())
                    conn.sendall(out)
                    out, _ = cmd("CLOSE")
                    conn.sendall(out)
                    break
        except Exception as e:  # noqa: BLE001 - reported as the step's detail
            self.errors.append(str(e))
        finally:
            conn.close()
            p.stdin.close()
            p.wait()

    def close(self):
        self.sock.close()


class Check:
    def __init__(self):
        self.failed = 0

    def step(self, what, ok, detail=""):
        print(("ok    " if ok else "FAIL  ") + what +
              ("" if ok or not detail else "\n      " + detail.strip().replace("\n", "\n      ")))
        if not ok:
            self.failed += 1
        return ok


def run(cmd, env=None, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    return p.returncode, p.stdout + p.stderr


def build(goose, cc, src, out, cwd):
    cmd = [goose, "build"] + (["--cc", cc] if cc else []) + ["-o", out, src]
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"building {src} failed:\n{p.stdout}{p.stderr}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--public", action="store_true", help="also public HTTPS sites (needs the internet)")
    ap.add_argument("--cc", help="the C compiler for goose build")
    args = ap.parse_args()
    if platform.system() != "Windows":
        sys.exit("sspi_check: SSPI is Windows'")
    goose = find_goose(args.goose)
    work = tempfile.mkdtemp(prefix="goose-sspi-")
    ex = os.path.join(GSLIB, "examples", "sspi")
    https_get = os.path.join(work, "https_get.exe")
    negotiate_get = os.path.join(work, "negotiate_get.exe")
    peer = os.path.join(work, "peer.exe")
    ntlm_tool = os.path.join(work, "goose-ntlm.exe")
    build(goose, args.cc, "https_get.goose", https_get, ex)
    build(goose, args.cc, "negotiate_get.goose", negotiate_get, ex)
    build(goose, args.cc, "peer.goose", peer, os.path.join(GSLIB, "crypto", "tls", "tools"))
    build(goose, args.cc, "ntlm.goose", ntlm_tool, os.path.join(GSLIB, "ntlm", "tools"))
    print(f"built in {work}")
    c = Check()

    # Schannel against gslib's TLS server.
    for cert in ("p256", "rsa"):
        for versions, name, want in ((None, "TLS 1.3", "TLS 1.3"), ("0303", "TLS 1.2", "TLS 1.2")):
            srv = TlsServer(peer, cert, versions)
            url = f"https://localhost:{srv.port}/"
            rc, out = run([https_get, "--insecure", url])
            c.step(f"schannel to gslib's server, {cert}, {name}, --insecure",
                   rc == 0 and f"version: {want}" in out and "status: HTTP/1.1 200 OK" in out and
                   "subject: CN=example.com" in out and "body: 16 bytes" in out,
                   out + "\n".join(srv.errors))
            srv.close()
    srv = TlsServer(peer, "p256", "0304", key_update=True)
    rc, out = run([https_get, "--insecure", f"https://localhost:{srv.port}/"])
    c.step("schannel through a TLS 1.3 KeyUpdate", rc == 0 and "body: 16 bytes" in out, out + "\n".join(srv.errors))
    srv.close()
    for versions, name in (("0304", "TLS 1.3"), ("0303", "TLS 1.2")):
        srv = TlsServer(peer, "p256", versions, big=True)
        rc, out = run([https_get, "--insecure", f"https://localhost:{srv.port}/"])
        c.step(f"a 128 KiB body over {name}", rc == 0 and "body: 131072 bytes" in out, out + "\n".join(srv.errors))
        srv.close()
    srv = TlsServer(peer, "p256")
    rc, out = run([https_get, f"https://localhost:{srv.port}/"])
    c.step("schannel refuses gslib's test root when verifying",
           rc != 0 and ("UNTRUSTED" in out or "CERT_E" in out or "SEC_E" in out), out)
    srv.close()
    srv = TlsServer(peer, "p256", "0304")
    rc, out = run([https_get, "--insecure", "--tls1.2", f"https://localhost:{srv.port}/"])
    c.step("a TLS 1.2 client and a TLS 1.3 server do not agree", rc != 0, out)
    srv.close()

    if args.public:
        for flag, want in (([], None), (["--tls1.3"], "TLS 1.3"), (["--tls1.2"], "TLS 1.2")):
            rc, out = run([https_get, *flag, "https://www.microsoft.com/"])
            c.step(f"schannel to a public site {' '.join(flag) or '(default)'}",
                   rc == 0 and "status: HTTP/1.1" in out and (want is None or f"version: {want}" in out), out)
        bad = 0
        for _ in range(8):
            rc, out = run([https_get, "--body", "https://www.microsoft.com/"])
            bad += rc != 0
        c.step("a public site's page, eight times over", bad == 0, out[-2000:])
        for host, what in (("self-signed.badssl.com", "self-signed"), ("wrong.host.badssl.com", "wrong name"),
                           ("expired.badssl.com", "expired")):
            rc, out = run([https_get, f"https://{host}/"])
            c.step(f"a {what} certificate refused", rc != 0, out)
        rc, out = run([https_get, "--insecure", "https://self-signed.badssl.com/"])
        c.step("a self-signed certificate taken with --insecure", rc == 0 and "status: HTTP/1.1 200" in out, out)

    # Negotiate against gslib's NTLM acceptor.
    user = "sspitest"
    password = secrets.token_urlsafe(18)
    users = os.path.join(work, "users.txt")
    with open(users, "w") as f:
        f.write(f"EXAMPLE:{user}:{password}\n")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    server = subprocess.Popen([ntlm_tool, "serve", "--users", users, "--port", str(port)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    try:
        import time
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                break
            except OSError:
                time.sleep(0.2)
        env = dict(os.environ, SSPI_TEST_PW=password)
        url = f"http://127.0.0.1:{port}/"
        rc, out = run([negotiate_get, "--user", f"EXAMPLE\\{user}", "--password-env", "SSPI_TEST_PW", url], env)
        c.step("Negotiate (NTLM) to gslib's acceptor", rc == 0 and ": 200" in out and
               f"hello EXAMPLE\\{user}" in out and "package: NTLM" in out, out)
        rc, out = run([negotiate_get, "--package", "NTLM", "--user", f"EXAMPLE\\{user}", "--password-env",
                       "SSPI_TEST_PW", url], env)
        c.step("the NTLM scheme to gslib's acceptor", rc == 0 and "NTLM token" in out and
               f"hello EXAMPLE\\{user}" in out, out)
        env_bad = dict(os.environ, SSPI_TEST_PW=password + "x")
        rc, out = run([negotiate_get, "--user", f"EXAMPLE\\{user}", "--password-env", "SSPI_TEST_PW", url], env_bad)
        c.step("a wrong password refused", rc != 0 and "401" in out, out)
        rc, out = run([negotiate_get, "--header-only", url])
        c.step("the logged-on user's first token", rc == 0 and "Authorization: Negotiate " in out, out)
    finally:
        server.terminate()
        server.wait()
        os.remove(users)
    print(f"\n{'all passed' if c.failed == 0 else str(c.failed) + ' failed'}")
    sys.exit(1 if c.failed else 0)


if __name__ == "__main__":
    main()
