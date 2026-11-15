#!/usr/bin/env python3
"""goose-ntlm against other NTLM implementations, all on 127.0.0.1.

    NTLM_PYTHON=/path/to/venv/bin/python make interop-ntlm
    /path/to/venv/bin/python ntlm/scripts/interop.py [--goose PATH] [--bin PATH] [--work DIR] [-k NAME]

The Python that runs it needs pyspnego (pure-Python NTLM, both sides) and,
for one cross-check, impacket; curl (with NTLM) and Go (Azure/go-ntlmssp,
pinned by scripts/gontlm's go.mod, built into the work directory) are
used when found. What is missing is
skipped and said so. Nothing is installed system-wide; every server is
on 127.0.0.1 and every password is made up here.

- goose-ntlm's initiator against pyspnego's acceptor, and pyspnego's
  initiator against goose-ntlm's acceptor: raw NTLMSSP and SPNEGO
  ("negotiate"), channel bindings that match and that do not, sealing
  and signing both ways after the exchange, a wrong password, NTLMv1
  (pyspnego with LM_COMPAT_LEVEL 1) refused, pyspnego's acceptor set to
  NTLMv2 only (LM_COMPAT_LEVEL 5) taking ours.
- goose-ntlm compute against impacket's computeResponseNTLMv2.
- curl --ntlm and Azure/go-ntlmssp against goose-ntlm serve, and
  pyspnego over http.client (NTLM and Negotiate/SPNEGO) against it.
- goose-ntlm get (net/http's fetch with AUTH_NTLM) against an HTTP
  server built on pyspnego's acceptor, offering "NTLM", and "Negotiate"
  alone; over https, with the channel binding of the server's
  certificate (tls-server-end-point) that the acceptor requires, and
  refused by one bound to another certificate.
"""

import argparse
import base64
import http.client
import http.server
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
NTLM_DIR = os.path.normpath(os.path.join(HERE, ".."))
GSLIB = os.path.normpath(os.path.join(NTLM_DIR, ".."))

try:
    import spnego
    from spnego.channel_bindings import GssChannelBindings
except ImportError:
    sys.exit("interop.py needs pyspnego (run it with a venv's python: NTLM_PYTHON)")

DOMAIN = "EXAMPLE"
USER = "alice"
# Made up for these tests only.
PASSWORD = "Interop-Test-Pw-7"
CB = b"tls-server-end-point:" + bytes(range(32))
CB_OTHER = b"tls-server-end-point:" + bytes(range(1, 33))

passed = 0
failed = []
skipped = []


def check(what, ok, detail=""):
    global passed
    if ok:
        passed += 1
        print("ok    " + what)
    else:
        failed.append(what)
        print("FAIL  " + what + (("\n      " + str(detail)[:2000].replace("\n", "\n      ")) if detail else ""))
    return ok


def skip(what, why):
    skipped.append(what)
    print(f"skip  {what}: {why}")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(GSLIB, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, proc, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class Goose:
    """goose-ntlm initiate/accept over pipes."""

    def __init__(self, binary, args, env):
        self.p = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True, env=env)

    def line(self):
        return self.p.stdout.readline().strip()

    def send(self, s):
        self.p.stdin.write(s + "\n")
        self.p.stdin.flush()

    def token(self):
        l = self.line()
        if not l.startswith("token "):
            return None, l
        return base64.b64decode(l[6:]), l

    def close(self):
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(10)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def b64(b):
    return base64.b64encode(b).decode()


def run_env(work, extra=None):
    env = dict(os.environ)
    env["NTLM_TEST_PW"] = PASSWORD
    env["NTLM_USER_FILE"] = os.path.join(work, "users.txt")
    env.pop("LM_COMPAT_LEVEL", None)
    if extra:
        env.update(extra)
    return env


def cred_args():
    return ["--user", USER, "--domain", DOMAIN, "--password-env", "NTLM_TEST_PW"]


# --- pyspnego in memory ---------------------------------------------------------------------

def goose_initiator_vs_pyspnego(binary, work, name, protocol="ntlm", cb_ours=None, cb_theirs=None, password=PASSWORD,
                                expect_ok=True, lm_level=None):
    """goose-ntlm initiate against spnego.server."""
    env = run_env(work, {"NTLM_TEST_PW": password})
    args = ["initiate", *cred_args(), "--spn", "HTTP/web.example.test", "--seal"]
    if protocol == "negotiate":
        args.append("--spnego")
    if cb_ours:
        args += ["--cb-hex", cb_ours.hex()]
    g = Goose(binary, args, env)
    old = os.environ.get("LM_COMPAT_LEVEL")
    os.environ["NTLM_USER_FILE"] = env["NTLM_USER_FILE"]
    if lm_level is not None:
        os.environ["LM_COMPAT_LEVEL"] = str(lm_level)
    try:
        srv = spnego.server(protocol=protocol,
                            channel_bindings=GssChannelBindings(application_data=cb_theirs) if cb_theirs else None)
        err = None
        tok, l = g.token()
        while tok is not None and not srv.complete:
            try:
                out = srv.step(tok)
            except Exception as e:      # pyspnego refused it
                err = e
                break
            if out:
                g.send("token " + b64(out))
            l = g.line()
            if l.startswith("token "):
                tok = base64.b64decode(l[6:])
                continue
            break
        if not expect_ok:
            check(f"{name}: refused", err is not None or not srv.complete, f"pyspnego completed; goose said {l}")
            return
        if not check(f"{name}: established", err is None and srv.complete and l.startswith("done"), f"{err} / {l}"):
            return
        # Sealing both ways, several times (RC4 state and sequence numbers).
        good = True
        for i in range(3):
            msg = f"message {i} from goose".encode()
            g.send("wrap " + b64(msg))
            w = g.line()
            good = good and w.startswith("wrapped ") and srv.unwrap(base64.b64decode(w[8:])).data == msg
            back = srv.wrap(f"reply {i}".encode()).data
            g.send("unwrap " + b64(back))
            p = g.line()
            good = good and p.startswith("plain ") and base64.b64decode(p[6:]) == f"reply {i}".encode()
        check(f"{name}: wrap/unwrap both ways", good)
        sig = srv.sign(b"signed data")
        g.send(f"verify {b64(b'signed data')} {b64(sig)}")
        check(f"{name}: pyspnego's MIC verified", g.line() == "ok")
        if protocol == "ntlm":
            u = srv.client_principal if hasattr(srv, "client_principal") else None
            if u is not None:
                check(f"{name}: pyspnego sees the user", u.lower().endswith(USER), u)
    finally:
        if lm_level is not None:
            if old is None:
                os.environ.pop("LM_COMPAT_LEVEL", None)
            else:
                os.environ["LM_COMPAT_LEVEL"] = old
        g.close()


def pyspnego_initiator_vs_goose(binary, work, name, protocol="ntlm", cb_ours=None, cb_theirs=None, password=PASSWORD,
                                expect=None, lm_level=None, extra_args=()):
    """spnego.client against goose-ntlm accept. expect: None for success,
    else the error text goose-ntlm should give."""
    args = ["accept", "--users", os.path.join(work, "users.txt"), *extra_args]
    if protocol == "negotiate":
        args.append("--spnego")
    if cb_ours:
        args += ["--cb-hex", cb_ours.hex(), "--cb", "required"]
    g = Goose(binary, args, run_env(work))
    old = os.environ.get("LM_COMPAT_LEVEL")
    if lm_level is not None:
        os.environ["LM_COMPAT_LEVEL"] = str(lm_level)
    try:
        cli = spnego.client(f"{DOMAIN}\\{USER}", password, hostname="web.example.test", service="HTTP", protocol=protocol,
                            channel_bindings=GssChannelBindings(application_data=cb_theirs) if cb_theirs else None)
        tok = cli.step()
        last = ""
        err = None
        while tok:
            g.send("token " + b64(tok))
            last = g.line()
            if last.startswith("token "):
                try:
                    tok = cli.step(base64.b64decode(last[6:]))
                except Exception as e:
                    err = e
                    last = g.line()     # goose-ntlm's verdict after its reject token
                    break
                if not tok:
                    break
                continue
            break
        if not last.startswith("done") and not last.startswith("error") and not err:
            last = g.line()
        if expect is not None:
            check(f"{name}: refused ({expect})", last == "error " + expect, f"{last} {err or ''}")
            return
        if not check(f"{name}: established", err is None and last.startswith("done") and cli.complete,
                     f"{last} {err or ''} complete={cli.complete}"):
            return
        check(f"{name}: user", last == f"done {DOMAIN}\\{USER}", last)
        good = True
        for i in range(3):
            w = cli.wrap(f"message {i} from pyspnego".encode()).data
            g.send("unwrap " + b64(w))
            p = g.line()
            good = good and p.startswith("plain ") and base64.b64decode(p[6:]) == f"message {i} from pyspnego".encode()
            g.send("wrap " + b64(f"reply {i}".encode()))
            w2 = g.line()
            good = good and w2.startswith("wrapped ") and cli.unwrap(base64.b64decode(w2[8:])).data == f"reply {i}".encode()
        check(f"{name}: wrap/unwrap both ways", good)
        g.send("mic " + b64(b"to sign"))
        m = g.line()
        try:
            cli.verify(b"to sign", base64.b64decode(m[4:]))
            ok = True
        except Exception as e:
            ok = False
        check(f"{name}: our MIC verified by pyspnego", ok, m)
    finally:
        if lm_level is not None:
            if old is None:
                os.environ.pop("LM_COMPAT_LEVEL", None)
            else:
                os.environ["LM_COMPAT_LEVEL"] = old
        g.close()


def pyspnego_tests(binary, work):
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego NTLM")
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego NTLM, NTLMv2-only acceptor", lm_level=5)
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego NTLM, channel bindings", cb_ours=CB, cb_theirs=CB)
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego NTLM, other bindings", cb_ours=CB_OTHER, cb_theirs=CB,
                                expect_ok=False)
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego NTLM, wrong password", password="nope", expect_ok=False)
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego SPNEGO", protocol="negotiate")
    goose_initiator_vs_pyspnego(binary, work, "goose -> pyspnego SPNEGO, channel bindings", protocol="negotiate",
                                cb_ours=CB, cb_theirs=CB)

    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, channel bindings", cb_ours=CB, cb_theirs=CB)
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, other bindings", cb_ours=CB, cb_theirs=CB_OTHER,
                                expect="channel bindings mismatch")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, no bindings where required", cb_ours=CB,
                                expect="channel bindings mismatch")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, wrong password", password="nope", expect="logon failure")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, SPN checked", extra_args=["--spn", "HTTP/web.example.test",
                                                                                              "--spn-required"])
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose NTLM, another SPN", expect="target name mismatch",
                                extra_args=["--spn", "HTTP/other.example.test"])
    pyspnego_initiator_vs_goose(binary, work, "pyspnego NTLMv1 -> goose", lm_level=1, expect="LM or NTLMv1 refused")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose SPNEGO", protocol="negotiate")
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose SPNEGO, channel bindings", protocol="negotiate", cb_ours=CB,
                                cb_theirs=CB)
    pyspnego_initiator_vs_goose(binary, work, "pyspnego -> goose SPNEGO, wrong password", protocol="negotiate", password="nope",
                                expect="logon failure")


# --- impacket -------------------------------------------------------------------------------

def impacket_tests(binary, work):
    try:
        from impacket import ntlm as intlm
    except ImportError:
        skip("impacket", "not installed")
        return
    sc = bytes.fromhex("0123456789abcdef")
    cc = bytes.fromhex("f0e1d2c3b4a59687")
    ti = bytes.fromhex("02000e004500580041004d0050004c00450001000600570045004200" + "00000000")
    # NbDomainName "EXAMPLE", NbComputerName "WEB", MsvAvEOL.
    ts = 133000000000000000
    p = subprocess.run([binary, "compute", *cred_args(), "--server-challenge", sc.hex(), "--client-challenge", cc.hex(),
                        "--time", str(ts), "--target-info", ti.hex()], capture_output=True, text=True, env=run_env(work))
    got = dict(l.split(" ", 1) for l in p.stdout.split("\n") if " " in l)
    nt_hash = intlm.compute_nthash(PASSWORD)
    key = intlm.NTOWFv2(USER, PASSWORD, DOMAIN)
    check("impacket: NTOWFv2", got.get("ntowfv2") == key.hex(), p.stdout + p.stderr)
    # impacket's computeResponseNTLMv2 builds the blob with its own clock;
    # rebuild ours with the same time and compare NTProofStr.
    import hmac
    import hashlib
    blob = b"\x01\x01" + b"\x00" * 6 + ts.to_bytes(8, "little") + cc + b"\x00" * 4 + ti + b"\x00" * 4
    proof = hmac.new(key, sc + blob, hashlib.md5).digest()
    check("impacket: NTProofStr", got.get("ntproofstr") == proof.hex())
    check("impacket: NT response", got.get("nt_response") == (proof + blob).hex())
    lm = hmac.new(key, sc + cc, hashlib.md5).digest() + cc
    check("impacket: LMv2", got.get("lmv2_response") == lm.hex())
    check("impacket: session base key", got.get("session_base_key") == hmac.new(key, proof, hashlib.md5).digest().hex())
    del nt_hash


# --- HTTP: other clients against goose-ntlm serve -------------------------------------------

def start_serve(binary, work, extra=()):
    port = free_port()
    p = subprocess.Popen([binary, "serve", "--users", os.path.join(work, "users.txt"), "--port", str(port), *extra],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if not wait_port(port, p):
        p.kill()
        return None, None
    return p, port


def stop(p):
    if p is None:
        return ""
    p.terminate()
    try:
        _, err = p.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        p.kill()
        _, err = p.communicate()
    return err


def pyspnego_http(port, protocol, scheme, password=PASSWORD):
    """pyspnego's client over one http.client connection."""
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    cli = spnego.client(f"{DOMAIN}\\{USER}", password, hostname="127.0.0.1", service="HTTP", protocol=protocol)
    tok = cli.step()
    status, body = 0, b""
    for _ in range(4):
        c.request("GET", "/x", headers={"Authorization": f"{scheme} {b64(tok)}"})
        r = c.getresponse()
        body = r.read()
        status = r.status
        www = [v for k, v in r.getheaders() if k.lower() == "www-authenticate"]
        mine = [v for v in www if v.lower().startswith(scheme.lower() + " ")]
        if status != 401 or not mine:
            if status == 200 and mine:
                cli.step(base64.b64decode(mine[0].split(" ", 1)[1]))
            break
        tok = cli.step(base64.b64decode(mine[0].split(" ", 1)[1]))
    # A second request on the same connection: authenticated already.
    second = 0
    if status == 200:
        c.request("GET", "/again")
        r = c.getresponse()
        r.read()
        second = r.status
    c.close()
    return status, body, second, cli.complete


def http_clients(binary, work):
    p, port = start_serve(binary, work)
    if p is None:
        check("goose-ntlm serve starts", False)
        return
    try:
        curl = shutil.which("curl")
        if curl and "NTLM" in subprocess.run([curl, "--version"], capture_output=True, text=True).stdout:
            url = f"http://127.0.0.1:{port}/curl"
            r = subprocess.run([curl, "-s", "--ntlm", "-u", f"{DOMAIN}\\{USER}:{PASSWORD}", url], capture_output=True, text=True)
            check("curl --ntlm -> goose serve", r.stdout.strip() == f"hello {DOMAIN}\\{USER}", r.stdout + r.stderr)
            r = subprocess.run([curl, "-s", "-o", "/dev/null", "-w", "%{http_code}", "--ntlm", "-u", f"{DOMAIN}\\{USER}:wrong", url],
                               capture_output=True, text=True)
            check("curl --ntlm, wrong password -> 401", r.stdout.strip() == "401", r.stdout)
        else:
            skip("curl --ntlm", "no curl with NTLM")
        for protocol, scheme in [("ntlm", "NTLM"), ("ntlm", "Negotiate"), ("negotiate", "Negotiate")]:
            st, body, second, done = pyspnego_http(port, protocol, scheme)
            check(f"pyspnego {protocol} as {scheme} over HTTP -> goose serve",
                  st == 200 and body.strip() == f"hello {DOMAIN}\\{USER}".encode() and second == 200 and done,
                  f"{st} {body!r} {second} {done}")
        st, body, second, done = pyspnego_http(port, "ntlm", "NTLM", password="wrong")
        check("pyspnego, wrong password over HTTP -> 401", st == 401, st)
        go_client(port, work)
    finally:
        err = stop(p)
    check("goose serve logged authentications", f"authenticated {DOMAIN}\\{USER}" in err, err)


def go_client(port, work):
    """Azure/go-ntlmssp's Negotiator (scripts/gontlm: go.mod pins it) against goose-ntlm serve."""
    go = shutil.which("go")
    if not go:
        skip("go-ntlmssp", "no Go")
        return
    exe = os.path.join(work, "gontlm")
    env = dict(os.environ)
    if not os.path.exists(exe):
        r = subprocess.run([go, "build", "-o", exe, "."], cwd=os.path.join(HERE, "gontlm"), capture_output=True, text=True,
                           env=env)
        if r.returncode != 0:
            skip("go-ntlmssp", "build failed: " + (r.stdout + r.stderr)[-400:])
            return
    env["NTLM_TEST_PW"] = PASSWORD
    r = subprocess.run([exe, f"http://127.0.0.1:{port}/go", f"{DOMAIN}\\{USER}"], capture_output=True, text=True, env=env)
    check("go-ntlmssp -> goose serve", r.stdout.strip() == f"200 hello {DOMAIN}\\{USER}", r.stdout + r.stderr)
    env["NTLM_TEST_PW"] = "wrong"
    r = subprocess.run([exe, f"http://127.0.0.1:{port}/go", f"{DOMAIN}\\{USER}"], capture_output=True, text=True, env=env)
    check("go-ntlmssp, wrong password -> 401", r.stdout.startswith("401"), r.stdout + r.stderr)


# --- HTTP: goose-ntlm get against a pyspnego server -----------------------------------------

def make_handler(schemes, log, cb=None, empty_401=False):
    """An HTTP/1.1 handler on pyspnego's NTLM acceptor; cb: the channel
    bindings' application data it requires; empty_401: the CHALLENGE's 401
    without a body."""
    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, status, body, extra=()):
            self.send_response(status)
            for k, v in extra:
                self.send_header(k, v)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            ctx = getattr(self, "ctx", None)
            if getattr(self, "who", None):
                self.reply(200, f"hello {self.who}\n".encode())
                return
            auth = self.headers.get("Authorization", "")
            sch, _, tok = auth.partition(" ")
            if sch not in schemes or not tok:
                self.reply(401, b"auth\n", [("WWW-Authenticate", s) for s in schemes])
                return
            raw = base64.b64decode(tok)
            if ctx is None or raw[8:12] == b"\x01\x00\x00\x00":
                ctx = self.ctx = spnego.server(protocol="ntlm",
                                               channel_bindings=GssChannelBindings(application_data=cb) if cb else None)
            try:
                out = ctx.step(raw)
            except Exception as e:
                log.append(f"refused: {e}")
                self.ctx = None
                self.reply(401, b"refused\n", [("WWW-Authenticate", s) for s in schemes])
                return
            if not ctx.complete:
                self.reply(401, b"" if empty_401 else b"continue\n", [("WWW-Authenticate", f"{sch} {b64(out)}")])
                return
            self.who = ctx.client_principal
            log.append(f"authenticated {self.who} via {sch}")
            self.reply(200, f"hello {self.who}\n".encode())

    return H


def goose_get(binary, work):
    for schemes in (["NTLM"], ["Negotiate"], ["Basic realm=\"x\"", "NTLM"]):
        log = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler([s.split(" ")[0] for s in schemes], log))
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            name = "+".join(s.split(" ")[0] for s in schemes)
            r = subprocess.run([binary, "get", *cred_args(), f"http://127.0.0.1:{port}/"], capture_output=True, text=True,
                               env=run_env(work), timeout=30)
            check(f"goose get -> pyspnego server ({name})", r.returncode == 0 and "hello" in r.stdout and
                  any(l.startswith("authenticated") for l in log), f"{r.stdout} {r.stderr} {log}")
            r = subprocess.run([binary, "get", *cred_args(), f"http://127.0.0.1:{port}/"], capture_output=True, text=True,
                               env=run_env(work, {"NTLM_TEST_PW": "wrong"}), timeout=30)
            check(f"goose get, wrong password -> 401 ({name})", r.returncode == 1 and "HTTP 401" in r.stderr, r.stderr)
        finally:
            srv.shutdown()
            srv.server_close()


def self_signed(work):
    """A P-256 certificate for 127.0.0.1 and its key, in work; its DER."""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .sign(key, hashes.SHA256()))
    with open(os.path.join(work, "tls.crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(os.path.join(work, "tls.key"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cert.public_bytes(serialization.Encoding.DER)


def goose_get_tls(binary, work):
    """goose-ntlm get over https: the channel binding of the server's
    certificate, which pyspnego's acceptor requires; a server bound to
    another certificate (a relay) refuses it."""
    import hashlib
    import ssl
    try:
        der = self_signed(work)
    except ImportError:
        skip("https channel bindings", "no cryptography module")
        return
    good = b"tls-server-end-point:" + hashlib.sha256(der).digest()
    other = b"tls-server-end-point:" + hashlib.sha256(der + b"x").digest()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(work, "tls.crt"), os.path.join(work, "tls.key"))
    for cb, empty, want, name in [(good, False, True, "bindings of this certificate"),
                                  (good, True, True, "bindings, empty 401 bodies"),
                                  (other, False, False, "bindings of another certificate refused")]:
        log = []
        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(["NTLM"], log, cb=cb, empty_401=empty))
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            r = subprocess.run([binary, "get", "--insecure", *cred_args(), f"https://127.0.0.1:{port}/"], capture_output=True,
                               text=True, env=run_env(work), timeout=60)
            ok = (r.returncode == 0 and "hello" in r.stdout) if want else (r.returncode == 1 and "HTTP 401" in r.stderr)
            check(f"goose get https -> pyspnego server: {name}", ok, f"{r.stdout} {r.stderr} {log}")
        finally:
            srv.shutdown()
            srv.server_close()


def goose_get_vs_serve(binary, work):
    p, port = start_serve(binary, work)
    if p is None:
        check("goose-ntlm serve starts", False)
        return
    try:
        r = subprocess.run([binary, "get", *cred_args(), f"http://127.0.0.1:{port}/self"], capture_output=True, text=True,
                           env=run_env(work), timeout=30)
        check("goose get -> goose serve", r.returncode == 0 and r.stdout.strip() == f"hello {DOMAIN}\\{USER}", r.stdout + r.stderr)
    finally:
        stop(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--bin", help="a goose-ntlm already built")
    ap.add_argument("--work")
    ap.add_argument("-k", help="only checks whose group name contains this")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        work = args.work or tmp
        os.makedirs(work, exist_ok=True)
        with open(os.path.join(work, "users.txt"), "w") as f:
            f.write(f"{DOMAIN}:{USER}:{PASSWORD}\n")
        # pyspnego's acceptors read their users from here.
        os.environ["NTLM_USER_FILE"] = os.path.join(work, "users.txt")
        binary = args.bin
        if not binary:
            binary = os.path.join(work, "goose-ntlm")
            goose = find_goose(args.goose)
            print("building goose-ntlm")
            r = subprocess.run([goose, "build", "-o", binary, os.path.join(NTLM_DIR, "tools", "ntlm.goose")],
                               capture_output=True, text=True)
            if r.returncode != 0:
                sys.exit("build failed:\n" + r.stdout + r.stderr)
        groups = [("pyspnego", pyspnego_tests), ("impacket", impacket_tests), ("http", http_clients),
                  ("get", goose_get), ("get-tls", goose_get_tls), ("self", goose_get_vs_serve)]
        for name, fn in groups:
            if args.k and args.k not in name:
                continue
            fn(binary, work)
    print(f"\n{passed} passed, {len(failed)} failed, {len(skipped)} skipped")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
