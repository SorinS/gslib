#!/usr/bin/env python3
"""mail.smtp, mail.pop3 and mail.imap against servers: goose-mail
(mail/tools/mail.goose) talks to

  - scripted SMTP and POP3 servers here (Python's socketserver and ssl), which
    check what the client sends and misbehave on purpose: STARTTLS/STLS and
    implicit TLS, every SASL mechanism checked the server's way (SCRAM's
    proofs too), APOP, HELO fallback, refusals, dot-stuffing both ways, the
    STARTTLS injection of CVE-2011-0411, a SCRAM server with a wrong
    signature;
  - a scripted IMAP server, which checks SASL the same way (with and
    without SASL-IR), takes literals (synchronizing and LITERAL+), and
    misbehaves on purpose: the STARTTLS injection, a bad certificate, a
    wrong password, an oversized literal, a malformed FETCH, a completion
    with another tag, BYE at the greeting and in the middle;
  - mailpit (SMTP in, POP3 out), when it is installed;
  - dovecot (POP3, with STLS, APOP and SASL; IMAP, with STARTTLS, 993,
    SASL and the mailbox commands), when it is installed.

    python3 scripts/interop.py [--goose PATH] [-k NAME]
"""

import argparse
import base64
import hashlib
import hmac
import os
import re
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
USER = "alice"
PASSWORD = "an interop password"
only = None
results = {"passed": 0, "failed": 0}
skipped = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def report(name, ok, detail=""):
    if ok:
        results["passed"] += 1
        print("ok    " + name)
    else:
        results["failed"] += 1
        print("FAIL  " + name + (": " + detail if detail else ""))


def wanted(name):
    return only is None or only in name


# --- The client ------------------------------------------------------------------

TOOL = None


def run_tool(args, user=USER, password=PASSWORD, timeout=60):
    env = dict(os.environ)
    env.pop("MAIL_USER", None)
    env.pop("MAIL_PASSWORD", None)
    if user is not None:
        env["MAIL_USER"] = user
        env["MAIL_PASSWORD"] = password
    p = subprocess.run([TOOL] + args, capture_output=True, text=True, env=env, timeout=timeout)
    return p.returncode, p.stdout + p.stderr


# --- SASL, the server's side -------------------------------------------------------

def scram_server(name, conn_lines, send, client_first, wrong_signature=False):
    """One SCRAM exchange after the client's first message; True if the
    client's proof checks out. conn_lines() reads the next decoded response."""
    algo = "sha1" if name == "SCRAM-SHA-1" else "sha256"
    assert client_first.startswith("n,,"), client_first
    bare = client_first[3:]
    attrs = dict(a.split("=", 1) for a in bare.split(","))
    user = attrs["n"].replace("=2C", ",").replace("=3D", "=")
    nonce = attrs["r"] + base64.b64encode(os.urandom(12)).decode()
    salt = os.urandom(16)
    iters = 4096
    server_first = "r=%s,s=%s,i=%d" % (nonce, base64.b64encode(salt).decode(), iters)
    send(server_first)
    final = conn_lines()
    without_proof, proof64 = final.rsplit(",p=", 1)
    fattrs = dict(a.split("=", 1) for a in without_proof.split(","))
    if fattrs.get("c") != "biws" or fattrs.get("r") != nonce:
        return False
    salted = hashlib.pbkdf2_hmac(algo, PASSWORD.encode(), salt, iters)
    client_key = hmac.new(salted, b"Client Key", algo).digest()
    stored = hashlib.new(algo, client_key).digest()
    auth_message = ",".join([bare, server_first, without_proof]).encode()
    sig = hmac.new(stored, auth_message, algo).digest()
    proof = base64.b64decode(proof64)
    if user != USER or bytes(a ^ b for a, b in zip(client_key, sig)) != proof:
        return False
    server_key = hmac.new(salted, b"Server Key", algo).digest()
    ssig = hmac.new(server_key, auth_message, algo).digest()
    if wrong_signature:
        ssig = bytes(b ^ 1 for b in ssig)
    send("v=" + base64.b64encode(ssig).decode())
    conn_lines()                                   # the client's empty response
    return True


def sasl_server(mech, initial, read_resp, send_challenge, wrong_signature=False):
    """Runs a mechanism; True if the client authenticated as USER."""
    if mech == "PLAIN":
        data = initial if initial is not None else read_resp_after(send_challenge, read_resp, "")
        return data == "\0%s\0%s" % (USER, PASSWORD)
    if mech == "LOGIN":
        send_challenge("Username:")
        u = read_resp()
        send_challenge("Password:")
        p = read_resp()
        return u == USER and p == PASSWORD
    if mech == "CRAM-MD5":
        challenge = "<%d.%d@mail.example.com>" % (os.getpid(), int(time.time()))
        send_challenge(challenge)
        resp = read_resp()
        want = USER + " " + hmac.new(PASSWORD.encode(), challenge.encode(), "md5").hexdigest()
        return resp == want
    if mech in ("SCRAM-SHA-1", "SCRAM-SHA-256"):
        first = initial if initial is not None else read_resp_after(send_challenge, read_resp, "")
        return scram_server(mech, read_resp, send_challenge, first, wrong_signature)
    return False


def read_resp_after(send_challenge, read_resp, challenge):
    send_challenge(challenge)
    return read_resp()


# --- A scripted SMTP server ----------------------------------------------------------

class Smtp(socketserver.StreamRequestHandler):
    # Set per server: ctx (ssl context), implicit, starttls, auth list,
    # helo_only, reject_rcpt, inject, scram_wrong, utf8; got: what it saw.
    def setup(self):
        o = self.server.o
        if o.get("implicit"):
            self.request = o["ctx"].wrap_socket(self.request, server_side=True)
        super().setup()

    def out(self, s):
        self.wfile.write(s.encode() + b"\r\n")
        self.wfile.flush()

    def line(self):
        l = self.rfile.readline(65536)
        if not l:
            raise EOFError
        return l.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        o = self.server.o
        got = self.server.got
        try:
            self.session(o, got)
        except (EOFError, ConnectionError, ssl.SSLError, OSError):
            pass

    def session(self, o, got):
        self.out("220 mail.example.com ESMTP fake")
        tls = bool(o.get("implicit"))
        while True:
            cmd = self.line()
            verb = cmd.split(" ", 1)[0].upper()
            got.setdefault("cmds", []).append(cmd if not verb == "AUTH" else "AUTH " + cmd.split(" ")[1])
            if verb == "EHLO":
                if o.get("helo_only"):
                    self.out("502 5.5.1 no ESMTP here")
                    continue
                exts = ["mail.example.com greets you", "8BITMIME", "SIZE 10240000", "DSN"]
                if o.get("starttls") and not tls:
                    exts.append("STARTTLS")
                if o.get("auth") and (tls or o.get("auth_plain_text")):
                    exts.append("AUTH " + " ".join(o["auth"]))
                if o.get("utf8"):
                    exts.append("SMTPUTF8")
                for i, e in enumerate(exts):
                    self.out("250%s%s" % ("-" if i < len(exts) - 1 else " ", e))
            elif verb == "HELO":
                self.out("250 mail.example.com")
            elif verb == "STARTTLS":
                if o.get("inject"):
                    # The reply and a forged one in the same packet.
                    self.wfile.write(b"220 2.0.0 go ahead\r\n250 injected\r\n")
                    self.wfile.flush()
                else:
                    self.out("220 2.0.0 go ahead")
                self.request = o["ctx"].wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                self.wfile = self.request.makefile("wb")
                tls = True
                got["tls"] = True
            elif verb == "AUTH":
                parts = cmd.split(" ")
                mech = parts[1].upper()
                initial = None
                if len(parts) > 2:
                    initial = "" if parts[2] == "=" else base64.b64decode(parts[2]).decode()

                def read_resp():
                    r = self.line()
                    if r == "*":
                        raise EOFError
                    return base64.b64decode(r).decode()

                def send_challenge(s):
                    self.out("334 " + base64.b64encode(s.encode()).decode())

                try:
                    ok = sasl_server(mech, initial, read_resp, send_challenge, o.get("scram_wrong"))
                except EOFError:
                    self.out("501 5.7.0 cancelled")
                    got["auth_cancelled"] = True
                    continue
                if ok:
                    got["auth"] = mech
                    self.out("235 2.7.0 accepted")
                else:
                    self.out("535 5.7.8 bad credentials")
            elif verb == "MAIL":
                got["from"] = cmd
                self.out("250 2.1.0 ok")
            elif verb == "RCPT":
                got.setdefault("rcpt", []).append(cmd)
                if o.get("reject_rcpt") and o["reject_rcpt"] in cmd:
                    self.out("550 5.1.1 no such user")
                else:
                    self.out("250 2.1.5 ok")
            elif verb == "DATA":
                self.out("354 go ahead")
                body = b""
                while True:
                    l = self.rfile.readline(1 << 20)
                    if not l:
                        raise EOFError
                    if l == b".\r\n":
                        break
                    if not l.endswith(b"\r\n"):
                        got["bare_lf"] = True
                    body += l[1:] if l.startswith(b".") else l
                got["data"] = body
                self.out("250 2.0.0 queued as 1")
            elif verb == "RSET":
                got["rset"] = True
                self.out("250 2.0.0 ok")
            elif verb == "NOOP":
                self.out("250 2.0.0 ok")
            elif verb == "QUIT":
                self.out("221 2.0.0 bye")
                return
            else:
                self.out("502 5.5.2 what")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(handler, o):
    srv = Server(("127.0.0.1", 0), handler)
    srv.o = o
    srv.got = {}
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


MESSAGE = (b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: interop\r\n\r\n"
           b"Hello.\r\n.a line that starts with a dot\r\n..two dots\r\n.\r\nend\r\n")


def smtp_cases(ctx, tmp):
    msgfile = os.path.join(tmp, "msg.eml")
    with open(msgfile, "wb") as f:
        f.write(MESSAGE)
    # A message with bare LF endings: DATA must carry CRLF.
    lffile = os.path.join(tmp, "lf.eml")
    with open(lffile, "wb") as f:
        f.write(MESSAGE.replace(b"\r\n", b"\n"))

    def case(name, o, args, want_rc=0, want_out=None, check=None, user=USER, password=PASSWORD, file=msgfile,
             rcpts=("bob@example.com",)):
        if not wanted("smtp " + name):
            return
        o.setdefault("ctx", ctx)
        srv = serve(Smtp, o)
        try:
            rc, out = run_tool(["smtp", "--port", str(srv.server_address[1])] + args +
                               ["127.0.0.1", file, "alice@example.com"] + list(rcpts), user, password)
            time.sleep(0.05)
            ok = rc == want_rc and (want_out is None or want_out in out)
            detail = "rc %d: %s" % (rc, out.strip().replace("\n", " | "))
            if ok and check:
                why = check(srv.got)
                if why:
                    ok, detail = False, why
            if password and password in out:
                ok, detail = False, "the password was printed"
            report("smtp " + name, ok, detail)
            if os.environ.get("SHOW"):
                print("      " + out.strip().replace("\n", " | "))
        finally:
            srv.shutdown()
            srv.server_close()

    def data_ok(g):
        if g.get("data") != MESSAGE:
            return "DATA arrived as %r" % g.get("data")
        if g.get("bare_lf"):
            return "a line without CRLF"
        return None

    case("plain text, no auth", {}, ["--tls", "none", "--auth", "none"], check=data_ok, user=None)
    case("bare LF made CRLF, dots stuffed", {}, ["--tls", "none", "--auth", "none"], check=data_ok, user=None,
         file=lffile)
    case("several recipients", {}, ["--tls", "none", "--auth", "none"], user=None,
         rcpts=("bob@example.com", "carol@example.com"),
         check=lambda g: None if len(g.get("rcpt", [])) == 2 else "rcpts %r" % g.get("rcpt"))
    case("HELO fallback", {"helo_only": True}, ["--tls", "none", "--auth", "none"], check=data_ok, user=None)
    case("STARTTLS", {"starttls": True}, ["--tls", "mandatory", "--insecure", "--auth", "none"], user=None,
         want_out="connected (TLS)", check=lambda g: data_ok(g) or (None if g.get("tls") else "no TLS"))
    case("STARTTLS required, not offered", {}, ["--tls", "mandatory", "--insecure"], want_rc=1,
         want_out="does not offer TLS")
    case("opportunistic without STARTTLS", {}, ["--tls", "opportunistic", "--auth", "none"], user=None,
         want_out="connected, ESMTP")
    case("certificate checked", {"starttls": True}, ["--tls", "mandatory", "--auth", "none"], user=None, want_rc=1,
         want_out="TLS failed")
    case("implicit TLS", {"implicit": True}, ["--tls", "implicit", "--insecure", "--auth", "none"], user=None,
         want_out="connected (TLS)", check=data_ok)
    case("STARTTLS injection refused", {"starttls": True, "inject": True},
         ["--tls", "mandatory", "--insecure", "--auth", "none"], user=None, want_rc=1,
         want_out="connect: mail: malformed server reply")
    for mech in ["PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256"]:
        case("AUTH " + mech, {"starttls": True, "auth": [mech]},
             ["--tls", "mandatory", "--insecure", "--auth", mech.lower()], want_out="authenticated",
             check=lambda g, m=mech: None if g.get("auth") == m else "server saw %r" % g.get("auth"))
        case("AUTH " + mech + " wrong password", {"starttls": True, "auth": [mech]},
             ["--tls", "mandatory", "--insecure", "--auth", mech.lower()], password="not it", want_rc=1,
             want_out="refused: 535")
    case("AUTH auto picks SCRAM-SHA-256", {"starttls": True, "auth": ["PLAIN", "LOGIN", "SCRAM-SHA-256", "CRAM-MD5"]},
         ["--tls", "mandatory", "--insecure", "--auth", "auto"], want_out="authenticated",
         check=lambda g: None if g.get("auth") == "SCRAM-SHA-256" else "server saw %r" % g.get("auth"))
    case("SCRAM server without the password", {"starttls": True, "auth": ["SCRAM-SHA-256"], "scram_wrong": True},
         ["--tls", "mandatory", "--insecure", "--auth", "scram-sha-256"], want_rc=1,
         want_out="the server did not prove itself",
         check=lambda g: None if g.get("auth_cancelled") else "the exchange was not cancelled")
    case("PLAIN over plain text to localhost", {"auth": ["PLAIN"], "auth_plain_text": True},
         ["--tls", "none", "--auth", "plain"], want_out="authenticated")
    case("refused recipient, then RSET", {"reject_rcpt": "nobody"}, ["--tls", "none", "--auth", "none"], user=None,
         rcpts=("nobody@example.com",), want_rc=1, want_out="refused: 550 5.1.1 no such user",
         check=lambda g: None if g.get("rset") else "no RSET")
    def composed_ok(g):
        import email
        import email.policy
        rcpts = g.get("rcpt", [])
        if rcpts != ["RCPT TO:<bob@example.com>", "RCPT TO:<hidden@example.com>"]:
            return "rcpts %r" % rcpts
        data = g.get("data") or b""
        m = email.message_from_bytes(data, policy=email.policy.default)
        if m["Bcc"] is not None or b"hidden@example.com" in data:
            return "the Bcc is in the message"
        if str(m["To"]) != "bob@example.com" or "composed" not in str(m["Subject"]):
            return "headers %r %r" % (m["To"], m["Subject"])
        att = [p for p in m.iter_attachments()]
        if len(att) != 1 or att[0].get_content() != b"\x00\x01\x02binary\xff":
            return "attachment %r" % att
        body = m.get_body(("plain",)).get_content()
        if ".a dotted line" not in body:
            return "body %r" % body
        return None

    case("a message from mail.message", {}, ["--tls", "none", "--auth", "none"], user=None, file="-",
         rcpts=("bob@example.com", "bcc:hidden@example.com"), want_out="message-id: ", check=composed_ok)
    case("8BITMIME and DSN advertised", {}, ["--tls", "none", "--auth", "none"], user=None,
         check=lambda g: None if "BODY=8BITMIME" in g.get("from", "") else "MAIL was %r" % g.get("from"))
    case("UTF-8 address without SMTPUTF8", {}, ["--tls", "none", "--auth", "none"], user=None,
         rcpts=("böb@example.com",), want_rc=1, want_out="not supported")
    case("UTF-8 address with SMTPUTF8", {"utf8": True}, ["--tls", "none", "--auth", "none"], user=None,
         rcpts=("böb@example.com",),
         check=lambda g: None if "SMTPUTF8" in g.get("from", "") else "MAIL was %r" % g.get("from"))


# --- A scripted POP3 server ----------------------------------------------------------

POP_MSGS = [
    b"From: a@example.com\r\nSubject: one\r\n\r\nfirst\r\n.dotted\r\nlast line\r\n",
    b"From: b@example.com\r\nSubject: two\r\n\r\nsecond body\r\nline 2\r\nline 3\r\n",
]


class Pop3(socketserver.StreamRequestHandler):
    def setup(self):
        o = self.server.o
        if o.get("implicit"):
            self.request = o["ctx"].wrap_socket(self.request, server_side=True)
        super().setup()

    def out(self, s):
        self.wfile.write(s.encode() + b"\r\n")
        self.wfile.flush()

    def line(self):
        l = self.rfile.readline(65536)
        if not l:
            raise EOFError
        return l.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        try:
            self.session(self.server.o, self.server.got)
        except (EOFError, ConnectionError, ssl.SSLError, OSError):
            pass

    def multi(self, data):
        for l in data.split(b"\r\n")[:-1]:
            self.wfile.write((b"." + l if l.startswith(b".") else l) + b"\r\n")
        self.wfile.write(b".\r\n")
        self.wfile.flush()

    def session(self, o, got):
        ts = "<%d.%d@pop.example.com>" % (os.getpid(), int(time.time()))
        self.out("+OK POP3 fake ready " + ts)
        tls = bool(o.get("implicit"))
        authed = False
        user = None
        deleted = set()
        while True:
            cmd = self.line()
            verb = cmd.split(" ", 1)[0].upper()
            args = cmd.split(" ")[1:]
            if verb == "CAPA":
                if o.get("no_capa"):
                    self.out("-ERR no CAPA")
                    continue
                self.out("+OK capabilities")
                caps = ["TOP", "UIDL", "USER", "PIPELINING"]
                if o.get("stls") and not tls:
                    caps.append("STLS")
                if o.get("sasl"):
                    caps.append("SASL " + " ".join(o["sasl"]))
                self.multi(("\r\n".join(caps) + "\r\n").encode())
            elif verb == "STLS":
                if o.get("inject"):
                    self.wfile.write(b"+OK begin TLS\r\n+OK injected\r\n")
                    self.wfile.flush()
                else:
                    self.out("+OK begin TLS")
                self.request = o["ctx"].wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                self.wfile = self.request.makefile("wb")
                tls = True
                got["tls"] = True
            elif verb == "USER":
                user = args[0] if args else None
                self.out("+OK")
            elif verb == "PASS":
                if user == USER and cmd[5:] == PASSWORD:
                    authed = True
                    got["auth"] = "USER"
                    self.out("+OK logged in")
                else:
                    self.out("-ERR [AUTH] bad password")
            elif verb == "APOP":
                want = hashlib.md5((ts + PASSWORD).encode()).hexdigest()
                if args == [USER, want]:
                    authed = True
                    got["auth"] = "APOP"
                    self.out("+OK logged in")
                else:
                    self.out("-ERR [AUTH] bad digest")
            elif verb == "AUTH":
                mech = args[0].upper()
                initial = None
                if len(args) > 1:
                    initial = "" if args[1] == "=" else base64.b64decode(args[1]).decode()

                def read_resp():
                    r = self.line()
                    if r == "*":
                        raise EOFError
                    return base64.b64decode(r).decode()

                def send_challenge(s):
                    self.out("+ " + base64.b64encode(s.encode()).decode())

                try:
                    ok = sasl_server(mech, initial, read_resp, send_challenge, o.get("scram_wrong"))
                except EOFError:
                    self.out("-ERR cancelled")
                    continue
                if ok:
                    authed = True
                    got["auth"] = mech
                    self.out("+OK logged in")
                else:
                    self.out("-ERR [AUTH] no")
            elif not authed and verb != "QUIT":
                self.out("-ERR log in first")
            elif verb == "STAT":
                live = [m for i, m in enumerate(POP_MSGS) if i + 1 not in deleted]
                self.out("+OK %d %d" % (len(live), sum(len(m) for m in live)))
            elif verb == "LIST":
                self.out("+OK")
                self.multi("".join("%d %d\r\n" % (i + 1, len(m)) for i, m in enumerate(POP_MSGS)
                                   if i + 1 not in deleted).encode())
            elif verb == "UIDL":
                self.out("+OK")
                self.multi("".join("%d uid-%d\r\n" % (i + 1, i + 1) for i in range(len(POP_MSGS))
                                   if i + 1 not in deleted).encode())
            elif verb in ("RETR", "TOP"):
                n = int(args[0])
                if n < 1 or n > len(POP_MSGS) or n in deleted:
                    self.out("-ERR no such message")
                    continue
                m = POP_MSGS[n - 1]
                if verb == "TOP":
                    head, body = m.split(b"\r\n\r\n", 1)
                    lines = body.split(b"\r\n")[:-1][:int(args[1])]
                    m = head + b"\r\n\r\n" + b"".join(l + b"\r\n" for l in lines)
                self.out("+OK %d octets" % len(m))
                self.multi(m)
            elif verb == "DELE":
                deleted.add(int(args[0]))
                self.out("+OK marked")
            elif verb == "RSET":
                deleted.clear()
                self.out("+OK")
            elif verb == "NOOP":
                self.out("+OK")
            elif verb == "QUIT":
                got["deleted"] = sorted(deleted)
                self.out("+OK bye")
                return
            else:
                self.out("-ERR unknown")


def pop3_cases(ctx):
    def case(name, o, args, cmds, want_rc=0, want_out=(), check=None, password=PASSWORD):
        if not wanted("pop3 " + name):
            return
        o.setdefault("ctx", ctx)
        srv = serve(Pop3, o)
        try:
            rc, out = run_tool(["pop3", "--port", str(srv.server_address[1])] + args + ["127.0.0.1"] + cmds,
                               USER, password)
            time.sleep(0.05)
            missing = [w for w in want_out if w not in out]
            ok = rc == want_rc and not missing
            detail = "rc %d, missing %r: %s" % (rc, missing, out.strip().replace("\n", " | "))
            if ok and check:
                why = check(srv.got)
                if why:
                    ok, detail = False, why
            if password and password in out:
                ok, detail = False, "the password was printed"
            report("pop3 " + name, ok, detail)
            if os.environ.get("SHOW"):
                print("      " + out.strip().replace("\n", " | "))
        finally:
            srv.shutdown()
            srv.server_close()

    sizes = [len(m) for m in POP_MSGS]
    case("USER/PASS, the mailbox", {}, ["--tls", "none", "--auth", "user"],
         ["stat", "list", "uidl", "retr", "1", "top", "2", "1"],
         want_out=["stat: 2 %d" % sum(sizes), "list: 1 %d" % sizes[0], "list: 2 %d" % sizes[1], "uidl: 2 uid-2",
                   "retr: 1 %d bytes" % len(POP_MSGS[0]), ".dotted", "top: 2", "second body"])
    case("RETR undoes the dots", {}, ["--tls", "none", "--auth", "user"], ["retr", "1"],
         want_out=["retr: 1 %d bytes" % len(POP_MSGS[0])])
    case("DELE then QUIT", {}, ["--tls", "none", "--auth", "user"], ["dele", "2", "stat"],
         want_out=["stat: 1 %d" % sizes[0]], check=lambda g: None if g.get("deleted") == [2] else "deleted %r" % g.get("deleted"))
    case("wrong password", {}, ["--tls", "none", "--auth", "user"], ["stat"], password="not it", want_rc=1,
         want_out=["refused", "bad password"])
    case("no such message", {}, ["--tls", "none", "--auth", "user"], ["retr", "9"], want_rc=1,
         want_out=["no such message"])
    case("STLS", {"stls": True}, ["--tls", "mandatory", "--insecure", "--auth", "user"], ["stat"],
         want_out=["connected (TLS)", "stat: 2"], check=lambda g: None if g.get("tls") else "no TLS")
    case("STLS required, not offered", {}, ["--tls", "mandatory", "--insecure", "--auth", "user"], ["stat"],
         want_rc=1, want_out=["does not offer TLS"])
    case("STLS required, no CAPA", {"no_capa": True}, ["--tls", "mandatory", "--insecure", "--auth", "user"],
         ["stat"], want_rc=1, want_out=["does not offer TLS"])
    case("STLS injection refused", {"stls": True, "inject": True},
         ["--tls", "mandatory", "--insecure", "--auth", "user"], ["stat"], want_rc=1,
         want_out=["connect: mail: malformed server reply"])
    case("implicit TLS", {"implicit": True}, ["--tls", "implicit", "--insecure", "--auth", "user"], ["stat"],
         want_out=["connected (TLS)", "stat: 2"])
    case("APOP", {}, ["--tls", "none", "--auth", "apop"], ["stat"], want_out=["authenticated", "stat: 2"],
         check=lambda g: None if g.get("auth") == "APOP" else "server saw %r" % g.get("auth"))
    case("APOP wrong password", {}, ["--tls", "none", "--auth", "apop"], ["stat"], password="not it", want_rc=1,
         want_out=["bad digest"])
    for mech in ["PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256"]:
        case("AUTH " + mech, {"stls": True, "sasl": [mech]},
             ["--tls", "mandatory", "--insecure", "--auth", mech.lower()], ["stat"],
             want_out=["authenticated", "stat: 2"],
             check=lambda g, m=mech: None if g.get("auth") == m else "server saw %r" % g.get("auth"))
        case("AUTH " + mech + " wrong password", {"stls": True, "sasl": [mech]},
             ["--tls", "mandatory", "--insecure", "--auth", mech.lower()], ["stat"], password="not it",
             want_rc=1, want_out=["auth: refused"])
    case("AUTH auto from SASL", {"stls": True, "sasl": ["PLAIN", "SCRAM-SHA-1", "CRAM-MD5"]},
         ["--tls", "mandatory", "--insecure", "--auth", "auto"], ["stat"], want_out=["authenticated"],
         check=lambda g: None if g.get("auth") == "SCRAM-SHA-1" else "server saw %r" % g.get("auth"))
    case("SCRAM server without the password", {"stls": True, "sasl": ["SCRAM-SHA-256"], "scram_wrong": True},
         ["--tls", "mandatory", "--insecure", "--auth", "scram-sha-256"], ["stat"], want_rc=1,
         want_out=["the server did not prove itself"])


# --- A scripted IMAP server ----------------------------------------------------------

IMAP_MSGS = [
    b"From: Alice <a@example.com>\r\nTo: bob@example.com\r\nSubject: say \"hi\"\r\nMessage-ID: <one@example.com>\r\n"
    b"\r\nfirst body\r\n) with a paren and a {5}\r\n",
    b"From: b@example.com\r\nTo: bob@example.com\r\nSubject: =?UTF-8?Q?Gr=C3=BC=C3=9Fe?=\r\n\r\nsecond\r\n",
]
IMAP_ENVELOPES = [
    '("Sat, 14 Nov 2026 10:00:00 +0000" "say \\"hi\\"" (("Alice" NIL "a" "example.com")) NIL NIL '
    '((NIL NIL "bob" "example.com")) NIL NIL NIL "<one@example.com>")',
    '("Sat, 14 Nov 2026 11:00:00 +0000" "=?UTF-8?Q?Gr=C3=BC=C3=9Fe?=" ((NIL NIL "b" "example.com")) NIL NIL '
    '((NIL NIL "bob" "example.com")) NIL NIL NIL NIL)',
]
APPEND_MSG = b"From: c@example.com\r\nSubject: appended\r\n\r\nappended body\r\n.dot\r\n"


def imap_split(seg):
    """The tokens of a command line's text: atoms (brackets and all),
    quoted strings unescaped, a parenthesized list as one raw string."""
    toks, i = [], 0
    s = seg.decode("utf-8", "replace")
    while i < len(s):
        if s[i] == " ":
            i += 1
        elif s[i] == '"':
            j, out = i + 1, ""
            while j < len(s) and s[j] != '"':
                if s[j] == "\\":
                    j += 1
                out += s[j]
                j += 1
            toks.append(out)
            i = j + 1
        elif s[i] == "(":
            depth, j = 0, i
            while j < len(s):
                depth += {"(": 1, ")": -1}.get(s[j], 0)
                j += 1
                if depth == 0:
                    break
            toks.append(s[i:j])
            i = j
        else:
            j, depth = i, 0
            while j < len(s) and (depth > 0 or s[j] != " "):
                depth += {"[": 1, "]": -1}.get(s[j], 0)
                j += 1
            toks.append(s[i:j])
            i = j
    return toks


def imap_set(spec, top):
    """A sequence set's numbers, '*' as top."""
    out = []
    for part in spec.split(","):
        a, _, b = part.partition(":")
        lo = top if a == "*" else int(a)
        hi = lo if not b else (top if b == "*" else int(b))
        lo, hi = min(lo, hi), max(lo, hi)
        out.extend(range(lo, hi + 1))
    return out


def imap_items(spec):
    s = spec[1:-1] if spec.startswith("(") else spec
    items, i = [], 0
    while i < len(s):
        if s[i] == " ":
            i += 1
            continue
        j, depth = i, 0
        while j < len(s) and (depth > 0 or s[j] != " "):
            depth += {"[": 1, "]": -1}.get(s[j], 0)
            j += 1
        items.append(s[i:j].upper())
        i = j
    return items


class Imap(socketserver.StreamRequestHandler):
    # Options: ctx, implicit, starttls, inject, auth (mechanisms), sasl_ir,
    # literal_plus, password, greeting ("bye", "preauth"), logindisabled,
    # huge_literal, malformed, wrong_tag, bye_on_noop, scram_wrong;
    # got: what it saw.
    def setup(self):
        o = self.server.o
        if o.get("implicit"):
            self.request = o["ctx"].wrap_socket(self.request, server_side=True)
        super().setup()

    def out(self, s):
        self.wfile.write((s if isinstance(s, bytes) else s.encode()) + b"\r\n")
        self.wfile.flush()

    def line(self):
        l = self.rfile.readline(65536)
        if not l:
            raise EOFError
        return l.decode("utf-8", "replace").rstrip("\r\n")

    def handle(self):
        try:
            self.session(self.server.o, self.server.got)
        except (EOFError, ConnectionError, ssl.SSLError, OSError):
            pass

    def command(self, got):
        """A command's tokens, its literals read (a "+" first unless {n+})."""
        toks = []
        while True:
            l = self.rfile.readline(1 << 20)
            if not l:
                raise EOFError
            l = l.rstrip(b"\r\n")
            m = re.search(rb"\{(\d+)(\+?)\}$", l)
            toks += imap_split(l[:m.start()] if m else l)
            if not m:
                return toks
            n, plus = int(m.group(1)), bool(m.group(2))
            got.setdefault("literals", []).append((n, plus))
            if not plus:
                self.out("+ go ahead")
            toks.append(self.rfile.read(n))

    def caps(self, o, tls, authed):
        c = ["IMAP4rev1", "IDLE", "ID", "ENABLE", "UIDPLUS", "MOVE", "UNSELECT", "UTF8=ACCEPT"]
        if o.get("starttls") and not tls:
            c.append("STARTTLS")
        if o.get("literal_plus"):
            c.append("LITERAL+")
        if o.get("rev2"):
            c.append("IMAP4rev2")
        if o.get("sasl_ir"):
            c.append("SASL-IR")
        if o.get("logindisabled") and not tls:
            c.append("LOGINDISABLED")
        if not authed:
            c += ["AUTH=" + m for m in o.get("auth", [])]
        return " ".join(c)

    def fetch_one(self, n, uid, items, msgs):
        body, flags = msgs[n - 1]
        parts = []
        for it in items:
            if it == "UID":
                parts.append(b"UID %d" % uid)
            elif it == "FLAGS":
                parts.append(("FLAGS (%s)" % " ".join(flags)).encode())
            elif it == "RFC822.SIZE":
                parts.append(b"RFC822.SIZE %d" % len(body))
            elif it == "INTERNALDATE":
                parts.append(b'INTERNALDATE "14-Nov-2026 10:00:00 +0000"')
            elif it == "ENVELOPE":
                parts.append(b"ENVELOPE " + IMAP_ENVELOPES[min(n, 2) - 1].encode())
            elif it in ("BODYSTRUCTURE", "BODY"):
                parts.append(it.encode() + b' ("TEXT" "PLAIN" ("CHARSET" "UTF-8") NIL NIL "7BIT" %d %d NIL NIL NIL NIL)'
                             % (len(body), body.count(b"\r\n")))
            elif it.startswith("BODY[") or it.startswith("BODY.PEEK["):
                sec = it[it.index("["):]
                data = body.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n" if sec == "[HEADER]" else body
                parts.append(b"BODY" + sec.encode() + b" {%d}\r\n" % len(data) + data)
                if not it.startswith("BODY.PEEK") and "\\Seen" not in flags:
                    flags.append("\\Seen")
        return b"* %d FETCH (" % n + b" ".join(parts) + b")"

    def session(self, o, got):
        greeting = o.get("greeting")
        if greeting == "bye":
            self.out("* BYE too busy, try later")
            return
        if greeting == "preauth":
            self.out("* PREAUTH [CAPABILITY %s] logged in already" % self.caps(o, False, True))
        elif o.get("no_caps_code"):
            self.out("* OK IMAP fake ready")
        else:
            self.out("* OK [CAPABILITY %s] IMAP fake ready" % self.caps(o, bool(o.get("implicit")), False))
        tls = bool(o.get("implicit"))
        authed = greeting == "preauth"
        utf8 = rev2 = False
        selected = False
        msgs = [[m, list(f)] for m, f in zip(IMAP_MSGS, [["\\Seen"], []])]
        uids = [1, 2]
        password = o.get("password", PASSWORD)
        while True:
            toks = self.command(got)
            if len(toks) < 2:
                self.out("* BAD what")
                continue
            tag, verb = toks[0], toks[1].upper()
            args = toks[2:]
            if verb == "UID" and args:
                verb, args = "UID " + args[0].upper(), args[1:]
            got.setdefault("cmds", []).append(verb)

            def ok(text="done", code=None):
                self.out("%s OK %s%s" % (tag, "[%s] " % code if code else "", text))

            if verb == "CAPABILITY":
                self.out("* CAPABILITY " + self.caps(o, tls, authed))
                ok()
            elif verb == "STARTTLS":
                if o.get("inject"):
                    self.wfile.write(("%s OK begin TLS\r\n* OK injected\r\n" % tag).encode())
                    self.wfile.flush()
                else:
                    ok("begin TLS")
                self.request = o["ctx"].wrap_socket(self.request, server_side=True)
                self.rfile = self.request.makefile("rb")
                self.wfile = self.request.makefile("wb")
                tls = True
                got["tls"] = True
            elif verb == "LOGIN":
                user = args[0] if isinstance(args[0], str) else args[0].decode()
                pw = args[1] if isinstance(args[1], str) else args[1].decode()
                if user == USER and pw == password:
                    authed = True
                    got["auth"] = "LOGIN"
                    ok("logged in", None if o.get("no_caps_code") else "CAPABILITY " + self.caps(o, tls, True))
                else:
                    self.out("%s NO [AUTHENTICATIONFAILED] bad password" % tag)
            elif verb == "AUTHENTICATE":
                mech = args[0].upper()
                initial = None
                if len(args) > 1:
                    initial = "" if args[1] == "=" else base64.b64decode(args[1]).decode()
                    got["sasl_ir"] = True

                def read_resp():
                    r = self.line()
                    if r == "*":
                        raise EOFError
                    return base64.b64decode(r).decode()

                def send_challenge(s):
                    self.out("+ " + base64.b64encode(s.encode()).decode())

                try:
                    good = sasl_server(mech, initial, read_resp, send_challenge, o.get("scram_wrong"))
                except EOFError:
                    self.out("%s BAD cancelled" % tag)
                    got["auth_cancelled"] = True
                    continue
                if good:
                    authed = True
                    got["auth"] = mech
                    ok("logged in")
                else:
                    self.out("%s NO [AUTHENTICATIONFAILED] no" % tag)
            elif verb == "LOGOUT":
                self.out("* BYE see you")
                ok()
                return
            elif verb == "NOOP" and o.get("bye_on_noop"):
                self.out("* BYE shutting down")
                return
            elif verb == "NOOP":
                self.out("* 3 EXISTS")
                self.out("* 1 RECENT")
                ok()
            elif not authed:
                self.out("%s NO log in first" % tag)
            elif verb == "ID":
                got["id"] = args[0]
                self.out('* ID ("name" "fake")')
                ok()
            elif verb == "ENABLE":
                if "UTF8=ACCEPT" in [a.upper() for a in args]:
                    utf8 = True
                    self.out("* ENABLED UTF8=ACCEPT")
                if o.get("rev2") and "IMAP4REV2" in [a.upper() for a in args]:
                    utf8 = rev2 = True
                    self.out("* ENABLED IMAP4rev2")
                ok()
            elif verb in ("LIST", "LSUB"):
                name = '"Entwürfe"' if utf8 else '"Entw&APw-rfe"'
                self.out('* %s (\\HasNoChildren) "/" INBOX' % verb)
                self.out('* %s (\\HasNoChildren \\Drafts) "/" %s' % (verb, name))
                self.out('* %s (\\Noselect) "/" {7}\r\na "b" c' % verb)
                ok()
            elif verb in ("SELECT", "EXAMINE"):
                got["selected"] = args[0]
                if args[0] != "INBOX":
                    self.out("%s NO [NONEXISTENT] no such mailbox" % tag)
                    continue
                selected = True
                self.out("* %d EXISTS" % len(msgs))
                self.out("* 0 RECENT")
                self.out("* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")
                self.out("* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited")
                self.out("* OK [UIDVALIDITY 42] UIDs valid")
                self.out("* OK [UIDNEXT %d] Predicted next UID" % (max(uids) + 1))
                ok("%s completed" % verb, "READ-WRITE" if verb == "SELECT" else "READ-ONLY")
            elif verb == "STATUS":
                self.out('* STATUS "%s" (MESSAGES %d UIDNEXT %d UIDVALIDITY 42 UNSEEN 1)' % (args[0], len(msgs), max(uids) + 1))
                ok()
            elif verb in ("CREATE", "DELETE", "SUBSCRIBE", "UNSUBSCRIBE", "RENAME"):
                got.setdefault("names", []).append([a if isinstance(a, str) else a.decode() for a in args])
                ok()
            elif verb == "APPEND":
                got["append"] = args[-1]
                got["append_flags"] = [a for a in args[1:-1] if isinstance(a, str)]
                ok("appended", "APPENDUID 42 %d" % (max(uids) + 1))
            elif not selected:
                self.out("%s BAD select a mailbox first" % tag)
            elif verb in ("FETCH", "UID FETCH"):
                if o.get("huge_literal"):
                    self.out("* 1 FETCH (BODY[] {99999999999}")
                    time.sleep(2)
                    return
                if o.get("malformed"):
                    self.out("* 1 FETCH (UID 1 FLAGS (\\Seen)")
                    ok()
                    continue
                self.out("* OK [ALERT] an untagged response before the data")
                if verb == "UID FETCH":
                    want = [uids.index(u) + 1 for u in imap_set(args[0], max(uids)) if u in uids]
                else:
                    want = [n for n in imap_set(args[0], len(msgs)) if 1 <= n <= len(msgs)]
                items = imap_items(args[1])
                if verb == "UID FETCH" and "UID" not in items:
                    items.insert(0, "UID")
                for n in want:
                    self.out(self.fetch_one(n, uids[n - 1], items, msgs))
                    if n == 1:
                        self.out("* 2 EXISTS")
                if o.get("wrong_tag"):
                    self.out("X999 OK FETCH completed")
                else:
                    ok("FETCH completed")
            elif verb in ("SEARCH", "UID SEARCH"):
                got["search"] = " ".join(a if isinstance(a, str) else "<lit>" for a in args)
                hits = [n for n in range(1, len(msgs) + 1) if args[0].upper() != "UNSEEN" or "\\Seen" not in msgs[n - 1][1]]
                if verb == "UID SEARCH":
                    hits = [uids[n - 1] for n in hits]
                if rev2:
                    # IMAP4rev2 answers SEARCH with ESEARCH.
                    self.out('* ESEARCH (TAG "%s")%s ALL %s' % (tag, " UID" if verb.startswith("UID") else "",
                                                                ",".join(str(h) for h in hits)))
                else:
                    self.out("* SEARCH" + "".join(" %d" % h for h in hits))
                ok()
            elif verb in ("STORE", "UID STORE"):
                how = args[1].upper()
                flags = args[2].strip("()").split()
                for n in imap_set(args[0], len(msgs)):
                    f = msgs[n - 1][1]
                    if how.startswith("+"):
                        f += [x for x in flags if x not in f]
                    elif how.startswith("-"):
                        f[:] = [x for x in f if x not in flags]
                    else:
                        f[:] = flags
                    if not how.endswith(".SILENT"):
                        self.out("* %d FETCH (FLAGS (%s))" % (n, " ".join(f)))
                ok()
            elif verb in ("COPY", "MOVE", "UID COPY", "UID MOVE"):
                got.setdefault("copied", []).append((verb, args[0], args[1] if isinstance(args[1], str) else args[1].decode()))
                code = "COPYUID 77 %s 100" % args[0]
                if verb.endswith("MOVE"):
                    self.out("* OK [%s] moved" % code)
                    self.out("* %s EXPUNGE" % args[0])
                    del msgs[int(args[0]) - 1]
                    del uids[int(args[0]) - 1]
                    ok("moved")
                else:
                    ok("copied", code)
            elif verb in ("EXPUNGE", "UID EXPUNGE"):
                gone = [i + 1 for i, m in enumerate(msgs) if "\\Deleted" in m[1]]
                for k, n in enumerate(gone):
                    self.out("* %d EXPUNGE" % (n - k))
                    del msgs[n - k - 1]
                    del uids[n - k - 1]
                ok()
            elif verb == "IDLE":
                self.out("+ idling")
                time.sleep(0.3)
                self.out("* 3 EXISTS")
                done = self.line()
                got["idle_done"] = done
                ok("IDLE terminated")
            elif verb in ("CLOSE", "UNSELECT"):
                selected = False
                ok()
            else:
                self.out("%s BAD unknown command" % tag)


def imap_cases(ctx):
    def case(name, o, args, cmds, want_rc=0, want_out=(), check=None, password=PASSWORD, user=USER):
        if not wanted("imap " + name):
            return
        o.setdefault("ctx", ctx)
        srv = serve(Imap, o)
        try:
            rc, out = run_tool(["imap", "--port", str(srv.server_address[1])] + args + ["127.0.0.1"] + cmds,
                               user, password, timeout=20)
            time.sleep(0.05)
            missing = [w for w in want_out if w not in out]
            ok = rc == want_rc and not missing
            detail = "rc %d, missing %r: %s" % (rc, missing, out.strip().replace("\n", " | ")[-1200:])
            if ok and check:
                why = check(srv.got)
                if why:
                    ok, detail = False, why
            if password and password in out:
                ok, detail = False, "the password was printed"
            report("imap " + name, ok, detail)
            if os.environ.get("SHOW"):
                print("      " + out.strip().replace("\n", " | "))
        finally:
            srv.shutdown()
            srv.server_close()

    plain = ["--tls", "none", "--auth", "user"]
    tls = ["--tls", "mandatory", "--insecure"]
    m0, m1 = IMAP_MSGS
    case("LOGIN, the mailbox", {}, plain,
         ["capa", "list", "select", "INBOX", "fetch", "1:*",
          "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE BODY.PEEK[])", "search", "UNSEEN",
          "status", "INBOX", "noop"],
         want_out=["capability: IMAP4REV1", "authenticated",
                   'list: (\\HasNoChildren \\Drafts) "/" "Entwürfe"', 'list: (\\Noselect) "/" "a "b" c"',
                   "selected: INBOX exists 2 uidvalidity 42 uidnext 3 readonly false",
                   "fetch: 1 uid 1 size %d flags (\\Seen) date \"14-Nov-2026 10:00:00 +0000\"" % len(m0),
                   'envelope: date "Sat, 14 Nov 2026 10:00:00 +0000" subject "say "hi""',
                   "envelope: from \"Alice\" <a@example.com>; to <bob@example.com>",
                   'envelope: date "Sat, 14 Nov 2026 11:00:00 +0000" subject "Grüße"',
                   "part: 1 text/plain size %d" % len(m0), "body: BODY[] %d bytes" % len(m0),
                   ") with a paren and a {5}", "body: BODY[] %d bytes" % len(m1),
                   "search: 2", "status: INBOX messages 2 uidnext 3 uidvalidity 42 unseen 1",
                   "noop: exists 3", "logout"],
         check=lambda g: None if g.get("auth") == "LOGIN" and "LOGOUT" in g.get("cmds", []) else "server saw %r" % g)
    case("UID FETCH, the header", {}, plain, ["examine", "INBOX", "uid-fetch", "2", "BODY.PEEK[HEADER]", "uid-search", "ALL"],
         want_out=["readonly true", "fetch: 2 uid 2", "body: BODY[HEADER] %d bytes" % (m1.index(b"\r\n\r\n") + 4),
                   "uid-search: 1 2"])
    case("STORE, COPY, MOVE, EXPUNGE", {}, plain,
         ["select", "INBOX", "store", "1", "+FLAGS", "\\Deleted", "copy", "1", "Sent", "move", "2", "Archive",
          "expunge"],
         want_out=["store: 1 flags (\\Seen \\Deleted)", "copy: 1 Sent [COPYUID 77 1 100]", "move: 2 Archive",
                   "expunged: 1 exists 0"],
         check=lambda g: None if g.get("copied") == [("COPY", "1", "Sent"), ("MOVE", "2", "Archive")] else "copied %r" % g.get("copied"))
    msgfile = os.path.join(tempfile.mkdtemp(), "append.eml")
    with open(msgfile, "wb") as f:
        f.write(APPEND_MSG)
    case("APPEND, a synchronizing literal", {}, plain, ["append", "Drafts", msgfile, "\\Seen \\Draft"],
         want_out=["append: %d bytes [APPENDUID 42 3]" % len(APPEND_MSG)],
         check=lambda g: None if g.get("append") == APPEND_MSG and g.get("literals") == [(len(APPEND_MSG), False)]
         and g.get("append_flags") == ["(\\Seen \\Draft)"] else "server saw %r %r" % (g.get("append"), g.get("literals")))
    case("APPEND with LITERAL+", {"literal_plus": True}, plain, ["append", "Drafts", msgfile],
         want_out=["append: %d bytes" % len(APPEND_MSG)],
         check=lambda g: None if g.get("append") == APPEND_MSG and g.get("literals") == [(len(APPEND_MSG), True)]
         else "literals %r" % g.get("literals"))
    case("LOGIN, an 8-bit password as a literal", {"password": "pässwörd ok"}, plain, ["noop"], password="pässwörd ok",
         want_out=["authenticated"],
         check=lambda g: None if g.get("literals") == [(len("pässwörd ok".encode()), False)] else "literals %r" % g.get("literals"))
    case("mailbox names in modified UTF-7", {}, plain, ["create", "Entwürfe/日本語", "rename", "Entwürfe", "a b", "delete", "a b"],
         want_out=["create: Entwürfe/日本語", "rename: Entwürfe a b"],
         check=lambda g: None if g.get("names") == [["Entw&APw-rfe/&ZeVnLIqe-"], ["Entw&APw-rfe", "a b"], ["a b"]]
         else "names %r" % g.get("names"))
    case("ID, ENABLE UTF8=ACCEPT, then UTF-8 names", {}, plain,
         ["id", "enable", "UTF8=ACCEPT", "list", "create", "Entwürfe"],
         want_out=['id: ("name" "fake")', "enabled: utf8 true", 'list: (\\HasNoChildren \\Drafts) "/" "Entwürfe"'],
         check=lambda g: None if g.get("names") == [["Entwürfe"]] and "goose-mail" in g.get("id", "")
         else "names %r id %r" % (g.get("names"), g.get("id")))
    case("IDLE", {}, plain, ["select", "INBOX", "idle", "1"],
         want_out=["idle: started", "idle: * 3 EXISTS", "idle: done, exists 3"],
         check=lambda g: None if g.get("idle_done") == "DONE" else "idle ended with %r" % g.get("idle_done"))
    case("IMAP4rev2: ENABLE, ESEARCH, UTF-8 names", {"rev2": True}, plain,
         ["enable", "IMAP4rev2", "list", "select", "INBOX", "search", "ALL", "uid-search", "ALL", "create", "Entwürfe"],
         want_out=["enabled: utf8 true rev2 true", 'list: (\\HasNoChildren \\Drafts) "/" "Entwürfe"', "search: 1 2",
                   "uid-search: 1 2"],
         check=lambda g: None if g.get("names") == [["Entwürfe"]] else "names %r" % g.get("names"))
    case("no CAPABILITY in the greeting or the login", {"no_caps_code": True}, plain, ["capa"],
         want_out=["authenticated", "capability: IMAP4REV1 IDLE"],
         check=lambda g: None if g.get("cmds", []).count("CAPABILITY") == 2 else "cmds %r" % g.get("cmds"))
    case("CLOSE and UNSELECT", {}, plain, ["select", "INBOX", "close", "select", "INBOX", "unselect"],
         want_out=["close: ok", "unselect: ok"])
    case("SELECT refused", {}, plain, ["select", "Nowhere"], want_rc=1,
         want_out=["select: refused: [NONEXISTENT] no such mailbox"])
    case("CR LF in an argument refused", {}, plain, ["select", "INBOX\r\nA9 DELETE INBOX"], want_rc=1,
         want_out=["a command argument contains CR, LF or NUL"],
         check=lambda g: None if "DELETE" not in g.get("cmds", []) and "SELECT" not in g.get("cmds", []) else "sent: %r" % g.get("cmds"))
    case("wrong password", {}, plain, ["noop"], password="not it", want_rc=1,
         want_out=["auth: refused: [AUTHENTICATIONFAILED] bad password"])
    case("LOGINDISABLED", {"logindisabled": True}, plain, ["noop"], want_rc=1, want_out=["auth: mail: not supported"],
         check=lambda g: None if "LOGIN" not in g.get("cmds", []) else "LOGIN was sent")
    case("greeting BYE", {"greeting": "bye"}, plain, ["noop"], want_rc=1, want_out=["connect: refused: too busy"])
    case("PREAUTH", {"greeting": "preauth"}, ["--tls", "none"], ["select", "INBOX"],
         want_out=["connected, PREAUTH", "selected: INBOX exists 2"],
         check=lambda g: None if g.get("auth") is None else "authenticated after PREAUTH")
    case("BYE in the middle", {"bye_on_noop": True}, plain, ["noop"], want_rc=1, want_out=["noop: refused: shutting down"])
    case("oversized literal refused", {"huge_literal": True}, plain, ["select", "INBOX", "fetch", "1", "BODY[]"],
         want_rc=1, want_out=["fetch: mail: malformed server reply"])
    case("malformed FETCH", {"malformed": True}, plain, ["select", "INBOX", "fetch", "1", "(UID FLAGS)"], want_rc=1,
         want_out=["fetch: mail: malformed server reply"])
    case("a completion with another tag", {"wrong_tag": True}, plain, ["select", "INBOX", "fetch", "1", "FLAGS"],
         want_rc=1, want_out=["fetch: mail: malformed server reply"])
    case("STARTTLS", {"starttls": True}, tls + ["--auth", "user"], ["noop"],
         want_out=["connected (TLS)", "authenticated", "logout"], check=lambda g: None if g.get("tls") else "no TLS")
    case("STARTTLS required, not offered", {}, tls + ["--auth", "user"], ["noop"], want_rc=1,
         want_out=["does not offer TLS"])
    case("certificate checked", {"starttls": True}, ["--tls", "mandatory", "--auth", "user"], ["noop"], want_rc=1,
         want_out=["TLS failed"])
    case("STARTTLS injection refused", {"starttls": True, "inject": True}, tls + ["--auth", "user"], ["noop"],
         want_rc=1, want_out=["connect: mail: malformed server reply"])
    case("implicit TLS", {"implicit": True}, ["--tls", "implicit", "--insecure", "--auth", "user"], ["noop"],
         want_out=["connected (TLS)", "authenticated", "logout"])
    for mech in ["PLAIN", "LOGIN", "CRAM-MD5", "SCRAM-SHA-1", "SCRAM-SHA-256"]:
        for ir in (False, True):
            label = "AUTHENTICATE " + mech + (" with SASL-IR" if ir else "")
            case(label, {"starttls": True, "auth": [mech], "sasl_ir": ir}, tls + ["--auth", mech.lower()], ["noop"],
                 want_out=["authenticated", "logout"],
                 check=lambda g, m=mech, ir=ir: None if g.get("auth") == m and
                 bool(g.get("sasl_ir")) == (ir and m not in ("LOGIN", "CRAM-MD5")) else "server saw %r" % g)
        case("AUTHENTICATE " + mech + " wrong password", {"starttls": True, "auth": [mech], "sasl_ir": True},
             tls + ["--auth", mech.lower()], ["noop"], password="not it", want_rc=1,
             want_out=["auth: refused: [AUTHENTICATIONFAILED]"])
    case("AUTHENTICATE auto picks SCRAM-SHA-256", {"starttls": True, "auth": ["PLAIN", "SCRAM-SHA-256", "CRAM-MD5"]},
         tls + ["--auth", "auto"], ["noop"], want_out=["authenticated"],
         check=lambda g: None if g.get("auth") == "SCRAM-SHA-256" else "server saw %r" % g.get("auth"))
    case("AUTHENTICATE when unset and offered", {"starttls": True, "auth": ["CRAM-MD5"]}, tls, ["noop"],
         want_out=["authenticated"], check=lambda g: None if g.get("auth") == "CRAM-MD5" else "server saw %r" % g.get("auth"))
    case("SCRAM server without the password", {"starttls": True, "auth": ["SCRAM-SHA-256"], "scram_wrong": True},
         tls + ["--auth", "scram-sha-256"], ["noop"], want_rc=1, want_out=["the server did not prove itself"],
         check=lambda g: None if g.get("auth_cancelled") else "the exchange was not cancelled")


# --- mailpit and dovecot -------------------------------------------------------------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def mailpit_cases(tmp, cert, key):
    mp = shutil.which("mailpit")
    if not mp:
        skipped.append("mailpit (brew install mailpit)")
        return
    smtp_port, pop_port, http_port = free_port(), free_port(), free_port()
    auth_file = os.path.join(tmp, "mailpit-auth")
    # htpasswd's form: mailpit takes hashes, not passwords.
    htpasswd = shutil.which("htpasswd")
    if not htpasswd:
        skipped.append("mailpit: needs htpasswd for its password file")
        return
    with open(auth_file, "w") as f:
        f.write(subprocess.run([htpasswd, "-nbB", USER, PASSWORD], capture_output=True, text=True,
                               check=True).stdout.strip() + "\n")
    log = open(os.path.join(tmp, "mailpit.log"), "w")
    p = subprocess.Popen([mp, "--smtp", "127.0.0.1:%d" % smtp_port, "--listen", "127.0.0.1:%d" % http_port,
                          "--pop3", "127.0.0.1:%d" % pop_port, "--pop3-auth-file", auth_file,
                          "--smtp-auth-file", auth_file, "--smtp-tls-cert", cert, "--smtp-tls-key", key,
                          "--pop3-tls-cert", cert, "--pop3-tls-key", key, "--database", os.path.join(tmp, "mp.db")],
                         stdout=log, stderr=subprocess.STDOUT)
    try:
        if not (wait_port(smtp_port) and wait_port(pop_port)):
            report("mailpit started", False, open(log.name).read()[-2000:])
            return
        msgfile = os.path.join(tmp, "mp.eml")
        with open(msgfile, "wb") as f:
            f.write(MESSAGE)
        # mailpit offers PLAIN and LOGIN (no CRAM-MD5 or SCRAM).
        for mech in ["plain", "login", "auto"]:
            name = "mailpit smtp STARTTLS AUTH " + mech
            if not wanted(name):
                continue
            rc, out = run_tool(["smtp", "--port", str(smtp_port), "--tls", "mandatory", "--insecure", "--auth", mech,
                                "127.0.0.1", msgfile, "alice@example.com", "bob@example.com"])
            report(name, rc == 0 and "sent: 250" in out, out.strip().replace("\n", " | "))
        name = "mailpit smtp a message from mail.message"
        if wanted(name):
            rc, out = run_tool(["smtp", "--port", str(smtp_port), "--tls", "mandatory", "--insecure", "--auth", "auto",
                                "127.0.0.1", "-", "alice@example.com", "bob@example.com"])
            report(name, rc == 0 and "sent: 250" in out, out.strip().replace("\n", " | "))
        if wanted("mailpit pop3"):
            rc, out = run_tool(["pop3", "--port", str(pop_port), "--tls", "implicit", "--insecure", "--auth", "user",
                                "127.0.0.1", "stat", "list", "uidl", "retr", "1", "retr", "2", "retr", "3", "retr", "4"])
            report("mailpit pop3 TLS, the messages sent", rc == 0 and "stat: " in out and "Subject: interop" in out
                   and ".a line that starts with a dot" in out and "uidl: " in out and "stat: 4 " in out
                   and "\n.a dotted line" in out and "AAECYmluYXJ5/w==" in out, out.strip().replace("\n", " | ")[-600:])
    finally:
        p.terminate()
        p.wait()
        log.close()


DOVECOT_CONF = """dovecot_config_version = 2.4.5
dovecot_storage_version = 2.4.5
base_dir = {d}/run
state_dir = {d}/state
log_path = {d}/dovecot.log
protocols = pop3 imap
listen = 127.0.0.1
default_internal_user = {user}
default_internal_group = {group}
default_login_user = {user}
default_vsz_limit = 1T
auth_mechanisms = plain login cram-md5 scram-sha-1 scram-sha-256 apop
auth_allow_cleartext = yes
ssl = yes
ssl_server_cert_file = {cert}
ssl_server_key_file = {key}
mail_driver = maildir
mail_path = {d}/mail/%{{user}}
mail_home = {d}/mail/%{{user}}
passdb passwd-file {{
  passwd_file_path = {d}/users
}}
userdb static {{
  fields {{
    uid = {user}
    gid = {group}
    home = {d}/mail/%{{user}}
  }}
}}
service pop3-login {{
  chroot =
  inet_listener pop3 {{
    port = {pop}
  }}
  inet_listener pop3s {{
    port = {pops}
    ssl = yes
  }}
}}
service imap-login {{
  chroot =
  inet_listener imap {{
    port = {imap}
  }}
  inet_listener imaps {{
    port = {imaps}
    ssl = yes
  }}
}}
"""


def dovecot_cases(tmp, cert, key):
    dv = shutil.which("dovecot") or next((p for p in ["/opt/homebrew/sbin/dovecot", "/usr/local/sbin/dovecot",
                                                      "/usr/sbin/dovecot"] if os.path.exists(p)), None)
    if not dv:
        skipped.append("dovecot (brew install dovecot)")
        return
    import grp
    import pwd
    # Run as this user, everything under one short directory: dovecot's
    # sockets live there, and a socket's path has ~104 bytes at most. A
    # memory limit of 1T: macOS refuses a setrlimit(RLIMIT_DATA) as low as
    # dovecot's 256M (and 16G), and dovecot's "unlimited" is over the hard limit.
    d = tempfile.mkdtemp(prefix="dv")
    pop, pops = free_port(), free_port()
    imap, imaps = free_port(), free_port()
    user = pwd.getpwuid(os.getuid()).pw_name
    group = grp.getgrgid(os.getgid()).gr_name
    conf = os.path.join(d, "dovecot.conf")
    with open(conf, "w") as f:
        f.write(DOVECOT_CONF.format(d=d, user=user, group=group, cert=cert, key=key, pop=pop, pops=pops,
                                    imap=imap, imaps=imaps))
    with open(os.path.join(d, "users"), "w") as f:
        f.write("%s:{PLAIN}%s\n" % (USER, PASSWORD))     # PLAIN: CRAM-MD5, SCRAM and APOP need it

    def fill():
        # A fresh mailbox: the POP3 messages, with their dots, in maildir's new/.
        box = os.path.join(d, "mail", USER)
        shutil.rmtree(box, ignore_errors=True)
        for sub in ("new", "cur", "tmp"):
            os.makedirs(os.path.join(box, sub))
        for i, m in enumerate(POP_MSGS):
            with open(os.path.join(box, "new", "%d.goose%d" % (1000 + i, i)), "wb") as f:
                f.write(m.replace(b"\r\n", b"\n"))

    fill()
    failed_before = results["failed"]
    p = subprocess.Popen([dv, "-F", "-c", conf], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        if not (wait_port(pop) and wait_port(pops) and wait_port(imap) and wait_port(imaps)):
            log = os.path.join(d, "dovecot.log")
            report("dovecot started", False, open(log).read()[-2000:] if os.path.exists(log) else "no log")
            return

        def case(name, args, cmds, want_rc=0, want_out=(), password=PASSWORD, port=pop):
            if not wanted("dovecot " + name):
                return
            rc, out = run_tool(["pop3", "--port", str(port)] + args + ["127.0.0.1"] + cmds, USER, password)
            missing = [w for w in want_out if w not in out]
            ok = (want_rc is None or rc == want_rc) and not missing and not (password and password in out)
            report("dovecot " + name, ok, "rc %d, missing %r: %s" % (rc, missing, out.strip().replace("\n", " | ")[-800:]))

        # Over TLS, dovecot 2.4.5 on macOS drops the session as its login
        # process hands it to the pop3 process (OpenSSL's s_client sees the
        # same), so TLS is tested up to the login, which the login process
        # does itself: want_rc None, the commands after it not counted on.
        # The mailbox is tested without TLS, on localhost.
        sizes = [len(m) for m in POP_MSGS]
        tls = ["--tls", "mandatory", "--insecure"]
        case("STLS", tls + ["--auth", "user"], ["capa"], want_rc=None, want_out=["connected (TLS)", "authenticated"])
        case("implicit TLS", ["--tls", "implicit", "--insecure", "--auth", "user"], ["capa"], port=pops, want_rc=None,
             want_out=["connected (TLS)", "authenticated"])
        case("certificate checked", ["--tls", "mandatory", "--auth", "user"], ["stat"], want_rc=1,
             want_out=["TLS failed"])
        case("TLS APOP", tls + ["--auth", "apop"], ["capa"], want_rc=None, want_out=["authenticated"])
        for mech in ["plain", "login", "cram-md5", "scram-sha-1", "scram-sha-256", "auto"]:
            case("TLS AUTH " + mech, tls + ["--auth", mech], ["capa"], want_rc=None, want_out=["authenticated"])
        case("TLS wrong password", tls + ["--auth", "scram-sha-256"], ["stat"], password="not it", want_rc=1,
             want_out=["auth: refused"])
        plain = ["--tls", "none"]
        case("USER/PASS, the mailbox", plain + ["--auth", "user"],
             ["stat", "list", "uidl", "retr", "1", "top", "2", "1"],
             want_out=["stat: 2 %d" % sum(sizes), "list: 1 %d" % sizes[0],
                       "retr: 1 %d bytes" % sizes[0], "\n.dotted\n", "top: 2", "second body", "quit"])
        for mech in ["apop", "cram-md5", "scram-sha-1", "scram-sha-256"]:
            case("AUTH " + mech + ", then STAT", plain + ["--auth", mech], ["stat"],
                 want_out=["authenticated", "stat: 2", "quit"])
        case("DELE then QUIT", plain + ["--auth", "user"], ["dele", "1"], want_out=["dele: 1", "quit"])
        case("deleted for good", plain + ["--auth", "scram-sha-256"], ["stat"], want_out=["stat: 1 %d" % sizes[1]])

        # IMAP, on a fresh mailbox. Over TLS, as for POP3, only up to the
        # login: dovecot drops the session when imap-login hands it to imap.
        fill()

        def icase(name, args, cmds, want_rc=0, want_out=(), password=PASSWORD, port=imap):
            if not wanted("dovecot imap " + name):
                return
            rc, out = run_tool(["imap", "--port", str(port)] + args + ["127.0.0.1"] + cmds, USER, password)
            missing = [w for w in want_out if w not in out]
            ok = (want_rc is None or rc == want_rc) and not missing and not (password and password in out)
            report("dovecot imap " + name, ok,
                   "rc %d, missing %r: %s" % (rc, missing, out.strip().replace("\n", " | ")[-1200:]))
            if os.environ.get("SHOW"):
                print("      " + out.strip().replace("\n", " | "))

        icase("STARTTLS, LOGIN", tls + ["--auth", "user"], ["capa"], want_rc=None,
              want_out=["connected (TLS)", "authenticated"])
        icase("implicit TLS", ["--tls", "implicit", "--insecure", "--auth", "user"], ["capa"], port=imaps,
              want_rc=None, want_out=["connected (TLS)", "authenticated"])
        icase("certificate checked", ["--tls", "mandatory", "--auth", "user"], ["capa"], want_rc=1,
              want_out=["TLS failed"])
        for mech in ["plain", "login", "cram-md5", "scram-sha-1", "scram-sha-256", "auto"]:
            icase("TLS AUTHENTICATE " + mech, tls + ["--auth", mech], ["capa"], want_rc=None,
                  want_out=["authenticated"])
        icase("TLS wrong password", tls + ["--auth", "scram-sha-256"], ["capa"], password="not it", want_rc=1,
              want_out=["auth: refused"])
        iplain = ["--tls", "none"]
        icase("LOGIN, the mailbox", iplain + ["--auth", "user"],
              ["capa", "id", "list", "select", "INBOX", "fetch", "1:*",
               "(UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODYSTRUCTURE BODY.PEEK[])",
               "search", "ALL", "uid-search", "UNSEEN", "search", "RETURN (ALL) ALL", "status", "INBOX", "noop"],
              want_out=["capability: IMAP4REV1", 'id: ("name" "Dovecot"', 'list: (\\HasNoChildren) "." "INBOX"',
                        "selected: INBOX exists 2", "fetch: 1 uid 1 size %d" % sizes[0], "fetch: 2 uid 2 size %d" % sizes[1],
                        'subject "one"', "envelope: from <a@example.com>", "part: 1 text/plain size",
                        "body: BODY[] %d bytes" % sizes[0], "\n.dotted\n", "search: 1 2", "uid-search: 1 2",
                        "status: INBOX messages 2", "logout"])
        for mech in ["plain", "cram-md5", "scram-sha-1", "scram-sha-256"]:
            icase("AUTHENTICATE " + mech + ", then SELECT", iplain + ["--auth", mech], ["examine", "INBOX"],
                  want_out=["authenticated", "selected: INBOX exists 2", "readonly true", "logout"])
        icase("mailboxes: CREATE, RENAME, LIST, STATUS, DELETE", iplain + ["--auth", "user"],
              ["create", "Entwürfe", "create", "日本語 x", "subscribe", "日本語 x", "list", "lsub",
               "rename", "Entwürfe", "Brouillons", "status", "Brouillons", "delete", "Brouillons", "list"],
              want_out=['list: (\\HasNoChildren) "." "Entwürfe"', 'list: (\\HasNoChildren) "." "日本語 x"',
                        'lsub: () "." "日本語 x"', "rename: Entwürfe Brouillons", "status: Brouillons messages 0",
                        "delete: Brouillons", "logout"])
        appended = os.path.join(d, "append.eml")
        with open(appended, "wb") as f:
            f.write(APPEND_MSG)
        icase("APPEND, then FETCH it", iplain + ["--auth", "user"],
              ["append", "INBOX", appended, "\\Seen", "select", "INBOX", "fetch", "3", "(UID RFC822.SIZE FLAGS BODY.PEEK[])"],
              want_out=["append: %d bytes [APPENDUID " % len(APPEND_MSG), "selected: INBOX exists 3",
                        "fetch: 3 uid 3 size %d flags (\\Seen" % len(APPEND_MSG), "body: BODY[] %d bytes" % len(APPEND_MSG),
                        "appended body"])
        icase("STORE, COPY, MOVE, EXPUNGE", iplain + ["--auth", "user"],
              ["create", "Archive", "select", "INBOX", "store", "1", "+FLAGS", "\\Flagged", "copy", "1", "Archive",
               "move", "3", "Archive", "store", "1", "+FLAGS.SILENT", "\\Deleted", "expunge", "status", "Archive"],
              want_out=["store: 1 flags (\\Flagged", "copy: 1 Archive [COPYUID", "move: 3 Archive",
                        "expunged: 1 exists 1", "status: Archive messages 2"])
        icase("UID FETCH, UID STORE, UID EXPUNGE", iplain + ["--auth", "user"],
              ["select", "Archive", "uid-fetch", "1:*", "(FLAGS BODY.PEEK[HEADER])", "uid-store", "2", "+FLAGS",
               "\\Deleted", "uid-expunge", "2", "uid-search", "ALL"],
              want_out=["fetch: 1 uid 1", "body: BODY[HEADER]", "Subject: one", "uid-store: ok", "expunged: 2 exists 1",
                        "uid-search: 1"])
        icase("IDLE", iplain + ["--auth", "user"], ["select", "INBOX", "idle", "1", "close"],
              want_out=["idle: started", "idle: done", "close: ok", "logout"])
        # This dovecot has neither UTF8=ACCEPT nor IMAP4rev2: names go in modified UTF-7.
        icase("ENABLE CONDSTORE, non-ASCII names", iplain + ["--auth", "user"],
              ["enable", "CONDSTORE", "create", "Ünïcødé", "list", "Ü*", "delete", "Ünïcødé"],
              want_out=["enabled: utf8 false", 'list: (\\HasNoChildren) "." "Ünïcødé"', "logout"])
        icase("wrong password", iplain + ["--auth", "user"], ["capa"], password="not it", want_rc=1,
              want_out=["auth: refused: [AUTHENTICATIONFAILED]"])
        icase("SELECT a mailbox that is not there", iplain + ["--auth", "user"], ["select", "Nowhere"], want_rc=1,
              want_out=["select: refused: [NONEXISTENT]"])
    finally:
        log = os.path.join(d, "dovecot.log")
        if results["failed"] > failed_before and os.path.exists(log):
            print("      dovecot.log:\n      " + open(log).read()[-3000:].replace("\n", "\n      "))
        p.terminate()
        p.wait()
        shutil.rmtree(d, ignore_errors=True)


# --- Main ------------------------------------------------------------------------------

def main():
    global only, TOOL
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("-k", help="only cases whose name has this")
    args = ap.parse_args()
    only = args.k
    goose = find_goose(args.goose)
    tmp = tempfile.mkdtemp()
    try:
        TOOL = os.path.join(tmp, "goose-mail")
        p = subprocess.run([goose, "build", "-o", TOOL, os.path.join(ROOT, "tools", "mail.goose")],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit(p.stdout + p.stderr)
        cert, key = os.path.join(tmp, "cert.pem"), os.path.join(tmp, "key.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-pkeyopt", "ec_param_enc:named_curve", "-nodes", "-keyout", key, "-out", cert, "-days", "2",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
                       check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        smtp_cases(ctx, tmp)
        pop3_cases(ctx)
        imap_cases(ctx)
        mailpit_cases(tmp, cert, key)
        dovecot_cases(tmp, cert, key)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for s in skipped:
        print("skip  " + s)
    print("\n%d passed, %d failed" % (results["passed"], results["failed"]))
    sys.exit(1 if results["failed"] else 0)


if __name__ == "__main__":
    main()
