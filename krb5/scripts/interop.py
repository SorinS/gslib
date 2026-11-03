#!/usr/bin/env python3
"""krb5 against MIT Kerberos: KDCs (scripts/kdc.py), kinit, kvno, klist,
gss-client and gss-server, and curl --negotiate. Everything listens on
127.0.0.1 only; MIT's gss-server runs in its inetd mode, handed
connections that this script accepts on loopback.

    python3 scripts/interop.py [--goose PATH] [--mit PREFIX] [-k NAME] [-v]

Each check prints ok or FAIL; the exit status is 1 if any failed.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))
from kdc import Kdc, SAM_ETYPES  # noqa: E402

failed = []
passed = 0
verbose = False
only = None


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def check(name, ok, detail=""):
    global passed
    if only and only not in name:
        return
    print(("ok    " if ok else "FAIL  ") + name)
    if ok:
        passed += 1
    else:
        failed.append(name)
        if detail:
            print("      " + detail.strip().replace("\n", "\n      "))


def run(k, args, stdin=None, env=None, timeout=60):
    p = subprocess.run(args, env=env or k.env, input=stdin, capture_output=True, text=True, timeout=timeout)
    if verbose:
        print("   $", " ".join(os.path.basename(a) if i == 0 else a for i, a in enumerate(args)), "->", p.returncode)
        print("   ", (p.stdout + p.stderr).strip().replace("\n", "\n    "))
    return p


def out(p):
    return p.stdout + p.stderr


def start_server(args, env):
    """A server of ours that prints "port N" first: the process and port."""
    p = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = p.stdout.readline()
    if not line.startswith("port "):
        p.kill()
        raise RuntimeError("server did not start: " + line + p.stdout.read())
    return p, int(line.split()[1])


def stop_server(p):
    if p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
    return p.stdout.read()


class InetdBridge:
    """Accepts one connection on 127.0.0.1 and runs MIT's gss-server -inetd on it."""

    def __init__(self, k, keytab, service):
        self.k = k
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.log = os.path.join(k.dir, f"gss-server-{self.port}.log")
        self.args = [k.bin("gss-server"), "-inetd", "-logfile", self.log, "-keytab", keytab, service]
        self.rc = None
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.sock.settimeout(30)
        try:
            c, _ = self.sock.accept()
        except OSError:
            return
        p = subprocess.Popen(self.args, env=self.k.env, stdin=c.fileno(), stdout=c.fileno(), stderr=subprocess.DEVNULL)
        c.close()
        try:
            self.rc = p.wait(30)
        except subprocess.TimeoutExpired:
            p.kill()
        self.sock.close()

    def output(self):
        self.thread.join(35)
        try:
            return open(self.log).read()
        except OSError:
            return ""


def tgs_tests(k, tool):
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n")
    check("kinit alice (password)", p.returncode == 0 and "alice@A.TEST" in p.stdout, out(p))
    p = run(k, [k.bin("klist")])
    check("MIT klist reads our cache", p.returncode == 0 and "krbtgt/A.TEST@A.TEST" in p.stdout, out(p))
    p = run(k, [tool, "kvno", "HTTP/svc.a.test"])
    check("kvno HTTP/svc.a.test", p.returncode == 0 and "kvno = 2" in p.stdout, out(p))
    p = run(k, [tool, "kvno", "-gss", "host@svc.a.test"])
    check("kvno host@svc.a.test (GSS name, domain_realm)", p.returncode == 0 and "host/svc.a.test@A.TEST" in p.stdout, out(p))
    p = run(k, [tool, "kvno", "HTTP/web.b.test@B.TEST"])
    check("kvno cross-realm A -> B", p.returncode == 0 and "HTTP/web.b.test@B.TEST" in p.stdout, out(p))
    p = run(k, [k.bin("klist")])
    check("cross-realm TGT cached", "krbtgt/B.TEST@A.TEST" in p.stdout, out(p))
    p = run(k, [k.bin("kvno"), "HTTP/svc.a.test@A.TEST"])
    check("MIT kvno with our TGT", p.returncode == 0 and "kvno = 2" in out(p), out(p))
    p = run(k, [tool, "kvno", "HTTP/nonexistent.a.test@A.TEST"])
    check("kvno unknown service fails", p.returncode == 1 and "S_PRINCIPAL_UNKNOWN" in out(p), out(p))

    # MIT's kinit makes the cache (with its configuration entries); we use it.
    p = run(k, [k.bin("kinit"), "alice"], "alice-pw\n")
    p = run(k, [tool, "kvno", "HTTP/web.b.test@B.TEST"])
    check("our kvno with MIT's cache", p.returncode == 0, out(p))
    p = run(k, [tool, "klist"])
    check("our klist of MIT's cache", p.returncode == 0 and "krbtgt/A.TEST@A.TEST" in p.stdout, out(p))

    p = run(k, [tool, "kinit", "bob"], "bob-pw\n")
    check("kinit bob (pre-authentication required)", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "bob"], "wrong\n")
    check("kinit bob, wrong password", p.returncode == 1 and "PREAUTH_FAILED" in out(p), out(p))
    p = run(k, [tool, "kinit", "alice"], "wrong\n")
    check("kinit alice, wrong password (no pre-auth)", p.returncode == 1, out(p))
    p = run(k, [tool, "kinit", "nobody"], "x\n")
    check("kinit unknown client", p.returncode == 1 and "C_PRINCIPAL_UNKNOWN" in out(p), out(p))
    for user, et in (("carol", "arcfour-hmac"), ("dave", "des3-cbc-sha1"), ("frank", "camellia256-cts-cmac")):
        p = run(k, [tool, "kinit", user], f"{user}-pw\n")
        check(f"kinit {user} ({et} keys only)", p.returncode == 0, out(p))
        p = run(k, [k.bin("klist"), "-e"])
        check(f"{user}'s TGT reads in MIT klist", f"{user}@A.TEST" in p.stdout, out(p))
        p = run(k, [tool, "kvno", "HTTP/svc.a.test"])
        check(f"kvno as {user}", p.returncode == 0, out(p))
    # The KDC logs the AS reply's etype: frank's long-term camellia key.
    log = open(k.path("kdc.log")).read()
    check("frank's AS reply under camellia256-cts-cmac (pre-authenticated with it)",
          any("frank@A.TEST" in l and "rep=camellia256-cts-cmac(26)" in l for l in log.splitlines()), log[-2000:])
    p = run(k, [tool, "kinit", "frank"], "wrong\n")
    check("kinit frank, wrong password (camellia pre-auth refused)", p.returncode == 1 and "PREAUTH_FAILED" in out(p), out(p))
    p = run(k, [tool, "kinit", "-k", k.path("svc.keytab"), "host/svc.a.test"])
    check("kinit -k with MIT's keytab", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "erin@B.TEST"], "erin-pw\n")
    check("kinit erin@B.TEST", p.returncode == 0, out(p))
    p = run(k, [tool, "kvno", "HTTP/svc.a.test@A.TEST"])
    check("kvno cross-realm B -> A", p.returncode == 0, out(p))

    # Every encryption type of the TGS reply, through MIT's keytab.
    for et in ("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha384-192",
               "aes128-cts-hmac-sha256-128", "arcfour-hmac", "des3-cbc-sha1", "camellia256-cts-cmac",
               "camellia128-cts-cmac"):
        conf = k.path(f"krb5-{et}.conf")
        with open(k.path("krb5.conf")) as f:
            text = f.read()
        text = text.replace("[libdefaults]", f"[libdefaults]\n    default_tkt_enctypes = {et}\n    default_tgs_enctypes = {et}")
        with open(conf, "w") as f:
            f.write(text)
        env = dict(k.env, KRB5_CONFIG=conf)
        p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
        q = run(k, [tool, "kvno", "HTTP/svc.a.test"], env=env)
        r = run(k, [k.bin("klist"), "-e"], env=env)
        check(f"TGT and service ticket as {et}", p.returncode == 0 and q.returncode == 0 and f"{et}, " in r.stdout,
              out(p) + out(q) + r.stdout)
        if et.startswith("camellia"):
            # The service's camellia key from MIT's keytab: a TGT with it.
            p = run(k, [tool, "kinit", "-k", k.path("svc.keytab"), "host/svc.a.test"], env=env)
            r = run(k, [k.bin("klist"), "-e"], env=env)
            check(f"kinit -k with MIT's keytab, {et}", p.returncode == 0 and f"{et}, " in r.stdout, out(p) + r.stdout)


def transport_tests(k, tool):
    base = open(k.path("krb5.conf")).read()

    def with_conf(name, extra):
        conf = k.path(name)
        with open(conf, "w") as f:
            f.write(base.replace("[libdefaults]", "[libdefaults]\n" + extra))
        return dict(k.env, KRB5_CONFIG=conf)

    env = with_conf("krb5-tcp.conf", "    udp_preference_limit = 1")
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
    q = run(k, [tool, "kvno", "HTTP/svc.a.test"], env=env)
    check("TCP only (udp_preference_limit = 1)", p.returncode == 0 and q.returncode == 0, out(p) + out(q))
    # tcp/ and udp/ prefixes on the kdc relation.
    for proto in ("tcp", "udp"):
        conf = k.path(f"krb5-{proto}only.conf")
        with open(conf, "w") as f:
            f.write(base.replace(f"kdc = 127.0.0.1:{k.port_a}", f"kdc = {proto}/127.0.0.1:{k.port_a}"))
        env = dict(k.env, KRB5_CONFIG=conf)
        p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
        check(f"kdc = {proto}/host:port", p.returncode == 0, out(p))
    # A KDC that does not answer, then the real one.
    dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dead.bind(("127.0.0.1", 0))
    dport = dead.getsockname()[1]
    conf = k.path("krb5-dead.conf")
    with open(conf, "w") as f:
        f.write(base.replace(f"kdc = 127.0.0.1:{k.port_a}", f"kdc = 127.0.0.1:{dport}\n        kdc = 127.0.0.1:{k.port_a}")
                .replace("[libdefaults]", "[libdefaults]\n    kdc_timeout = 1"))
    env = dict(k.env, KRB5_CONFIG=conf)
    t = time.time()
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
    dead.close()
    check("a silent KDC is skipped", p.returncode == 0, out(p))
    # Renewal: a renewable TGT renewed.
    env = with_conf("krb5-renew.conf", "    renew_lifetime = 2d")
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
    q = run(k, [tool, "renew"], env=env)
    check("renew a renewable TGT", p.returncode == 0 and q.returncode == 0 and "renewed until" in q.stdout, out(p) + out(q))
    # Forwardable and proxiable flags.
    env = with_conf("krb5-fwd.conf", "    forwardable = true\n    proxiable = true")
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=env)
    q = run(k, [k.bin("klist"), "-f"], env=env)
    check("forwardable and proxiable TGT", p.returncode == 0 and "Flags: FPI" in q.stdout, out(p) + q.stdout)


def der(b, i):
    """The DER element at b[i]: (tag, content start, end)."""
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7f
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    return tag, i, i + n


def der_field(b, start, end, tag):
    """The element with `tag` among those in b[start:end], or None."""
    i = start
    while i < end:
        t, cs, e = der(b, i)
        if t == tag:
            return t, cs, e
        i = e
    return None


class TamperRelay:
    """A KDC on 127.0.0.1 (TCP) that forwards to a KDC (F.TEST's, S.TEST's,
    P.TEST's) and alters its replies as `mode` says: as-ticket, as-cname,
    as-strip (an AS-REP's ticket, client name, or PA-FX-FAST), tgs-ticket,
    tgs-strip, err-strip (an armored KRB-ERROR's PA-FX-FAST), err-spake-neg
    (an edwards25519 SPAKE challenge's key T made -T: still a point),
    as-pk-key (a bit of the KDC's DH value inside its signed
    KDCDHKeyInfo), as-pk-kdf (the KDF the KDC names, SHA-256 made SHA-512,
    outside the signature), as-pk-kx (PA-PKINIT-KX's ciphertext), or none."""

    def __init__(self, port):
        self.kdc_port = port
        self.mode = "none"
        self.requests = 0
        self.altered = 0
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                c.settimeout(10)
                req = self.read(c)
                self.requests += 1
                k = socket.create_connection(("127.0.0.1", self.kdc_port), timeout=10)
                k.sendall(len(req).to_bytes(4, "big") + req)
                rep = bytearray(self.read(k))
                k.close()
                self.tamper(rep)
                c.sendall(len(rep).to_bytes(4, "big") + bytes(rep))
            except OSError:
                pass
            finally:
                c.close()

    @staticmethod
    def read(s):
        buf = b""
        while len(buf) < 4:
            buf += s.recv(4 - len(buf))
        n = int.from_bytes(buf, "big")
        data = b""
        while len(data) < n:
            data += s.recv(n - len(data))
        return data

    @staticmethod
    def unfast(b, start, end):
        # Each PA-DATA of type 136 (PA-FX-FAST) made 135.
        _, cs, e = der(b, start)
        i = cs
        while i < e:
            _, ps, pe = der(b, i)
            f = der_field(b, ps, pe, 0xa1)
            if f:
                _, is_, ie = der(b, f[1])
                if int.from_bytes(b[is_:ie], "big") == 136:
                    b[ie - 1] = 135
            i = pe

    def tamper(self, b):
        mode = self.mode
        if mode == "none" or not b:
            return
        kind = {0x6b: "as", 0x6d: "tgs", 0x7e: "err"}.get(b[0])
        if kind is None or not mode.startswith(kind + "-"):
            return
        _, cs, end = der(b, 0)
        _, ss, se = der(b, cs)
        before = bytes(b)
        if mode.endswith("-ticket"):
            _, ts, te = der_field(b, ss, se, 0xa5)
            b[te - 1] ^= 1
        elif mode == "as-cname":
            _, ns, ne = der_field(b, ss, se, 0xa4)
            i = bytes(b).find(b"grace", ns, ne)
            b[i:i + 5] = b"mallo"
        elif mode.endswith("-strip") and kind != "err":
            _, ps, pe = der_field(b, ss, se, 0xa2)
            self.unfast(b, ps, pe)
        elif mode == "err-spake-neg":
            # group 1, then [1] OCTET STRING of 32 bytes: T's last byte
            # holds the sign of x.
            i = bytes(b).find(b"\x02\x01\x01\xa1\x22\x04\x20")
            if i >= 0:
                b[i + 7 + 31] ^= 0x80
        elif mode.startswith("as-pk-"):
            _, ps, pe = der_field(b, ss, se, 0xa2)
            want = {"as-pk-kx": 147}.get(mode, 17)
            _, qs, qe = der(b, ps)
            i = qs
            while i < qe:
                _, es, ee = der(b, i)
                t = der_field(b, es, ee, 0xa1)
                v = der_field(b, es, ee, 0xa2)
                _, ts, te = der(b, t[1])
                if int.from_bytes(b[ts:te], "big") == want:
                    _, vs, ve = der(b, v[1])
                    if mode == "as-pk-kx":
                        b[ve - 1] ^= 1
                    elif mode == "as-pk-kdf":
                        # id-pkinit-kdf-ah-sha256 (1.3.6.1.5.2.3.6.2) -> sha512 (.3).
                        j = bytes(b).find(b"\x06\x08\x2b\x06\x01\x05\x02\x03\x06\x02", vs, ve)
                        if j >= 0:
                            b[j + 9] = 3
                    else:
                        # id-pkinit-DHKeyData, then [0] { OCTET STRING { KDCDHKeyInfo } }:
                        # a byte of the public value's last part.
                        j = bytes(b).find(b"\x06\x07\x2b\x06\x01\x05\x02\x03\x02", vs, ve)
                        if j >= 0:
                            _, cs2, ce2 = der(b, j + 9)       # [0]
                            _, os2, oe2 = der(b, cs2)         # OCTET STRING
                            _, ks, ke = der(b, os2)           # KDCDHKeyInfo
                            _, fs, fe = der(b, ks)            # [0] subjectPublicKey
                            b[fe - 3] ^= 1
                i = ee
        elif mode == "err-strip":
            f = der_field(b, ss, se, 0xac)
            if f:
                _, os_, oe = der(b, f[1])
                self.unfast(b, os_, oe)
        if bytes(b) != before:
            self.altered += 1

    def close(self):
        self.sock.close()


def fast_tests(k, tool):
    """FAST (RFC 6113) in F.TEST, whose KDC refuses the encrypted
    timestamp: a password works there only armored."""
    keytab = k.path("fast.keytab")
    armor = "FILE:" + k.path("armor.cc")
    mit_armor = "FILE:" + k.path("mit-armor.cc")

    def cc(name):
        return dict(k.env, KRB5CCNAME="FILE:" + k.path(name))

    p = run(k, [tool, "kinit", "-k", keytab, "host/fast.f.test@F.TEST"], env=cc("armor.cc"))
    check("FAST: armor TGT from the host keytab", p.returncode == 0, out(p))
    p = run(k, [k.bin("klist"), "-C"], env=cc("armor.cc"))
    check("FAST: our cache says fast_avail, as MIT's do", "fast_avail(krbtgt/F.TEST@F.TEST) = yes" in p.stdout, out(p))
    p = run(k, [tool, "kinit", "grace@F.TEST"], "grace-pw\n", env=cc("grace.cc"))
    check("FAST: unarmored kinit refused (no encrypted timestamp)", p.returncode == 1, out(p))
    p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=cc("grace.cc"))
    q = run(k, [k.bin("klist")], env=cc("grace.cc"))
    check("FAST: kinit -T grace (encrypted challenge)", p.returncode == 0 and "krbtgt/F.TEST@F.TEST" in q.stdout,
          out(p) + out(q))
    p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "wrong\n", env=cc("wrong.cc"))
    check("FAST: wrong password, the armored error read", p.returncode == 1 and "PREAUTH_FAILED" in out(p), out(p))
    p = run(k, [tool, "kinit", "-T", armor, "heidi@F.TEST"], "heidi-pw\n", env=cc("heidi.cc"))
    log = open(k.path("kdc-f.log")).read()
    check("FAST: camellia reply key under aes armor (heidi)", p.returncode == 0 and any(
        "heidi@F.TEST for krbtgt" in l and "rep=camellia256-cts-cmac(26)" in l for l in log.splitlines()), out(p))
    p = run(k, [tool, "kvno", "HTTP/svc.f.test@F.TEST"], env=cc("grace.cc"))
    check("FAST: kvno, the TGS exchange armored by the TGT", p.returncode == 0, out(p))
    p = run(k, [k.bin("kvno"), "HTTP/svc.f.test@F.TEST"], env=cc("grace.cc"))
    check("FAST: MIT kvno with our armored TGT", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "-T", armor, "-k", keytab, "host/fast.f.test@F.TEST"], env=cc("armored-kt.cc"))
    check("FAST: kinit -T -k (armored keytab exchange)", p.returncode == 0, out(p))

    # MIT's kinit armored by our cache; ours by MIT's.
    trace = k.path("fast-trace.log")
    p = run(k, [k.bin("kinit"), "-T", armor, "grace@F.TEST"], "grace-pw\n", env=dict(cc("mit-grace.cc"), KRB5_TRACE=trace))
    t = open(trace).read() if os.path.exists(trace) else ""
    check("FAST: MIT kinit -T with our armor cache (our fast_avail read, encrypted challenge)",
          p.returncode == 0 and "Using FAST due to armor ccache negotiation result" in t
          and "encrypted_challenge (138) (real) returned: 0/Success" in t, out(p) + t[-1500:])
    p = run(k, [k.bin("kinit"), "-k", "-t", keytab, "host/fast.f.test@F.TEST"], env=cc("mit-armor.cc"))
    q = run(k, [tool, "kinit", "-T", mit_armor, "grace@F.TEST"], "grace-pw\n", env=cc("grace2.cc"))
    check("FAST: our kinit -T with MIT's armor cache", p.returncode == 0 and q.returncode == 0, out(p) + out(q))
    # Armor for another realm is no armor for this one.
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n", env=cc("alice.cc"))
    q = run(k, [tool, "kinit", "-T", "FILE:" + k.path("alice.cc"), "grace@F.TEST"], "grace-pw\n", env=cc("grace3.cc"))
    check("FAST: armor TGT of another realm refused", q.returncode == 1, out(p) + out(q))

    # disable_encrypted_timestamp on the client side (MIT's krb5.conf
    # relation): bob's timestamp is never sent, so kinit fails.
    base = open(k.path("krb5.conf")).read()
    conf = k.path("krb5-nots.conf")
    with open(conf, "w") as f:
        f.write(base.replace(f"kdc = 127.0.0.1:{k.port_a}", f"kdc = 127.0.0.1:{k.port_a}\n        disable_encrypted_timestamp = true"))
    env = dict(cc("bob.cc"), KRB5_CONFIG=conf)
    p = run(k, [tool, "kinit", "bob"], "bob-pw\n", env=env)
    q = run(k, [k.bin("kinit"), "bob"], "bob-pw\n", env=env)
    check("FAST: client disable_encrypted_timestamp, ours and MIT's refuse", p.returncode == 1 and q.returncode != 0,
          out(p) + out(q))

    # A KDC in the middle that alters replies: the armor catches it.
    relay = TamperRelay(k.port_f)
    conf = k.path("krb5-relay.conf")
    with open(conf, "w") as f:
        f.write(base.replace(f"kdc = 127.0.0.1:{k.port_f}", f"kdc = tcp/127.0.0.1:{relay.port}"))
    env = dict(cc("relay.cc"), KRB5_CONFIG=conf)
    try:
        relay.mode = "none"
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        check("FAST relay: unaltered", p.returncode == 0, out(p))
        relay.mode = "as-ticket"
        a = relay.altered
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        check("FAST relay: AS-REP ticket altered, finished checksum fails", p.returncode == 1 and "FAST" in out(p) and relay.altered > a, out(p))
        relay.mode = "as-strip"
        a = relay.altered
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        check("FAST relay: AS-REP without PA-FX-FAST refused", p.returncode == 1 and "FAST" in out(p) and relay.altered > a,
              out(p))
        relay.mode = "as-cname"
        a = relay.altered
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        q = run(k, [k.bin("klist")], env=env)
        check("FAST relay: AS-REP client name altered, the finished name used",
              p.returncode == 0 and "grace@F.TEST" in p.stdout and "Default principal: grace@F.TEST" in q.stdout
              and relay.altered > a, out(p) + out(q))
        relay.mode = "err-strip"
        before, a = relay.requests, relay.altered
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        check("FAST relay: unarmored error not acted on (one request, no retry)",
              p.returncode == 1 and relay.requests - before == 1 and relay.altered > a,
              out(p) + f"requests: {relay.requests - before}")
        relay.mode = "none"
        p = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n", env=env)
        relay.mode = "tgs-ticket"
        a = relay.altered
        q = run(k, [tool, "kvno", "HTTP/svc.f.test@F.TEST"], env=env)
        check("FAST relay: TGS-REP ticket altered, finished checksum fails",
              p.returncode == 0 and q.returncode == 1 and "FAST" in out(q) and relay.altered > a, out(p) + out(q))
        relay.mode = "tgs-strip"
        a = relay.altered
        q = run(k, [tool, "kvno", "HTTP/svc.f.test@F.TEST"], env=env)
        check("FAST relay: TGS-REP without PA-FX-FAST fails (its key was strengthened)",
              q.returncode == 1 and relay.altered > a, out(q))
    finally:
        relay.close()


def spake_tests(k, tool):
    """SPAKE pre-authentication against MIT's KDC. S.TEST offers it in
    all four groups and refuses the encrypted timestamp, so an unarmored
    password works there only through SPAKE; O.TEST sends an optimistic
    edwards25519 challenge and takes edwards25519 and P-256 only, and the
    timestamp. Each exchange is read back from the KDC's log."""
    base = open(k.path("krb5.conf")).read()
    slog, olog = k.path("kdc-s.log"), k.path("kdc-o.log")

    def cc(name):
        return dict(k.env, KRB5CCNAME="FILE:" + k.path(name))

    def conf(name, groups=None, realm_port=None, extra=""):
        text = base
        if groups:
            text = text.replace("[libdefaults]", f"[libdefaults]\n    spake_preauth_groups = {groups}", 1)
        if realm_port and extra:
            text = text.replace(f"kdc = 127.0.0.1:{realm_port}", f"kdc = 127.0.0.1:{realm_port}\n        {extra}")
        path = k.path(name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def mark(log):
        return len(open(log).read())

    def since(log, at):
        # The AS-REQ lines and the SPAKE module's, logged after `at`.
        return [l for l in open(log).read()[at:].splitlines() if "AS_REQ" in l or "preauth (spake)" in l]

    more = "preauth (spake) verify failure: More preauthentication data is required"
    # The reply key's type, as the KDC logs it (rep=...).
    for user, etype in [("sam", "aes256-cts-hmac-sha1-96")] + [(f"sam-{x}", e) for x, e in SAM_ETYPES]:
        at = mark(slog)
        p = run(k, [tool, "kinit", f"{user}@S.TEST"], f"{user}-pw\n", env=cc(f"{user}.cc"))
        lines = since(slog, at)
        issued = [l for l in lines if "ISSUE" in l and f"{user}@S.TEST for krbtgt" in l]
        rep = issued[0].split("rep=")[1].split(",")[0] if len(issued) == 1 else ""
        check(f"SPAKE: kinit {user} (support, challenge, response; reply key {etype})",
              p.returncode == 0 and any(more in l for l in lines) and etype in rep, out(p) + "\n".join(lines))
    for g in ("P-256", "P-384", "P-521"):
        env = dict(cc("sam-g.cc"), KRB5_CONFIG=conf(f"krb5-spake-{g}.conf", groups=g))
        at = mark(slog)
        p = run(k, [tool, "kinit", "sam@S.TEST"], "sam-pw\n", env=env)
        lines = since(slog, at)
        check(f"SPAKE: kinit in {g} (the only group we offer)", p.returncode == 0 and any(more in l for l in lines),
              out(p) + "\n".join(lines))
    env = dict(cc("sam-nots.cc"), KRB5_CONFIG=conf("krb5-spake-nots.conf", realm_port=k.port_s,
                                                    extra="disable_encrypted_timestamp = true"))
    p = run(k, [tool, "kinit", "sam@S.TEST"], "sam-pw\n", env=env)
    check("SPAKE: client disable_encrypted_timestamp, SPAKE still taken", p.returncode == 0, out(p))
    p = run(k, [tool, "kvno", "host/fast.s.test@S.TEST"], env=cc("sam.cc"))
    check("SPAKE: kvno with the TGT SPAKE got", p.returncode == 0, out(p))

    # O.TEST's optimistic challenge, taken, refused, and no group in common.
    # Taken: the client sends no timestamp, so SPAKE alone can succeed.
    at = mark(olog)
    env = dict(cc("olga.cc"), KRB5_CONFIG=conf("krb5-spake-onots.conf", realm_port=k.port_o,
                                                extra="disable_encrypted_timestamp = true"))
    p = run(k, [tool, "kinit", "olga@O.TEST"], "olga-pw\n", env=env)
    lines = since(olog, at)
    check("SPAKE: optimistic challenge answered at once (2 requests)",
          p.returncode == 0 and len(lines) == 2 and "NEEDED_PREAUTH" in lines[0] and "ISSUE" in lines[1],
          out(p) + "\n".join(lines))
    at = mark(olog)
    env = dict(cc("olga-p256.cc"), KRB5_CONFIG=conf("krb5-spake-o256.conf", groups="P-256"))
    p = run(k, [tool, "kinit", "olga@O.TEST"], "olga-pw\n", env=env)
    lines = since(olog, at)
    check("SPAKE: optimistic edwards25519 refused, P-256 asked for and used",
          p.returncode == 0 and any(more in l for l in lines) and "ISSUE" in lines[-1], out(p) + "\n".join(lines))
    at = mark(olog)
    env = dict(cc("olga-p384.cc"), KRB5_CONFIG=conf("krb5-spake-o384.conf", groups="P-384"))
    p = run(k, [tool, "kinit", "olga@O.TEST"], "olga-pw\n", env=env)
    lines = since(olog, at)
    check("SPAKE: no group in common, the support refused, encrypted timestamp instead",
          p.returncode == 0 and any("PREAUTH_FAILED" in l for l in lines) and "ISSUE" in lines[-1],
          out(p) + "\n".join(lines))
    at = mark(olog)
    env = dict(cc("olga-p384n.cc"), KRB5_CONFIG=conf("krb5-spake-o384nots.conf", groups="P-384", realm_port=k.port_o,
                                                     extra="disable_encrypted_timestamp = true"))
    p = run(k, [tool, "kinit", "olga@O.TEST"], "olga-pw\n", env=env)
    lines = since(olog, at)
    check("SPAKE: no group in common and disable_encrypted_timestamp: refused, no timestamp sent",
          p.returncode == 1 and not any("ISSUE" in l for l in lines) and len([l for l in lines if "AS_REQ" in l]) == 2,
          out(p) + "\n".join(lines))
    at = mark(olog)
    p = run(k, [tool, "kinit", "olga@O.TEST"], "wrong\n", env=cc("olga-wrong.cc"))
    all_lines = since(olog, at)
    lines = [l for l in all_lines if "AS_REQ" in l]
    check("SPAKE: wrong password, PREAUTH_FAILED and no fallback to the timestamp",
          p.returncode == 1 and "PREAUTH_FAILED" in out(p) and len(lines) == 2 and "PREAUTH_FAILED" in lines[1]
          and any("preauth (spake) verify failure: Preauthentication failed" in l for l in all_lines),
          out(p) + "\n".join(all_lines))

    # Inside FAST: SPAKE taken over the encrypted challenge.
    armor = "FILE:" + k.path("s-armor.cc")
    p = run(k, [tool, "kinit", "-k", k.path("s-fast.keytab"), "host/fast.s.test@S.TEST"], env=cc("s-armor.cc"))
    at = mark(slog)
    q = run(k, [tool, "kinit", "-T", armor, "sam@S.TEST"], "sam-pw\n", env=cc("sam-fast.cc"))
    lines = since(slog, at)
    check("SPAKE: inside FAST (kinit -T)", p.returncode == 0 and q.returncode == 0 and any(more in l for l in lines),
          out(p) + out(q) + "\n".join(lines))
    at = mark(slog)
    q = run(k, [tool, "kinit", "-T", armor, "sam@S.TEST"], "wrong\n", env=cc("sam-fast-wrong.cc"))
    lines = since(slog, at)
    check("SPAKE: inside FAST, wrong password", q.returncode == 1 and "PREAUTH_FAILED" in out(q)
          and any("preauth (spake) verify failure: Preauthentication failed" in l for l in lines), out(q) + "\n".join(lines))

    # A KDC in the middle that answers for the KDC's T with -T.
    relay = TamperRelay(k.port_s)
    env = dict(cc("sam-relay.cc"), KRB5_CONFIG=k.path("krb5-spake-relay.conf"))
    with open(k.path("krb5-spake-relay.conf"), "w") as f:
        f.write(base.replace(f"kdc = 127.0.0.1:{k.port_s}", f"kdc = tcp/127.0.0.1:{relay.port}"))
    try:
        p = run(k, [tool, "kinit", "sam@S.TEST"], "sam-pw\n", env=env)
        check("SPAKE relay: unaltered", p.returncode == 0, out(p))
        relay.mode = "err-spake-neg"
        a = relay.altered
        p = run(k, [tool, "kinit", "sam@S.TEST"], "sam-pw\n", env=env)
        check("SPAKE relay: T replaced by -T, the KDC refuses the response",
              p.returncode == 1 and "PREAUTH_FAILED" in out(p) and relay.altered > a, out(p))
    finally:
        relay.close()


def skew_tests(mit, tool, goose):
    # A KDC whose clock is ten minutes ahead: pre-authentication fails on
    # skew, the client learns the offset from the error and retries.
    with Kdc(mit=mit, time_offset=600) as k:
        p = run(k, [tool, "kinit", "bob"], "bob-pw\n")
        check("clock skew corrected (KDC 10 minutes ahead)", p.returncode == 0, out(p))
        q = run(k, [tool, "kvno", "HTTP/svc.a.test"])
        check("service ticket after skew correction", q.returncode == 0, out(q))
        # FAST: the KDC reads the armor's authenticator against its clock
        # and refuses it in the clear; the client corrects and stays armored.
        armor = "FILE:" + k.path("armor.cc")
        p = run(k, [tool, "kinit", "-k", k.path("fast.keytab"), "host/fast.f.test@F.TEST"],
                env=dict(k.env, KRB5CCNAME=armor))
        q = run(k, [tool, "kinit", "-T", armor, "grace@F.TEST"], "grace-pw\n")
        check("FAST: clock skew corrected with armor (KDC 10 minutes ahead)", p.returncode == 0 and q.returncode == 0,
              out(p) + out(q))


def gss_tests(k, tool, gss):
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n")
    # Ours to MIT's gss-server.
    for mech in ("", "-spnego"):
        for extra in ([], ["-seq"], ["-noconf"]):
            b = InetdBridge(k, k.path("svc.keytab"), "host@svc.a.test")
            args = [gss, "client", "127.0.0.1", str(b.port), "host@svc.a.test", "hello mit"] + ([mech] if mech else []) + extra
            p = run(k, args)
            log = b.output()
            check(f"our initiator -> MIT gss-server {mech or 'krb5'} {' '.join(extra)}".strip(),
                  p.returncode == 0 and "Signature verified." in p.stdout and 'Received message: "hello mit"' in log,
                  out(p) + log)
    p = run(k, [tool, "kinit", "alice"], "alice-pw\n",
            env=dict(k.env, KRB5_CONFIG=k.path("krb5-fwd.conf")) if os.path.exists(k.path("krb5-fwd.conf")) else None)
    b = InetdBridge(k, k.path("svc.keytab"), "host@svc.a.test")
    p = run(k, [gss, "client", "127.0.0.1", str(b.port), "host@svc.a.test", "with delegation", "-deleg"],
            env=dict(k.env, KRB5_CONFIG=k.path("krb5-fwd.conf")))
    log = b.output()
    check("our initiator -> MIT gss-server with delegation", p.returncode == 0 and "Signature verified." in p.stdout, out(p) + log)

    # MIT's gss-client to ours.
    run(k, [k.bin("kinit"), "-f", "alice"], "alice-pw\n", env=dict(k.env, KRB5_CONFIG=k.path("krb5-fwd.conf")))
    for opts in ([], ["-spnego"], ["-seq"], ["-nomutual"], ["-spnego", "-d"], ["-d"], ["-nx"], ["-spnego", "-nx"]):
        srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("svc.keytab")], k.env)
        p = run(k, [k.bin("gss-client"), "-port", str(port)] + opts + ["127.0.0.1", "host@svc.a.test", "hello goose"])
        log = stop_server(srv)
        want_deleg = "-d" in opts
        ok = (p.returncode == 0 and "Signature verified" in out(p) and "accepted: alice@A.TEST" in log
              and f"message: hello goose sealed={'false' if '-nx' in opts else 'true'}" in log
              and (not want_deleg or "delegated=1" in log))
        check(f"MIT gss-client {' '.join(opts) or 'krb5'} -> our acceptor", ok, out(p) + log)
        if not opts:
            # MIT's KDC (1.20 and later) signs a PAC into every ticket.
            check("PAC of an MIT ticket verified (server signature, client info)",
                  "pac: verified client=alice" in log, log)
    # RC4 session keys: RFC 4757's tokens, both ways.
    rc4 = dict(k.env, KRB5_CONFIG=k.path("krb5-arcfour-hmac.conf"), KRB5CCNAME="FILE:" + k.path("ccache-rc4"))
    run(k, [tool, "kinit", "alice"], "alice-pw\n", env=rc4)
    for mech in ("", "-spnego"):
        for extra in ([], ["-noconf"]):
            b = InetdBridge(k, k.path("svc.keytab"), "host@svc.a.test")
            args = [gss, "client", "127.0.0.1", str(b.port), "host@svc.a.test", "hello rc4"] + ([mech] if mech else []) + extra
            p = run(k, args, env=rc4)
            log = b.output()
            check(f"RC4 context: our initiator -> MIT gss-server {mech or 'krb5'} {' '.join(extra)}".strip(),
                  p.returncode == 0 and "Signature verified." in p.stdout and 'Received message: "hello rc4"' in log,
                  out(p) + log)
    run(k, [k.bin("kinit"), "alice"], "alice-pw\n", env=rc4)
    for opts in ([], ["-nx"], ["-spnego"]):
        srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("svc.keytab")], rc4)
        p = run(k, [k.bin("gss-client"), "-port", str(port)] + opts + ["127.0.0.1", "host@svc.a.test", "hello goose"], env=rc4)
        log = stop_server(srv)
        q = run(k, [k.bin("klist"), "-e"], env=rc4)
        # The session key MIT's klist shows is RC4's.
        ok = (p.returncode == 0 and "Signature verified" in out(p) and "message: hello goose" in log
              and "arcfour-hmac" in q.stdout)
        check(f"RC4 context: MIT gss-client {' '.join(opts) or 'krb5'} -> our acceptor", ok, out(p) + log)

    # Camellia session keys: RFC 4121's tokens with CMAC checksums, both
    # ways; the PAC MIT signs into the ticket carries cmac-camellia.
    for et in ("camellia256-cts-cmac", "camellia128-cts-cmac"):
        cam = dict(k.env, KRB5_CONFIG=k.path(f"krb5-{et}.conf"), KRB5CCNAME="FILE:" + k.path(f"ccache-{et}"))
        run(k, [tool, "kinit", "alice"], "alice-pw\n", env=cam)
        for mech in ("", "-spnego"):
            for extra in ([], ["-noconf"], ["-seq"]):
                b = InetdBridge(k, k.path("svc.keytab"), "host@svc.a.test")
                args = [gss, "client", "127.0.0.1", str(b.port), "host@svc.a.test", "hello camellia"] + ([mech] if mech else []) + extra
                p = run(k, args, env=cam)
                log = b.output()
                check(f"{et} context: our initiator -> MIT gss-server {mech or 'krb5'} {' '.join(extra)}".strip(),
                      p.returncode == 0 and "Signature verified." in p.stdout and 'Received message: "hello camellia"' in log,
                      out(p) + log)
        run(k, [k.bin("kinit"), "-f", "alice"], "alice-pw\n", env=cam)
        for opts in ([], ["-nx"], ["-spnego"], ["-d"]):
            srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("svc.keytab")], cam)
            p = run(k, [k.bin("gss-client"), "-port", str(port)] + opts + ["127.0.0.1", "host@svc.a.test", "hello goose"], env=cam)
            log = stop_server(srv)
            q = run(k, [k.bin("klist"), "-e"], env=cam)
            # MIT picks the ticket's etype from the service's keys (AES
            # here); the session key is the one asked for.
            ok = (p.returncode == 0 and "Signature verified" in out(p) and "message: hello goose" in log
                  and f"Etype (skey, tkt): {et}, " in q.stdout)
            check(f"{et} context: MIT gss-client {' '.join(opts) or 'krb5'} -> our acceptor", ok, out(p) + log + q.stdout)
        # A service with camellia keys only: the ticket is encrypted with
        # one, and the PAC's server signature is cmac-camellia256.
        for opts in ([], ["-spnego"]):
            srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("svc.keytab")], cam)
            p = run(k, [k.bin("gss-client"), "-port", str(port)] + opts + ["127.0.0.1", "host@cam.a.test", "hello cam"], env=cam)
            log = stop_server(srv)
            q = run(k, [k.bin("klist"), "-e"], env=cam)
            ok = (p.returncode == 0 and "Signature verified" in out(p) and "message: hello cam" in log
                  and "pac: verified client=alice" in log and f"{et}, camellia256-cts-cmac" in q.stdout)
            check(f"{et} session, camellia256 ticket and PAC: MIT gss-client {' '.join(opts) or 'krb5'} -> our acceptor",
                  ok, out(p) + log + q.stdout)
        p = run(k, [tool, "kvno", "host/cam.a.test"], env=cam)
        check(f"our kvno of a camellia-only service ({et} session)", p.returncode == 0, out(p))

    # An acceptor without the key refuses.
    srv, port = start_server([gss, "server", "0", "-once", "-keytab", k.path("web.keytab")], k.env)
    p = run(k, [k.bin("gss-client"), "-port", str(port), "127.0.0.1", "host@svc.a.test", "x"], timeout=20)
    log = stop_server(srv)
    check("acceptor without the service key refuses", p.returncode != 0 and "error:" in log, out(p) + log)


def http_tests(k, tool, gss):
    run(k, [tool, "kinit", "alice"], "alice-pw\n")
    srv, port = start_server([gss, "http-server", "0", "-keytab", k.path("svc.keytab")], k.env)
    try:
        p = run(k, [gss, "http-client", "127.0.0.1", str(port), "/", "HTTP@svc.a.test"])
        check("our HTTP Negotiate client -> our server, mutual", p.returncode == 0 and "200 OK" in p.stdout
              and "hello alice@A.TEST" in p.stdout and "mutual authentication: ok" in p.stdout, out(p))
        # curl (macOS: Heimdal's GSS.framework) with MIT's cache.
        run(k, [k.bin("kinit"), "alice"], "alice-pw\n")
        p = run(k, ["curl", "-sS", "--negotiate", "-u", ":", "--resolve", f"svc.a.test:{port}:127.0.0.1",
                    f"http://svc.a.test:{port}/"], timeout=30)
        check("curl --negotiate -> our server", p.returncode == 0 and "hello alice@A.TEST" in p.stdout, out(p))
        p = run(k, ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"http://127.0.0.1:{port}/"])
        check("no credentials: 401 with a challenge", p.stdout.strip() == "401", out(p))
    finally:
        log = stop_server(srv)
        if verbose:
            print(log)


def pkinit_tests(k, tool):
    """PKINIT (RFC 4556, 8636) and anonymous PKINIT (RFC 8062) against
    MIT's KDC in P.TEST, Q.TEST, R.TEST and N.TEST (scripts/kdc.py, with
    certificates from scripts/pki.py): RSA and ECDSA certificates, a
    chain, PKCS #12, each Diffie-Hellman group and KDF, freshness tokens
    and a refused group (Q.TEST), PKINIT inside FAST armored by an
    anonymous TGT; certificates the KDC must refuse, KDC certificates the
    client must refuse, and replies altered on the way."""
    pki = k.path("pki")
    base = open(k.path("krb5.conf")).read()
    n = [0]

    def env_with(extra="", realm_extra=None, relay=None, anchors=None):
        # A krb5.conf with `extra` in [libdefaults], realm_extra lines in
        # P.TEST's (or the realm's named) stanza, P.TEST through a relay.
        text = base.replace("[libdefaults]", "[libdefaults]\n" + extra)
        if anchors:
            text = text.replace(f"pkinit_anchors = FILE:{pki}/ca.pem", f"pkinit_anchors = FILE:{anchors}")
        if realm_extra:
            r, lines = realm_extra
            port = k.ports_p[r]
            text = text.replace(f"kdc = 127.0.0.1:{port}\n", f"kdc = 127.0.0.1:{port}\n        {lines}\n")
        if relay:
            text = text.replace(f"kdc = 127.0.0.1:{k.ports_p['P.TEST']}", f"kdc = tcp/127.0.0.1:{relay.port}")
        n[0] += 1
        conf = k.path(f"krb5-pk{n[0]}.conf")
        with open(conf, "w") as f:
            f.write(text)
        return dict(k.env, KRB5_CONFIG=conf, KRB5CCNAME="FILE:" + k.path(f"pk{n[0]}.cc"))

    def ident(name, chain=False):
        return f"X509_user_identity=FILE:{pki}/{name}.pem,{pki}/{name}.key"

    def kinit(name, principal, env=None, extra=()):
        env = env or env_with()
        p = run(k, [tool, "kinit", *extra, "-X", ident(name), principal], env=env)
        return p, env

    def klist(env):
        return run(k, [k.bin("klist")], env=env).stdout

    def kdc_log():
        return open(k.path("kdc-p.log")).read()

    for name, what in (("pat", "RSA 2048"), ("pat-p256", "ECDSA P-256"), ("pat-p384", "ECDSA P-384"),
                       ("pat-p521", "ECDSA P-521"), ("pat-rsa3072", "RSA 3072, SHA-384 certificate")):
        p, env = kinit(name, "pat@P.TEST")
        check(f"PKINIT: kinit -X pat ({what})", p.returncode == 0 and "Default principal: pat@P.TEST" in klist(env), out(p))
    # Our cache's TGT with MIT's kvno.
    q = run(k, [k.bin("kvno"), "HTTP/svc.p.test@P.TEST"], env=env)
    check("PKINIT: MIT's kvno with our PKINIT TGT", q.returncode == 0, out(q))
    # An intermediate CA, sent beside the certificate.
    with open(k.path("pat-chain.pem"), "w") as f:
        f.write(open(f"{pki}/pat-inter.pem").read() + open(f"{pki}/inter.pem").read())
    env = env_with()
    p = run(k, [tool, "kinit", "-X", f"X509_user_identity=FILE:{k.path('pat-chain.pem')},{pki}/pat-inter.key", "pat@P.TEST"],
            env=env)
    check("PKINIT: a certificate under an intermediate CA (sent with it)", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "-X", f"X509_user_identity=FILE:{pki}/pat-inter.pem,{pki}/pat-inter.key", "pat@P.TEST"],
            env=env)
    check("PKINIT: the same without the intermediate refused (CANT_VERIFY_CERTIFICATE)",
          p.returncode == 1 and "CANT_VERIFY_CERTIFICATE" in out(p), out(p))
    env = env_with()
    p = run(k, [tool, "kinit", "-X", f"X509_user_identity=PKCS12:{pki}/pat.p12", "pat@P.TEST"], "pat-p12\n", env=env)
    check("PKINIT: PKCS #12 identity", p.returncode == 0 and "pat@P.TEST" in klist(env), out(p))
    p = run(k, [tool, "kinit", "-X", f"X509_user_identity=PKCS12:{pki}/pat.p12", "pat@P.TEST"], "wrong\n", env=env)
    check("PKINIT: PKCS #12, wrong password", p.returncode == 1 and "certificate or key" in out(p), out(p))
    p, env = kinit("pat-upn", "pat@P.TEST")
    check("PKINIT: a certificate with a UPN SAN (pkinit_allow_upn)", p.returncode == 0, out(p))

    # Each group, as pkinit_dh_min_bits picks it.
    for g in ("2048", "P-256", "4096", "P-384", "P-521"):
        p, env = kinit("pat", "pat@P.TEST", env_with(f"    pkinit_dh_min_bits = {g}"))
        check(f"PKINIT: group {g}", p.returncode == 0, out(p))
    # Each KDF, and none (RFC 4556's octetstring2key).
    for kdf in ("sha1", "sha256", "sha384", "sha512", "none"):
        p, env = kinit("pat", "pat@P.TEST", env_with(f"    pkinit_kdfs = {kdf}"))
        check(f"PKINIT: KDF {kdf}", p.returncode == 0, out(p))
    # Q.TEST: freshness tokens required, groups of 4096 bits and more; we
    # start at 2048 and take the first the KDC lists.
    refused = "verify failure: Key parameters not accepted"
    before = kdc_log().count(refused)
    p, env = kinit("quinn", "quinn@Q.TEST")
    log = kdc_log()
    check("PKINIT: Q.TEST refuses 2048, we retry with its group, freshness token sent",
          p.returncode == 0 and log.count(refused) == before + 1
          and "freshness token received from quinn@Q.TEST" in log, out(p))
    p, env = kinit("quinn", "quinn@Q.TEST", env_with("    pkinit_dh_min_bits = P-521"))
    check("PKINIT: Q.TEST with P-521 from the start", p.returncode == 0, out(p))

    # Anonymous, and its TGT as FAST armor for PKINIT.
    anon = env_with()
    p = run(k, [tool, "kinit", "-n", "@P.TEST"], env=anon)
    check("PKINIT: anonymous (kinit -n), WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS",
          p.returncode == 0 and "Default principal: WELLKNOWN/ANONYMOUS@WELLKNOWN:ANONYMOUS" in klist(anon), out(p))
    armor = anon["KRB5CCNAME"][5:]
    p, env = kinit("pat", "pat@P.TEST", extra=("-T", armor))
    check("PKINIT: inside FAST, armored by the anonymous TGT", p.returncode == 0 and "pat@P.TEST" in klist(env), out(p))
    q = run(k, [k.bin("kinit"), "-T", armor, "-X", ident("pat"), "pat@P.TEST"], env=dict(env, KRB5CCNAME="FILE:" + k.path("mit-armored.cc")))
    check("PKINIT: MIT's kinit armored by our anonymous TGT", q.returncode == 0, out(q))

    # Refused by the KDC.
    # MIT says CANT_VERIFY_CERTIFICATE for an issuer it does not know.
    for name, principal, code, what in (("pat-other", "pat@P.TEST", "CANT_VERIFY_CERTIFICATE", "a certificate from another CA"),
                                        ("pat-noeku", "pat@P.TEST", "INCONSISTENT_KEY_PURPOSE", "EKU serverAuth only"),
                                        ("pat-expired", "pat@P.TEST", "", "an expired certificate"),
                                        ("pat", "quinn@Q.TEST", "CLIENT_NAME_MISMATCH", "pat's certificate for quinn")):
        p, env = kinit(name, principal)
        check(f"PKINIT: KDC refuses {what}" + (f" ({code})" if code else ""),
              p.returncode == 1 and (code in out(p)), out(p))

    # KDC certificates we refuse, or take as MIT does.
    p, env = kinit("pat", "pat@P.TEST", env_with(anchors=f"{pki}/rogue.pem"))
    check("PKINIT: KDC certificate from a CA we do not trust (KDC_NOT_TRUSTED)",
          p.returncode == 1 and "KDC_NOT_TRUSTED" in out(p), out(p))
    p, env = kinit("rita", "rita@R.TEST")
    check("PKINIT: KDC certificate naming a host, not krbtgt (KDC_NAME_MISMATCH)",
          p.returncode == 1 and "KDC_NAME_MISMATCH" in out(p), out(p))
    p, env = kinit("rita", "rita@R.TEST", env_with(realm_extra=("R.TEST", "pkinit_kdc_hostname = kdc.r.test")))
    check("PKINIT: the same with pkinit_kdc_hostname (EKU id-pkinit-KPKdc)", p.returncode == 0, out(p))
    p, env = kinit("rita", "rita@R.TEST", env_with(realm_extra=(
        "R.TEST", "pkinit_kdc_hostname = kdc.r.test\n        pkinit_eku_checking = kpServerAuth")))
    check("PKINIT: pkinit_eku_checking = kpServerAuth refuses it (INCONSISTENT_KEY_PURPOSE)",
          p.returncode == 1 and "INCONSISTENT_KEY_PURPOSE" in out(p), out(p))
    p, env = kinit("rita", "nate@N.TEST")
    check("PKINIT: KDC certificate with id-pkinit-san and EKU serverAuth taken (as MIT)", p.returncode == 0, out(p))

    # Replies altered on the way.
    relay = TamperRelay(k.ports_p["P.TEST"])
    try:
        for mode, code, what in (("as-pk-key", "INVALID_SIG", "the KDC's DH value changed (signature fails)"),
                                 ("as-pk-kdf", "PREAUTH_FAILED", "the KDF named changed (another key)")):
            relay.mode = mode
            altered = relay.altered
            env = env_with(relay=relay)
            p = run(k, [tool, "kinit", "-X", ident("pat"), "pat@P.TEST"], env=env)
            check(f"PKINIT: {what}", p.returncode == 1 and code in out(p) and relay.altered > altered, out(p))
        # MIT sends PA-PKINIT-KX to anonymous clients only (RFC 8062 says
        # SHOULD for others): nothing to alter for pat.
        relay.mode = "as-pk-kx"
        altered = relay.altered
        p = run(k, [tool, "kinit", "-X", ident("pat"), "pat@P.TEST"], env=env_with(relay=relay))
        check("PKINIT: no PA-PKINIT-KX for a named client (MIT)", p.returncode == 0 and relay.altered == altered, out(p))
        p = run(k, [tool, "kinit", "-n", "@P.TEST"], env=env_with(relay=relay))
        check("PKINIT: anonymous, PA-PKINIT-KX changed", p.returncode == 1 and relay.altered > altered, out(p))
        relay.mode = "none"
        p = run(k, [tool, "kinit", "-X", ident("pat"), "pat@P.TEST"], env=env_with(relay=relay))
        check("PKINIT: through the relay unaltered", p.returncode == 0, out(p))
    finally:
        relay.close()


def main():
    global verbose, only
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--mit")
    ap.add_argument("-k", help="only checks whose name contains this")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    verbose = args.v
    only = args.k
    goose = find_goose(args.goose)
    with tempfile.TemporaryDirectory() as tmp:
        tool = os.path.join(tmp, "krb5")
        gss = os.path.join(tmp, "gss")
        for src, exe in (("tools/krb5.goose", tool), ("tools/gss.goose", gss)):
            p = subprocess.run([goose, "build", "-o", exe, src], cwd=ROOT, capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit(f"building {src} failed:\n{p.stdout}{p.stderr}")
        with Kdc(mit=args.mit) as k:
            tgs_tests(k, tool)
            transport_tests(k, tool)
            fast_tests(k, tool)
            spake_tests(k, tool)
            pkinit_tests(k, tool)
            gss_tests(k, tool, gss)
            http_tests(k, tool, gss)
        skew_tests(args.mit, tool, goose)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
