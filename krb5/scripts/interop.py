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
from kdc import Kdc  # noqa: E402

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
    for user, et in (("carol", "arcfour-hmac"), ("dave", "des3-cbc-sha1")):
        p = run(k, [tool, "kinit", user], f"{user}-pw\n")
        check(f"kinit {user} ({et} keys only)", p.returncode == 0, out(p))
        p = run(k, [k.bin("klist"), "-e"])
        check(f"{user}'s TGT reads in MIT klist", f"{user}@A.TEST" in p.stdout, out(p))
        p = run(k, [tool, "kvno", "HTTP/svc.a.test"])
        check(f"kvno as {user}", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "-k", k.path("svc.keytab"), "host/svc.a.test"])
    check("kinit -k with MIT's keytab", p.returncode == 0, out(p))
    p = run(k, [tool, "kinit", "erin@B.TEST"], "erin-pw\n")
    check("kinit erin@B.TEST", p.returncode == 0, out(p))
    p = run(k, [tool, "kvno", "HTTP/svc.a.test@A.TEST"])
    check("kvno cross-realm B -> A", p.returncode == 0, out(p))

    # Every encryption type of the TGS reply, through MIT's keytab.
    for et in ("aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha384-192",
               "aes128-cts-hmac-sha256-128", "arcfour-hmac", "des3-cbc-sha1"):
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


def skew_tests(mit, tool, goose):
    # A KDC whose clock is ten minutes ahead: pre-authentication fails on
    # skew, the client learns the offset from the error and retries.
    with Kdc(mit=mit, time_offset=600) as k:
        p = run(k, [tool, "kinit", "bob"], "bob-pw\n")
        check("clock skew corrected (KDC 10 minutes ahead)", p.returncode == 0, out(p))
        q = run(k, [tool, "kvno", "HTTP/svc.a.test"])
        check("service ticket after skew correction", q.returncode == 0, out(q))


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
            gss_tests(k, tool, gss)
            http_tests(k, tool, gss)
        skew_tests(args.mit, tool, goose)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
