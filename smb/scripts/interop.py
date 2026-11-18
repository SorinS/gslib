#!/usr/bin/env python3
"""smb against Samba 4.17, in Docker on this machine (Linux), everything
on loopback (scripts/interop/samba.sh starts it):

  * every dialect (2.0.2, 2.1, 3.0, 3.0.2, 3.1.1) with NTLMv2: directories,
    small and large files (multi-credit READ and WRITE), ls, stat, mv,
    truncate, touch, rm, rmdir, df, echo; what gslib wrote read back by
    Samba's smbclient, and the other way;
  * signing: HMAC-SHA256 (2.x), AES-128-CMAC (3.0, 3.0.2, 3.1.1),
    AES-128-GMAC (3.1.1); 3.0's validate-negotiate;
  * encryption: AES-128-CCM (3.0, 3.0.2), and AES-128-GCM, AES-128-CCM,
    AES-256-GCM and AES-256-CCM (3.1.1), asked for by the client, by a
    share (enc) and by a server that requires it for every session;
  * Kerberos against Samba's AD DC (3.1.1 with AES-256 encryption, 3.0,
    2.1), and NTLM as a domain user there;
  * anonymous (null) sessions on IPC$, and refused where signing is
    required;
  * refusals: a wrong password, an unknown share, a missing file,
    encryption required from a server without it, 2.x on a share or
    server that requires encryption;
  * a man in the middle (a proxy here) that changes one response: a
    signature, the SIGNED flag, an encrypted message, a NEGOTIATE
    response under 3.1.1 (the preauth hash catches it) and under 3.0
    (validate-negotiate catches it). Each must make the client fail.

    python3 scripts/interop.py [--goose PATH] [--work DIR] [--no-setup]

The work directory (default: smb-interop in the current directory) gets
Samba's configuration and the files moved. --no-setup reuses the
containers a previous run started. The containers are left running
(gs-smb, gs-smb-strict, gs-smb-dc); docker rm -f them when done.
"""

import argparse
import os
import shutil
import socket
import subprocess
import sys
import threading

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HERE = os.path.join(ROOT, "scripts", "interop")
IMAGE = "gs-samba"
PASSWORD = "Alice-smb-pw1"      # the test user's, on the test servers only
PLAIN, STRICT, DC = 4451, 4452, 4453
DIALECTS = ["2.0.2", "2.1", "3.0", "3.0.2", "3.1.1"]

passed = 0
failed = []


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def run(cmd, env=None, timeout=300, cwd=None):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=cwd)
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


# --- A man in the middle ---------------------------------------------------------------

class Proxy:
    """Forwards one connection to the server, changing the server's n-th
    message (1: the NEGOTIATE response) with `mutate`."""

    def __init__(self, port, n, mutate):
        self.target, self.n, self.mutate = port, n, mutate
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    @staticmethod
    def frames(src):
        buf = b""
        while True:
            while len(buf) < 4 or len(buf) < 4 + int.from_bytes(buf[1:4], "big"):
                d = src.recv(65536)
                if not d:
                    return
                buf += d
            n = 4 + int.from_bytes(buf[1:4], "big")
            yield buf[4:n]
            buf = buf[n:]

    def serve(self):
        try:
            cli, _ = self.sock.accept()
            srv = socket.create_connection(("127.0.0.1", self.target))
        except OSError:
            return

        def up():
            try:
                while True:
                    d = cli.recv(65536)
                    if not d:
                        break
                    srv.sendall(d)
            except OSError:
                pass

        threading.Thread(target=up, daemon=True).start()
        try:
            for i, m in enumerate(self.frames(srv), 1):
                if i == self.n:
                    m = self.mutate(bytearray(m))
                cli.sendall(len(m).to_bytes(4, "big") + bytes(m))
        except OSError:
            pass
        for s in (cli, srv):
            s.close()


def flip(at):
    def f(m):
        m[at if at >= 0 else len(m) + at] ^= 0x01
        return m
    return f


def unsign(m):
    m[16] &= ~0x08
    m[48:64] = bytes(16)
    return m


def clear_cap(bit):
    def f(m):
        m[64 + 24] &= ~bit
        return m
    return f


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--work", default=os.path.abspath("smb-interop"))
    ap.add_argument("--no-setup", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)

    if not args.no_setup:
        rc, out = run(["sh", os.path.join(HERE, "samba.sh"), work, PASSWORD], timeout=1800)
        if rc != 0:
            sys.exit("cannot start Samba:\n" + out)

    tool = os.path.join(work, "smbclient")
    p = subprocess.run([goose, "build", "-o", tool, os.path.join("tools", "smbclient.goose")],
                       cwd=ROOT, capture_output=True, text=True, timeout=900)
    if p.returncode != 0:
        sys.exit(f"cannot build smbclient:\n{p.stdout}{p.stderr}")

    env = dict(os.environ, SMB_PASSWORD=PASSWORD)
    krb5conf = os.path.join(work, "krb5.conf")
    with open(krb5conf, "w") as f:
        f.write("[libdefaults]\n  default_realm = SMB.TEST\n  dns_lookup_kdc = false\n  dns_lookup_realm = false\n"
                "[realms]\n  SMB.TEST = {\n    kdc = 127.0.0.1:8853\n  }\n")
    env["KRB5_CONFIG"] = krb5conf

    big = os.path.join(work, "big.bin")
    with open(big, "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024 + 12345))
    small = os.path.join(work, "small.txt")
    with open(small, "w") as f:
        f.write("hello from gslib\n")

    def same(a, b):
        try:
            return open(a, "rb").read() == open(b, "rb").read()
        except OSError:
            return False

    def smb(port, share, *cmds, opts=(), environ=None):
        argv = [tool, "--port", str(port), *opts, f"//127.0.0.1/{share}"]
        for i, c in enumerate(cmds):
            if i:
                argv.append(";")
            argv.extend(c.split())
        return run(argv, env=environ or env, cwd=work)

    def samba_client(port, share, cmd):
        return run(["docker", "run", "--rm", "--network", "host", "-v", f"{work}:/w", IMAGE, "smbclient",
                    f"//127.0.0.1/{share}", "-p", str(port), "-U", f"alice%{PASSWORD}", "-c", cmd])

    # --- Every dialect, NTLMv2 ---------------------------------------------------------
    for d in DIALECTS:
        dd = "d" + d.replace(".", "")
        back = os.path.join(work, f"big-{dd}.back")
        rc, out = smb(PLAIN, "pub", "info", f"mkdir {dd}", f"put small.txt {dd}/a.txt", f"put big.bin {dd}/big.bin",
                      f"ls {dd}", f"stat {dd}/big.bin", f"get {dd}/big.bin big-{dd}.back", f"mv {dd}/a.txt {dd}/b.txt",
                      f"truncate {dd}/b.txt 5", f"touch {dd}/c", "df", "echo", opts=["--dialect", d])
        sig = "HMAC-SHA256" if d.startswith("2") else ("AES-128-GMAC" if d == "3.1.1" else "AES-128-CMAC")
        ok = rc == 0 and f"dialect {d}\n" in out and f"signing {sig}" in out and same(big, back) and \
            "size 5\n" in out and "echo ok" in out and "big.bin" in out and "total " in out
        if d in ("3.0", "3.0.2"):
            ok = ok and "validated yes" in out
        check(f"{d}: files, directories, {sig}", ok, out)
        # Samba reads what we wrote; we read what Samba wrote.
        rc, out = samba_client(PLAIN, "pub", f"get {dd}/big.bin /w/big-{dd}.samba")
        check(f"{d}: Samba's smbclient reads our file", same(big, os.path.join(work, f"big-{dd}.samba")), out)
        rc, out = samba_client(PLAIN, "pub", f"put /w/small.txt {dd}/from-samba.txt")
        rc, out = smb(PLAIN, "pub", f"cat {dd}/from-samba.txt", f"ls {dd}", opts=["--dialect", d])
        check(f"{d}: we read Samba's file", rc == 0 and out.startswith("hello from gslib") and "from-samba.txt" in out, out)
        rc, out = smb(PLAIN, "pub", f"rm {dd}/b.txt", f"rm {dd}/c", f"rm {dd}/big.bin", f"rm {dd}/from-samba.txt",
                      f"rmdir {dd}", "ls", opts=["--dialect", d])
        check(f"{d}: rm, rmdir", rc == 0 and dd not in out, out)

    # --- 3.1.1's signing algorithms; small and large I/O ---------------------------------
    for alg, name in (("aes-gmac", "AES-128-GMAC"), ("aes-cmac", "AES-128-CMAC")):
        rc, out = smb(PLAIN, "pub", "info", "put big.bin s.bin", "get s.bin s.back", "rm s.bin", opts=["--signing", alg])
        check(f"3.1.1 signing {name}", rc == 0 and f"signing {name}" in out and same(big, os.path.join(work, "s.back")), out)
    for io in ("65536", "8388608"):
        rc, out = smb(PLAIN, "pub", "put big.bin io.bin", "get io.bin io.back", "rm io.bin", opts=["--max-io", io])
        check(f"3.1.1 READ and WRITE of up to {io} bytes", rc == 0 and same(big, os.path.join(work, "io.back")), out)

    # --- Encryption -------------------------------------------------------------------------
    for d, ciphers in (("3.0", ["aes-128-ccm"]), ("3.0.2", ["aes-128-ccm"]),
                       ("3.1.1", ["aes-128-gcm", "aes-128-ccm", "aes-256-gcm", "aes-256-ccm"])):
        for ci in ciphers:
            rc, out = smb(PLAIN, "pub", "info", "put big.bin e.bin", "get e.bin e.back", "rm e.bin",
                          opts=["--dialect", d, "--encrypt", "--cipher", ci])
            check(f"{d} encrypted ({ci}), client's choice",
                  rc == 0 and f"encryption {ci.upper()}" in out and same(big, os.path.join(work, "e.back")), out)
    for d in ("3.0", "3.0.2", "3.1.1"):
        rc, out = smb(PLAIN, "enc", "info", "put small.txt s.txt", "cat s.txt", "rm s.txt", opts=["--dialect", d])
        check(f"{d} share that requires encryption", rc == 0 and "(the share's)" in out and "hello from gslib" in out, out)
        rc, out = smb(STRICT, "pub", "info", "put big.bin x.bin", "get x.bin x.back", "rm x.bin",
                      opts=["--dialect", d, "--no-sign"])
        check(f"{d} server that requires signing and encryption",
              rc == 0 and "encryption AES-128" in out and same(big, os.path.join(work, "x.back")), out)
    rc, out = smb(PLAIN, "enc", "ls", opts=["--dialect", "2.1"])
    check("2.1 on a share that requires encryption: refused", rc == 2 and "STATUS_ACCESS_DENIED" in out, out)
    rc, out = smb(STRICT, "pub", "ls", opts=["--dialect", "2.1"])
    check("2.1 on a server that requires encryption: refused", rc == 2 and "STATUS_ACCESS_DENIED" in out, out)
    rc, out = smb(PLAIN, "pub", "ls", opts=["--dialect", "2.1", "--encrypt"])
    check("encryption required of 2.1: refused", rc == 2 and "not supported" in out, out)

    # --- Kerberos and the AD DC ---------------------------------------------------------------
    krb = ["--kerberos", "-U", "alice@SMB.TEST", "--spn-host", "dc.smb.test"]
    rc, out = smb(DC, "pub", "info", "put big.bin k.bin", "get k.bin k.back", "rm k.bin",
                  opts=[*krb, "--encrypt", "--cipher", "aes-256-gcm"])
    check("Kerberos, 3.1.1, AES-256-GCM", rc == 0 and "encryption AES-256-GCM" in out and same(big, os.path.join(work, "k.back")),
          out)
    for d in ("3.0", "2.1"):
        rc, out = smb(DC, "pub", "info", "put small.txt k.txt", "cat k.txt", "rm k.txt", opts=[*krb, "--dialect", d])
        check(f"Kerberos, {d}", rc == 0 and f"dialect {d}\n" in out and "hello from gslib" in out, out)
    rc, out = smb(DC, "pub", "ls", opts=krb, environ=dict(env, SMB_PASSWORD="wrong"))
    check("Kerberos, wrong password: no ticket", rc == 2 and "Kerberos" in out, out)
    rc, out = smb(DC, "pub", "info", "echo", opts=["-U", "SMBTEST\\alice"])
    check("NTLM as a domain user on the DC", rc == 0 and "echo ok" in out, out)

    # --- Anonymous ---------------------------------------------------------------------------
    rc, out = smb(PLAIN, "IPC$", "echo", opts=["--anonymous", "--no-sign"])
    check("anonymous session, IPC$", rc == 0 and "echo ok" in out, out)
    rc, out = smb(PLAIN, "IPC$", "echo", opts=["--anonymous"])
    check("anonymous session with signing required: refused", rc == 2 and "not supported" in out, out)

    # --- Refusals ------------------------------------------------------------------------------
    rc, out = smb(PLAIN, "pub", "ls", environ=dict(env, SMB_PASSWORD="wrong"))
    check("wrong password", rc == 2 and "STATUS_LOGON_FAILURE" in out, out)
    rc, out = smb(PLAIN, "nosuch", "ls")
    check("unknown share", rc == 2 and "STATUS_BAD_NETWORK_NAME" in out, out)
    rc, out = smb(PLAIN, "pub", "get no/such/file")
    check("missing file", rc == 1 and ("STATUS_OBJECT_PATH_NOT_FOUND" in out or "STATUS_OBJECT_NAME_NOT_FOUND" in out), out)

    # --- A man in the middle -------------------------------------------------------------------
    # Server messages: 1 NEGOTIATE, 2 and 3 SESSION_SETUP, 4 TREE_CONNECT,
    # 5 the first command's CREATE. First the proxy changing nothing.
    px = Proxy(PLAIN, 0, None)
    rc, out = smb(px.port, "pub", "ls")
    check("through the proxy, unchanged", rc == 0, out)
    for label, n, mutate, opts, want in [
        ("a signature changed", 5, flip(50), [], "bad or missing signature"),
        ("a signature removed", 5, unsign, [], "bad or missing signature"),
        ("the final SESSION_SETUP signature changed", 3, flip(50), [], "bad or missing signature"),
        ("an encrypted response changed", 5, flip(-1), ["--encrypt"], "bad or missing encryption"),
        ("3.1.1 NEGOTIATE changed (preauth hash)", 1, clear_cap(0x04), [], "bad or missing signature"),
        ("3.0 NEGOTIATE changed (validate-negotiate)", 1, clear_cap(0x04), ["--dialect", "3.0"], "dialect negotiation failed"),
        ("3.0 NEGOTIATE's security mode changed", 1, flip(66), ["--dialect", "3.0", "--no-sign"],
         "dialect negotiation failed"),
    ]:
        px = Proxy(PLAIN, n, mutate)
        rc, out = smb(px.port, "pub", "ls", opts=opts)
        check(f"man in the middle: {label} -> refused", rc != 0 and want in out, out)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
