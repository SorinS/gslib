#!/usr/bin/env python3
"""tpm2 against live TPMs, each started here on 127.0.0.1 and stopped:

  tpmemu   the Sail TPM's emulator ($TPMEMU, else tpmemu on PATH), over raw
           TCP (TPM_PORT) and the Microsoft simulator's protocol
           (TPM_MSSIM_PORT, its platform channel on the next port)
  swtpm    swtpm socket --tpm2 (on PATH), raw TCP; and, when swtpm_setup can
           provision one, a second swtpm with EK certificates in NV

Against each: scripts/live.goose (every command of tpm2, each result checked
in software), and goose-tpm's commands; against swtpm also
scripts/signer.goose (keys that never leave the TPM signing certificates, a
CSR, TLS and SSH handshakes and a JWT through tpm2::sign_data). Then goose-tpm against a fake TPM
whose responses lie (oversized, truncated, a wrong tag, a TPM2B past the end):
each must be refused, never believed or crashed on.

tpmemu deviates from the TPM Library specification in ways swtpm does not;
those checks are listed in KNOWN_TPMEMU with the reason, and are reported
as "known" rather than failing the run (tpm2/README.md, Quirks). A TPM not
installed is skipped.

    python3 scripts/interop.py [--goose PATH] [--only tpmemu|swtpm|hostile] [-v]
"""

import argparse
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# tpmemu checks that fail for its deviations from the specification:
# a substring of the check's name, and why.
KNOWN_TPMEMU = [
    ("again: the same key", "primary keys are random, not derived from the hierarchy's seed (Part 1 §28.3)"),
    ("RSA_Decrypt of software RSA-OAEP", "RSA_Encrypt/RSA_Decrypt ignore the OAEP label and hash"),
    ("CreateLoaded HMAC key", "KEYEDHASH signing keys refused with TPM_RC_AUTH_TYPE"),
    ("bound session: the signature verifies", "a bound session's parameter-encryption key leaves out the authValue (Part 1 §21.1)"),
    ("StartAuthSession trial", "trial sessions refused with TPM_RC_VALUE"),
    ("Unseal with a wrong authValue", "PolicyAuthValue's HMAC not checked"),
    ("Unseal after PCR_Extend fails", "a policy session's digest is never compared with the authPolicy"),
    ("CertifyCreation RSA verified", "CertifyCreation takes its handles in the wrong order; no creation data"),
    ("CertifyCreation ECC verified", "CertifyCreation takes its handles in the wrong order; no creation data"),
    ("ActivateCredential (ECC EK)", "ActivateCredential with an ECC EK fails"),
    ("ActivateCredential of the TPM's (ECC)", "ActivateCredential with an ECC EK fails"),
    ("tool: unseal", "a new SRK each process (random primaries): blobs do not load again"),
    ("tool: sign", "a new SRK each process (random primaries): blobs do not load again"),
]


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def free_ports(n):
    """A base port with n free ports after it."""
    for _ in range(50):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        base = s.getsockname()[1]
        s.close()
        if base + n > 65535:
            continue
        ok = True
        for p in range(base, base + n):
            t = socket.socket()
            try:
                t.bind(("127.0.0.1", p))
            except OSError:
                ok = False
            finally:
                t.close()
        if ok:
            return base
    sys.exit("no free ports")


def wait_port(port, proc, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


class Results:
    def __init__(self, verbose):
        self.passed = 0
        self.failed = []
        self.known = []
        self.skipped = []
        self.verbose = verbose

    def ok(self, label):
        self.passed += 1
        if self.verbose:
            print(f"ok    {label}")

    def fail(self, label, why, known_list=None):
        for sub, reason in known_list or []:
            if sub in label:
                self.known.append(label)
                print(f"known {label}: {reason}")
                return
        self.failed.append(label)
        print(f"FAIL  {label}" + (f": {why}" if why else ""))

    def skip(self, label, why):
        self.skipped.append(label)
        print(f"skip  {label}: {why}")


def run_live(goose, spec, label, res, known, extra=(), script="live.goose"):
    p = subprocess.run([goose, os.path.join("scripts", script), "--", "--tpm", spec, *extra],
                       cwd=ROOT, capture_output=True, text=True, timeout=900)
    seen = False
    for line in p.stdout.splitlines():
        if line.startswith("ok    "):
            res.ok(f"{label}: {line[6:]}")
            seen = True
        elif line.startswith("FAIL  "):
            # Names have ": " in them too: match the known ones on the whole line.
            res.fail(f"{label}: {line[6:]}", "", known)
            seen = True
        elif line.startswith("skip  "):
            name, _, why = line[6:].partition(": ")
            res.skip(f"{label}: {name}", why)
    if not seen or "runtime error" in p.stderr or p.returncode not in (0, 1):
        res.fail(f"{label}: {script} ran", (p.stderr or p.stdout).strip()[-400:])


def tool(cmd, tmp, *args, ok=True):
    p = subprocess.run([cmd, *args], cwd=tmp, capture_output=True, timeout=300)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


def run_tool(gt, spec, label, tmp, res, known):
    T = lambda *a: tool(gt, tmp, "--tpm", spec, *a)

    def want(name, cond, why=""):
        if cond:
            res.ok(f"{label}: tool: {name}")
        else:
            res.fail(f"{label}: tool: {name}", why, known)

    rc, out, err = T("getrandom", "32")
    want("getrandom", rc == 0 and len(out.strip()) == 64, err)
    rc, out, err = T("pcrread", "--pcrs", "0-3,16")
    want("pcrread", rc == 0 and out.count(b"\n") == 6, err)
    rc, out, err = T("pcrextend", "--pcrs", "16", "--data", "interop")
    want("pcrextend", rc == 0 and out.startswith(b"sha256:16 "), err)
    q = os.path.join(tmp, "q")
    rc, out, err = T("quote", "--nonce", "a1b2c3d4", "--pcrs", "0-7,16", "--out", q)
    want("quote", rc == 0, err)
    rc, out, err = tool(gt, tmp, "verify-quote", "--in", q, "--nonce", "a1b2c3d4", "--pcrs", "0-7,16")
    want("verify-quote", rc == 0 and b"quote verified" in out, err)
    rc, out, err = tool(gt, tmp, "verify-quote", "--in", q, "--nonce", "a1b2c3d5", "--pcrs", "0-7,16")
    want("verify-quote with another nonce refused", rc == 1 and "nonce" in err, err)
    pin = os.path.join(tmp, "pin")
    with open(pin, "w") as f:
        f.write("1234\n")
    sealed = os.path.join(tmp, "sealed")
    rc, out, err = T("seal", "--data", "interop secret", "--pcrs", "16", "--auth-file", pin, "--out", sealed)
    want("seal", rc == 0, err)
    rc, out, err = T("unseal", "--in", sealed, "--pcrs", "16", "--auth-file", pin)
    want("unseal", rc == 0 and out == b"interop secret", err)
    T("pcrextend", "--pcrs", "16", "--data", "something else")
    rc, out, err = T("unseal", "--in", sealed, "--pcrs", "16", "--auth-file", pin)
    want("unseal after pcrextend refused", rc == 1 and "POLICY_FAIL" in err, err or out.decode(errors="replace"))
    key = os.path.join(tmp, "key")
    rc, out, err = T("createkey", "--ecc", "--out", key)
    want("createkey", rc == 0 and b"BEGIN PUBLIC KEY" in out, err)
    msg = os.path.join(tmp, "msg")
    with open(msg, "w") as f:
        f.write("to be signed\n")
    rc, out, err = T("sign", "--key", key, "--in", msg)
    want("sign", rc == 0 and out[:1] == b"\x30", err)
    rc, out, err = T("ekpub")
    want("ekpub", rc == 0 and b"BEGIN PUBLIC KEY" in out, err)
    idx = "0x01500050"
    T("nvundefine", "--index", idx)
    rc, out, err = T("nvdefine", "--index", idx, "--size", "16")
    want("nvdefine", rc == 0, err)
    rc, out, err = T("nvwrite", "--index", idx, "--data", "nv interop")
    want("nvwrite", rc == 0, err)
    rc, out, err = T("nvread", "--index", idx, "--size", "10")
    want("nvread", rc == 0 and out.strip() == b"nv interop".hex().encode(), err)
    rc, out, err = T("nvlist")
    want("nvlist", rc == 0 and b"0x1500050" in out, err)
    rc, out, err = T("nvundefine", "--index", idx)
    want("nvundefine", rc == 0, err)


# --- A TPM whose responses lie --------------------------------------------------

def hdr(tag, size, rc):
    return struct.pack(">HII", tag, size, rc)


STARTUP_OK = hdr(0x8001, 10, 0)
LIES = [
    ("a response larger than any TPM's", hdr(0x8001, 0x100000, 0) + b"\0" * 64),
    ("a size smaller than its header", hdr(0x8001, 6, 0)),
    ("a response cut short", hdr(0x8001, 30, 0) + b"\0\x10" + b"\xaa" * 5),
    ("a wrong tag", hdr(0x1234, 12, 0) + b"\0\0"),
    ("a TPM2B past the end", hdr(0x8001, 14, 0) + b"\x00\xc8\xaa\xbb"),
    ("more random bytes than asked for", hdr(0x8001, 12 + 40, 0) + b"\x00\x28" + b"\x11" * 40),
    ("bytes after the parameters", hdr(0x8001, 12 + 8 + 1, 0) + b"\x00\x08" + b"\x11" * 8 + b"!"),
    ("an error code with parameters", hdr(0x8001, 14, 0x101) + b"\0\0\0\0"),
    ("a session area to a command without sessions", hdr(0x8002, 22, 0) + b"\0\0\0\x0a\x00\x08" + b"\x11" * 8),
]


class Liar:
    """Answers Startup, then the lie, on each connection; one lie a connection."""

    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.port = self.sock.getsockname()[1]
        self.lie = b""
        self.stopped = False
        threading.Thread(target=self.serve, daemon=True).start()

    def read_cmd(self, c):
        h = b""
        while len(h) < 10:
            d = c.recv(10 - len(h))
            if not d:
                return False
            h += d
        n = struct.unpack(">HII", h)[1] - 10
        while n > 0:
            d = c.recv(n)
            if not d:
                return False
            n -= len(d)
        return True

    def serve(self):
        while not self.stopped:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            try:
                if self.read_cmd(c):
                    c.sendall(STARTUP_OK)
                    if self.read_cmd(c):
                        c.sendall(self.lie)
                time.sleep(0.05)
            except OSError:
                pass
            finally:
                c.close()

    def close(self):
        self.stopped = True
        self.sock.close()


def run_hostile(gt, tmp, res):
    liar = Liar()
    try:
        for name, lie in LIES:
            liar.lie = lie
            rc, out, err = tool(gt, tmp, "--tpm", f"tcp:127.0.0.1:{liar.port}", "getrandom", "8")
            good = rc == 1 and not out and ("malformed" in err or "transport" in err or "refused" in err)
            if good:
                res.ok(f"hostile: {name} refused")
            else:
                res.fail(f"hostile: {name} refused", f"exit {rc}, stdout {out[:40]!r}, stderr {err.strip()[:200]}")
    finally:
        liar.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--only")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    res = Results(args.v)
    tmp = tempfile.mkdtemp(prefix="tpm2-interop-")
    procs = []
    try:
        gt = os.path.join(tmp, "goose-tpm")
        b = subprocess.run([goose, "build", "-o", gt, os.path.join("tools", "tpm.goose")], cwd=ROOT,
                           capture_output=True, text=True)
        if b.returncode != 0:
            sys.exit("cannot build goose-tpm:\n" + b.stdout + b.stderr)

        if args.only in (None, "hostile"):
            run_hostile(gt, tmp, res)

        if args.only in (None, "tpmemu"):
            emu = os.environ.get("TPMEMU") or shutil.which("tpmemu")
            if not emu or not os.path.isfile(emu):
                res.skip("tpmemu", "not found: set TPMEMU to the tpmemu binary")
            else:
                for mode in ("tcp", "mssim"):
                    base = free_ports(2)
                    d = os.path.join(tmp, f"tpmemu-{mode}")
                    os.makedirs(d)
                    env = dict(os.environ, TPM_NV_FILE=os.path.join(d, "nvchip"))
                    env["TPM_PORT" if mode == "tcp" else "TPM_MSSIM_PORT"] = str(base)
                    log = open(os.path.join(d, "log"), "w")
                    p = subprocess.Popen([emu], cwd=d, env=env, stdout=log, stderr=log, stdin=subprocess.DEVNULL)
                    procs.append(p)
                    if not wait_port(base, p) or (mode == "mssim" and not wait_port(base + 1, p)):
                        res.fail(f"tpmemu {mode}", "did not start")
                        continue
                    spec = f"{mode}:127.0.0.1:{base}"
                    print(f">> tpmemu over {mode} ({spec})", flush=True)
                    run_live(goose, spec, f"tpmemu {mode}", res, KNOWN_TPMEMU)
                    run_tool(gt, spec, f"tpmemu {mode}", d, res, KNOWN_TPMEMU)
                    stop(p)

        if args.only in (None, "swtpm"):
            sw = shutil.which("swtpm")
            if not sw:
                res.skip("swtpm", "not on PATH")
            else:
                states = [("swtpm", None)]
                setup = shutil.which("swtpm_setup")
                if setup:
                    d = os.path.join(tmp, "swtpm-ek")
                    os.makedirs(os.path.join(d, "state"))
                    env = dict(os.environ, XDG_CONFIG_HOME=os.path.join(d, "config"))
                    a = subprocess.run([setup, "--create-config-files", "skip-if-exist"], env=env, capture_output=True)
                    s = subprocess.run([setup, "--tpm2", "--tpmstate", os.path.join(d, "state"), "--create-ek-cert",
                                        "--config", os.path.join(d, "config", "swtpm_setup.conf"),
                                        "--pcr-banks", "sha1,sha256"], env=env, capture_output=True, text=True)
                    if s.returncode == 0:
                        states.append(("swtpm with EK certificates", os.path.join(d, "state")))
                    else:
                        res.skip("swtpm EK certificates", "swtpm_setup could not provision: " + s.stderr.strip()[-200:])
                for label, state in states:
                    d = state or os.path.join(tmp, "swtpm")
                    os.makedirs(d, exist_ok=True)
                    base = free_ports(2)
                    log = open(os.path.join(tmp, label.replace(" ", "-") + ".log"), "w")
                    p = subprocess.Popen([sw, "socket", "--tpm2", "--server", f"type=tcp,port={base},bindaddr=127.0.0.1",
                                          "--ctrl", f"type=tcp,port={base + 1},bindaddr=127.0.0.1",
                                          "--tpmstate", f"dir={d}", "--flags", "not-need-init,startup-clear"],
                                         stdout=log, stderr=log, stdin=subprocess.DEVNULL)
                    procs.append(p)
                    if not wait_port(base, p):
                        res.fail(label, "did not start")
                        continue
                    spec = f"tcp:127.0.0.1:{base}"
                    print(f">> {label} ({spec})", flush=True)
                    if state:
                        run_live(goose, spec, label, res, [], ("--only", "ekcert", "--ek-cert"))
                        rc, out, err = tool(gt, tmp, "--tpm", spec, "ekcert")
                        if rc == 0 and b"BEGIN CERTIFICATE" in out:
                            res.ok(f"{label}: tool: ekcert")
                        else:
                            res.fail(f"{label}: tool: ekcert", err)
                    else:
                        run_live(goose, spec, label, res, [])
                        run_live(goose, spec, f"{label} signer", res, [], script="signer.goose")
                        run_tool(gt, spec, label, tmp, res, [])
                    stop(p)
    finally:
        for p in procs:
            stop(p)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"\n{res.passed} passed, {len(res.failed)} failed, {len(res.known)} known tpmemu deviations, "
          f"{len(res.skipped)} skipped")
    sys.exit(1 if res.failed else 0)


if __name__ == "__main__":
    main()
