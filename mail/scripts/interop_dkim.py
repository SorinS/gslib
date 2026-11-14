#!/usr/bin/env python3
"""mail.dkim against dkimpy: `goose-mail dkim` (mail/tools/mail.goose) signs
and dkimpy verifies, and dkimpy signs and goose-mail verifies, for RSA-SHA256
(2048 bits) and Ed25519-SHA256, under all four canonicalizations; then l=,
i=, a changed body, rsa-sha1 (refused unless --allow-sha1), and the key
records goose-mail writes. dkimpy gets the keys through its dnsfunc, never
DNS. Last, goose-mail looks the keys up for real (dns.client) in goose-dnsd
(dns/tools/dnsd.goose) serving a zone on 127.0.0.1.

dkimpy (`pip install dkimpy pynacl`) is run by $DKIMPY_PYTHON, a python
that can `import dkim`, else by this python; without it, the cases that
need it are skipped. openssl makes the keys.

    python3 scripts/interop_dkim.py [--goose PATH] [-k NAME]
"""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DOMAIN = "example.com"
NOW = "1711929600"
only = None
results = {"passed": 0, "failed": 0}
skipped = []

MESSAGE = (b"From: Alice <alice@example.com>\r\n"
           b"To: Bob <bob@example.org>\r\n"
           b"Subject: Interop  test\r\n"
           b"Date: Mon, 01 Apr 2024 00:00:00 +0000\r\n"
           b"Message-ID: <interop-1@example.com>\r\n"
           b"MIME-Version: 1.0\r\n"
           b"Content-Type: text/plain; charset=UTF-8\r\n"
           b"\r\n"
           b"Hello Bob,  \r\n"
           b"\r\n"
           b"the  plans\tare attached.\r\n"
           b"\r\n"
           b"\r\n")

CANONS = ["simple/simple", "simple/relaxed", "relaxed/simple", "relaxed/relaxed"]

# Run by dkimpy's python: one request (JSON on stdin), one answer (JSON on stdout).
HELPER = r'''
import base64, json, sys
import dkim
req = json.load(sys.stdin)
msg = base64.b64decode(req["msg"])
if req["op"] == "sign":
    h, b = req["canon"].split("/")
    try:
        sig = dkim.sign(msg, req["selector"].encode(), req["domain"].encode(), req["key"].encode(),
                        identity=req["identity"].encode() if req.get("identity") else None,
                        canonicalize=(h.encode(), b.encode()), signature_algorithm=req["alg"].encode(),
                        length=req.get("length", False))
        print(json.dumps({"ok": True, "msg": base64.b64encode(sig + msg).decode()}))
    except Exception as e:
        print(json.dumps({"ok": False, "error": "%s: %s" % (type(e).__name__, e)}))
else:
    records = {k.encode(): v.encode() for k, v in req["records"].items()}
    def dnsfunc(name, timeout=5):
        return records.get(name.rstrip(b"."))
    d = dkim.DKIM(msg, minkey=1024)
    n = sum(1 for k, v in d.headers if k.lower() == b"dkim-signature")
    out = []
    for i in range(n):
        try:
            out.append([bool(d.verify(idx=i, dnsfunc=dnsfunc)), ""])
        except Exception as e:
            out.append([False, "%s: %s" % (type(e).__name__, e)])
    print(json.dumps({"ok": True, "results": out}))
'''


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


# --- The two sides ---------------------------------------------------------------------

TOOL = None
DKIMPY = None          # [python, helper]


def goose_sign(tmp, key_path, selector, canon, extra=()):
    path = os.path.join(tmp, "in.eml")
    with open(path, "wb") as f:
        f.write(MESSAGE)
    p = subprocess.run([TOOL, "dkim", "sign", "--key", key_path, "--domain", DOMAIN, "--selector", selector,
                        "--canon", canon, "--timestamp", NOW, *extra, path], capture_output=True, timeout=60)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


def goose_verify(tmp, msg, record=None, extra=()):
    path = os.path.join(tmp, "verify.eml")
    with open(path, "wb") as f:
        f.write(msg)
    args = [TOOL, "dkim", "verify", "--now", NOW, *extra]
    if record is not None:
        args += ["--record", record]
    p = subprocess.run(args + [path], capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


def dkimpy(req):
    p = subprocess.run(DKIMPY, input=json.dumps(req), capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        return {"ok": False, "error": p.stderr[-2000:]}
    return json.loads(p.stdout)


def dkimpy_sign(msg, key_text, selector, alg, canon, identity=None, length=False):
    r = dkimpy({"op": "sign", "msg": base64.b64encode(msg).decode(), "key": key_text, "selector": selector,
                "domain": DOMAIN, "alg": alg, "canon": canon, "identity": identity or "", "length": length})
    return (base64.b64decode(r["msg"]) if r["ok"] else None), r.get("error", "")


def dkimpy_verify(msg, records):
    r = dkimpy({"op": "verify", "msg": base64.b64encode(msg).decode(),
                "records": {"%s._domainkey.%s" % (s, DOMAIN): v for s, v in records.items()}})
    if not r["ok"]:
        return [[False, r["error"]]]
    return r["results"]


def find_dkimpy(tmp):
    py = os.environ.get("DKIMPY_PYTHON") or sys.executable
    p = subprocess.run([py, "-c", "import dkim, nacl"], capture_output=True)
    if p.returncode != 0:
        return None
    helper = os.path.join(tmp, "dkimpy_helper.py")
    with open(helper, "w") as f:
        f.write(HELPER)
    return [py, "-I", helper]


# --- Keys --------------------------------------------------------------------------------

def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def make_keys(tmp):
    """The keys, as files for goose-mail, text for dkimpy, and records made by
    openssl (not by the code under test)."""
    keys = {}
    rsa = os.path.join(tmp, "rsa.pem")
    openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", rsa)
    spki = openssl("pkey", "-in", rsa, "-pubout", "-outform", "DER")
    keys["rsa"] = {"path": rsa, "text": open(rsa).read(), "alg": "rsa-sha256", "selector": "rsa",
                   "record": "v=DKIM1; k=rsa; p=" + base64.b64encode(spki).decode()}
    ed = os.path.join(tmp, "ed25519.pem")
    openssl("genpkey", "-algorithm", "ed25519", "-out", ed)
    seed = openssl("pkey", "-in", ed, "-outform", "DER")[-32:]
    pub = openssl("pkey", "-in", ed, "-pubout", "-outform", "DER")[-32:]
    keys["ed25519"] = {"path": ed, "text": base64.b64encode(seed).decode(), "alg": "ed25519-sha256",
                       "selector": "ed", "record": "v=DKIM1; k=ed25519; p=" + base64.b64encode(pub).decode()}
    return keys


# --- The cases -----------------------------------------------------------------------------

def records_of(keys):
    return {k["selector"]: k["record"] for k in keys.values()}


def passed(lines):
    return lines.startswith("dkim=pass")


def cross_cases(tmp, keys):
    recs = records_of(keys)
    for name, k in keys.items():
        for canon in CANONS:
            case = "goose signs, dkimpy verifies: %s %s" % (name, canon)
            if wanted(case):
                rc, signed, err = goose_sign(tmp, k["path"], k["selector"], canon)
                if rc != 0:
                    report(case, False, err)
                else:
                    res = dkimpy_verify(signed, recs)
                    report(case, len(res) == 1 and res[0][0], str(res))
            case = "dkimpy signs, goose verifies: %s %s" % (name, canon)
            if wanted(case):
                signed, err = dkimpy_sign(MESSAGE, k["text"], k["selector"], k["alg"], canon)
                if signed is None:
                    report(case, False, err)
                else:
                    rc, out = goose_verify(tmp, signed, k["record"])
                    report(case, rc == 0 and passed(out), out.strip())

    k = keys["ed25519"]
    case = "l=: goose signs, text added, dkimpy verifies"
    if wanted(case):
        rc, signed, err = goose_sign(tmp, k["path"], k["selector"], "relaxed/relaxed", ["--length"])
        res = dkimpy_verify(signed + b"P.S. Unsigned.\r\n", recs) if rc == 0 else [[False, err]]
        report(case, b" l=" in signed and len(res) == 1 and res[0][0], str(res))
    case = "l=: dkimpy signs, text added, goose verifies"
    if wanted(case):
        signed, err = dkimpy_sign(MESSAGE, k["text"], k["selector"], k["alg"], "relaxed/simple", length=True)
        rc, out = goose_verify(tmp, (signed or b"") + b"P.S. Unsigned.\r\n", k["record"])
        report(case, signed is not None and rc == 0 and passed(out), out.strip() or err)
    case = "i=: goose signs, dkimpy verifies"
    if wanted(case):
        rc, signed, err = goose_sign(tmp, k["path"], k["selector"], "relaxed/relaxed",
                                     ["--identity", "alice@mail.example.com"])
        res = dkimpy_verify(signed, recs) if rc == 0 else [[False, err]]
        report(case, len(res) == 1 and res[0][0], str(res))
    case = "i=: dkimpy signs, goose verifies"
    if wanted(case):
        signed, err = dkimpy_sign(MESSAGE, k["text"], k["selector"], k["alg"], "relaxed/relaxed",
                                  identity="alice@mail.example.com")
        rc, out = goose_verify(tmp, signed or b"", k["record"])
        report(case, signed is not None and rc == 0 and passed(out), out.strip() or err)
    case = "a changed body: goose signs, dkimpy fails it"
    if wanted(case):
        rc, signed, err = goose_sign(tmp, k["path"], k["selector"], "relaxed/relaxed")
        res = dkimpy_verify(signed.replace(b"plans", b"pans"), recs) if rc == 0 else [[True, err]]
        report(case, len(res) == 1 and not res[0][0], str(res))
    case = "a changed body: dkimpy signs, goose fails it"
    if wanted(case):
        signed, err = dkimpy_sign(MESSAGE, k["text"], k["selector"], k["alg"], "relaxed/relaxed")
        rc, out = goose_verify(tmp, (signed or b"").replace(b"plans", b"pans"), k["record"])
        report(case, signed is not None and rc == 1 and out.startswith("dkim=fail"), out.strip() or err)

    r = keys["rsa"]
    case = "rsa-sha1: dkimpy signs, goose refuses, then allows"
    if wanted(case):
        signed, err = dkimpy_sign(MESSAGE, r["text"], r["selector"], "rsa-sha1", "relaxed/relaxed")
        if signed is None:
            skipped.append("rsa-sha1: dkimpy would not sign it (%s)" % err)
        else:
            rc1, out1 = goose_verify(tmp, signed, r["record"])
            rc2, out2 = goose_verify(tmp, signed, r["record"], ["--allow-sha1"])
            report(case, rc1 == 1 and "neutral" in out1 and rc2 == 0 and passed(out2), out1 + out2)

    for name, k in keys.items():
        case = "the record goose-mail writes: " + name
        if wanted(case):
            p = subprocess.run([TOOL, "dkim", "record", "--key", k["path"]], capture_output=True, text=True)
            report(case, p.returncode == 0 and p.stdout.strip() == k["record"], p.stdout + p.stderr)


def goose_only_cases(tmp, keys):
    """Without dkimpy: goose-mail both ways, so the tool itself is checked."""
    for name, k in keys.items():
        for canon in CANONS:
            case = "goose signs, goose verifies: %s %s" % (name, canon)
            if wanted(case):
                rc, signed, err = goose_sign(tmp, k["path"], k["selector"], canon)
                rc2, out = goose_verify(tmp, signed, k["record"]) if rc == 0 else (1, err)
                report(case, rc2 == 0 and passed(out), out.strip())


# --- DNS: goose-dnsd -------------------------------------------------------------------------

def txt_strings(text):
    # A TXT record's character-strings are 255 bytes at most.
    return " ".join('"%s"' % text[i:i + 255] for i in range(0, len(text), 255))


def dns_cases(tmp, goose, keys, have_dkimpy):
    if not any(wanted(n) for n in ("dns", "DNS")):
        return
    dnsd = os.path.join(tmp, "goose-dnsd")
    p = subprocess.run([goose, "build", "-o", dnsd, os.path.join(ROOT, "..", "dns", "tools", "dnsd.goose")],
                       capture_output=True, text=True)
    if p.returncode != 0:
        report("dns: build goose-dnsd", False, p.stdout + p.stderr)
        return
    zone = os.path.join(tmp, "example.com.zone")
    with open(zone, "w") as f:
        f.write("$ORIGIN example.com.\n$TTL 300\n"
                "@ IN SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
                "@ IN NS ns1\nns1 IN A 127.0.0.1\n")
        for k in keys.values():
            f.write("%s._domainkey IN TXT %s\n" % (k["selector"], txt_strings(k["record"])))
        f.write("revoked._domainkey IN TXT \"v=DKIM1; k=ed25519; p=\"\n")
    srv = subprocess.Popen([dnsd, "-a", "127.0.0.1", "-p", "0", "example.com.=" + zone],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = srv.stdout.readline()
        if not line.startswith("listening on "):
            report("dns: goose-dnsd started", False, line + srv.stderr.read())
            return
        server = "127.0.0.1:" + line.split()[-1]
        for name, k in keys.items():
            case = "dns: goose verifies with the key from goose-dnsd: " + name
            if wanted(case):
                rc, signed, err = goose_sign(tmp, k["path"], k["selector"], "relaxed/relaxed")
                rc2, out = goose_verify(tmp, signed, None, ["--dns", server]) if rc == 0 else (1, err)
                report(case, rc2 == 0 and passed(out), out.strip())
        k = keys["rsa"]
        if have_dkimpy:
            case = "dns: dkimpy signs (2048-bit RSA, the record in two strings), goose looks it up"
            if wanted(case):
                signed, err = dkimpy_sign(MESSAGE, k["text"], k["selector"], k["alg"], "relaxed/simple")
                rc, out = goose_verify(tmp, signed or b"", None, ["--dns", server])
                report(case, signed is not None and rc == 0 and passed(out), out.strip() or err)
        case = "dns: no record for the selector"
        if wanted(case):
            rc, signed, err = goose_sign(tmp, k["path"], "absent", "relaxed/relaxed")
            rc2, out = goose_verify(tmp, signed, None, ["--dns", server])
            report(case, rc2 == 1 and out.startswith("dkim=temperror"), out.strip())
        case = "dns: a revoked key"
        if wanted(case):
            ed = keys["ed25519"]
            rc, signed, err = goose_sign(tmp, ed["path"], "revoked", "relaxed/relaxed")
            rc2, out = goose_verify(tmp, signed, None, ["--dns", server])
            report(case, rc2 == 1 and out.startswith("dkim=permerror") and "revoked" in out, out.strip())
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=5)
        except subprocess.TimeoutExpired:
            srv.kill()


def main():
    global only, TOOL, DKIMPY
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
        keys = make_keys(tmp)
        DKIMPY = find_dkimpy(tmp)
        if DKIMPY is None:
            skipped.append("dkimpy (pip install dkimpy pynacl; or set DKIMPY_PYTHON to a python that has it)")
            goose_only_cases(tmp, keys)
        else:
            cross_cases(tmp, keys)
        dns_cases(tmp, goose, keys, DKIMPY is not None)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for s in skipped:
        print("skip  " + s)
    print("\n%d passed, %d failed" % (results["passed"], results["failed"]))
    sys.exit(1 if results["failed"] else 0)


if __name__ == "__main__":
    main()
