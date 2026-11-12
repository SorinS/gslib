#!/usr/bin/env python3
"""dns against other implementations, over the network on 127.0.0.1:

1. dig (BIND's) against goose-dnsd: answers, CNAMEs, NXDOMAIN, wildcards,
   referrals, truncation, and a TSIG-signed AXFR in several messages,
   which dig verifies;
2. miekg/dns's client against goose-dnsd (scripts/oracle, "client"):
   UDP and TCP, truncation, TSIG-signed queries, an AXFR whose every
   message miekg's Transfer verifies, a signed update;
3. goose-dig against a miekg/dns server (scripts/oracle, "serve"):
   answers, truncation and TCP fallback, a TSIG-signed query, and a
   TSIG-signed AXFR from miekg's Transfer.Out.

Needs Go (the oracle module is scripts/oracle); dig is skipped if absent.

    python3 scripts/interop.py [--goose PATH]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ORACLE = os.path.join(ROOT, "scripts", "oracle")
KEY = "xfr.example."
SECRET = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng=="

failures = 0


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def check(what, ok, detail=""):
    global failures
    print(("ok   " if ok else "FAIL ") + what)
    if not ok:
        failures += 1
        if detail:
            print("     " + detail.strip()[-1500:].replace("\n", "\n     "))


def build(goose, tool, out):
    p = subprocess.run([goose, "build", "-o", out, tool + ".goose"], cwd=os.path.join(ROOT, "tools"),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"cannot build {tool}:\n{p.stdout}{p.stderr}")


def start(cmd, cwd=None):
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if not line.startswith("listening on "):
        p.kill()
        sys.exit(f"{cmd[0]} did not start: {line}{p.stderr.read()}")
    return p, line.split()[-1]


def dig(port, *args):
    p = subprocess.run(["dig", "@127.0.0.1", "-p", port, *args], capture_output=True, text=True, timeout=60)
    return p.stdout


def with_dig(port):
    out = dig(port, "+short", "ns1.example.org", "A")
    check("dig: A", out.strip() == "192.0.2.1", out)
    out = dig(port, "+short", "alias.example.org", "A")
    check("dig: CNAME chain", out.split() == ["www.example.org.", "web.example.org.", "host.example.net."], out)
    out = dig(port, "nope.example.org", "A")
    check("dig: NXDOMAIN", "status: NXDOMAIN" in out and "SOA" in out, out)
    out = dig(port, "+short", "a.b.wild.example.org", "TXT")
    check("dig: wildcard", out.strip() == '"wildcard"', out)
    out = dig(port, "host.sub.example.org", "A")
    check("dig: referral", "sub.example.org.\t3600\tIN\tNS\tns.sub.example.org." in out and "192.0.2.4" in out, out)
    out = dig(port, "+ignore", "+bufsize=512", "big.example.org", "TXT")
    check("dig: truncated", " tc" in out.split("flags:")[1].split(";")[0], out)
    out = dig(port, "+tcp", "big.example.org", "TXT")
    check("dig: over TCP", "ANSWER: 6" in out, out)
    out = dig(port, "example.org", "AXFR", "-y", f"hmac-sha256:{KEY}:{SECRET}")
    check("dig: AXFR with TSIG", "XFR size: 5024 records" in out and "Transfer failed" not in out
          and "tsig verify failure" not in out.lower(), out)
    out = dig(port, "example.org", "AXFR")
    check("dig: AXFR unsigned refused", "Transfer failed" in out, out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("go"):
        sys.exit("go not found")
    zone = os.path.join(ROOT, "test", "vectors", "zones", "served.zone")
    with tempfile.TemporaryDirectory() as tmp:
        dnsd = os.path.join(tmp, "goose-dnsd")
        godig = os.path.join(tmp, "goose-dig")
        oracle = os.path.join(tmp, "oracle")
        build(goose, "dnsd", dnsd)
        build(goose, "dig", godig)
        p = subprocess.run(["go", "build", "-o", oracle, "."], cwd=ORACLE, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("cannot build the oracle:\n" + p.stderr)

        def serve_goose():
            return start([dnsd, "-a", "127.0.0.1", "-p", "0", "-y", f"{KEY}:{SECRET}", f"example.org.={zone}"])

        # 1. dig against goose-dnsd.
        if shutil.which("dig"):
            srv, port = serve_goose()
            try:
                with_dig(port)
            finally:
                srv.kill()
        else:
            print("skip dig: not found")

        # 2. miekg's client against goose-dnsd.
        srv, port = serve_goose()
        try:
            p = subprocess.run([oracle, "client", port], capture_output=True, text=True, timeout=120)
            for line in p.stdout.splitlines():
                check("miekg client: " + line[5:], line.startswith("ok"), line)
            check("miekg client ran", p.returncode == 0 or "FAIL" in p.stdout, p.stderr)
        finally:
            srv.kill()

        # 3. goose-dig against a miekg server.
        srv, port = start([oracle, "serve"])
        try:
            def gd(*a):
                p = subprocess.run([godig, f"@127.0.0.1", "-p", port, *a], capture_output=True, text=True, timeout=120)
                return p.returncode, p.stdout + p.stderr

            rc, out = gd("+short", "www.example.com", "A")
            check("goose-dig: A from miekg", rc == 0 and out.strip() == "192.0.2.99", out)
            rc, out = gd("big.example.com", "TXT")
            check("goose-dig: truncated, then TCP", rc == 0 and "ANSWER: 8" in out and " tc" not in out, out)
            rc, out = gd("-y", f"hmac-sha256:{KEY}:{SECRET}", "+short", "secret.example.com", "TXT")
            check("goose-dig: TSIG-signed query", rc == 0 and out.strip() == '"signed"', out)
            rc, out = gd("-y", f"hmac-sha256:{KEY}:c2VjcmV0", "secret.example.com", "TXT")
            check("goose-dig: wrong TSIG secret refused", rc != 0, out)
            rc, out = gd("-y", f"hmac-sha384:{KEY}:{SECRET}", "example.com", "AXFR")
            check("goose-dig: AXFR with TSIG from miekg", rc == 0 and "XFR size: 3002 records" in out, out)
            rc, out = gd("example.com", "AXFR")
            check("goose-dig: AXFR unsigned from miekg", rc == 0 and "XFR size: 3002 records" in out, out)
        finally:
            srv.kill()

    print(f"\n{'all passed' if failures == 0 else str(failures) + ' failed'}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
