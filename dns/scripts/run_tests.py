#!/usr/bin/env python3
"""Run dns's tests.

Every test/*.goose runs under the in-process JIT at -O0 and -O2 and with
--debug (overflow, range and bounds checks); a test passes when it exits 0.
--native also builds and runs the tests with the C compiler.

A test whose first line is "// needs: dnsd" gets a server: goose-dnsd
(tools/dnsd.goose, built once, natively) on a free port of 127.0.0.1,
serving test/vectors/zones/served.zone with the TSIG key the tests use, a
fresh one for each run; the port is the test's argument.

    python3 scripts/run_tests.py [--goose PATH] [--native] [-k NAME]

The compiler is --goose, else $GOOSE, else `goose` on PATH, else
../goose.git/build/goose beside gslib.git.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SECRET = "c2VjcmV0IGtleSBmb3IgdGVzdGluZyBUU0lHIDEyMzQ1Ng=="


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def strip_notes(text):
    return "".join(l for l in text.splitlines(True)
                   if not l.startswith(("parsed ok", "typechecked ok", "bce:")))


def build_dnsd(goose, tmp):
    exe = os.path.join(tmp, "goose-dnsd" + (".exe" if os.name == "nt" else ""))
    p = subprocess.run([goose, "build", "-o", exe, "dnsd.goose"], cwd=os.path.join(ROOT, "tools"),
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("cannot build goose-dnsd:\n" + p.stdout + p.stderr)
    return exe


def start_dnsd(exe):
    """goose-dnsd on a free port: the process and the port."""
    zone = os.path.join(ROOT, "test", "vectors", "zones", "served.zone")
    p = subprocess.Popen([exe, "-a", "127.0.0.1", "-p", "0", "-y", "xfr.example.:" + SECRET,
                          "example.org.=" + zone], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    line = p.stdout.readline()
    if not line.startswith("listening on "):
        p.kill()
        sys.exit("goose-dnsd did not start: " + line + p.stderr.read())
    return p, line.split()[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("--native", action="store_true")
    ap.add_argument("-k", help="only files whose name contains this")
    args = ap.parse_args()
    goose = find_goose(args.goose)

    test_dir = os.path.join(ROOT, "test")
    # A test is a program; the shared helpers (test/tv.goose) have no main.
    tests = sorted(f for f in os.listdir(test_dir)
                   if f.endswith(".goose") and "fn main()" in open(os.path.join(test_dir, f)).read())
    if args.k:
        tests = [t for t in tests if args.k in t]
    needs = {t for t in tests if open(os.path.join(test_dir, t)).readline().startswith("// needs: dnsd")}
    failed = []
    passed = 0

    def check(label, p):
        nonlocal passed
        ok = p.returncode == 0
        print(("ok    " if ok else "FAIL  ") + label)
        if ok:
            passed += 1
        else:
            failed.append(label)
            out = strip_notes(p.stdout) + "\n".join(l for l in p.stderr.splitlines()
                                                    if "warning" not in l and not l.strip().startswith("^"))
            print("      " + out.strip()[-3000:].replace("\n", "\n      "))

    with tempfile.TemporaryDirectory() as tmp:
        dnsd = build_dnsd(goose, tmp) if needs else None
        runs = [["-O0"], ["-O2"], ["--debug"]] + ([["native"]] if args.native else [])
        for t in tests:
            for flags in runs:
                server, extra = None, []
                if t in needs:
                    server, port = start_dnsd(dnsd)
                    extra = ["--", port]
                try:
                    if flags == ["native"]:
                        exe = os.path.join(tmp, t[:-6])
                        p = subprocess.run([goose, "build", "-o", exe, t], cwd=test_dir, capture_output=True, text=True)
                        if p.returncode == 0:
                            p = subprocess.run([exe] + extra[1:], cwd=test_dir, capture_output=True, text=True)
                    else:
                        p = subprocess.run([goose, *flags, t] + extra, cwd=test_dir, capture_output=True, text=True)
                finally:
                    if server:
                        server.kill()
                        server.wait()
                check(f"{t} {' '.join(flags)}", p)

    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
