#!/usr/bin/env python3
"""Every library's unit tests: each one's scripts/run_tests.py in turn
(every test program at -O0, -O2 and --debug, and natively with --native),
and a summary. Arguments other than --only go to each run_tests.py.

    python3 scripts/run_all.py [--only bignum,tls] [--native] [--goose PATH] [-k NAME]

The compiler is --goose, else $GOOSE, else `goose` on PATH, else
../goose.git/build/goose beside gslib.git. Exit status 1 if any failed.
"""

import os
import re
import subprocess
import sys
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
# Each library's directory, by its name.
LIBS = {"asn1": "encoding/asn1", "bignum": "crypto/bignum", "x509": "crypto/x509", "tls": "crypto/tls",
        "ssh": "crypto/ssh", "ldap": "net/ldap", "yaml": "encoding/yaml", "http": "net/http",
        "compress": "compress"}


def main():
    args = sys.argv[1:]
    libs = list(LIBS)
    if "--only" in args:
        i = args.index("--only")
        libs = [l for l in args[i + 1].split(",") if l]
        del args[i:i + 2]
        unknown = [l for l in libs if l not in LIBS]
        if unknown:
            sys.exit(f"no such library: {', '.join(unknown)} (they are {', '.join(LIBS)})")
    total_pass = total_fail = 0
    bad = []
    for lib in libs:
        t0 = time.time()
        p = subprocess.run([sys.executable, os.path.join(ROOT, LIBS[lib], "scripts", "run_tests.py"), *args],
                           cwd=os.path.join(ROOT, LIBS[lib]), capture_output=True, text=True)
        out = p.stdout + p.stderr
        m = re.search(r"(\d+) passed, (\d+) failed", out)
        passed, failed = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        total_pass += passed
        total_fail += failed
        status = "ok  " if p.returncode == 0 and m else "FAIL"
        print(f"{status}  {lib:7} {passed:4} passed, {failed} failed  ({time.time() - t0:.0f} s)", flush=True)
        if status == "FAIL":
            bad.append(lib)
            for line in out.splitlines():
                if line.startswith("FAIL") or "error" in line:
                    print("      " + line)
    print(f"\n{total_pass} passed, {total_fail} failed" + (f"; failing: {', '.join(bad)}" if bad else ""))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
