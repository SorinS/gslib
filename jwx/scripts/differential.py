#!/usr/bin/env python3
"""jwx against Go's lestrrat-go/jwx v4, both ways, with fresh keys:

1. Go makes N rounds of messages (every signature algorithm, ML-DSA too,
   compact and JSON; every key management algorithm with every content
   algorithm, some compressed, some JSON), which test/go_jwx.goose
   verifies and decrypts;
2. tools/tokens.goose makes as many, which Go verifies and decrypts.

    python3 scripts/differential.py [-n ROUNDS] [--goose PATH] [--update]

--update also rewrites test/vectors/go_jwx.txt, the Go messages the unit
tests keep. Needs Go 1.27 or later (crypto/mldsa); the module is in
scripts/differential.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
GODIR = os.path.join(ROOT, "scripts", "differential")


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=1)
    ap.add_argument("--goose")
    ap.add_argument("--update", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("go"):
        sys.exit("go not found")
    ok = True
    with tempfile.TemporaryDirectory() as tmp:
        go_msgs = os.path.join(tmp, "go.txt")
        with open(go_msgs, "w") as f:
            subprocess.run(["go", "run", ".", "gen", "-n", str(args.n)], cwd=GODIR, stdout=f, check=True)
        p = subprocess.run([goose, "-O2", "go_jwx.goose", "--", go_msgs], cwd=os.path.join(ROOT, "test"),
                           capture_output=True, text=True)
        out = [l for l in p.stdout.splitlines() if l.startswith(("FAIL", "go jwx", "go_jwx", "      "))]
        print("Go -> Goose:", *out, sep="\n  ")
        ok = ok and p.returncode == 0
        if args.update and p.returncode == 0:
            shutil.copy(go_msgs, os.path.join(ROOT, "test", "vectors", "go_jwx.txt"))
        mine = os.path.join(tmp, "goose.txt")
        with open(mine, "w") as f:
            p = subprocess.run([goose, "-O2", "tools/tokens.goose", "--", str(args.n)], cwd=ROOT, stdout=f,
                               stderr=subprocess.PIPE, text=True)
        if p.returncode != 0:
            print(p.stderr)
            sys.exit(1)
        with open(mine) as f:
            p = subprocess.run(["go", "run", ".", "check"], cwd=GODIR, stdin=f, capture_output=True, text=True)
        print("Goose -> Go:", *p.stdout.splitlines(), sep="\n  ")
        ok = ok and p.returncode == 0
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
