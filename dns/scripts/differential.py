#!/usr/bin/env python3
"""dns against miekg/dns v1.1.73 on fresh vectors: scripts/oracle makes
them again (new keys, so new DNSKEYs, RRSIGs, DS records and private-key
files; TSIG and SIG(0) signatures; the records and messages of the corpus
read at today's date), and the tests that read vectors check them:
test/rr.goose, msg.goose, dnssec.goose, tsig.goose, sig0.goose, misc.goose.

    python3 scripts/differential.py [-n ROUNDS] [--goose PATH] [--update]

--update also writes the fresh vectors over test/vectors. Needs Go; the
oracle module is scripts/oracle.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
ORACLE = os.path.join(ROOT, "scripts", "oracle")
CORPUS = os.path.join(ROOT, "test", "vectors", "rr_corpus.txt")
MODES = [("rr", CORPUS, "rr.txt"), ("msg", CORPUS, "msg.txt"), ("dnssec", CORPUS, "dnssec.txt"),
         ("tsig", "-", "tsig.txt"), ("misc", "-", "misc.txt")]
TESTS = ["rr.goose", "msg.goose", "dnssec.goose", "tsig.goose", "sig0.goose", "misc.goose"]


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
    failed = 0
    with tempfile.TemporaryDirectory() as tmp:
        oracle = os.path.join(tmp, "oracle")
        p = subprocess.run(["go", "build", "-o", oracle, "."], cwd=ORACLE, capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("cannot build the oracle:\n" + p.stderr)
        for round_ in range(args.n):
            vec = os.path.join(tmp, f"vectors{round_}")
            os.makedirs(vec)
            for mode, arg, out in MODES:
                with open(os.path.join(vec, out), "w") as f:
                    subprocess.run([oracle, mode, arg], stdout=f, check=True)
            for t in TESTS:
                p = subprocess.run([goose, "-O2", t, "--", vec], cwd=os.path.join(ROOT, "test"),
                                   capture_output=True, text=True)
                last = (p.stdout.strip().splitlines() or ["(no output)"])[-1]
                ok = p.returncode == 0
                print(("ok    " if ok else "FAIL  ") + f"round {round_ + 1}: {last}")
                if not ok:
                    failed += 1
                    print("      " + p.stdout.strip()[-2000:].replace("\n", "\n      "))
            if args.update and round_ == 0:
                for _, _, out in MODES:
                    shutil.copy(os.path.join(vec, out), os.path.join(ROOT, "test", "vectors", out))
    print(f"\n{'all passed' if not failed else str(failed) + ' failed'}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
