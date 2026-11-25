#!/usr/bin/env python3
"""regex against the Rust regex crate, on random cases.

Random small patterns mix the assertions `^ $ \\A \\z \\b \\B` into
alternations, repetitions (lazy too), capturing and non-capturing groups and
scoped (?m:) (?-m:) (?i:) flags, some under a leading (?m); each runs on
three random texts over "ab \\n_x.A", short ones, and every other round
longer ones with longer literals so that the skip loops are chosen. The
crate (regex 1.13.2, regex::bytes, Unicode off; scripts/oracle, built with
cargo) and test/differential.goose print every match's groups for each
case, and the lines are compared. A pattern gslib reports as too large for
its DFAs, which the crate's lazy DFA runs, is counted apart; any other
difference fails. The generator leaves out `{0}` and does not aim at the
module's documented known difference (a repeating prefix shared by every
branch of an alternation).

    python3 scripts/differential.py [-n PATTERNS] [--seed N] [--goose PATH]

Needs cargo (the crate is fetched once). The compiler is --goose, else
$GOOSE, else `goose` on PATH, else ../goose.git/build/goose beside gslib.git.
"""

import argparse
import os
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

ATOMS = ["a", "b", " ", "\\n", "_", ".", "[ab]", "[^a]", "[a ]", "\\w", "\\W", "\\s", "x", "(?s:.)"]
LONG_ATOMS = ["xa", "bx_", "Ax", "x\\n"]
LOOKS = ["^", "$", "\\A", "\\z", "\\b", "\\B"]
TEXT = "ab \n_x.A"


def patterns(rng, atoms):
    def atom(d):
        r = rng.random()
        if r < 0.30: return rng.choice(LOOKS)
        if r < 0.65 or d > 1: return rng.choice(atoms)
        if r < 0.80: return "(" + alt(d + 1) + ")"
        if r < 0.88: return "(?:" + alt(d + 1) + ")"
        if r < 0.92: return "(?m:" + alt(d + 1) + ")"
        if r < 0.96: return "(?i:" + alt(d + 1) + ")"
        return "(?-m:" + alt(d + 1) + ")"

    def rep(d):
        a = atom(d)
        if rng.random() < 0.6: return a
        q = rng.choice(["*", "+", "?", "{1,2}", "{2}", "{1,}"])
        return a + q + ("?" if rng.random() < 0.3 else "")

    def cat(d):
        return "".join(rep(d) for _ in range(rng.randint(0 if d else 1, 3)))

    def alt(d):
        n = 1 if rng.random() < 0.6 else rng.randint(2, 3)
        return "|".join(cat(d) for _ in range(n))

    p = alt(0)
    return "(?m)" + p if rng.random() < 0.4 else p


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-n", type=int, default=2000, help="patterns (each on three texts)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    if not shutil.which("cargo"):
        print("skip: no cargo for the regex crate")
        return
    rng = random.Random(args.seed)
    lines = []
    for i in range(args.n):
        long = i % 2 == 1
        p = patterns(rng, ATOMS + LONG_ATOMS if long else ATOMS)
        for _ in range(3):
            t = "".join(rng.choice(TEXT) for _ in range(rng.randint(0, 60 if long else 12)))
            lines.append(p.encode().hex() + " " + t.encode().hex())
    with tempfile.TemporaryDirectory() as tmp:
        cases = os.path.join(tmp, "cases.txt")
        with open(cases, "w") as f:
            f.write("\n".join(lines) + "\n")
        oracle = os.path.join(ROOT, "scripts", "oracle")
        subprocess.run(["cargo", "build", "--release", "--quiet", "--target-dir", os.path.join(tmp, "target")],
                       cwd=oracle, check=True)
        rust = subprocess.run([os.path.join(tmp, "target", "release", "regex-oracle"), cases],
                              capture_output=True, text=True, check=True).stdout.splitlines()
        g = subprocess.run([goose, "differential.goose", "--", cases], cwd=os.path.join(ROOT, "test"),
                           capture_output=True, text=True)
        if g.returncode != 0:
            sys.exit("differential.goose failed:\n" + g.stderr[-2000:])
        ours = g.stdout.splitlines()
    same = large = 0
    differ = []
    for r, o in zip(rust, ours):
        if r == o:
            same += 1
        elif "would be too large" in o and not r.endswith(" error"):
            large += 1
        else:
            differ.append((r, o))
    for r, o in differ[:10]:
        print("crate:", r)
        print("gslib:", o)
    print(f"{len(rust)} cases: {same} the same, {large} too large for gslib's DFAs, {len(differ)} different")
    sys.exit(1 if differ or len(rust) != len(ours) else 0)


if __name__ == "__main__":
    main()
