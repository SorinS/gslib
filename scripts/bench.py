#!/usr/bin/env python3
"""Times mimegoose against Go on the same work: tools/bench.goose (built
with the C compiler) and tools/mimeoracle.sh bench.

    python3 scripts/bench.py [--goose PATH]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "bench")
        b = subprocess.run([goose, "build", "-o", exe, "tools/bench.goose"], cwd=ROOT, capture_output=True, text=True)
        if b.returncode != 0:
            sys.exit(b.stderr + b.stdout)
        print("Goose:")
        sys.stdout.flush()
        subprocess.run([exe], check=True)
    print("Go:")
    sys.stdout.flush()
    subprocess.run([os.path.join(ROOT, "tools", "mimeoracle.sh"), "bench"], check=True)


if __name__ == "__main__":
    main()
