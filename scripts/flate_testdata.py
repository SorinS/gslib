#!/usr/bin/env python3
"""Go's own flate and gzip test files, decoded by Go and by us.

Every file in $GOROOT/src/compress/flate/testdata is decoded as raw
DEFLATE (the .golden and .expect files are streams Go's Huffman bit writer
made; the .in files are not streams, and both readers must refuse or
accept them alike), and compress/gzip/testdata's files as gzip (.base64
ones decoded first). tools/flateverdict.goose's result must equal
gooracle's for each, fed whole and a byte at a time.

    python3 scripts/flate_testdata.py [--goose PATH] [-v]
"""

import argparse
import base64
import glob
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from flate_differential import ROOT, build_tools, find_goose  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip()
    files = []
    for path in sorted(glob.glob(os.path.join(goroot, "src/compress/flate/testdata/*"))):
        files.append(("raw", path, open(path, "rb").read()))
    for path in sorted(glob.glob(os.path.join(goroot, "src/compress/gzip/testdata/*"))):
        data = open(path, "rb").read()
        if path.endswith(".base64"):
            data = base64.b64decode(data)
        files.append(("gzip", path, data))
    with tempfile.TemporaryDirectory() as tmp:
        verdict, oracle = build_tools(goose, tmp)
        ours_path = os.path.join(tmp, "ours.txt")
        go_path = os.path.join(tmp, "go.txt")
        with open(ours_path, "w") as f, open(go_path, "w") as g:
            for fmt, _, data in files:
                for chunk, room in ((1 << 30, 1 << 20), (1, 1), (7, 300)):
                    f.write(f"{fmt} {chunk} {room} {data.hex() or '-'}\n")
                g.write(f"{fmt} {data.hex() or '-'}\n")
        ours = subprocess.run(verdict + [ours_path], cwd=ROOT, capture_output=True, text=True).stdout.splitlines()
        gos = subprocess.run([oracle, "inflate", go_path], capture_output=True, text=True).stdout.splitlines()
    if len(ours) != 3 * len(files) or len(gos) != len(files):
        sys.exit("missing results")
    diffs = 0
    decoded = 0
    for i, (fmt, path, data) in enumerate(files):
        want = gos[i]
        decoded += want.startswith("ok")
        for got in ours[3 * i:3 * i + 3]:
            if got != want:
                diffs += 1
                print(f"DIFF {os.path.relpath(path, goroot)}: ours {got!r}, Go {want!r}")
                break
        else:
            if args.v:
                print(f"ok   {os.path.relpath(path, goroot)}: {want}")
    print(f"{len(files)} files of Go's testdata ({decoded} decode, {len(files) - decoded} refused by Go), "
          f"{diffs} differ from Go")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
