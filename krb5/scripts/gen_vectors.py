#!/usr/bin/env python3
"""Write krb5's test vectors from go-krb5's test data.

test/vectors/mit_encodings.txt holds MIT's reference encodings of every
message (src/tests/asn.1/reference_encode.out, as go-krb5 copied them into
test/testdata/test_vectors.go): one `name|hex` per line. pac.txt holds the
PAC vectors from the same file, files.txt the keytabs and the cache.
pac_oracle.txt is go-krb5's reading of pac.txt (tools/krb5oracle), which
test/pac.goose compares its own with; it needs Go, and the oracle's
checkout where tools/krb5oracle/go.mod's replace points.

    python3 scripts/gen_vectors.py [--oracle ~/Dev/Go.Code/krb5.git]
"""

import argparse
import os
import re
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", default=os.path.expanduser("~/Dev/Go.Code/krb5.git"))
    args = ap.parse_args()
    src = open(os.path.join(args.oracle, "test", "testdata", "test_vectors.go")).read()
    consts = dict(re.findall(r'^\s*(\w+)\s*=\s*"([0-9A-Fa-f]+)"\s*$', src, re.M))
    groups = {
        "mit_encodings.txt": lambda n: n.startswith("MarshaledKRB5"),
        "pac.txt": lambda n: n.startswith("MarshaledPAC_"),
        "files.txt": lambda n: n.startswith(("KEYTAB_", "HTTP_KEYTAB", "CCACHE_")),
    }
    out_dir = os.path.join(ROOT, "test", "vectors")
    os.makedirs(out_dir, exist_ok=True)
    for fname, pick in groups.items():
        with open(os.path.join(out_dir, fname), "w") as f:
            f.write("# from go-krb5 test/testdata/test_vectors.go (scripts/gen_vectors.py)\n")
            for name, hx in consts.items():
                if pick(name):
                    f.write(f"{name}|{hx.lower()}\n")
        print(fname, sum(1 for n in consts if pick(n)))
    oracle = os.path.join(ROOT, "tools", "krb5oracle")
    with open(os.path.join(out_dir, "pac.txt")) as f:
        p = subprocess.run(["go", "run", "."], cwd=oracle, stdin=f, capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit("krb5oracle failed: " + p.stderr)
    v = subprocess.run(["go", "run", ".", "-version"], cwd=oracle, capture_output=True, text=True).stdout.strip()
    with open(os.path.join(out_dir, "pac_oracle.txt"), "w") as f:
        f.write(f"# {v}: go-krb5's reading of pac.txt (scripts/gen_vectors.py)\n")
        f.write(p.stdout)
    print("pac_oracle.txt", p.stdout.count("== "))


if __name__ == "__main__":
    main()
