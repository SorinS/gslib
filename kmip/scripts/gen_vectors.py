#!/usr/bin/env python3
"""Collect the TTLV encodings in PyKMIP's unit tests into kmip/test/vectors/pykmip.txt.

    python3 kmip/scripts/gen_vectors.py PATH/TO/pykmip > kmip/test/vectors/pykmip.txt

The tests are parsed, not run: every BytearrayStream(b'...') whose bytes
are long enough to be an item is kept, one a line, as "file:line hex".
Most are KMIP's own examples (the specification's test cases for the
messages and payloads); some are malformed on purpose. test/corpus.goose
decodes each, writes what it decoded again and compares.

Collected from PyKMIP 4815637 (2026-09-10), Apache License 2.0.
"""

import ast
import os
import sys


def main():
    root = os.path.join(sys.argv[1], "kmip", "tests", "unit")
    seen = set()
    for dirpath, _, files in sorted(os.walk(root)):
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            path = os.path.join(dirpath, f)
            tree = ast.parse(open(path, encoding="utf-8").read(), path)
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and node.args):
                    continue
                fn = node.func
                name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
                if name != "BytearrayStream":
                    continue
                a = node.args[0]
                if not (isinstance(a, ast.Constant) and isinstance(a.value, bytes)):
                    continue
                b = a.value
                if len(b) < 8 or b[0] != 0x42 or b in seen:
                    continue
                seen.add(b)
                rel = os.path.relpath(path, root)
                print(f"{rel}:{node.lineno} {b.hex()}")


if __name__ == "__main__":
    main()
