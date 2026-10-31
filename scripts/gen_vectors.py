#!/usr/bin/env python3
"""Regenerate test/vectors/go_*.txt from Go's own test tables.

Each table is read from $GOROOT/src/mime/**/*_test.go by
`tools/mimeoracle.sh vectors -table NAME` (go/ast, nothing copied by hand),
and each row carries, after "=>", what Go's function returns for it. This
script then checks that Go's result agrees with the table's expectation in
the way Go's own test checks it, so a misread row cannot pass silently.

    python3 scripts/gen_vectors.py [--check]

--check compares with the files in the tree instead of writing them.
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
ORACLE = os.path.join(ROOT, "tools", "mimeoracle.sh")
OUT = os.path.join(ROOT, "test", "vectors")

TABLES = [
    "consume_token", "consume_value", "consume_media_param",
    "parse_media_type", "bad_media_type", "format_media_type",
    "encode_word", "encoded_word_length", "decode_word", "decode_header", "charset_decoder",
    "qp_reader", "qp_writer", "qp_testmsg",
    "name_accessors", "multipart_parse", "set_boundary", "file_disposition",
    "line_endings", "truncated_bodies", "multipart_body", "line_continuation", "raw_part", "qp_part",
    "readahead_1", "readahead_2",
    "canonical_key", "header_malformed", "read_mime_header",
    "form_message", "form_nameless", "form_filename", "form_textct", "form_contents", "form_limits",
]

# Go's test data files, copied as they are.
TESTDATA = [
    ("mime/multipart/testdata/nested-mime", "go_nested-mime"),
    ("mime/testdata/test.types", "go_test.types"),
    ("mime/testdata/test.types.globs2", "go_test.types.globs2"),
]


def unescape(f):
    out = bytearray()
    i = 0
    b = f.encode("latin-1")
    while i < len(b):
        if b[i] == 0x5C:
            if b[i + 1:i + 2] == b"N":
                return None
            out.append(int(b[i + 2:i + 4], 16))
            i += 4
        else:
            out.append(b[i])
            i += 1
    return bytes(out)


def rows(text):
    for line in text.splitlines():
        if line.startswith("#") or not line:
            continue
        f = line.split("|")
        if "=>" in f:
            k = f.index("=>")
            yield f[:k], f[k + 1:]
        else:
            yield f, []


def take_map(f, i):
    """A flattened map[string]string at f[i]: (dict, next index)."""
    if f[i] == "\\N":
        return {}, i + 1
    n = int(f[i])
    m = {}
    for k in range(n):
        m[unescape(f[i + 1 + 2 * k])] = unescape(f[i + 2 + 2 * k])
    return m, i + 1 + 2 * n


def check(table, want, got):
    """Go's result (got) against the row's expectation (want), as Go's test does."""
    u = [unescape(x) for x in want]
    if table == "parse_media_type":
        err, mt = unescape(got[0]), unescape(got[1])
        params, _ = take_map(got, 2)
        wparams, _ = take_map(want, 2)
        if err:
            return u[1] == b""
        return mt == u[1] and (params == wparams or (not params and not wparams))
    if table == "bad_media_type":
        err, mt = unescape(got[0]), unescape(got[1])
        if err != u[2]:
            return False
        return mt == u[1] if err == b"mime: invalid media parameter" else mt == b""
    if table == "format_media_type":
        _, k = take_map(want, 1)
        return unescape(got[0]) == unescape(want[k])
    if table == "encode_word":
        return unescape(got[0]) == u[3]
    if table == "encoded_word_length":
        return all(len(w) <= 75 for w in unescape(got[0]).split(b" "))
    if table == "decode_word":
        s, err = unescape(got[0]), unescape(got[1])
        return (err != b"") == (u[2] == b"1") and s == u[1]
    if table == "decode_header":
        return unescape(got[0]) == u[1] and unescape(got[1]) == b""
    if table == "qp_reader":
        s, err = unescape(got[0]), unescape(got[1])
        return s == u[1] and err == (u[2] or b"")
    if table == "qp_writer":
        return unescape(got[0]) == u[1] and unescape(got[1]) == (u[2] or u[1])
    if table == "name_accessors":
        return unescape(got[0]) == u[2] and unescape(got[1]) == u[3]     # a [3]string row: its length first
    if table == "multipart_parse":
        return got[-1] == "" and want[3:] == got[:-1]
    if table == "set_boundary":
        return (unescape(got[0]) == b"") == (u[1] == b"1")
    if table == "file_disposition":
        return unescape(got[0]) == u[2]
    if table.startswith("form_") and got:
        return got[0] == ""
    if table == "canonical_key":
        return unescape(got[0]) == u[1]
    if table == "header_malformed":
        return unescape(got[0]) not in (b"", b"EOF")
    if table == "truncated_bodies":
        return got[-1] == "body: unexpected EOF"
    if table in ("line_continuation", "raw_part", "qp_part"):
        return got[-1] == ""
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    bad = 0
    for t in TABLES:
        p = subprocess.run([ORACLE, "vectors", "-table", t], capture_output=True, text=True,
                           encoding="latin-1")
        if p.returncode != 0:
            sys.exit(f"{t}: {p.stderr.strip()}")
        text = p.stdout
        n = 0
        for i, (want, got) in enumerate(rows(text)):
            n += 1
            if got and not check(t, want, got):
                print(f"{t}: row {i}: Go's result differs from the table: {want} => {got}")
                bad += 1
        path = os.path.join(OUT, f"go_{t}.txt")
        if args.check:
            old = open(path, encoding="latin-1").read() if os.path.exists(path) else ""
            if old != text:
                print(f"{t}: {os.path.relpath(path, ROOT)} is out of date")
                bad += 1
        else:
            with open(path, "w", encoding="latin-1") as f:
                f.write(text)
        print(f"{t}: {n} rows")
    goroot = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True).stdout.strip()
    for src, name in TESTDATA:
        data = open(os.path.join(goroot, "src", src), "rb").read()
        path = os.path.join(OUT, name)
        if args.check:
            if not os.path.exists(path) or open(path, "rb").read() != data:
                print(f"{os.path.relpath(path, ROOT)} differs from $GOROOT/src/{src}")
                bad += 1
        else:
            open(path, "wb").write(data)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
