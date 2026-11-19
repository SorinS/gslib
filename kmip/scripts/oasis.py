#!/usr/bin/env python3
"""Run OASIS's KMIP test cases: the XML and JSON encodings, and the server.

    python3 kmip/scripts/oasis.py [--cache DIR] [--goose PATH] [--jit]
                                  [--roundtrip | --replay] [-k TEXT] [-v]

The test cases (scripts/fetch_oasis.py fetches them when the cache does
not have them) are run by test/oasis.goose, built once natively (or, with
--jit, run under the JIT a batch of files at a time):

- roundtrip: every message of every file read from XML to TTLV, written
  as XML and as JSON and read back to the same bytes. Each must pass.
- replay: each file's requests played against kmip.server's in-memory
  server, and its responses compared with the file's. A scoreboard: the
  counts by version and directory, and the failures grouped by what the
  server answered (an operation it does not have, a result that differs)
  or the first difference.

Both run unless one is asked for. Exit status 1 when a round trip fails;
the replay's failures are reported, not fatal.
"""

import argparse
import collections
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_oasis  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Files OASIS published broken: a round trip cannot pass the first, and no
# server can pass either in a replay.
KNOWN_DEFECTS = {
    "TC-ECDSA-SIGN-1-14.xml": "an end tag too many at line 493 (not well-formed XML)",
    "OMOS-O-1-14.xml": "a response in KMIP 1.3 to a request in 1.4",
}


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def group_of(path, cache):
    """profiles-v2.1/mandatory, testcases-v1.4, ..."""
    rel = os.path.relpath(path, cache).split(os.sep)
    g = rel[0]
    if "mandatory" in rel:
        g += "/mandatory"
    elif "optional" in rel:
        g += "/optional"
    return g


def run_files(cmd_prefix, mode, files, jit):
    """Each file's result line, by file name."""
    out = {}
    if not jit:
        for f in files:
            p = subprocess.run(cmd_prefix + [mode, f], capture_output=True, text=True)
            lines = [l for l in p.stdout.splitlines() if l.startswith(("PASS ", "FAIL "))]
            if not lines:
                tail = (p.stderr or p.stdout).strip().splitlines()[-1:] or ["no output"]
                lines = [f"FAIL {os.path.basename(f)}: crashed (exit {p.returncode}): {tail[0][:200]}"]
            out[f] = lines[0]
        return out
    batch = 40
    for k in range(0, len(files), batch):
        chunk = files[k:k + batch]
        p = subprocess.run(cmd_prefix + ["--", mode] + chunk, capture_output=True, text=True)
        lines = [l for l in p.stdout.splitlines() if l.startswith(("PASS ", "FAIL "))]
        if len(lines) == len(chunk):
            out.update(zip(chunk, lines))
        else:
            # Something stopped the batch: one at a time.
            for f in chunk:
                q = subprocess.run(cmd_prefix + ["--", mode, f], capture_output=True, text=True)
                ls = [l for l in q.stdout.splitlines() if l.startswith(("PASS ", "FAIL "))]
                out[f] = ls[0] if ls else f"FAIL {os.path.basename(f)}: crashed (exit {q.returncode})"
    return out


def reason(line):
    """What a replay failure comes to, for grouping."""
    m = re.search(r"\[server: (.*)\]$", line)
    said = m.group(1) if m else ""
    for part in said.split("; "):
        words = part.split(" ")
        if "OperationNotSupported" in part or "FeatureNotSupported" in part:
            return f"the server has no {words[0]} ({words[1].split('/')[-1]})"
        if "UnsupportedProtocolVersion" in part:
            return "refused: " + part[:120]
    if "is not KMIP's XML" in line:
        return "a request that is not KMIP's XML: " + line.split("XML: ", 1)[-1][:100]
    if "crashed" in line:
        return "crashed"
    m = re.search(r" step \d+: (.*?)(?: \[server: .*\])?$", line)
    diff = m.group(1) if m else line
    diff = re.sub(r"\$[A-Z_0-9]+", "$...", diff)
    diff = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", diff)
    if "ResultStatus: expected Success" in diff:
        for part in said.split("; "):
            if "OperationFailed" in part:
                return "failed: " + re.sub(r"\d+", "N", part)[:140]
    return "differs: " + diff[:140]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache")
    ap.add_argument("--goose")
    ap.add_argument("--jit", action="store_true", help="run under the JIT instead of building")
    ap.add_argument("--roundtrip", action="store_true")
    ap.add_argument("--replay", action="store_true")
    ap.add_argument("-k", help="only files whose path contains this")
    ap.add_argument("-v", action="store_true", help="print every file's line")
    args = ap.parse_args()
    goose = find_goose(args.goose)
    cache = fetch_oasis.cache_dir(args.cache)
    if not fetch_oasis.present(cache):
        fetch_oasis.fetch(cache)
    files = sorted(os.path.join(dp, f) for dp, _, fs in os.walk(cache) for f in fs if f.endswith(".xml"))
    if args.k:
        files = [f for f in files if args.k in f]
    modes = [m for m in ("roundtrip", "replay") if getattr(args, m)] or ["roundtrip", "replay"]

    test_dir = os.path.join(ROOT, "test")
    tmp = tempfile.mkdtemp()
    try:
        if args.jit:
            prefix = [goose, "run", "oasis.goose"]
        else:
            exe = os.path.join(tmp, "oasis")
            p = subprocess.run([goose, "build", "-O2", "-o", exe, "oasis.goose"], cwd=test_dir,
                               capture_output=True, text=True)
            if p.returncode != 0:
                sys.exit("building test/oasis.goose failed:\n" + p.stderr)
            prefix = [exe]
        status = 0
        for mode in modes:
            res = run_files(prefix, mode, files, args.jit)
            by_group = collections.defaultdict(lambda: [0, 0])
            reasons = collections.defaultdict(list)
            known = []
            for f in files:
                line = res[f]
                g = group_of(f, cache)
                by_group[g][0] += 1
                base = os.path.basename(f)
                if line.startswith("PASS"):
                    by_group[g][1] += 1
                elif base in KNOWN_DEFECTS:
                    known.append(base)
                else:
                    reasons[reason(line) if mode == "replay" else line.split(": ", 1)[-1][:120]].append(
                        os.path.basename(f))
                if args.v or (mode == "roundtrip" and not line.startswith("PASS") and base not in KNOWN_DEFECTS):
                    print(line)
            total = sum(v[0] for v in by_group.values())
            passed = sum(v[1] for v in by_group.values())
            print(f"\n{mode}: {passed} of {total} test cases pass, {len(known)} of the others broken in OASIS's files")
            for g in sorted(by_group):
                print(f"  {g:28s} {by_group[g][1]:4d} / {by_group[g][0]}")
            if reasons:
                print(f"\n{mode} failures by reason:")
                for r, fs in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
                    shown = ", ".join(sorted(fs)[:6]) + (", ..." if len(fs) > 6 else "")
                    print(f"  {len(fs):4d}  {r}\n        {shown}")
            if known:
                print("\nbroken in OASIS's files:")
                for k in sorted(known):
                    print(f"  {k}: {KNOWN_DEFECTS[k]}")
            if mode == "roundtrip" and passed + len(known) != total:
                status = 1
            print()
        sys.exit(status)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
