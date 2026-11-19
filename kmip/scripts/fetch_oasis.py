#!/usr/bin/env python3
"""Fetch OASIS's KMIP test cases into a cache directory.

    python3 kmip/scripts/fetch_oasis.py [--cache DIR]

The KMIP Profiles' mandatory and optional test cases (1.4, 2.0, 2.1) and
the KMIP Test Cases notes' (1.4, 2.0, 2.1), from docs.oasis-open.org: six
zips, each checked against its SHA-256 here, of which only the
test-cases/**.xml are unpacked. They are OASIS's ("Copyright (c) OASIS
Open. All Rights Reserved."), so they are fetched, not kept in this
repository. The cache is --cache, else $KMIP_OASIS, else
kmip/test/oasis-cache (ignored by git). scripts/oasis.py runs them.
"""

import argparse
import hashlib
import io
import os
import sys
import urllib.request
import zipfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DEFAULT_CACHE = os.path.join(ROOT, "test", "oasis-cache")

BASE = "https://docs.oasis-open.org/kmip/"
ZIPS = [
    # (directory in the cache, URL, SHA-256)
    ("profiles-v1.4", BASE + "profiles/v1.4/os/kmip-profiles-v1.4-os.zip",
     "ec85e2ebfffd18b8fc6b56e4c46f8c9cb68d2cda1b3da48810a41fa62329e97d"),
    ("profiles-v2.0", BASE + "kmip-profiles/v2.0/os/kmip-profiles-v2.0-os.zip",
     "449cc338e1d66cdee9cf51ee16e4a486a97d911f3e6e393d579e7075a249b8b5"),
    ("profiles-v2.1", BASE + "kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.zip",
     "4f32dea38072c98517e1a406227b567cfd644feaea3bf85a7d0d7b7dbe4cf9b6"),
    ("testcases-v1.4", BASE + "testcases/v1.4/cn01/kmip-testcases-v1.4-cn01.zip",
     "fbf33cf599f06251ec32eeb26dc224b5396a6b8a0521b8bf8d833b67de5e926c"),
    ("testcases-v2.0", BASE + "kmip-testcases/v2.0/cn01/kmip-testcases-v2.0-cn01.zip",
     "4c2c086e7206b0a00ba63f52f4c801c32f527a5f48d84cfba49819d43b0d151f"),
    ("testcases-v2.1", BASE + "kmip-testcases/v2.1/cn01/kmip-testcases-v2.1-cn01.zip",
     "247853f087dddb405eda6321abf7e6c4c497fb59c0b4bbeecf0c89192a22f421"),
]


def cache_dir(arg):
    return arg or os.environ.get("KMIP_OASIS") or DEFAULT_CACHE


def present(cache):
    return all(os.path.isfile(os.path.join(cache, d, ".done")) for d, _, _ in ZIPS)


def fetch(cache, quiet=False):
    for d, url, sha in ZIPS:
        dest = os.path.join(cache, d)
        if os.path.isfile(os.path.join(dest, ".done")):
            continue
        if not quiet:
            print(f"fetching {url}")
        data = urllib.request.urlopen(url, timeout=120).read()
        got = hashlib.sha256(data).hexdigest()
        if got != sha:
            sys.exit(f"{url}: SHA-256 {got}, not {sha}")
        n = 0
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                name = info.filename
                if info.is_dir() or "test-cases/" not in name or not name.endswith(".xml"):
                    continue
                rel = name[name.index("test-cases/"):]
                parts = rel.split("/")
                if any(p in ("", ".", "..") for p in parts) or os.path.isabs(rel):
                    sys.exit(f"{url}: refusing the path {name!r}")
                out = os.path.join(dest, *parts)
                os.makedirs(os.path.dirname(out), exist_ok=True)
                with open(out, "wb") as f:
                    f.write(z.read(info))
                n += 1
        with open(os.path.join(dest, ".done"), "w") as f:
            f.write(f"{url}\n{sha}\n{n} files\n")
        if not quiet:
            print(f"  {n} test cases in {dest}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache")
    args = ap.parse_args()
    fetch(cache_dir(args.cache))


if __name__ == "__main__":
    main()
