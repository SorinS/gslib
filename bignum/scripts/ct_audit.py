#!/usr/bin/env python3
"""Check that the constant-time modules use BigInt on public values only.

BigInt (bignum.goose) is variable time. In every other module of the
package, a function that calls it, or calls a `*_vartime` function, must be
listed in PUBLIC below with the reason its values are public. A new call
fails the audit until someone looks at it and lists it; an entry that no
longer calls BigInt fails too, so the list stays exact.

    python3 scripts/ct_audit.py           # exit status 1 on a finding
    python3 scripts/ct_audit.py --list    # every function that uses BigInt
"""

import argparse
import os
import re
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

# (module, function): why what it hands BigInt is public.
PUBLIC = {
    ("rsa", "rsa_public_from"): "n and e: the public key",
    ("rsa", "rsa_key_from_limbs"): "big_of(n), big_of(e): the public half, checked by rsa_public_from",
    ("rsa", "rsa_public_op_ct"): "R^2 mod n: the public modulus (x itself goes through mont_mul only)",
    ("rsa", "rsa_public_op"): "x^e mod n to verify: public key, public signature (encryption: rsa_public_op_ct)",
    ("rsa", "random_bits_vartime"): "for public candidates only (DSA's domain parameters)",
    ("rsa", "random_range_vartime"): "for public candidates only (miller_rabin_vartime's bases)",
    ("rsa", "miller_rabin_vartime"): "for public candidates only (DSA's p and q)",
    ("dsa", "dsa_be"): "p, q, g, y, and bits2octets of the digest",
    ("dsa", "dsa_width"): "a public parameter's width",
    ("dsa", "dsa_key_from"): "p, q, g, y; x is checked by dsa_in_range",
    ("dsa", "dsa_generate_parameters"): "domain parameters are public",
    ("dsa", "dsa_probably_prime"): "domain parameters are public",
    ("dsa", "dsa_sign_deterministic"): "z mod q: the digest is public",
    ("dsa", "dsa_verify"): "verification sees public values only",
    ("ec", "ec_hex"): "curve constants",
    ("ffdh", "ffdh_value_ok"): "the peer's public value and p",
}

FN = re.compile(r"^\s*(?:(?:recursive|inline|simd|checkfree|export)\s+)*fn\s+(\w+)")
CALL = re.compile(r"\b(\w+)\s*\(")


def strip(line):
    """The code of a line: no // comment, no string literal."""
    line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
    return line.split("//")[0]


def bigint_api():
    names = set()
    for line in open(os.path.join(ROOT, "bignum.goose")):
        m = FN.match(line)
        if m:
            names.add(m.group(1))
    return names


def uses(path, api):
    """{function: {BigInt function it calls}} for one module."""
    found = {}
    fn = None
    for line in open(path):
        code = strip(line)
        m = FN.match(code)
        if m:
            fn = m.group(1)
            code = code[m.end():]           # a one-line function's body
        if fn is None:
            continue
        for name in CALL.findall(code):
            if name in api or name.endswith("_vartime"):
                found.setdefault(fn, set()).add(name)
    return found


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true", help="print every function that uses BigInt")
    args = ap.parse_args()
    api = bigint_api()
    seen = {}
    for f in sorted(os.listdir(ROOT)):
        if not f.endswith(".goose") or f == "bignum.goose":
            continue
        module = f[:-6]
        for fn, names in uses(os.path.join(ROOT, f), api).items():
            if fn.endswith("_vartime") and (module, fn) not in PUBLIC:
                continue                    # its callers are checked instead
            seen[(module, fn)] = names
    bad = 0
    for key, names in sorted(seen.items()):
        if args.list:
            print(f"{key[0]}.{key[1]}: {', '.join(sorted(names))}")
        if key not in PUBLIC:
            print(f"UNLISTED {key[0]}.goose {key[1]} calls {', '.join(sorted(names))}: "
                  "check that it is on public values, then list it in scripts/ct_audit.py")
            bad += 1
    for key in sorted(PUBLIC):
        if key not in seen:
            print(f"STALE {key[0]}.goose {key[1]} no longer calls BigInt: remove it from PUBLIC")
            bad += 1
    print(f"ct audit: {len(seen)} functions use BigInt on public values, {bad} findings")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
