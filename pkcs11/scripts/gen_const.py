#!/usr/bin/env python3
"""pkcs11/constants.goose from the OASIS PKCS#11 header pkcs11t.h (3.1 tested,
https://github.com/oasis-tcs/pkcs11, published/3-01), as miekg/pkcs11's
const_generate.go makes zconst.go from it: every #define of a CK*, CKA_,
CKM_, ... constant as a u64, and tables of the names of the CKR_ (errors),
CKM_ (mechanisms), CKA_ (attributes), CKO_ (classes) and CKK_ (key types)
values, for error messages and for printing.

    python3 scripts/gen_const.py path/to/pkcs11t.h > constants.goose

The header itself is not kept here; only the values, which are the
standard's.
"""

import re
import sys

PREFIXES = ("CK_", "CKA_", "CKC_", "CKD_", "CKF_", "CKG_", "CKH_", "CKK_", "CKM_", "CKN_", "CKO_", "CKP_",
            "CKR_", "CKS_", "CKU_", "CKZ_", "CRYPTOKI_", "CKV_", "CKP11_")
NAMED = [("CKR_", "ckr"), ("CKM_", "ckm"), ("CKA_", "cka"), ("CKO_", "cko"), ("CKK_", "ckk")]
DEFINE = re.compile(r"^\s*#\s*define\s+([A-Z][A-Z0-9_]*)\s+(.+?)\s*(?:/\*.*)?$")


def value(expr, known):
    """The value of a #define's expression: numbers (UL suffixes dropped),
    names defined before it, | + ~ and parentheses."""
    e = re.sub(r"\b(0[xX][0-9a-fA-F]+|\d+)[uUlL]*\b", r"\1", expr)
    e = re.sub(r"\(\s*CK_[A-Z_]+\s*\)", "", e)          # casts such as (CK_ULONG)
    names = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", re.sub(r"\b0[xX][0-9a-fA-F]+|\b\d+", " ", e))
    for n in names:
        if n not in known:
            return None
    if not re.fullmatch(r"[\sA-Za-z0-9_|+~()xX]*", e):
        return None
    v = eval(e, {"__builtins__": {}}, dict(known))
    return v & 0xFFFFFFFFFFFFFFFF


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    known = {}
    order = []
    for line in open(sys.argv[1], encoding="latin-1"):
        m = DEFINE.match(line)
        if not m or not m.group(1).startswith(PREFIXES):
            continue
        name, expr = m.group(1), m.group(2).strip()
        if "(" in name or name.endswith("_H_"):
            continue
        v = value(expr, known)
        if v is None:
            continue
        known[name] = v
        order.append(name)

    out = sys.stdout
    out.write("// pkcs11.constants: the constants of PKCS#11 (CKA_, CKM_, CKR_, ...), made by\n")
    out.write("// scripts/gen_const.py from the OASIS header pkcs11t.h (3.1), as miekg/pkcs11's\n")
    out.write("// zconst.go is. Do not edit: run the script again.\n\n")
    out.write("namespace pkcs11;\n\n")
    for name in order:
        out.write(f"let {name}: u64 = 0x{known[name]:X};\n")
    # Name tables: the first name given a value is its name (later ones are
    # deprecated aliases).
    for prefix, short in NAMED:
        seen = {}
        for name in order:
            if name.startswith(prefix) and name not in ("CKA_SUB_PRIME_BITS", "CKA_SUBPRIME_BITS") \
                    and not name.endswith("VENDOR_DEFINED") and known[name] not in seen:
                seen[known[name]] = name
        vals = ", ".join(f"0x{v:X}" for v in seen)
        names = ", ".join(f'"{n}"' for n in seen.values())
        out.write(f"\nlet {short.upper()}_VALUES: u64[] = [{vals}];\n")
        out.write(f"let {short.upper()}_NAMES: const u8[:][] = [{names}];\n")


if __name__ == "__main__":
    main()
