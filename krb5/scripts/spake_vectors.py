#!/usr/bin/env python3
"""Writes test/vectors/spake.txt from Appendix C of
draft-ietf-kitten-krb-spake-preauth (the text file is the argument).

One vector per line, fields separated by '|' ('-' for none):
name|etype|group|key|w|w_reduced|x|y|X|Y|T|S|K|support|optimistic|challenge|thash1|thash2|body|K0|K1|K2|K3

    python3 scripts/spake_vectors.py draft-ietf-kitten-krb-spake-preauth-13.txt
"""

import os
import re
import sys

ETYPES = {"des3-cbc-sha1": 16, "rc4-hmac": 23, "aes128-cts-hmac-sha1-96": 17,
          "aes256-cts-hmac-sha1-96": 18, "AES256": 18}
GROUPS = {"edwards25519": 1, "P-256": 2, "P-384": 3, "P-521": 4}
FIELDS = ["key", "w (PRF+ output)", "w (reduced multiplier)", "x", "y", "X", "Y", "T", "S", "K",
          "SPAKESupport", "Optimistic SPAKEChallenge", "SPAKEChallenge",
          "Transcript hash after challenge", "Final transcript hash after pubkey",
          "KDC-REQ-BODY", "K'[0]", "K'[1]", "K'[2]", "K'[3]"]


def main():
    text = open(sys.argv[1]).read()
    # The appendix itself, not its line in the table of contents.
    text = text[text.rindex("Appendix C.  Test Vectors"):text.rindex("Appendix D.")]
    # Page breaks: the footer, form feed and header lines.
    lines = [l for l in text.splitlines()
             if l.strip() and not l.startswith(("McCallum", "Internet-Draft", "\f"))]
    vectors, cur, field = [], None, None
    for l in lines:
        s = l.strip()
        m = re.match(r"^(\S+) (edwards25519|P-256|P-384|P-521)(.*)$", s)
        if m and m.group(1) in ETYPES:
            cur = {"name": s, "etype": ETYPES[m.group(1)],
                   "group": -1 if "group number -1" in s else GROUPS[m.group(2)]}
            vectors.append(cur)
            field = None
            continue
        if cur is None:
            continue
        m = re.match(r"^(.*?):\s*([0-9a-f]*)$", s)
        if m and m.group(1) in FIELDS:
            field = m.group(1)
            cur[field] = m.group(2)
        elif field and re.fullmatch(r"[0-9a-f]+", s):
            cur[field] += s
        else:
            field = None
    out = []
    for v in vectors:
        row = [v["name"].replace("|", "/"), str(v["etype"]), str(v["group"])]
        row += [v.get(f) or "-" for f in FIELDS]
        out.append("|".join(row))
    dst = os.path.join(os.path.dirname(__file__), "..", "test", "vectors", "spake.txt")
    open(dst, "w").write("\n".join(out) + "\n")
    print(len(out), "vectors")


if __name__ == "__main__":
    main()
