#!/usr/bin/env python3
"""Make test/vectors/der.txt with openssl as the oracle.

The samples are real DER from openssl (certificates with RSA, EC and
Ed25519 keys and many extensions, a CSR, private keys in PKCS #8 and SEC 1)
and documents built with `openssl asn1parse -genconf` to reach the rarer
types: BMPString, UniversalString, T61String, GeneralizedTime, negative
and long integers, BOOLEAN, ENUMERATED, IMPLICIT and EXPLICIT tags with
high numbers. For each one the file holds

    der <hex>
    dump <offset> d=<depth> hl=<header> l=<length> cons|prim <class>:<number>
    int <offset> <signed hex>          from openssl's printout
    time <offset> <unix seconds>       openssl's text, through Python's datetime
    str <offset> <hex of UTF-8>        the raw content, decoded by Python
    oid <offset> <dotted>
    end

    python3 scripts/gen_vectors.py
"""

import calendar
import os
import re
import subprocess
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

NAMES = {"BOOLEAN": 1, "INTEGER": 2, "BIT STRING": 3, "OCTET STRING": 4, "NULL": 5,
         "OBJECT": 6, "ENUMERATED": 10, "UTF8STRING": 12, "SEQUENCE": 16, "SET": 17,
         "NUMERICSTRING": 18, "PRINTABLESTRING": 19, "T61STRING": 20, "IA5STRING": 22,
         "UTCTIME": 23, "GENERALIZEDTIME": 24, "VISIBLESTRING": 26, "UNIVERSALSTRING": 28,
         "BMPSTRING": 30}
CLASSES = {"univ": 0, "appl": 1, "cont": 2, "priv": 3}
STRINGS = {12: "utf-8", 19: "ascii", 22: "ascii", 26: "ascii", 20: "latin-1",
           30: "utf-16-be", 28: "utf-32-be"}


def run(args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True).stdout


def oid_text(b):
    arcs, v = [], 0
    for x in b:
        v = (v << 7) | (x & 0x7f)
        if not x & 0x80:
            arcs.append(v)
            v = 0
    first = min(arcs[0] // 40, 2)
    return ".".join(map(str, [first, arcs[0] - 40 * first] + arcs[1:]))


def vectors(der):
    lines = [f"der {der.hex()}"]
    out = run(["asn1parse", "-inform", "DER", "-i"], der).decode("latin-1")
    for line in out.splitlines():
        m = re.match(r"\s*(\d+):d=(\d+)\s+hl=(\d+) l=\s*(\d+) (cons|prim): +(.*)$", line)
        assert m, line
        off, depth, hl, ln, kind, rest = m.groups()
        off, hl, ln = int(off), int(hl), int(ln)
        tm = re.match(r"(cont|appl|priv) \[ (\d+) \]", rest.strip())
        if tm:
            cls, num = CLASSES[tm.group(1)], int(tm.group(2))
            value = ""
        else:
            name = re.sub(r"\s*\[HEX DUMP\]$", "", rest.split(":")[0].strip())
            cls, num = 0, NAMES[name]
            value = rest.split(":", 1)[1].strip() if ":" in rest else ""
        lines.append(f"dump {off} d={depth} hl={hl} l={ln} {kind} {cls}:{num}")
        content = der[off + hl:off + hl + ln]
        if cls != 0:
            continue
        if num == 2:
            lines.append(f"int {off} {value.lower()}")
        elif num == 6:
            lines.append(f"oid {off} {oid_text(content)}")
        elif num in (23, 24):
            s = content.decode()
            if num == 23:
                yy = int(s[:2])
                s = ("20" if yy < 50 else "19") + s
            t = calendar.timegm((int(s[:4]), int(s[4:6]), int(s[6:8]), int(s[8:10]),
                                 int(s[10:12]), int(s[12:14])))
            lines.append(f"time {off} {t}")
        elif num in STRINGS:
            text = content.decode(STRINGS[num])
            lines.append(f"str {off} {text.encode().hex() or '-'}")
    lines.append("end")
    return lines


GENCONF = """
asn1 = SEQUENCE:top
[top]
a = INTEGER:-1
b = INTEGER:-129
c = INTEGER:0
d = INTEGER:0x00ffffffffffffffff
e = INTEGER:-0x0102030405060708090a
f = BOOLEAN:TRUE
g = BOOLEAN:FALSE
h = ENUMERATED:3
i = NULL
j = OID:1.2.840.113549.1.1.11
k = OID:2.999.18446744073709551615
l = FORMAT:UTF8,UTF8:héllo
m = PRINTABLESTRING:Hello World
n = IA5STRING:user@example.com
o = FORMAT:UTF8,BMPSTRING:aé€
p = FORMAT:UTF8,UNIVERSALSTRING:x€😀
q = T61STRING:café
r = VISIBLESTRING:visible
s = UTCTIME:491231235959Z
t = UTCTIME:500101000000Z
u = GENERALIZEDTIME:20500101000000Z
v = GENERALIZEDTIME:99991231235959Z
w = IMPLICIT:0,INTEGER:5
x = EXPLICIT:1,INTEGER:6
y = IMPLICIT:31,OCTETSTRING:abc
z = EXPLICIT:200C,SEQUENCE:inner
aa = IMPLICIT:5A,INTEGER:1
ab = IMPLICIT:7P,BOOLEAN:TRUE
ac = SET:inner
ad = BITSTRING:hello
ae = FORMAT:HEX,OCTETSTRING:00ff10
af = INTEGER:0x7f
ag = INTEGER:0x80
[inner]
x = INTEGER:1
y = FORMAT:UTF8,UTF8:€
"""


def main():
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        def p(name):
            return os.path.join(tmp, name)
        ext = ("subjectAltName=DNS:example.com,DNS:*.example.com,IP:192.0.2.1,email:a@example.com,"
               "URI:https://example.com/")
        for name, key in [("rsa", ["-newkey", "rsa:2048"]),
                          ("p256", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                          ("p384", ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384"]),
                          ("ed25519", ["-newkey", "ed25519"])]:
            run(["req", "-x509", *key, "-nodes", "-subj",
                 "/C=US/ST=Example State/O=Example Org/OU=Unit/CN=example.com/emailAddress=a@example.com",
                 "-addext", ext, "-addext", "basicConstraints=critical,CA:TRUE,pathlen:2",
                 "-addext", "keyUsage=critical,digitalSignature,keyCertSign,cRLSign",
                 "-addext", "extendedKeyUsage=serverAuth,clientAuth",
                 "-days", "400", "-keyout", p(f"{name}.key"), "-out", p(f"{name}.pem")])
            out += vectors(run(["x509", "-in", p(f"{name}.pem"), "-outform", "DER"]))
            out += vectors(run(["pkey", "-in", p(f"{name}.key"), "-outform", "DER"]))
        out += vectors(run(["ec", "-in", p("p256.key"), "-outform", "DER"]))      # SEC 1
        run(["req", "-new", "-key", p("p256.key"), "-subj", "/CN=csr.example", "-out", p("csr.pem")])
        out += vectors(run(["req", "-in", p("csr.pem"), "-outform", "DER"]))
        with open(p("gen.cnf"), "w", encoding="utf-8") as f:
            f.write(GENCONF)
        run(["asn1parse", "-genconf", p("gen.cnf"), "-noout", "-out", p("gen.der")])
        out += vectors(open(p("gen.der"), "rb").read())
    path = os.path.join(ROOT, "test", "vectors", "der.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {sum(l.startswith('der ') for l in out)} documents, "
          f"{sum(l.startswith('dump ') for l in out)} elements to {os.path.relpath(path, ROOT)}")


if __name__ == "__main__":
    main()
