#!/usr/bin/env python3
"""Make test/vectors/pkinit.txt: a CA, KDC certificates and the KDC's key
from scripts/pki.py (OpenSSL), for test/pkinit.goose to sign replies as
a KDC would and check the client's side of them. Test keys only.

    python3 scripts/pkinit_vectors.py

Lines: "now UNIX" (a time inside the certificates' validity), then
"cert NAME HEX" (DER) and "key NAME HEX" (PKCS #8 DER) for ca, kdc,
kdc-dns, kdc-noeku and rogue.
"""

import os
import subprocess
import tempfile
import time

from pki import Pki, openssl

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def main():
    d = tempfile.mkdtemp()
    p = Pki(d)
    p.make()
    der = lambda *a: subprocess.run([openssl(), *a], capture_output=True, check=True).stdout
    lines = [f"now {int(time.time()) + 3600}"]
    for name in ("ca", "kdc", "kdc-dns", "kdc-noeku", "rogue"):
        lines.append(f"cert {name} {der('x509', '-in', p.path(name + '.pem'), '-outform', 'DER').hex()}")
        lines.append(f"key {name} {der('pkey', '-in', p.path(name + '.key'), '-outform', 'DER').hex()}")
    with open(os.path.join(ROOT, "test", "vectors", "pkinit.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"{len(lines)} lines")


if __name__ == "__main__":
    main()
