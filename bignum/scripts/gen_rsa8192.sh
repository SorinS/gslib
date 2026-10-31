#!/bin/sh
# Remakes test/vectors/rsa8192.txt: an 8192-bit RSA key from openssl, and
# openssl's PKCS #1 v1.5 SHA-256 and PSS SHA-256 (salt 32) signatures and
# OAEP SHA-256 ciphertext of "a message". Needs openssl 3 or later.
set -e
d=$(mktemp -d)
trap 'rm -rf "$d"' EXIT
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:8192 -out "$d/k.pem" 2>/dev/null
printf 'a message' > "$d/m"
openssl dgst -sha256 -sign "$d/k.pem" -out "$d/pkcs1" "$d/m"
openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sign "$d/k.pem" -out "$d/pss" "$d/m"
openssl pkeyutl -encrypt -inkey "$d/k.pem" -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -pkeyopt rsa_mgf1_md:sha256 -in "$d/m" -out "$d/oaep"
python3 - "$d" "$(dirname "$0")/../test/vectors/rsa8192.txt" <<'PY'
import re, subprocess, sys
d, out = sys.argv[1], sys.argv[2]
t = subprocess.run(["openssl", "rsa", "-in", f"{d}/k.pem", "-noout", "-text"], capture_output=True, text=True).stdout
def field(name):
    m = re.search(name + r":\s*\n((?:\s+[0-9a-f:]+\n)+)", t)
    v = m.group(1).replace(" ", "").replace("\n", "").replace(":", "").lstrip("0") or "0"
    return v if len(v) % 2 == 0 else "0" + v
e = format(int(re.search(r"publicExponent: (\d+)", t).group(1)), "x")
e = e if len(e) % 2 == 0 else "0" + e
raw = lambda name: open(f"{d}/{name}", "rb").read().hex()
lines = ["# An 8192-bit RSA key from openssl genpkey, and openssl's outputs for",
         "# 'a message': a PKCS #1 v1.5 SHA-256 signature, a PSS SHA-256 (salt 32) signature,",
         "# and an OAEP SHA-256 ciphertext. scripts/gen_rsa8192.sh.",
         f"n {field('modulus')}", f"e {e}", f"d {field('privateExponent')}",
         f"p {field('prime1')}", f"q {field('prime2')}",
         f"pkcs1 {raw('pkcs1')}", f"pss {raw('pss')}", f"oaep {raw('oaep')}"]
open(out, "w").write("\n".join(lines) + "\n")
PY
