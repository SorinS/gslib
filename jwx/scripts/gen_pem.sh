#!/bin/sh
# PEM fixtures for test/pem.goose, made by OpenSSL (independent of gslib;
# ML-DSA needs OpenSSL 3.5 or later):
# for each key type a private key (PKCS #8, and SEC 1 or PKCS #1 too), its
# public key (SubjectPublicKeyInfo), a self-signed certificate, and the
# certificate's SHA-1 and SHA-256 fingerprints.
#
#   sh scripts/gen_pem.sh      (from jwx/; writes test/vectors/pem)
set -eu
OPENSSL=${OPENSSL:-openssl}
out=test/vectors/pem
mkdir -p "$out"
gen() {
    name=$1; shift
    "$OPENSSL" genpkey "$@" -out "$out/$name.key" 2>/dev/null
    "$OPENSSL" pkey -in "$out/$name.key" -pubout -out "$out/$name.pub"
    "$OPENSSL" req -new -x509 -key "$out/$name.key" -subj "/CN=jwx $name" -days 3650 -out "$out/$name.crt" 2>/dev/null
    for h in sha1 sha256; do
        "$OPENSSL" x509 -in "$out/$name.crt" -noout -fingerprint -$h | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f' > "$out/$name.$h"
    done
}
gen rsa -algorithm RSA -pkeyopt rsa_keygen_bits:2048
gen p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256
gen p384 -algorithm EC -pkeyopt ec_paramgen_curve:P-384
gen p521 -algorithm EC -pkeyopt ec_paramgen_curve:P-521
gen ed25519 -algorithm ED25519
gen mldsa44 -algorithm ML-DSA-44
gen mldsa65 -algorithm ML-DSA-65
gen mldsa87 -algorithm ML-DSA-87
# The traditional forms: PKCS #1 for RSA, SEC 1 for EC.
"$OPENSSL" pkey -in "$out/rsa.key" -traditional -out "$out/rsa-pkcs1.key"
"$OPENSSL" pkey -in "$out/p256.key" -traditional -out "$out/p256-sec1.key"
# ML-DSA's PKCS #8 with the seed alone (the default above is seed and expanded key).
"$OPENSSL" pkey -in "$out/mldsa65.key" -provparam ml-dsa.output_formats=seed-only -out "$out/mldsa65-seed.key"
echo "wrote $out"
