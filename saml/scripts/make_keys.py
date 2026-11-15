#!/usr/bin/env python3
"""Make saml/test/data's keys and self-signed certificates (for the tests
only): an IdP's and an SP's RSA 2048 keys, an attacker's, an RSA 1024 one,
and P-256 and Ed25519 ones. Needs the cryptography package.

    python3 saml/scripts/make_keys.py
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

OUT = os.path.join(os.path.dirname(__file__), "..", "test", "data")


def make(name, key, cn):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650 * 3)))
    algo = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    cert = cert.sign(key, algo)
    with open(os.path.join(OUT, name + ".key"), "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    with open(os.path.join(OUT, name + ".crt"), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def main():
    os.makedirs(OUT, exist_ok=True)
    make("idp", rsa.generate_private_key(65537, 2048), "idp.example.test")
    make("sp", rsa.generate_private_key(65537, 2048), "sp.example.test")
    make("evil", rsa.generate_private_key(65537, 2048), "idp.example.test")
    make("rsa1024", rsa.generate_private_key(65537, 1024), "small.example.test")
    make("idp-p256", ec.generate_private_key(ec.SECP256R1()), "idp.example.test")
    make("sp-p256", ec.generate_private_key(ec.SECP256R1()), "sp.example.test")
    make("idp-ed25519", ed25519.Ed25519PrivateKey.generate(), "idp.example.test")


if __name__ == "__main__":
    main()
