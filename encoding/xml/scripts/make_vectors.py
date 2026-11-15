#!/usr/bin/env python3
"""Writes the signed and encrypted documents of test/data that other
implementations made, which test/dsig.goose and test/enc.goose verify and
decrypt without them: signxml's and xmlsec's signatures (xmlsec's for SHA-1, which signxml no longer makes), and xmlsec's and
cryptography's encryption (for the algorithms we only decrypt: AES-CBC,
RSA PKCS #1 v1.5, rsa-oaep with differing hashes). Run with the Python of
scripts/interop.py; the files are committed, so this is only to remake
them. With --keys it first makes new test keys and self-signed
certificates (RSA 2048 twice and 1024, P-256, P-384, P-521, Ed25519),
which every vector then has to be made again for.

    python3 scripts/make_vectors.py [--keys]
"""

import base64
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import interop  # noqa: E402
from interop import etree, signxml, XMLSigner, SignatureMethod, DigestAlgorithm, CanonicalizationMethod, \
    SignatureConfiguration, xmlsec, DS, SAML_A, pem, key, crt, DATA  # noqa: E402


def write(name, data):
    open(os.path.join(DATA, name), "wb").write(data)
    print("wrote", name)


def signxml_vector(name, method, digest, c14n, k="rsa2048"):
    root = etree.fromstring(interop.RESPONSE_PLACEHOLDER.encode())
    signer = XMLSigner(method=signxml.methods.enveloped, signature_algorithm=method, digest_algorithm=digest,
                       c14n_algorithm=c14n)
    signer.namespaces = {"ds": DS}
    signed = signer.sign(root, key=pem(key(k)), cert=pem(crt(k)).decode(), reference_uri="_assert1", id_attribute="ID")
    write(name, etree.tostring(signed))


def xmlsec_sign_vector(name, k, alg, c14n, digest=None):
    C = xmlsec.constants
    root = etree.fromstring(interop.RESPONSE_LANG.encode())
    target = root.find(f"{{{SAML_A}}}Assertion")
    xmlsec.tree.add_ids(target, ["ID"])
    sig = xmlsec.template.create(target, c14n, alg, ns="ds")
    target.insert(1, sig)
    ref = xmlsec.template.add_reference(sig, digest or C.TransformSha384, uri="#_assert1")
    xmlsec.template.add_transform(ref, C.TransformEnveloped)
    xmlsec.template.add_transform(ref, c14n)
    ki = xmlsec.template.ensure_key_info(sig)
    xmlsec.template.add_x509_data(ki)
    ctx = xmlsec.SignatureContext()
    kk = xmlsec.Key.from_file(key(k), C.KeyDataFormatPem)
    kk.load_cert_from_file(crt(k), C.KeyDataFormatPem)
    ctx.key = kk
    ctx.sign(sig)
    write(name, etree.tostring(root))


def xmlsec_encrypt_vector(name, alg, kt, bits):
    C = xmlsec.constants
    root = etree.fromstring(interop.RESPONSE.encode())
    assertion = root.find(f"{{{SAML_A}}}Assertion")
    ed = xmlsec.template.encrypted_data_create(root, alg, type=C.TypeEncElement, ns="xenc")
    xmlsec.template.encrypted_data_ensure_cipher_value(ed)
    ki = xmlsec.template.encrypted_data_ensure_key_info(ed, ns="dsig")
    ek = xmlsec.template.add_encrypted_key(ki, kt)
    xmlsec.template.encrypted_data_ensure_cipher_value(ek)
    manager = xmlsec.KeysManager()
    manager.add_key(xmlsec.Key.from_file(crt("rsa2048"), C.KeyDataFormatCertPem, None))
    ctx = xmlsec.EncryptionContext(manager)
    ctx.key = xmlsec.Key.generate(C.KeyDataAes, bits, C.KeyDataTypeSession)
    ctx.encrypt_xml(ed, assertion)
    write(name, etree.tostring(root))


def oaep_mixed_vector(name):
    """rsa-oaep (xmlenc11) with a SHA-256 digest and MGF1 with SHA-1 (the
    MGF element left out: its default), AES-128-GCM content, the
    EncryptedKey beside the EncryptedData as SAML's EncryptedAssertion
    holds it, named by a RetrievalMethod."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    cert = __import__("cryptography.x509", fromlist=["x"]).load_pem_x509_certificate(pem(crt("rsa2048")))
    cek = os.urandom(16)
    iv = os.urandom(12)
    plain = etree.tostring(etree.fromstring(interop.RESPONSE.encode()).find(f"{{{SAML_A}}}Assertion"))
    ct = iv + AESGCM(cek).encrypt(iv, plain, None)
    wrapped = cert.public_key().encrypt(cek, padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None))
    b = lambda x: base64.b64encode(x).decode()
    doc = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="{SAML_A}" ID="_resp1"><saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Type="http://www.w3.org/2001/04/xmlenc#Element"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes128-gcm"/><ds:KeyInfo xmlns:ds="{DS}"><ds:RetrievalMethod Type="http://www.w3.org/2001/04/xmlenc#EncryptedKey" URI="#_ek1"/></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>{b(ct)}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="_ek1"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep"><ds:DigestMethod xmlns:ds="{DS}" Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>
{b(wrapped)[:64]}
{b(wrapped)[64:]}
</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></saml:EncryptedAssertion></samlp:Response>"""
    write(name, doc.encode())


def make_keys():
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

    def make(name, k, h):
        subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"xml test {name}")])
        start = datetime.datetime(2026, 1, 1)
        cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(k.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(start)
                .not_valid_after(start + datetime.timedelta(days=36500)).sign(k, h))
        write(name + ".key", k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                             serialization.NoEncryption()))
        write(name + ".crt", cert.public_bytes(serialization.Encoding.PEM))

    make("rsa2048", rsa.generate_private_key(65537, 2048), hashes.SHA256())
    make("rsa2048b", rsa.generate_private_key(65537, 2048), hashes.SHA256())
    make("rsa1024", rsa.generate_private_key(65537, 1024), hashes.SHA256())
    make("p256", ec.generate_private_key(ec.SECP256R1()), hashes.SHA256())
    make("p384", ec.generate_private_key(ec.SECP384R1()), hashes.SHA384())
    make("p521", ec.generate_private_key(ec.SECP521R1()), hashes.SHA512())
    make("ed25519", ed25519.Ed25519PrivateKey.generate(), None)


def main():
    if "--keys" in sys.argv[1:]:
        make_keys()
    signxml_vector("signxml-rsa-sha256-exc.xml", SignatureMethod.RSA_SHA256, DigestAlgorithm.SHA256,
                   CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)
    signxml_vector("signxml-ecdsa-p384-c14n11.xml", SignatureMethod.ECDSA_SHA384, DigestAlgorithm.SHA512,
                   CanonicalizationMethod.CANONICAL_XML_1_1, k="p384")
    signxml_vector("signxml-pss-sha256.xml", SignatureMethod.SHA256_RSA_MGF1, DigestAlgorithm.SHA256,
                   CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0)
    C = xmlsec.constants
    xmlsec_sign_vector("xmlsec-ecdsa-p256-c14n10.xml", "p256", C.TransformEcdsaSha256, C.TransformInclC14N)
    xmlsec_sign_vector("xmlsec-rsa-sha512-c14n11.xml", "rsa2048", C.TransformRsaSha512, C.TransformInclC14N11)
    xmlsec_sign_vector("xmlsec-rsa-sha1.xml", "rsa2048", C.TransformRsaSha1, C.TransformExclC14N, C.TransformSha1)
    xmlsec_encrypt_vector("xmlsec-aes128-gcm-oaep.xml", C.TransformAes128Gcm, C.TransformRsaOaep, 128)
    xmlsec_encrypt_vector("xmlsec-aes256-cbc-oaep.xml", C.TransformAes256Cbc, C.TransformRsaOaep, 256)
    xmlsec_encrypt_vector("xmlsec-aes128-cbc-rsa15.xml", C.TransformAes128Cbc, C.TransformRsaPkcs1, 128)
    oaep_mixed_vector("oaep-sha256-mgf1sha1-retrieval.xml")


if __name__ == "__main__":
    main()
