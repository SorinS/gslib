#!/usr/bin/env python3
"""Make saml/test/data's Responses signed by another implementation:
libxmlsec1 (through python-xmlsec) signs the assertion of a Response
issued at 2026-01-01T00:00:00Z (the tests' clock) with the IdP's key,
by rsa-sha1 with SHA-1 digests (which the SP refuses by default) and by
rsa-sha256. Needs lxml and xmlsec in the Python that runs it.

    python3 saml/scripts/make_vectors.py
"""
import os

import xmlsec
from lxml import etree

DATA = os.path.join(os.path.dirname(__file__), "..", "test", "data")
SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion"

RESPONSE = """<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.test/acs" InResponseTo="_req1"><saml:Issuer>https://idp.example.test/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://idp.example.test/metadata</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.test</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2026-01-01T00:05:00Z" Recipient="https://sp.example.test/acs" InResponseTo="_req1"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2025-12-31T23:59:00Z" NotOnOrAfter="2026-01-01T00:05:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example.test/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z" SessionIndex="_s1"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>"""


def sign(name, alg, digest):
    C = xmlsec.constants
    root = etree.fromstring(RESPONSE.encode())
    target = root.find(f"{{{SAML_A}}}Assertion")
    xmlsec.tree.add_ids(target, ["ID"])
    sig = xmlsec.template.create(target, C.TransformExclC14N, alg, ns="ds")
    target.insert(1, sig)
    ref = xmlsec.template.add_reference(sig, digest, uri="#_assert1")
    xmlsec.template.add_transform(ref, C.TransformEnveloped)
    xmlsec.template.add_transform(ref, C.TransformExclC14N)
    ki = xmlsec.template.ensure_key_info(sig)
    xmlsec.template.add_x509_data(ki)
    ctx = xmlsec.SignatureContext()
    k = xmlsec.Key.from_file(os.path.join(DATA, "idp.key"), C.KeyDataFormatPem)
    k.load_cert_from_file(os.path.join(DATA, "idp.crt"), C.KeyDataFormatPem)
    ctx.key = k
    ctx.sign(sig)
    with open(os.path.join(DATA, name), "wb") as f:
        f.write(etree.tostring(root))


def main():
    C = xmlsec.constants
    sign("xmlsec-rsa-sha1.xml", C.TransformRsaSha1, C.TransformSha1)
    sign("xmlsec-rsa-sha256.xml", C.TransformRsaSha256, C.TransformSha256)


if __name__ == "__main__":
    main()
