#!/usr/bin/env python3
"""xml's signatures and encryption against Python's signxml and xmlsec
(libxmlsec1), both ways:

  - we sign (every signature method, digest and canonicalization we
    have), signxml and xmlsec verify;
  - signxml and xmlsec sign, we verify;
  - signature wrapping and other tampering of signed documents: we refuse;
  - xmlsec encrypts (AES-GCM, AES-CBC; RSA-OAEP, RSA 1.5), we decrypt;
  - we encrypt (AES-GCM; RSA-OAEP, ECDH-ES), xmlsec decrypts.

It needs a Python with lxml, signxml, xmlsec and cryptography; make one
with

    python3 -m venv VENV && VENV/bin/pip install lxml signxml xmlsec cryptography

and run this script with that Python (XML_PYTHON=VENV/bin/python makes
`make interop-xml` use it). Without the modules it says so and skips.

    python3 scripts/interop.py [--goose PATH] [-v]
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, "test", "data")
TOOL = os.path.join(ROOT, "tools", "xmltool.goose")

try:
    from lxml import etree
    import signxml
    from signxml import XMLSigner, XMLVerifier, SignatureConfiguration
    from signxml.algorithms import SignatureMethod, DigestAlgorithm, CanonicalizationMethod
except ImportError as e:
    print(f"skipped: {e} (see the docstring for a venv)")
    sys.exit(0)
try:
    import xmlsec
except ImportError:
    xmlsec = None

SAML_P = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion"
DS = "http://www.w3.org/2000/09/xmldsig#"

TEMPLATE = """<samlp:Response xmlns:samlp="{SAML_P}" xmlns:saml="{SAML_A}" ID="_resp1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://sp.example.com/acs">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"{lang}>
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@example.com</saml:NameID></saml:Subject>
    <!-- a comment the digest leaves out -->
    <saml:AttributeStatement xmlns:x="urn:example:x">
      <saml:Attribute Name="role" x:note="a &amp; b&#9;c"><saml:AttributeValue xml:lang="en">admin &lt;all&gt;</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
"""
# xml:lang on the assertion: Canonical XML 1.0 and 1.1 carry it onto the
# apex of a subset (SignedInfo), as xmlsec does; signxml, through lxml's
# subtree canonicalization, does not, so its tests use RESPONSE.
RESPONSE = TEMPLATE.replace("{lang}", "").replace("{SAML_P}", SAML_P).replace("{SAML_A}", SAML_A)
RESPONSE_LANG = TEMPLATE.replace("{lang}", ' xml:lang="en"').replace("{SAML_P}", SAML_P).replace("{SAML_A}", SAML_A)
# Where signxml puts the enveloped signature (signing in place, so that
# SignedInfo has the namespaces it will be verified with).
RESPONSE_PLACEHOLDER = RESPONSE.replace("<saml:Issuer>https://idp.example.com</saml:Issuer>\n    <saml:Subject>",
    '<saml:Issuer>https://idp.example.com</saml:Issuer><ds:Signature xmlns:ds="' + DS + '" Id="placeholder"/>\n    <saml:Subject>')

passed = 0
failed = []
verbose = False


def report(name, ok, detail=""):
    global passed
    if ok:
        passed += 1
        if verbose:
            print("ok    " + name)
    else:
        failed.append(name)
        print("FAIL  " + name + (("\n      " + detail.strip().replace("\n", "\n      ")) if detail else ""))


def tool(exe, *args, stdin=None):
    p = subprocess.run([exe, *args], capture_output=True, input=stdin)
    return p.returncode, p.stdout, p.stderr.decode(errors="replace")


def key(name):
    return os.path.join(DATA, name + ".key")


def crt(name):
    return os.path.join(DATA, name + ".crt")


def pem(path):
    return open(path, "rb").read()


def xmlsec_verify(data, cert, id_attr="ID"):
    doc = etree.fromstring(data)
    for el in doc.iter():
        if isinstance(el.tag, str) and el.get(id_attr) is not None:
            xmlsec.tree.add_ids(el, [id_attr])
    sig = xmlsec.tree.find_node(doc, xmlsec.constants.NodeSignature)
    ctx = xmlsec.SignatureContext()
    ctx.key = xmlsec.Key.from_file(cert, xmlsec.constants.KeyDataFormatCertPem)
    ctx.verify(sig)


SIG_METHODS = [
    # (our name, hash, key, signxml method)
    ("rsa", 256, "rsa2048", SignatureMethod.RSA_SHA256),
    ("rsa", 384, "rsa2048", SignatureMethod.RSA_SHA384),
    ("rsa", 512, "rsa2048", SignatureMethod.RSA_SHA512),
    ("pss", 256, "rsa2048", SignatureMethod.SHA256_RSA_MGF1),
    ("pss", 384, "rsa2048", SignatureMethod.SHA384_RSA_MGF1),
    ("pss", 512, "rsa2048", SignatureMethod.SHA512_RSA_MGF1),
    ("ecdsa", 256, "p256", SignatureMethod.ECDSA_SHA256),
    ("ecdsa", 384, "p384", SignatureMethod.ECDSA_SHA384),
    ("ecdsa", 512, "p521", SignatureMethod.ECDSA_SHA512),
    ("ecdsa", 256, "p384", SignatureMethod.ECDSA_SHA256),
]
DIGESTS = {256: DigestAlgorithm.SHA256, 384: DigestAlgorithm.SHA384, 512: DigestAlgorithm.SHA512}
METHODS = {"exc": CanonicalizationMethod.EXCLUSIVE_XML_CANONICALIZATION_1_0,
           "c14n10": CanonicalizationMethod.CANONICAL_XML_1_0,
           "c14n11": CanonicalizationMethod.CANONICAL_XML_1_1}

ALL_SIG = SignatureConfiguration(signature_methods=frozenset(SignatureMethod),
                                 digest_algorithms=frozenset(DigestAlgorithm), require_x509=False)


def we_sign(exe, tmp):
    src = os.path.join(tmp, "response.xml")
    open(src, "w").write(RESPONSE)
    src_lang = os.path.join(tmp, "response-lang.xml")
    open(src_lang, "w").write(RESPONSE_LANG)
    cases = [(s, h, k, sm, dg, m) for (s, h, k, sm) in SIG_METHODS for dg in (256,) for m in ("exc",)]
    cases += [("rsa", 256, "rsa2048", SignatureMethod.RSA_SHA256, dg, m) for dg in (384, 512) for m in ("exc", "c14n10", "c14n11")]
    cases += [("ed25519", 0, "ed25519", None, 256, "exc")]
    for target in ("_assert1", "_resp1"):
        for (s, h, k, sm, dg, m) in cases:
            name = f"we sign {target} {s}-{h} {k} digest {dg} {m}"
            rc, out, err = tool(exe, "sign", key(k), crt(k), src, target, s, str(h), str(dg), m)
            if rc != 0:
                report(name, False, err)
                continue
            # We verify our own, as a check of the tool.
            signed = os.path.join(tmp, "signed.xml")
            open(signed, "wb").write(out)
            rc2, out2, err2 = tool(exe, "verify", crt(k), signed, target)
            report(name + ": we verify", rc2 == 0, out2.decode() + err2)
            if sm is not None:
                try:
                    r = XMLVerifier().verify(out, x509_cert=pem(crt(k)).decode(), id_attribute="ID", expect_config=ALL_SIG)
                    ok = r.signed_xml.get("ID") == target
                    report(name + ": signxml verifies", ok, "signed the wrong element")
                except Exception as e:
                    report(name + ": signxml verifies", False, repr(e))
            if xmlsec is not None:
                rc, out, err = tool(exe, "sign", key(k), crt(k), src_lang, target, s, str(h), str(dg), m)
                try:
                    xmlsec_verify(out, crt(k))
                    report(name + " (xml:lang on the assertion): xmlsec verifies", True)
                except Exception as e:
                    report(name + " (xml:lang on the assertion): xmlsec verifies", False, repr(e))


def they_sign(exe, tmp):
    for (s, h, k, sm) in SIG_METHODS:
        for dg in (256, 384, 512):
            for m, cm in METHODS.items():
                name = f"signxml signs {s}-{h} {k} digest {dg} {m}"
                root = etree.fromstring(RESPONSE_PLACEHOLDER.encode())
                signer = XMLSigner(method=signxml.methods.enveloped, signature_algorithm=sm, digest_algorithm=DIGESTS[dg],
                                   c14n_algorithm=cm)
                signer.namespaces = {"ds": DS}
                try:
                    signed = signer.sign(root, key=pem(key(k)), cert=pem(crt(k)).decode(), reference_uri="_assert1",
                                         id_attribute="ID")
                except Exception as e:
                    report(name, False, repr(e))
                    continue
                data = etree.tostring(signed)
                path = os.path.join(tmp, "theirs.xml")
                open(path, "wb").write(data)
                rc, out, err = tool(exe, "verify", crt(k), path, "_assert1")
                report(name + ": we verify", rc == 0 and out.startswith(b"ok Assertion"), out.decode() + err)
    if xmlsec is None:
        return
    # xmlsec signs: a template with every transform it would add.
    for (alg, k, xs) in [("rsa-sha256", "rsa2048", xmlsec.constants.TransformRsaSha256),
                         ("rsa-sha512", "rsa2048", xmlsec.constants.TransformRsaSha512),
                         ("ecdsa-sha256", "p256", xmlsec.constants.TransformEcdsaSha256),
                         ("ecdsa-sha384", "p384", xmlsec.constants.TransformEcdsaSha384)]:
        for (cname, c14n) in [("exc", xmlsec.constants.TransformExclC14N), ("c14n10", xmlsec.constants.TransformInclC14N),
                              ("c14n11", xmlsec.constants.TransformInclC14N11)]:
            name = f"xmlsec signs {alg} {cname}"
            root = etree.fromstring(RESPONSE_LANG.encode())
            target = root.find(f"{{{SAML_A}}}Assertion")
            xmlsec.tree.add_ids(target, ["ID"])
            sig = xmlsec.template.create(target, c14n, xs, ns="ds")
            target.insert(1, sig)
            ref = xmlsec.template.add_reference(sig, xmlsec.constants.TransformSha256, uri="#_assert1")
            xmlsec.template.add_transform(ref, xmlsec.constants.TransformEnveloped)
            xmlsec.template.add_transform(ref, c14n)
            ki = xmlsec.template.ensure_key_info(sig)
            xmlsec.template.add_x509_data(ki)
            ctx = xmlsec.SignatureContext()
            kk = xmlsec.Key.from_file(key(k), xmlsec.constants.KeyDataFormatPem)
            kk.load_cert_from_file(crt(k), xmlsec.constants.KeyDataFormatPem)
            ctx.key = kk
            try:
                ctx.sign(sig)
            except Exception as e:
                report(name, False, repr(e))
                continue
            path = os.path.join(tmp, "xmlsec.xml")
            open(path, "wb").write(etree.tostring(root))
            rc, out, err = tool(exe, "verify", crt(k), path, "_assert1")
            report(name + ": we verify", rc == 0, out.decode() + err)


def signed_by_signxml(k="rsa2048"):
    root = etree.fromstring(RESPONSE_PLACEHOLDER.encode())
    signer = XMLSigner(method=signxml.methods.enveloped, signature_algorithm=SignatureMethod.RSA_SHA256,
                       digest_algorithm=DigestAlgorithm.SHA256)
    signer.namespaces = {"ds": DS}
    return signer.sign(root, key=pem(key(k)), cert=pem(crt(k)).decode(), reference_uri="_assert1", id_attribute="ID")


def attacks(exe, tmp):
    """Each mutation of a validly signed response must be refused when the
    caller asks for the assertion's enveloped signature, or must not report
    the evil element as signed."""
    def run(name, root, target="_assert1", expect_fail=True, cert="rsa2048"):
        path = os.path.join(tmp, "attack.xml")
        open(path, "wb").write(etree.tostring(root) if not isinstance(root, bytes) else root)
        rc, out, err = tool(exe, "verify", crt(cert), path, target)
        if expect_fail:
            report("refused: " + name, rc != 0, out.decode() + err)
        else:
            report("accepted: " + name, rc == 0, out.decode() + err)

    run("the untouched response (control)", signed_by_signxml(), expect_fail=False)

    r = signed_by_signxml()
    r.find(f".//{{{SAML_A}}}NameID").text = "mallory@example.com"
    run("NameID changed", r)

    r = signed_by_signxml()
    r.find(f".//{{{SAML_A}}}AttributeValue").text = "root"
    run("attribute value changed", r)

    # Wrapping: the signed assertion moved under Extensions/Object, an evil
    # copy with the same ID in its place.
    import copy
    r = signed_by_signxml()
    good = r.find(f"{{{SAML_A}}}Assertion")
    evil = copy.deepcopy(good)
    evil.find(f".//{{{SAML_A}}}NameID").text = "mallory@example.com"
    evil.remove(evil.find(f"{{{DS}}}Signature"))
    ext = etree.SubElement(r, f"{{{SAML_P}}}Extensions")
    r.remove(good)
    ext.append(good)
    r.insert(2, evil)
    run("evil assertion with the same ID, the signed one under Extensions (duplicate ID)", r)

    r = signed_by_signxml()
    good = r.find(f"{{{SAML_A}}}Assertion")
    evil = copy.deepcopy(good)
    evil.find(f".//{{{SAML_A}}}NameID").text = "mallory@example.com"
    evil.set("ID", "_evil")
    sig = good.find(f"{{{DS}}}Signature")
    good.remove(sig)
    evil.remove(evil.find(f"{{{DS}}}Signature"))
    evil.insert(1, sig)
    # The original, unsigned now, hidden in the signature's Object.
    obj = etree.SubElement(sig, f"{{{DS}}}Object")
    r.remove(good)
    obj.append(good)
    r.insert(2, evil)
    run("signature moved into the evil assertion, the original inside ds:Object", r, target="_evil")

    r = signed_by_signxml()
    good = r.find(f"{{{SAML_A}}}Assertion")
    evil = copy.deepcopy(good)
    evil.remove(evil.find(f"{{{DS}}}Signature"))
    evil.set("ID", "_evil")
    evil.find(f".//{{{SAML_A}}}NameID").text = "mallory@example.com"
    sig = good.find(f"{{{DS}}}Signature")
    good.remove(sig)
    evil.insert(1, sig)
    ext = etree.SubElement(r, f"{{{SAML_P}}}Extensions")
    r.remove(good)
    ext.append(good)
    r.insert(2, evil)
    run("evil assertion holding the signature over the original (Reference not the element)", r, target="_evil")

    r = signed_by_signxml()
    ref = r.find(f".//{{{DS}}}Reference")
    ref.set("URI", "#xpointer(id('_assert1'))")
    run("XPointer Reference URI", r)

    r = signed_by_signxml()
    ref = r.find(f".//{{{DS}}}Reference")
    ref.set("URI", "https://example.com/doc.xml")
    run("external Reference URI", r)

    r = signed_by_signxml()
    tr = r.find(f".//{{{DS}}}Transforms")
    t = etree.SubElement(tr, f"{{{DS}}}Transform", Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116")
    etree.SubElement(t, f"{{{DS}}}XPath").text = "not(ancestor-or-self::ds:Signature)"
    run("XPath transform", r)

    r = signed_by_signxml()
    tr = r.find(f".//{{{DS}}}Transforms")
    etree.SubElement(tr, f"{{{DS}}}Transform", Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116")
    run("XSLT transform", r)

    r = signed_by_signxml()
    r.find(f".//{{{DS}}}SignatureMethod").set("Algorithm", "http://www.w3.org/2000/09/xmldsig#hmac-sha1")
    run("HMAC signature method", r)

    r = signed_by_signxml()
    r.find(f".//{{{DS}}}SignatureMethod").set("Algorithm", "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
    run("RSA-SHA1 without allow_sha1", r)

    r = signed_by_signxml()
    si = r.find(f".//{{{DS}}}SignedInfo")
    ref2 = etree.SubElement(si, f"{{{DS}}}Reference", URI="#_resp1")
    run("a second Reference added", r)

    r = signed_by_signxml()
    a = r.find(f"{{{SAML_A}}}Assertion")
    a.append(etree.Comment(" a comment added "))
    run("a comment added (digest leaves comments out)", r, expect_fail=False)

    r = signed_by_signxml()
    run("verified with another key", r, cert="rsa2048b")

    data = etree.tostring(signed_by_signxml()).replace(b"<samlp:Response", b"<!DOCTYPE r [<!ENTITY x \"y\">]><samlp:Response", 1)
    run("a DOCTYPE with entities", data)


def encryption(exe, tmp):
    if xmlsec is None:
        print("xmlsec not installed: encryption interop skipped")
        return
    C = xmlsec.constants
    algs = [("aes128-gcm", C.TransformAes128Gcm, []), ("aes256-gcm", C.TransformAes256Gcm, []),
            ("aes128-cbc", C.TransformAes128Cbc, ["cbc"]), ("aes256-cbc", C.TransformAes256Cbc, ["cbc"])]
    kts = [("rsa-oaep-mgf1p", C.TransformRsaOaep, []), ("rsa-1_5", C.TransformRsaPkcs1, ["rsa15"])]
    for (an, at, aflags) in algs:
        for (kn, kt, kflags) in kts:
            name = f"xmlsec encrypts {an} {kn}"
            root = etree.fromstring(RESPONSE.encode())
            assertion = root.find(f"{{{SAML_A}}}Assertion")
            ed = xmlsec.template.encrypted_data_create(root, at, type=C.TypeEncElement, ns="xenc")
            xmlsec.template.encrypted_data_ensure_cipher_value(ed)
            ki = xmlsec.template.encrypted_data_ensure_key_info(ed, ns="dsig")
            ek = xmlsec.template.add_encrypted_key(ki, kt)
            xmlsec.template.encrypted_data_ensure_cipher_value(ek)
            manager = xmlsec.KeysManager()
            manager.add_key(xmlsec.Key.from_file(crt("rsa2048"), C.KeyDataFormatCertPem, None))
            ctx = xmlsec.EncryptionContext(manager)
            bits = 128 if "128" in an else 256
            ctx.key = xmlsec.Key.generate(C.KeyDataAes, bits, C.KeyDataTypeSession)
            try:
                ctx.encrypt_xml(ed, assertion)
            except Exception as e:
                report(name, False, repr(e))
                continue
            path = os.path.join(tmp, "xmlsec-enc.xml")
            open(path, "wb").write(etree.tostring(root))
            rc, out, err = tool(exe, "decrypt", key("rsa2048"), path, *aflags, *kflags)
            ok = rc == 0 and b"alice@example.com" in out and b"EncryptedData" not in out
            report(name + ": we decrypt", ok, out.decode()[:300] + err)
            if aflags or kflags:
                rc, out, err = tool(exe, "decrypt", key("rsa2048"), path)
                report(name + ": refused without the opt-in", rc != 0, out.decode()[:200] + err)

    src = os.path.join(tmp, "plain.xml")
    open(src, "w").write(RESPONSE)
    for (an, kn, k) in [("aes128-gcm", "rsa-oaep-mgf1p", "rsa2048"), ("aes256-gcm", "rsa-oaep-mgf1p", "rsa2048"),
                        ("aes256-gcm", "rsa-oaep", "rsa2048"), ("aes128-gcm", "ecdh-es", "p256"),
                        ("aes256-gcm", "ecdh-es", "p384"), ("aes256-gcm", "ecdh-es", "p521")]:
        name = f"we encrypt {an} {kn} {k}"
        rc, out, err = tool(exe, "encrypt", crt(k), src, "_assert1", an, kn)
        if rc != 0:
            report(name, False, err)
            continue
        rc2, out2, err2 = tool(exe, "decrypt", key(k), "/dev/stdin", stdin=out)
        report(name + ": we decrypt", rc2 == 0 and b"alice@example.com" in out2, out2.decode()[:200] + err2)
        if kn == "ecdh-es":
            # python-xmlsec cannot raise libxmlsec1's maxEncryptedKeyLevel,
            # which ECDH-ES needs: decrypt with cryptography instead.
            try:
                report(name + ": cryptography decrypts", b"alice@example.com" in ecdh_decrypt(out, key(k)))
            except Exception as e:
                report(name + ": cryptography decrypts", False, repr(e))
            continue
        try:
            root = etree.fromstring(out)
            ed = root.find(".//{http://www.w3.org/2001/04/xmlenc#}EncryptedData")
            manager = xmlsec.KeysManager()
            manager.add_key(xmlsec.Key.from_file(key(k), C.KeyDataFormatPem, None))
            ctx = xmlsec.EncryptionContext(manager)
            dec = ctx.decrypt(ed)
            ok = b"alice@example.com" in etree.tostring(root)
            report(name + ": xmlsec decrypts", ok)
        except Exception as e:
            report(name + ": xmlsec decrypts", False, repr(e))


def ecdh_decrypt(data, key_path):
    """An EncryptedData with an ECDH-ES EncryptedKey (ConcatKDF, AES key
    wrap) and AES-GCM content, decrypted with cryptography alone."""
    import base64
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    X = "{http://www.w3.org/2001/04/xmlenc#}"
    X11 = "{http://www.w3.org/2009/xmlenc11#}"
    D11 = "{http://www.w3.org/2009/xmldsig11#}"
    root = etree.fromstring(data)
    ed = root.find(f".//{X}EncryptedData")
    ek = ed.find(f".//{X}EncryptedKey")
    kw = {"kw-aes128": 16, "kw-aes192": 24, "kw-aes256": 32}[ek.find(f"{X}EncryptionMethod").get("Algorithm").split("#")[1]]
    params = ek.find(f".//{X11}ConcatKDFParams")
    hname = params.find(f"{{{DS}}}DigestMethod").get("Algorithm").split("#")[1]
    h = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}[hname]
    other = b""
    for a in ("AlgorithmID", "PartyUInfo", "PartyVInfo"):
        v = params.get(a) or ""
        if v:
            assert v[:2] == "00"
            other += bytes.fromhex(v[2:])
    pub = base64.b64decode(ek.find(f".//{D11}PublicKey").text)
    priv = serialization.load_pem_private_key(pem(key_path), None)
    peer = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, pub)
    z = priv.exchange(ec.ECDH(), peer)
    kek = ConcatKDFHash(algorithm=h, length=kw, otherinfo=other).derive(z)
    cek = aes_key_unwrap(kek, base64.b64decode(ek.find(f"{X}CipherData/{X}CipherValue").text))
    ct = base64.b64decode(ed.find(f"{X}CipherData/{X}CipherValue").text)
    return AESGCM(cek).decrypt(ct[:12], ct[12:], None)


def main():
    global verbose
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("-v", action="store_true")
    args = ap.parse_args()
    verbose = args.v
    goose = None
    for cand in [args.goose, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "..", "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            goose = cand
            break
    if goose is None:
        sys.exit("no goose compiler found: pass --goose or set GOOSE")
    print(f"signxml {signxml.__version__ if hasattr(signxml, '__version__') else ''}, "
          f"xmlsec {xmlsec.get_libxmlsec_version() if xmlsec else 'not installed'}")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "xmltool")
        p = subprocess.run([goose, "build", "-o", exe, TOOL], capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("cannot build xmltool:\n" + p.stdout + p.stderr)
        we_sign(exe, tmp)
        they_sign(exe, tmp)
        attacks(exe, tmp)
        encryption(exe, tmp)
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
