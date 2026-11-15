// XML Signature: signing and verifying with every method, digest and
// canonicalization; signatures signxml and xmlsec made (test/data, from
// scripts/make_vectors.py); and what verification must refuse: signature
// wrapping (a copy with the signed ID, the signature moved into an evil
// element with the signed one under ds:Object, a Reference to a sibling,
// a whole-document signature moved into an element, two signatures, two
// References), References other than "" and #id, transforms beyond
// enveloped-signature and one canonicalization, algorithms not allowed
// (HMAC, SHA-1 without allow_sha1), malformed Signatures, tampering, the
// wrong key, a small RSA key, a key of another type.
import std;
import base64;
import gslib from "../../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;
import gslib.encoding.xml.dsig;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let RSA_KEY = embed_file("data/rsa2048.key");
let RSA_CRT = embed_file("data/rsa2048.crt");
let RSA_B_CRT = embed_file("data/rsa2048b.crt");
let RSA1024_KEY = embed_file("data/rsa1024.key");
let RSA1024_CRT = embed_file("data/rsa1024.crt");
let P256_KEY = embed_file("data/p256.key");
let P256_CRT = embed_file("data/p256.crt");
let P384_KEY = embed_file("data/p384.key");
let P384_CRT = embed_file("data/p384.crt");
let P521_KEY = embed_file("data/p521.key");
let P521_CRT = embed_file("data/p521.crt");
let ED_KEY = embed_file("data/ed25519.key");
let ED_CRT = embed_file("data/ed25519.crt");

let V_SIGNXML_RSA = embed_file("data/signxml-rsa-sha256-exc.xml");
let V_SIGNXML_PSS = embed_file("data/signxml-pss-sha256.xml");
let V_SIGNXML_P384 = embed_file("data/signxml-ecdsa-p384-c14n11.xml");
let V_XMLSEC_P256 = embed_file("data/xmlsec-ecdsa-p256-c14n10.xml");
let V_XMLSEC_RSA512 = embed_file("data/xmlsec-rsa-sha512-c14n11.xml");
let V_XMLSEC_SHA1 = embed_file("data/xmlsec-rsa-sha1.xml");

let SAML_P = "urn:oasis:names:tc:SAML:2.0:protocol";
let SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion";

let RESPONSE = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp1\">\n  <saml:Issuer>https://idp.example.com</saml:Issuer>\n  <saml:Assertion ID=\"_assert1\" xml:lang=\"en\">\n    <saml:Issuer>https://idp.example.com</saml:Issuer>\n    <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>\n    <!-- comment -->\n    <saml:AttributeStatement xmlns:x=\"urn:x\"><saml:Attribute Name=\"role\" x:n=\"a&#9;b\"><saml:AttributeValue>admin &amp; more</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>\n  </saml:Assertion>\n  <saml:Assertion ID=\"_assert2\"><saml:Subject><saml:NameID>bob@example.com</saml:NameID></saml:Subject></saml:Assertion>\n</samlp:Response>";

fn key_of(text: const u8[:]) -> x509::PrivateKey {
    let k, ok = x509::parse_private_key_pem(text);
    assert(ok);
    return k;
}

fn cert_of(text: const u8[:]) -> x509::Cert {
    let c, e = x509::parse_pem(text);
    assert(e == x509::OK);
    return c;
}

// RESPONSE with the element of ID `id` signed, written out.
fn signed(key_pem: const u8[:], cert_pem: const u8[:], id: const u8[:], o: const xml::SignOptions&) -> u8[>..] {
    let key = key_of(key_pem);
    let cert = cert_of(cert_pem);
    var d = xml::Doc { .. };
    let e = xml::parse(d, RESPONSE);
    assert(e.code == xml::OK);
    let el, n = xml::by_id(d, id);
    assert(n == 1);
    // After its Issuer, as SAML has it.
    let before = xml::next_element(d, xml::first_element(d, el));
    var out: u8[>..] = [];
    let sig, se = xml::sign_enveloped(d, el, before, key, cert.der, o);
    if se != xml::OK { out.append(str("sign error ", se)); return out; }
    xml::write_document(d, out);
    return out;
}

// Parses text and verifies the enveloped signature of the element with ID
// id: the error code (a parse error's, or verification's).
fn verify_code(text: const u8[:], cert_pem: const u8[:], id: const u8[:], o: const xml::VerifyOptions&) -> i64 {
    let cert = cert_of(cert_pem);
    var d = xml::Doc { .. };
    let e = xml::parse(d, text);
    if e.code != xml::OK { return e.code; }
    let el, n = xml::by_id(d, id);
    if n != 1 { return -1; }
    let v = xml::verify_enveloped(d, el, cert, o);
    return v.code;
}

fn vcode(text: const u8[:], cert_pem: const u8[:], id: const u8[:]) -> i64 {
    let o = xml::verify_options();
    return verify_code(text, cert_pem, id, o);
}

fn expect_code(what: const u8[:], got: i64, want: i64) {
    check(str(what, ": want ", xml::dsig_error_name(want), ", got ", xml::dsig_error_name(got), " (", got, ")"), got == want);
}

// A signature method and hash, with a key: 0 RSA, 1 P-256, 2 P-384, 3
// P-521, 4 Ed25519.
struct Case { alg: i64, h: i64, which: i64 }

fn matrix() {
    var o = xml::sign_options();
    var cases: Case[>..] = [];
    for h in [256, 384, 512] {
        cases.push(Case { alg: x509::SIG_RSA_PKCS1, h: h, which: 0 });
        cases.push(Case { alg: x509::SIG_RSA_PSS, h: h, which: 0 });
        cases.push(Case { alg: x509::SIG_ECDSA, h: h, which: 1 });
    }
    cases.push(Case { alg: x509::SIG_ECDSA, h: 384, which: 2 });
    cases.push(Case { alg: x509::SIG_ECDSA, h: 512, which: 3 });
    cases.push(Case { alg: x509::SIG_ED25519, h: 0, which: 4 });
    for c in cases {
        o.alg = c.alg;
        o.hash = c.h;
        let kp = if c.which == 0 { RSA_KEY } else if c.which == 1 { P256_KEY } else if c.which == 2 { P384_KEY } else if c.which == 3 { P521_KEY } else { ED_KEY };
        let cp = if c.which == 0 { RSA_CRT } else if c.which == 1 { P256_CRT } else if c.which == 2 { P384_CRT } else if c.which == 3 { P521_CRT } else { ED_CRT };
        let s = signed(kp, cp, "_assert1", o);
        expect_code(str("sign and verify alg ", c.alg, " hash ", c.h, " key ", c.which), vcode(s, cp, "_assert1"), xml::OK);
    }
    o = xml::sign_options();
    for m in [xml::C14N_10, xml::C14N_11, xml::EXC_C14N] {
        for dg in [256, 384, 512] {
            o.c14n = m;
            o.digest = dg;
            let s = signed(RSA_KEY, RSA_CRT, "_assert1", o);
            expect_code(str("c14n ", m, " digest ", dg), vcode(s, RSA_CRT, "_assert1"), xml::OK);
            let r = signed(P256_KEY, P256_CRT, "_resp1", o);
            expect_code(str("the response, c14n ", m, " digest ", dg), vcode(r, P256_CRT, "_resp1"), xml::OK);
        }
    }
    o = xml::sign_options();
    format(o.inclusive, "saml #default");
    let inc = signed(RSA_KEY, RSA_CRT, "_assert1", o);
    expect_code("InclusiveNamespaces", vcode(inc, RSA_CRT, "_assert1"), xml::OK);
    check("InclusiveNamespaces written", find(inc, "PrefixList=\"saml #default\"") >= 0);
    o = xml::sign_options();
    o.prefix.clear();
    let nop = signed(RSA_KEY, RSA_CRT, "_assert1", o);
    expect_code("default-namespace Signature", vcode(nop, RSA_CRT, "_assert1"), xml::OK);
    check("written without a prefix", find(nop, "<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">") >= 0);

    // A document element without an ID: URI "".
    let key = key_of(P256_KEY);
    let cert = cert_of(P256_CRT);
    var d = xml::Doc { .. };
    xml::parse(d, "<doc xmlns=\"urn:d\"><a>1</a><!-- c --></doc>");
    let root = xml::root_element(d);
    let sig, se = xml::sign_enveloped(d, root, -1, key, cert.der);
    check("sign the document", se == xml::OK);
    var out: u8[>..] = [];
    xml::write(d, 0, out);
    check("URI \"\"", find(out, "URI=\"\"") >= 0);
    var d2 = xml::Doc { .. };
    xml::parse(d2, out);
    let v = xml::verify_enveloped(d2, xml::root_element(d2), cert);
    check("verify the document", v.code == xml::OK && v.refs.len == 1 && v.refs[0] == 0);
    check("is_signed: a child", xml::is_signed(d2, v, xml::first_element(d2, xml::root_element(d2))));
    check("is_signed: not the signature", !xml::is_signed(d2, v, xml::child(d2, xml::root_element(d2), xml::DSIG_NS, "Signature")));
    // A child without an ID cannot be signed.
    let s2, e2 = xml::sign_enveloped(d, xml::first_element(d, root), -1, key, cert.der);
    check("no ID, not the root: refused", e2 == xml::ERR_DSIG_ID);
    // Algorithms that do not fit the key.
    var bad = xml::sign_options();
    bad.alg = x509::SIG_RSA_PKCS1;
    let s3, e3 = xml::sign_enveloped(d, root, -1, key, cert.der, bad);
    check("RSA with an EC key: refused", e3 == xml::ERR_DSIG_KEY);
    bad = xml::sign_options();
    bad.digest = 160;
    let s4, e4 = xml::sign_enveloped(d, root, -1, key, cert.der, bad);
    check("signing with SHA-1: refused", e4 == xml::ERR_DSIG_ALGORITHM);
}

fn vectors() {
    expect_code("signxml RSA-SHA256, exclusive", vcode(V_SIGNXML_RSA, RSA_CRT, "_assert1"), xml::OK);
    expect_code("signxml RSA-PSS SHA-256", vcode(V_SIGNXML_PSS, RSA_CRT, "_assert1"), xml::OK);
    expect_code("signxml ECDSA P-384, c14n 1.1, SHA-512", vcode(V_SIGNXML_P384, P384_CRT, "_assert1"), xml::OK);
    expect_code("xmlsec ECDSA P-256, c14n 1.0, xml:lang on the assertion", vcode(V_XMLSEC_P256, P256_CRT, "_assert1"), xml::OK);
    expect_code("xmlsec RSA-SHA512, c14n 1.1, xml:lang on the assertion", vcode(V_XMLSEC_RSA512, RSA_CRT, "_assert1"), xml::OK);
    expect_code("xmlsec RSA-SHA1 refused", vcode(V_XMLSEC_SHA1, RSA_CRT, "_assert1"), xml::ERR_DSIG_ALGORITHM);
    var o = xml::verify_options();
    o.allow_sha1 = true;
    expect_code("xmlsec RSA-SHA1 with allow_sha1", verify_code(V_XMLSEC_SHA1, RSA_CRT, "_assert1", o), xml::OK);
    expect_code("signxml's with another key", vcode(V_SIGNXML_RSA, RSA_B_CRT, "_assert1"), xml::ERR_DSIG_SIGNATURE);
    expect_code("ECDSA signature, RSA certificate", vcode(V_XMLSEC_P256, RSA_CRT, "_assert1"), xml::ERR_DSIG_KEY);
    expect_code("P-256 signature, P-384 certificate", vcode(V_XMLSEC_P256, P384_CRT, "_assert1"), xml::ERR_DSIG_SIGNATURE);
    // KeyInfo's certificate is handed over, not trusted.
    var d = xml::Doc { .. };
    xml::parse(d, V_SIGNXML_RSA);
    var sigs: i64[>..<] = [];
    xml::find_signatures(d, sigs);
    let der, has = xml::keyinfo_cert(d, sigs[0]);
    let cert = cert_of(RSA_CRT);
    check("keyinfo_cert", sigs.len == 1 && has && der == cert.der);
}

// Replaces the first `old` in text with `new`.
fn replaced(text: const u8[:], old: const u8[:], new: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let i = find(text, old);
    assert(i >= 0);
    out.append(text[..i]);
    out.append(new);
    out.append(text[i + old.len..]);
    return out;
}

// Signs SignedInfo of sig again with the RSA key, after it was changed.
fn resign(d: xml::Doc&, sig: i64) {
    let key = key_of(RSA_KEY);
    let si = xml::child(d, sig, xml::DSIG_NS, "SignedInfo");
    let m = xml::C14n { .. };
    var octets: u8[>..] = [];
    xml::canonicalize(d, si, m, octets);
    let s, ok = x509::sign(key, x509::SIG_RSA_PKCS1, 256, octets);
    var b: u8[>..] = [];
    base64::encode(b, s);
    xml::set_text(d, xml::child(d, sig, xml::DSIG_NS, "SignatureValue"), b);
}

fn sig_parts(d: const xml::Doc&, el: i64) -> i64, i64, i64 {
    let sig = xml::child(d, el, xml::DSIG_NS, "Signature");
    let si = xml::child(d, sig, xml::DSIG_NS, "SignedInfo");
    let r = xml::child(d, si, xml::DSIG_NS, "Reference");
    return sig, si, r;
}

fn tampering() {
    let o = xml::sign_options();
    let s = signed(RSA_KEY, RSA_CRT, "_assert1", o);
    expect_code("control", vcode(s, RSA_CRT, "_assert1"), xml::OK);
    expect_code("NameID changed", vcode(replaced(s, "alice@", "mallory@"), RSA_CRT, "_assert1"), xml::ERR_DSIG_DIGEST);
    expect_code("white space added", vcode(replaced(s, "<saml:Subject>", "<saml:Subject> "), RSA_CRT, "_assert1"), xml::ERR_DSIG_DIGEST);
    expect_code("attribute added", vcode(replaced(s, "Name=\"role\"", "Name=\"role\" admin=\"1\""), RSA_CRT, "_assert1"), xml::ERR_DSIG_DIGEST);
    expect_code("xml:lang changed", vcode(replaced(s, "xml:lang=\"en\"", "xml:lang=\"fr\""), RSA_CRT, "_assert1"), xml::ERR_DSIG_DIGEST);
    expect_code("a comment added: comments are not signed", vcode(replaced(s, "<saml:Subject>", "<!--x--><saml:Subject>"), RSA_CRT, "_assert1"), xml::OK);
    expect_code("SignatureValue changed", vcode(replaced(s, "<ds:SignatureValue>", "<ds:SignatureValue>AAAA"), RSA_CRT, "_assert1"), xml::ERR_DSIG_SIGNATURE);
    expect_code("SignatureValue not base64", vcode(replaced(s, "<ds:SignatureValue>", "<ds:SignatureValue>!"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("SignatureValue line-wrapped", vcode(replaced(s, "<ds:SignatureValue>", "<ds:SignatureValue>\n"), RSA_CRT, "_assert1"), xml::OK);
    expect_code("DigestValue too short", vcode(replaced(s, "<ds:DigestValue>", "<ds:DigestValue>AAAA"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("another certificate", vcode(s, RSA_B_CRT, "_assert1"), xml::ERR_DSIG_SIGNATURE);
    expect_code("the other assertion is not signed", vcode(s, RSA_CRT, "_assert2"), xml::ERR_DSIG_WRAPPING);
    var small = xml::sign_options();
    let s1024 = signed(RSA1024_KEY, RSA1024_CRT, "_assert1", small);
    expect_code("RSA 1024 refused", vcode(s1024, RSA1024_CRT, "_assert1"), xml::ERR_DSIG_KEY);
    var lax = xml::verify_options();
    lax.min_rsa_bits = 1024;
    expect_code("RSA 1024 with min_rsa_bits 1024", verify_code(s1024, RSA1024_CRT, "_assert1", lax), xml::OK);

    // Malformed or not allowed, before the signature is looked at.
    expect_code("HMAC", vcode(replaced(s, "xmldsig-more#rsa-sha256", "xmldsig-more#hmac-sha256"), RSA_CRT, "_assert1"), xml::ERR_DSIG_ALGORITHM);
    expect_code("HMACOutputLength", vcode(replaced(s, "rsa-sha256\"/>", "rsa-sha256\"><ds:HMACOutputLength>80</ds:HMACOutputLength></ds:SignatureMethod>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("SHA-1 digest", vcode(replaced(s, "xmlenc#sha256", "xmldsig#sha1"), RSA_CRT, "_assert1"), xml::ERR_DSIG_ALGORITHM);
    expect_code("an unknown canonicalization", vcode(replaced(s, "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>", "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2006/12/xml-c14n12\"/>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_ALGORITHM);
    expect_code("XPath transform", vcode(replaced(s, "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>", "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xpath-19991116\"><ds:XPath>1</ds:XPath></ds:Transform>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_TRANSFORM);
    expect_code("XSLT transform", vcode(replaced(s, "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>", "<ds:Transform Algorithm=\"http://www.w3.org/TR/1999/REC-xslt-19991116\"/>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_TRANSFORM);
    expect_code("a third transform", vcode(replaced(s, "</ds:Transforms>", "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_TRANSFORM);
    expect_code("two canonicalizations", vcode(replaced(s, "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>", "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_TRANSFORM);
    expect_code("enveloped after the canonicalization", vcode(replaced(s, "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>", "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_TRANSFORM);
    expect_code("an unknown element in SignedInfo", vcode(replaced(s, "</ds:SignedInfo>", "<ds:Extra/></ds:SignedInfo>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("an element of another namespace in SignedInfo", vcode(replaced(s, "</ds:SignedInfo>", "<x:Extra xmlns:x=\"urn:x\"/></ds:SignedInfo>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("text in SignedInfo", vcode(replaced(s, "</ds:SignedInfo>", "text</ds:SignedInfo>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("no SignatureValue", vcode(replaced(s, "<ds:SignatureValue>", "<ds:SignatureValueX>"), RSA_CRT, "_assert1"), xml::ERR_TAG);
    expect_code("Signature without a SignedInfo first", vcode(replaced(s, "<ds:SignedInfo>", "<ds:Object/><ds:SignedInfo>"), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    expect_code("an attribute on Reference", vcode(replaced(s, "<ds:Reference ", "<ds:Reference Evil=\"1\" "), RSA_CRT, "_assert1"), xml::ERR_DSIG_MALFORMED);
    var one = xml::verify_options();
    one.max_references = 0;
    expect_code("max_references", verify_code(s, RSA_CRT, "_assert1", one), xml::ERR_DSIG_REFERENCE);
    expect_code("a DOCTYPE", vcode(replaced(s, "<samlp:Response", "<!DOCTYPE r [<!ENTITY e \"x\">]><samlp:Response"), RSA_CRT, "_assert1"), xml::ERR_DOCTYPE);
}

fn wrapping() {
    let o = xml::sign_options();
    let s = signed(RSA_KEY, RSA_CRT, "_assert1", o);
    let cert = cert_of(RSA_CRT);

    // An evil copy with the signed ID: two elements with one ID.
    let evil = "<saml:Assertion ID=\"_assert1\"><saml:Subject><saml:NameID>mallory@example.com</saml:NameID></saml:Subject></saml:Assertion>";
    expect_code("an evil copy with the same ID before it", vcode(replaced(s, "<saml:Assertion ID=\"_assert1\"", str(evil, "<saml:Assertion ID=\"_assert1\"")), RSA_CRT, "_assert1"), xml::ERR_DUP_ID);
    expect_code("the same ID on a ds:Object", vcode(replaced(s, "</ds:Signature>", "<ds:Object Id=\"_assert1\"/></ds:Signature>"), RSA_CRT, "_assert1"), xml::ERR_DUP_ID);
    expect_code("the same ID as xml:id", vcode(replaced(s, "<saml:Assertion ID=\"_assert2\"", "<saml:Assertion xml:id=\"_assert1\" ID=\"_assert2\""), RSA_CRT, "_assert1"), xml::ERR_DUP_ID);

    // The signature moved into an evil assertion, the signed one under
    // ds:Object: the signature verifies, over the original; the evil one is
    // not what was signed, and nothing inside the Signature counts as signed.
    var d = xml::Doc { .. };
    xml::parse(d, s);
    let resp = xml::root_element(d);
    let good, n1 = xml::by_id(d, "_assert1");
    let sig, si, r = sig_parts(d, good);
    let ev = xml::element(d, resp, "saml", "Assertion", SAML_A);
    xml::set_attr(d, ev, "ID", "_evil");
    let sub = xml::element(d, ev, "saml", "Subject", SAML_A);
    let nid = xml::element(d, sub, "saml", "NameID", SAML_A);
    xml::text(d, nid, "mallory@example.com");
    check("move the signature", xml::move_to(d, sig, ev, -1));
    let obj = xml::element(d, sig, "ds", "Object", xml::DSIG_NS);
    check("move the assertion into Object", xml::move_to(d, good, obj, -1));
    let v = xml::verify(d, sig, cert);
    check("the moved signature still verifies, over the original", v.code == xml::OK && v.refs.len == 1 && v.refs[0] == good);
    check("the evil NameID is not signed", !xml::is_signed(d, v, nid));
    check("the original, now inside the Signature, is not taken as signed", !xml::is_signed(d, v, xml::first_element(d, good)));
    let ve = xml::verify_enveloped(d, ev, cert);
    expect_code("verify_enveloped of the evil assertion", ve.code, xml::ERR_DSIG_WRAPPING);

    // The signature of one assertion moved into its sibling.
    var d2 = xml::Doc { .. };
    xml::parse(d2, s);
    let a1, n2 = xml::by_id(d2, "_assert1");
    let a2, n3 = xml::by_id(d2, "_assert2");
    let sig2, si2, r2 = sig_parts(d2, a1);
    xml::move_to(d2, sig2, a2, -1);
    expect_code("a sibling's signature", xml::verify_enveloped(d2, a2, cert).code, xml::ERR_DSIG_WRAPPING);
    expect_code("the signed one without its signature", xml::verify_enveloped(d2, a1, cert).code, xml::ERR_DSIG_WRAPPING);

    // Two signatures in the element.
    var d3 = xml::Doc { .. };
    xml::parse(d3, s);
    let a3, n4 = xml::by_id(d3, "_assert1");
    xml::element(d3, a3, "ds", "Signature", xml::DSIG_NS);
    expect_code("two signatures", xml::verify_enveloped(d3, a3, cert).code, xml::ERR_DSIG_WRAPPING);

    // A whole-document signature moved into an element.
    let key = key_of(RSA_KEY);
    var d4 = xml::Doc { .. };
    xml::parse(d4, "<r><a ref=\"x\"><b>evil</b></a></r>");
    let root4 = xml::root_element(d4);
    let s4, e4 = xml::sign_enveloped(d4, root4, -1, key, cert.der);
    let a4 = xml::first_element(d4, root4);
    xml::move_to(d4, s4, a4, -1);
    let v4 = xml::verify(d4, s4, cert);
    check("a document signature verifies wherever it is", v4.code == xml::OK && v4.refs[0] == 0);
    expect_code("but not as the element's", xml::verify_enveloped(d4, a4, cert).code, xml::ERR_DSIG_WRAPPING);

    // References: validly signed, but not allowed.
    fn with_uri(uri: const u8[:], drop: bool) -> i64 {
        var dd = xml::Doc { .. };
        xml::parse(dd, s);
        let a, n = xml::by_id(dd, "_assert1");
        let sg, sgi, ref = sig_parts(dd, a);
        if drop {
            xml::detach(dd, xml::attr_node(dd, ref, "", "URI"));
        } else {
            xml::set_attr(dd, ref, "URI", uri);
        }
        resign(dd, sg);
        return xml::verify_enveloped(dd, a, cert).code;
    }
    expect_code("resigned control", with_uri("#_assert1", false), xml::OK);
    expect_code("XPointer URI", with_uri("#xpointer(id('_assert1'))", false), xml::ERR_DSIG_REFERENCE);
    expect_code("XPointer root", with_uri("#xpointer(/)", false), xml::ERR_DSIG_REFERENCE);
    expect_code("external URI", with_uri("https://example.com/a.xml#_assert1", false), xml::ERR_DSIG_REFERENCE);
    expect_code("relative URI", with_uri("other.xml", false), xml::ERR_DSIG_REFERENCE);
    expect_code("no URI", with_uri("", true), xml::ERR_DSIG_REFERENCE);
    expect_code("an ID that is not there", with_uri("#_nowhere", false), xml::ERR_DSIG_ID);
    expect_code("the other assertion's ID", with_uri("#_assert2", false), xml::ERR_DSIG_DIGEST);

    // Two References to the element, both right: still not one.
    var d5 = xml::Doc { .. };
    xml::parse(d5, s);
    let a5, n5 = xml::by_id(d5, "_assert1");
    let sig5, si5, r5 = sig_parts(d5, a5);
    var copy_text: u8[>..] = [];
    xml::write(d5, r5, copy_text);
    xml::parse_fragment(d5, si5, -1, copy_text);
    resign(d5, sig5);
    let v5 = xml::verify(d5, sig5, cert);
    check("two References verify", v5.code == xml::OK && v5.refs.len == 2);
    expect_code("two References for verify_enveloped", xml::verify_enveloped(d5, a5, cert).code, xml::ERR_DSIG_WRAPPING);
}

fn main() {
    matrix();
    vectors();
    tampering();
    wrapping();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
