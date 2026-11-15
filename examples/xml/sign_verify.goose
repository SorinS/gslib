// sign_verify: an identity provider's signed assertion, end to end. A
// SAML-shaped response built with the builder; its assertion signed with
// an enveloped signature (ECDSA P-256, SHA-256, exclusive
// canonicalization) placed after its Issuer, as SAML wants it; the
// document written out and parsed again as a service provider would; the
// signature verified against the certificate the provider trusts, and
// only then the signed values read, from the nodes verification returned.
// Then a wrapped copy, an evil assertion carrying the moved signature, is
// refused. A fresh key and self-signed certificate each run.
//
//   goose examples/xml/sign_verify.goose

import std;
import gslib from "../..";
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";
let SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

fn main() {
    // The identity provider's key and certificate.
    let key = x509::generate_key(x509::KEY_EC_P256);
    var t, okt = x509::template("CN=idp.example.com", 1767225600, 1798761600);
    let cert_der, ce = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    guard okt && ce == x509::OK else { print("sign_verify: no certificate"); exit(1); }

    // The response, built.
    var d = xml::Doc { .. };
    xml::new_document(d);
    let resp = xml::element(d, 0, "samlp", "Response", SAMLP);
    xml::set_attr(d, resp, "ID", "_r1");
    xml::declare_ns(d, resp, "saml", SAML);
    xml::text(d, xml::element(d, resp, "saml", "Issuer", SAML), "https://idp.example.com");
    let a = xml::element(d, resp, "saml", "Assertion", SAML);
    xml::set_attr(d, a, "ID", "_a1");
    xml::text(d, xml::element(d, a, "saml", "Issuer", SAML), "https://idp.example.com");
    let subj = xml::element(d, a, "saml", "Subject", SAML);
    xml::text(d, xml::element(d, subj, "saml", "NameID", SAML), "alice@example.com");

    // Signed: the Signature goes after the assertion's Issuer.
    let sig, se = xml::sign_enveloped(d, a, xml::next_element(d, xml::first_element(d, a)), key, cert_der);
    guard se == xml::OK else { print("sign_verify: ", xml::dsig_error_name(se)); exit(1); }
    var wire: u8[>..] = [];
    xml::write_document(d, wire);
    print(wire);

    // The service provider's side.
    let cert, pe = x509::parse(cert_der);
    var r = xml::Doc { .. };
    let e = xml::parse(r, wire);
    guard e.code == xml::OK else { print("sign_verify: ", e.message); exit(1); }
    let got, n = xml::by_id(r, "_a1");
    let v = xml::verify_enveloped(r, got, cert);
    guard v.code == xml::OK else { print("sign_verify: ", v.message); exit(1); }
    let nid = xml::child(r, xml::child(r, v.refs[0], SAML, "Subject"), SAML, "NameID");
    var name: u8[>..] = [];
    xml::text_content(r, nid, name);
    print("verified; NameID ", name, " (signed: ", xml::is_signed(r, v, nid), ")");

    // Wrapped: an evil assertion holds the signature, the real one moves away.
    let evil = xml::element(r, xml::root_element(r), "saml", "Assertion", SAML);
    xml::set_attr(r, evil, "ID", "_evil");
    xml::move_to(r, xml::child(r, got, xml::DSIG_NS, "Signature"), evil, -1);
    let w = xml::verify_enveloped(r, evil, cert);
    print("wrapped: ", xml::dsig_error_name(w.code));

    guard name == "alice@example.com" && xml::is_signed(r, v, nid) && w.code == xml::ERR_DSIG_WRAPPING
    else { print("sign_verify: wrong results"); exit(1); }
}
