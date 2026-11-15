// encrypt_decrypt: SAML's EncryptedAssertion. The identity provider signs
// an assertion (RSA-SHA256) and encrypts it to the service provider's
// certificate (AES-256-GCM, the key by RSA-OAEP); the provider decrypts it
// in place, parsing the plaintext in the scope of where it was, and
// verifies the signature of what came out. Then the same to an EC
// certificate, the key agreed by ECDH-ES. Fresh keys each run.
//
//   goose examples/xml/encrypt_decrypt.goose

import std;
import gslib from "../..";
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.encoding.xml.enc;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

let RESPONSE = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_r1\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:EncryptedAssertion><saml:Assertion ID=\"_a1\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></saml:EncryptedAssertion></samlp:Response>";

fn self_signed(key: const x509::PrivateKey&, name: const u8[:]) -> x509::Cert {
    var t, okt = x509::template(name, 1767225600, 1798761600);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    let c, pe = x509::parse(der);
    assert(okt && e == x509::OK && pe == x509::OK);
    return c;
}

// The IdP's response, signed and encrypted to sp_cert.
fn idp(idp_key: const x509::PrivateKey&, idp_cert: const x509::Cert&, sp_cert: const x509::Cert&) -> u8[>..] {
    var d = xml::Doc { .. };
    xml::parse(d, RESPONSE);
    let a, n = xml::by_id(d, "_a1");
    xml::sign_enveloped(d, a, xml::next_element(d, xml::first_element(d, a)), idp_key, idp_cert.der);
    let ed, e = xml::encrypt_element(d, a, sp_cert);
    assert(e == xml::OK);
    var out: u8[>..] = [];
    xml::write_document(d, out);
    return out;
}

// The SP's reading: decrypted, verified, the NameID.
fn sp(wire: const u8[:], sp_key: const x509::PrivateKey&, idp_cert: const x509::Cert&) -> u8[>..] {
    var name: u8[>..] = [];
    var d = xml::Doc { .. };
    if xml::parse(d, wire).code != xml::OK { return name; }
    var eds: i64[>..<] = [];
    xml::find_encrypted(d, eds);
    if eds.len != 1 { return name; }
    let de = xml::decrypt_replace(d, eds[0], sp_key);
    if de != xml::OK { print("decrypt: ", xml::enc_error_name(de)); return name; }
    let a, n = xml::by_id(d, "_a1");
    let v = xml::verify_enveloped(d, a, idp_cert);
    if v.code != xml::OK { print("verify: ", v.message); return name; }
    let nid = xml::child(d, xml::child(d, v.refs[0], SAML, "Subject"), SAML, "NameID");
    xml::text_content(d, nid, name);
    return name;
}

fn main() {
    let idp_key = x509::generate_key(x509::KEY_RSA, 2048);
    let idp_cert = self_signed(idp_key, "CN=idp.example.com");
    let sp_rsa = x509::generate_key(x509::KEY_RSA, 2048);
    let sp_rsa_cert = self_signed(sp_rsa, "CN=sp.example.com");
    let sp_ec = x509::generate_key(x509::KEY_EC_P384);
    let sp_ec_cert = self_signed(sp_ec, "CN=sp-ec.example.com");

    let w1 = idp(idp_key, idp_cert, sp_rsa_cert);
    print(w1[.. ::min(w1.len, 600)], "...");
    let n1 = sp(w1, sp_rsa, idp_cert);
    print("RSA-OAEP: ", n1);
    let w2 = idp(idp_key, idp_cert, sp_ec_cert);
    let n2 = sp(w2, sp_ec, idp_cert);
    print("ECDH-ES: ", n2);
    let n3 = sp(w1, sp_ec, idp_cert);
    print("the wrong key: \"", n3, "\"");
    guard n1 == "alice@example.com" && n2 == "alice@example.com" && n3.len == 0 && find(w1, "alice") < 0
    else { print("encrypt_decrypt: wrong results"); exit(1); }
}
