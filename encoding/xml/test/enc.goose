// XML Encryption: round trips of every content algorithm and key transport
// we encrypt with (AES-GCM; RSA-OAEP, ECDH-ES); what xmlsec and
// cryptography made (test/data: AES-GCM and AES-CBC, RSA-OAEP and RSA
// PKCS #1 v1.5, rsa-oaep with a SHA-256 digest and MGF1-SHA1 named by a
// RetrievalMethod); the opt-ins for CBC and v1.5; every decryption failure
// one error; decrypted content checked against its Type and the
// document's IDs; and SAML's whole path: sign, encrypt, decrypt, verify.
import std;
import os;
import base64;
import gslib from "../../..";
import gslib.encoding.xml;
import gslib.encoding.xml.c14n;
import gslib.encoding.xml.dsig;
import gslib.encoding.xml.enc;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.bignum;
import gslib.crypto.bignum.gcm;
import gslib.entropy;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let RSA_KEY = embed_file("data/rsa2048.key");
let RSA_CRT = embed_file("data/rsa2048.crt");
let RSA_B_KEY = embed_file("data/rsa2048b.key");
let P256_KEY = embed_file("data/p256.key");
let P256_CRT = embed_file("data/p256.crt");
let P384_KEY = embed_file("data/p384.key");
let P384_CRT = embed_file("data/p384.crt");
let P521_KEY = embed_file("data/p521.key");
let P521_CRT = embed_file("data/p521.crt");

let V_GCM_OAEP = embed_file("data/xmlsec-aes128-gcm-oaep.xml");
let V_CBC_OAEP = embed_file("data/xmlsec-aes256-cbc-oaep.xml");
let V_CBC_RSA15 = embed_file("data/xmlsec-aes128-cbc-rsa15.xml");
let V_OAEP_MIXED = embed_file("data/oaep-sha256-mgf1sha1-retrieval.xml");

let SAML_A = "urn:oasis:names:tc:SAML:2.0:assertion";

let RESPONSE = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp1\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Assertion ID=\"_assert1\"><saml:Issuer>https://idp.example.com</saml:Issuer><saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>";

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

fn expect_code(what: const u8[:], got: i64, want: i64) {
    check(str(what, ": want ", xml::enc_error_name(want), ", got ", xml::enc_error_name(got), " (", got, ")"), got == want);
}

// Parses text, decrypts every EncryptedData in place with the key: the
// error, and the document written out.
fn decrypt_text(text: const u8[:], key_pem: const u8[:], o: const xml::DecryptOptions&) -> i64, u8[>..] {
    let key = key_of(key_pem);
    var d = xml::Doc { .. };
    var out: u8[>..] = [];
    let e = xml::parse(d, text);
    if e.code != xml::OK { return e.code, out; }
    var eds: i64[>..<] = [];
    xml::find_encrypted(d, eds);
    if eds.len == 0 { return xml::ERR_ENC_MALFORMED, out; }
    for ed in eds {
        let de = xml::decrypt_replace(d, ed, key, o);
        if de != xml::OK { return de, out; }
    }
    xml::write(d, 0, out);
    return xml::OK, out;
}

fn dcode(text: const u8[:], key_pem: const u8[:]) -> i64 {
    let o = xml::decrypt_options();
    let e, out = decrypt_text(text, key_pem, o);
    return e;
}

// RESPONSE with the assertion encrypted to cert by o.
fn encrypted(cert_pem: const u8[:], o: const xml::EncryptOptions&) -> u8[>..] {
    let cert = cert_of(cert_pem);
    var d = xml::Doc { .. };
    xml::parse(d, RESPONSE);
    let a, n = xml::by_id(d, "_assert1");
    var out: u8[>..] = [];
    let ed, e = xml::encrypt_element(d, a, cert, o);
    if e != xml::OK { out.append(str("encrypt error ", e)); return out; }
    xml::write(d, 0, out);
    return out;
}

fn round_trips() {
    var o = xml::encrypt_options();
    for alg in [xml::ENC_AES128_GCM, xml::ENC_AES192_GCM, xml::ENC_AES256_GCM] {
        o.alg = alg;
        o.key_alg = xml::KEY_RSA_OAEP_MGF1P;
        let t = encrypted(RSA_CRT, o);
        let dopt = xml::decrypt_options();
        let e, out = decrypt_text(t, RSA_KEY, dopt);
        check(str("round trip GCM ", alg, " rsa-oaep-mgf1p: ", e), e == xml::OK && find(out, "alice@example.com") >= 0
              && find(out, "EncryptedData") < 0 && find(t, "alice") < 0);
        o.key_alg = xml::KEY_RSA_OAEP;
        o.oaep_digest = 256;
        o.oaep_mgf = 256;
        let t2 = encrypted(RSA_CRT, o);
        let e2, out2 = decrypt_text(t2, RSA_KEY, dopt);
        check(str("round trip GCM ", alg, " rsa-oaep SHA-256"), e2 == xml::OK && find(out2, "alice@example.com") >= 0
              && find(t2, "mgf1sha256") >= 0);
        o.oaep_digest = 512;
        o.oaep_mgf = 160;
        let t3 = encrypted(RSA_CRT, o);
        let e3, out3 = decrypt_text(t3, RSA_KEY, dopt);
        check(str("round trip GCM ", alg, " rsa-oaep SHA-512, MGF1-SHA1"), e3 == xml::OK && find(out3, "alice@example.com") >= 0);
    }
    o = xml::encrypt_options();
    for kw in [128, 192, 256] {
        for kd in [256, 384, 512] {
            o.kw = kw;
            o.kdf_digest = kd;
            let t = encrypted(P256_CRT, o);
            let dopt = xml::decrypt_options();
            let e, out = decrypt_text(t, P256_KEY, dopt);
            check(str("ECDH-ES P-256 kw ", kw, " ConcatKDF ", kd, ": ", e), e == xml::OK && find(out, "alice@example.com") >= 0);
        }
    }
    o = xml::encrypt_options();
    let t384 = encrypted(P384_CRT, o);
    expect_code("ECDH-ES P-384", dcode(t384, P384_KEY), xml::OK);
    let t521 = encrypted(P521_CRT, o);
    expect_code("ECDH-ES P-521", dcode(t521, P521_KEY), xml::OK);
    expect_code("ECDH-ES to P-384, the P-521 key", dcode(t384, P521_KEY), xml::ERR_ENC_KEY);
    expect_code("ECDH-ES to P-256, an RSA key", dcode(encrypted(P256_CRT, o), RSA_KEY), xml::ERR_ENC_KEY);
    expect_code("RSA-OAEP, an EC key", dcode(encrypted(RSA_CRT, o), P256_KEY), xml::ERR_ENC_KEY);
    expect_code("RSA-OAEP, another RSA key", dcode(encrypted(RSA_CRT, o), RSA_B_KEY), xml::ERR_ENC_DECRYPT);

    var cbc = xml::encrypt_options();
    cbc.alg = xml::ENC_AES128_CBC;
    check("encrypting with CBC refused", encrypted(RSA_CRT, cbc) == str("encrypt error ", xml::ERR_ENC_ALGORITHM));
    var v15 = xml::encrypt_options();
    v15.key_alg = xml::KEY_RSA_15;
    check("encrypting with RSA 1.5 refused", encrypted(RSA_CRT, v15) == str("encrypt error ", xml::ERR_ENC_ALGORITHM));
}

fn vectors() {
    let o = xml::decrypt_options();
    let e, out = decrypt_text(V_GCM_OAEP, RSA_KEY, o);
    check(str("xmlsec AES-128-GCM, RSA-OAEP: ", e), e == xml::OK && find(out, "alice@example.com") >= 0);
    expect_code("xmlsec AES-256-CBC refused", dcode(V_CBC_OAEP, RSA_KEY), xml::ERR_ENC_ALGORITHM);
    var cbc = xml::decrypt_options();
    cbc.allow_cbc = true;
    let e2, out2 = decrypt_text(V_CBC_OAEP, RSA_KEY, cbc);
    check("xmlsec AES-256-CBC with allow_cbc", e2 == xml::OK && find(out2, "alice@example.com") >= 0);
    let e3, out3 = decrypt_text(V_CBC_RSA15, RSA_KEY, cbc);
    expect_code("xmlsec RSA 1.5 refused", e3, xml::ERR_ENC_ALGORITHM);
    var both = xml::decrypt_options();
    both.allow_cbc = true;
    both.allow_rsa15 = true;
    let e4, out4 = decrypt_text(V_CBC_RSA15, RSA_KEY, both);
    check("xmlsec AES-128-CBC, RSA 1.5 with both opt-ins", e4 == xml::OK && find(out4, "alice@example.com") >= 0);
    let e5, out5 = decrypt_text(V_CBC_RSA15, RSA_B_KEY, both);
    check("RSA 1.5 with the wrong key fails (implicit rejection)", e5 != xml::OK);
    let e6, out6 = decrypt_text(V_OAEP_MIXED, RSA_KEY, o);
    check(str("rsa-oaep SHA-256 with MGF1-SHA1 by RetrievalMethod: ", e6), e6 == xml::OK && find(out6, "alice@example.com") >= 0);
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

// The base64 of the n-th CipherValue of text with one byte flipped.
fn flipped(text: const u8[:], nth: i64, at: i64) -> u8[>..] {
    var from = 0;
    for i in nth + 1 { from = find(text[from..], "<xenc:CipherValue>") + from + 18; }
    let to = find(text[from..], "<") + from;
    var raw: u8[>..] = [];
    base64::decode(raw, text[from..to]);
    let k = if at < 0 { raw.len + at } else { at };
    raw[k] ^= 1;
    var out: u8[>..] = [];
    out.append(text[..from]);
    base64::encode(out, raw);
    out.append(text[to..]);
    return out;
}

// text with the n-th CipherValue's base64 replaced by four characters.
fn shortened(text: const u8[:], nth: i64) -> u8[>..] {
    var from = 0;
    for i in nth + 1 { from = find(text[from..], "<xenc:CipherValue>") + from + 18; }
    let to = find(text[from..], "<") + from;
    var out: u8[>..] = [];
    out.append(text[..from]);
    out.append("AAAA");
    out.append(text[to..]);
    return out;
}

// A response whose EncryptedData holds `plain`, by AES-128-GCM and
// rsa-oaep-mgf1p to the RSA certificate, of Type type_uri ("": none).
fn crafted(plain: const u8[:], type_uri: const u8[:]) -> u8[>..] {
    let cert = cert_of(RSA_CRT);
    let pub, okp = x509::rsa_public_key(cert);
    var cek: u8[16] = [0; 16];
    entropy::random_bytes(cek);
    var iv: u8[12] = [0; 12];
    entropy::random_bytes(iv);
    var ct: u8[>..] = [];
    ct.append(iv);
    ct.append(bignum::aes_gcm_seal(cek, iv, "", plain));
    let wrapped, ok = xml::oaep_encrypt(pub, cek, "", 160, 160);
    var out: u8[>..] = [];
    out.append("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_resp1\"><saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"");
    if type_uri.len > 0 { format(out, " Type=\"", type_uri, "\""); }
    out.append("><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes128-gcm\"/><xenc:CipherData><xenc:CipherValue>");
    base64::encode(out, ct);
    out.append("</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/><xenc:CipherData><xenc:CipherValue>");
    base64::encode(out, wrapped);
    out.append("</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></saml:EncryptedAssertion></samlp:Response>");
    return out;
}

// Parses text, tries to decrypt its EncryptedData in place: the error, and
// whether the document was left as it was.
fn try_replace(text: const u8[:]) -> i64, bool {
    let key = key_of(RSA_KEY);
    var d = xml::Doc { .. };
    xml::parse(d, text);
    var before: u8[>..] = [];
    xml::write(d, 0, before);
    var eds: i64[>..<] = [];
    xml::find_encrypted(d, eds);
    let e = xml::decrypt_replace(d, eds[0], key);
    var after: u8[>..] = [];
    xml::write(d, 0, after);
    return e, before == after;
}

fn failures_and_content() {
    var o = xml::encrypt_options();
    let t = encrypted(RSA_CRT, o);
    expect_code("control", dcode(t, RSA_KEY), xml::OK);
    expect_code("content flipped at the start", dcode(flipped(t, 1, 20), RSA_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("tag flipped", dcode(flipped(t, 1, -1), RSA_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("IV flipped", dcode(flipped(t, 1, 0), RSA_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("wrapped key flipped", dcode(flipped(t, 0, 5), RSA_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("CipherValue cut short", dcode(shortened(t, 1), RSA_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("wrapped key cut short", dcode(shortened(t, 0), RSA_KEY), xml::ERR_ENC_DECRYPT);
    o.key_alg = xml::KEY_ECDH_ES;
    let te = encrypted(P256_CRT, o);
    expect_code("ECDH-ES wrapped key flipped", dcode(flipped(te, 0, 3), P256_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("ECDH-ES content flipped", dcode(flipped(te, 1, 30), P256_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("ECDH-ES originator key not a point", dcode(replaced(te, "<dsig11:PublicKey>B", "<dsig11:PublicKey>A"), P256_KEY), xml::ERR_ENC_DECRYPT);
    expect_code("ECDH-ES another KDF", dcode(replaced(te, "xmlenc11#ConcatKDF", "xmlenc11#PBKDF2"), P256_KEY), xml::ERR_ENC_ALGORITHM);
    expect_code("ECDH-ES SHA-1 KDF", dcode(replaced(te, "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\"", "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\""), P256_KEY), xml::ERR_ENC_ALGORITHM);
    expect_code("CipherReference", dcode(replaced(t, "<xenc:CipherValue>", "<xenc:CipherReference URI=\"https://example.com/x\"/><xenc:CipherValue>"), RSA_KEY), xml::ERR_ENC_MALFORMED);
    expect_code("an unknown content algorithm", dcode(replaced(t, "xmlenc11#aes256-gcm", "xmlenc11#aes512-gcm"), RSA_KEY), xml::ERR_ENC_ALGORITHM);
    expect_code("an unknown key transport", dcode(replaced(t, "xmlenc#rsa-oaep-mgf1p", "xmlenc#rsa-oaep-mgf2p"), RSA_KEY), xml::ERR_ENC_ALGORITHM);
    var five: u8[>..] = [];
    let ek_at = find(t, "<xenc:EncryptedKey>");
    let ek_end = find(t, "</xenc:EncryptedKey>") + 20;
    five.append(t[..ek_end]);
    for i in 4 { five.append(t[ek_at..ek_end]); }
    five.append(t[ek_end..]);
    expect_code("five EncryptedKeys, over max_keys", dcode(five, RSA_KEY), xml::ERR_LIMIT);
    expect_code("no key", dcode(replaced(t, "<xenc:EncryptedKey>", "<xenc:EncryptedKeyX>"), RSA_KEY), xml::ERR_TAG);

    // What the plaintext must be.
    let e1, same1 = try_replace(crafted("<saml:Assertion ID=\"_a\"/><saml:Assertion ID=\"_b\"/>", xml::URI_TYPE_ELEMENT));
    check("Type Element of two elements refused, document unchanged", e1 == xml::ERR_ENC_CONTENT && same1);
    let e2, same2 = try_replace(crafted("text<saml:Assertion ID=\"_a\"/>", xml::URI_TYPE_ELEMENT));
    check("Type Element with text refused", e2 == xml::ERR_ENC_CONTENT && same2);
    let e3, same3 = try_replace(crafted("<saml:Assertion ID=\"_resp1\"/>", xml::URI_TYPE_ELEMENT));
    check("plaintext repeating the document's ID refused", e3 == xml::ERR_ENC_CONTENT && same3);
    let e4, same4 = try_replace(crafted("<saml:Assertion><x:y/></saml:Assertion>", xml::URI_TYPE_ELEMENT));
    check("plaintext with an unbound prefix refused", e4 == xml::ERR_ENC_CONTENT && same4);
    let e5, same5 = try_replace(crafted("<!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>", xml::URI_TYPE_ELEMENT));
    check("plaintext with a DOCTYPE refused", e5 == xml::ERR_ENC_CONTENT && same5);
    let e6, same6 = try_replace(crafted("text <saml:NameID>x</saml:NameID>", xml::URI_TYPE_CONTENT));
    check("Type Content: text and an element", e6 == xml::OK && !same6);
    let e7, same7 = try_replace(crafted("<saml:Assertion ID=\"_a\"/>", ""));
    check("no Type: content", e7 == xml::OK);
    let e8, same8 = try_replace(crafted("<a/>", "urn:other"));
    check("another Type refused", e8 == xml::ERR_ENC_MALFORMED && same8);
    // decrypt returns the octets.
    let key = key_of(RSA_KEY);
    var d = xml::Doc { .. };
    xml::parse(d, crafted("<p>octets</p>", xml::URI_TYPE_ELEMENT));
    var eds: i64[>..<] = [];
    xml::find_encrypted(d, eds);
    let pt, pe = xml::decrypt(d, eds[0], key);
    check("decrypt gives the octets", pe == xml::OK && pt == "<p>octets</p>");
}

// SAML's path: the IdP signs the assertion and encrypts it to the SP; the
// SP decrypts it in place and verifies the signature on what came out.
fn saml_flow() {
    let idp_key = key_of(P256_KEY);
    let idp_cert = cert_of(P256_CRT);
    let sp_key = key_of(RSA_KEY);
    let sp_cert = cert_of(RSA_CRT);
    var d = xml::Doc { .. };
    xml::parse(d, RESPONSE);
    let a, n = xml::by_id(d, "_assert1");
    let sig, se = xml::sign_enveloped(d, a, xml::next_element(d, xml::first_element(d, a)), idp_key, idp_cert.der);
    check("IdP signs", se == xml::OK);
    let ea = xml::insert_element(d, xml::root_element(d), a, "saml", "EncryptedAssertion", SAML_A);
    xml::move_to(d, a, ea, -1);
    let ed, ee = xml::encrypt_element(d, a, sp_cert);
    check("IdP encrypts", ee == xml::OK);
    var wire: u8[>..] = [];
    xml::write_document(d, wire);
    check("nothing in the clear", find(wire, "alice") < 0);

    var r = xml::Doc { .. };
    check("SP parses", xml::parse(r, wire).code == xml::OK);
    var eds: i64[>..<] = [];
    xml::find_encrypted(r, eds);
    check("one EncryptedData", eds.len == 1);
    check("SP decrypts in place", xml::decrypt_replace(r, eds[0], sp_key) == xml::OK);
    let got, cnt = xml::by_id(r, "_assert1");
    check("the assertion is back, by its ID", cnt == 1 && xml::is(r, got, SAML_A, "Assertion")
          && xml::is(r, xml::parent(r, got), SAML_A, "EncryptedAssertion"));
    let v = xml::verify_enveloped(r, got, idp_cert);
    check(str("SP verifies the decrypted assertion: ", v.message), v.code == xml::OK);
    let subj = xml::child(r, got, SAML_A, "Subject");
    let nid = xml::child(r, subj, SAML_A, "NameID");
    var name: u8[>..] = [];
    xml::text_content(r, nid, name);
    check("its NameID is signed", xml::is_signed(r, v, nid) && name == "alice@example.com");
    check("the response's Issuer is not", !xml::is_signed(r, v, xml::first_element(r, xml::root_element(r))));
}

// Many candidate keys before any signature is checked: the search stops
// past max_keys, and RetrievalMethods' IDs are looked up in one pass (one
// scan of the document each before: quadratic).
fn many_keys() {
    let rm = "<ds:RetrievalMethod Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\" URI=\"#_ek1\"/>";
    let at = find(V_OAEP_MIXED, rm);
    check("the vector has a RetrievalMethod", at > 0);
    var many: u8[>..] = [];
    many.append(V_OAEP_MIXED[..at]);
    for i in 20000 { many.append(rm); }
    many.append(V_OAEP_MIXED[at..]);
    let t0 = clock();
    expect_code("20000 RetrievalMethods", dcode(many, RSA_KEY), xml::ERR_LIMIT);
    check("  quickly", clock() - t0 < 5.0);
    expect_code("a RetrievalMethod to no ID", dcode(replaced(V_OAEP_MIXED, "URI=\"#_ek1\"", "URI=\"#_nothing\""), RSA_KEY), xml::ERR_ENC_MALFORMED);
    expect_code("a RetrievalMethod to another element", dcode(replaced(V_OAEP_MIXED, "URI=\"#_ek1\"", "URI=\"#_resp1\""), RSA_KEY), xml::ERR_ENC_MALFORMED);
    // Siblings: SAML's EncryptedAssertion's EncryptedKey, 20000 times.
    let t = crafted("<saml:Assertion/>", xml::URI_TYPE_ELEMENT);
    let ek_at = find(t, "<xenc:EncryptedKey ");
    let ek_end = find(t, "</xenc:EncryptedKey>") + 20;
    var sib: u8[>..] = [];
    sib.append(t[..ek_end]);
    for i in 20000 { sib.append(t[ek_at..ek_end]); }
    sib.append(t[ek_end..]);
    let t1 = clock();
    expect_code("20000 sibling EncryptedKeys", dcode(sib, RSA_KEY), xml::ERR_LIMIT);
    check("  quickly", clock() - t1 < 5.0);
}

fn main() {
    round_trips();
    many_keys();
    vectors();
    failures_and_content();
    saml_flow();
    print(checks, " checks, ", failures, " failures");
    if failures > 0 { exit(1); }
}
