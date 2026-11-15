// The service provider's checks of a Response: the good ones (assertion
// signed, Response signed, both; encrypted with RSA-OAEP and with
// ECDH-ES; an EncryptedID; IdP-initiated with the opt-in), and every
// hostile one: the eight signature wrapping attacks of "On Breaking SAML"
// (XSW1-XSW8) and duplicate IDs, a comment in the NameID (the 2018 bug:
// the NameID is its whole text), an unsigned assertion beside a signed
// one, expired and not yet valid, another audience, recipient,
// destination and issuer, InResponseTo, unsolicited Responses, replay, a
// certificate that is not the IdP's, SHA-1, RSA 1024, a DOCTYPE, and
// sizes over the limit.
import std;
import os;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.encoding.xml.enc;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import tv;

let SAMLNS = "urn:oasis:names:tc:SAML:2.0:assertion";
let SAMLPNS = "urn:oasis:names:tc:SAML:2.0:protocol";
let DSNS = "http://www.w3.org/2000/09/xmldsig#";

fn ok_response(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    for mode in 3 {
        let sa = mode != 1;
        let sr = mode != 0;
        let x = tv::response(idp, spe, sa, sr) { d, resp, asrt => };
        let e = tv::run(sp, idpe, x, "_req1", a);
        tv::check_code(str("signed assertion ", sa, " response ", sr), e, saml::OK, a.message);
        tv::check("  NameID", a.name_id[..] == "alice@example.test");
        tv::check("  NameID format", a.name_id_format[..] == saml::NAMEID_EMAIL);
        tv::check("  signed flags", a.assertion_signed == sa && a.response_signed == sr);
        tv::check("  session index", a.session_index[..] == "_session1");
        tv::check("  authn context", a.authn_context[..] == saml::AC_PASSWORD_PROTECTED);
        tv::check("  issuer", a.issuer[..] == tv::IDP_ID);
        tv::check("  in response to", a.in_response_to[..] == "_req1");
        tv::check("  conditions", a.not_before == tv::NOW - 60 && a.not_on_or_after == tv::NOW + 300);
        tv::check("  session expiry", a.session_not_on_or_after == tv::NOW + 28800);
        tv::check("  replay until", a.replay_until == tv::NOW + 300 + sp.clock_skew && a.id.len == 41);
        tv::check("  status", a.status[..] == saml::STATUS_SUCCESS);
    }
    // Attributes, multi-valued, by Name and by FriendlyName.
    let x = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let at = tv::find(d, asrt, SAMLNS, "Attribute");
        tv::set(d, at, "FriendlyName", "mail");
    };
    tv::check_code("attributes", tv::run(sp, idpe, x, "_req1", a), saml::OK, a.message);
    tv::check("  three names? two attributes", a.attr_names.len == 2 && a.values.len == 3);
    let mail, hasm = saml::attribute(a, "urn:oid:0.9.2342.19200300.100.1.3");
    tv::check("  mail by Name", hasm && mail[..] == "alice@example.test");
    let mail2, hasm2 = saml::attribute(a, "mail");
    tv::check("  mail by FriendlyName", hasm2 && mail2[..] == "alice@example.test");
    tv::check("  groups has two values", saml::value_count(a, "groups") == 2);
    var groups: u8[>..] = [];
    saml::each_value(a, "groups") { v => groups.append(v); groups.push(';'); };
    tv::check("  groups in order", groups[..] == "staff;admins;");
    let none, hasn = saml::attribute(a, "nope");
    tv::check("  no such attribute", !hasn);
    var names = 0;
    saml::each_attribute(a) { n, info => names++; };
    tv::check("  each_attribute", names == 2);
    // A comment between AttributeValue text nodes keeps the whole value.
    let x2 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let v = tv::find(d, asrt, SAMLNS, "AttributeValue");
        tv::set_text(d, v, "alice@");
        xml::comment(d, v, "");
        xml::text(d, v, "example.test");
    };
    tv::check_code("comment in an AttributeValue", tv::run(sp, idpe, x2, "_req1", a), saml::OK, a.message);
    let m3, hasm3 = saml::attribute(a, "urn:oid:0.9.2342.19200300.100.1.3");
    tv::check("  whole value", hasm3 && m3[..] == "alice@example.test");
}

fn encrypted(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    var r = saml::Message { .. };
    tv::request(r);
    var user = saml::Login { .. };
    tv::alice(user);
    idp.encrypt = true;
    for mode in 3 {
        idp.sign_assertion = mode != 1;
        idp.sign_response = mode != 0;
        var o = saml::Outgoing { .. };
        tv::check_code("IdP encrypts", saml::idp_response(idp, spe, r, user, o), saml::OK, "");
        tv::check("  no plain assertion", find(o.xml, "alice@example.test") < 0 && find(o.xml, "EncryptedAssertion") >= 0);
        let e = tv::run(sp, idpe, o.xml, "_req1", a);
        tv::check_code(str("encrypted, signed assertion ", idp.sign_assertion, " response ", idp.sign_response), e, saml::OK, a.message);
        tv::check("  encrypted and read", a.encrypted && a.name_id[..] == "alice@example.test" && saml::value_count(a, "groups") == 2);
    }
    idp.sign_assertion = true;
    idp.sign_response = false;
    // require_encrypted: a plain one refused.
    sp.require_encrypted = true;
    let plain = tv::response(idp, spe, true, false) { d, resp, asrt => };
    tv::check_code("require_encrypted refuses a plain assertion", tv::run(sp, idpe, plain, "_req1", a), saml::ERR_NOT_ENCRYPTED, a.message);
    // To another key: does not decrypt.
    var other = saml::Entity { .. };
    saml::sp_entity(sp, other);
    other.sp_encryption.clear();
    let ek, ec = tv::load("evil");
    saml::add_cert(other.sp_encryption, ec);
    var o2 = saml::Outgoing { .. };
    tv::check_code("encrypted to another key", saml::idp_response(idp, other, r, user, o2), saml::OK, "");
    tv::check_code("  refused", tv::run(sp, idpe, o2.xml, "_req1", a), saml::ERR_DECRYPT, a.message);
    // To an EC key (ECDH-ES), the SP's decryption key apart from its signing key.
    let pk, pc = tv::load("sp-p256");
    sp.has_enc_key = true;
    sp.enc_key = pk;
    sp.enc_cert_der.append(pc);
    var spe2 = saml::Entity { .. };
    saml::sp_entity(sp, spe2);
    var o3 = saml::Outgoing { .. };
    tv::check_code("encrypted to P-256", saml::idp_response(idp, spe2, r, user, o3), saml::OK, "");
    tv::check("  by ECDH-ES", find(o3.xml, "ECDH-ES") >= 0);
    tv::check_code("  decrypted with the encryption key", tv::run(sp, idpe, o3.xml, "_req1", a), saml::OK, a.message);
    sp.has_enc_key = false;
    sp.enc_cert_der.clear();
    sp.require_encrypted = false;
    idp.encrypt = false;
    // An EncryptedAssertion holding two assertions, or text.
    let two = tv::response(idp, spe, false, true) { d, resp, asrt =>
        tv::clone(d, asrt, resp, -1, "_second", "");
        let ea = xml::insert_element(d, resp, asrt, "saml", "EncryptedAssertion", SAMLNS);
        xml::move_to(d, asrt, ea, -1);
        let second = xml::next_element(d, ea);
        xml::move_to(d, second, ea, -1);
        let c, ce = x509::parse(sp.signer.cert_der);
        // Encrypt the first; the second stays plain beside it.
        let ed, ee = xml::encrypt_element(d, asrt, c);
        assert(ee == xml::OK);
    };
    tv::check_code("an EncryptedAssertion with a plain Assertion beside the EncryptedData", tv::run(sp, idpe, two, "_req1", a),
                   saml::ERR_MALFORMED, a.message);
    // An EncryptedID.
    let eid = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let nid = tv::find(d, asrt, SAMLNS, "NameID");
        let subj = xml::parent(d, nid);
        let w = xml::insert_element(d, subj, nid, "saml", "EncryptedID", SAMLNS);
        xml::move_to(d, nid, w, -1);
        let c, ce = x509::parse(sp.signer.cert_der);
        let ed, ee = xml::encrypt_element(d, nid, c);
        assert(ee == xml::OK);
    };
    tv::check_code("an EncryptedID", tv::run(sp, idpe, eid, "_req1", a), saml::OK, a.message);
    tv::check("  the NameID decrypted", a.name_id[..] == "alice@example.test");
}

// The eight wrapping attacks of Somorovsky et al., "On Breaking SAML" (2012), §5.
fn wrapping(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    // XSW1: the Response signed; an evil Response at the top, the signed
    // one moved into the Signature, which the evil one now carries.
    let x1 = tv::response(idp, spe, false, true) { d, resp, asrt => };
    let w1 = wrap_response(x1, true);
    let e1 = tv::run(sp, idpe, w1, "_req1", a);
    tv::check_code("XSW1 (signed Response inside its Signature)", e1, saml::ERR_SIGNATURE, a.message);
    tv::check("  the evil NameID never read", a.name_id.len == 0);
    // XSW1 again, the signed Response in a ds:Object of the Signature (where
    // XML Signature allows other content).
    let w1b = wrap_object(x1);
    tv::check_code("XSW1 (signed Response in a ds:Object of its Signature)", tv::run(sp, idpe, w1b, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // XSW2: the same, the signed Response a sibling before the Signature.
    let w2 = wrap_response(x1, false);
    tv::check_code("XSW2 (signed Response beside its Signature)", tv::run(sp, idpe, w2, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // XSW3: an evil assertion, another ID, before the signed one.
    let x3 = tv::response(idp, spe, true, false) { d, resp, asrt => };
    let w3 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
    };
    tv::check_code("XSW3 (evil assertion before the signed one)", tv::run(sp, idpe, w3, "_req1", a), saml::ERR_ASSERTION, a.message);
    // XSW4: the signed assertion inside an evil one.
    let w4 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
        xml::move_to(d, asrt, evil, -1);
    };
    tv::check_code("XSW4 (signed assertion inside the evil one)", tv::run(sp, idpe, w4, "_req1", a), saml::ERR_NOT_SIGNED, a.message);
    // XSW5: the evil assertion carries the signature; the signed one,
    // unsigned now, after it (and, in a second form, at the end of the
    // document's Extensions).
    let w5 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, asrt, DSNS, "Signature"));
    };
    tv::check_code("XSW5 (signature on the evil copy, original beside)", tv::run(sp, idpe, w5, "_req1", a), saml::ERR_ASSERTION, a.message);
    let w5b = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, asrt, DSNS, "Signature"));
        let ext = xml::insert_element(d, resp, xml::child(d, resp, SAMLPNS, "Status"), "samlp", "Extensions", SAMLPNS);
        xml::move_to(d, asrt, ext, -1);
    };
    tv::check_code("XSW5 (signature on the evil copy, original in Extensions)", tv::run(sp, idpe, w5b, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // XSW6: the evil assertion carries the signature, the original inside it.
    let w6 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        let sig = xml::child(d, asrt, DSNS, "Signature");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
        xml::move_to(d, sig, evil, tv::find(d, evil, SAMLNS, "Subject"));
        xml::move_to(d, asrt, sig, -1);
    };
    tv::check_code("XSW6 (original inside the signature on the evil copy)", tv::run(sp, idpe, w6, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // XSW7: the signed assertion in Extensions, an evil one unsigned.
    let w7 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
        let ext = xml::insert_element(d, resp, xml::child(d, resp, SAMLPNS, "Status"), "samlp", "Extensions", SAMLPNS);
        xml::move_to(d, asrt, ext, -1);
    };
    tv::check_code("XSW7 (original in Extensions, evil unsigned)", tv::run(sp, idpe, w7, "_req1", a), saml::ERR_NOT_SIGNED, a.message);
    // XSW8: the evil assertion carries the signature, an Object in it
    // holding the original stripped of its signature.
    let w8 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "_evil", "admin@example.test");
        let sig = xml::child(d, asrt, DSNS, "Signature");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
        xml::move_to(d, sig, evil, tv::find(d, evil, SAMLNS, "Subject"));
        let obj = xml::element(d, sig, "ds", "Object", DSNS);
        xml::move_to(d, asrt, obj, -1);
    };
    tv::check_code("XSW8 (original in a ds:Object of the evil copy's signature)", tv::run(sp, idpe, w8, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // The same IDs kept: refused by the parser before any signature is looked at.
    let dup = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, asrt, "", "admin@example.test");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
    };
    tv::check_code("an evil copy with the same ID", tv::run(sp, idpe, dup, "_req1", a), saml::ERR_MALFORMED, a.message);
    // A signed Response with an unsigned assertion added beside the signed one.
    let x9 = tv::response(idp, spe, false, true) { d, resp, asrt => };
    let w9 = mutate(x9) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, -1, "_evil", "admin@example.test");
    };
    tv::check_code("an assertion added to a signed Response", tv::run(sp, idpe, w9, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // A signed assertion with an unsigned sibling in an unsigned Response.
    let w10 = mutate(x3) { d, resp, asrt =>
        let evil = tv::clone(d, asrt, resp, -1, "_evil", "admin@example.test");
        xml::detach(d, xml::child(d, evil, DSNS, "Signature"));
    };
    tv::check_code("an unsigned assertion beside a signed one", tv::run(sp, idpe, w10, "_req1", a), saml::ERR_ASSERTION, a.message);
    // A signed assertion moved under the Response's Status (not a direct child): none.
    let w11 = mutate(x3) { d, resp, asrt => xml::move_to(d, asrt, xml::child(d, resp, SAMLPNS, "Status"), -1); };
    tv::check_code("the signed assertion hidden under Status", tv::run(sp, idpe, w11, "_req1", a), saml::ERR_ASSERTION, a.message);
    // An assertion inside Advice of the signed one is never read.
    let x12 = tv::response(idp, spe, false, false) { d, resp, asrt => };
    let w12 = mutate(x12) { d, resp, asrt =>
        let adv = xml::insert_element(d, asrt, tv::find(d, asrt, SAMLNS, "Conditions"), "saml", "Advice", SAMLNS);
        tv::clone(d, asrt, adv, -1, "_evil", "admin@example.test");
        assert(saml::sign_element(d, asrt, idp.signer) == saml::OK);
    };
    tv::check_code("an assertion in Advice", tv::run(sp, idpe, w12, "_req1", a), saml::OK, a.message);
    tv::check("  the outer NameID", a.name_id[..] == "alice@example.test");
    // Two signatures on the assertion.
    let w13 = mutate(x3) { d, resp, asrt => assert(saml::sign_element(d, asrt, idp.signer) == saml::OK); };
    tv::check_code("two signatures", tv::run(sp, idpe, w13, "_req1", a), saml::ERR_SIGNATURE, a.message);
}

// XSW1 and XSW2: x's root Response signed; an evil Response made from
// it, its own ID and NameID, holding the Signature; the original inside
// the Signature (XSW1) or beside it (XSW2).
fn wrap_response(x: const u8[:], inside: bool) -> u8[>..] {
    var d = xml::Doc { .. };
    var o = xml::options();
    o.unique_ids = false;
    let pe = xml::parse(d, x, o);
    assert(pe.code == xml::OK);
    let orig = xml::root_element(d);
    // A new document whose root is the evil copy.
    var t: u8[>..] = [];
    xml::write(d, orig, t);
    var e = xml::Doc { .. };
    assert(xml::parse(e, t, o).code == xml::OK);
    let evil = xml::root_element(e);
    tv::set(e, evil, "ID", "_evilresp");
    let asrt = xml::child(e, evil, SAMLNS, "Assertion");
    tv::set(e, asrt, "ID", "_evilasrt");
    tv::set_text(e, tv::find(e, asrt, SAMLNS, "NameID"), "admin@example.test");
    let sig = xml::child(e, evil, DSNS, "Signature");
    var ot: u8[>..] = [];
    xml::write(d, orig, ot);
    if inside {
        assert(xml::parse_fragment(e, sig, -1, ot, o).code == xml::OK);
    } else {
        assert(xml::parse_fragment(e, evil, sig, ot, o).code == xml::OK);
    }
    // The copied Response inside has its own copy of the Signature: drop it.
    let inner = if inside { xml::last_child(e, sig) } else { xml::prev_sibling(e, sig) };
    xml::detach(e, xml::child(e, inner, DSNS, "Signature"));
    var out: u8[>..] = [];
    xml::write_document(e, out);
    return out;
}

// XSW1 with the original Response in a ds:Object at the end of the Signature.
fn wrap_object(x: const u8[:]) -> u8[>..] {
    let w = wrap_response(x, true);
    var e = xml::Doc { .. };
    var o = xml::options();
    o.unique_ids = false;
    assert(xml::parse(e, w, o).code == xml::OK);
    let sig = xml::child(e, xml::root_element(e), DSNS, "Signature");
    let inner = xml::last_child(e, sig);
    let obj = xml::element(e, sig, "ds", "Object", DSNS);
    xml::move_to(e, inner, obj, -1);
    var out: u8[>..] = [];
    xml::write_document(e, out);
    return out;
}

// x parsed (duplicate IDs let through), F(d, response, assertion), written.
fn mutate<F>(x: const u8[:]) -> u8[>..] {
    var d = xml::Doc { .. };
    var o = xml::options();
    o.unique_ids = false;
    let pe = xml::parse(d, x, o);
    assert(pe.code == xml::OK);
    let resp = xml::root_element(d);
    let asrt = xml::child(d, resp, SAMLNS, "Assertion");
    F(d, resp, asrt);
    var out: u8[>..] = [];
    xml::write_document(d, out);
    return out;
}

// The 2018 NameID bug (Duo Labs): the user registers
// alice@example.test.evil.test; after signing, a comment is put into
// the NameID: alice@example.test<!---->.evil.test. Comments are not in
// the signature (exclusive canonicalization drops them), so it still
// verifies; the NameID must still read as its whole text.
fn comment_name_id(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    let x = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set_text(d, tv::find(d, asrt, SAMLNS, "NameID"), "alice@example.test.evil.test");
    };
    let w = mutate(x) { d, resp, asrt =>
        let nid = tv::find(d, asrt, SAMLNS, "NameID");
        tv::set_text(d, nid, "alice@example.test");
        xml::comment(d, nid, "");
        xml::text(d, nid, ".evil.test");
    };
    tv::check("the comment is in the document", find(w, "alice@example.test<!---->.evil.test") >= 0);
    tv::check_code("a comment in the NameID: the signature holds", tv::run(sp, idpe, w, "_req1", a), saml::OK, a.message);
    tv::check("  the NameID is the whole text", a.name_id[..] == "alice@example.test.evil.test");
    // A CDATA section split the same way.
    let w2 = mutate(x) { d, resp, asrt =>
        let nid = tv::find(d, asrt, SAMLNS, "NameID");
        var t: u8[>..] = [];
        xml::write(d, resp, t);
    };
    tv::check_code("unchanged", tv::run(sp, idpe, w2, "_req1", a), saml::OK, a.message);
    // An element inside the NameID (signed so): refused.
    let x3 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let nid = tv::find(d, asrt, SAMLNS, "NameID");
        xml::element(d, nid, "saml", "Issuer", SAMLNS);
    };
    tv::check_code("an element in the NameID", tv::run(sp, idpe, x3, "_req1", a), saml::ERR_SUBJECT, a.message);
    // Text changed after signing: refused.
    let w4 = mutate(x) { d, resp, asrt => tv::set_text(d, tv::find(d, asrt, SAMLNS, "NameID"), "alice@example.test"); };
    tv::check_code("the NameID changed after signing", tv::run(sp, idpe, w4, "_req1", a), saml::ERR_SIGNATURE, a.message);
}

fn times(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    let x = tv::response(idp, spe, true, false) { d, resp, asrt => };
    let saved = sp.now;
    sp.now = tv::NOW + 300 + 120 - 1;
    tv::check_code("within the skew after NotOnOrAfter", tv::run(sp, idpe, x, "_req1", a), saml::OK, a.message);
    sp.now = tv::NOW + 300 + 120;
    tv::check_code("expired", tv::run(sp, idpe, x, "_req1", a), saml::ERR_EXPIRED, a.message);
    sp.clock_skew = 0;
    sp.now = tv::NOW + 300;
    tv::check_code("expired, no skew", tv::run(sp, idpe, x, "_req1", a), saml::ERR_EXPIRED, a.message);
    sp.now = tv::NOW - 61;
    tv::check_code("before NotBefore, no skew", tv::run(sp, idpe, x, "_req1", a), saml::ERR_NOT_YET_VALID, a.message);
    sp.clock_skew = 120;
    sp.now = saved;
    let xnb = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "Conditions"), "NotBefore", saml::time_text(tv::NOW + 100));
    };
    tv::check_code("NotBefore ahead, within the skew", tv::run(sp, idpe, xnb, "_req1", a), saml::OK, a.message);
    let xnb2 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "Conditions"), "NotBefore", saml::time_text(tv::NOW + 200));
    };
    tv::check_code("NotBefore ahead, past the skew", tv::run(sp, idpe, xnb2, "_req1", a), saml::ERR_NOT_YET_VALID, a.message);
    // Only the confirmation expired.
    let x2 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "NotOnOrAfter", saml::time_text(tv::NOW - 200));
    };
    tv::check_code("the bearer confirmation expired", tv::run(sp, idpe, x2, "_req1", a), saml::ERR_EXPIRED, a.message);
    let x3 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "NotBefore", saml::time_text(tv::NOW + 1000));
    };
    tv::check_code("the bearer confirmation not yet valid", tv::run(sp, idpe, x3, "_req1", a), saml::ERR_NOT_YET_VALID, a.message);
    // The session over.
    let x4 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "AuthnStatement"), "SessionNotOnOrAfter", saml::time_text(tv::NOW - 500));
    };
    tv::check_code("SessionNotOnOrAfter passed", tv::run(sp, idpe, x4, "_req1", a), saml::ERR_SESSION, a.message);
    // IssueInstant ahead.
    let x5 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set(d, asrt, "IssueInstant", saml::time_text(tv::NOW + 3600)); };
    tv::check_code("IssueInstant ahead", tv::run(sp, idpe, x5, "_req1", a), saml::ERR_NOT_YET_VALID, a.message);
    // Not times.
    let x6 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "Conditions"), "NotOnOrAfter", "tomorrow");
    };
    tv::check_code("NotOnOrAfter not a time", tv::run(sp, idpe, x6, "_req1", a), saml::ERR_TIME, a.message);
    let x7 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "NotOnOrAfter", "2026-02-30T00:00:00Z");
    };
    tv::check_code("February 30th", tv::run(sp, idpe, x7, "_req1", a), saml::ERR_TIME, a.message);
    // Without NotOnOrAfter on the confirmation.
    let x8 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let scd = tv::find(d, asrt, SAMLNS, "SubjectConfirmationData");
        let p = xml::parent(d, scd);
        xml::detach(d, scd);
        let n = xml::element(d, p, "saml", "SubjectConfirmationData", SAMLNS);
        tv::set(d, n, "Recipient", tv::SP_ACS);
        tv::set(d, n, "InResponseTo", "_req1");
    };
    tv::check_code("a bearer confirmation without NotOnOrAfter", tv::run(sp, idpe, x8, "_req1", a), saml::ERR_CONFIRMATION, a.message);
}

fn addressing(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    // Audience.
    let x1 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set_text(d, tv::find(d, asrt, SAMLNS, "Audience"), "https://other.example.test");
    };
    tv::check_code("another audience", tv::run(sp, idpe, x1, "_req1", a), saml::ERR_AUDIENCE, a.message);
    let x2 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let ar = tv::find(d, asrt, SAMLNS, "AudienceRestriction");
        xml::text(d, xml::element(d, ar, "saml", "Audience", SAMLNS), "https://other.example.test");
    };
    tv::check_code("us among two audiences", tv::run(sp, idpe, x2, "_req1", a), saml::OK, a.message);
    let x3 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let c = tv::find(d, asrt, SAMLNS, "Conditions");
        let ar = xml::element(d, c, "saml", "AudienceRestriction", SAMLNS);
        xml::text(d, xml::element(d, ar, "saml", "Audience", SAMLNS), "https://other.example.test");
    };
    tv::check_code("a second AudienceRestriction without us", tv::run(sp, idpe, x3, "_req1", a), saml::ERR_AUDIENCE, a.message);
    let x4 = tv::response(idp, spe, true, false) { d, resp, asrt => xml::detach(d, tv::find(d, asrt, SAMLNS, "AudienceRestriction")); };
    tv::check_code("no AudienceRestriction", tv::run(sp, idpe, x4, "_req1", a), saml::ERR_AUDIENCE, a.message);
    let x5 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let c = tv::find(d, asrt, SAMLNS, "Conditions");
        xml::element(d, c, "saml", "OneTimeUse", SAMLNS);
    };
    tv::check_code("OneTimeUse", tv::run(sp, idpe, x5, "_req1", a), saml::OK, a.message);
    tv::check("  reported", a.one_time_use);
    let x6 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let c = tv::find(d, asrt, SAMLNS, "Conditions");
        xml::element(d, c, "saml", "OneTimeUse", SAMLNS);
        xml::element(d, c, "saml", "OneTimeUse", SAMLNS);
    };
    tv::check_code("OneTimeUse twice", tv::run(sp, idpe, x6, "_req1", a), saml::ERR_CONDITION, a.message);
    let x7 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let c = tv::find(d, asrt, SAMLNS, "Conditions");
        xml::element(d, c, "saml", "Condition", SAMLNS);
    };
    tv::check_code("a condition not understood", tv::run(sp, idpe, x7, "_req1", a), saml::ERR_CONDITION, a.message);
    // Recipient, Destination, Issuer.
    let x8 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "Recipient", "https://other.example.test/acs");
    };
    tv::check_code("another Recipient", tv::run(sp, idpe, x8, "_req1", a), saml::ERR_RECIPIENT, a.message);
    let x9 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set(d, resp, "Destination", "https://other.example.test/acs"); };
    tv::check_code("another Destination", tv::run(sp, idpe, x9, "_req1", a), saml::ERR_DESTINATION, a.message);
    let x10 = tv::response(idp, spe, false, true) { d, resp, asrt => xml::detach(d, xml::attr_node(d, resp, "", "Destination")); };
    tv::check_code("a signed Response without Destination", tv::run(sp, idpe, x10, "_req1", a), saml::ERR_DESTINATION, a.message);
    let x11 = tv::response(idp, spe, true, false) { d, resp, asrt => xml::detach(d, xml::attr_node(d, resp, "", "Destination")); };
    tv::check_code("an unsigned Response without Destination", tv::run(sp, idpe, x11, "_req1", a), saml::OK, a.message);
    let x12 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set_text(d, xml::child(d, asrt, SAMLNS, "Issuer"), "https://evil.example.test"); };
    tv::check_code("the assertion's Issuer another", tv::run(sp, idpe, x12, "_req1", a), saml::ERR_ISSUER, a.message);
    let x13 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set_text(d, xml::child(d, resp, SAMLNS, "Issuer"), "https://evil.example.test"); };
    tv::check_code("the Response's Issuer another", tv::run(sp, idpe, x13, "_req1", a), saml::ERR_ISSUER, a.message);
    let x14 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set(d, xml::child(d, asrt, SAMLNS, "Issuer"), "Format", saml::NAMEID_EMAIL); };
    tv::check_code("an Issuer of another Format", tv::run(sp, idpe, x14, "_req1", a), saml::ERR_ISSUER, a.message);
    // Status.
    let x15 = tv::response(idp, spe, false, true) { d, resp, asrt =>
        let sc = tv::find(d, resp, SAMLPNS, "StatusCode");
        tv::set(d, sc, "Value", saml::STATUS_RESPONDER);
        tv::set(d, xml::element(d, sc, "samlp", "StatusCode", SAMLPNS), "Value", saml::STATUS_AUTHN_FAILED);
    };
    tv::check_code("a Responder status", tv::run(sp, idpe, x15, "_req1", a), saml::ERR_STATUS, a.message);
    tv::check("  the codes kept", a.status[..] == saml::STATUS_RESPONDER && a.status2[..] == saml::STATUS_AUTHN_FAILED);
    // Version and such.
    let x16 = tv::response(idp, spe, true, false) { d, resp, asrt => tv::set(d, asrt, "Version", "1.1"); };
    tv::check_code("Version 1.1", tv::run(sp, idpe, x16, "_req1", a), saml::ERR_VERSION, a.message);
    let x17 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        let st = tv::find(d, asrt, SAMLNS, "AuthnStatement");
        xml::detach(d, st);
    };
    tv::check_code("no AuthnStatement", tv::run(sp, idpe, x17, "_req1", a), saml::ERR_SESSION, a.message);
    let x18 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmation"), "Method", "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key");
    };
    tv::check_code("holder-of-key only", tv::run(sp, idpe, x18, "_req1", a), saml::ERR_CONFIRMATION, a.message);
    let x19 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        // A second, good, bearer confirmation after a bad one.
        let sc = tv::find(d, asrt, SAMLNS, "SubjectConfirmation");
        tv::clone(d, sc, xml::parent(d, sc), sc, "", "");
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "Recipient", "https://other.example.test/acs");
    };
    tv::check_code("a good confirmation after a bad one", tv::run(sp, idpe, x19, "_req1", a), saml::OK, a.message);
}

fn requests(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    let x = tv::response(idp, spe, true, false) { d, resp, asrt => };
    tv::check_code("InResponseTo another request", tv::run(sp, idpe, x, "_req2", a), saml::ERR_IN_RESPONSE_TO, a.message);
    tv::check_code("a solicited Response taken as unsolicited", tv::run(sp, idpe, x, "", a), saml::ERR_IN_RESPONSE_TO, a.message);
    let x2 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        tv::set(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "InResponseTo", "_req2");
    };
    tv::check_code("the confirmation's InResponseTo another", tv::run(sp, idpe, x2, "_req1", a), saml::ERR_IN_RESPONSE_TO, a.message);
    let x3 = tv::response(idp, spe, true, false) { d, resp, asrt =>
        xml::detach(d, xml::attr_node(d, tv::find(d, asrt, SAMLNS, "SubjectConfirmationData"), "", "InResponseTo"));
    };
    tv::check_code("the confirmation without InResponseTo", tv::run(sp, idpe, x3, "_req1", a), saml::ERR_IN_RESPONSE_TO, a.message);
    // IdP-initiated.
    var user = saml::Login { .. };
    tv::alice(user);
    var o = saml::Outgoing { .. };
    tv::check_code("an unsolicited Response made", saml::idp_unsolicited_response(idp, spe, user, "/app", o), saml::OK, "");
    var m = saml::Received { .. };
    var body: u8[>..] = [];
    saml::post_body(body, false, o.xml, o.relay_state);
    saml::read_post(m, body, sp.max_message);
    tv::check_code("refused without the opt-in", saml::process_response(sp, idpe, m, "", a), saml::ERR_UNSOLICITED, a.message);
    sp.allow_idp_initiated = true;
    tv::check_code("taken with it", saml::process_response(sp, idpe, m, "", a), saml::OK, a.message);
    tv::check("  RelayState", a.has_relay_state && a.relay_state[..] == "/app");
    tv::check_code("  but not for a request we sent", saml::process_response(sp, idpe, m, "_req1", a), saml::ERR_IN_RESPONSE_TO, a.message);
    sp.allow_idp_initiated = false;
    // Replay.
    var seen: u8[][>..] = [];
    var mx = saml::Received { .. };
    saml::read_xml(mx, false, x, sp.max_message);
    let fresh = saml::process_response_replay(sp, idpe, mx, "_req1", a) { id, until =>
        var known = false;
        for s in seen { if s == id { known = true; } }
        if !known { var c: u8[>..] = []; c.append(id); seen.push(copy(c)); }
        !known
    };
    tv::check_code("first time", fresh, saml::OK, a.message);
    tv::check("  remembered until", a.replay_until == tv::NOW + 300 + 120);
    let again = saml::process_response_replay(sp, idpe, mx, "_req1", a) { id, until =>
        var known = false;
        for s in seen { if s == id { known = true; } }
        !known
    };
    tv::check_code("the same assertion again", again, saml::ERR_REPLAY, a.message);
    // By the Redirect binding: refused.
    var mr = saml::Received { .. };
    var q: u8[>..] = [];
    let none = saml::Signer { .. };
    saml::redirect_query(q, false, x, "", none, false);
    saml::read_redirect(mr, q, sp.max_message);
    tv::check_code("a Response by the Redirect binding", saml::process_response(sp, idpe, mr, "_req1", a), saml::ERR_BINDING, a.message);
}

fn keys_and_algorithms(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    // Signed by another key (a certificate with the IdP's name).
    let ek, ec = tv::load("evil");
    let real = copy(idp.signer.cert_der);
    saml::idp_set_key(idp, ek, ec);
    let x = tv::response(idp, spe, true, false) { d, resp, asrt => };
    let y = tv::response(idp, spe, false, true) { d, resp, asrt => };
    let ik = tv::load_key("idp");
    saml::idp_set_key(idp, ik, real);
    tv::check_code("an assertion signed by a key that is not the IdP's", tv::run(sp, idpe, x, "_req1", a), saml::ERR_SIGNATURE, a.message);
    tv::check_code("a Response signed by a key that is not the IdP's", tv::run(sp, idpe, y, "_req1", a), saml::ERR_SIGNATURE, a.message);
    tv::check("  the KeyInfo certificate is not trusted", find(x, "ds:X509Certificate") >= 0);
    // Two certificates in the IdP's metadata (a rollover): the second verifies.
    var two = saml::Entity { .. };
    saml::idp_entity(idp, two);
    two.idp_signing.clear();
    let ok, okc = tv::load("sp");
    saml::add_cert(two.idp_signing, okc);
    saml::add_cert(two.idp_signing, ec);
    tv::check_code("the second of two certificates", tv::run(sp, two, x, "_req1", a), saml::OK, a.message);
    var nocert = saml::Entity { .. };
    saml::idp_entity(idp, nocert);
    nocert.idp_signing.clear();
    tv::check_code("no certificate at all", tv::run(sp, nocert, x, "_req1", a), saml::ERR_SIGNATURE, a.message);
    // Unsigned.
    let u = tv::response(idp, spe, false, false) { d, resp, asrt => };
    tv::check_code("nothing signed", tv::run(sp, idpe, u, "_req1", a), saml::ERR_NOT_SIGNED, a.message);
    let r = tv::response(idp, spe, false, true) { d, resp, asrt => };
    sp.want_assertions_signed = true;
    tv::check_code("want_assertions_signed and only the Response signed", tv::run(sp, idpe, r, "_req1", a), saml::ERR_NOT_SIGNED, a.message);
    sp.want_assertions_signed = false;
    let s = tv::response(idp, spe, true, false) { d, resp, asrt => };
    sp.want_response_signed = true;
    tv::check_code("want_response_signed and only the assertion signed", tv::run(sp, idpe, s, "_req1", a), saml::ERR_NOT_SIGNED, a.message);
    sp.want_response_signed = false;
    // EC and Ed25519 IdP keys.
    signed_with(sp, idp, spe, "idp-p256");
    signed_with(sp, idp, spe, "idp-ed25519");
    // RSA 1024: too small.
    let sk, sc = tv::load("rsa1024");
    saml::idp_set_key(idp, sk, sc);
    var e3 = saml::Entity { .. };
    saml::idp_entity(idp, e3);
    let z3 = tv::response(idp, spe, true, false) { d, resp, asrt => };
    tv::check_code("an RSA 1024 key", tv::run(sp, e3, z3, "_req1", a), saml::ERR_SIGNATURE, a.message);
    saml::idp_set_key(idp, ik, real);
    // SHA-1: xmlsec's rsa-sha1 signature over a Response (make_vectors.py).
    let v = tv::read("data/xmlsec-rsa-sha1.xml");
    let saved = sp.now;
    sp.now = tv::NOW + 10;
    tv::check_code("SHA-1 refused", tv::run(sp, idpe, v, "_req1", a), saml::ERR_ALGORITHM, a.message);
    sp.allow_sha1 = true;
    tv::check_code("SHA-1 with allow_sha1", tv::run(sp, idpe, v, "_req1", a), saml::OK, a.message);
    sp.allow_sha1 = false;
    let v2 = tv::read("data/xmlsec-rsa-sha256.xml");
    tv::check_code("xmlsec's RSA-SHA256", tv::run(sp, idpe, v2, "_req1", a), saml::OK, a.message);
    tv::check("  its NameID", a.name_id[..] == "alice@example.test");
    sp.now = saved;
}

fn signed_with(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, name: const u8[:]) {
    var a = saml::Assertion { .. };
    let k, c = tv::load(name);
    saml::idp_set_key(idp, k, c);
    var e2 = saml::Entity { .. };
    saml::idp_entity(idp, e2);
    let z = tv::response(idp, spe, true, true) { d, resp, asrt => };
    let e = tv::run(sp, e2, z, "_req1", a);
    tv::check_code(str("signed with ", name), e, saml::OK, a.message);
}

fn hostile_input(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var a = saml::Assertion { .. };
    let x = tv::response(idp, spe, true, false) { d, resp, asrt => };
    // A DOCTYPE (an entity to expand in the NameID).
    let decl = find(x, "?>") + 2;
    var dt: u8[>..] = [];
    dt.append(x[..decl]);
    dt.append("<!DOCTYPE r [<!ENTITY e \"admin\">]>");
    dt.append(x[decl..]);
    tv::check_code("a DOCTYPE", tv::run(sp, idpe, dt, "_req1", a), saml::ERR_MALFORMED, a.message);
    tv::check("  said so", find(a.message, "doctype") >= 0);
    var dt2: u8[>..] = [];
    dt2.append(x[..decl]);
    dt2.append("<!DOCTYPE Response SYSTEM \"http://evil.example.test/x.dtd\">");
    dt2.append(x[decl..]);
    tv::check_code("an external DTD", tv::run(sp, idpe, dt2, "_req1", a), saml::ERR_MALFORMED, a.message);
    // Over the size limit.
    sp.max_message = 4096;
    tv::check_code("a Response over max_message", tv::run(sp, idpe, x, "_req1", a), saml::ERR_LIMIT, a.message);
    var big: u8[>..] = [];
    saml::post_body(big, false, x, "");
    var m = saml::Received { .. };
    tv::check_code("a POST over the limit", saml::read_post(m, big, 4096), saml::ERR_LIMIT, m.message);
    sp.max_message = saml::DEFAULT_MAX_MESSAGE;
    // A deep document.
    var deep: u8[>..] = [];
    for i in 1000 { deep.append("<a>"); }
    tv::check_code("1000 elements deep", tv::run(sp, idpe, deep, "_req1", a), saml::ERR_LIMIT, a.message);
    // Not XML; not a Response.
    tv::check_code("not XML", tv::run(sp, idpe, "hello", "_req1", a), saml::ERR_MALFORMED, a.message);
    tv::check_code("not a Response", tv::run(sp, idpe, "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"/>", "_req1", a),
                   saml::ERR_MALFORMED, a.message);
    // A SAMLRequest given as a Response.
    var mq = saml::Received { .. };
    saml::read_xml(mq, true, x, sp.max_message);
    tv::check_code("a SAMLRequest", saml::process_response(sp, idpe, mq, "_req1", a), saml::ERR_BINDING, a.message);
}

fn main() {
    var sp = saml::Sp { .. };
    var idp = saml::Idp { .. };
    var spe = saml::Entity { .. };
    var idpe = saml::Entity { .. };
    tv::setup(sp, idp, spe, idpe);
    ok_response(sp, idp, spe, idpe);
    encrypted(sp, idp, spe, idpe);
    wrapping(sp, idp, spe, idpe);
    comment_name_id(sp, idp, spe, idpe);
    times(sp, idp, spe, idpe);
    addressing(sp, idp, spe, idpe);
    requests(sp, idp, spe, idpe);
    keys_and_algorithms(sp, idp, spe, idpe);
    hostile_input(sp, idp, spe, idpe);
    tv::done("sp");
}
