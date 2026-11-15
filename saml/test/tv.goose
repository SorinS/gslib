// tv: what saml's tests share: counting checks, the keys in data/, a
// service provider and an identity provider set up to talk to each other
// at a fixed time, and Responses built by the IdP code unsigned, changed
// by the test, then signed as the test asks.

namespace tv;

import std;
import os;
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.encoding.xml;
import gslib.encoding.xml.dsig;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok {
        failures++;
        print("FAIL ", what);
    }
}

// That code is what came back, printing the error message when not.
fn check_code(what: const u8[:], got: i64, want: i64, why: const u8[:]) {
    check(what, got == want);
    var verbose: u8[>..] = [];
    if env("SAML_VERBOSE", verbose) { print("  ", what, ": ", saml::error_text(got), " (", why, ")"); }
    if got != want { print("      got ", saml::error_text(got), " (", why, "), want ", saml::error_text(want)); }
}

fn done(name: const u8[:]) {
    print(name, ": ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}

let SAMLNS = "urn:oasis:names:tc:SAML:2.0:assertion";
let SAMLPNS = "urn:oasis:names:tc:SAML:2.0:protocol";

// 2026-01-01T00:00:00Z: the IdP's clock; the SP's is 10 seconds later.
let NOW: i64 = 1767225600;

let SP_ID = "https://sp.example.test/metadata";
let SP_ACS = "https://sp.example.test/acs";
let SP_SLO = "https://sp.example.test/slo";
let IDP_ID = "https://idp.example.test/metadata";
let IDP_SSO = "https://idp.example.test/sso";
let IDP_SLO = "https://idp.example.test/slo";

fn read(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !read_file(path, out) { print("cannot read ", path); exit(1); }
    return out;
}

// A key and its certificate's DER, from data/NAME.key and data/NAME.crt.
fn load(name: const u8[:]) -> x509::PrivateKey, u8[>..] {
    let k = read(str("data/", name, ".key"));
    let c = read(str("data/", name, ".crt"));
    let key, ok = x509::parse_private_key_pem(k);
    let cert, ce = x509::parse_pem(c);
    if !ok || ce != x509::OK { print("bad key or certificate ", name); exit(1); }
    return key, copy(cert.der);
}

fn load_key(name: const u8[:]) -> x509::PrivateKey {
    let k, c = load(name);
    return k;
}

fn cert(name: const u8[:]) -> x509::Cert {
    let c = read(str("data/", name, ".crt"));
    let cert, ce = x509::parse_pem(c);
    return cert;
}

// The two sides, each with the other's metadata.
fn setup(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    sp.entity_id.append(SP_ID);
    sp.acs_url.append(SP_ACS);
    sp.slo_url.append(SP_SLO);
    let sk, sc = load("sp");
    saml::sp_set_key(sp, sk, sc);
    sp.now = NOW + 10;
    idp.entity_id.append(IDP_ID);
    idp.sso_url.append(IDP_SSO);
    idp.slo_url.append(IDP_SLO);
    let ik, ic = load("idp");
    saml::idp_set_key(idp, ik, ic);
    idp.now = NOW;
    saml::sp_entity(sp, spe);
    saml::idp_entity(idp, idpe);
}

// The user every Response is about.
fn alice(user: saml::Login&) {
    user.name_id.append("alice@example.test");
    user.name_id_format.append(saml::NAMEID_EMAIL);
    user.session_index.append("_session1");
    saml::add_value(user, "urn:oid:0.9.2342.19200300.100.1.3", "alice@example.test");
    saml::add_value(user, "groups", "staff");
    saml::add_value(user, "groups", "admins");
}

// The request a Response answers: ID _req1, our ACS.
fn request(r: saml::Message&) {
    saml::reset_message(r);
    r.id.append("_req1");
    r.acs_url.append(SP_ACS);
}

// A Response from the IdP code, unsigned, for the test to change:
// F(d, response, assertion) before anything is signed; then the assertion
// and the Response signed as asked. The XML.
fn response<F>(idp: saml::Idp&, spe: const saml::Entity&, sign_assertion: bool, sign_response: bool) -> u8[>..] {
    var r = saml::Message { .. };
    request(r);
    var user = saml::Login { .. };
    alice(user);
    let sa = idp.sign_assertion;
    let sr = idp.sign_response;
    let en = idp.encrypt;
    idp.sign_assertion = false;
    idp.sign_response = false;
    idp.encrypt = false;
    var o = saml::Outgoing { .. };
    let e = saml::idp_response(idp, spe, r, user, o);
    idp.sign_assertion = sa;
    idp.sign_response = sr;
    idp.encrypt = en;
    assert(e == saml::OK);
    var d = xml::Doc { .. };
    let pe = xml::parse(d, o.xml);
    assert(pe.code == xml::OK);
    let resp = xml::root_element(d);
    let asrt = xml::child(d, resp, SAMLNS, "Assertion");
    F(d, resp, asrt);
    if sign_assertion { assert(saml::sign_element(d, asrt, idp.signer) == saml::OK); }
    if sign_response { assert(saml::sign_element(d, resp, idp.signer) == saml::OK); }
    var out: u8[>..] = [];
    xml::write_document(d, out);
    return out;
}

// The SP's verdict on a Response's XML, as if posted, for request _req1
// (or `request_id`).
fn run(sp: const saml::Sp&, idpe: const saml::Entity&, text: const u8[:], request_id: const u8[:], a: saml::Assertion&) -> i64 {
    var m = saml::Received { .. };
    let e = saml::read_xml(m, false, text, sp.max_message);
    if e != saml::OK { saml::reset_assertion(a); a.message.append(m.message); return e; }
    return saml::process_response(sp, idpe, m, request_id, a);
}

// Sets an attribute's value on el.
fn set(d: xml::Doc&, el: i64, name: const u8[:], value: const u8[:]) { assert(xml::set_attr(d, el, name, value)); }

// The first descendant element of n named local in ns, -1 for none.
fn find(d: const xml::Doc&, n: i64, ns: const u8[:], local: const u8[:]) -> i64 {
    var found: i64 = -1;
    xml::walk(d, n) { x, entering =>
        if entering && found < 0 && xml::kind(d, x) == xml::ELEMENT && xml::is(d, x, ns, local) { found = x; }
        found < 0
    };
    return found;
}

// Replaces the text of el.
fn set_text(d: xml::Doc&, el: i64, value: const u8[:]) {
    var c = xml::first_child(d, el);
    while c >= 0 { let nx = xml::next_sibling(d, c); xml::detach(d, c); c = nx; }
    assert(xml::text(d, el, value) >= 0);
}

// A copy of the subtree el (written and parsed again), inserted under
// parent before `before`, with every "ID" value and the NameID changed
// as given (empty: kept); the copy.
fn clone(d: xml::Doc&, el: i64, parent: i64, before: i64, new_id: const u8[:], name_id: const u8[:]) -> i64 {
    var text: u8[>..] = [];
    xml::write(d, el, text);
    var o = xml::options();
    o.unique_ids = false;
    let pe = xml::parse_fragment(d, parent, before, text, o);
    assert(pe.code == xml::OK);
    let c = if before >= 0 { xml::prev_sibling(d, before) } else { xml::last_child(d, parent) };
    if new_id.len > 0 { set(d, c, "ID", new_id); }
    if name_id.len > 0 {
        let n = find(d, c, SAMLNS, "NameID");
        if n >= 0 { set_text(d, n, name_id); }
    }
    return c;
}
