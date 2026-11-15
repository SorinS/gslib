// Fuzz target: saml. The first byte picks the binding: HTTP-POST (a form
// body: SAMLResponse or SAMLRequest, base64) or HTTP-Redirect (a query
// string: base64 of raw DEFLATE, RelayState, SigAlg, Signature). What
// read_post or read_redirect delivers goes to every reader that takes it,
// as SP and as IdP: a Response to process_response (the assertion's
// accessors after), a LogoutResponse to both sides' readers; a request to
// idp_read_authn_request and both sides' LogoutRequest readers; and
// peek_issuer. The SP and IdP are saml/test's (tv.goose setup), built
// once in main() at a fixed time: the SP with its key (to decrypt), the
// IdP with its certificate only (as the SP's metadata of it).

import std;
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

let SP_KEY = embed_file("../../saml/test/data/sp.key");
let SP_CRT = embed_file("../../saml/test/data/sp.crt");
let IDP_CRT = embed_file("../../saml/test/data/idp.crt");

let NOW: i64 = 1767225600;        // tv::NOW

var SP = saml::Sp { .. };
var IDP = saml::Idp { .. };
var SPE = saml::Entity { .. };    // the SP's metadata, as the IdP has it
var IDPE = saml::Entity { .. };   // the IdP's, as the SP has it

fn assertion_accessors(a: const saml::Assertion&) {
    saml::each_attribute(a) { n, info => let _ = n.len; };
    var k = 0;
    for name in a.attr_names {
        if k >= 4 { break; }
        k++;
        saml::each_value(a, name) { v => let _ = v.len; };
        let _, _ = saml::attribute(a, name);
        let _ = saml::value_count(a, name);
    }
    let _, _ = saml::logout_subject_of(a);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let input = data[1..];
    var m = saml::Received { .. };
    let e = if data[0] % 2 == 0 { saml::read_post(m, input, SP.max_message) } else { saml::read_redirect(m, input, SP.max_message) };
    if e != saml::OK { return 0; }
    var issuer: u8[>..] = [];
    let _ = saml::peek_issuer(m, issuer);
    let _ = saml::redirect_signed(m);
    var r = saml::Message { .. };
    if m.is_request {
        let _ = saml::idp_read_authn_request(IDP, SPE, m, r);
        let _ = saml::sp_read_logout_request(SP, IDPE, m, r);
        let _ = saml::idp_read_logout_request(IDP, SPE, m, r);
    } else {
        var a = saml::Assertion { .. };
        let pe = saml::process_response(SP, IDPE, m, "_req1", a);
        if pe == saml::OK { assertion_accessors(a); }
        let _ = saml::sp_read_logout_response(SP, IDPE, m, "_req1", r);
        let _ = saml::idp_read_logout_response(IDP, SPE, m, "_req1", r);
    }
    return 0;
}

fn main() {
    SP.entity_id.append("https://sp.example.test/metadata");
    SP.acs_url.append("https://sp.example.test/acs");
    SP.slo_url.append("https://sp.example.test/slo");
    let key, ok = x509::parse_private_key_pem(SP_KEY);
    let spc, e1 = x509::parse_pem(SP_CRT);
    assert(ok && e1 == x509::OK);
    saml::sp_set_key(SP, key, spc.der);
    SP.now = NOW + 10;
    IDP.entity_id.append("https://idp.example.test/metadata");
    IDP.sso_url.append("https://idp.example.test/sso");
    IDP.slo_url.append("https://idp.example.test/slo");
    let idc, e2 = x509::parse_pem(IDP_CRT);
    assert(e2 == x509::OK);
    IDP.signer.cert_der.append(idc.der);
    IDP.now = NOW;
    saml::sp_entity(SP, SPE);
    saml::idp_entity(IDP, IDPE);
}
