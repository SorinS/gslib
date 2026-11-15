// offline: a SAML login from end to end in one program, no network. A
// service provider and an identity provider, each with a fresh key and
// self-signed certificate (P-256), exchange metadata; the SP sends an
// AuthnRequest by the HTTP-Redirect binding; the IdP reads it and answers
// with a Response whose assertion is signed and encrypted to the SP; the
// SP checks the Response (signature, destination, audience, times,
// InResponseTo) and reads the user and the attributes from what the
// signature covers. Then the same Response is refused as a replay, and a
// copy with a forged assertion wrapped around the signed one is refused.
//
//   goose examples/saml/offline.goose

import std;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

// A fresh P-256 key and a self-signed certificate for it (DER).
fn key_and_cert(name: const u8[:]) -> x509::PrivateKey, u8[>..] {
    let key = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template(str("CN=", name), 1767225600, 1798761600);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    guard ok && e == x509::OK else { print("offline: no certificate"); exit(1); }
    return key, der;
}

fn main() {
    // The service provider.
    var sp = saml::Sp { .. };
    sp.entity_id.append("https://sp.example.test/metadata");
    sp.acs_url.append("https://sp.example.test/acs");
    let sk, sc = key_and_cert("sp.example.test");
    saml::sp_set_key(sp, sk, sc);
    sp.require_encrypted = true;
    sp.want_assertions_signed = true;

    // The identity provider.
    var idp = saml::Idp { .. };
    idp.entity_id.append("https://idp.example.test/metadata");
    idp.sso_url.append("https://idp.example.test/sso");
    let ik, ic = key_and_cert("idp.example.test");
    saml::idp_set_key(idp, ik, ic);
    idp.encrypt = true;

    // Each reads the other's metadata (here written and parsed again, as it
    // would come in a file).
    var md: u8[>..] = [];
    saml::sp_metadata(sp, false, md);
    var sp_meta = saml::Entity { .. };
    guard saml::parse_metadata(sp_meta, md, "") == saml::OK else { print("offline: SP metadata: ", sp_meta.message); exit(1); }
    md.clear();
    saml::idp_metadata(idp, true, md);
    var idp_meta = saml::Entity { .. };
    let icert, ice = x509::parse(ic);
    guard saml::parse_metadata_signed(idp_meta, md, "", icert, saml::now_or(0)) == saml::OK
    else { print("offline: IdP metadata: ", idp_meta.message); exit(1); }

    // The SP sends the browser to the IdP, and keeps the request's ID.
    var req = saml::Outgoing { .. };
    guard saml::authn_request(sp, idp_meta, saml::BINDING_REDIRECT, "/inbox", req) == saml::OK else { exit(1); }
    print("redirect the browser to:\n  ", req.url[..120], "...");
    let request_id = copy(req.id);

    // The IdP gets the query string, checks the request, and answers.
    var m = saml::Received { .. };
    saml::read_redirect(m, req.url[find(req.url, "?") + 1..], saml::DEFAULT_MAX_MESSAGE);
    var ar = saml::Message { .. };
    let re = saml::idp_read_authn_request(idp, sp_meta, m, ar);
    guard re == saml::OK else { print("offline: the IdP refused: ", ar.message); exit(1); }
    print("the IdP read AuthnRequest ", ar.id, " from ", ar.issuer, ", to answer at ", ar.acs_url);
    var user = saml::Login { .. };
    user.name_id.append("alice@example.test");
    user.name_id_format.append(saml::NAMEID_EMAIL);
    saml::add_value(user, "mail", "alice@example.test");
    saml::add_value(user, "groups", "staff");
    saml::add_value(user, "groups", "admins");
    var resp = saml::Outgoing { .. };
    guard saml::idp_response(idp, sp_meta, ar, user, resp) == saml::OK else { exit(1); }
    print("the IdP answers with a page that posts ", resp.xml.len, " bytes of XML to ", resp.url);

    // The browser posts it to the SP's ACS; the SP checks it.
    var body: u8[>..] = [];
    saml::post_body(body, false, resp.xml, resp.relay_state);
    var got = saml::Received { .. };
    saml::read_post(got, body, sp.max_message);
    var seen: u8[][>..] = [];
    var a = saml::Assertion { .. };
    let e = saml::process_response_replay(sp, idp_meta, got, request_id, a) { id, until =>
        var known = false;
        for s in seen { if s == id { known = true; } }
        if !known { seen.push(str(id)); }
        !known
    };
    guard e == saml::OK else { print("offline: refused: ", saml::error_text(e), ": ", a.message); exit(1); }
    print("logged in: ", a.name_id, " (", a.name_id_format, ")");
    print("  encrypted ", a.encrypted, ", assertion signed ", a.assertion_signed, ", back to ", a.relay_state);
    saml::each_attribute(a) { name, info =>
        var values: u8[>..] = [];
        saml::each_value(a, name) { v => if values.len > 0 { values.append(", "); } values.append(v); };
        print("  ", name, ": ", values);
    };
    print("  remember assertion ", a.id, " until ", saml::time_text(a.replay_until));

    // The same Response again.
    let again = saml::process_response_replay(sp, idp_meta, got, request_id, a) { id, until =>
        var known = false;
        for s in seen { if s == id { known = true; } }
        !known
    };
    print("the same Response again: ", saml::error_text(again));

    // An attacker's copy: the signed assertion (decrypted) moved into an
    // assertion of their own, which is then the Response's only assertion.
    sp.require_encrypted = false;
    idp.encrypt = false;
    var plain = saml::Outgoing { .. };
    saml::idp_response(idp, sp_meta, ar, user, plain);
    let at = find(plain.xml, "<saml:Assertion ");
    let end = find(plain.xml, "</saml:Assertion>") + 17;
    let wrapped = str(plain.xml[..at], "<saml:Assertion ID=\"_evil\" Version=\"2.0\" IssueInstant=\"", saml::time_text(saml::now_or(0)),
                      "\"><saml:Issuer>https://idp.example.test/metadata</saml:Issuer>", plain.xml[at..end], "</saml:Assertion>", plain.xml[end..]);
    var w = saml::Received { .. };
    saml::read_xml(w, false, wrapped, sp.max_message);
    let we = saml::process_response(sp, idp_meta, w, request_id, a);
    print("a forged assertion wrapped around the signed one: ", saml::error_text(we), " (", a.message, ")");
    guard again == saml::ERR_REPLAY && we != saml::OK else { print("offline: wrong results"); exit(1); }
}
