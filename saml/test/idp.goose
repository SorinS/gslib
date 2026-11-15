// The identity provider's side, and Single Logout both ways: an
// AuthnRequest by each binding, signed and not, read and checked (the
// signature required by the IdP or by the SP's metadata, another key,
// the ACS URL against the metadata, an index, the ProtocolBinding, the
// Destination, the Issuer, IssueInstant), answered with a Response the
// SP takes, or refused with an error Response; then LogoutRequest and
// LogoutResponse from the SP to the IdP and back, and from the IdP to the
// SP, by each binding, and refused unsigned, expired, for another
// request, or with a failure status.
import std;
import os;
import gslib from "../..";
import gslib.saml;
import gslib.saml.metadata;
import gslib.saml.logout;
import gslib.saml.sp;
import gslib.saml.idp;
import gslib.encoding.xml;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import tv;

// What the browser carries from an Outgoing to the other side, as that
// side's HTTP server sees it.
fn carry(o: const saml::Outgoing&, m: saml::Received&) -> i64 {
    if o.binding == saml::BINDING_REDIRECT {
        let q = o.url[find(o.url, "?") + 1..];
        return saml::read_redirect(m, q, saml::DEFAULT_MAX_MESSAGE);
    }
    var body: u8[>..] = [];
    saml::post_body(body, find(o.form, "name=\"SAMLRequest\"") >= 0, o.xml, o.relay_state);
    return saml::read_post(m, body, saml::DEFAULT_MAX_MESSAGE);
}

fn authn_requests(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var o = saml::Outgoing { .. };
    var m = saml::Received { .. };
    var r = saml::Message { .. };
    for b in 2 {
        let binding = if b == 0 { saml::BINDING_REDIRECT } else { saml::BINDING_POST };
        for signed in 2 {
            sp.sign_requests = signed == 1;
            idp.want_authn_requests_signed = signed == 1;
            var ao = saml::AuthnOptions { force_authn: true, .. };
            format(ao.name_id_format, saml::NAMEID_PERSISTENT);
            format(ao.authn_context, saml::AC_PASSWORD_PROTECTED);
            let e = saml::authn_request_with(sp, idpe, binding, "state-1", ao, o);
            tv::check_code(str("AuthnRequest by ", saml::binding_name(binding), ", signed ", sp.sign_requests), e, saml::OK, "");
            tv::check("  an ID", o.id.len == 41);
            tv::check("  the destination", starts_with(if binding == saml::BINDING_REDIRECT { o.url[..] } else { o.url[..] }, tv::IDP_SSO));
            tv::check("  the XML signed only by POST", (find(o.xml, "Signature") >= 0) == (signed == 1 && binding == saml::BINDING_POST));
            tv::check("  the query signed only by Redirect", (find(o.url, "&Signature=") >= 0) == (signed == 1 && binding == saml::BINDING_REDIRECT));
            tv::check_code("  carried", carry(o, m), saml::OK, m.message);
            var who: u8[>..] = [];
            tv::check_code("  peek_issuer", saml::peek_issuer(m, who), saml::OK, "");
            tv::check("  the SP", who[..] == tv::SP_ID);
            let re = saml::idp_read_authn_request(idp, spe, m, r);
            tv::check_code("  read by the IdP", re, saml::OK, r.message);
            tv::check("  its fields", r.id[..] == o.id[..] && r.acs_url[..] == tv::SP_ACS && r.force_authn && !r.is_passive &&
                      r.name_id_policy[..] == saml::NAMEID_PERSISTENT && r.allow_create && r.authn_context.len == 1 &&
                      r.relay_state[..] == "state-1" && r.signed == (signed == 1) && r.issuer[..] == tv::SP_ID);
        }
    }
    sp.sign_requests = false;
    // Unsigned, when the IdP wants them signed.
    saml::authn_request(sp, idpe, saml::BINDING_REDIRECT, "", o);
    carry(o, m);
    idp.want_authn_requests_signed = true;
    tv::check_code("unsigned, the IdP wanting signatures", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_NOT_SIGNED, r.message);
    idp.want_authn_requests_signed = false;
    spe.authn_requests_signed = true;
    tv::check_code("unsigned, the SP's metadata saying they are", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_NOT_SIGNED, r.message);
    spe.authn_requests_signed = false;
    tv::check_code("unsigned, neither", saml::idp_read_authn_request(idp, spe, m, r), saml::OK, r.message);
    // Signed by another key.
    let ek, ec = tv::load("evil");
    let real = copy(sp.signer.cert_der);
    let real_key = sp.signer.key;
    saml::sp_set_key(sp, ek, ec);
    sp.sign_requests = true;
    saml::authn_request(sp, idpe, saml::BINDING_REDIRECT, "", o);
    carry(o, m);
    tv::check_code("a Redirect request signed by another key", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_SIGNATURE, r.message);
    saml::authn_request(sp, idpe, saml::BINDING_POST, "", o);
    carry(o, m);
    tv::check_code("a POST request signed by another key", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_SIGNATURE, r.message);
    saml::sp_set_key(sp, real_key, real);
    // The query's signature over another RelayState.
    saml::authn_request(sp, idpe, saml::BINDING_REDIRECT, "one", o);
    var swapped: u8[>..] = [];
    format_replaced(swapped, o.url, "RelayState=one", "RelayState=two");
    saml::read_redirect(m, swapped[find(swapped, "?") + 1..], saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("RelayState changed in a signed query", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_SIGNATURE, r.message);
    sp.sign_requests = false;
    // Requests made by hand.
    let good = str("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_a1\" Version=\"2.0\" IssueInstant=\"",
                   saml::time_text(tv::NOW), "\" Destination=\"", tv::IDP_SSO, "\"");
    let issuer = str("><saml:Issuer>", tv::SP_ID, "</saml:Issuer></samlp:AuthnRequest>");
    var cases: u8[][>..] = [];
    cases.push(str(good, " AssertionConsumerServiceURL=\"https://evil.example.test/acs\"", issuer));
    cases.push(str(good, " AssertionConsumerServiceIndex=\"5\"", issuer));
    cases.push(str(good, " ProtocolBinding=\"", saml::URI_BINDING_ARTIFACT, "\"", issuer));
    cases.push(str(good, " AssertionConsumerServiceIndex=\"0\"", issuer));
    cases.push(str(good, issuer));
    let want = [saml::ERR_ENDPOINT, saml::ERR_ENDPOINT, saml::ERR_BINDING, saml::OK, saml::OK];
    let what = ["an ACS URL not in the metadata", "an ACS index not in the metadata", "the Artifact binding", "ACS index 0", "the default ACS"];
    var i: i64 = 0;
    for c in cases {
        saml::read_xml(m, true, c, saml::DEFAULT_MAX_MESSAGE);
        m.binding = saml::BINDING_POST;
        let e = saml::idp_read_authn_request(idp, spe, m, r);
        tv::check_code(what[i], e, want[i], r.message);
        i++;
    }
    tv::check("  the default ACS", r.acs_url[..] == tv::SP_ACS);
    var bad: u8[>..] = [];
    format_replaced(bad, str(good, issuer), tv::IDP_SSO, "https://other.example.test/sso");
    saml::read_xml(m, true, bad, saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("another Destination", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_DESTINATION, r.message);
    bad.clear();
    format_replaced(bad, str(good, issuer), tv::SP_ID, "https://evil.example.test");
    saml::read_xml(m, true, bad, saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("another Issuer", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_ISSUER, r.message);
    bad.clear();
    format_replaced(bad, str(good, issuer), saml::time_text(tv::NOW), saml::time_text(tv::NOW + 3600));
    saml::read_xml(m, true, bad, saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("IssueInstant ahead", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_NOT_YET_VALID, r.message);
    bad.clear();
    format_replaced(bad, str(good, issuer), "Version=\"2.0\"", "Version=\"1.0\"");
    saml::read_xml(m, true, bad, saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("Version 1.0", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_VERSION, r.message);
    saml::read_xml(m, false, str(good, issuer), saml::DEFAULT_MAX_MESSAGE);
    tv::check_code("as a SAMLResponse", saml::idp_read_authn_request(idp, spe, m, r), saml::ERR_BINDING, r.message);
}

fn responses(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var o = saml::Outgoing { .. };
    var m = saml::Received { .. };
    var r = saml::Message { .. };
    var a = saml::Assertion { .. };
    saml::authn_request(sp, idpe, saml::BINDING_REDIRECT, "back-to", o);
    carry(o, m);
    let request_id = copy(o.id);
    tv::check_code("a request", saml::idp_read_authn_request(idp, spe, m, r), saml::OK, r.message);
    var user = saml::Login { .. };
    tv::alice(user);
    var resp = saml::Outgoing { .. };
    tv::check_code("the IdP answers", saml::idp_response(idp, spe, r, user, resp), saml::OK, "");
    tv::check("  by POST to the ACS", resp.binding == saml::BINDING_POST && resp.url[..] == tv::SP_ACS && find(resp.form, "SAMLResponse") >= 0);
    tv::check_code("  carried", carry(resp, m), saml::OK, m.message);
    tv::check_code("  the SP takes it", saml::process_response(sp, idpe, m, request_id, a), saml::OK, a.message);
    tv::check("  RelayState came back", a.relay_state[..] == "back-to");
    // An error Response.
    tv::check_code("a refusal", saml::idp_error_response(idp, spe, r, saml::STATUS_RESPONDER, saml::STATUS_AUTHN_FAILED, "wrong password", resp), saml::OK, "");
    carry(resp, m);
    tv::check_code("  the SP reads the status", saml::process_response(sp, idpe, m, request_id, a), saml::ERR_STATUS, a.message);
    tv::check("  its codes and message", a.status[..] == saml::STATUS_RESPONDER && a.status2[..] == saml::STATUS_AUTHN_FAILED &&
              a.status_message[..] == "wrong password");
    // The IdP signs with SHA-512.
    idp.signer.hash = 512;
    tv::check_code("RSA-SHA512", saml::idp_response(idp, spe, r, user, resp), saml::OK, "");
    tv::check("  the method", find(resp.xml, "rsa-sha512") >= 0 && find(resp.xml, "xmlenc#sha512") >= 0);
    carry(resp, m);
    tv::check_code("  taken", saml::process_response(sp, idpe, m, request_id, a), saml::OK, a.message);
    idp.signer.hash = 256;
    // Without a key, nothing to sign with.
    var nokey = saml::Idp { .. };
    nokey.entity_id.append(tv::IDP_ID);
    tv::check_code("an IdP without a key", saml::idp_response(nokey, spe, r, user, resp), saml::ERR_ARG, "");
    var empty = saml::Login { .. };
    tv::check_code("a Login without a NameID", saml::idp_response(idp, spe, r, empty, resp), saml::ERR_ARG, "");
    // Encryption asked for, but the SP has no encryption certificate.
    var nocert = saml::Entity { .. };
    saml::sp_entity(sp, nocert);
    nocert.sp_encryption.clear();
    idp.encrypt = true;
    tv::check_code("encrypting without the SP's certificate", saml::idp_response(idp, nocert, r, user, resp), saml::ERR_ARG, "");
    idp.encrypt = false;
}

fn logout(sp: saml::Sp&, idp: saml::Idp&, spe: saml::Entity&, idpe: saml::Entity&) {
    var o = saml::Outgoing { .. };
    var back = saml::Outgoing { .. };
    var m = saml::Received { .. };
    var r = saml::Message { .. };
    var who = saml::LogoutSubject { .. };
    format(who.name_id, "alice@example.test");
    format(who.format, saml::NAMEID_EMAIL);
    format(who.session_index, "_session1");
    for b in 2 {
        let binding = if b == 0 { saml::BINDING_REDIRECT } else { saml::BINDING_POST };
        let bn = saml::binding_name(binding);
        // SP to IdP.
        let e0 = saml::sp_logout_request(sp, idpe, binding, who, "rs", o);
        tv::check_code(str("SP LogoutRequest by ", bn), e0, saml::OK, "");
        tv::check_code("  carried", carry(o, m), saml::OK, m.message);
        let e = saml::idp_read_logout_request(idp, spe, m, r);
        tv::check_code("  read by the IdP", e, saml::OK, r.message);
        tv::check("  its NameID and SessionIndex", r.name_id[..] == "alice@example.test" && r.name_id_format[..] == saml::NAMEID_EMAIL &&
                  r.session_indexes.len == 1 && r.signed && r.not_on_or_after == tv::NOW + 10 + 300 && r.relay_state[..] == "rs");
        var si = false;
        for s in r.session_indexes { si = s == "_session1"; }
        tv::check("  the session", si);
        tv::check_code("  the IdP answers", saml::idp_logout_response(idp, spe, binding, r.id, saml::STATUS_SUCCESS, r.relay_state, back), saml::OK, "");
        carry(back, m);
        let e2 = saml::sp_read_logout_response(sp, idpe, m, o.id, r);
        tv::check_code("  the SP reads it", e2, saml::OK, r.message);
        let e3 = saml::sp_read_logout_response(sp, idpe, m, "_other", r);
        tv::check_code("  for another request", e3, saml::ERR_IN_RESPONSE_TO, r.message);
        // IdP to SP.
        let e1 = saml::idp_logout_request(idp, spe, binding, who, "", o);
        tv::check_code(str("IdP LogoutRequest by ", bn), e1, saml::OK, "");
        carry(o, m);
        let e4 = saml::sp_read_logout_request(sp, idpe, m, r);
        tv::check_code("  read by the SP", e4, saml::OK, r.message);
        tv::check("  its NameID", r.name_id[..] == "alice@example.test" && r.issuer[..] == tv::IDP_ID);
        tv::check_code("  the SP answers with a failure", saml::sp_logout_response(sp, idpe, binding, r.id, saml::STATUS_RESPONDER, "", back), saml::OK, "");
        carry(back, m);
        let e5 = saml::idp_read_logout_response(idp, spe, m, o.id, r);
        tv::check_code("  the IdP sees the failure", e5, saml::ERR_STATUS, r.message);
        tv::check("  its status", r.status[..] == saml::STATUS_RESPONDER);
    }
    // Unsigned: refused.
    sp.sign_logout = false;
    saml::sp_logout_request(sp, idpe, saml::BINDING_REDIRECT, who, "", o);
    carry(o, m);
    tv::check_code("an unsigned LogoutRequest", saml::idp_read_logout_request(idp, spe, m, r), saml::ERR_NOT_SIGNED, r.message);
    sp.sign_logout = true;
    // Expired: the IdP's clock long after.
    saml::sp_logout_request(sp, idpe, saml::BINDING_POST, who, "", o);
    carry(o, m);
    idp.now = tv::NOW + 3600;
    tv::check_code("an expired LogoutRequest", saml::idp_read_logout_request(idp, spe, m, r), saml::ERR_EXPIRED, r.message);
    idp.now = tv::NOW;
    // Without NotOnOrAfter: IssueInstant no older than logout_max_age and the skew.
    let sign_now = sp.now;
    saml::logout_request_to(sp.entity_id, sp.signer, true, idpe, saml::ROLE_IDP, saml::BINDING_POST, who, sign_now, 0, "", o);
    carry(o, m);
    tv::check_code("a LogoutRequest without NotOnOrAfter", saml::idp_read_logout_request(idp, spe, m, r), saml::OK, r.message);
    tv::check("  remembered for max age and skew", r.not_on_or_after == 0 && r.replay_until == sign_now + 300 + idp.clock_skew);
    idp.now = sign_now + 300 + idp.clock_skew + 1;
    tv::check_code("  replayed much later", saml::idp_read_logout_request(idp, spe, m, r), saml::ERR_EXPIRED, r.message);
    idp.now = tv::NOW;
    // Replayed: the caller's cache refuses its ID the second time.
    saml::sp_logout_request(sp, idpe, saml::BINDING_POST, who, "", o);
    carry(o, m);
    var seen: u8[][>..] = [];
    var kept_until: i64 = 0;
    for i in 2 {
        let e = saml::idp_read_logout_request_replay(idp, spe, m, r) { id, until =>
            var known = false;
            for s in seen { if s == id { known = true; } }
            if !known { seen.push(str(id)); kept_until = until; }
            !known
        };
        if i == 0 {
            tv::check_code("a LogoutRequest, replay checked", e, saml::OK, r.message);
            tv::check("  kept until its NotOnOrAfter and the skew", kept_until == r.not_on_or_after + idp.clock_skew);
        } else {
            tv::check_code("  the same again: refused", e, saml::ERR_REPLAY, r.message);
        }
    }
    saml::idp_logout_request(idp, spe, saml::BINDING_REDIRECT, who, "", o);
    carry(o, m);
    var seen2: u8[][>..] = [];
    for i in 2 {
        let e = saml::sp_read_logout_request_replay(sp, idpe, m, r) { id, until =>
            var known = false;
            for s in seen2 { if s == id { known = true; } }
            if !known { seen2.push(str(id)); }
            !known
        };
        tv::check_code(if i == 0 { "the SP's replay check: new" } else { "  replayed" }, e, if i == 0 { saml::OK } else { saml::ERR_REPLAY }, r.message);
    }
    // Another IdP's SLO URL.
    var other = saml::Entity { .. };
    saml::idp_entity(idp, other);
    for &ep in other.endpoints { if ep.kind == saml::EP_SLO { ep.location.clear(); format(ep.location, "https://other.example.test/slo"); } }
    saml::sp_logout_request(sp, other, saml::BINDING_POST, who, "", o);
    carry(o, m);
    tv::check_code("a LogoutRequest to another endpoint", saml::idp_read_logout_request(idp, spe, m, r), saml::ERR_DESTINATION, r.message);
    // From an assertion.
    var a = saml::Assertion { .. };
    a.name_id.append("bob@example.test");
    a.name_id_format.append(saml::NAMEID_EMAIL);
    a.session_index.append("_s9");
    let w, okw = saml::logout_subject_of(a);
    tv::check("whom an assertion was about", okw && w.name_id[..] == "bob@example.test" && w.session_index[..] == "_s9");
    var long_id: u8[>..] = [];
    long_id.resize(1025, 'x');
    a.name_id.clear();
    a.name_id.append(long_id);
    let w2, okw2 = saml::logout_subject_of(a);
    tv::check("  a NameID too long for a LogoutSubject: refused, not cut", !okw2);
    // No SLO endpoint at the peer.
    var noslo = saml::Entity { .. };
    saml::idp_entity(idp, noslo);
    noslo.endpoints.clear();
    tv::check_code("no SLO endpoint", saml::sp_logout_request(sp, noslo, saml::BINDING_POST, who, "", o), saml::ERR_ENDPOINT, "");
}

fn main() {
    var sp = saml::Sp { .. };
    var idp = saml::Idp { .. };
    var spe = saml::Entity { .. };
    var idpe = saml::Entity { .. };
    tv::setup(sp, idp, spe, idpe);
    authn_requests(sp, idp, spe, idpe);
    responses(sp, idp, spe, idpe);
    logout(sp, idp, spe, idpe);
    tv::done("idp");
}
