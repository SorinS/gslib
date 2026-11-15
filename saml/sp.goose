// saml.sp: a SAML 2.0 service provider. AuthnRequests by the Redirect or
// the POST binding (signed when asked), the Response checked as the Web
// Browser SSO profile (saml-profiles §4.1.4) and saml-core say, and
// Single Logout both ways.
//
// What process_response checks, in this order:
//   - the message: POST binding, at most max_message bytes, no DOCTYPE,
//     well-formed, unique IDs; samlp:Response, Version 2.0, an ID, an
//     IssueInstant not ahead of the clock;
//   - the Response's signature, when it has one, verified with the
//     identity provider's signing certificates from its metadata; from
//     then on the Response is the node the signature covers;
//   - Issuer, if present, the IdP's entityID; Destination, if present, our
//     ACS URL (and present when the Response is signed); InResponseTo the
//     ID of the request the caller kept, or absent only for an
//     IdP-initiated response, which needs allow_idp_initiated;
//   - StatusCode Success (else ERR_STATUS, with the codes and message);
//   - exactly one Assertion or EncryptedAssertion, a direct child of the
//     Response: never one found elsewhere in the document;
//   - an EncryptedAssertion decrypted with our key (AES-GCM; CBC and
//     RSA 1.5 only with allow_cbc and allow_rsa15), then
//   - the assertion's own signature, when it has one, verified, and the
//     assertion read from the node it covers. Response or assertion must
//     be signed; want_assertions_signed and want_response_signed ask for
//     each;
//   - the assertion's Version, ID, IssueInstant, Issuer (the IdP's);
//   - Subject: one NameID (an EncryptedID decrypted), no elements in it,
//     its whole text; a bearer SubjectConfirmation whose
//     SubjectConfirmationData has Recipient our ACS URL, NotOnOrAfter not
//     passed, NotBefore (if any) not ahead, InResponseTo the request's (or
//     absent for an IdP-initiated response);
//   - Conditions: NotBefore and NotOnOrAfter with the clock skew; an
//     AudienceRestriction, each with our entityID among its Audiences;
//     OneTimeUse at most once (reported); ProxyRestriction let through; any
//     other condition refused;
//   - an AuthnStatement, its SessionNotOnOrAfter not passed;
//   - the attributes (EncryptedAttributes decrypted), every value kept;
//   - replay: the assertion's ID and the time it must be remembered until
//     (replay_until) are returned, and process_response_replay hands them
//     to the caller's block, which says whether it is new.

namespace saml;

import std;
import encoding.xml;
import encoding.xml.dsig;
import encoding.xml.enc;
import crypto.x509;
import crypto.x509.keys;
import saml.metadata;
import saml.logout;

// A service provider: who it is, its endpoints, its keys, and what it
// accepts. A root struct: declare it as a local, `var sp = saml::Sp { .. };`.
root struct Sp {
    entity_id:              u8[>..]          = [],
    acs_url:                u8[>..]          = [],   // the AssertionConsumerService (HTTP-POST)
    slo_url:                u8[>..]          = [],   // the SingleLogoutService (both bindings), "" for none
    signer:                 Signer           = Signer { .. },  // signs requests, logout, metadata
    has_enc_key:            bool             = false,          // else signer.key decrypts
    enc_key:                x509::PrivateKey = x509::empty_key(),
    enc_cert_der:           u8[>..]          = [],             // published for encryption, else signer.cert_der
    sign_requests:          bool             = false,          // sign AuthnRequests (also when the IdP wants it)
    sign_logout:            bool             = true,           // sign logout messages (with a key)
    want_assertions_signed: bool             = false,
    want_response_signed:   bool             = false,
    require_encrypted:      bool             = false,
    allow_idp_initiated:    bool             = false,
    allow_sha1:             bool             = false,
    allow_cbc:              bool             = false,
    allow_rsa15:            bool             = false,
    clock_skew:             i64              = 120,            // seconds either way
    logout_max_age:         i64              = 300,            // how old a LogoutRequest's IssueInstant may be (seconds, besides the skew)
    max_message:            i64              = DEFAULT_MAX_MESSAGE,
    name_id_format:         u8[>..]          = [],             // asked for in NameIDPolicy; "" none
    now:                    i64              = 0,              // seconds; 0: the clock (tests set it)
}

fn sp_set_key(sp: Sp&, key: const x509::PrivateKey&, cert_der: const u8[:]) {
    sp.signer.has_key = true;
    sp.signer.key = key;
    sp.signer.cert_der.clear();
    sp.signer.cert_der.append(cert_der);
}

fn sp_checks(sp: const Sp&, require_signed: bool) -> Checks {
    Checks { now: now_or(sp.now), skew: sp.clock_skew, allow_sha1: sp.allow_sha1, require_signed: require_signed, max: sp.max_message,
             max_age: sp.logout_max_age }
}

// The service provider's metadata as an Entity. False (and an endpoint
// left out) when acs_url or slo_url is not an absolute http(s) URL.
fn sp_entity(sp: const Sp&, e: Entity&) -> bool {
    reset_entity(e);
    e.entity_id.append(sp.entity_id);
    e.is_sp = true;
    e.authn_requests_signed = sp.sign_requests;
    e.want_assertions_signed = sp.want_assertions_signed;
    var ok = add_endpoint(e, ROLE_SP, EP_ACS, BINDING_POST, sp.acs_url);
    if sp.slo_url.len > 0 {
        ok = add_endpoint(e, ROLE_SP, EP_SLO, BINDING_REDIRECT, sp.slo_url) && ok;
        ok = add_endpoint(e, ROLE_SP, EP_SLO, BINDING_POST, sp.slo_url) && ok;
    }
    if sp.signer.cert_der.len > 0 { add_cert(e.sp_signing, sp.signer.cert_der); }
    let enc = if sp.has_enc_key { sp.enc_cert_der[..] } else { sp.signer.cert_der[..] };
    if enc.len > 0 {
        add_cert(e.sp_encryption, enc);
        for m in ["http://www.w3.org/2009/xmlenc11#aes256-gcm", "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                  "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2009/xmlenc11#rsa-oaep"] {
            var a: u8[>..] = [];
            a.append(m);
            e.encryption_methods.push(copy(a));
        }
    }
    if sp.name_id_format.len > 0 { add_cert(e.sp_name_id_formats, sp.name_id_format); }
    return ok;
}

// The service provider's metadata, signed when it has a key and `signed`
// is set; ERR_ENDPOINT for an endpoint URL sp_entity refuses.
fn sp_metadata(sp: const Sp&, signed: bool, out: u8[>..]&) -> i64 {
    var e = Entity { .. };
    if !sp_entity(sp, e) { return ERR_ENDPOINT; }
    if signed { return write_metadata_signed(e, sp.signer, out); }
    return write_metadata(e, out);
}

// --- AuthnRequest ------------------------------------------------------------------------

struct AuthnOptions {
    force_authn:    bool      = false,
    is_passive:     bool      = false,
    name_id_format: u8[..256] = [],    // else sp.name_id_format
    allow_create:   bool      = true,
    authn_context:  u8[..512] = [],    // a RequestedAuthnContext class (exact), "" none
}

// An AuthnRequest to the IdP's SingleSignOnService for the binding (the
// Response to come by POST to our ACS), signed when sp.sign_requests or
// the IdP wants signed requests. The caller keeps o.id to give
// process_response, and sends the browser to o.url (Redirect) or
// serves o.form (POST).
fn authn_request_with(sp: const Sp&, idp: const Entity&, binding: i64, relay_state: const u8[:], ao: const AuthnOptions&, o: Outgoing&) -> i64 {
    reset_outgoing(o);
    let dest = endpoint_location(idp, ROLE_IDP, EP_SSO, binding);
    if dest.len == 0 { return ERR_ENDPOINT; }
    let sign = sp.sign_requests || idp.want_authn_requests_signed;
    if sign && !sp.signer.has_key { return ERR_ARG; }
    var d = xml::Doc { .. };
    o.id.append(new_id());
    let root = start_message(d, "AuthnRequest", o.id, now_or(sp.now), dest, sp.entity_id);
    if root < 0 { return ERR_ARG; }
    if !xml::set_attr(d, root, "AssertionConsumerServiceURL", sp.acs_url) { return ERR_ARG; }
    xml::set_attr(d, root, "ProtocolBinding", URI_BINDING_POST);
    if ao.force_authn { xml::set_attr(d, root, "ForceAuthn", "true"); }
    if ao.is_passive { xml::set_attr(d, root, "IsPassive", "true"); }
    let fmt = if ao.name_id_format.len > 0 { ao.name_id_format[..] } else { sp.name_id_format[..] };
    let pol = xml::element(d, root, "samlp", "NameIDPolicy", SAMLP_NS);
    if fmt.len > 0 && !xml::set_attr(d, pol, "Format", fmt) { return ERR_ARG; }
    xml::set_attr(d, pol, "AllowCreate", if ao.allow_create { "true" } else { "false" });
    if ao.authn_context.len > 0 {
        let rac = xml::element(d, root, "samlp", "RequestedAuthnContext", SAMLP_NS);
        xml::set_attr(d, rac, "Comparison", "exact");
        if xml::text(d, xml::element(d, rac, "saml", "AuthnContextClassRef", SAML_NS), ao.authn_context[..]) < 0 { return ERR_ARG; }
    }
    return deliver(d, root, binding, dest, true, relay_state, sp.signer, sign, o);
}

fn authn_request(sp: const Sp&, idp: const Entity&, binding: i64, relay_state: const u8[:], o: Outgoing&) -> i64 {
    let ao = AuthnOptions { .. };
    return authn_request_with(sp, idp, binding, relay_state, ao, o);
}

// --- The assertion -----------------------------------------------------------------------

// An attribute: its NameFormat and FriendlyName, and its values, which are
// values[first .. first + count] (in Assertion.values, by iteration).
struct AttrInfo {
    name_format:   u8[..256] = [],
    friendly_name: u8[..256] = [],
    first:         i64       = 0,
    count:         i64       = 0,
}

// What a Response said, once process_response has checked it: the user
// (NameID), the session, the attributes, and what the replay check needs.
// On an error, code and message say why, and a refusal by the IdP leaves
// its status here.
root struct Assertion {
    code:                    i64           = OK,
    message:                 u8[>..]       = [],
    response_id:             u8[>..]       = [],
    in_response_to:          u8[>..]       = [],
    status:                  u8[>..]       = [],
    status2:                 u8[>..]       = [],
    status_message:          u8[>..]       = [],
    relay_state:             u8[>..]       = [],
    has_relay_state:         bool          = false,
    id:                      u8[>..]       = [],   // the assertion's ID: remember it until replay_until
    issuer:                  u8[>..]       = [],
    issue_instant:           i64           = 0,
    name_id:                 u8[>..]       = [],
    name_id_format:          u8[>..]       = [],
    name_qualifier:          u8[>..]       = [],
    sp_name_qualifier:       u8[>..]       = [],
    not_before:              i64           = 0,    // Conditions, seconds; 0: none
    not_on_or_after:         i64           = 0,
    confirmation_expires:    i64           = 0,    // the bearer SubjectConfirmationData's NotOnOrAfter
    replay_until:            i64           = 0,    // until when the ID must be remembered
    one_time_use:            bool          = false,
    authn_instant:           i64           = 0,
    session_index:           u8[>..]       = [],
    session_not_on_or_after: i64           = 0,    // 0: none
    authn_context:           u8[>..]       = [],   // AuthnContextClassRef
    response_signed:         bool          = false,
    assertion_signed:        bool          = false,
    encrypted:               bool          = false,
    attr_names:              u8[][>..]     = [],
    attr_info:               AttrInfo[>..] = [],
    values:                  u8[][>..]     = [],
}

fn reset_assertion(a: Assertion&) {
    a.code = OK; a.message.clear(); a.response_id.clear(); a.in_response_to.clear();
    a.status.clear(); a.status2.clear(); a.status_message.clear(); a.relay_state.clear(); a.has_relay_state = false;
    a.id.clear(); a.issuer.clear(); a.issue_instant = 0;
    a.name_id.clear(); a.name_id_format.clear(); a.name_qualifier.clear(); a.sp_name_qualifier.clear();
    a.not_before = 0; a.not_on_or_after = 0; a.confirmation_expires = 0; a.replay_until = 0; a.one_time_use = false;
    a.authn_instant = 0; a.session_index.clear(); a.session_not_on_or_after = 0; a.authn_context.clear();
    a.response_signed = false; a.assertion_signed = false; a.encrypted = false;
    a.attr_names.clear(); a.attr_info.clear(); a.values.clear();
}

fn fail_assertion(a: Assertion&, code: i64, why: const u8[:]) -> i64 { a.code = code; set_msg(a.message, why); return code; }

// F(name, info) for each attribute, in order.
fn each_attribute<F>(a: const Assertion&) {
    var i: i64 = 0;
    for n in a.attr_names { F(n, a.attr_info[i]); i++; }
}

// F(value) for each value of the attributes named `name` (Name, or
// FriendlyName when no attribute has that Name).
fn each_value<F>(a: const Assertion&, name: const u8[:]) {
    var by_name = false;
    for n in a.attr_names { if n == name { by_name = true; } }
    var i: i64 = 0;
    for n in a.attr_names {
        let info = a.attr_info[i];
        if (by_name && n == name) || (!by_name && info.friendly_name[..] == name) {
            var k: i64 = 0;
            for v in a.values {
                if k >= info.first && k < info.first + info.count { F(v); }
                k++;
            }
        }
        i++;
    }
}

// The first value of an attribute, and whether there is one.
fn attribute(a: const Assertion&, name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var found = false;
    each_value(a, name) { v => if !found { out.append(v); found = true; } };
    return out, found;
}

// How many values the attributes named `name` have.
fn value_count(a: const Assertion&, name: const u8[:]) -> i64 {
    var n: i64 = 0;
    each_value(a, name) { v => n++; };
    return n;
}

// --- Checking a Response -----------------------------------------------------------------

fn sp_decrypt_options(sp: const Sp&) -> xml::DecryptOptions {
    var o = xml::decrypt_options();
    o.allow_cbc = sp.allow_cbc;
    o.allow_rsa15 = sp.allow_rsa15;
    o.parse.max_size = sp.max_message;
    return o;
}

// Decrypts the one xenc:EncryptedData of a SAML wrapper (EncryptedAssertion,
// EncryptedID, EncryptedAttribute) in place; the one element of `local`
// in SAML's namespace it held, or -1 with an error.
fn decrypt_wrapper(sp: const Sp&, d: xml::Doc&, wrapper: i64, local: const u8[:]) -> i64, i64 {
    if !sp.has_enc_key && !sp.signer.has_key { return -1, ERR_DECRYPT; }
    if xml::count_children(d, wrapper, xml::XENC_NS, "EncryptedData") != 1 { return -1, ERR_MALFORMED; }
    let ed = xml::child(d, wrapper, xml::XENC_NS, "EncryptedData");
    let o = sp_decrypt_options(sp);
    let e = if sp.has_enc_key { xml::decrypt_replace(d, ed, sp.enc_key, o) } else { xml::decrypt_replace(d, ed, sp.signer.key, o) };
    if e == xml::ERR_ENC_ALGORITHM { return -1, ERR_ALGORITHM; }
    if e == xml::ERR_ENC_CONTENT || e == xml::ERR_ENC_MALFORMED { return -1, ERR_MALFORMED; }
    if e != xml::OK { return -1, ERR_DECRYPT; }
    var found: i64 = -1;
    var n = 0;
    var c = xml::first_element(d, wrapper);
    while c >= 0 {
        if !xml::is(d, c, xml::XENC_NS, "EncryptedKey") {
            n++;
            if xml::is(d, c, SAML_NS, local) { found = c; }
        }
        c = xml::next_element(d, c);
    }
    if n != 1 || found < 0 { return -1, ERR_MALFORMED; }
    return found, OK;
}

// A time attribute: its value, whether it is there, and false if it is
// there and not an xs:dateTime.
fn time_attr(d: const xml::Doc&, el: i64, name: const u8[:]) -> i64, bool, bool {
    let v, has = xml::attr(d, el, name);
    if !has { return 0, false, true; }
    let t, ok = parse_time(v);
    return t, true, ok;
}

// The checks of one bearer SubjectConfirmation; OK or why not.
fn check_confirmation(sp: const Sp&, d: const xml::Doc&, sc: i64, request_id: const u8[:], now: i64, a: Assertion&) -> i64 {
    let method, hasm = xml::attr(d, sc, "Method");
    if !hasm || method != CM_BEARER { return fail_assertion(a, ERR_CONFIRMATION, "not a bearer SubjectConfirmation"); }
    if xml::count_children(d, sc, SAML_NS, "SubjectConfirmationData") != 1 {
        return fail_assertion(a, ERR_CONFIRMATION, "a bearer SubjectConfirmation without SubjectConfirmationData");
    }
    let scd = xml::child(d, sc, SAML_NS, "SubjectConfirmationData");
    let noa, hasnoa, oknoa = time_attr(d, scd, "NotOnOrAfter");
    if !oknoa { return fail_assertion(a, ERR_TIME, "SubjectConfirmationData NotOnOrAfter is not a time"); }
    if !hasnoa { return fail_assertion(a, ERR_CONFIRMATION, "SubjectConfirmationData without NotOnOrAfter"); }
    if now - sp.clock_skew >= noa { return fail_assertion(a, ERR_EXPIRED, "the bearer confirmation has expired"); }
    let nb, hasnb, oknb = time_attr(d, scd, "NotBefore");
    if !oknb { return fail_assertion(a, ERR_TIME, "SubjectConfirmationData NotBefore is not a time"); }
    if hasnb && now + sp.clock_skew < nb { return fail_assertion(a, ERR_NOT_YET_VALID, "the bearer confirmation is not yet valid"); }
    let rcp, hasr = xml::attr(d, scd, "Recipient");
    if !hasr || rcp != sp.acs_url { return fail_assertion(a, ERR_RECIPIENT, "the bearer confirmation's Recipient is not our ACS URL"); }
    let irt, hasirt = xml::attr(d, scd, "InResponseTo");
    if request_id.len > 0 {
        if !hasirt || irt != request_id { return fail_assertion(a, ERR_IN_RESPONSE_TO, "the bearer confirmation's InResponseTo is not the request's ID"); }
    } else if hasirt {
        return fail_assertion(a, ERR_IN_RESPONSE_TO, "the bearer confirmation is in response to a request we do not know");
    }
    a.confirmation_expires = noa;
    return OK;
}

fn check_conditions(sp: const Sp&, d: const xml::Doc&, asrt: i64, now: i64, a: Assertion&) -> i64 {
    let n = xml::count_children(d, asrt, SAML_NS, "Conditions");
    if n != 1 { return fail_assertion(a, ERR_AUDIENCE, if n == 0 { "no Conditions (and so no AudienceRestriction)" } else { "two Conditions" }); }
    let cond = xml::child(d, asrt, SAML_NS, "Conditions");
    let nb, hasnb, oknb = time_attr(d, cond, "NotBefore");
    let noa, hasnoa, oknoa = time_attr(d, cond, "NotOnOrAfter");
    if !oknb || !oknoa { return fail_assertion(a, ERR_TIME, "Conditions NotBefore or NotOnOrAfter is not a time"); }
    if hasnb {
        a.not_before = nb;
        if now + sp.clock_skew < nb { return fail_assertion(a, ERR_NOT_YET_VALID, "the assertion is not yet valid"); }
    }
    if hasnoa {
        a.not_on_or_after = noa;
        if now - sp.clock_skew >= noa { return fail_assertion(a, ERR_EXPIRED, "the assertion has expired"); }
    }
    var restrictions = 0;
    var c = xml::first_element(d, cond);
    while c >= 0 {
        if xml::is(d, c, SAML_NS, "AudienceRestriction") {
            restrictions++;
            var ours = false;
            var au = xml::first_element(d, c);
            while au >= 0 {
                if !xml::is(d, au, SAML_NS, "Audience") { return fail_assertion(a, ERR_MALFORMED, "AudienceRestriction holds something other than Audience"); }
                var v: u8[>..] = [];
                xml::text_content(d, au, v);
                if trim(v) == sp.entity_id[..] { ours = true; }
                au = xml::next_element(d, au);
            }
            if !ours { return fail_assertion(a, ERR_AUDIENCE, "an AudienceRestriction without our entityID"); }
        } else if xml::is(d, c, SAML_NS, "OneTimeUse") {
            if a.one_time_use { return fail_assertion(a, ERR_CONDITION, "OneTimeUse twice"); }
            a.one_time_use = true;
        } else if xml::is(d, c, SAML_NS, "ProxyRestriction") {
            // Allows proxying; we are not one.
        } else {
            return fail_assertion(a, ERR_CONDITION, str("a condition not understood: ", xml::local_name(d, c)));
        }
        c = xml::next_element(d, c);
    }
    if restrictions == 0 { return fail_assertion(a, ERR_AUDIENCE, "no AudienceRestriction"); }
    return OK;
}

fn read_attribute(sp: const Sp&, d: const xml::Doc&, at: i64, a: Assertion&) -> i64 {
    let name, hasn = xml::attr(d, at, "Name");
    if !hasn { return fail_assertion(a, ERR_MALFORMED, "an Attribute without Name"); }
    let nf, hasnf = xml::attr(d, at, "NameFormat");
    let fr, hasfr = xml::attr(d, at, "FriendlyName");
    if nf.len > 256 || fr.len > 256 { return fail_assertion(a, ERR_LIMIT, "an Attribute's NameFormat or FriendlyName over 256 bytes"); }
    var info = AttrInfo { first: a.values.len, .. };
    info.name_format.append(if hasnf { nf } else { ATTRNAME_UNSPECIFIED });
    info.friendly_name.append(fr);
    var v = xml::first_element(d, at);
    while v >= 0 {
        if xml::is(d, v, SAML_NS, "AttributeValue") {
            var t: u8[>..] = [];
            xml::text_content(d, v, t);
            a.values.push(copy(t));
            info.count++;
        }
        v = xml::next_element(d, v);
    }
    var nm: u8[>..] = [];
    nm.append(name);
    a.attr_names.push(copy(nm));
    a.attr_info.push(info);
    return OK;
}

fn read_subject(sp: const Sp&, d: xml::Doc&, asrt: i64, request_id: const u8[:], now: i64, a: Assertion&) -> i64 {
    if xml::count_children(d, asrt, SAML_NS, "Subject") != 1 { return fail_assertion(a, ERR_SUBJECT, "not exactly one Subject"); }
    let subj = xml::child(d, asrt, SAML_NS, "Subject");
    let ids = xml::count_children(d, subj, SAML_NS, "NameID") + xml::count_children(d, subj, SAML_NS, "EncryptedID") +
              xml::count_children(d, subj, SAML_NS, "BaseID");
    if ids != 1 { return fail_assertion(a, ERR_SUBJECT, "not exactly one NameID"); }
    var nid = xml::child(d, subj, SAML_NS, "NameID");
    if nid < 0 {
        let eid = xml::child(d, subj, SAML_NS, "EncryptedID");
        if eid < 0 { return fail_assertion(a, ERR_SUBJECT, "a BaseID, not a NameID"); }
        let n, e = decrypt_wrapper(sp, d, eid, "NameID");
        if e != OK { return fail_assertion(a, e, "the EncryptedID does not decrypt to a NameID"); }
        nid = n;
    }
    // The whole text: a comment inside cannot cut it short.
    if has_elements(d, nid) { return fail_assertion(a, ERR_SUBJECT, "a NameID with elements in it"); }
    xml::text_content(d, nid, a.name_id);
    if a.name_id.len == 0 { return fail_assertion(a, ERR_SUBJECT, "an empty NameID"); }
    let f, hasf = xml::attr(d, nid, "Format");
    a.name_id_format.append(if hasf { f } else { NAMEID_UNSPECIFIED });
    let nq, hasnq = xml::attr(d, nid, "NameQualifier");
    if hasnq { a.name_qualifier.append(nq); }
    let spq, hasspq = xml::attr(d, nid, "SPNameQualifier");
    if hasspq { a.sp_name_qualifier.append(spq); }
    // A bearer confirmation that holds.
    var any = false;
    var first_err: i64 = ERR_CONFIRMATION;
    var why: u8[>..] = [];
    format(why, "no bearer SubjectConfirmation");
    var c = xml::first_element(d, subj);
    while c >= 0 && !any {
        if xml::is(d, c, SAML_NS, "SubjectConfirmation") {
            let e = check_confirmation(sp, d, c, request_id, now, a);
            if e == OK { any = true; }
            else if first_err == ERR_CONFIRMATION || e != ERR_CONFIRMATION { first_err = e; why.clear(); why.append(a.message); }
        }
        c = xml::next_element(d, c);
    }
    if !any { return fail_assertion(a, first_err, why); }
    a.message.clear();
    a.code = OK;
    return OK;
}

// Checks a Response that came by the POST binding, as the header says,
// against the IdP's metadata, for the request whose ID the caller kept
// (empty for an IdP-initiated response, if sp.allow_idp_initiated). OK
// with a filled in, or an error with a.code and a.message saying why.
// The caller must still check that a.id has not been seen before, and
// remember it until a.replay_until: process_response_replay does that
// through a block.
fn process_response(sp: const Sp&, idp: const Entity&, m: const Received&, request_id: const u8[:], a: Assertion&) -> i64 {
    reset_assertion(a);
    if m.has_relay_state { a.has_relay_state = true; a.relay_state.append(m.relay_state); }
    if m.is_request { return fail_assertion(a, ERR_BINDING, "a SAMLRequest, not a SAMLResponse"); }
    if m.binding != BINDING_POST { return fail_assertion(a, ERR_BINDING, "a Response must come by the POST binding"); }
    let now = now_or(sp.now);
    var d = xml::Doc { .. };
    var why: u8[>..] = [];
    let pe = parse_saml(d, m.xml, sp.max_message, why);
    if pe != OK { return fail_assertion(a, pe, why); }
    var resp = xml::root_element(d);
    if !xml::is(d, resp, SAMLP_NS, "Response") { return fail_assertion(a, ERR_MALFORMED, "not a samlp:Response"); }
    var vo = xml::verify_options();
    vo.allow_sha1 = sp.allow_sha1;
    // The Response's signature: from here on, read what it covers.
    if xml::count_children(d, resp, xml::DSIG_NS, "Signature") > 0 {
        let v = verify_by(d, resp, idp, ROLE_IDP, vo);
        if v.code != xml::OK { return fail_assertion(a, dsig_error(v.code), str("the Response's signature: ", v.message)); }
        resp = if v.refs[0] == 0 { xml::root_element(d) } else { v.refs[0] };
        a.response_signed = true;
    }
    if sp.want_response_signed && !a.response_signed { return fail_assertion(a, ERR_NOT_SIGNED, "the Response is not signed"); }
    let ver, hasv = xml::attr(d, resp, "Version");
    if !hasv || ver != "2.0" { return fail_assertion(a, ERR_VERSION, "Version is not 2.0"); }
    let rid, hasrid = xml::attr(d, resp, "ID");
    if !hasrid || rid.len == 0 { return fail_assertion(a, ERR_MALFORMED, "the Response has no ID"); }
    a.response_id.append(rid);
    let rii, hasrii, okrii = time_attr(d, resp, "IssueInstant");
    if !hasrii || !okrii { return fail_assertion(a, ERR_TIME, "the Response's IssueInstant is missing or not a time"); }
    if rii > now + sp.clock_skew { return fail_assertion(a, ERR_NOT_YET_VALID, "the Response's IssueInstant is ahead of the clock"); }
    if xml::count_children(d, resp, SAML_NS, "Issuer") > 0 {
        var iss: u8[>..] = [];
        if !issuer_of(d, resp, iss) { return fail_assertion(a, ERR_ISSUER, "a malformed Issuer"); }
        if iss[..] != idp.entity_id[..] { return fail_assertion(a, ERR_ISSUER, "the Response's Issuer is not the IdP"); }
    }
    let dest, hasdest = xml::attr(d, resp, "Destination");
    if hasdest && dest != sp.acs_url { return fail_assertion(a, ERR_DESTINATION, "the Response's Destination is not our ACS URL"); }
    if !hasdest && a.response_signed { return fail_assertion(a, ERR_DESTINATION, "a signed Response without Destination"); }
    let irt, hasirt = xml::attr(d, resp, "InResponseTo");
    if hasirt { a.in_response_to.append(irt); }
    if request_id.len > 0 {
        if !hasirt || irt != request_id { return fail_assertion(a, ERR_IN_RESPONSE_TO, "InResponseTo is not the request's ID"); }
    } else {
        if hasirt { return fail_assertion(a, ERR_IN_RESPONSE_TO, "in response to a request we do not know"); }
        if !sp.allow_idp_initiated { return fail_assertion(a, ERR_UNSOLICITED, "an IdP-initiated Response, not allowed"); }
    }
    // Status.
    var st = Message { .. };
    if !read_status(d, resp, st) { return fail_assertion(a, ERR_MALFORMED, "no Status"); }
    a.status.append(st.status);
    a.status2.append(st.status2);
    a.status_message.append(st.status_message);
    if st.status[..] != STATUS_SUCCESS { return fail_assertion(a, ERR_STATUS, "the IdP did not authenticate the user"); }
    // Exactly one assertion, a direct child of the (verified) Response.
    let plain = xml::count_children(d, resp, SAML_NS, "Assertion");
    let enc = xml::count_children(d, resp, SAML_NS, "EncryptedAssertion");
    if plain + enc != 1 { return fail_assertion(a, ERR_ASSERTION, "not exactly one Assertion"); }
    var asrt: i64 = -1;
    if enc == 1 {
        let n, e = decrypt_wrapper(sp, d, xml::child(d, resp, SAML_NS, "EncryptedAssertion"), "Assertion");
        if e != OK { return fail_assertion(a, e, "the EncryptedAssertion does not decrypt to an Assertion"); }
        asrt = n;
        a.encrypted = true;
    } else {
        if sp.require_encrypted { return fail_assertion(a, ERR_NOT_ENCRYPTED, "the assertion is not encrypted"); }
        asrt = xml::child(d, resp, SAML_NS, "Assertion");
    }
    // The assertion's signature: from here on, read what it covers.
    if xml::count_children(d, asrt, xml::DSIG_NS, "Signature") > 0 {
        let v = verify_by(d, asrt, idp, ROLE_IDP, vo);
        if v.code != xml::OK { return fail_assertion(a, dsig_error(v.code), str("the Assertion's signature: ", v.message)); }
        asrt = v.refs[0];
        a.assertion_signed = true;
    }
    if !a.response_signed && !a.assertion_signed { return fail_assertion(a, ERR_NOT_SIGNED, "neither the Response nor the Assertion is signed"); }
    if sp.want_assertions_signed && !a.assertion_signed { return fail_assertion(a, ERR_NOT_SIGNED, "the Assertion is not signed"); }
    if !xml::is(d, asrt, SAML_NS, "Assertion") { return fail_assertion(a, ERR_ASSERTION, "the signed element is not an Assertion"); }
    // The assertion itself.
    let aver, hasav = xml::attr(d, asrt, "Version");
    if !hasav || aver != "2.0" { return fail_assertion(a, ERR_VERSION, "the Assertion's Version is not 2.0"); }
    let aid, hasaid = xml::attr(d, asrt, "ID");
    if !hasaid || aid.len == 0 { return fail_assertion(a, ERR_MALFORMED, "the Assertion has no ID"); }
    a.id.append(aid);
    let aii, hasaii, okaii = time_attr(d, asrt, "IssueInstant");
    if !hasaii || !okaii { return fail_assertion(a, ERR_TIME, "the Assertion's IssueInstant is missing or not a time"); }
    if aii > now + sp.clock_skew { return fail_assertion(a, ERR_NOT_YET_VALID, "the Assertion's IssueInstant is ahead of the clock"); }
    a.issue_instant = aii;
    if !issuer_of(d, asrt, a.issuer) { return fail_assertion(a, ERR_ISSUER, "the Assertion has no Issuer, or a malformed one"); }
    if a.issuer[..] != idp.entity_id[..] { return fail_assertion(a, ERR_ISSUER, "the Assertion's Issuer is not the IdP"); }
    let se = read_subject(sp, d, asrt, request_id, now, a);
    if se != OK { return se; }
    let ce = check_conditions(sp, d, asrt, now, a);
    if ce != OK { return ce; }
    // The AuthnStatement (the first; the profile asks for at least one).
    let ast = xml::child(d, asrt, SAML_NS, "AuthnStatement");
    if ast < 0 { return fail_assertion(a, ERR_SESSION, "no AuthnStatement"); }
    let ai, hasai, okai = time_attr(d, ast, "AuthnInstant");
    if !hasai || !okai { return fail_assertion(a, ERR_TIME, "AuthnInstant is missing or not a time"); }
    a.authn_instant = ai;
    let si, hassi = xml::attr(d, ast, "SessionIndex");
    if hassi { a.session_index.append(si); }
    let snoa, hassnoa, oksnoa = time_attr(d, ast, "SessionNotOnOrAfter");
    if !oksnoa { return fail_assertion(a, ERR_TIME, "SessionNotOnOrAfter is not a time"); }
    if hassnoa {
        a.session_not_on_or_after = snoa;
        if now - sp.clock_skew >= snoa { return fail_assertion(a, ERR_SESSION, "the session has expired (SessionNotOnOrAfter)"); }
    }
    let ac = xml::child(d, ast, SAML_NS, "AuthnContext");
    if ac >= 0 {
        let cr = xml::child(d, ac, SAML_NS, "AuthnContextClassRef");
        if cr >= 0 { xml::text_content(d, cr, a.authn_context); }
    }
    // Attributes.
    var s = xml::first_element(d, asrt);
    while s >= 0 {
        if xml::is(d, s, SAML_NS, "AttributeStatement") {
            var at = xml::first_element(d, s);
            while at >= 0 {
                var el = at;
                let nx = xml::next_element(d, at);
                if xml::is(d, at, SAML_NS, "EncryptedAttribute") {
                    let n, e = decrypt_wrapper(sp, d, at, "Attribute");
                    if e != OK { return fail_assertion(a, e, "an EncryptedAttribute does not decrypt to an Attribute"); }
                    el = n;
                }
                if xml::is(d, el, SAML_NS, "Attribute") {
                    let e = read_attribute(sp, d, el, a);
                    if e != OK { return e; }
                }
                at = nx;
            }
        }
        s = xml::next_element(d, s);
    }
    // How long the ID must be remembered: as long as the assertion could
    // still be taken, the clock skew included.
    var until = a.confirmation_expires;
    if a.not_on_or_after != 0 && a.not_on_or_after < until { until = a.not_on_or_after; }
    a.replay_until = until + sp.clock_skew;
    return OK;
}

// process_response, and then the replay check: F(id, until) says whether
// the assertion ID is new (and remembers it until `until`, seconds);
// ERR_REPLAY when it is not.
fn process_response_replay<F>(sp: const Sp&, idp: const Entity&, m: const Received&, request_id: const u8[:], a: Assertion&) -> i64 {
    let e = process_response(sp, idp, m, request_id, a);
    if e != OK { return e; }
    if !F(a.id[..], a.replay_until) { return fail_assertion(a, ERR_REPLAY, "the assertion was seen before"); }
    return OK;
}

// --- Single Logout -----------------------------------------------------------------------

// A LogoutRequest to the IdP for the user of a (or any NameID and
// SessionIndex in who), signed with the SP's key when it has one.
fn sp_logout_request(sp: const Sp&, idp: const Entity&, binding: i64, who: const LogoutSubject&, relay_state: const u8[:], o: Outgoing&) -> i64 {
    let sign = sp.sign_logout && sp.signer.has_key;
    return logout_request_to(sp.entity_id, sp.signer, sign, idp, ROLE_IDP, binding, who, now_or(sp.now), 300, relay_state, o);
}

// Whom an assertion was about, for a LogoutRequest.
fn logout_subject_of(a: const Assertion&) -> LogoutSubject, bool {
    var w = LogoutSubject { .. };
    if a.name_id.len > 1024 || a.name_id_format.len > 256 || a.name_qualifier.len > 1024 || a.sp_name_qualifier.len > 1024 ||
       a.session_index.len > 256 {
        return w, false;
    }
    w.name_id.append(a.name_id);
    w.format.append(a.name_id_format);
    w.name_qualifier.append(a.name_qualifier);
    w.sp_name_qualifier.append(a.sp_name_qualifier);
    w.session_index.append(a.session_index);
    return w, true;
}

// A LogoutRequest from the IdP to our SLO URL, checked (signed: the IdP's
// key, by either binding, unless require_signed is false).
fn sp_read_logout_request(sp: const Sp&, idp: const Entity&, m: const Received&, r: Message&) -> i64 {
    let c = sp_checks(sp, true);
    return read_logout_request(m, idp, ROLE_IDP, sp.slo_url, c, r);
}

// sp_read_logout_request, and then the replay check: F(id, until) says
// whether the LogoutRequest's ID is new (and remembers it until `until`,
// seconds); ERR_REPLAY when it is not.
fn sp_read_logout_request_replay<F>(sp: const Sp&, idp: const Entity&, m: const Received&, r: Message&) -> i64 {
    let c = sp_checks(sp, true);
    return read_logout_request_replay(m, idp, ROLE_IDP, sp.slo_url, c, r) { id, until => F(id, until) };
}

// The LogoutResponse to it.
fn sp_logout_response(sp: const Sp&, idp: const Entity&, binding: i64, in_response_to: const u8[:], status: const u8[:],
                      relay_state: const u8[:], o: Outgoing&) -> i64 {
    let sign = sp.sign_logout && sp.signer.has_key;
    return logout_response_to(sp.entity_id, sp.signer, sign, idp, ROLE_IDP, binding, in_response_to, status, "", now_or(sp.now),
                              relay_state, o);
}

// The IdP's LogoutResponse to our LogoutRequest (whose ID the caller kept).
fn sp_read_logout_response(sp: const Sp&, idp: const Entity&, m: const Received&, request_id: const u8[:], r: Message&) -> i64 {
    let c = sp_checks(sp, true);
    return read_logout_response(m, idp, ROLE_IDP, sp.slo_url, request_id, c, r);
}
