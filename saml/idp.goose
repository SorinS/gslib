// saml.idp: a SAML 2.0 identity provider, enough to run one for tests and
// small deployments: AuthnRequests read and checked (signature by either
// binding, Destination, the ACS URL against the service provider's
// metadata), Responses built with a signed assertion, a signed Response,
// or both, the assertion encrypted to the service provider's encryption
// certificate when asked (AES-256-GCM, RSA-OAEP), sent by the POST
// binding; IdP-initiated Responses; error Responses; Single Logout; and
// the IdP's metadata. Who the user is, and checking their password, is
// the caller's: a Login says what to assert.

namespace saml;

import std;
import encoding.xml;
import encoding.xml.dsig;
import encoding.xml.enc;
import crypto.x509;
import crypto.x509.keys;
import saml.metadata;
import saml.logout;

// An identity provider. A root struct: `var idp = saml::Idp { .. };`.
root struct Idp {
    entity_id:                  u8[>..]   = [],
    sso_url:                    u8[>..]   = [],    // SingleSignOnService (both bindings)
    slo_url:                    u8[>..]   = [],    // SingleLogoutService (both bindings), "" for none
    signer:                     Signer    = Signer { .. },
    sign_assertion:             bool      = true,
    sign_response:              bool      = false,
    encrypt:                    bool      = false, // encrypt assertions to the SP's encryption certificate
    enc_alg:                    i64       = xml::ENC_AES256_GCM,
    want_authn_requests_signed: bool      = false, // require signed AuthnRequests (and say so in metadata)
    sign_logout:                bool      = true,
    assertion_lifetime:         i64       = 300,   // seconds the assertion and its confirmation are good for
    session_lifetime:           i64       = 28800, // SessionNotOnOrAfter, seconds after now; 0: none
    allow_sha1:                 bool      = false,
    clock_skew:                 i64       = 120,
    max_message:                i64       = DEFAULT_MAX_MESSAGE,
    name_id_formats:            u8[][>..] = [],    // published in metadata
    now:                        i64       = 0,     // seconds; 0: the clock
}

fn idp_set_key(idp: Idp&, key: const x509::PrivateKey&, cert_der: const u8[:]) {
    idp.signer.has_key = true;
    idp.signer.key = key;
    idp.signer.cert_der.clear();
    idp.signer.cert_der.append(cert_der);
}

fn idp_checks(idp: const Idp&, require_signed: bool) -> Checks {
    Checks { now: now_or(idp.now), skew: idp.clock_skew, allow_sha1: idp.allow_sha1, require_signed: require_signed, max: idp.max_message }
}

// The identity provider's metadata as an Entity.
fn idp_entity(idp: const Idp&, e: Entity&) {
    reset_entity(e);
    e.entity_id.append(idp.entity_id);
    e.is_idp = true;
    e.want_authn_requests_signed = idp.want_authn_requests_signed;
    add_endpoint(e, ROLE_IDP, EP_SSO, BINDING_REDIRECT, idp.sso_url);
    add_endpoint(e, ROLE_IDP, EP_SSO, BINDING_POST, idp.sso_url);
    if idp.slo_url.len > 0 {
        add_endpoint(e, ROLE_IDP, EP_SLO, BINDING_REDIRECT, idp.slo_url);
        add_endpoint(e, ROLE_IDP, EP_SLO, BINDING_POST, idp.slo_url);
    }
    if idp.signer.cert_der.len > 0 { add_cert(e.idp_signing, idp.signer.cert_der); }
    for f in idp.name_id_formats { add_cert(e.idp_name_id_formats, f); }
}

// The identity provider's metadata, signed when `signed` is set.
fn idp_metadata(idp: const Idp&, signed: bool, out: u8[>..]&) -> i64 {
    var e = Entity { .. };
    idp_entity(idp, e);
    if signed { return write_metadata_signed(e, idp.signer, out); }
    return write_metadata(e, out);
}

// --- AuthnRequest ------------------------------------------------------------------------

// Reads an AuthnRequest that came to our SSO URL from the service provider
// whose metadata is sp (peek_issuer says which): check_message's checks,
// signed when we or the SP's metadata say so; then the ACS: the
// AssertionConsumerServiceURL (exactly one of the SP's in its metadata),
// or the AssertionConsumerServiceIndex, or the SP's default; the
// ProtocolBinding (POST: the only one we answer by); NameIDPolicy,
// ForceAuthn, IsPassive and RequestedAuthnContext into r.
fn idp_read_authn_request(idp: const Idp&, sp: const Entity&, m: const Received&, r: Message&) -> i64 {
    reset_message(r);
    if !m.is_request { return fail_message(r, ERR_BINDING, "not a SAMLRequest"); }
    if !sp.is_sp { return fail_message(r, ERR_ARG, "the metadata has no SPSSODescriptor"); }
    let c = idp_checks(idp, idp.want_authn_requests_signed || sp.authn_requests_signed);
    var d = xml::Doc { .. };
    if parse_received(d, m, c, r) < 0 { return r.code; }
    let root = check_message(d, m, "AuthnRequest", sp, ROLE_SP, idp.sso_url, c, r);
    if root < 0 { return r.code; }
    let pb, haspb = xml::attr(d, root, "ProtocolBinding");
    if haspb && pb != URI_BINDING_POST { return fail_message(r, ERR_BINDING, "a ProtocolBinding other than HTTP-POST"); }
    let url, hasurl = xml::attr(d, root, "AssertionConsumerServiceURL");
    let ix, hasix = xml::attr(d, root, "AssertionConsumerServiceIndex");
    if hasurl && hasix { return fail_message(r, ERR_MALFORMED, "both AssertionConsumerServiceURL and AssertionConsumerServiceIndex"); }
    var ep: i64 = -1;
    if hasurl {
        ep = acs_by_location(sp, url, BINDING_POST);
        if ep < 0 { return fail_message(r, ERR_ENDPOINT, "the AssertionConsumerServiceURL is not an HTTP-POST ACS of the SP's metadata"); }
    } else if hasix {
        let v, okv = parse_int(ix);
        if !okv { return fail_message(r, ERR_MALFORMED, "AssertionConsumerServiceIndex is not a number"); }
        ep = acs_by_index(sp, v);
        if ep < 0 || sp.endpoints[ep].binding != BINDING_POST { return fail_message(r, ERR_ENDPOINT, "no HTTP-POST ACS with that index"); }
    } else {
        ep = find_endpoint(sp, ROLE_SP, EP_ACS, BINDING_POST);
        if ep < 0 { return fail_message(r, ERR_ENDPOINT, "the SP has no HTTP-POST ACS"); }
    }
    r.acs_url.append(sp.endpoints[ep].location[..]);
    r.acs_index = sp.endpoints[ep].index;
    let fa, okfa = bool_attr(d, root, "ForceAuthn");
    let ip, okip = bool_attr(d, root, "IsPassive");
    if !okfa || !okip { return fail_message(r, ERR_MALFORMED, "ForceAuthn or IsPassive is not a boolean"); }
    r.force_authn = fa;
    r.is_passive = ip;
    let pol = xml::child(d, root, SAMLP_NS, "NameIDPolicy");
    if pol >= 0 {
        let f, hasf = xml::attr(d, pol, "Format");
        if hasf { r.name_id_policy.append(f); }
        let ac, okac = bool_attr(d, pol, "AllowCreate");
        if !okac { return fail_message(r, ERR_MALFORMED, "AllowCreate is not a boolean"); }
        r.allow_create = ac;
    }
    let rac = xml::child(d, root, SAMLP_NS, "RequestedAuthnContext");
    if rac >= 0 {
        var cr = xml::first_element(d, rac);
        while cr >= 0 {
            if xml::is(d, cr, SAML_NS, "AuthnContextClassRef") {
                var v: u8[>..] = [];
                xml::text_content(d, cr, v);
                r.authn_context.push(copy(v));
            }
            cr = xml::next_element(d, cr);
        }
    }
    return OK;
}

// --- The Response ------------------------------------------------------------------------

// What the IdP asserts about the user: the NameID, the session, how they
// authenticated, and attributes. Attributes go in pairs, name and value,
// by add_value; consecutive values of one name make one multi-valued
// Attribute. A root struct: `var user = saml::Login { .. };`.
root struct Login {
    name_id:           u8[>..]   = [],
    name_id_format:    u8[>..]   = [],    // "" : unspecified
    sp_name_qualifier: u8[>..]   = [],
    session_index:     u8[>..]   = [],    // "" : a fresh one
    authn_context:     u8[>..]   = [],    // "" : PasswordProtectedTransport
    authn_instant:     i64       = 0,     // 0 : now
    attr_name_format:  u8[>..]   = [],    // "" : uri
    attrs:             u8[][>..] = [],    // name, value, name, value, ...
}

// One more value of the attribute `name`.
fn add_value(l: Login&, name: const u8[:], value: const u8[:]) {
    var n: u8[>..] = [];
    n.append(name);
    l.attrs.push(copy(n));
    var v: u8[>..] = [];
    v.append(value);
    l.attrs.push(copy(v));
}

fn build_assertion(idp: const Idp&, d: xml::Doc&, resp: i64, sp: const Entity&, acs_url: const u8[:], in_response_to: const u8[:],
                   user: const Login&, now: i64) -> i64 {
    let a = xml::element(d, resp, "saml", "Assertion", SAML_NS);
    xml::set_attr(d, a, "ID", new_id());
    xml::set_attr(d, a, "Version", "2.0");
    xml::set_attr(d, a, "IssueInstant", time_text(now));
    xml::text(d, xml::element(d, a, "saml", "Issuer", SAML_NS), idp.entity_id);
    let subj = xml::element(d, a, "saml", "Subject", SAML_NS);
    let fmt = if user.name_id_format.len > 0 { user.name_id_format[..] } else { NAMEID_UNSPECIFIED };
    if !add_name_id(d, subj, user.name_id, fmt, "", user.sp_name_qualifier) { return -1; }
    let sc = xml::element(d, subj, "saml", "SubjectConfirmation", SAML_NS);
    xml::set_attr(d, sc, "Method", CM_BEARER);
    let scd = xml::element(d, sc, "saml", "SubjectConfirmationData", SAML_NS);
    xml::set_attr(d, scd, "NotOnOrAfter", time_text(now + idp.assertion_lifetime));
    if !xml::set_attr(d, scd, "Recipient", acs_url) { return -1; }
    if in_response_to.len > 0 && !xml::set_attr(d, scd, "InResponseTo", in_response_to) { return -1; }
    let cond = xml::element(d, a, "saml", "Conditions", SAML_NS);
    xml::set_attr(d, cond, "NotBefore", time_text(now - 60));
    xml::set_attr(d, cond, "NotOnOrAfter", time_text(now + idp.assertion_lifetime));
    let ar = xml::element(d, cond, "saml", "AudienceRestriction", SAML_NS);
    if xml::text(d, xml::element(d, ar, "saml", "Audience", SAML_NS), sp.entity_id) < 0 { return -1; }
    let ast = xml::element(d, a, "saml", "AuthnStatement", SAML_NS);
    xml::set_attr(d, ast, "AuthnInstant", time_text(if user.authn_instant != 0 { user.authn_instant } else { now }));
    if user.session_index.len > 0 {
        if !xml::set_attr(d, ast, "SessionIndex", user.session_index) { return -1; }
    } else {
        xml::set_attr(d, ast, "SessionIndex", new_id());
    }
    if idp.session_lifetime > 0 { xml::set_attr(d, ast, "SessionNotOnOrAfter", time_text(now + idp.session_lifetime)); }
    let ac = xml::element(d, ast, "saml", "AuthnContext", SAML_NS);
    let acr = if user.authn_context.len > 0 { user.authn_context[..] } else { AC_PASSWORD_PROTECTED };
    if xml::text(d, xml::element(d, ac, "saml", "AuthnContextClassRef", SAML_NS), acr) < 0 { return -1; }
    if user.attrs.len > 0 {
        let st = xml::element(d, a, "saml", "AttributeStatement", SAML_NS);
        let nf = if user.attr_name_format.len > 0 { user.attr_name_format[..] } else { ATTRNAME_URI };
        var cur: i64 = -1;
        var last: u8[>..] = [];
        var is_name = true;
        var name: u8[>..] = [];
        for x in user.attrs {
            if is_name {
                name.clear();
                name.append(x);
            } else {
                if cur < 0 || name[..] != last[..] {
                    cur = xml::element(d, st, "saml", "Attribute", SAML_NS);
                    if !xml::set_attr(d, cur, "Name", name) { return -1; }
                    xml::set_attr(d, cur, "NameFormat", nf);
                    last.clear();
                    last.append(name);
                }
                if xml::text(d, xml::element(d, cur, "saml", "AttributeValue", SAML_NS), x) < 0 { return -1; }
            }
            is_name = !is_name;
        }
    }
    return a;
}

// A Response to acs_url (InResponseTo the request when there is one) with
// an assertion about user, signed and encrypted as idp says, put in o for
// the POST binding.
fn build_response(idp: const Idp&, sp: const Entity&, acs_url: const u8[:], in_response_to: const u8[:], user: const Login&,
                  relay_state: const u8[:], o: Outgoing&) -> i64 {
    reset_outgoing(o);
    if (idp.sign_assertion || idp.sign_response) && !idp.signer.has_key { return ERR_ARG; }
    if user.name_id.len == 0 { return ERR_ARG; }
    let now = now_or(idp.now);
    var d = xml::Doc { .. };
    o.id.append(new_id());
    let resp = start_message(d, "Response", o.id, now, acs_url, idp.entity_id);
    if resp < 0 { return ERR_ARG; }
    if in_response_to.len > 0 && !xml::set_attr(d, resp, "InResponseTo", in_response_to) { return ERR_ARG; }
    add_status(d, resp, STATUS_SUCCESS, "", "");
    let a = build_assertion(idp, d, resp, sp, acs_url, in_response_to, user, now);
    if a < 0 { return ERR_ARG; }
    if idp.sign_assertion {
        let e = sign_element(d, a, idp.signer);
        if e != OK { return e; }
    }
    if idp.encrypt {
        // The first encryption certificate of the SP's metadata.
        var cert_der: u8[>..] = [];
        each_encryption(sp, ROLE_SP) { der => if cert_der.len == 0 { cert_der.append(der); } };
        if cert_der.len == 0 { return ERR_ARG; }
        let cert, ce = x509::parse(cert_der);
        if ce != x509::OK { return ERR_ARG; }
        let ea = xml::insert_element(d, resp, a, "saml", "EncryptedAssertion", SAML_NS);
        xml::move_to(d, a, ea, -1);
        var eo = xml::encrypt_options();
        eo.alg = idp.enc_alg;
        let ed, ee = xml::encrypt_element(d, a, cert, eo);
        if ee != xml::OK { return ERR_ARG; }
    }
    if idp.sign_response {
        let e = sign_element(d, resp, idp.signer);
        if e != OK { return e; }
    }
    return deliver(d, resp, BINDING_POST, acs_url, false, relay_state, idp.signer, false, o);
}

// The Response to an AuthnRequest read by idp_read_authn_request.
fn idp_response(idp: const Idp&, sp: const Entity&, req: const Message&, user: const Login&, o: Outgoing&) -> i64 {
    return build_response(idp, sp, req.acs_url, req.id, user, req.relay_state, o);
}

// An IdP-initiated (unsolicited) Response to the SP's default HTTP-POST ACS.
fn idp_unsolicited_response(idp: const Idp&, sp: const Entity&, user: const Login&, relay_state: const u8[:], o: Outgoing&) -> i64 {
    let acs = endpoint_location(sp, ROLE_SP, EP_ACS, BINDING_POST);
    if acs.len == 0 { return ERR_ENDPOINT; }
    return build_response(idp, sp, acs, "", user, relay_state, o);
}

// A Response that refuses the request: status (STATUS_REQUESTER,
// STATUS_RESPONDER) and a second-level code (STATUS_AUTHN_FAILED,
// STATUS_NO_PASSIVE, ...), with no assertion; signed when idp signs
// Responses or assertions.
fn idp_error_response(idp: const Idp&, sp: const Entity&, req: const Message&, status: const u8[:], status2: const u8[:],
                      message: const u8[:], o: Outgoing&) -> i64 {
    reset_outgoing(o);
    let now = now_or(idp.now);
    var d = xml::Doc { .. };
    o.id.append(new_id());
    let resp = start_message(d, "Response", o.id, now, req.acs_url, idp.entity_id);
    if resp < 0 { return ERR_ARG; }
    if req.id.len > 0 && !xml::set_attr(d, resp, "InResponseTo", req.id) { return ERR_ARG; }
    if !add_status(d, resp, status, status2, message) { return ERR_ARG; }
    let sign = (idp.sign_response || idp.sign_assertion) && idp.signer.has_key;
    if sign {
        let e = sign_element(d, resp, idp.signer);
        if e != OK { return e; }
    }
    return deliver(d, resp, BINDING_POST, req.acs_url, false, req.relay_state, idp.signer, false, o);
}

// --- Single Logout -----------------------------------------------------------------------

fn idp_logout_request(idp: const Idp&, sp: const Entity&, binding: i64, who: const LogoutSubject&, relay_state: const u8[:], o: Outgoing&) -> i64 {
    let sign = idp.sign_logout && idp.signer.has_key;
    return logout_request_to(idp.entity_id, idp.signer, sign, sp, ROLE_SP, binding, who, now_or(idp.now), 300, relay_state, o);
}

// A LogoutRequest from the SP to our SLO URL, checked; it must be signed.
fn idp_read_logout_request(idp: const Idp&, sp: const Entity&, m: const Received&, r: Message&) -> i64 {
    let c = idp_checks(idp, true);
    return read_logout_request(m, sp, ROLE_SP, idp.slo_url, c, r);
}

fn idp_logout_response(idp: const Idp&, sp: const Entity&, binding: i64, in_response_to: const u8[:], status: const u8[:],
                       relay_state: const u8[:], o: Outgoing&) -> i64 {
    let sign = idp.sign_logout && idp.signer.has_key;
    return logout_response_to(idp.entity_id, idp.signer, sign, sp, ROLE_SP, binding, in_response_to, status, "", now_or(idp.now),
                              relay_state, o);
}

fn idp_read_logout_response(idp: const Idp&, sp: const Entity&, m: const Received&, request_id: const u8[:], r: Message&) -> i64 {
    let c = idp_checks(idp, true);
    return read_logout_response(m, sp, ROLE_SP, idp.slo_url, request_id, c, r);
}
