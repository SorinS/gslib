// saml.logout: what both sides share for the protocol messages that are
// not Responses to AuthnRequests: checking one that came in (its version,
// ID, issuer, destination and signature, by either binding), and Single
// Logout (saml-core §3.7, saml-profiles §4.4): LogoutRequest and
// LogoutResponse, made and read by a service provider or an identity
// provider alike. saml/sp.goose and saml/idp.goose wrap these with their
// own settings.

namespace saml;

import std;
import encoding.xml;
import encoding.xml.dsig;
import crypto.x509;
import saml.metadata;

// What reading a message that came in may take: the clock (seconds), the
// skew allowed, SHA-1, whether it must be signed, the endpoint it must be
// addressed to, and the size limit.
struct Checks {
    now:            i64  = 0,
    skew:           i64  = 120,
    allow_sha1:     bool = false,
    require_signed: bool = false,
    max:            i64  = DEFAULT_MAX_MESSAGE,
}

// What a message said and what its checks found: the code and why, and
// the values read (from signed nodes when it was signed).
root struct Message {
    code:              i64       = OK,
    message:           u8[>..]   = [],
    kind:              u8[>..]   = [],   // the root's local name: AuthnRequest, LogoutRequest, ...
    id:                u8[>..]   = [],
    issuer:            u8[>..]   = [],
    issue_instant:     i64       = 0,
    destination:       u8[>..]   = [],
    in_response_to:    u8[>..]   = [],
    signed:            bool      = false,
    binding:           i64       = 0,
    has_relay_state:   bool      = false,
    relay_state:       u8[>..]   = [],
    // A StatusResponse's status.
    status:            u8[>..]   = [],
    status2:           u8[>..]   = [],
    status_message:    u8[>..]   = [],
    // An AuthnRequest's.
    acs_url:           u8[>..]   = [],   // AssertionConsumerServiceURL, or the metadata's by index or default
    acs_binding:       i64       = BINDING_POST,
    acs_index:         i64       = -1,
    force_authn:       bool      = false,
    is_passive:        bool      = false,
    name_id_policy:    u8[>..]   = [],   // NameIDPolicy Format
    allow_create:      bool      = false,
    authn_context:     u8[][>..] = [],   // RequestedAuthnContext's AuthnContextClassRefs
    // A LogoutRequest's.
    name_id:           u8[>..]   = [],
    name_id_format:    u8[>..]   = [],
    name_qualifier:    u8[>..]   = [],
    sp_name_qualifier: u8[>..]   = [],
    session_indexes:   u8[][>..] = [],
    not_on_or_after:   i64       = 0,
}

fn reset_message(r: Message&) {
    r.code = OK;
    r.message.clear(); r.kind.clear(); r.id.clear(); r.issuer.clear(); r.issue_instant = 0;
    r.destination.clear(); r.in_response_to.clear(); r.signed = false; r.binding = 0;
    r.has_relay_state = false; r.relay_state.clear();
    r.status.clear(); r.status2.clear(); r.status_message.clear();
    r.acs_url.clear(); r.acs_binding = BINDING_POST; r.acs_index = -1; r.force_authn = false; r.is_passive = false;
    r.name_id_policy.clear(); r.allow_create = false; r.authn_context.clear();
    r.name_id.clear(); r.name_id_format.clear(); r.name_qualifier.clear(); r.sp_name_qualifier.clear();
    r.session_indexes.clear(); r.not_on_or_after = 0;
}

fn fail_message(r: Message&, code: i64, why: const u8[:]) -> i64 { r.code = code; set_msg(r.message, why); return code; }

// Reads samlp:Status of el into r. False if there is none or it is malformed.
fn read_status(d: const xml::Doc&, el: i64, r: Message&) -> bool {
    if xml::count_children(d, el, SAMLP_NS, "Status") != 1 { return false; }
    let st = xml::child(d, el, SAMLP_NS, "Status");
    let sc = xml::child(d, st, SAMLP_NS, "StatusCode");
    if sc < 0 { return false; }
    let v, has = xml::attr(d, sc, "Value");
    if !has { return false; }
    r.status.append(v);
    let sc2 = xml::child(d, sc, SAMLP_NS, "StatusCode");
    if sc2 >= 0 {
        let v2, has2 = xml::attr(d, sc2, "Value");
        if has2 { r.status2.append(v2); }
    }
    let sm = xml::child(d, st, SAMLP_NS, "StatusMessage");
    if sm >= 0 { xml::text_content(d, sm, r.status_message); }
    return true;
}

// Checks a protocol message that came in from peer (in its role) and is
// addressed to my_url: the root is samlp:<kind>, Version 2.0, an ID, an
// IssueInstant not ahead of the clock, the Issuer the peer's; a signature
// (the Redirect query's, or the root's enveloped one) verified with the
// peer's signing certificates, and required when c.require_signed; the
// Destination, when there is one, my_url, and there must be one when the
// message is signed (saml-bindings §3.4.5.2, §3.5.5.2). Returns the root
// (the node the signature covers when signed) or -1, with r.code set.
fn check_message(d: const xml::Doc&, m: const Received&, kind: const u8[:], peer: const Entity&, role: u8,
                 my_url: const u8[:], c: const Checks&, r: Message&) -> i64 {
    var root = xml::root_element(d);
    if !xml::is(d, root, SAMLP_NS, kind) { fail_message(r, ERR_MALFORMED, str("not a samlp:", kind)); return -1; }
    r.kind.append(kind);
    r.binding = m.binding;
    if m.has_relay_state { r.has_relay_state = true; r.relay_state.append(m.relay_state); }
    // The signature first: what follows is read from what it covers.
    var o = xml::verify_options();
    o.allow_sha1 = c.allow_sha1;
    let xml_signed = xml::count_children(d, root, xml::DSIG_NS, "Signature") > 0;
    if redirect_signed(m) {
        let e = verify_redirect_by(m, peer, role, c.allow_sha1);
        if e != OK { fail_message(r, e, "the query's signature does not verify with the peer's certificates"); return -1; }
        r.signed = true;
    }
    if xml_signed {
        let v = verify_by(d, root, peer, role, o);
        if v.code != xml::OK { fail_message(r, dsig_error(v.code), v.message); return -1; }
        root = if v.refs[0] == 0 { xml::root_element(d) } else { v.refs[0] };
        r.signed = true;
    }
    if c.require_signed && !r.signed { fail_message(r, ERR_NOT_SIGNED, "the message is not signed"); return -1; }
    let ver, hasv = xml::attr(d, root, "Version");
    if !hasv || ver != "2.0" { fail_message(r, ERR_VERSION, "Version is not 2.0"); return -1; }
    let id, hasid = xml::attr(d, root, "ID");
    if !hasid || id.len == 0 { fail_message(r, ERR_MALFORMED, "no ID"); return -1; }
    r.id.append(id);
    let ii, hasii = xml::attr(d, root, "IssueInstant");
    let t, okt = parse_time(ii);
    if !hasii || !okt { fail_message(r, ERR_TIME, "IssueInstant missing or not a time"); return -1; }
    r.issue_instant = t;
    if t > c.now + c.skew { fail_message(r, ERR_NOT_YET_VALID, "IssueInstant is ahead of the clock"); return -1; }
    if !issuer_of(d, root, r.issuer) { fail_message(r, ERR_ISSUER, "no Issuer, or a malformed one"); return -1; }
    if r.issuer[..] != peer.entity_id[..] { fail_message(r, ERR_ISSUER, "the Issuer is not the peer"); return -1; }
    let dest, hasd = xml::attr(d, root, "Destination");
    if hasd {
        r.destination.append(dest);
        if dest != my_url { fail_message(r, ERR_DESTINATION, "the Destination is not this endpoint"); return -1; }
    } else if r.signed {
        fail_message(r, ERR_DESTINATION, "a signed message without Destination");
        return -1;
    }
    let irt, hasirt = xml::attr(d, root, "InResponseTo");
    if hasirt { r.in_response_to.append(irt); }
    return root;
}

// Parses m's XML for check_message: the root, or -1 with r.code set.
fn parse_received(d: xml::Doc&, m: const Received&, c: const Checks&, r: Message&) -> i64 {
    var why: u8[>..] = [];
    let e = parse_saml(d, m.xml, c.max, why);
    if e != OK { fail_message(r, e, why); return -1; }
    return xml::root_element(d);
}

// --- Single Logout ------------------------------------------------------------------------

// A NameID element under parent.
fn add_name_id(d: xml::Doc&, parent: i64, value: const u8[:], format: const u8[:], name_qualifier: const u8[:],
               sp_name_qualifier: const u8[:]) -> bool {
    let n = xml::element(d, parent, "saml", "NameID", SAML_NS);
    if format.len > 0 && !xml::set_attr(d, n, "Format", format) { return false; }
    if name_qualifier.len > 0 && !xml::set_attr(d, n, "NameQualifier", name_qualifier) { return false; }
    if sp_name_qualifier.len > 0 && !xml::set_attr(d, n, "SPNameQualifier", sp_name_qualifier) { return false; }
    return xml::text(d, n, value) >= 0;
}

// Whom a logout is for: the NameID as the assertion had it, and the
// session's SessionIndex (empty: all of the principal's sessions).
struct LogoutSubject {
    name_id:           u8[..1024] = [],
    format:            u8[..256]  = [],
    name_qualifier:    u8[..1024] = [],
    sp_name_qualifier: u8[..1024] = [],
    session_index:     u8[..256]  = [],
}

// A LogoutRequest from issuer to the peer's SLO endpoint for the binding,
// signed by s when sign is set (in the query for Redirect, in the XML for
// POST), valid for `lifetime` seconds (NotOnOrAfter; 0: none).
fn logout_request_to(issuer: const u8[:], s: const Signer&, sign: bool, peer: const Entity&, peer_role: u8, binding: i64,
                     who: const LogoutSubject&, now: i64, lifetime: i64, relay_state: const u8[:], o: Outgoing&) -> i64 {
    reset_outgoing(o);
    let dest = endpoint_location(peer, peer_role, EP_SLO, binding);
    if dest.len == 0 { return ERR_ENDPOINT; }
    if who.name_id.len == 0 { return ERR_ARG; }
    var d = xml::Doc { .. };
    o.id.append(new_id());
    let root = start_message(d, "LogoutRequest", o.id, now, dest, issuer);
    if root < 0 { return ERR_ARG; }
    if lifetime > 0 { xml::set_attr(d, root, "NotOnOrAfter", time_text(now + lifetime)); }
    if !add_name_id(d, root, who.name_id[..], who.format[..], who.name_qualifier[..], who.sp_name_qualifier[..]) { return ERR_ARG; }
    if who.session_index.len > 0 && xml::text(d, xml::element(d, root, "samlp", "SessionIndex", SAMLP_NS), who.session_index[..]) < 0 {
        return ERR_ARG;
    }
    return deliver(d, root, binding, dest, true, relay_state, s, sign, o);
}

// A LogoutResponse to the request r (its ID in InResponseTo) at the
// peer's SLO endpoint (its ResponseLocation when it has one) for the
// binding, with status (STATUS_SUCCESS, or a failure and a second-level
// code), signed by s when sign is set.
fn logout_response_to(issuer: const u8[:], s: const Signer&, sign: bool, peer: const Entity&, peer_role: u8, binding: i64,
                      in_response_to: const u8[:], status: const u8[:], status2: const u8[:], now: i64,
                      relay_state: const u8[:], o: Outgoing&) -> i64 {
    reset_outgoing(o);
    let dest = slo_response_location(peer, peer_role, binding);
    if dest.len == 0 { return ERR_ENDPOINT; }
    var d = xml::Doc { .. };
    o.id.append(new_id());
    let root = start_message(d, "LogoutResponse", o.id, now, dest, issuer);
    if root < 0 { return ERR_ARG; }
    if in_response_to.len > 0 && !xml::set_attr(d, root, "InResponseTo", in_response_to) { return ERR_ARG; }
    if !add_status(d, root, status, status2, "") { return ERR_ARG; }
    return deliver(d, root, binding, dest, false, relay_state, s, sign, o);
}

// Reads a LogoutRequest from peer to my_url: check_message's checks, then
// NotOnOrAfter (not passed), the NameID (whole text; no elements in it)
// and the SessionIndexes, into r.
fn read_logout_request(m: const Received&, peer: const Entity&, peer_role: u8, my_url: const u8[:], c: const Checks&, r: Message&) -> i64 {
    reset_message(r);
    if !m.is_request { return fail_message(r, ERR_BINDING, "not a SAMLRequest"); }
    var d = xml::Doc { .. };
    if parse_received(d, m, c, r) < 0 { return r.code; }
    let root = check_message(d, m, "LogoutRequest", peer, peer_role, my_url, c, r);
    if root < 0 { return r.code; }
    let noa, hasnoa = xml::attr(d, root, "NotOnOrAfter");
    if hasnoa {
        let t, ok = parse_time(noa);
        if !ok { return fail_message(r, ERR_TIME, "NotOnOrAfter is not a time"); }
        r.not_on_or_after = t;
        if c.now - c.skew >= t { return fail_message(r, ERR_EXPIRED, "the LogoutRequest has expired"); }
    }
    if xml::count_children(d, root, SAML_NS, "NameID") != 1 {
        return fail_message(r, ERR_SUBJECT, "not exactly one NameID (BaseID and EncryptedID are not supported)");
    }
    let n = xml::child(d, root, SAML_NS, "NameID");
    if has_elements(d, n) { return fail_message(r, ERR_SUBJECT, "a NameID with elements in it"); }
    xml::text_content(d, n, r.name_id);
    let f, hasf = xml::attr(d, n, "Format");
    r.name_id_format.append(if hasf { f } else { NAMEID_UNSPECIFIED });
    let nq, hasnq = xml::attr(d, n, "NameQualifier");
    if hasnq { r.name_qualifier.append(nq); }
    let spq, hasspq = xml::attr(d, n, "SPNameQualifier");
    if hasspq { r.sp_name_qualifier.append(spq); }
    var c2 = xml::first_element(d, root);
    while c2 >= 0 {
        if xml::is(d, c2, SAMLP_NS, "SessionIndex") {
            if has_elements(d, c2) { return fail_message(r, ERR_MALFORMED, "a SessionIndex with elements in it"); }
            var si: u8[>..] = [];
            xml::text_content(d, c2, si);
            r.session_indexes.push(copy(si));
        }
        c2 = xml::next_element(d, c2);
    }
    return OK;
}

// Reads a LogoutResponse from peer to my_url, in response to the request
// whose ID the caller kept: check_message's checks, InResponseTo that ID,
// and the status: OK for Success (r.status says PartialLogout and the
// like as a second-level code), ERR_STATUS otherwise.
fn read_logout_response(m: const Received&, peer: const Entity&, peer_role: u8, my_url: const u8[:], request_id: const u8[:],
                        c: const Checks&, r: Message&) -> i64 {
    reset_message(r);
    if m.is_request { return fail_message(r, ERR_BINDING, "not a SAMLResponse"); }
    var d = xml::Doc { .. };
    if parse_received(d, m, c, r) < 0 { return r.code; }
    let root = check_message(d, m, "LogoutResponse", peer, peer_role, my_url, c, r);
    if root < 0 { return r.code; }
    if r.in_response_to[..] != request_id || request_id.len == 0 {
        return fail_message(r, ERR_IN_RESPONSE_TO, "InResponseTo is not the LogoutRequest's ID");
    }
    if !read_status(d, root, r) { return fail_message(r, ERR_MALFORMED, "no Status"); }
    if r.status[..] != STATUS_SUCCESS { return fail_message(r, ERR_STATUS, "the logout did not succeed"); }
    return OK;
}
