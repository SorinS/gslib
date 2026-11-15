// saml: SAML 2.0 Web Browser SSO and Single Logout, both sides: a service
// provider (saml/sp.goose) that sends AuthnRequests and checks the
// Responses that come back, and an identity provider (saml/idp.goose) that
// answers AuthnRequests with signed, optionally encrypted assertions; the
// HTTP-Redirect binding (DEFLATE, the query string signed by SigAlg and
// Signature) and the HTTP-POST binding (an auto-submitting form); metadata
// (saml/metadata.goose: EntityDescriptor with SPSSODescriptor and
// IDPSSODescriptor), read, verified when signed, and written; and
// LogoutRequest and LogoutResponse both ways over both bindings
// (saml/logout.goose).
//
// XML, signatures and encryption are gslib's encoding/xml: no DTDs, every
// limit an error, and signatures verified against wrapping. What a
// signature covers is what dsig says it covers: the assertion a service
// provider reads is the node signature verification returned (or the one
// direct child of a verified Response), never one found by searching the
// document again.
//
//   var sp = saml::Sp { .. };                     // saml/sp.goose
//   var idp = saml::Entity { .. };
//   saml::parse_metadata(idp, metadata_xml, "");
//   var req = saml::Outgoing { .. };
//   saml::authn_request(sp, idp, saml::BINDING_REDIRECT, "relay", req);
//   // send the browser to req.url; keep req.id until the Response comes
//   var m = saml::Received { .. };
//   saml::read_post(m, form_body, sp.max_message);
//   var a = saml::Assertion { .. };
//   let e = saml::process_response(sp, idp, m, kept_id, a);
//
// Nothing is kept in part: a value that does not fit where it goes is an
// error, never cut.

namespace saml;

import std;
import os;
import base64;
import encoding.xml;
import encoding.xml.c14n;
import encoding.xml.dsig;
import encoding.xml.enc;
import crypto.x509;
import crypto.x509.keys;
import crypto.bignum;
import crypto.bignum.entropy;
import crypto.bignum.ec;
import compress;
import compress.flate;
import compress.deflate;
import net.http;
import net.http.url;

// --- Names ----------------------------------------------------------------------

let SAML_NS:  const u8[:] = "urn:oasis:names:tc:SAML:2.0:assertion";
let SAMLP_NS: const u8[:] = "urn:oasis:names:tc:SAML:2.0:protocol";
let MD_NS:    const u8[:] = "urn:oasis:names:tc:SAML:2.0:metadata";
let XSI_NS:   const u8[:] = "http://www.w3.org/2001/XMLSchema-instance";
let XS_NS:    const u8[:] = "http://www.w3.org/2001/XMLSchema";

let URI_BINDING_REDIRECT: const u8[:] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";
let URI_BINDING_POST:     const u8[:] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
let URI_BINDING_ARTIFACT: const u8[:] = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact";
let URI_BINDING_SOAP:     const u8[:] = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

let BINDING_OTHER:    i64 = 0;   // one this package does not speak (Artifact, SOAP, ...)
let BINDING_REDIRECT: i64 = 1;
let BINDING_POST:     i64 = 2;

fn binding_uri(b: i64) -> const u8[:] {
    if b == BINDING_REDIRECT { return URI_BINDING_REDIRECT; }
    if b == BINDING_POST { return URI_BINDING_POST; }
    return "";
}

fn binding_of_uri(uri: const u8[:]) -> i64 {
    if uri == URI_BINDING_REDIRECT { return BINDING_REDIRECT; }
    if uri == URI_BINDING_POST { return BINDING_POST; }
    return BINDING_OTHER;
}

fn binding_name(b: i64) -> const u8[:] {
    if b == BINDING_REDIRECT { return "HTTP-Redirect"; }
    if b == BINDING_POST { return "HTTP-POST"; }
    return "other";
}

let NAMEID_UNSPECIFIED: const u8[:] = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
let NAMEID_EMAIL:       const u8[:] = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
let NAMEID_PERSISTENT:  const u8[:] = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
let NAMEID_TRANSIENT:   const u8[:] = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
let NAMEID_ENTITY:      const u8[:] = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity";

let ATTRNAME_URI:         const u8[:] = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";
let ATTRNAME_BASIC:       const u8[:] = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
let ATTRNAME_UNSPECIFIED: const u8[:] = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified";

let CM_BEARER: const u8[:] = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

let AC_PASSWORD_PROTECTED: const u8[:] = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
let AC_PASSWORD:           const u8[:] = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
let AC_UNSPECIFIED:        const u8[:] = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";

let STATUS_SUCCESS:           const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:Success";
let STATUS_REQUESTER:         const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:Requester";
let STATUS_RESPONDER:         const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:Responder";
let STATUS_VERSION_MISMATCH:  const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
let STATUS_AUTHN_FAILED:      const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
let STATUS_NO_PASSIVE:        const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
let STATUS_PARTIAL_LOGOUT:    const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout";
let STATUS_REQUEST_DENIED:    const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:RequestDenied";
let STATUS_UNKNOWN_PRINCIPAL: const u8[:] = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";

// --- Errors ---------------------------------------------------------------------

let OK:                 i64 = 0;
let ERR_ARG:            i64 = 1;    // an argument that cannot be used (no key, a value XML cannot hold)
let ERR_MALFORMED:      i64 = 2;    // not well-formed XML (a DOCTYPE too), or not the SAML element it should be
let ERR_LIMIT:          i64 = 3;    // larger than a limit (the message, the inflated message, RelayState)
let ERR_BINDING:        i64 = 4;    // the binding's encoding is wrong (query, base64, DEFLATE, parameters), or the wrong binding
let ERR_VERSION:        i64 = 5;    // Version is not 2.0
let ERR_SIGNATURE:      i64 = 6;    // a signature that does not verify with the peer's certificates, or that wraps
let ERR_NOT_SIGNED:     i64 = 7;    // a signature that must be there is not
let ERR_ALGORITHM:      i64 = 8;    // an algorithm not allowed (SHA-1 by default)
let ERR_DESTINATION:    i64 = 9;    // Destination is not this endpoint (or missing on a signed message)
let ERR_ISSUER:         i64 = 10;   // the Issuer is not the peer
let ERR_STATUS:         i64 = 11;   // the peer answered with a StatusCode other than Success
let ERR_IN_RESPONSE_TO: i64 = 12;   // InResponseTo is not the request's
let ERR_ASSERTION:      i64 = 13;   // not exactly one assertion
let ERR_DECRYPT:        i64 = 14;   // an encrypted part that does not decrypt with our key
let ERR_SUBJECT:        i64 = 15;   // no Subject, no NameID, a NameID with elements in it
let ERR_CONFIRMATION:   i64 = 16;   // no bearer SubjectConfirmation that holds
let ERR_RECIPIENT:      i64 = 17;   // the bearer confirmation's Recipient is not our ACS
let ERR_EXPIRED:        i64 = 18;   // NotOnOrAfter has passed (with the clock skew)
let ERR_NOT_YET_VALID:  i64 = 19;   // NotBefore is ahead (with the clock skew)
let ERR_AUDIENCE:       i64 = 20;   // no AudienceRestriction, or one that leaves us out
let ERR_CONDITION:      i64 = 21;   // a condition not understood, or two OneTimeUse
let ERR_SESSION:        i64 = 22;   // no AuthnStatement, or its SessionNotOnOrAfter has passed
let ERR_REPLAY:         i64 = 23;   // the assertion was seen before (the caller's replay check)
let ERR_UNSOLICITED:    i64 = 24;   // an IdP-initiated response, not allowed
let ERR_NOT_ENCRYPTED:  i64 = 25;   // a plain assertion where an encrypted one is required
let ERR_TIME:           i64 = 26;   // a time that is not an xs:dateTime, or missing
let ERR_ENDPOINT:       i64 = 27;   // no endpoint for the binding, or a request's ACS URL not in the metadata

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_MALFORMED { return "not a well-formed SAML message"; }
    if e == ERR_LIMIT { return "over the size limit"; }
    if e == ERR_BINDING { return "the binding's encoding is wrong"; }
    if e == ERR_VERSION { return "not SAML 2.0"; }
    if e == ERR_SIGNATURE { return "the signature does not verify"; }
    if e == ERR_NOT_SIGNED { return "not signed"; }
    if e == ERR_ALGORITHM { return "an algorithm not allowed"; }
    if e == ERR_DESTINATION { return "the Destination is not this endpoint"; }
    if e == ERR_ISSUER { return "the Issuer is not the peer"; }
    if e == ERR_STATUS { return "the peer's status is not Success"; }
    if e == ERR_IN_RESPONSE_TO { return "InResponseTo is not the request's"; }
    if e == ERR_ASSERTION { return "not exactly one assertion"; }
    if e == ERR_DECRYPT { return "does not decrypt"; }
    if e == ERR_SUBJECT { return "no usable Subject or NameID"; }
    if e == ERR_CONFIRMATION { return "no bearer SubjectConfirmation holds"; }
    if e == ERR_RECIPIENT { return "the Recipient is not this endpoint"; }
    if e == ERR_EXPIRED { return "expired"; }
    if e == ERR_NOT_YET_VALID { return "not yet valid"; }
    if e == ERR_AUDIENCE { return "not for this audience"; }
    if e == ERR_CONDITION { return "a condition not understood"; }
    if e == ERR_SESSION { return "no AuthnStatement, or the session has expired"; }
    if e == ERR_REPLAY { return "the assertion was seen before"; }
    if e == ERR_UNSOLICITED { return "an unsolicited response, not allowed"; }
    if e == ERR_NOT_ENCRYPTED { return "the assertion must be encrypted"; }
    if e == ERR_TIME { return "a time that is missing or not an xs:dateTime"; }
    if e == ERR_ENDPOINT { return "no such endpoint"; }
    return "unknown";
}

// --- Time -----------------------------------------------------------------------

fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn civil_from_days(days: i64) -> i64, i64, i64 {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    return yoe + era * 400 + (if m <= 2 { 1 } else { 0 }), m, d;
}

fn num(s: const u8[:], at: i64, n: i64) -> i64 {
    if at + n > s.len { return -1; }
    var v: i64 = 0;
    for i in n {
        let c = s[at + i];
        if c < '0' || c > '9' { return -1; }
        v = v * 10 + (c - '0');
    }
    return v;
}

fn days_in_month(y: i64, m: i64) -> i64 {
    if m == 2 { return if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 { 29 } else { 28 }; }
    if m == 4 || m == 6 || m == 9 || m == 11 { return 30; }
    return 31;
}

// An xs:dateTime (YYYY-MM-DDThh:mm:ss, a fraction, and Z, an offset or
// nothing, read as UTC) in milliseconds since 1970, and whether it is
// one. SAML says times are UTC; an offset is applied.
fn parse_time_ms(s: const u8[:]) -> i64, bool {
    if s.len < 19 || s.len > 64 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' { return 0, false; }
    let y = num(s, 0, 4);
    let mo = num(s, 5, 2);
    let d = num(s, 8, 2);
    let h = num(s, 11, 2);
    let mi = num(s, 14, 2);
    let se = num(s, 17, 2);
    if y < 1 || mo < 1 || mo > 12 || d < 1 || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 59 { return 0, false; }
    if d > days_in_month(y, mo) { return 0, false; }
    var p: i64 = 19;
    var ms: i64 = 0;
    if p < s.len && s[p] == '.' {
        p++;
        let start = p;
        var scale: i64 = 100;
        while p < s.len && s[p] >= '0' && s[p] <= '9' {
            ms += (s[p] - '0') * scale;
            scale /= 10;
            p++;
        }
        if p == start { return 0, false; }
    }
    var off: i64 = 0;
    if p < s.len {
        if s[p] == 'Z' { p++; }
        else if s[p] == '+' || s[p] == '-' {
            if p + 6 != s.len || s[p + 3] != ':' { return 0, false; }
            let oh = num(s, p + 1, 2);
            let om = num(s, p + 4, 2);
            if oh < 0 || oh > 14 || om < 0 || om > 59 { return 0, false; }
            off = (oh * 60 + om) * 60;
            if s[p] == '+' { off = -off; }
            p += 6;
        } else { return 0, false; }
    }
    if p != s.len { return 0, false; }
    let secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se + off;
    return secs * 1000 + ms, true;
}

// The same in whole seconds (a fraction dropped).
fn parse_time(s: const u8[:]) -> i64, bool {
    let ms, ok = parse_time_ms(s);
    return (if ms >= 0 { ms / 1000 } else { (ms - 999) / 1000 }), ok;
}

// secs as an xs:dateTime in UTC, as SAML writes it: 2026-01-02T03:04:05Z.
fn format_time(out: u8[>..]&, secs: i64) {
    let days = (if secs >= 0 { secs } else { secs - 86399 }) / 86400;
    let rem = secs - days * 86400;
    let y, m, d = civil_from_days(days);
    format_int(out, y, 10, 4, '0');
    out.push('-');
    format_int(out, m, 10, 2, '0');
    out.push('-');
    format_int(out, d, 10, 2, '0');
    out.push('T');
    format_int(out, rem / 3600, 10, 2, '0');
    out.push(':');
    format_int(out, rem / 60 % 60, 10, 2, '0');
    out.push(':');
    format_int(out, rem % 60, 10, 2, '0');
    out.push('Z');
}

fn time_text(secs: i64) -> u8[>..] {
    var out: u8[>..] = [];
    format_time(out, secs);
    return out;
}

// The clock in seconds, or `configured` when it is not 0 (tests set it).
fn now_or(configured: i64) -> i64 { if configured != 0 { configured } else { time_ns() / 1000000000 } }

// --- Small things ---------------------------------------------------------------

// A fresh message or assertion ID: "_" and 40 hex digits (160 random
// bits), an NCName as xs:ID wants.
fn new_id() -> u8[>..] {
    var r: u8[20] = [0; 20];
    bignum::random_bytes(r);
    var out: u8[>..] = [];
    out.push('_');
    let hex = "0123456789abcdef";
    for b in r { out.push(hex[b >> 4]); out.push(hex[b & 15]); }
    return out;
}

fn is_ws(c: u8) -> bool { c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// base64 with white space anywhere passed over (line breaks in POST forms
// and in certificates); false if it is not base64.
fn b64_decode_ws(out: u8[>..]&, s: const u8[:]) -> bool {
    var t: u8[>..] = [];
    for c in s { if !is_ws(c) { t.push(c); } }
    return base64::decode(out, t);
}

// Text for HTML: & < > " ' escaped.
fn html_escape(out: u8[>..]&, s: const u8[:]) {
    for c in s {
        if c == '&' { out.append("&amp;"); }
        else if c == '<' { out.append("&lt;"); }
        else if c == '>' { out.append("&gt;"); }
        else if c == '"' { out.append("&quot;"); }
        else if c == '\'' { out.append("&#39;"); }
        else { out.push(c); }
    }
}

// Whether el has element children (a NameID or an Issuer must not).
fn has_elements(d: const xml::Doc&, el: i64) -> bool { xml::first_element(d, el) >= 0 }

fn set_msg(m: u8[>..]&, s: const u8[:]) { m.clear(); m.append(s); }

// --- Signing ----------------------------------------------------------------------

// Who signs: a key, its certificate (DER, sent in KeyInfo and in
// metadata), and the signature's hash (256, 384 or 512; Ed25519 has its
// own). alg 0 is the key's own algorithm (RSA PKCS #1 v1.5, ECDSA, Ed25519).
struct Signer {
    has_key:  bool             = false,
    alg:      i64              = 0,
    hash:     i64              = 256,
    key:      x509::PrivateKey = x509::empty_key(),
    cert_der: u8[>..]          = [],
}

// The x509 algorithm and hash a signer uses.
fn signer_alg(s: const Signer&) -> i64, i64 {
    if s.alg != 0 { return s.alg, (if s.alg == x509::SIG_ED25519 { 0 } else { s.hash }); }
    let a, h = x509::default_sig(s.key.kind);
    if a == x509::SIG_ED25519 { return a, 0; }
    return a, s.hash;
}

// The SignatureMethod URI a signer's signatures carry ("" if it cannot sign).
fn signer_alg_uri(s: const Signer&) -> const u8[:] {
    let a, h = signer_alg(s);
    if !s.has_key || !x509::sig_fits_key(s.key.kind, a, h) { return ""; }
    return xml::sig_uri(a, h);
}

// Signs el (a message, an assertion, metadata) with an enveloped
// signature after its Issuer (first, with no Issuer). OK or an error.
fn sign_element(d: xml::Doc&, el: i64, s: const Signer&) -> i64 {
    if !s.has_key { return ERR_ARG; }
    var before = xml::first_element(d, el);
    if before >= 0 && xml::is(d, before, SAML_NS, "Issuer") { before = xml::next_element(d, before); }
    var o = xml::sign_options();
    let a, h = signer_alg(s);
    o.alg = a;
    o.hash = if h == 0 { 256 } else { h };
    o.digest = if h == 384 || h == 512 { h } else { 256 };
    let sig, e = xml::sign_enveloped(d, el, before, s.key, s.cert_der, o);
    if e == xml::ERR_DSIG_KEY || e == xml::ERR_DSIG_ALGORITHM { return ERR_ALGORITHM; }
    if e != xml::OK { return ERR_ARG; }
    return OK;
}

// A signature over the bytes of a Redirect query: XML Signature's form
// (r || s for ECDSA), to be base64'd.
fn sign_bytes(s: const Signer&, msg: const u8[:]) -> u8[>..], bool {
    var none: u8[>..] = [];
    let a, h = signer_alg(s);
    if !s.has_key || !x509::sig_fits_key(s.key.kind, a, h) { return none, false; }
    var value, ok = x509::sign(s.key, a, h, msg);
    if !ok { return none, false; }
    if a == x509::SIG_ECDSA {
        let curve = x509::curve_of_key(s.key.kind);
        let raw, okr = bignum::ecdsa_sig_from_der(curve, value);
        if !okr { return none, false; }
        value.clear();
        value.append(raw);
    }
    return value, true;
}

// --- What came in ------------------------------------------------------------------

// A message as the binding delivered it: which binding, a request
// (SAMLRequest) or a response (SAMLResponse), the XML, RelayState, and
// for the Redirect binding the signature over the query (SigAlg,
// Signature, and the bytes they sign: the parameters exactly as they came).
root struct Received {
    binding:         i64     = 0,
    is_request:      bool    = false,
    xml:             u8[>..] = [],
    has_relay_state: bool    = false,
    relay_state:     u8[>..] = [],
    sig_alg:         u8[>..] = [],
    signature:       u8[>..] = [],
    signed_octets:   u8[>..] = [],
    message:         u8[>..] = [],
}

let DEFAULT_MAX_MESSAGE: i64 = 1 << 20;   // bytes of XML, inflated
let MAX_RELAY_STATE:     i64 = 4096;      // the spec says 80 bytes; peers send more

fn reset_received(m: Received&) {
    m.binding = 0;
    m.is_request = false;
    m.xml.clear();
    m.has_relay_state = false;
    m.relay_state.clear();
    m.sig_alg.clear();
    m.signature.clear();
    m.signed_octets.clear();
    m.message.clear();
}

fn fail_received(m: Received&, code: i64, why: const u8[:]) -> i64 { set_msg(m.message, why); return code; }

// The raw spans of the parameters a binding knows, as they came.
struct Params {
    msg_at: i64 = -1, msg_end: i64 = -1, is_request: bool = false,
    rs_at: i64 = -1, rs_end: i64 = -1,
    sa_at: i64 = -1, sa_end: i64 = -1,
    sg_at: i64 = -1, sg_end: i64 = -1,
    dup: bool = false,
}

fn scan_params(q: const u8[:]) -> Params {
    var p = Params { .. };
    var pos: i64 = 0;
    while pos <= q.len {
        var e = pos;
        while e < q.len && q[e] != '&' { e++; }
        let pair = q[pos..e];
        let eq = position(pair, '=');
        let k = if eq < 0 { pair } else { pair[..eq] };
        let vat = if eq < 0 { e } else { pos + eq + 1 };
        if k == "SAMLRequest" || k == "SAMLResponse" {
            if p.msg_at >= 0 { p.dup = true; }
            p.msg_at = vat;
            p.msg_end = e;
            p.is_request = k == "SAMLRequest";
        } else if k == "RelayState" {
            if p.rs_at >= 0 { p.dup = true; }
            p.rs_at = vat;
            p.rs_end = e;
        } else if k == "SigAlg" {
            if p.sa_at >= 0 { p.dup = true; }
            p.sa_at = vat;
            p.sa_end = e;
        } else if k == "Signature" {
            if p.sg_at >= 0 { p.dup = true; }
            p.sg_at = vat;
            p.sg_end = e;
        }
        pos = e + 1;
    }
    return p;
}

fn read_relay_state(m: Received&, raw: const u8[:]) -> i64 {
    if raw.len > 3 * MAX_RELAY_STATE { return fail_received(m, ERR_LIMIT, "RelayState too long"); }
    if !http::query_unescape(m.relay_state, raw) { return fail_received(m, ERR_BINDING, "bad percent-encoding in RelayState"); }
    if m.relay_state.len > MAX_RELAY_STATE { return fail_received(m, ERR_LIMIT, "RelayState too long"); }
    m.has_relay_state = true;
    return OK;
}

// Reads an HTTP-Redirect message from the request's raw query string (what
// follows "?", not decoded): SAMLRequest or SAMLResponse (base64 of raw
// DEFLATE), RelayState, SigAlg and Signature. The signed bytes are made of
// the parameters as they came, percent-encoding and all, in the order the
// binding gives (§3.4.4.1); verify_redirect checks them. The XML is
// inflated to at most `max` bytes.
fn read_redirect(m: Received&, query: const u8[:], max: i64) -> i64 {
    reset_received(m);
    m.binding = BINDING_REDIRECT;
    if query.len > 4 * max + 65536 { return fail_received(m, ERR_LIMIT, "query too long"); }
    let p = scan_params(query);
    m.is_request = p.is_request;
    if p.dup { return fail_received(m, ERR_BINDING, "a parameter given twice"); }
    if p.msg_at < 0 { return fail_received(m, ERR_BINDING, "no SAMLRequest or SAMLResponse"); }
    if (p.sa_at >= 0) != (p.sg_at >= 0) { return fail_received(m, ERR_BINDING, "SigAlg without Signature, or Signature without SigAlg"); }
    var b64: u8[>..] = [];
    if !http::query_unescape(b64, query[p.msg_at..p.msg_end]) { return fail_received(m, ERR_BINDING, "bad percent-encoding"); }
    var deflated: u8[>..] = [];
    if !b64_decode_ws(deflated, b64) { return fail_received(m, ERR_BINDING, "the message is not base64"); }
    let ie = compress::inflate_decode(deflated, m.xml, max);
    if ie == compress::ERR_LIMIT || m.xml.len > max { m.xml.clear(); return fail_received(m, ERR_LIMIT, "the inflated message is over the limit"); }
    if ie != 0 { m.xml.clear(); return fail_received(m, ERR_BINDING, "the message is not raw DEFLATE"); }
    if p.rs_at >= 0 {
        let e = read_relay_state(m, query[p.rs_at..p.rs_end]);
        if e != OK { return e; }
    }
    if p.sa_at >= 0 {
        if p.sa_end - p.sa_at > 1024 || p.sg_end - p.sg_at > 8192 { return fail_received(m, ERR_LIMIT, "SigAlg or Signature too long"); }
        if !http::query_unescape(m.sig_alg, query[p.sa_at..p.sa_end]) { return fail_received(m, ERR_BINDING, "bad percent-encoding in SigAlg"); }
        var sb: u8[>..] = [];
        if !http::query_unescape(sb, query[p.sg_at..p.sg_end]) || !b64_decode_ws(m.signature, sb) || m.signature.len == 0 {
            return fail_received(m, ERR_BINDING, "the Signature is not base64");
        }
        m.signed_octets.append(if m.is_request { "SAMLRequest=" } else { "SAMLResponse=" });
        m.signed_octets.append(query[p.msg_at..p.msg_end]);
        if p.rs_at >= 0 {
            m.signed_octets.append("&RelayState=");
            m.signed_octets.append(query[p.rs_at..p.rs_end]);
        }
        m.signed_octets.append("&SigAlg=");
        m.signed_octets.append(query[p.sa_at..p.sa_end]);
    }
    return OK;
}

// Reads an HTTP-POST message from an application/x-www-form-urlencoded
// body: SAMLRequest or SAMLResponse (base64 of the XML, line breaks
// allowed) and RelayState. At most `max` bytes of XML.
fn read_post(m: Received&, body: const u8[:], max: i64) -> i64 {
    reset_received(m);
    m.binding = BINDING_POST;
    if body.len > 2 * max + 65536 { return fail_received(m, ERR_LIMIT, "form too long"); }
    let p = scan_params(body);
    m.is_request = p.is_request;
    if p.dup { return fail_received(m, ERR_BINDING, "a parameter given twice"); }
    if p.msg_at < 0 { return fail_received(m, ERR_BINDING, "no SAMLRequest or SAMLResponse"); }
    var b64: u8[>..] = [];
    if !http::query_unescape(b64, body[p.msg_at..p.msg_end]) { return fail_received(m, ERR_BINDING, "bad percent-encoding"); }
    if !b64_decode_ws(m.xml, b64) { m.xml.clear(); return fail_received(m, ERR_BINDING, "the message is not base64"); }
    if m.xml.len > max { m.xml.clear(); return fail_received(m, ERR_LIMIT, "the message is over the limit"); }
    if p.rs_at >= 0 {
        let e = read_relay_state(m, body[p.rs_at..p.rs_end]);
        if e != OK { return e; }
    }
    return OK;
}

// A message handed over as it is (a file, a test): its XML, as if by POST.
fn read_xml(m: Received&, is_request: bool, text: const u8[:], max: i64) -> i64 {
    reset_received(m);
    m.binding = BINDING_POST;
    m.is_request = is_request;
    if text.len > max { return fail_received(m, ERR_LIMIT, "the message is over the limit"); }
    m.xml.append(text);
    return OK;
}

// Whether the Redirect query was signed.
fn redirect_signed(m: const Received&) -> bool { m.binding == BINDING_REDIRECT && m.signature.len > 0 }

// Verifies the Redirect query's signature with cert: SigAlg from the
// allowed list (SHA-1 only with allow_sha1), over the bytes as received.
// OK, ERR_ALGORITHM, ERR_SIGNATURE, or ERR_NOT_SIGNED when there is none.
fn verify_redirect(m: const Received&, cert: const x509::Cert&, allow_sha1: bool) -> i64 {
    if !redirect_signed(m) { return ERR_NOT_SIGNED; }
    let a, h = xml::sig_of_uri(m.sig_alg, allow_sha1);
    if a == x509::SIG_UNKNOWN { return ERR_ALGORITHM; }
    let o = xml::verify_options();
    var e = xml::verify_value(cert, a, h, m.signed_octets, m.signature, o);
    if e != xml::OK && a == x509::SIG_ECDSA {
        // Some senders give ECDSA as DER rather than XML Signature's r || s.
        let curve = x509::curve_of_key(cert.key_type);
        let raw, okr = bignum::ecdsa_sig_from_der(curve, m.signature);
        if okr { e = xml::verify_value(cert, a, h, m.signed_octets, raw, o); }
    }
    return if e == xml::OK { OK } else { ERR_SIGNATURE };
}

// --- What goes out ----------------------------------------------------------------

// A message ready for a binding: its ID (kept by the sender of a request,
// to match InResponseTo), the XML, and for the Redirect binding the whole
// URL to send the browser to; for the POST binding the endpoint URL and an
// HTML page whose form posts the message there by itself.
root struct Outgoing {
    id:          u8[>..] = [],
    binding:     i64     = 0,
    xml:         u8[>..] = [],
    url:         u8[>..] = [],
    form:        u8[>..] = [],
    relay_state: u8[>..] = [],
}

fn reset_outgoing(o: Outgoing&) {
    o.id.clear();
    o.binding = 0;
    o.xml.clear();
    o.url.clear();
    o.form.clear();
    o.relay_state.clear();
}

// The query of an HTTP-Redirect message: SAMLRequest or SAMLResponse
// (DEFLATE, base64, percent-encoded), RelayState if any, and when sign is
// set, SigAlg and Signature over those bytes (§3.4.4.1).
fn redirect_query(out: u8[>..]&, is_request: bool, xml_text: const u8[:], relay_state: const u8[:], s: const Signer&, sign: bool) -> i64 {
    var deflated: u8[>..] = [];
    compress::deflate_encode(xml_text, deflated, 6);
    var b64: u8[>..] = [];
    base64::encode(b64, deflated);
    let start = out.len;
    out.append(if is_request { "SAMLRequest=" } else { "SAMLResponse=" });
    http::query_escape(out, b64);
    if relay_state.len > 0 {
        out.append("&RelayState=");
        http::query_escape(out, relay_state);
    }
    if sign {
        let uri = signer_alg_uri(s);
        if uri.len == 0 { out.resize(start, 0); return ERR_ARG; }
        out.append("&SigAlg=");
        http::query_escape(out, uri);
        var signed: u8[>..] = [];
        signed.append(out[start..]);
        let sig, ok = sign_bytes(s, signed);
        if !ok { out.resize(start, 0); return ERR_ALGORITHM; }
        var sb: u8[>..] = [];
        base64::encode(sb, sig);
        out.append("&Signature=");
        http::query_escape(out, sb);
    }
    return OK;
}

// The URL of an HTTP-Redirect message to location (which may have a
// query of its own).
fn redirect_url(out: u8[>..]&, location: const u8[:], is_request: bool, xml_text: const u8[:], relay_state: const u8[:],
                s: const Signer&, sign: bool) -> i64 {
    var q: u8[>..] = [];
    let e = redirect_query(q, is_request, xml_text, relay_state, s, sign);
    if e != OK { return e; }
    out.append(location);
    out.push(if position(location, '?') >= 0 { '&' } else { '?' });
    out.append(q);
    return OK;
}

// An HTML page with a form that posts the message to location as soon as
// it loads (a button for browsers without script), §3.5.4.
fn post_form(out: u8[>..]&, location: const u8[:], is_request: bool, xml_text: const u8[:], relay_state: const u8[:]) {
    var b64: u8[>..] = [];
    base64::encode(b64, xml_text);
    out.append("<!DOCTYPE html>\n<html><head><meta charset=\"utf-8\"><title>SAML</title></head>\n");
    out.append("<body onload=\"document.forms[0].submit()\">\n<form method=\"post\" action=\"");
    html_escape(out, location);
    out.append("\">\n<input type=\"hidden\" name=\"");
    out.append(if is_request { "SAMLRequest" } else { "SAMLResponse" });
    out.append("\" value=\"");
    out.append(b64);
    out.append("\"/>\n");
    if relay_state.len > 0 {
        out.append("<input type=\"hidden\" name=\"RelayState\" value=\"");
        html_escape(out, relay_state);
        out.append("\"/>\n");
    }
    out.append("<noscript><button type=\"submit\">Continue</button></noscript>\n</form>\n</body></html>\n");
}

// The form body (application/x-www-form-urlencoded) of a POST message:
// what the page above makes the browser send.
fn post_body(out: u8[>..]&, is_request: bool, xml_text: const u8[:], relay_state: const u8[:]) {
    var b64: u8[>..] = [];
    base64::encode(b64, xml_text);
    http::form_add(out, if is_request { "SAMLRequest" } else { "SAMLResponse" }, b64);
    if relay_state.len > 0 { http::form_add(out, "RelayState", relay_state); }
}

// Puts a message built in d into o for a binding: for POST the XML,
// signed in it when sign is set, and the form; for Redirect the URL, its
// query carrying the signature (and the XML none).
fn deliver(d: xml::Doc&, root: i64, binding: i64, location: const u8[:], is_request: bool, relay_state: const u8[:],
           s: const Signer&, sign: bool, o: Outgoing&) -> i64 {
    if relay_state.len > MAX_RELAY_STATE { return ERR_LIMIT; }
    if location.len == 0 { return ERR_ENDPOINT; }
    o.binding = binding;
    o.relay_state.append(relay_state);
    if binding == BINDING_POST {
        if sign {
            let e = sign_element(d, root, s);
            if e != OK { return e; }
        }
        xml::write_document(d, o.xml);
        o.url.append(location);
        post_form(o.form, location, is_request, o.xml, relay_state);
        return OK;
    }
    if binding == BINDING_REDIRECT {
        xml::write(d, root, o.xml);
        return redirect_url(o.url, location, is_request, o.xml, relay_state, s, sign);
    }
    return ERR_ARG;
}

// --- Building messages ----------------------------------------------------------------

// A protocol message's root: ID, Version, IssueInstant, Destination (when
// given), and its Issuer. -1 for a value XML cannot hold.
fn start_message(d: xml::Doc&, local: const u8[:], id: const u8[:], now: i64, destination: const u8[:], issuer: const u8[:]) -> i64 {
    xml::new_document(d);
    let root = xml::element(d, 0, "samlp", local, SAMLP_NS);
    if root < 0 { return -1; }
    xml::declare_ns(d, root, "saml", SAML_NS);
    if !xml::set_attr(d, root, "ID", id) { return -1; }
    xml::set_attr(d, root, "Version", "2.0");
    xml::set_attr(d, root, "IssueInstant", time_text(now));
    if destination.len > 0 && !xml::set_attr(d, root, "Destination", destination) { return -1; }
    let iss = xml::element(d, root, "saml", "Issuer", SAML_NS);
    if xml::text(d, iss, issuer) < 0 { return -1; }
    return root;
}

// A samlp:Status with a top-level code (and a second-level one, and a
// message, when given).
fn add_status(d: xml::Doc&, parent: i64, code: const u8[:], second: const u8[:], message: const u8[:]) -> bool {
    let st = xml::element(d, parent, "samlp", "Status", SAMLP_NS);
    let sc = xml::element(d, st, "samlp", "StatusCode", SAMLP_NS);
    if !xml::set_attr(d, sc, "Value", code) { return false; }
    if second.len > 0 {
        let sc2 = xml::element(d, sc, "samlp", "StatusCode", SAMLP_NS);
        if !xml::set_attr(d, sc2, "Value", second) { return false; }
    }
    if message.len > 0 && xml::text(d, xml::element(d, st, "samlp", "StatusMessage", SAMLP_NS), message) < 0 { return false; }
    return true;
}

// --- Reading messages -------------------------------------------------------------------

// Parses SAML XML: no DOCTYPE, at most max bytes, IDs unique.
fn parse_saml(d: xml::Doc&, text: const u8[:], max: i64, why: u8[>..]&) -> i64 {
    var o = xml::options();
    o.max_size = max;
    let e = xml::parse(d, text, o);
    if e.code == xml::OK { return OK; }
    why.clear();
    format(why, "XML: ", xml::error_name(e.code), ": ", e.message);
    return if e.code == xml::ERR_LIMIT { ERR_LIMIT } else { ERR_MALFORMED };
}

// A boolean attribute (xs:boolean: true, false, 1, 0): its value, false
// when absent, and whether it is one.
fn bool_attr(d: const xml::Doc&, el: i64, name: const u8[:]) -> bool, bool {
    let v, has = xml::attr(d, el, name);
    if !has { return false, true; }
    if v == "true" || v == "1" { return true, true; }
    if v == "false" || v == "0" { return false, true; }
    return false, false;
}

// The Issuer child of el, read: no elements in it, Format absent or the
// entity format. False when there is none or it is not so.
fn issuer_of(d: const xml::Doc&, el: i64, out: u8[>..]&) -> bool {
    if xml::count_children(d, el, SAML_NS, "Issuer") != 1 { return false; }
    let iss = xml::child(d, el, SAML_NS, "Issuer");
    if has_elements(d, iss) { return false; }
    let f, hasf = xml::attr(d, iss, "Format");
    if hasf && f != NAMEID_ENTITY { return false; }
    xml::text_content(d, iss, out);
    return true;
}

// The Issuer of a message as it came, unverified: for an identity
// provider to find the metadata of the service provider that sent it.
fn peek_issuer(m: const Received&, out: u8[>..]&) -> i64 {
    var d = xml::Doc { .. };
    var why: u8[>..] = [];
    let e = parse_saml(d, m.xml, m.xml.len + 1, why);
    if e != OK { return e; }
    let root = xml::root_element(d);
    if xml::ns_uri(d, root) != SAMLP_NS { return ERR_MALFORMED; }
    if !issuer_of(d, root, out) { return ERR_ISSUER; }
    return OK;
}
