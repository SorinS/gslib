// saml.metadata: SAML 2.0 metadata (saml-metadata-2.0-os): an
// EntityDescriptor with an IDPSSODescriptor, an SPSSODescriptor or both,
// read into an Entity (from the document itself, or picked by entityID
// out of an EntitiesDescriptor) and written from one. Read are the
// KeyDescriptors (use signing, encryption, or none for both; each
// X509Certificate in KeyInfo), the SingleSignOnService,
// AssertionConsumerService and SingleLogoutService endpoints with their
// bindings, NameIDFormat, EncryptionMethod, and the flags
// WantAuthnRequestsSigned, AuthnRequestsSigned and WantAssertionsSigned.
// Signed metadata is verified against a certificate the caller trusts
// (parse_metadata_signed) and read from the node the signature covers.

namespace saml;

import std;
import base64;
import encoding.xml;
import encoding.xml.dsig;
import crypto.x509;
import crypto.x509.keys;

// Roles and endpoint kinds.
let ROLE_IDP: u8 = 1;
let ROLE_SP:  u8 = 2;

let EP_SSO: u8 = 1;   // IDPSSODescriptor/SingleSignOnService
let EP_ACS: u8 = 2;   // SPSSODescriptor/AssertionConsumerService
let EP_SLO: u8 = 3;   // SingleLogoutService (of the role)

let MAX_LOCATION: i64 = 2048;

// An endpoint of a role: its kind, binding (BINDING_* and the URI as
// written), Location, ResponseLocation (SLO), index and isDefault (ACS).
struct Endpoint {
    role:              u8              = 0,
    kind:              u8              = 0,
    binding:           i64             = BINDING_OTHER,
    binding_uri:       u8[..256]       = [],
    location:          u8[..2048]      = [],
    response_location: u8[..2048]      = [],
    index:             i64             = -1,
    is_default:        bool            = false,
    has_default:       bool            = false,
}

// An entity's metadata. Certificates are kept as DER, per role and use
// (a KeyDescriptor without use goes in both lists).
root struct Entity {
    entity_id:                  u8[>..]    = [],
    id:                         u8[>..]    = [],    // the EntityDescriptor's ID, for signing
    valid_until:                i64        = 0,     // seconds; 0: none given
    is_idp:                     bool       = false,
    is_sp:                      bool       = false,
    want_authn_requests_signed: bool       = false, // IdP
    authn_requests_signed:      bool       = false, // SP
    want_assertions_signed:     bool       = false, // SP
    signed:                     bool       = false, // the metadata's signature was verified
    endpoints:                  Endpoint[>..] = [],
    idp_signing:                u8[][>..]  = [],
    idp_encryption:             u8[][>..]  = [],
    sp_signing:                 u8[][>..]  = [],
    sp_encryption:              u8[][>..]  = [],
    encryption_methods:         u8[][>..]  = [],    // the SP's encryption KeyDescriptors' EncryptionMethods
    idp_name_id_formats:        u8[][>..]  = [],
    sp_name_id_formats:         u8[][>..]  = [],
    message:                    u8[>..]    = [],    // why parsing failed
}

fn reset_entity(e: Entity&) {
    e.entity_id.clear(); e.id.clear(); e.valid_until = 0; e.is_idp = false; e.is_sp = false;
    e.want_authn_requests_signed = false; e.authn_requests_signed = false; e.want_assertions_signed = false;
    e.signed = false; e.endpoints.clear();
    e.idp_signing.clear(); e.idp_encryption.clear(); e.sp_signing.clear(); e.sp_encryption.clear();
    e.encryption_methods.clear(); e.idp_name_id_formats.clear(); e.sp_name_id_formats.clear();
    e.message.clear();
}

// --- Building one ------------------------------------------------------------------

// An endpoint added to e. False for a binding that does not fit, or a
// location that is not an absolute http(s) URL (location_ok).
fn add_endpoint(e: Entity&, role: u8, kind: u8, binding: i64, location: const u8[:]) -> bool {
    if location.len > MAX_LOCATION || !location_ok(location) || binding_uri(binding).len == 0 { return false; }
    var ep = Endpoint { role: role, kind: kind, binding: binding, .. };
    ep.binding_uri.append(binding_uri(binding));
    ep.location.append(location);
    if kind == EP_ACS {
        var n: i64 = 0;
        for x in e.endpoints { if x.role == role && x.kind == EP_ACS { n++; } }
        ep.index = n;
        if n == 0 { ep.is_default = true; ep.has_default = true; }
    }
    e.endpoints.push(ep);
    if role == ROLE_IDP { e.is_idp = true; } else { e.is_sp = true; }
    return true;
}

fn add_cert(list: u8[][>..]&, der: const u8[:]) {
    var c: u8[>..] = [];
    c.append(der);
    list.push(copy(c));
}

// --- Looking things up -----------------------------------------------------------------

// The endpoint of a role and kind for a binding: for ACS, the default (or
// the lowest index); else the first. -1 if there is none.
fn find_endpoint(e: const Entity&, role: u8, kind: u8, binding: i64) -> i64 {
    var best: i64 = -1;
    for i in e.endpoints.len {
        let x = e.endpoints[i];
        if x.role != role || x.kind != kind || x.binding != binding { continue; }
        if best < 0 { best = i; continue; }
        if kind == EP_ACS {
            let b = e.endpoints[best];
            if x.is_default && !b.is_default { best = i; }
            else if x.is_default == b.is_default && x.index < b.index { best = i; }
        }
    }
    return best;
}

// The Location of that endpoint ("" for none).
fn endpoint_location(e: const Entity&, role: u8, kind: u8, binding: i64) -> const u8[:] {
    let i = find_endpoint(e, role, kind, binding);
    if i < 0 { return ""; }
    return e.endpoints[i].location[..];
}

// The SLO endpoint's ResponseLocation, else its Location.
fn slo_response_location(e: const Entity&, role: u8, binding: i64) -> const u8[:] {
    let i = find_endpoint(e, role, EP_SLO, binding);
    if i < 0 { return ""; }
    if e.endpoints[i].response_location.len > 0 { return e.endpoints[i].response_location[..]; }
    return e.endpoints[i].location[..];
}

// The ACS endpoint with this index, -1 for none.
fn acs_by_index(e: const Entity&, index: i64) -> i64 {
    for i in e.endpoints.len {
        let x = e.endpoints[i];
        if x.role == ROLE_SP && x.kind == EP_ACS && x.index == index { return i; }
    }
    return -1;
}

// The ACS endpoint at this URL (exactly) for a binding, -1 for none.
fn acs_by_location(e: const Entity&, location: const u8[:], binding: i64) -> i64 {
    for i in e.endpoints.len {
        let x = e.endpoints[i];
        if x.role == ROLE_SP && x.kind == EP_ACS && x.location[..] == location && (binding == 0 || x.binding == binding) { return i; }
    }
    return -1;
}

// F(der) for each signing certificate of the role.
fn each_signing<F>(e: const Entity&, role: u8) {
    if role == ROLE_IDP { for c in e.idp_signing { F(c); } } else { for c in e.sp_signing { F(c); } }
}

// F(der) for each encryption certificate of the role.
fn each_encryption<F>(e: const Entity&, role: u8) {
    if role == ROLE_IDP { for c in e.idp_encryption { F(c); } } else { for c in e.sp_encryption { F(c); } }
}

// --- Verifying with a peer's certificates --------------------------------------------------

// Verifies el's enveloped signature with each of the peer's signing
// certificates for the role, the first that verifies. The Verified of
// that one, or of the last tried; ERR_DSIG_KEY with no certificate.
fn verify_by(d: const xml::Doc&, el: i64, e: const Entity&, role: u8, o: const xml::VerifyOptions&) -> xml::Verified {
    var last = xml::Verified { code: xml::ERR_DSIG_KEY, .. };
    format(last.message, "the peer has no signing certificate");
    each_signing(e, role) { der =>
        let c, ce = x509::parse(der);
        if ce == x509::OK {
            let v = xml::verify_enveloped(d, el, c, o);
            if v.code == xml::OK { return v; }
            last = v;
            // A wrapped or malformed signature fails for every key alike.
            if v.code != xml::ERR_DSIG_SIGNATURE && v.code != xml::ERR_DSIG_KEY && v.code != xml::ERR_DSIG_DIGEST { return v; }
        }
    };
    return last;
}

// Verifies a Redirect query's signature with each of the peer's signing
// certificates for the role.
fn verify_redirect_by(m: const Received&, e: const Entity&, role: u8, allow_sha1: bool) -> i64 {
    var last = ERR_SIGNATURE;
    each_signing(e, role) { der =>
        let c, ce = x509::parse(der);
        if ce == x509::OK {
            let r = verify_redirect(m, c, allow_sha1);
            if r == OK || r == ERR_ALGORITHM || r == ERR_NOT_SIGNED { return r; }
            last = r;
        }
    };
    return last;
}

// The saml error for a dsig one.
fn dsig_error(code: i64) -> i64 {
    if code == xml::ERR_DSIG_ALGORITHM { return ERR_ALGORITHM; }
    return ERR_SIGNATURE;
}

// --- Reading metadata -------------------------------------------------------------------

fn fail_entity(e: Entity&, code: i64, why: const u8[:]) -> i64 { set_msg(e.message, why); return code; }

// The certificates of a KeyDescriptor's KeyInfo/X509Data, appended.
fn read_key_descriptor(d: const xml::Doc&, kd: i64, e: Entity&, role: u8) -> i64 {
    let use, has_use = xml::attr(d, kd, "use");
    if has_use && use != "signing" && use != "encryption" { return fail_entity(e, ERR_MALFORMED, "KeyDescriptor use is not signing or encryption"); }
    let ki = xml::child(d, kd, xml::DSIG_NS, "KeyInfo");
    if ki < 0 { return fail_entity(e, ERR_MALFORMED, "KeyDescriptor without KeyInfo"); }
    var found = 0;
    var x = xml::first_element(d, ki);
    while x >= 0 {
        if xml::is(d, x, xml::DSIG_NS, "X509Data") {
            var c = xml::first_element(d, x);
            while c >= 0 {
                if xml::is(d, c, xml::DSIG_NS, "X509Certificate") {
                    var der: u8[>..] = [];
                    if !xml::base64_content(d, c, der) { return fail_entity(e, ERR_MALFORMED, "X509Certificate is not base64"); }
                    let cert, ce = x509::parse(der);
                    if ce != x509::OK { return fail_entity(e, ERR_MALFORMED, "X509Certificate is not a certificate"); }
                    let signing = !has_use || use == "signing";
                    let encryption = !has_use || use == "encryption";
                    if role == ROLE_IDP {
                        if signing { add_cert(e.idp_signing, der); }
                        if encryption { add_cert(e.idp_encryption, der); }
                    } else {
                        if signing { add_cert(e.sp_signing, der); }
                        if encryption { add_cert(e.sp_encryption, der); }
                    }
                    found++;
                }
                c = xml::next_element(d, c);
            }
        }
        x = xml::next_element(d, x);
    }
    if role == ROLE_SP && (!has_use || use == "encryption") {
        var em = xml::first_element(d, kd);
        while em >= 0 {
            if xml::is(d, em, MD_NS, "EncryptionMethod") {
                let alg, has = xml::attr(d, em, "Algorithm");
                if has {
                    var a: u8[>..] = [];
                    a.append(alg);
                    e.encryption_methods.push(copy(a));
                }
            }
            em = xml::next_element(d, em);
        }
    }
    return OK;
}

fn read_endpoint(d: const xml::Doc&, el: i64, role: u8, kind: u8, e: Entity&) -> i64 {
    let b, hasb = xml::attr(d, el, "Binding");
    let loc, hasl = xml::attr(d, el, "Location");
    if !hasb || !hasl { return fail_entity(e, ERR_MALFORMED, "an endpoint without Binding or Location"); }
    let rl, hasrl = xml::attr(d, el, "ResponseLocation");
    if b.len > 256 || loc.len > MAX_LOCATION || rl.len > MAX_LOCATION { return fail_entity(e, ERR_LIMIT, "an endpoint's Binding or Location is too long"); }
    if !location_ok(loc) || (hasrl && !location_ok(rl)) {
        return fail_entity(e, ERR_MALFORMED, "an endpoint's Location or ResponseLocation is not an absolute http(s) URL");
    }
    var ep = Endpoint { role: role, kind: kind, binding: binding_of_uri(b), .. };
    ep.binding_uri.append(b);
    ep.location.append(loc);
    if hasrl { ep.response_location.append(rl); }
    let ix, hasix = xml::attr(d, el, "index");
    if hasix {
        let v, okv = parse_int(ix);
        if !okv || v < 0 || v > 65535 { return fail_entity(e, ERR_MALFORMED, "an endpoint index is not an unsignedShort"); }
        ep.index = v;
    } else if kind == EP_ACS {
        return fail_entity(e, ERR_MALFORMED, "AssertionConsumerService without index");
    }
    let dv, okd = bool_attr(d, el, "isDefault");
    if !okd { return fail_entity(e, ERR_MALFORMED, "isDefault is not a boolean"); }
    let dvs, hasd = xml::attr(d, el, "isDefault");
    ep.is_default = dv;
    ep.has_default = hasd;
    e.endpoints.push(ep);
    return OK;
}

fn add_format(list: u8[][>..]&, d: const xml::Doc&, el: i64) {
    var f: u8[>..] = [];
    xml::text_content(d, el, f);
    var t: u8[>..] = [];
    t.append(trim(f));
    list.push(copy(t));
}

// Whether a protocolSupportEnumeration lists SAML 2.0's protocol.
fn supports_saml2(d: const xml::Doc&, el: i64) -> bool {
    let p, has = xml::attr(d, el, "protocolSupportEnumeration");
    if !has { return false; }
    var found = false;
    for w in words(p) { if w == SAMLP_NS { found = true; } }
    return found;
}

fn read_role(d: const xml::Doc&, rd: i64, role: u8, e: Entity&) -> i64 {
    var c = xml::first_element(d, rd);
    while c >= 0 {
        var r = OK;
        if xml::is(d, c, MD_NS, "KeyDescriptor") { r = read_key_descriptor(d, c, e, role); }
        else if xml::is(d, c, MD_NS, "SingleLogoutService") { r = read_endpoint(d, c, role, EP_SLO, e); }
        else if role == ROLE_IDP && xml::is(d, c, MD_NS, "SingleSignOnService") { r = read_endpoint(d, c, role, EP_SSO, e); }
        else if role == ROLE_SP && xml::is(d, c, MD_NS, "AssertionConsumerService") { r = read_endpoint(d, c, role, EP_ACS, e); }
        else if xml::is(d, c, MD_NS, "NameIDFormat") {
            if role == ROLE_IDP { add_format(e.idp_name_id_formats, d, c); } else { add_format(e.sp_name_id_formats, d, c); }
        }
        if r != OK { return r; }
        c = xml::next_element(d, c);
    }
    return OK;
}

// Reads an EntityDescriptor element into e.
fn read_entity(d: const xml::Doc&, ed: i64, e: Entity&) -> i64 {
    let id, has = xml::attr(d, ed, "entityID");
    if !has || id.len == 0 { return fail_entity(e, ERR_MALFORMED, "EntityDescriptor without entityID"); }
    if id.len > 1024 { return fail_entity(e, ERR_LIMIT, "entityID over 1024 bytes"); }
    e.entity_id.append(id);
    let xid, hasx = xml::attr(d, ed, "ID");
    if hasx { e.id.append(xid); }
    let vu, hasvu = xml::attr(d, ed, "validUntil");
    if hasvu {
        let t, ok = parse_time(vu);
        if !ok { return fail_entity(e, ERR_TIME, "validUntil is not a time"); }
        e.valid_until = t;
    }
    var c = xml::first_element(d, ed);
    while c >= 0 {
        if xml::is(d, c, MD_NS, "IDPSSODescriptor") && supports_saml2(d, c) {
            if e.is_idp { return fail_entity(e, ERR_MALFORMED, "two IDPSSODescriptors"); }
            e.is_idp = true;
            let w, okw = bool_attr(d, c, "WantAuthnRequestsSigned");
            if !okw { return fail_entity(e, ERR_MALFORMED, "WantAuthnRequestsSigned is not a boolean"); }
            e.want_authn_requests_signed = w;
            let r = read_role(d, c, ROLE_IDP, e);
            if r != OK { return r; }
        } else if xml::is(d, c, MD_NS, "SPSSODescriptor") && supports_saml2(d, c) {
            if e.is_sp { return fail_entity(e, ERR_MALFORMED, "two SPSSODescriptors"); }
            e.is_sp = true;
            let a, oka = bool_attr(d, c, "AuthnRequestsSigned");
            let w, okw = bool_attr(d, c, "WantAssertionsSigned");
            if !oka || !okw { return fail_entity(e, ERR_MALFORMED, "AuthnRequestsSigned or WantAssertionsSigned is not a boolean"); }
            e.authn_requests_signed = a;
            e.want_assertions_signed = w;
            let r = read_role(d, c, ROLE_SP, e);
            if r != OK { return r; }
        }
        c = xml::next_element(d, c);
    }
    if !e.is_idp && !e.is_sp { return fail_entity(e, ERR_MALFORMED, "no SAML 2.0 IDPSSODescriptor or SPSSODescriptor"); }
    if e.is_idp && find_endpoint_any(e, ROLE_IDP, EP_SSO) < 0 { return fail_entity(e, ERR_MALFORMED, "IDPSSODescriptor without SingleSignOnService"); }
    if e.is_sp && find_endpoint_any(e, ROLE_SP, EP_ACS) < 0 { return fail_entity(e, ERR_MALFORMED, "SPSSODescriptor without AssertionConsumerService"); }
    return OK;
}

fn find_endpoint_any(e: const Entity&, role: u8, kind: u8) -> i64 {
    for i in e.endpoints.len { if e.endpoints[i].role == role && e.endpoints[i].kind == kind { return i; } }
    return -1;
}

// The EntityDescriptor to read: the root, or in an EntitiesDescriptor
// (nested ones too) the one with entityID want (the only one, when want
// is empty). -1 and a reason.
fn pick_entity(d: const xml::Doc&, top: i64, want: const u8[:], e: Entity&) -> i64 {
    if xml::is(d, top, MD_NS, "EntityDescriptor") {
        let id, has = xml::attr(d, top, "entityID");
        if want.len > 0 && (!has || id != want) { fail_entity(e, ERR_MALFORMED, "the metadata is for another entity"); return -1; }
        return top;
    }
    if !xml::is(d, top, MD_NS, "EntitiesDescriptor") { fail_entity(e, ERR_MALFORMED, "not SAML metadata"); return -1; }
    var found: i64 = -1;
    var count = 0;
    xml::walk(d, top) { n, entering =>
        var down = false;
        if entering && xml::kind(d, n) == xml::ELEMENT {
            if xml::is(d, n, MD_NS, "EntitiesDescriptor") { down = true; }
            else if xml::is(d, n, MD_NS, "EntityDescriptor") {
                let id, has = xml::attr(d, n, "entityID");
                if want.len == 0 || (has && id == want) { found = n; count++; }
            }
        }
        down
    };
    if count == 0 { fail_entity(e, ERR_MALFORMED, "no EntityDescriptor for that entityID"); return -1; }
    if count > 1 { fail_entity(e, ERR_MALFORMED, if want.len == 0 { "several entities: name one" } else { "the entityID twice" }); return -1; }
    return found;
}

// Reads metadata (an EntityDescriptor, or one picked from an
// EntitiesDescriptor by entity_id) into e, unverified: for metadata that
// came over a channel the caller trusts (a file, TLS to the peer).
fn parse_metadata(e: Entity&, text: const u8[:], entity_id: const u8[:]) -> i64 {
    reset_entity(e);
    var d = xml::Doc { .. };
    var why: u8[>..] = [];
    let pe = parse_saml(d, text, 16 << 20, why);
    if pe != OK { return fail_entity(e, pe, why); }
    let top = pick_entity(d, xml::root_element(d), entity_id, e);
    if top < 0 { return ERR_MALFORMED; }
    return read_entity(d, top, e);
}

// Reads signed metadata: the root element's enveloped signature verified
// with cert (which the caller trusts: the federation's or the peer's
// metadata-signing certificate), and the entity read only from what the
// signature covers. validUntil, when given, must be ahead of now.
fn parse_metadata_signed(e: Entity&, text: const u8[:], entity_id: const u8[:], cert: const x509::Cert&, now: i64) -> i64 {
    reset_entity(e);
    var d = xml::Doc { .. };
    var why: u8[>..] = [];
    let pe = parse_saml(d, text, 16 << 20, why);
    if pe != OK { return fail_entity(e, pe, why); }
    let root = xml::root_element(d);
    if xml::count_children(d, root, xml::DSIG_NS, "Signature") == 0 { return fail_entity(e, ERR_NOT_SIGNED, "the metadata is not signed"); }
    let o = xml::verify_options();
    let v = xml::verify_enveloped(d, root, cert, o);
    if v.code != xml::OK { return fail_entity(e, dsig_error(v.code), v.message); }
    let signed_root = if v.refs[0] == 0 { root } else { v.refs[0] };
    let top = pick_entity(d, signed_root, entity_id, e);
    if top < 0 { return ERR_MALFORMED; }
    if !xml::is_signed(d, v, top) { return fail_entity(e, ERR_SIGNATURE, "the entity is not in what was signed"); }
    let r = read_entity(d, top, e);
    if r != OK { return r; }
    // validUntil of the signed root (an aggregate's) and of the entity.
    let vu, hasvu = xml::attr(d, signed_root, "validUntil");
    if hasvu {
        let t, ok = parse_time(vu);
        if !ok { return fail_entity(e, ERR_TIME, "validUntil is not a time"); }
        if e.valid_until == 0 || t < e.valid_until { e.valid_until = t; }
    }
    if e.valid_until != 0 && now >= e.valid_until { return fail_entity(e, ERR_EXPIRED, "the metadata's validUntil has passed"); }
    e.signed = true;
    return OK;
}

// --- Writing metadata --------------------------------------------------------------------

fn write_key_descriptor(d: xml::Doc&, rd: i64, use: const u8[:], der: const u8[:], methods: const u8[][:]) {
    let kd = xml::element(d, rd, "md", "KeyDescriptor", MD_NS);
    xml::set_attr(d, kd, "use", use);
    let ki = xml::element(d, kd, "ds", "KeyInfo", xml::DSIG_NS);
    let xd = xml::element(d, ki, "ds", "X509Data", xml::DSIG_NS);
    var b: u8[>..] = [];
    base64::encode(b, der);
    xml::text(d, xml::element(d, xd, "ds", "X509Certificate", xml::DSIG_NS), b);
    for m in methods {
        let em = xml::element(d, kd, "md", "EncryptionMethod", MD_NS);
        xml::set_attr(d, em, "Algorithm", m);
    }
}

fn write_endpoints(d: xml::Doc&, rd: i64, e: const Entity&, role: u8, kind: u8, local: const u8[:]) {
    for x in e.endpoints {
        if x.role != role || x.kind != kind { continue; }
        let el = xml::element(d, rd, "md", local, MD_NS);
        xml::set_attr(d, el, "Binding", x.binding_uri[..]);
        xml::set_attr(d, el, "Location", x.location[..]);
        if x.response_location.len > 0 { xml::set_attr(d, el, "ResponseLocation", x.response_location[..]); }
        if kind == EP_ACS {
            var ix: u8[>..] = [];
            format(ix, x.index);
            xml::set_attr(d, el, "index", ix);
            if x.is_default { xml::set_attr(d, el, "isDefault", "true"); }
        }
    }
}

fn write_formats(d: xml::Doc&, rd: i64, list: const u8[][:]) {
    for f in list { xml::text(d, xml::element(d, rd, "md", "NameIDFormat", MD_NS), f); }
}

// Builds e's EntityDescriptor in d; its element (-1 for a value XML cannot hold).
fn build_metadata(d: xml::Doc&, e: const Entity&) -> i64 {
    xml::new_document(d);
    let ed = xml::element(d, 0, "md", "EntityDescriptor", MD_NS);
    xml::declare_ns(d, ed, "ds", xml::DSIG_NS);
    if !xml::set_attr(d, ed, "entityID", e.entity_id) { return -1; }
    if e.id.len > 0 && !xml::set_attr(d, ed, "ID", e.id) { return -1; }
    if e.valid_until != 0 { xml::set_attr(d, ed, "validUntil", time_text(e.valid_until)); }
    var none: u8[][>..] = [];
    if e.is_idp {
        let rd = xml::element(d, ed, "md", "IDPSSODescriptor", MD_NS);
        if e.want_authn_requests_signed { xml::set_attr(d, rd, "WantAuthnRequestsSigned", "true"); }
        xml::set_attr(d, rd, "protocolSupportEnumeration", SAMLP_NS);
        for c in e.idp_signing { write_key_descriptor(d, rd, "signing", c, none); }
        for c in e.idp_encryption { write_key_descriptor(d, rd, "encryption", c, none); }
        write_endpoints(d, rd, e, ROLE_IDP, EP_SLO, "SingleLogoutService");
        write_formats(d, rd, e.idp_name_id_formats);
        write_endpoints(d, rd, e, ROLE_IDP, EP_SSO, "SingleSignOnService");
    }
    if e.is_sp {
        let rd = xml::element(d, ed, "md", "SPSSODescriptor", MD_NS);
        xml::set_attr(d, rd, "AuthnRequestsSigned", if e.authn_requests_signed { "true" } else { "false" });
        xml::set_attr(d, rd, "WantAssertionsSigned", if e.want_assertions_signed { "true" } else { "false" });
        xml::set_attr(d, rd, "protocolSupportEnumeration", SAMLP_NS);
        for c in e.sp_signing { write_key_descriptor(d, rd, "signing", c, none); }
        for c in e.sp_encryption { write_key_descriptor(d, rd, "encryption", c, e.encryption_methods); }
        write_endpoints(d, rd, e, ROLE_SP, EP_SLO, "SingleLogoutService");
        write_formats(d, rd, e.sp_name_id_formats);
        write_endpoints(d, rd, e, ROLE_SP, EP_ACS, "AssertionConsumerService");
    }
    return ed;
}

// e's metadata, appended to out.
fn write_metadata(e: const Entity&, out: u8[>..]&) -> i64 {
    var d = xml::Doc { .. };
    let ed = build_metadata(d, e);
    if ed < 0 { return ERR_ARG; }
    xml::write_document(d, out);
    return OK;
}

// e's metadata signed by s (an ID made when e has none), appended to out.
fn write_metadata_signed(e: const Entity&, s: const Signer&, out: u8[>..]&) -> i64 {
    var d = xml::Doc { .. };
    let ed = build_metadata(d, e);
    if ed < 0 { return ERR_ARG; }
    if e.id.len == 0 { xml::set_attr(d, ed, "ID", new_id()); }
    let r = sign_element(d, ed, s);
    if r != OK { return r; }
    xml::write_document(d, out);
    return OK;
}
