// mail.dkim: DKIM signatures (RFC 6376), signed and verified, with
// RSA-SHA256 and Ed25519-SHA256 (RFC 8463), and RSA-SHA1 verified only
// when asked for (RFC 8301 retires it).
//
//     let key, ke = dkim::parse_key(pem_text);            // RSA or Ed25519, PEM or a base64 seed
//     var o = dkim::SignOptions { .. };
//     o.domain.append("example.com");
//     o.selector.append("mail2026");
//     var out: u8[>..] = [];
//     let e = dkim::sign(msg, key, o, out);               // DKIM-Signature: ... then msg
//
//     var res: dkim::Result[>..] = [];
//     let v = dkim::verify(msg, res) { domain, selector, rec =>
//         rec.append(record_for(domain, selector));        // the key's TXT record, "" for none
//     };
//     // or dkim::verify_record(msg, record, res), dkim::verify_dns(msg, "", res)
//
// Messages are RFC 5322 bytes with CRLF line ends; bare LFs are made CRLF
// first, as SMTP would send them (RFC 6376 §5.3). The signature header is
// written folded at 78 columns, b= last, and the hash covers it as it is
// written. By default the header fields signed are those of DEFAULT_HEADERS
// the message has, each instance once, and From once more ("over-signed"),
// so that a From added on the way breaks the signature.
//
// Verifying checks every DKIM-Signature field (up to max_signatures), each
// on its own: its tag-list (§3.2: duplicate tags, the required v a b bh d
// h s), the i= and d= alignment, x= against the time, then the key record
// (v=DKIM1, k=, h=, s=, t=s, p= empty for a revoked key), the body hash
// with l=, and the signature. Header fields are taken bottom-up for each
// name in h=, a name with no instance left adding nothing. Each Result has
// a status:
//
//   mail::OK               pass
//   mail::ERR_SIGNATURE    fail: the signature, or the body hash (body_mismatch), or x= passed
//   mail::ERR_KEY          the key record: malformed, revoked, the wrong type, too small
//   mail::ERR_DNS          no key record came back
//   mail::ERR_FORMAT       the DKIM-Signature field does not parse or is inconsistent
//   mail::ERR_UNSUPPORTED  an algorithm, canonicalization or query type not done here;
//                          rsa-sha1 unless allow_sha1
//
// and reason says which check failed.

namespace dkim;

import std;
import os;
import base64;
import encoding.asn1;
import crypto.bignum;
import crypto.bignum.rsa;
import crypto.bignum.ed25519;
import crypto.bignum.sha1;
import crypto.bignum.sha256;
import crypto.bignum.hmac;
import crypto.x509;
import crypto.x509.keys;
import dns;
import dns.msg;
import dns.client;
import mail;
import mail.address;
import mail.message;

// Canonicalizations (§3.4).
let SIMPLE:  i64 = 0;
let RELAXED: i64 = 1;

// Signature algorithms.
let ALG_RSA_SHA256:     i64 = 0;
let ALG_ED25519_SHA256: i64 = 1;
let ALG_RSA_SHA1:       i64 = 2;   // verified only with allow_sha1

// A key record's k= (PublicKey.kind).
let REC_RSA:     i64 = 1;
let REC_ED25519: i64 = 2;

// SignOptions.body_length: l= with the whole canonical body's length.
let BODY_ALL: i64 = -2;

let MAX_LINE: i64 = 78;            // where the signature header folds

// The fields signed by default, when the message has them (with From, which
// it must have).
let DEFAULT_HEADERS = ["from", "to", "cc", "subject", "date", "message-id", "reply-to", "mime-version",
                       "content-type", "in-reply-to", "references"];

struct SignOptions {
    domain:        u8[..253]  = [],      // d=
    selector:      u8[..253]  = [],      // s=
    headers:       u8[..1000] = [],      // h=: names joined by ':', "" for the default list
    oversign_from: bool       = true,    // with the default list: "from" once more
    header_canon:  i64        = RELAXED,
    body_canon:    i64        = RELAXED,
    identity:      u8[..320]  = [],      // i=, "" for none: "@domain" or "user@sub.domain"
    timestamp:     i64        = -1,      // t=, unix seconds; -1 for none
    expire:        i64        = -1,      // x=; -1 for none
    body_length:   i64        = -1,      // l=: -1 for none, BODY_ALL, or the bytes of the canonical body signed
}

struct VerifyOptions {
    allow_sha1:     bool = false,       // rsa-sha1 (RFC 8301 says no)
    min_rsa_bits:   i64  = 1024,        // RFC 8301's floor; smaller keys are ERR_KEY
    now:            i64  = -1,          // unix seconds for x=; -1 for the clock
    max_signatures: i64  = 8,           // DKIM-Signature fields checked, the first ones
}

struct Result {
    status:        i64       = 0,       // mail::OK or an ERR_* (above)
    d:             u8[..253] = [],
    s:             u8[..253] = [],
    i:             u8[..320] = [],      // i=, or "@" and d= when there is none
    alg:           i64       = -1,      // ALG_*, -1 when a= is not one of them
    body_length:   i64       = -1,      // l= when the signature has one: bytes after it are not signed
    body_mismatch: bool      = false,   // ERR_SIGNATURE because bh= is not the body's hash
    testing:       bool      = false,   // the key record's t=y
    reason:        u8[..96]  = [],
}

// --- Small things ----------------------------------------------------------------

struct Span { pos: i64 = 0, end: i64 = 0 }

fn is_wsp(c: u8) -> bool { c == ' ' || c == '\t' }
fn is_fws(c: u8) -> bool { c == ' ' || c == '\t' || c == '\r' || c == '\n' }

fn lower(c: u8) -> u8 { if c >= 'A' && c <= 'Z' { c + 32 } else { c } }

// s with FWS cut from both ends.
fn trim_fws(s: const u8[:]) -> Span {
    var a = 0;
    var b = s.len;
    while a < b && is_fws(s[a]) { a++; }
    while b > a && is_fws(s[b - 1]) { b--; }
    return Span { pos: a, end: b };
}

fn trimmed(s: const u8[:]) -> const u8[:] {
    let t = trim_fws(s);
    return s[t.pos..t.end];
}

// dst = s, cut to max bytes.
fn keep<A>(dst: A&, s: const u8[:], max: i64) {
    dst.clear();
    dst.append(s[.. ::min(s.len, max)]);
}

fn set_reason(r: Result&, why: const u8[:]) { keep(r.reason, why, 96); }

// A decimal number of 1 to 76 digits (l= may have that many); one too large
// for an i64 is saturated at 4e18, more than any body or date.
fn number(s: const u8[:]) -> i64, bool {
    if s.len == 0 || s.len > 76 { return 0, false; }
    var v: i64 = 0;
    for c in s {
        if c < '0' || c > '9' { return 0, false; }
        if v < 400000000000000000 { v = v * 10 + (c - '0'); } else { v = 4000000000000000000; }
    }
    return v, true;
}

// Base64 with FWS anywhere in it (b=, bh=, p=); false if it does not decode.
fn b64(out: u8[>..]&, s: const u8[:]) -> bool {
    var t: u8[>..] = [];
    for c in s { if !is_fws(c) { t.push(c); } }
    return base64::decode(out, t);
}

// Whether domain a is b or a subdomain of it, without case.
fn within(a: const u8[:], b: const u8[:]) -> bool {
    if b.len == 0 || a.len < b.len { return false; }
    if !mail::eq_fold(a[a.len - b.len..], b) { return false; }
    return a.len == b.len || a[a.len - b.len - 1] == '.';
}

// The text of a domain or selector: letters, digits, '-', '_' and dots.
fn name_ok(s: const u8[:]) -> bool {
    if s.len == 0 || s[0] == '.' || s[s.len - 1] == '.' { return false; }
    for c in s {
        let ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                 c == '-' || c == '_' || c == '.';
        if !ok { return false; }
    }
    return true;
}

// --- The message -------------------------------------------------------------------

// A header field: from pos to end (after its CRLF, or the message's end),
// the name before colon (-1 when the line has none).
struct Field { pos: i64 = 0, colon: i64 = -1, end: i64 = 0 }

// Whether msg has a LF without a CR before it.
fn has_bare_lf(msg: const u8[:]) -> bool {
    for i in msg.len { if msg[i] == '\n' && (i == 0 || msg[i - 1] != '\r') { return true; } }
    return false;
}

// msg with every bare LF made CRLF, appended to out.
fn to_crlf(out: u8[>..]&, msg: const u8[:]) {
    for i in msg.len {
        if msg[i] == '\n' && (i == 0 || msg[i - 1] != '\r') { out.push('\r'); }
        out.push(msg[i]);
    }
}

// The header's fields, in order, and where the body starts (after the
// empty line; msg.len when there is none).
fn split_message(msg: const u8[:], fields: Field[>..]&) -> i64 {
    fields.clear();
    var i = 0;
    while i < msg.len {
        var e = i;
        while e < msg.len && msg[e] != '\n' { e++; }
        if e < msg.len { e++; }
        if e - i == 2 && msg[i] == '\r' { return e; }          // the empty line
        if e - i == 1 && msg[i] == '\n' { return e; }
        if is_wsp(msg[i]) && fields.len > 0 {
            fields[fields.len - 1].end = e;                    // a continuation
        } else {
            var c = -1;
            for k in i..e { if msg[k] == ':' { c = k; break; } }
            fields.push(Field { pos: i, colon: c, end: e });
        }
        i = e;
    }
    return msg.len;
}

// A field's name, without the WSP before its colon.
fn field_name(msg: const u8[:], f: Field) -> const u8[:] {
    if f.colon < 0 { return ""; }
    var e = f.colon;
    while e > f.pos && is_wsp(msg[e - 1]) { e--; }
    return msg[f.pos..e];
}

// A field without its final CRLF.
fn field_text(msg: const u8[:], f: Field) -> const u8[:] {
    var e = f.end;
    if e > f.pos && msg[e - 1] == '\n' { e--; }
    if e > f.pos && msg[e - 1] == '\r' { e--; }
    return msg[f.pos..e];
}

// --- Canonicalization (§3.4) ---------------------------------------------------------

// A header field (without its final CRLF) as the canonicalization has it,
// appended to out, also without the CRLF. Relaxed: the name in lower case,
// the value unfolded, WSP runs made one space, none at either end of it.
fn canon_header(out: u8[>..]&, field: const u8[:], canon: i64) {
    if canon == SIMPLE { out.append(field); return; }
    var colon = -1;
    for k in field.len { if field[k] == ':' { colon = k; break; } }
    if colon < 0 { colon = field.len; }
    var ne = colon;
    while ne > 0 && is_wsp(field[ne - 1]) { ne--; }
    for k in ne { out.push(lower(field[k])); }
    if colon == field.len { return; }
    out.push(':');
    var space = false;
    var any = false;
    for k in colon + 1..field.len {
        let c = field[k];
        if c == '\r' || c == '\n' { continue; }
        if is_wsp(c) { space = true; continue; }
        if space && any { out.push(' '); }
        space = false;
        any = true;
        out.push(c);
    }
}

// The body as the canonicalization has it, appended to out. Simple: the
// empty lines at the end made one CRLF (an empty body is CRLF). Relaxed:
// WSP runs made one space, none at the ends of lines, no empty lines at the
// end (an empty body stays empty); a last line without CRLF gets one.
fn canon_body(out: u8[>..]&, body: const u8[:], canon: i64) {
    if canon == SIMPLE {
        var e = body.len;
        while e >= 2 && body[e - 2] == '\r' && body[e - 1] == '\n' { e -= 2; }
        out.append(body[..e]);
        out.append("\r\n");
        return;
    }
    let mark = out.len;
    var keep_to = mark;                  // after the last line that is not empty
    var i = 0;
    while i < body.len {
        var e = i;
        while e < body.len && !(body[e] == '\r' && e + 1 < body.len && body[e + 1] == '\n') { e++; }
        var space = false;
        var any = false;
        for k in i..e {
            let c = body[k];
            if is_wsp(c) { space = true; continue; }
            if space { out.push(' '); }
            space = false;
            any = true;
            out.push(c);
        }
        out.append("\r\n");
        if any { keep_to = out.len; }
        i = if e < body.len { e + 2 } else { e };
    }
    out.resize(keep_to);
}

// The names of an h= list (or a signer's), split at ':' and trimmed; false
// if one is empty.
fn split_names(text: const u8[:], names: Span[>..]&) -> bool {
    names.clear();
    var i = 0;
    loop {
        var e = i;
        while e < text.len && text[e] != ':' { e++; }
        let t = trim_fws(text[i..e]);
        if t.pos == t.end { return false; }
        for k in i + t.pos..i + t.end { if is_fws(text[k]) { return false; } }
        names.push(Span { pos: i + t.pos, end: i + t.end });
        if e >= text.len { break; }
        i = e + 1;
    }
    return true;
}

// The header fields that h= names, appended to out canonicalized, each with
// its CRLF: for each name, the last instance not yet taken (§5.4.2), none
// when they are all taken. skip is the signature's own field.
fn signed_headers(out: u8[>..]&, msg: const u8[:], fields: const Field[:], htext: const u8[:], names: const Span[:],
                  skip: i64, canon: i64) {
    var used: bool[>..] = [];
    used.resize(fields.len, false);
    for n in names {
        let want = htext[n.pos..n.end];
        var k = fields.len - 1;
        while k >= 0 {
            if !used[k] && k != skip && mail::eq_fold(field_name(msg, fields[k]), want) {
                used[k] = true;
                canon_header(out, field_text(msg, fields[k]), canon);
                out.append("\r\n");
                break;
            }
            k--;
        }
    }
}

// --- Tag lists (§3.2) ----------------------------------------------------------------

// A tag=value: its name and value (FWS cut from both) in the text parsed,
// and eq, the '=', and stop, the ';' after the value or the end.
struct Tag { name: Span = Span { .. }, value: Span = Span { .. }, eq: i64 = 0, stop: i64 = 0 }

// The tags of a tag-list into tags. ERR_FORMAT for a spec without '=', a
// name that is not ALPHA *(ALPHA / DIGIT / "_"), a control character in a
// value, or a name twice. Empty specs (";;", a ';' at the end) are passed
// over.
fn parse_tags(text: const u8[:], tags: Tag[>..]&) -> i64 {
    tags.clear();
    var i = 0;
    while i <= text.len {
        var e = i;
        while e < text.len && text[e] != ';' { e++; }
        let spec = text[i..e];
        let t = trim_fws(spec);
        if t.pos < t.end {
            var eq = -1;
            for k in t.pos..t.end { if spec[k] == '=' { eq = k; break; } }
            if eq < 0 { return mail::ERR_FORMAT; }
            let ns = trim_fws(spec[..eq]);
            let vs = trim_fws(spec[eq + 1..]);
            let name = spec[ns.pos..ns.end];
            if name.len == 0 { return mail::ERR_FORMAT; }
            for k in name.len {
                let c = name[k];
                let alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
                if !(alpha || (k > 0 && ((c >= '0' && c <= '9') || c == '_'))) { return mail::ERR_FORMAT; }
            }
            for k in eq + 1 + vs.pos..eq + 1 + vs.end {
                let c = spec[k];
                if (c < 0x20 && !is_fws(c)) || c == 0x7f { return mail::ERR_FORMAT; }
            }
            for g in tags { if text[g.name.pos..g.name.end] == name { return mail::ERR_FORMAT; } }
            tags.push(Tag { name: Span { pos: i + ns.pos, end: i + ns.end },
                            value: Span { pos: i + eq + 1 + vs.pos, end: i + eq + 1 + vs.end },
                            eq: i + eq, stop: e });
        }
        i = e + 1;
    }
    return mail::OK;
}

// The tag of that name: its index, -1 if there is none.
fn find_tag(text: const u8[:], tags: const Tag[:], name: const u8[:]) -> i64 {
    for k in tags.len { if text[tags[k].name.pos..tags[k].name.end] == name { return k; } }
    return -1;
}

// A tag's value, "" and false when there is no such tag.
fn tag_value(text: const u8[:], tags: const Tag[:], name: const u8[:]) -> const u8[:], bool {
    let k = find_tag(text, tags, name);
    if k < 0 { return "", false; }
    return text[tags[k].value.pos..tags[k].value.end], true;
}

// Whether a ':'-separated list (FWS around the items) has item, without case.
fn list_has(list: const u8[:], item: const u8[:]) -> bool {
    var i = 0;
    loop {
        var e = i;
        while e < list.len && list[e] != ':' { e++; }
        if mail::eq_fold(trimmed(list[i..e]), item) { return true; }
        if e >= list.len { return false; }
        i = e + 1;
    }
}

// --- Keys ------------------------------------------------------------------------------

// A public key from a key record (§3.6.1).
struct PublicKey {
    kind:    i64                  = 0,
    rsa:     bignum::RsaPublicKey = bignum::RsaPublicKey { n: [], e: [] },
    ed:      u8[..32]             = [],
    sha1:    bool                 = true,      // h= allows it (or there is no h=)
    sha256:  bool                 = true,
    testing: bool                 = false,     // t=y
    strict:  bool                 = false,     // t=s: i= must be d= itself
}

// An RSA public key from SubjectPublicKeyInfo DER, or the bare RSAPublicKey
// some publish. ERR_KEY when neither parses or rsa_public_from refuses the
// numbers (fewer than 1024 bits, say); the bool says whether it parsed.
fn rsa_public_of(der: const u8[:]) -> bignum::RsaPublicKey, i64, bool {
    let none = bignum::RsaPublicKey { n: [], e: [] };
    let top, ok = asn1::parse(der);
    if !ok || top.end != der.len { return none, mail::ERR_KEY, false; }
    let f, okf = asn1::children_of(der, top, asn1::SEQUENCE);
    if !okf || f.len != 2 { return none, mail::ERR_KEY, false; }
    var rsapub: u8[>..] = [];
    if f[0].tag == asn1::SEQUENCE {
        let kind, bits, oks = x509::spki_of(der, top);
        if !oks || kind != x509::KEY_RSA { return none, mail::ERR_KEY, false; }
        let b, unused, okb = asn1::read_bits(der, bits);
        if !okb || unused != 0 { return none, mail::ERR_KEY, false; }
        rsapub.append(b);
    } else {
        rsapub.append(der);
    }
    let t2, ok2 = asn1::parse(rsapub);
    if !ok2 || t2.end != rsapub.len { return none, mail::ERR_KEY, false; }
    let p, okp = asn1::children_of(rsapub, t2, asn1::SEQUENCE);
    if !okp || p.len != 2 { return none, mail::ERR_KEY, false; }
    let n, okn = asn1::read_uint(rsapub, p[0]);
    let e, oke = asn1::read_uint(rsapub, p[1]);
    if !okn || !oke { return none, mail::ERR_KEY, false; }
    let pub, okpub = bignum::rsa_public_from(bignum::from_bytes_be(n), bignum::from_bytes_be(e));
    if !okpub { return none, mail::ERR_KEY, true; }
    return pub, mail::OK, true;
}

// A key record into k: mail::OK, or ERR_KEY with the reason in r.
fn parse_record(rec: const u8[:], k: PublicKey&, r: Result&) -> i64 {
    var tags: Tag[>..] = [];
    if parse_tags(rec, tags) != mail::OK { set_reason(r, "key record: malformed tag-list"); return mail::ERR_KEY; }
    let v, hasv = tag_value(rec, tags, "v");
    if hasv && (find_tag(rec, tags, "v") != 0 || v != "DKIM1") {
        set_reason(r, "key record: v= is not DKIM1, first");
        return mail::ERR_KEY;
    }
    let h, hash = tag_value(rec, tags, "h");
    if hash {
        k.sha1 = list_has(h, "sha1");
        k.sha256 = list_has(h, "sha256");
    }
    let kt, hask = tag_value(rec, tags, "k");
    if !hask || mail::eq_fold(kt, "rsa") { k.kind = REC_RSA; }
    else if mail::eq_fold(kt, "ed25519") { k.kind = REC_ED25519; }
    else { set_reason(r, "key record: unknown k="); return mail::ERR_KEY; }
    let s, hass = tag_value(rec, tags, "s");
    if hass && !list_has(s, "*") && !list_has(s, "email") {
        set_reason(r, "key record: s= is not for email");
        return mail::ERR_KEY;
    }
    let t, hast = tag_value(rec, tags, "t");
    if hast {
        k.testing = list_has(t, "y");
        k.strict = list_has(t, "s");
    }
    let p, hasp = tag_value(rec, tags, "p");
    if !hasp { set_reason(r, "key record: no p="); return mail::ERR_KEY; }
    if p.len == 0 { set_reason(r, "key revoked (p= empty)"); return mail::ERR_KEY; }
    var der: u8[>..] = [];
    if !b64(der, p) { set_reason(r, "key record: p= is not base64"); return mail::ERR_KEY; }
    if k.kind == REC_ED25519 {
        if der.len != 32 { set_reason(r, "key record: an Ed25519 p= is not 32 bytes"); return mail::ERR_KEY; }
        keep(k.ed, der, 32);
        return mail::OK;
    }
    let pub, e, parsed = rsa_public_of(der);
    if e != mail::OK {
        set_reason(r, if parsed { "key record: RSA key refused (under 1024 bits?)" } else { "key record: p= is not an RSA key" });
        return mail::ERR_KEY;
    }
    k.rsa = pub;
    return mail::OK;
}

// A signing key: an RSA or Ed25519 private key in PEM (PKCS #8, or PKCS #1
// "RSA PRIVATE KEY"), DER, or an Ed25519 seed in base64 (dkimpy's and
// opendkim's form). ERR_KEY when it is none of these, or RSA under 1024 bits.
fn parse_key(text: const u8[:]) -> x509::PrivateKey, i64 {
    var k = x509::empty_key();
    var ok = false;
    var pem = false;
    for i in text.len { if text[i..].starts_with("-----BEGIN") { pem = true; break; } }
    if pem {
        let pk, okp = x509::parse_private_key_pem(text);
        k = pk;
        ok = okp;
    } else {
        var raw: u8[>..] = [];
        if b64(raw, text) && raw.len == 32 {
            return key_from_seed(raw);
        }
        let pk, okd = x509::parse_private_key(if raw.len > 0 { raw[..] } else { text });
        k = pk;
        ok = okd;
    }
    if !ok || (k.kind != x509::KEY_RSA && k.kind != x509::KEY_ED25519) { return x509::empty_key(), mail::ERR_KEY; }
    if k.kind == x509::KEY_RSA && bignum::rsa_bits(k.rsa) < 1024 { return x509::empty_key(), mail::ERR_KEY; }
    return k, mail::OK;
}

// An Ed25519 key from its 32-byte seed.
fn key_from_seed(seed: const u8[:]) -> x509::PrivateKey, i64 {
    var k = x509::empty_key();
    if seed.len != 32 { return k, mail::ERR_KEY; }
    for i in 32 { k.seed[i] = seed[i]; }
    k.kind = x509::KEY_ED25519;
    return k, mail::OK;
}

// The key's TXT record, appended to out: "v=DKIM1; k=rsa; p=<SPKI>" or
// "v=DKIM1; k=ed25519; p=<the 32 bytes>", in base64.
fn key_record(key: const x509::PrivateKey&, out: u8[>..]&) -> i64 {
    if key.kind == x509::KEY_RSA {
        out.append("v=DKIM1; k=rsa; p=");
        base64::encode(out, x509::marshal_public_key(key));
        return mail::OK;
    }
    if key.kind == x509::KEY_ED25519 {
        out.append("v=DKIM1; k=ed25519; p=");
        base64::encode(out, bignum::ed25519_public(key.seed));
        return mail::OK;
    }
    return mail::ERR_KEY;
}

// --- Signing ---------------------------------------------------------------------------

// The signature header's writer: pieces after a space, or a fold where the
// line would pass MAX_LINE.
struct Folder { line: i64 = 0 }

fn put(out: u8[>..]&, f: Folder&, piece: const u8[:], space: bool) {
    let extra = if space { 1 } else { 0 };
    if f.line + extra + piece.len > MAX_LINE && f.line > 1 {
        out.append("\r\n ");
        f.line = 1;
    } else if space {
        out.push(' ');
        f.line++;
    }
    out.append(piece);
    f.line += piece.len;
}

fn alg_name(alg: i64) -> const u8[:] {
    if alg == ALG_ED25519_SHA256 { return "ed25519-sha256"; }
    if alg == ALG_RSA_SHA1 { return "rsa-sha1"; }
    return "rsa-sha256";
}

fn canon_name(c: i64) -> const u8[:] { if c == SIMPLE { "simple" } else { "relaxed" } }

// The h= list the signer uses: o.headers as given, or the default names the
// message has (each as often as it has them) and From once more.
fn header_list(msg: const u8[:], fields: const Field[:], o: const SignOptions&, out: u8[>..]&) -> i64 {
    if o.headers.len > 0 {
        var names: Span[>..] = [];
        if !split_names(o.headers, names) { return mail::ERR_ARG; }
        var from = false;
        for n in names {
            if mail::eq_fold(o.headers[n.pos..n.end], "from") { from = true; }
            if out.len > 0 { out.push(':'); }
            out.append(o.headers[n.pos..n.end]);
        }
        return if from { mail::OK } else { mail::ERR_ARG };
    }
    var froms = 0;
    for name in DEFAULT_HEADERS {
        for f in fields {
            if mail::eq_fold(field_name(msg, f), name) {
                if out.len > 0 { out.push(':'); }
                out.append(name);
                if name == "from" { froms++; }
            }
        }
    }
    if froms == 0 { return mail::ERR_HEADER; }
    if o.oversign_from { out.append(":from"); }
    return mail::OK;
}

fn sign_check(o: const SignOptions&) -> i64 {
    if !name_ok(o.domain) || !name_ok(o.selector) { return mail::ERR_ARG; }
    if (o.header_canon != SIMPLE && o.header_canon != RELAXED) || (o.body_canon != SIMPLE && o.body_canon != RELAXED) {
        return mail::ERR_ARG;
    }
    if o.identity.len > 0 {
        var at = -1;
        for k in o.identity.len {
            let c = o.identity[k];
            if c == '@' { at = k; }
            if c <= ' ' || c >= 0x7f || c == ';' { return mail::ERR_ARG; }
        }
        if at < 0 || !within(o.identity[at + 1..], o.domain) { return mail::ERR_ARG; }
    }
    if o.timestamp < -1 || o.expire < -1 || o.body_length < BODY_ALL { return mail::ERR_ARG; }
    if o.expire >= 0 && o.timestamp >= 0 && o.expire <= o.timestamp { return mail::ERR_ARG; }
    return mail::OK;
}

// The DKIM-Signature field for msg, appended to out with its CRLF, to go
// before msg's first line. ERR_ARG for options that cannot be written (a
// domain or selector with other than letters, digits, '-', '_' and '.', an
// i= outside d=, x= not after t=, l= past the body, h= without From),
// ERR_HEADER when the message has no From, ERR_KEY for a key that is not
// RSA of 1024 bits or more, or Ed25519.
fn signature(msg_in: const u8[:], key: const x509::PrivateKey&, o: SignOptions, out: u8[>..]&) -> i64 {
    var norm: u8[>..] = [];
    if has_bare_lf(msg_in) { to_crlf(norm, msg_in); }
    let msg = if norm.len > 0 { norm[..] } else { msg_in };
    return sign_crlf(msg, key, o, out);
}

fn sign_crlf(msg: const u8[:], key: const x509::PrivateKey&, o: const SignOptions&, out: u8[>..]&) -> i64 {
    var rc = sign_check(o);
    if rc != mail::OK { return rc; }
    var alg = ALG_RSA_SHA256;
    if key.kind == x509::KEY_ED25519 { alg = ALG_ED25519_SHA256; }
    else if key.kind != x509::KEY_RSA || bignum::rsa_bits(key.rsa) < 1024 { return mail::ERR_KEY; }

    var fields: Field[>..] = [];
    let body_at = split_message(msg, fields);
    var hlist: u8[>..] = [];
    rc = header_list(msg, fields, o, hlist);
    if rc != mail::OK { return rc; }

    // The body hash.
    var body: u8[>..] = [];
    canon_body(body, msg[body_at..], o.body_canon);
    var blen = -1;
    if o.body_length == BODY_ALL { blen = body.len; }
    else if o.body_length >= 0 {
        if o.body_length > body.len { return mail::ERR_ARG; }
        blen = o.body_length;
    }
    let bh = bignum::sha256(if blen >= 0 { body[..blen] } else { body[..] });

    // The field, b= empty.
    let mark = out.len;
    var f = Folder { line: 15 };
    out.append("DKIM-Signature:");
    put(out, f, "v=1;", true);
    put(out, f, str("a=", alg_name(alg), ";"), true);
    put(out, f, str("c=", canon_name(o.header_canon), "/", canon_name(o.body_canon), ";"), true);
    put(out, f, str("d=", o.domain, ";"), true);
    put(out, f, str("s=", o.selector, ";"), true);
    if o.identity.len > 0 { put(out, f, str("i=", o.identity, ";"), true); }
    if blen >= 0 { put(out, f, str("l=", blen, ";"), true); }
    if o.timestamp >= 0 { put(out, f, str("t=", o.timestamp, ";"), true); }
    if o.expire >= 0 { put(out, f, str("x=", o.expire, ";"), true); }
    var names: Span[>..] = [];
    split_names(hlist, names);
    for k in names.len {
        let n = hlist[names[k].pos..names[k].end];
        let last = k == names.len - 1;
        let piece = str(if k == 0 { "h=" } else { "" }, n, if last { ";" } else { ":" });
        put(out, f, piece, k == 0);
    }
    var bhs: u8[>..] = [];
    base64::encode(bhs, bh);
    put(out, f, str("bh=", bhs, ";"), true);
    put(out, f, "b=", true);

    // What is signed: the fields h= names, then this one as it stands.
    var data: u8[>..] = [];
    signed_headers(data, msg, fields, hlist, names, -1, o.header_canon);
    canon_header(data, out[mark..], o.header_canon);
    let digest = bignum::sha256(data);
    var sig: u8[>..] = [];
    if alg == ALG_ED25519_SHA256 {
        sig.append(bignum::ed25519_sign(key.seed, digest));
    } else {
        let s, ok = bignum::rsa_sign_pkcs1_digest(key.rsa, digest, 256);
        if !ok { out.resize(mark); return mail::ERR_KEY; }
        sig.append(s);
    }
    var bs: u8[>..] = [];
    base64::encode(bs, sig);
    var i = 0;
    while i < bs.len {
        if f.line >= MAX_LINE { out.append("\r\n "); f.line = 1; }
        let n = ::min(bs.len - i, MAX_LINE - f.line);
        out.append(bs[i..i + n]);
        f.line += n;
        i += n;
    }
    out.append("\r\n");
    return mail::OK;
}

// msg signed: its DKIM-Signature field, then msg (bare LFs made CRLF),
// appended to out. On an error out is as it was.
fn sign(msg_in: const u8[:], key: const x509::PrivateKey&, o: SignOptions, out: u8[>..]&) -> i64 {
    var norm: u8[>..] = [];
    if has_bare_lf(msg_in) { to_crlf(norm, msg_in); }
    let msg = if norm.len > 0 { norm[..] } else { msg_in };
    let mark = out.len;
    let rc = sign_crlf(msg, key, o, out);
    if rc != mail::OK { out.resize(mark); return rc; }
    out.append(msg);
    return mail::OK;
}

// A message built with mail.message, written (mail::write) and signed.
fn sign_msg(m: mail::Msg&, key: const x509::PrivateKey&, o: SignOptions, out: u8[>..]&) -> i64 {
    var raw: u8[>..] = [];
    let rc = mail::write(m, raw);
    if rc != mail::OK { return rc; }
    return sign(raw, key, o, out);
}

// --- Verifying -------------------------------------------------------------------------

// A DKIM-Signature field's tags, checked (§6.1.1): what the rest needs.
struct Sig {
    field:  i64  = 0,                   // its index in the fields
    vpos:   i64  = 0,                   // where its value (after the colon) starts in msg
    alg:    i64  = 0,
    hcanon: i64  = SIMPLE,
    bcanon: i64  = SIMPLE,
    hash:   i64  = 256,                 // bignum's hash id
    l:      i64  = -1,
    b:      Span = Span { .. },         // in msg
    bh:     Span = Span { .. },
    h:      Span = Span { .. },
    beq:    i64  = 0,                   // b='s '=' and what ends its value, in msg
    bstop:  i64  = 0,
}

fn now_of(o: VerifyOptions) -> i64 { if o.now >= 0 { o.now } else { time_ns() / 1000000000 } }

fn check_sig(msg: const u8[:], fields: const Field[:], fi: i64, o: VerifyOptions, sp: Sig&, r: Result&) -> i64 {
    let f = fields[fi];
    sp.field = fi;
    sp.vpos = f.colon + 1;
    let text = field_text(msg, f)[f.colon + 1 - f.pos..];
    var tags: Tag[>..] = [];
    if parse_tags(text, tags) != mail::OK { set_reason(r, "malformed tag-list"); return mail::ERR_FORMAT; }
    let d, hasd = tag_value(text, tags, "d");
    let s, hass = tag_value(text, tags, "s");
    keep(r.d, d, 253);
    keep(r.s, s, 253);
    for req in ["v", "a", "b", "bh", "d", "h", "s"] {
        if find_tag(text, tags, req) < 0 { set_reason(r, str("no ", req, "= tag")); return mail::ERR_FORMAT; }
    }
    let v, hv = tag_value(text, tags, "v");
    if v != "1" { set_reason(r, "v= is not 1"); return mail::ERR_FORMAT; }
    if !name_ok(d) || !name_ok(s) { set_reason(r, "d= or s= is not a domain name"); return mail::ERR_FORMAT; }

    let a, ha = tag_value(text, tags, "a");
    if mail::eq_fold(a, "rsa-sha256") { sp.alg = ALG_RSA_SHA256; }
    else if mail::eq_fold(a, "ed25519-sha256") { sp.alg = ALG_ED25519_SHA256; }
    else if mail::eq_fold(a, "rsa-sha1") { sp.alg = ALG_RSA_SHA1; sp.hash = bignum::HASH_SHA1; }
    else { set_reason(r, "unknown a= algorithm"); return mail::ERR_UNSUPPORTED; }
    r.alg = sp.alg;

    let c, hc = tag_value(text, tags, "c");
    if hc {
        var slash = -1;
        for k in c.len { if c[k] == '/' { slash = k; break; } }
        let hs = if slash < 0 { c } else { c[..slash] };
        let bs = if slash < 0 { "simple" } else { c[slash + 1..] };
        if mail::eq_fold(hs, "relaxed") { sp.hcanon = RELAXED; }
        else if !mail::eq_fold(hs, "simple") { set_reason(r, "unknown c= canonicalization"); return mail::ERR_UNSUPPORTED; }
        if mail::eq_fold(bs, "relaxed") { sp.bcanon = RELAXED; }
        else if !mail::eq_fold(bs, "simple") { set_reason(r, "unknown c= canonicalization"); return mail::ERR_UNSUPPORTED; }
    }
    let q, hq = tag_value(text, tags, "q");
    if hq && !list_has(q, "dns/txt") { set_reason(r, "q= has no dns/txt"); return mail::ERR_UNSUPPORTED; }

    let i, hi = tag_value(text, tags, "i");
    if hi {
        keep(r.i, i, 320);
        var at = -1;
        for k in i.len { if i[k] == '@' { at = k; } }
        if at < 0 || !within(i[at + 1..], d) { set_reason(r, "i= is not within d="); return mail::ERR_FORMAT; }
    } else {
        keep(r.i, str("@", d), 320);
    }

    let hk = find_tag(text, tags, "h");
    let h = text[tags[hk].value.pos..tags[hk].value.end];
    var names: Span[>..] = [];
    if !split_names(h, names) { set_reason(r, "h= has an empty name"); return mail::ERR_FORMAT; }
    var from = false;
    for n in names { if mail::eq_fold(h[n.pos..n.end], "from") { from = true; } }
    if !from { set_reason(r, "h= does not sign From"); return mail::ERR_FORMAT; }
    sp.h = Span { pos: sp.vpos + tags[hk].value.pos, end: sp.vpos + tags[hk].value.end };

    let l, hl = tag_value(text, tags, "l");
    if hl {
        let n, ok = number(l);
        if !ok { set_reason(r, "l= is not a number"); return mail::ERR_FORMAT; }
        sp.l = n;
        r.body_length = n;
    }
    let t, ht = tag_value(text, tags, "t");
    var tv: i64 = -1;
    if ht {
        let n, ok = number(t);
        if !ok { set_reason(r, "t= is not a number"); return mail::ERR_FORMAT; }
        tv = n;
    }
    let x, hx = tag_value(text, tags, "x");
    if hx {
        let n, ok = number(x);
        if !ok { set_reason(r, "x= is not a number"); return mail::ERR_FORMAT; }
        if tv >= 0 && n <= tv { set_reason(r, "x= is not after t="); return mail::ERR_FORMAT; }
        if n < now_of(o) { set_reason(r, "signature expired (x=)"); return mail::ERR_SIGNATURE; }
    }
    let bk = find_tag(text, tags, "b");
    sp.b = Span { pos: sp.vpos + tags[bk].value.pos, end: sp.vpos + tags[bk].value.end };
    sp.beq = sp.vpos + tags[bk].eq;
    sp.bstop = sp.vpos + tags[bk].stop;
    let bhk = find_tag(text, tags, "bh");
    sp.bh = Span { pos: sp.vpos + tags[bhk].value.pos, end: sp.vpos + tags[bhk].value.end };

    if sp.alg == ALG_RSA_SHA1 && !o.allow_sha1 { set_reason(r, "rsa-sha1 refused (RFC 8301)"); return mail::ERR_UNSUPPORTED; }
    return mail::OK;
}

// The rest, once the key record is in hand (§6.1.2, §6.1.3).
fn check_with_key(msg: const u8[:], fields: const Field[:], body_at: i64, o: VerifyOptions, sp: const Sig&,
                  rec: const u8[:], r: Result&) -> i64 {
    if trimmed(rec).len == 0 { set_reason(r, "no key record"); return mail::ERR_DNS; }
    var k = PublicKey { .. };
    let ke = parse_record(rec, k, r);
    if ke != mail::OK { return ke; }
    r.testing = k.testing;
    let want = if sp.alg == ALG_ED25519_SHA256 { REC_ED25519 } else { REC_RSA };
    if k.kind != want { set_reason(r, "key record: k= does not match a="); return mail::ERR_KEY; }
    if (sp.hash == 256 && !k.sha256) || (sp.hash != 256 && !k.sha1) {
        set_reason(r, "key record: h= does not allow the hash");
        return mail::ERR_KEY;
    }
    if k.kind == REC_RSA && bignum::rsa_bits(k.rsa) < o.min_rsa_bits {
        set_reason(r, "key record: RSA key too small");
        return mail::ERR_KEY;
    }
    if k.strict {
        var at = -1;
        for c in r.i.len { if r.i[c] == '@' { at = c; } }
        if !mail::eq_fold(r.i[at + 1..], r.d) { set_reason(r, "key record: t=s and i= is a subdomain"); return mail::ERR_KEY; }
    }

    // The body.
    var body: u8[>..] = [];
    canon_body(body, msg[body_at..], sp.bcanon);
    if sp.l > body.len { set_reason(r, "l= is longer than the body"); return mail::ERR_SIGNATURE; }
    let signed_body = if sp.l >= 0 { body[..sp.l] } else { body[..] };
    var want_bh: u8[>..] = [];
    if !b64(want_bh, msg[sp.bh.pos..sp.bh.end]) { set_reason(r, "bh= is not base64"); return mail::ERR_FORMAT; }
    let got_bh = bignum::hash_bits(sp.hash, signed_body);
    if got_bh != want_bh {
        r.body_mismatch = true;
        set_reason(r, "body hash mismatch");
        return mail::ERR_SIGNATURE;
    }

    // The header: the fields h= names, then this one with b= empty.
    var data:  u8[>..]   = [];
    var names: Span[>..] = [];
    let htext = msg[sp.h.pos..sp.h.end];
    split_names(htext, names);
    signed_headers(data, msg, fields, htext, names, sp.field, sp.hcanon);
    let f = fields[sp.field];
    var own: u8[>..] = [];
    let ft = field_text(msg, f);
    own.append(msg[f.pos..sp.beq + 1]);
    own.append(msg[sp.bstop..f.pos + ft.len]);
    canon_header(data, own, sp.hcanon);
    var sig: u8[>..] = [];
    if !b64(sig, msg[sp.b.pos..sp.b.end]) { set_reason(r, "b= is not base64"); return mail::ERR_FORMAT; }
    let digest = bignum::hash_bits(sp.hash, data);
    var good = false;
    if k.kind == REC_ED25519 { good = bignum::ed25519_verify(k.ed, digest, sig); }
    else { good = bignum::rsa_verify_pkcs1_digest(k.rsa, digest, sig, sp.hash); }
    if !good { set_reason(r, "signature did not verify"); return mail::ERR_SIGNATURE; }
    return mail::OK;
}

// Every DKIM-Signature of msg (the first max_signatures), each Result
// appended to out in the order of the fields. The key record comes from
// F(domain, selector, record&), which appends the TXT record's text (its
// strings joined) to record, or leaves it empty when there is none.
// mail::OK when one signature passes; else the first one's status, or
// ERR_SIGNATURE when there are none.
fn verify<F>(msg_in: const u8[:], out: Result[>..]&, o: VerifyOptions = VerifyOptions { .. }) -> i64 {
    var norm: u8[>..] = [];
    if has_bare_lf(msg_in) { to_crlf(norm, msg_in); }
    let msg = if norm.len > 0 { norm[..] } else { msg_in };
    var fields: Field[>..] = [];
    let body_at = split_message(msg, fields);
    var first = mail::ERR_SIGNATURE;
    var any = false;
    var count = 0;
    for fi in fields.len {
        if count >= o.max_signatures { break; }
        if !mail::eq_fold(field_name(msg, fields[fi]), "DKIM-Signature") { continue; }
        count++;
        var r = Result { .. };
        var sp = Sig { .. };
        var e = check_sig(msg, fields, fi, o, sp, r);
        if e == mail::OK {
            var rec: u8[>..] = [];
            F(r.d[..], r.s[..], rec);
            e = check_with_key(msg, fields, body_at, o, sp, rec, r);
        }
        r.status = e;
        if e == mail::OK { set_reason(r, ""); any = true; }
        if count == 1 { first = e; }
        out.push(r);
    }
    return if any { mail::OK } else { first };
}

// verify with one key record for every signature: offline, or tests.
fn verify_record(msg: const u8[:], record: const u8[:], out: Result[>..]&, o: VerifyOptions = VerifyOptions { .. }) -> i64 {
    return verify(msg, out, o) { d, s, rec => rec.append(record); };
}

// The TXT record at selector._domainkey.domain, its strings joined,
// appended to rec. server is "host" or "host:port"; "" for the first
// nameserver of /etc/resolv.conf. ERR_DNS when the lookup fails or there
// is no TXT record.
fn lookup(server: const u8[:], domain: const u8[:], selector: const u8[:], rec: u8[>..]&) -> i64 {
    var srv: u8[>..] = [];
    if server.len > 0 {
        srv.append(server);
    } else {
        let cfg, ok = dns::client_config_file("/etc/resolv.conf");
        if !ok || cfg.servers.len == 0 { return mail::ERR_DNS; }
        srv.append(cfg.servers[0]);
    }
    var name: u8[>..] = [];
    name.append(selector);
    name.append("._domainkey.");
    name.append(domain);
    if name[name.len - 1] != '.' { name.push('.'); }
    var r = dns::Msg { .. };
    let e = dns::query(srv, name, dns::TYPE_TXT, r);
    if e != dns::OK || r.hdr.rcode != 0 { return mail::ERR_DNS; }
    var found = false;
    dns::each_rr(r.answer) { rr =>
        if !found && rr.rtype == dns::TYPE_TXT {
            found = true;
            let rd = dns::rdata(rr, r.answer);
            var i = 0;
            while i < rd.len {
                let n: i64 = rd[i];
                let e2 = ::min(i + 1 + n, rd.len);
                rec.append(rd[i + 1..e2]);
                i = e2;
            }
        }
    };
    return if found { mail::OK } else { mail::ERR_DNS };
}

// verify with the keys looked up in DNS (lookup's server).
fn verify_dns(msg: const u8[:], server: const u8[:], out: Result[>..]&, o: VerifyOptions = VerifyOptions { .. }) -> i64 {
    return verify(msg, out, o) { d, s, rec => lookup(server, d, s, rec); };
}

// RFC 8601's word for a status: pass, fail, neutral (an algorithm not
// done here), temperror (no key) or permerror.
fn result_word(status: i64) -> const u8[:] {
    if status == mail::OK { return "pass"; }
    if status == mail::ERR_SIGNATURE { return "fail"; }
    if status == mail::ERR_UNSUPPORTED { return "neutral"; }
    if status == mail::ERR_DNS { return "temperror"; }
    return "permerror";
}

// "dkim=pass header.d=example.com header.s=sel header.a=ed25519-sha256",
// and the reason in parentheses when it did not pass.
fn result_text(r: const Result&, out: u8[>..]&) {
    out.append("dkim=");
    out.append(result_word(r.status));
    if r.d.len > 0 { out.append(" header.d="); out.append(r.d); }
    if r.s.len > 0 { out.append(" header.s="); out.append(r.s); }
    if r.alg >= 0 { out.append(" header.a="); out.append(alg_name(r.alg)); }
    if r.reason.len > 0 { out.append(" ("); out.append(r.reason); out.append(")"); }
}
