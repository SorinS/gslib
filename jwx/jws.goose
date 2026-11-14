// jwx.jws: JSON Web Signatures (RFC 7515), compact and JSON (general and
// flattened), with detached payloads and RFC 7797's unencoded ones
// ("b64": false), by every algorithm of RFC 7518 §3, RFC 8037's EdDSA and
// RFC 9964's ML-DSA-44, -65 and -87.
//
//   let token, err = jws::sign(payload, jwa::ES256, key);
//   let payload, err = jws::verify(token, jwa::ES256, public_key);
//
// Verifying takes the algorithm the caller expects, or a set of keys that
// name theirs; a message whose header names another is refused. A JSON
// message verifies when any of its signatures does, as in jwx.

namespace jws;

import std;
import json;
import jwx;
import jwx.jwa;
import jwx.jwk;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.rsa;
import crypto.bignum.ec;
import crypto.bignum.ed25519;
import crypto.bignum.hmac;
import crypto.bignum.mldsa;

// The header parameters RFC 7515 §4.1 and RFC 7797 define. Others, a
// caller's own, go in `extra` when signing (JSON members, without braces:
// "\"iat\":1,\"x\":\"y\"") and are read with header_string and header_int.
struct Header {
    alg: i64 = jwa::UNKNOWN,
    kid: u8[..256] = [],
    typ: u8[..128] = [],
    cty: u8[..128] = [],
    jku: u8[..512] = [],
    x5u: u8[..512] = [],
    x5t: u8[..20] = [],
    x5t256: u8[..32] = [],
    has_jwk: bool = false,
    jwk: jwk::Key = jwk::empty(),
    b64: bool = true,
    crit: u8[..256] = [],       // the names in "crit", each followed by a NUL
}

// One signature of a parsed message: its header (protected and
// unprotected together), where the protected header's base64url text and
// the unprotected header's JSON are in the message's `text`, and the
// signature.
struct Signature {
    header: Header,
    protected_at: i64,
    protected_len: i64,
    unprotected_at: i64,
    unprotected_len: i64,
    sig: u8[..4627],            // up to ML-DSA-87's signature
}

// A parsed JWS. `payload` is the payload, decoded; `text` holds the parts
// as they arrived, which signing inputs are made from.
root struct Message {
    payload: u8[>..] = [],
    text: u8[>..] = [],
    sigs: Signature[>..] = [],
    payload_at: i64 = 0,        // the payload as it arrived (base64url, or itself when b64 is false), in text
    payload_len: i64 = 0,
    compact: bool = false,
    detached: bool = false,
}

// A signer for sign_json: the key, the protected header (whose alg is the
// algorithm) and the unprotected header's members, as JSON without braces.
struct Signer {
    key: jwk::Key,
    header: Header = Header { .. },
    unprotected: u8[..1024] = [],
}

// --- Headers --------------------------------------------------------------------

fn put_member_string(out: u8[>..]&, name: const u8[:], v: const u8[:]) {
    jwx::put_comma(out);
    json::format_key(out, name);
    json::format_string(out, v);
}

fn put_member_b64(out: u8[>..]&, name: const u8[:], v: const u8[:]) {
    jwx::put_comma(out);
    json::format_key(out, name);
    out.push('"');
    jwx::b64_append(out, v);
    out.push('"');
}

// The protected header as JSON: alg first, then the others in lexical
// order, then the caller's own members.
fn header_json(h: const Header&, extra: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.push('{');
    put_member_string(out, "alg", jwa::name(h.alg));
    if !h.b64 {
        out.append(",\"b64\":false");
    }
    if h.crit.len > 0 || !h.b64 {
        out.append(",\"crit\":[");
        var first = true;
        if !h.b64 { out.append("\"b64\""); first = false; }
        for name in split(h.crit, 0) {
            if name.len == 0 || name == "b64" { continue; }
            if !first { out.push(','); }
            json::format_string(out, name);
            first = false;
        }
        out.push(']');
    }
    if h.cty.len > 0 { put_member_string(out, "cty", h.cty); }
    if h.jku.len > 0 { put_member_string(out, "jku", h.jku); }
    if h.has_jwk {
        jwx::put_comma(out);
        json::format_key(out, "jwk");
        jwk::marshal_to(out, h.jwk, false);
    }
    if h.kid.len > 0 { put_member_string(out, "kid", h.kid); }
    if h.typ.len > 0 { put_member_string(out, "typ", h.typ); }
    if h.x5t.len > 0 { put_member_b64(out, "x5t", h.x5t); }
    if h.x5t256.len > 0 { put_member_b64(out, "x5t#S256", h.x5t256); }
    if h.x5u.len > 0 { put_member_string(out, "x5u", h.x5u); }
    if extra.len > 0 {
        out.push(',');
        out.append(extra);
    }
    out.push('}');
    return out;
}

// The header parameters this package understands, which "crit" may not
// name except for b64 (RFC 7515 §4.1.11: crit lists extensions only).
fn is_registered(name: const u8[:]) -> bool {
    for r in ["alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
              "enc", "zip", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c"] {
        if r == name { return true; }
    }
    return false;
}

// A string member into a fixed field: false when it is there and is no
// string, or does not fit.
fn take_string(n: json::Node&, name: const u8[:], out: u8[>..]&, cap: i64) -> bool {
    let m = json::member(n, name);
    guard m else { return true; }
    let s, ok = json::as_string(m);
    if !ok || s.len > cap { return false; }
    out.append(s);
    return true;
}

fn take_b64(n: json::Node&, name: const u8[:], out: u8[>..]&, want: i64) -> bool {
    let m = json::member(n, name);
    guard m else { return true; }
    let s, ok = json::as_string(m);
    if !ok { return false; }
    var b: u8[>..] = [];
    if !jwx::b64_decode_append(b, s) || b.len != want { return false; }
    out.append(b);
    return true;
}

// The parameters of one header object into h. `protected` says which it
// is: crit and b64 must be protected (RFC 7515 §4.1.11, RFC 7797 §3).
fn read_header(n: json::Node&, h: Header&, protected: bool) -> i64 {
    match n.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    if jwk::has_duplicates(n) { return jwx::ERR_MALFORMED; }
    let am = json::member(n, "alg");
    if am {
        let s, ok = json::as_string(am);
        if !ok { return jwx::ERR_MALFORMED; }
        h.alg = jwa::lookup(s);
        if !jwa::is_signature(h.alg) { return jwx::ERR_UNSUPPORTED; }
    }
    var kid: u8[>..] = [];
    var typ: u8[>..] = [];
    var cty: u8[>..] = [];
    var jku: u8[>..] = [];
    var x5u: u8[>..] = [];
    var x5t: u8[>..] = [];
    var x5t256: u8[>..] = [];
    if !take_string(n, "kid", kid, 256) || !take_string(n, "typ", typ, 128) || !take_string(n, "cty", cty, 128)
       || !take_string(n, "jku", jku, 512) || !take_string(n, "x5u", x5u, 512)
       || !take_b64(n, "x5t", x5t, 20) || !take_b64(n, "x5t#S256", x5t256, 32) {
        return jwx::ERR_MALFORMED;
    }
    h.kid.append(kid);
    h.typ.append(typ);
    h.cty.append(cty);
    h.jku.append(jku);
    h.x5u.append(x5u);
    h.x5t.append(x5t);
    h.x5t256.append(x5t256);
    let jm = json::member(n, "jwk");
    if jm {
        let k, e = jwk::from_node(jm);
        if e != jwx::OK { return e; }
        // A header's key is public (RFC 7515 §4.1.3).
        if k.private && k.kty != jwa::KTY_OCT { return jwx::ERR_KEY; }
        if k.kty == jwa::KTY_OCT { return jwx::ERR_KEY; }
        h.jwk = k;
        h.has_jwk = true;
    }
    let bm = json::member(n, "b64");
    if bm {
        if !protected { return jwx::ERR_MALFORMED; }
        let v, ok = json::as_bool(bm);
        if !ok { return jwx::ERR_MALFORMED; }
        h.b64 = v;
    }
    let cm = json::member(n, "crit");
    if cm {
        if !protected { return jwx::ERR_MALFORMED; }
        var bad = false;
        var count = 0;
        match cm.val {
            Arr => {},
            _ => { return jwx::ERR_MALFORMED; },
        }
        json::each(cm) { c =>
            let s, ok = json::as_string(c);
            count++;
            if !ok || s.len == 0 || (is_registered(s) && s != "b64") { bad = true; }
            // Each name must be a parameter the header has (RFC 7515 §4.1.11).
            else if !json::member(n, s) { bad = true; }
            else if h.crit.len + s.len + 1 > 256 { bad = true; }
            else { h.crit.append(s); h.crit.push(0); }
        };
        if bad || count == 0 { return jwx::ERR_MALFORMED; }
    }
    return jwx::OK;
}

// OK when every name in "crit" is one this package understands: b64 only.
// b64 itself must be in crit when it is false (RFC 7797 §6).
fn check_crit(h: const Header&) -> i64 {
    var has_b64 = false;
    for name in split(h.crit, 0) {
        if name.len == 0 { continue; }
        if name != "b64" { return jwx::ERR_CRIT; }
        has_b64 = true;
    }
    if !h.b64 && !has_b64 { return jwx::ERR_MALFORMED; }
    return jwx::OK;
}

// --- Signing and verifying the bytes ------------------------------------------------

// The signature of input by alg with key; ERR_KEY for a key that does not
// fit or is not private.
fn sign_bytes(input: const u8[:], alg: i64, key: const jwk::Key&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if alg == jwa::NONE { return out, jwx::OK; }
    if !jwa::is_signature(alg) { return out, jwx::ERR_UNSUPPORTED; }
    if !jwk::fits(key, alg) || !key.private { return out, jwx::ERR_KEY; }
    let h = jwa::hash_of(alg);
    var ok = true;
    if jwa::is_hmac(alg) {
        out.append(bignum::hmac(h, key.k, input));
    } else if jwa::is_rsa_pkcs1(alg) {
        let s, oks = bignum::rsa_sign_pkcs1(key.rsa, input, h);
        out.append(s);
        ok = oks;
    } else if jwa::is_rsa_pss(alg) {
        // The salt is as long as the hash (RFC 7518 §3.5).
        let s, oks = bignum::rsa_sign_pss(key.rsa, input, bignum::hash_len(h), h);
        out.append(s);
        ok = oks;
    } else if jwa::is_ecdsa(alg) {
        let c = jwk::curve(key.crv);
        out.append(bignum::ecdsa_sign(c, key.d, input));
    } else if jwa::is_mldsa(alg) {
        // Hedged, with the empty context (RFC 9964 §5).
        out.append(bignum::mldsa_sign(jwa::mldsa_set(alg), key.d, input));
    } else {
        out.append(bignum::ed25519_sign(key.d, input));
    }
    return out, if ok { jwx::OK } else { jwx::ERR_KEY };
}

// OK when sig is alg's signature of input under key (public or private).
fn verify_bytes(input: const u8[:], sig: const u8[:], alg: i64, key: const jwk::Key&) -> i64 {
    if alg == jwa::NONE { return if sig.len == 0 { jwx::OK } else { jwx::ERR_BAD_SIGNATURE }; }
    if !jwa::is_signature(alg) { return jwx::ERR_UNSUPPORTED; }
    if !jwk::fits(key, alg) { return jwx::ERR_KEY; }
    let h = jwa::hash_of(alg);
    var good = false;
    if jwa::is_hmac(alg) {
        let mac = bignum::hmac(h, key.k, input);
        good = sig.len == mac.len && bignum::ct_eq_bytes(mac, sig) == 1;
    } else if jwa::is_rsa_pkcs1(alg) {
        let pub = jwk::rsa_public(key);
        good = bignum::rsa_verify_pkcs1(pub, input, sig, h);
    } else if jwa::is_rsa_pss(alg) {
        let pub = jwk::rsa_public(key);
        good = bignum::rsa_verify_pss(pub, input, sig, bignum::hash_len(h), h);
    } else if jwa::is_ecdsa(alg) {
        let c = jwk::curve(key.crv);
        good = sig.len == 2 * jwa::crv_len(key.crv) && bignum::ecdsa_verify(c, jwk::ec_point(key), input, sig);
    } else if jwa::is_mldsa(alg) {
        let set = jwa::mldsa_set(alg);
        good = sig.len == bignum::mldsa_sig_len(set) && bignum::mldsa_verify(set, key.pub, input, sig);
    } else {
        good = sig.len == 64 && bignum::ed25519_verify(key.x, input, sig);
    }
    return if good { jwx::OK } else { jwx::ERR_BAD_SIGNATURE };
}

// --- Signing --------------------------------------------------------------------------

// The signing input: the protected header's base64url text, '.', and the
// payload's (or the payload itself when b64 is false).
fn signing_input(protected_b64: const u8[:], payload: const u8[:], b64: bool) -> u8[>..] {
    var input: u8[>..] = [];
    input.append(protected_b64);
    input.push('.');
    if b64 { jwx::b64_append(input, payload); } else { input.append(payload); }
    return input;
}

// A compact JWS of payload by h.alg with key, its protected header h and
// the caller's own members `extra`. `detached` leaves the payload out
// (RFC 7515 Appendix F). An unencoded payload (h.b64 false) may not hold
// a '.' unless detached (RFC 7797 §5.2).
fn sign_with(payload: const u8[:], key: const jwk::Key&, h: const Header&, extra: const u8[:] = "",
             detached: bool = false) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if !h.b64 && !detached && find(payload, ".") >= 0 { return out, jwx::ERR_MALFORMED; }
    let protected_b64 = jwx::b64_encode(header_json(h, extra));
    let input = signing_input(protected_b64, payload, h.b64);
    let sig, err = sign_bytes(input, h.alg, key);
    if err != jwx::OK { return out, err; }
    if detached {
        out.append(protected_b64);
        out.push('.');
    } else {
        out.append(input);
    }
    out.push('.');
    jwx::b64_append(out, sig);
    return out, jwx::OK;
}

// A compact JWS of payload by alg with key. The key's "kid", if it has one,
// goes in the header, as jwx puts it there.
fn sign(payload: const u8[:], alg: i64, key: const jwk::Key&) -> u8[>..], i64 {
    var h = Header { .. };
    h.alg = alg;
    h.kid.append(key.kid);
    let out, err = sign_with(payload, key, h);
    return out, err;
}

// A JWS in the JSON serialization, one signature per signer: general, or
// flattened when there is one signer and `flattened` is true.
fn sign_json(payload: const u8[:], signers: const Signer[:], flattened: bool = false) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if signers.len == 0 || (flattened && signers.len != 1) { return out, jwx::ERR_MALFORMED; }
    let b64 = signers[0].header.b64;
    for &s in signers {
        if s.header.b64 != b64 { return out, jwx::ERR_MALFORMED; }
    }
    out.append("{\"payload\":");
    if b64 {
        out.push('"');
        jwx::b64_append(out, payload);
        out.push('"');
    } else {
        json::format_string(out, payload);
    }
    if !flattened { out.append(",\"signatures\":["); }
    var first = true;
    for &s in signers {
        var kidded = s.header;
        if kidded.kid.len == 0 && s.unprotected.len == 0 { kidded.kid.append(s.key.kid); }
        let protected_b64 = jwx::b64_encode(header_json(kidded, ""));
        let input = signing_input(protected_b64, payload, b64);
        let sig, err = sign_bytes(input, s.header.alg, s.key);
        if err != jwx::OK { return out, err; }
        if !flattened {
            if !first { out.push(','); }
            out.push('{');
        } else {
            out.push(',');
        }
        first = false;
        out.append("\"protected\":\"");
        out.append(protected_b64);
        out.push('"');
        if s.unprotected.len > 0 {
            out.append(",\"header\":{");
            out.append(s.unprotected);
            out.push('}');
        }
        out.append(",\"signature\":\"");
        jwx::b64_append(out, sig);
        out.push('"');
        if !flattened { out.push('}'); }
    }
    if !flattened { out.push(']'); }
    out.push('}');
    return out, jwx::OK;
}

// --- Parsing ------------------------------------------------------------------------------

// Records one signature: its protected header's text and its unprotected
// header's JSON, both kept in m.text, parsed together into a header.
fn add_signature(m: Message&, protected_b64: const u8[:], unprotected: const u8[:], sig_b64: const u8[:]) -> i64 {
    var s = Signature { header: Header { .. }, protected_at: m.text.len, protected_len: protected_b64.len,
                        unprotected_at: 0, unprotected_len: 0, sig: [] };
    m.text.append(protected_b64);
    s.unprotected_at = m.text.len;
    s.unprotected_len = unprotected.len;
    m.text.append(unprotected);
    var sig: u8[>..] = [];
    if !jwx::b64_decode_append(sig, sig_b64) || sig.len > 4627 { return jwx::ERR_MALFORMED; }
    s.sig.append(sig);
    var htext: u8[>..] = [];
    if !jwx::b64_decode_append(htext, protected_b64) { return jwx::ERR_MALFORMED; }
    // A JSON-serialized signature may have no protected header at all.
    if protected_b64.len > 0 || m.compact {
        var doc: json::Node[>..] = [];
        var decoded: u8[>..] = [];
        let root, msg = json::parse(htext, doc, decoded);
        guard root else { return jwx::ERR_MALFORMED; }
        let e = read_header(root, s.header, true);
        if e != jwx::OK { return e; }
    }
    if unprotected.len > 0 {
        var doc2: json::Node[>..] = [];
        var decoded2: u8[>..] = [];
        let root2, msg2 = json::parse(unprotected, doc2, decoded2);
        guard root2 else { return jwx::ERR_MALFORMED; }
        // Names may not be in both (RFC 7515 §7.2.1).
        if protected_b64.len > 0 {
            var doc3: json::Node[>..] = [];
            var decoded3: u8[>..] = [];
            let root3, msg3 = json::parse(htext, doc3, decoded3);
            guard root3 else { return jwx::ERR_MALFORMED; }
            var clash = false;
            json::each(root2) { u => if json::member(root3, u.key) { clash = true; } };
            if clash { return jwx::ERR_MALFORMED; }
        }
        let e = read_header(root2, s.header, false);
        if e != jwx::OK { return e; }
    }
    if s.header.alg == jwa::UNKNOWN { return jwx::ERR_MALFORMED; }
    let ec = check_crit(s.header);
    if ec != jwx::OK { return ec; }
    m.sigs.push(s);
    return jwx::OK;
}

// The payload as it arrived, decoded into m.payload.
fn set_payload(m: Message&, text: const u8[:], b64: bool) -> i64 {
    m.payload_at = m.text.len;
    m.payload_len = text.len;
    m.text.append(text);
    if b64 {
        if !jwx::b64_decode_append(m.payload, text) { return jwx::ERR_MALFORMED; }
    } else {
        m.payload.append(text);
    }
    return jwx::OK;
}

fn parse_compact(m: Message&, token: const u8[:]) -> i64 {
    m.compact = true;
    let parts = split(token, '.');
    if parts.len != 3 { return jwx::ERR_MALFORMED; }
    var p: const u8[:][3] = ["", "", ""];
    var i = 0;
    for part in parts { p[i] = part; i++; }
    let e = add_signature(m, p[0], "", p[2]);
    if e != jwx::OK { return e; }
    m.detached = p[1].len == 0;
    return set_payload(m, p[1], m.sigs[0].header.b64);
}

// One signature object of the JSON serialization (or the flattened
// message itself).
fn parse_json_signature(m: Message&, n: json::Node&, raw: const u8[:]) -> i64 {
    let pm = json::member(n, "protected");
    let protected_b64, has_protected = json::as_string(pm);
    if pm && (!has_protected || protected_b64.len == 0) { return jwx::ERR_MALFORMED; }
    let sm = json::member(n, "signature");
    guard sm else { return jwx::ERR_MALFORMED; }
    let sig, oks = json::as_string(sm);
    if !oks { return jwx::ERR_MALFORMED; }
    var unprotected: u8[>..] = [];
    let hm = json::member(n, "header");
    if hm {
        match hm.val {
            Obj => {},
            _ => { return jwx::ERR_MALFORMED; },
        }
        // The member's JSON again, from its parsed form: names and strings
        // as given, numbers as the reader read them.
        write_node(unprotected, hm);
    }
    if !pm && !hm { return jwx::ERR_MALFORMED; }
    return add_signature(m, protected_b64, unprotected, sig);
}

// A parsed JSON value written back as JSON.
recursive fn write_node(out: u8[>..]&, n: json::Node&) {
    match n.val {
        Null => { out.append("null"); },
        Bool b => { json::format_bool(out, b.v); },
        Int i => { json::format_int(out, i.v); },
        Num x => { json::format_number(out, x.v); },
        Str t => { json::format_string(out, t.s); },
        Arr => {
            out.push('[');
            var first = true;
            var c = n.first;
            while c {
                if !first { out.push(','); }
                first = false;
                write_node(out, c);
                c .= c.next;
            }
            out.push(']');
        },
        Obj => {
            out.push('{');
            var first = true;
            var c = n.first;
            while c {
                if !first { out.push(','); }
                first = false;
                json::format_key(out, c.key);
                write_node(out, c);
                c .= c.next;
            }
            out.push('}');
        },
    }
}

fn parse_json(m: Message&, token: const u8[:]) -> i64 {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(token, doc, decoded);
    guard root else { return jwx::ERR_MALFORMED; }
    match root.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    // No payload member: a detached payload (RFC 7515 Appendix F).
    let pm = json::member(root, "payload");
    let payload, okp = json::as_string(pm);
    if pm && !okp { return jwx::ERR_MALFORMED; }
    m.detached = !pm;
    let list = json::member(root, "signatures");
    if list {
        if json::member(root, "signature") || json::member(root, "protected") { return jwx::ERR_MALFORMED; }
        match list.val {
            Arr => {},
            _ => { return jwx::ERR_MALFORMED; },
        }
        var err = jwx::OK;
        json::each(list) { s => if err == jwx::OK { err = parse_json_signature(m, s, token); } };
        if err != jwx::OK { return err; }
    } else {
        let e = parse_json_signature(m, root, token);
        if e != jwx::OK { return e; }
    }
    if m.sigs.len == 0 { return jwx::ERR_MALFORMED; }
    // Every signature must agree on b64: the payload is one or the other.
    let b64 = m.sigs[0].header.b64;
    for &s in m.sigs {
        if s.header.b64 != b64 { return jwx::ERR_MALFORMED; }
    }
    return set_payload(m, payload, b64);
}

// Parses a JWS, compact or JSON, into m (a fresh Message).
fn parse(m: Message&, token: const u8[:]) -> i64 {
    let t = trim(token);
    if t.len > 0 && t[0] == '{' { return parse_json(m, t); }
    return parse_compact(m, t);
}

// Signature i's protected header text, as signed.
fn protected_text(m: const Message&, i: i64) -> const u8[:] {
    let s = m.sigs[i];
    return m.text[s.protected_at..s.protected_at + s.protected_len];
}

// Verifies signature i of m by alg with key. `payload` stands in for a
// detached payload; empty, the message's own is used.
fn verify_signature(m: const Message&, i: i64, alg: i64, key: const jwk::Key&, payload: const u8[:] = "") -> i64 {
    let s = m.sigs[i];
    if s.header.alg != alg { return jwx::ERR_ALG_MISMATCH; }
    let ec = check_crit(s.header);
    if ec != jwx::OK { return ec; }
    var input: u8[>..] = [];
    input.append(protected_text(m, i));
    input.push('.');
    if payload.len > 0 || m.detached {
        if s.header.b64 { jwx::b64_append(input, payload); } else { input.append(payload); }
    } else {
        input.append(m.text[m.payload_at..m.payload_at + m.payload_len]);
    }
    return verify_bytes(input, s.sig, alg, key);
}

// The best error of several signatures: a bad signature over a mismatch.
fn worse(a: i64, b: i64) -> i64 {
    if a == jwx::ERR_BAD_SIGNATURE || b == jwx::ERR_BAD_SIGNATURE { return jwx::ERR_BAD_SIGNATURE; }
    if a == jwx::ERR_ALG_MISMATCH { return b; }
    return a;
}

// The payload of a JWS that alg with key verifies: any one signature of a
// JSON message will do. "none" is refused unless alg is jwa::NONE.
fn verify(token: const u8[:], alg: i64, key: const jwk::Key&) -> u8[>..], i64 {
    var m = Message { .. };
    var out: u8[>..] = [];
    let e = parse(m, token);
    if e != jwx::OK { return out, e; }
    var err = jwx::ERR_ALG_MISMATCH;
    for i in m.sigs.len {
        if m.sigs[i].header.alg == jwa::NONE && alg != jwa::NONE { err = worse(err, jwx::ERR_NONE); continue; }
        let r = verify_signature(m, i, alg, key);
        if r == jwx::OK {
            out.append(m.payload);
            return out, jwx::OK;
        }
        err = if err == jwx::ERR_ALG_MISMATCH { r } else { worse(err, r) };
    }
    return out, err;
}

// Verifies a JWS whose payload was detached, against `payload`.
fn verify_detached(token: const u8[:], payload: const u8[:], alg: i64, key: const jwk::Key&) -> i64 {
    var m = Message { .. };
    let e = parse(m, token);
    if e != jwx::OK { return e; }
    if !m.detached { return jwx::ERR_MALFORMED; }
    var err = jwx::ERR_ALG_MISMATCH;
    for i in m.sigs.len {
        let r = verify_signature(m, i, alg, key, payload);
        if r == jwx::OK { return jwx::OK; }
        err = if err == jwx::ERR_ALG_MISMATCH { r } else { worse(err, r) };
    }
    return err;
}

// The payload of a JWS verified by a key of the set: the key whose "kid" is
// the header's, or every key when the header has none. The algorithm is the
// key's "alg"; a key without one is used only when `infer` is true, with
// the header's alg if the key fits it (jwx's InferAlgorithmFromKey).
fn verify_set(token: const u8[:], keys: const jwk::Key[:], infer: bool = false) -> u8[>..], i64 {
    var m = Message { .. };
    var out: u8[>..] = [];
    let e = parse(m, token);
    if e != jwx::OK { return out, e; }
    var err = jwx::ERR_NO_KEY;
    for i in m.sigs.len {
        let h = m.sigs[i].header;
        for &k in keys {
            if h.kid.len > 0 && k.kid[..] != h.kid[..] { continue; }
            var alg = k.alg;
            if alg == jwa::UNKNOWN {
                if !infer || h.alg == jwa::NONE || !jwk::fits(k, h.alg) { continue; }
                alg = h.alg;
            }
            // A key that says "alg": "none" verifies nothing: an unsigned
            // token is never accepted through a set.
            if alg == jwa::NONE { continue; }
            if k.key_use == jwk::USE_ENC { continue; }
            let r = verify_signature(m, i, alg, k);
            if r == jwx::OK {
                out.append(m.payload);
                return out, jwx::OK;
            }
            err = if err == jwx::ERR_NO_KEY { r } else { worse(err, r) };
        }
    }
    return out, err;
}

// A string member of signature i's header (protected or not), by name: a
// parameter of the caller's own, say. False when absent or not a string.
fn header_string(m: const Message&, i: i64, name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let s = m.sigs[i];
    for which in 2 {
        var text: u8[>..] = [];
        if which == 0 {
            if !jwx::b64_decode_append(text, m.text[s.protected_at..s.protected_at + s.protected_len]) { continue; }
        } else {
            text.append(m.text[s.unprotected_at..s.unprotected_at + s.unprotected_len]);
        }
        if text.len == 0 { continue; }
        var doc: json::Node[>..] = [];
        var decoded: u8[>..] = [];
        let root, msg = json::parse(text, doc, decoded);
        let v, ok = json::as_string(json::member(root, name));
        if ok {
            out.append(v);
            return out, true;
        }
    }
    return out, false;
}

// An integer member of signature i's header, by name.
fn header_int(m: const Message&, i: i64, name: const u8[:]) -> i64, bool {
    let s = m.sigs[i];
    for which in 2 {
        var text: u8[>..] = [];
        if which == 0 {
            if !jwx::b64_decode_append(text, m.text[s.protected_at..s.protected_at + s.protected_len]) { continue; }
        } else {
            text.append(m.text[s.unprotected_at..s.unprotected_at + s.unprotected_len]);
        }
        if text.len == 0 { continue; }
        var doc: json::Node[>..] = [];
        var decoded: u8[>..] = [];
        let root, msg = json::parse(text, doc, decoded);
        let v, ok = json::as_i64(json::member(root, name));
        if ok { return v, true; }
    }
    return 0, false;
}
