// jwx.jwt: JSON Web Tokens (RFC 7519): claims, tokens signed (JWS) or
// encrypted (JWE) or both (nested), and validating a token's claims.
//
//   var c = jwt::new_claims();
//   c.iss.append("https://issuer.example");
//   jwt::add_audience(c, "api");
//   jwt::set_expiry(c, now + 3600);
//   let token, err = jwt::sign(c, jwa::ES256, key);
//
//   var got = jwt::new_claims();
//   var v = jwt::Validator { .. };
//   v.audience.append("api");
//   let err = jwt::parse(token, jwa::ES256, public_key, got, v);
//
// Parsing verifies the token and then validates its claims, as jwx's
// Parse does: exp, nbf and iat against the clock with an allowed skew,
// and iss, sub, aud and jti when the validator asks for them.

namespace jwt;

import std;
import os;
import json;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.jws;
import jwx.jwe;

// The registered claims as bits, for Validator.required.
let CLAIM_ISS: u32 = 1;
let CLAIM_SUB: u32 = 2;
let CLAIM_AUD: u32 = 4;
let CLAIM_EXP: u32 = 8;
let CLAIM_NBF: u32 = 16;
let CLAIM_IAT: u32 = 32;
let CLAIM_JTI: u32 = 64;

// A token's claims: the registered ones of RFC 7519 §4.1, and the others,
// a caller's own, as JSON members without braces in `private`.
struct Claims {
    iss: u8[..256],
    sub: u8[..256],
    jti: u8[..256],
    aud: u8[..1024],            // the audiences, each its length (2 bytes, big-endian) then its bytes
    exp: i64,
    nbf: i64,
    iat: i64,
    has: u32,                   // CLAIM_* bits of the claims present
    private: u8[>..],
}

fn new_claims() -> Claims {
    Claims { iss: [], sub: [], jti: [], aud: [], exp: 0, nbf: 0, iat: 0, has: 0, private: [] }
}

// An audience, any bytes (a JSON string may hold a NUL): each is kept
// with its length, so it reads back the same string, empty ones too.
fn add_audience(c: Claims&, aud: const u8[:]) {
    assert(c.aud.len + aud.len + 2 <= 1024);
    c.aud.push((aud.len >> 8) as! u8);
    c.aud.push((aud.len & 0xff) as! u8);
    c.aud.append(aud);
    c.has = c.has | CLAIM_AUD;
}

fn audiences(c: const Claims&) -> const u8[:][>..] {
    var out: const u8[:][>..] = [];
    var i = 0;
    while i + 2 <= c.aud.len {
        let n = ((c.aud[i] as i64) << 8) | c.aud[i + 1];
        out.push(c.aud[i + 2..i + 2 + n]);
        i = i + 2 + n;
    }
    return out;
}

fn set_expiry(c: Claims&, t: i64) { c.exp = t; c.has = c.has | CLAIM_EXP; }
fn set_not_before(c: Claims&, t: i64) { c.nbf = t; c.has = c.has | CLAIM_NBF; }
fn set_issued_at(c: Claims&, t: i64) { c.iat = t; c.has = c.has | CLAIM_IAT; }

// Whether the token has the claims of `which` (CLAIM_* bits). iss, sub and
// jti count as present when not empty.
fn has(c: const Claims&, which: u32) -> bool {
    var h = c.has;
    if c.iss.len > 0 { h = h | CLAIM_ISS; }
    if c.sub.len > 0 { h = h | CLAIM_SUB; }
    if c.jti.len > 0 { h = h | CLAIM_JTI; }
    return h & which == which;
}

// A claim of the caller's own: a string, an integer, or any JSON value
// (`raw` written as it is: an object, an array, true).
fn set_string(c: Claims&, name: const u8[:], v: const u8[:]) {
    jwx::put_comma(c.private);
    json::format_key(c.private, name);
    json::format_string(c.private, v);
}

fn set_int(c: Claims&, name: const u8[:], v: i64) {
    jwx::put_comma(c.private);
    json::format_key(c.private, name);
    json::format_int(c.private, v);
}

fn set_raw(c: Claims&, name: const u8[:], raw: const u8[:]) {
    jwx::put_comma(c.private);
    json::format_key(c.private, name);
    c.private.append(raw);
}

// A claim of the caller's own, read back.
fn get_string(c: const Claims&, name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let text = str("{", c.private, "}");
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    let v, ok = json::as_string(json::member(root, name));
    if ok { out.append(v); }
    return out, ok;
}

fn get_int(c: const Claims&, name: const u8[:]) -> i64, bool {
    let text = str("{", c.private, "}");
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    let v, ok = json::as_i64(json::member(root, name));
    return v, ok;
}

// The claim's value as JSON text (any type).
fn get_raw(c: const Claims&, name: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let text = str("{", c.private, "}");
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    let v = json::member(root, name);
    guard v else { return out, false; }
    jws::write_node(out, v);
    return out, true;
}

// --- JSON ------------------------------------------------------------------------

fn put_int(out: u8[>..]&, name: const u8[:], v: i64) {
    jwx::put_comma(out);
    json::format_key(out, name);
    json::format_int(out, v);
}

// The claims as a JSON object: the registered claims in lexical order,
// then the others. "aud" is an array, as jwx writes it, unless `flatten`
// and there is one audience.
fn marshal(c: const Claims&, flatten: bool = false) -> u8[>..] {
    var out: u8[>..] = [];
    out.push('{');
    let auds = audiences(c);
    if auds.len > 0 {
        jwx::put_comma(out);
        json::format_key(out, "aud");
        if flatten && auds.len == 1 {
            for a in auds { json::format_string(out, a); }
        } else {
            out.push('[');
            var first = true;
            for a in auds {
                if !first { out.push(','); }
                first = false;
                json::format_string(out, a);
            }
            out.push(']');
        }
    }
    if c.has & CLAIM_EXP != 0 { put_int(out, "exp", c.exp); }
    if c.has & CLAIM_IAT != 0 { put_int(out, "iat", c.iat); }
    if c.iss.len > 0 { jws::put_member_string(out, "iss", c.iss); }
    if c.jti.len > 0 { jws::put_member_string(out, "jti", c.jti); }
    if c.has & CLAIM_NBF != 0 { put_int(out, "nbf", c.nbf); }
    if c.sub.len > 0 { jws::put_member_string(out, "sub", c.sub); }
    if c.private.len > 0 {
        jwx::put_comma(out);
        out.append(c.private);
    }
    out.push('}');
    return out;
}

// A NumericDate (RFC 7519 §2): seconds, an integer or not; jwx truncates
// fractions, so does this.
fn numeric_date(n: json::Node&) -> i64, bool {
    let i, oki = json::as_i64(n);
    if oki { return i, true; }
    let f, okf = json::as_f64(n);
    if !okf || f != f || f > 9.0e18 || f < -9.0e18 { return 0, false; }
    return f as! i64, true;     // truncated, as jwx truncates
}

fn take(n: json::Node&, name: const u8[:], out: u8[>..]&) -> bool {
    let m = json::member(n, name);
    guard m else { return true; }
    let s, ok = json::as_string(m);
    if !ok || s.len > 256 { return false; }
    out.append(s);
    return true;
}

// The claims in a JSON object (a token's payload) into c (a fresh Claims).
fn parse_claims(text: const u8[:], c: Claims&) -> i64 {
    var doc: json::Node[>..] = [];
    var decoded: u8[>..] = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return jwx::ERR_MALFORMED; }
    match root.val {
        Obj => {},
        _ => { return jwx::ERR_MALFORMED; },
    }
    if jwk::has_duplicates(root) { return jwx::ERR_MALFORMED; }
    var iss: u8[>..] = [];
    var sub: u8[>..] = [];
    var jti: u8[>..] = [];
    if !take(root, "iss", iss) || !take(root, "sub", sub) || !take(root, "jti", jti) { return jwx::ERR_MALFORMED; }
    c.iss.append(iss);
    c.sub.append(sub);
    c.jti.append(jti);
    for name in ["exp", "nbf", "iat"] {
        let m = json::member(root, name);
        if m {
            let t, ok = numeric_date(m);
            if !ok { return jwx::ERR_MALFORMED; }
            if name == "exp" { set_expiry(c, t); } else if name == "nbf" { set_not_before(c, t); } else { set_issued_at(c, t); }
        }
    }
    // "aud": one string, or an array of them (RFC 7519 §4.1.3).
    let am = json::member(root, "aud");
    if am {
        var bad = false;
        match am.val {
            Str s => {
                if s.s.len + 2 > 1024 { return jwx::ERR_MALFORMED; }
                add_audience(c, s.s);
            },
            Arr => {
                json::each(am) { a =>
                    let s, ok = json::as_string(a);
                    if !ok || c.aud.len + s.len + 2 > 1024 { bad = true; } else { add_audience(c, s); }
                };
                c.has = c.has | CLAIM_AUD;
            },
            _ => { bad = true; },
        }
        if bad { return jwx::ERR_MALFORMED; }
    }
    json::each(root) { m =>
        var registered = false;
        for r in ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"] {
            if r == m.key { registered = true; }
        }
        if !registered {
            jwx::put_comma(c.private);
            json::format_key(c.private, m.key);
            jws::write_node(c.private, m);
        }
    };
    return jwx::OK;
}

// --- Validation ------------------------------------------------------------------------

// What parse checks. `now` is the time in seconds since 1970 (0: the
// clock's); `skew` the seconds exp, nbf and iat may be off by; issuer,
// subject, audience and jwt_id, when not empty, must be the token's (the
// audience one of its audiences); `max_age`, when above 0, the most
// seconds since iat; `required` the CLAIM_* bits the token must have.
// `validate` false skips it all, as jwx's WithValidate(false).
struct Validator {
    validate: bool = true,
    now: i64 = 0,
    skew: i64 = 0,
    issuer: u8[..256] = [],
    subject: u8[..256] = [],
    audience: u8[..256] = [],
    jwt_id: u8[..256] = [],
    max_age: i64 = 0,
    required: u32 = 0,
}

fn validate(c: const Claims&, v: Validator) -> i64 {
    if !v.validate { return jwx::OK; }
    let now = if v.now != 0 { v.now } else { time_ns() / 1000000000 };
    if !has(c, v.required) { return jwx::ERR_MISSING_CLAIM; }
    // exp: the token is good while now < exp + skew (RFC 7519 §4.1.4).
    if c.has & CLAIM_EXP != 0 && now >= c.exp + v.skew { return jwx::ERR_EXPIRED; }
    // nbf: good once now + skew >= nbf (§4.1.5).
    if c.has & CLAIM_NBF != 0 && now + v.skew < c.nbf { return jwx::ERR_NOT_YET_VALID; }
    if c.has & CLAIM_IAT != 0 {
        if now + v.skew < c.iat { return jwx::ERR_IAT; }
        if v.max_age > 0 && now - v.skew > c.iat + v.max_age { return jwx::ERR_IAT; }
    } else if v.max_age > 0 {
        return jwx::ERR_MISSING_CLAIM;
    }
    if v.issuer.len > 0 && c.iss[..] != v.issuer[..] { return jwx::ERR_ISSUER; }
    if v.subject.len > 0 && c.sub[..] != v.subject[..] { return jwx::ERR_SUBJECT; }
    if v.jwt_id.len > 0 && c.jti[..] != v.jwt_id[..] { return jwx::ERR_JTI; }
    if v.audience.len > 0 {
        var found = false;
        for a in audiences(c) {
            if a == v.audience[..] { found = true; }
        }
        if !found { return jwx::ERR_AUDIENCE; }
    }
    return jwx::OK;
}

// --- Tokens -------------------------------------------------------------------------------

// A signed token (JWS compact, "typ": "JWT") of the claims.
fn sign(c: const Claims&, alg: i64, key: const jwk::Key&) -> u8[>..], i64 {
    var h = jws::Header { .. };
    h.alg = alg;
    h.typ.append("JWT");
    h.kid.append(key.kid);
    let out, err = jws::sign_with(marshal(c), key, h);
    return out, err;
}

// An encrypted token (JWE compact) of the claims.
fn encrypt(c: const Claims&, alg: i64, enc: i64, key: const jwk::Key&) -> u8[>..], i64 {
    var h = jwe::Header { .. };
    h.alg = alg;
    h.enc = enc;
    h.typ.append("JWT");
    h.kid.append(key.kid);
    let out, err = jwe::encrypt_with(marshal(c), key, h);
    return out, err;
}

// A nested token (RFC 7519 §5.2, Appendix A.2): the claims signed with
// sign_key, then that token encrypted to enc_key, "cty": "JWT".
fn sign_encrypt(c: const Claims&, sig_alg: i64, sign_key: const jwk::Key&, alg: i64, enc: i64,
                enc_key: const jwk::Key&) -> u8[>..], i64 {
    let inner, e = sign(c, sig_alg, sign_key);
    var out: u8[>..] = [];
    if e != jwx::OK { return out, e; }
    var h = jwe::Header { .. };
    h.alg = alg;
    h.enc = enc;
    h.cty.append("JWT");
    h.kid.append(enc_key.kid);
    let o, err = jwe::encrypt_with(inner, enc_key, h);
    out.append(o);
    return out, err;
}

fn finish(payload: const u8[:], err: i64, c: Claims&, v: Validator) -> i64 {
    if err != jwx::OK { return err; }
    let e = parse_claims(payload, c);
    if e != jwx::OK { return e; }
    return validate(c, v);
}

// A JWT is in the compact serialization only (RFC 7519 §1): a JSON JWS or
// JWE is ERR_MALFORMED.
fn compact(token: const u8[:]) -> bool {
    let t = trim(token);
    return t.len > 0 && t[0] != '{';
}

// Verifies a signed token by alg with key, reads its claims into c and
// validates them.

fn parse(token: const u8[:], alg: i64, key: const jwk::Key&, c: Claims&, v: Validator) -> i64 {
    if !compact(token) { return jwx::ERR_MALFORMED; }
    let payload, err = jws::verify(token, alg, key);
    return finish(payload, err, c, v);
}

// parse, with a key of a set (jws::verify_set).
fn parse_set(token: const u8[:], keys: const jwk::Key[:], c: Claims&, v: Validator, infer: bool = false) -> i64 {
    if !compact(token) { return jwx::ERR_MALFORMED; }
    let payload, err = jws::verify_set(token, keys, infer);
    return finish(payload, err, c, v);
}

// Decrypts an encrypted token by alg with key, reads its claims and
// validates them.
fn parse_encrypted(token: const u8[:], alg: i64, key: const jwk::Key&, c: Claims&, v: Validator) -> i64 {
    if !compact(token) { return jwx::ERR_MALFORMED; }
    let payload, err = jwe::decrypt(token, alg, key);
    return finish(payload, err, c, v);
}

// A nested token: decrypted by alg with dec_key, the token inside verified
// by sig_alg with verify_key.
fn parse_nested(token: const u8[:], alg: i64, dec_key: const jwk::Key&, sig_alg: i64, verify_key: const jwk::Key&,
                c: Claims&, v: Validator) -> i64 {
    if !compact(token) { return jwx::ERR_MALFORMED; }
    let inner, err = jwe::decrypt(token, alg, dec_key);
    if err != jwx::OK { return err; }
    if !compact(inner) { return jwx::ERR_MALFORMED; }
    let payload, e2 = jws::verify(inner, sig_alg, verify_key);
    return finish(payload, e2, c, v);
}

// A token's claims without verifying it (jwx's WithVerify(false)): for
// looking at a token, never for trusting one.
fn parse_insecure(token: const u8[:], c: Claims&) -> i64 {
    if !compact(token) { return jwx::ERR_MALFORMED; }
    var m = jws::Message { .. };
    let e = jws::parse(m, token);
    if e != jwx::OK { return e; }
    return parse_claims(m.payload, c);
}
