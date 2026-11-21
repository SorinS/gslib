// oauth.oidc: tokens checked against the issuer's keys. ID tokens as
// OpenID Connect Core §3.1.3.7 validates them (iss, aud, azp, exp and iat
// with a leeway, nonce, auth_time against max_age, at_hash and c_hash,
// the signature by a key of the issuer's JWKS and an alg the client
// allows, never "none"); JWT access tokens as a resource server checks
// them (RFC 9068: typ at+jwt, iss, aud, exp, scope); the binding of a
// sender-constrained token to a DPoP proof (RFC 9449 §4.3, §6) or to the
// client's certificate (RFC 8705 §3); and the UserInfo endpoint (OIDC
// Core §5.3), JSON or a signed JWT.
//
//   let id, err = oauth::validate_id_token(c, hc, t.id_token, ar.nonce, t.access_token);
//   let at, aerr = oauth::validate_access_token(rs, hc, token, "https://api.example.test", "read");
//
// The JWKS is fetched from the metadata's jwks_uri when a token first
// needs it, kept in the Client, and fetched again when a token names a key
// it does not hold, at most once every c.jwks_min_interval_s seconds.

namespace oauth;

import std;
import json;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.jws;
import jwx.jwt;
import crypto.bignum;
import crypto.bignum.sha256;
import crypto.bignum.hmac;
import crypto.bignum.sha3;
import net.http;
import net.http.client;
import net.http.fetch;
import oauth;

// --- Types ----------------------------------------------------------------------

// A validated ID token's claims (OIDC Core §2), and the whole payload in
// `claims` for the others (email, name, ...: claim_string).
struct IdToken {
    iss:       u8[..512]  = [],
    sub:       u8[..256]  = [],
    aud:       u8[..1024] = [],     // the audiences, one a line
    azp:       u8[..256]  = [],
    nonce:     u8[..256]  = [],
    exp:       i64        = 0,
    iat:       i64        = 0,
    auth_time: i64        = 0,      // 0 when absent
    acr:       u8[..256]  = [],
    sid:       u8[..256]  = [],
    at_hash:   u8[..128]  = [],
    c_hash:    u8[..128]  = [],
    alg:       i64        = jwa::UNKNOWN,
    kid:       u8[..256]  = [],
    claims:    u8[>..]    = [],
}

// A validated JWT access token (RFC 9068 §2.2), with its confirmation
// (cnf: jkt for DPoP, x5t#S256 for mutual TLS) and the whole payload.
struct AccessToken {
    iss:       u8[..512]  = [],
    sub:       u8[..256]  = [],
    aud:       u8[..1024] = [],     // one a line
    client_id: u8[..256]  = [],
    scope:     u8[..2048] = [],
    jti:       u8[..256]  = [],
    exp:       i64        = 0,
    iat:       i64        = 0,
    auth_time: i64        = 0,
    cnf_jkt:   u8[..64]   = [],
    cnf_x5t:   u8[..64]   = [],
    alg:       i64        = jwa::UNKNOWN,
    claims:    u8[>..]    = [],
}

// A verified DPoP proof (RFC 9449 §4.2): the thumbprint of its key (what
// a bound token's cnf.jkt must be), and its claims.
struct DpopProof {
    jkt:   u8[..64]   = [],
    jti:   u8[..256]  = [],
    htm:   u8[..16]   = [],
    htu:   u8[..1024] = [],
    iat:   i64        = 0,
    nonce: u8[..512]  = [],
    ath:   u8[..64]   = [],
    alg:   i64        = jwa::UNKNOWN,
}

// --- Claims ----------------------------------------------------------------------

// A string claim of a token's payload (IdToken.claims, AccessToken.claims,
// UserInfo's JSON): false when absent or not a string.
fn claim_string(payload: const u8[:], name: const u8[:]) -> u8[>..], bool {
    var out:     u8[>..]         = [];
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(payload, doc, decoded);
    let v, ok = json::as_string(json::member(root, name));
    if ok { out.append(v); }
    return out, ok;
}

fn claim_int(payload: const u8[:], name: const u8[:]) -> i64, bool {
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(payload, doc, decoded);
    let v, ok = json::as_i64(json::member(root, name));
    return v, ok;
}

fn claim_bool(payload: const u8[:], name: const u8[:]) -> bool, bool {
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(payload, doc, decoded);
    let v, ok = json::as_bool(json::member(root, name));
    return v, ok;
}

// A token's audiences one a line, for IdToken.aud and AccessToken.aud:
// false when they do not all fit in 1024 bytes, or one holds a line end
// (it would read as two audiences). The token is refused then.
fn aud_lines(cl: const jwt::Claims&) -> u8[>..], bool {
    var out: u8[>..] = [];
    for a in jwt::audiences(cl) {
        if position(a, '\n') >= 0 || out.len + a.len + 1 > 1024 + 1 { out.clear(); return out, false; }
        if out.len > 0 { out.push('\n'); }
        out.append(a);
    }
    return out, true;
}

// --- The issuer's keys --------------------------------------------------------------

// The keys of a JWK Set instead of the issuer's jwks_uri (offline, or
// keys known beforehand). Keys of types this package does not do are
// passed over.
fn set_keys(c: Client&, jwks: const u8[:]) -> i64 {
    var keys: jwk::Key[>..] = [];
    if jwk::parse_set(jwks, keys) != jwx::OK { return ERR_MALFORMED; }
    c.keys.clear();
    for &k in keys { c.keys.push(k); }
    c.jwks_fetched_ns = clock_ns();
    return OK;
}

// Fetches the issuer's JWKS from its jwks_uri.
fn fetch_jwks(c: Client&, hc: http::Client&) -> i64 {
    if c.meta.jwks_uri.len == 0 { return ERR_ARG; }
    if !url_allowed(c, c.meta.jwks_uri) { return ERR_INSECURE; }
    c.jwks_fetches++;
    c.jwks_fetched_ns = clock_ns();
    let r = http::request(hc, "GET", c.meta.jwks_uri, "Accept: application/json\r\n", "");
    if r.err != 0 { c.http_err = r.err; return ERR_HTTP; }
    if r.status != 200 {
        c.error = error_of(http::response_body(r), r.status);
        return ERR_OAUTH;
    }
    let e = set_keys(c, http::response_body(r));
    c.jwks_fetched_ns = clock_ns();
    return e;
}

// Whether the JWKS may be fetched again now (at clock_ns() `now_ns`): never
// fetched, or fetched at least jwks_min_interval_s ago.
fn jwks_may_refetch(c: const Client&, now_ns: i64) -> bool {
    return c.jwks_fetched_ns == 0 || now_ns - c.jwks_fetched_ns >= c.jwks_min_interval_s * 1000000000;
}

// Whether tokens may be signed with alg: one of c.algs, or when that is
// empty RS*, PS*, ES* and EdDSA. Never "none", and HMAC only when listed.
fn alg_allowed(c: const Client&, alg: i64) -> bool {
    if alg == jwa::NONE || alg == jwa::UNKNOWN || !jwa::is_signature(alg) { return false; }
    if c.algs.len > 0 {
        for a in c.algs {
            if a == alg { return true; }
        }
        return false;
    }
    return jwa::is_rsa_pkcs1(alg) || jwa::is_rsa_pss(alg) || jwa::is_ecdsa(alg) || jwa::is_eddsa(alg);
}

fn try_keys(c: const Client&, m: const jws::Message&, alg: i64, kid: const u8[:]) -> i64 {
    var tried = false;
    for &k in c.keys {
        if kid.len > 0 && k.kid[..] != kid { continue; }
        if k.key_use == jwk::USE_ENC || !jwk::fits(k, alg) { continue; }
        tried = true;
        if jws::verify_signature(m, 0, alg, k) == jwx::OK { return OK; }
    }
    return if tried { ERR_SIGNATURE } else { ERR_NO_KEY };
}

// Parses a compact JWS into m and verifies it: the header's alg must be
// allowed (alg_allowed), and the key the issuer's (by kid, or any that
// fits when there is none), fetching the JWKS when it has not been and
// again for a kid it does not hold (rate-limited). An HMAC alg, when
// allowed, is verified with the client secret (OIDC Core §10.1).
fn verify_signed(c: Client&, hc: http::Client&, m: jws::Message&, token: const u8[:]) -> i64 {
    // The JSON serialization is refused before it is parsed.
    if !jwt::compact(token) { return ERR_MALFORMED; }
    let e = jws::parse(m, token);
    if e == jwx::ERR_UNSUPPORTED { return ERR_ALG; }
    if e != jwx::OK || !m.compact || m.sigs.len != 1 { return ERR_MALFORMED; }
    let alg = m.sigs[0].header.alg;
    if !alg_allowed(c, alg) { return ERR_ALG; }
    if jwa::is_hmac(alg) {
        if c.secret.len == 0 || c.secret.len > jwk::MAX_OCT { return ERR_NO_KEY; }
        var k = jwk::empty();
        k.kty = jwa::KTY_OCT;
        k.private = true;
        k.k.append(c.secret);
        return if jws::verify_signature(m, 0, alg, k) == jwx::OK { OK } else { ERR_SIGNATURE };
    }
    var kid: u8[..256] = [];
    kid.append(m.sigs[0].header.kid);
    if c.keys.len == 0 && c.jwks_fetched_ns == 0 && c.meta.jwks_uri.len > 0 {
        let fe = fetch_jwks(c, hc);
        if fe != OK { return fe; }
    }
    var r = try_keys(c, m, alg, kid);
    if r == ERR_NO_KEY && c.meta.jwks_uri.len > 0 && jwks_may_refetch(c, clock_ns()) {
        let fe = fetch_jwks(c, hc);
        if fe != OK { return fe; }
        r = try_keys(c, m, alg, kid);
    }
    return r;
}

// --- ID tokens ---------------------------------------------------------------------------

// at_hash and c_hash (OIDC Core §3.1.3.6, §3.3.2.11): the left half of the
// value's hash by the hash of the token's alg, in base64url. EdDSA's
// depends on the curve (`crv`, the signing key's): SHA-512 for Ed25519,
// SHAKE256 to 114 bytes for Ed448 (as alg "Ed448", RFC 9864, is too).
fn token_hash(alg: i64, value: const u8[:], crv: i64 = jwa::CRV_ED25519) -> u8[>..] {
    var out: u8[>..] = [];
    if alg == jwa::ED448 || (alg == jwa::EDDSA && crv == jwa::CRV_ED448) {
        var s = bignum::shake_init(256);
        bignum::sha3_update(s, value);
        var d: u8[114] = [0; 114];
        bignum::shake_read(s, d);
        out.append(jwx::b64_encode(d[..57]));
        return out;
    }
    var bits = jwa::hash_of(alg);
    if jwa::is_eddsa(alg) { bits = bignum::HASH_SHA512; }
    if bits == 0 { return out; }
    let d = bignum::hash_bits(bits, value);
    out.append(jwx::b64_encode(d[..d.len / 2]));
    return out;
}

// The curve of the issuer's key that verifies m (for EdDSA's hashes).
fn signer_crv(c: const Client&, m: const jws::Message&, alg: i64) -> i64 {
    let kid = m.sigs[0].header.kid[..];
    for &k in c.keys {
        if kid.len > 0 && k.kid[..] != kid { continue; }
        if k.key_use == jwk::USE_ENC || !jwk::fits(k, alg) { continue; }
        if jws::verify_signature(m, 0, alg, k) == jwx::OK { return k.crv; }
    }
    return jwa::CRV_UNKNOWN;
}

fn typ_is(typ: const u8[:], want: const u8[:]) -> bool {
    if eq_fold(typ, want) { return true; }
    let app = "application/";
    return typ.len == app.len + want.len && eq_fold(typ[..app.len], app) && eq_fold(typ[app.len..], want);
}

// Whether a typ names some kind of JWT other than a plain one: "+jwt"
// at its end, with or without "application/".
fn other_jwt(typ: const u8[:]) -> bool {
    let suffix = "+jwt";
    return typ.len >= suffix.len && eq_fold(typ[typ.len - suffix.len..], suffix);
}

// Validates an ID token (OIDC Core §3.1.3.7) for this client: `nonce` is
// the authorization request's (ar.nonce; must match when not empty);
// `access_token` and `code`, when given, are checked against at_hash and
// c_hash if the token has them; `max_age` (-1: none) asks for auth_time
// no older than that.
fn validate_id_token(c: Client&, hc: http::Client&, token: const u8[:], nonce: const u8[:],
                     access_token: const u8[:] = "", code: const u8[:] = "", max_age: i64 = -1) -> IdToken, i64 {
    var id = IdToken { .. };
    var m = jws::Message { .. };
    let ve = verify_signed(c, hc, m, token);
    if ve != OK { return id, ve; }
    let alg = m.sigs[0].header.alg;
    // An access token (RFC 9068), a logout token (OIDC Back-Channel Logout
    // §2.4), or any other explicitly typed JWT (RFC 8725 §3.11) is not an
    // ID token.
    if other_jwt(m.sigs[0].header.typ) { return id, ERR_TYP; }
    id.alg = alg;
    id.kid.append(m.sigs[0].header.kid);
    var cl = jwt::new_claims();
    if jwt::parse_claims(m.payload, cl) != jwx::OK { return id, ERR_MALFORMED; }
    id.claims.append(m.payload);
    id.iss.append(cl.iss);
    id.sub.append(cl.sub);
    let al, alok = aud_lines(cl);
    if !alok { return IdToken { .. }, ERR_MALFORMED; }
    id.aud.append(al);
    id.exp = cl.exp;
    id.iat = cl.iat;
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(m.payload, doc, decoded);
    guard root else { return id, ERR_MALFORMED; }
    // A logout token carries "events"; one typed as a plain JWT is still
    // not an ID token.
    if json::member(root, "events") { return id, ERR_TYP; }
    // Each whole or the token refused: an azp, nonce, at_hash or c_hash
    // that is not a string would otherwise read as absent, and its check
    // be passed over.
    let azp, ok1 = str_field(root, "azp", 256);
    let n, ok2 = str_field(root, "nonce", 256);
    let acr, ok3 = str_field(root, "acr", 256);
    let sid, ok4 = str_field(root, "sid", 256);
    let ath, ok5 = str_field(root, "at_hash", 128);
    let ch, ok6 = str_field(root, "c_hash", 128);
    if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) { return IdToken { .. }, ERR_MALFORMED; }
    id.azp.append(azp);
    id.nonce.append(n);
    id.acr.append(acr);
    id.sid.append(sid);
    id.at_hash.append(ath);
    id.c_hash.append(ch);
    id.auth_time = int_member(root, "auth_time");

    if id.iss[..] != c.meta.issuer[..] { return id, ERR_ISSUER; }
    if cl.sub.len == 0 { return id, ERR_CLAIM; }
    var mine = false;
    var count = 0;
    for a in jwt::audiences(cl) {
        count++;
        if a == c.client_id[..] { mine = true; }
    }
    if !mine { return id, ERR_AUDIENCE; }
    // Several audiences: the token says which party it was issued to (§2).
    if count > 1 && id.azp.len == 0 { return id, ERR_AZP; }
    if id.azp.len > 0 && id.azp[..] != c.client_id[..] { return id, ERR_AZP; }
    let now = now_s(c);
    if cl.has & jwt::CLAIM_EXP == 0 || cl.has & jwt::CLAIM_IAT == 0 { return id, ERR_CLAIM; }
    if now >= cl.exp + c.leeway { return id, ERR_EXPIRED; }
    if cl.has & jwt::CLAIM_NBF != 0 && now + c.leeway < cl.nbf { return id, ERR_EXPIRED; }
    if cl.iat > now + c.leeway { return id, ERR_IAT; }
    if nonce.len > 0 && id.nonce[..] != nonce { return id, ERR_NONCE; }
    if max_age >= 0 {
        if id.auth_time == 0 { return id, ERR_AUTH_TIME; }
        if now - id.auth_time > max_age + c.leeway { return id, ERR_AUTH_TIME; }
    }
    let crv = if alg == jwa::EDDSA { signer_crv(c, m, alg) } else { jwa::CRV_UNKNOWN };
    if access_token.len > 0 && id.at_hash.len > 0 && token_hash(alg, access_token, crv)[..] != id.at_hash[..] {
        return id, ERR_AT_HASH;
    }
    if code.len > 0 && id.c_hash.len > 0 && token_hash(alg, code, crv)[..] != id.c_hash[..] { return id, ERR_C_HASH; }
    return id, OK;
}

// --- JWT access tokens (RFC 9068) ------------------------------------------------------------

// Validates a JWT access token as a resource server does (RFC 9068 §4):
// typ "at+jwt", signed by the issuer (c.meta, c.keys), iss the issuer,
// `audience` one of its audiences, not expired, iat not ahead, the claims
// §2.2 requires there, and every scope of `scope` (space-separated) in
// its scope. Binding (at.cnf_jkt, at.cnf_x5t) is checked by
// check_dpop_binding and check_cert_binding.
fn validate_access_token(c: Client&, hc: http::Client&, token: const u8[:], audience: const u8[:],
                         scope: const u8[:] = "") -> AccessToken, i64 {
    var at = AccessToken { .. };
    var m = jws::Message { .. };
    let ve = verify_signed(c, hc, m, token);
    if ve != OK { return at, ve; }
    if !typ_is(m.sigs[0].header.typ, "at+jwt") { return at, ERR_TYP; }
    at.alg = m.sigs[0].header.alg;
    var cl = jwt::new_claims();
    if jwt::parse_claims(m.payload, cl) != jwx::OK { return at, ERR_MALFORMED; }
    at.claims.append(m.payload);
    at.iss.append(cl.iss);
    at.sub.append(cl.sub);
    at.jti.append(cl.jti);
    let al, alok = aud_lines(cl);
    if !alok { return AccessToken { .. }, ERR_MALFORMED; }
    at.aud.append(al);
    at.exp = cl.exp;
    at.iat = cl.iat;
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(m.payload, doc, decoded);
    guard root else { return at, ERR_MALFORMED; }
    let ci, ok1 = str_field(root, "client_id", 256);
    let sc, ok2 = str_field(root, "scope", 2048);
    if !ok1 || !ok2 { return AccessToken { .. }, ERR_MALFORMED; }
    at.client_id.append(ci);
    at.scope.append(sc);
    at.auth_time = int_member(root, "auth_time");
    if !read_cnf(root, at.cnf_jkt, at.cnf_x5t) { return AccessToken { .. }, ERR_MALFORMED; }

    if at.iss[..] != c.meta.issuer[..] { return at, ERR_ISSUER; }
    var mine = false;
    for a in jwt::audiences(cl) {
        if a == audience { mine = true; }
    }
    if !mine || audience.len == 0 { return at, ERR_AUDIENCE; }
    let now = now_s(c);
    if cl.has & jwt::CLAIM_EXP == 0 { return at, ERR_CLAIM; }
    if now >= cl.exp + c.leeway { return at, ERR_EXPIRED; }
    if cl.has & jwt::CLAIM_NBF != 0 && now + c.leeway < cl.nbf { return at, ERR_EXPIRED; }
    if cl.has & jwt::CLAIM_IAT == 0 { return at, ERR_CLAIM; }
    if cl.iat > now + c.leeway { return at, ERR_IAT; }
    if cl.sub.len == 0 || cl.jti.len == 0 || at.client_id.len == 0 { return at, ERR_CLAIM; }
    if !has_scopes(at.scope, scope) { return at, ERR_SCOPE; }
    return at, OK;
}

// --- Sender-constrained tokens -----------------------------------------------------------

// The x5t#S256 of a certificate (RFC 8705 §3.1): base64url(SHA-256(DER)).
fn cert_thumbprint(der: const u8[:]) -> u8[>..] {
    let d = bignum::sha256(der);
    return jwx::b64_encode(d[..]);
}

// OK when a token's cnf (cnf_x5t) binds it to the client's certificate
// (DER), as the resource server saw it in the TLS handshake; ERR_CNF when
// it is another's or the token is not bound.
fn check_cert_binding(cnf_x5t: const u8[:], cert_der: const u8[:]) -> i64 {
    if cnf_x5t.len == 0 || cert_der.len == 0 { return ERR_CNF; }
    return if cert_thumbprint(cert_der)[..] == cnf_x5t { OK } else { ERR_CNF };
}

// OK when a token's cnf.jkt is the thumbprint of the DPoP proof's key
// (RFC 9449 §6.1, §7.1).
fn check_dpop_binding(cnf_jkt: const u8[:], p: const DpopProof&) -> i64 {
    if cnf_jkt.len == 0 || p.jkt.len == 0 { return ERR_CNF; }
    return if p.jkt[..] == cnf_jkt { OK } else { ERR_CNF };
}

// Checks a DPoP proof as a server does (RFC 9449 §4.3): one JWS, typ
// "dpop+jwt", an asymmetric alg the client allows, signed by the public
// key in its header; jti there; htm and htu this request's (htu without
// query and fragment); iat within max_age_s (and the leeway) of now; the
// nonce when one is expected; ath the access token's hash when a token
// goes with it. The thumbprint of its key is p.jkt.
fn verify_dpop_proof(c: const Client&, proof: const u8[:], htm: const u8[:], htu: const u8[:],
                     access_token: const u8[:] = "", nonce: const u8[:] = "", max_age_s: i64 = 300) -> DpopProof, i64 {
    var p = DpopProof { .. };
    if !jwt::compact(proof) { return p, ERR_DPOP; }
    var m = jws::Message { .. };
    let e = jws::parse(m, proof);
    if e == jwx::ERR_UNSUPPORTED { return p, ERR_ALG; }
    if e != jwx::OK || !m.compact || m.sigs.len != 1 { return p, ERR_DPOP; }
    if !eq_fold(m.sigs[0].header.typ, "dpop+jwt") { return p, ERR_TYP; }
    let alg = m.sigs[0].header.alg;
    if !alg_allowed(c, alg) || jwa::is_hmac(alg) { return p, ERR_ALG; }
    if !m.sigs[0].header.has_jwk { return p, ERR_DPOP; }
    if jws::verify_signature(m, 0, alg, m.sigs[0].header.jwk) != jwx::OK { return p, ERR_SIGNATURE; }
    p.alg = alg;
    p.jkt.append(jwk::thumbprint_b64(m.sigs[0].header.jwk));
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(m.payload, doc, decoded);
    guard root else { return p, ERR_DPOP; }
    let jti = str_member(root, "jti");
    let pm = str_member(root, "htm");
    let pu = str_member(root, "htu");
    let pn = str_member(root, "nonce");
    let pa = str_member(root, "ath");
    if jti.len == 0 || jti.len > 256 || pm.len > 16 || pu.len > 1024 || pn.len > 512 || pa.len > 64 { return p, ERR_DPOP; }
    p.jti.append(jti);
    p.htm.append(pm);
    p.htu.append(pu);
    p.nonce.append(pn);
    p.ath.append(pa);
    let iat, has_iat = json::as_i64(json::member(root, "iat"));
    if !has_iat { return p, ERR_IAT; }
    p.iat = iat;
    if p.htm[..] != htm || p.htu[..] != dpop_htu(htu) { return p, ERR_DPOP; }
    let now = now_s(c);
    if iat > now + c.leeway || iat < now - max_age_s - c.leeway { return p, ERR_IAT; }
    if nonce.len > 0 && p.nonce[..] != nonce { return p, ERR_DPOP; }
    if access_token.len > 0 && p.ath[..] != dpop_ath(access_token)[..] { return p, ERR_DPOP; }
    return p, OK;
}

// --- UserInfo (OIDC Core §5.3) ---------------------------------------------------------------

// The UserInfo response for an access token, as JSON: a signed response
// (application/jwt, §5.3.2) is verified by the issuer's keys and its iss
// and aud checked. Its sub must be `expect_sub` (the ID token's) when
// that is given (ERR_SUBJECT).
fn userinfo(c: Client&, hc: http::Client&, t: const Token&, expect_sub: const u8[:] = "") -> u8[>..], i64 {
    var out: u8[>..] = [];
    let url = endpoint(c, c.meta.userinfo_endpoint, c.meta.mtls_userinfo);
    if url.len == 0 { return out, ERR_ARG; }
    let r, err = resource_request(c, hc, "GET", url, t, "Accept: application/json\r\n");
    if err != OK { return out, err; }
    if r.status != 200 {
        c.error = error_of(http::response_body(r), r.status);
        return out, ERR_OAUTH;
    }
    let ct, has_ct = http::response_header(r, "Content-Type");
    var payload: u8[>..] = [];
    if has_ct && ct.len >= 15 && eq_fold(ct[..15], "application/jwt") {
        var m = jws::Message { .. };
        let ve = verify_signed(c, hc, m, trim(http::response_body(r)));
        if ve != OK { return out, ve; }
        var cl = jwt::new_claims();
        if jwt::parse_claims(m.payload, cl) != jwx::OK { return out, ERR_MALFORMED; }
        if cl.iss.len > 0 && cl.iss[..] != c.meta.issuer[..] { return out, ERR_ISSUER; }
        if cl.has & jwt::CLAIM_AUD != 0 {
            var mine = false;
            for a in jwt::audiences(cl) {
                if a == c.client_id[..] { mine = true; }
            }
            if !mine { return out, ERR_AUDIENCE; }
        }
        payload.append(m.payload);
    } else {
        payload.append(http::response_body(r));
    }
    let sub, ok = claim_string(payload, "sub");
    if !ok || sub.len == 0 { return out, ERR_MALFORMED; }
    if expect_sub.len > 0 && sub[..] != expect_sub { return out, ERR_SUBJECT; }
    out.append(payload);
    return out, OK;
}
