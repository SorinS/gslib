// acme: an ACME client (RFC 8555), for getting certificates from Let's
// Encrypt, from an enterprise's own CA (Vault and OpenBao's PKI, step-ca,
// EJBCA) or from a commercial CA that binds accounts to one of its own
// (external account binding, §7.3.4). Accounts, orders, the http-01 and
// dns-01 challenges, finalizing with a CSR, downloading the chain,
// revoking, rolling the account key over, deactivating.
//
//   var hc = http::Client { .. };
//   var a = acme::Client { .. };
//   let key = jwk::generate_ec(jwa::CRV_P256);  // kept: jwk::marshal, in a file only you read
//   acme::set_key(a, key);
//   acme::open(a, hc, "https://acme-staging-v02.api.letsencrypt.org/directory");
//   acme::new_account(a, hc, "mailto:admin@example.com", true);
//   var o, err = acme::new_order(a, hc, "example.com\nwww.example.com");
//   for url in split(o.authz, '\n') {
//       let z, err = acme::get_authz(a, hc, url);
//       let i = acme::find_challenge(z, "http-01");
//       // serve acme::key_authorization(a, token) at acme::http01_path(token)
//       acme::accept(a, hc, z.challenges[i]);
//       acme::wait_authz(a, hc, url);
//   }
//   acme::finalize(a, hc, o, csr_der);           // waits for the order to be valid
//   let chain, err = acme::certificate(a, hc, o); // PEM, the leaf first
//
// Or all of it in one call, the challenges published by a block:
//
//   let chain, err = acme::obtain(a, hc, names, csr_der, "dns-01") { z, ch, value => publish(...) };  // true if it did
//
// Every request is a JWS (flattened JSON) signed by the account key, with
// a fresh nonce from the server and the URL it goes to; a nonce the
// server turns down (badNonce) is replaced and the request sent again.
// The http::Client is the caller's: its TLS configuration says which CA
// certificates the server's may chain to (the system's by default).

namespace acme;

import std;
import json;
import jwx;
import jwx.jwa;
import jwx.jwk;
import jwx.jws;
import crypto.bignum;
import crypto.bignum.sha256;
import net.http;
import net.http.client;
import net.http.fetch;
import net.http.cookie;

// --- Errors -------------------------------------------------------------------

let OK:             i64 = 0;
let ERR_ARG:        i64 = 1;    // an argument that cannot be used
let ERR_HTTP:       i64 = 2;    // no response: the connection, TLS, a timeout (a.http_err says which)
let ERR_PROBLEM:    i64 = 3;    // the server refused, with a problem document (a.problem)
let ERR_MALFORMED:  i64 = 4;    // a response that is not what RFC 8555 says it is
let ERR_KEY:        i64 = 5;    // no key, or one that cannot sign
let ERR_INVALID:    i64 = 6;    // an authorization or order went invalid (its error says why)
let ERR_TIMEOUT:    i64 = 7;    // still pending or processing when poll_timeout_ms ran out
let ERR_NO_ACCOUNT: i64 = 8;    // a request that needs an account, before there is one
let ERR_PUBLISH:    i64 = 9;    // obtain's block could not publish a challenge

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_HTTP { return "the request failed"; }
    if e == ERR_PROBLEM { return "the server refused the request"; }
    if e == ERR_MALFORMED { return "the server's response is not ACME"; }
    if e == ERR_KEY { return "the account key cannot sign"; }
    if e == ERR_INVALID { return "the authorization or order is invalid"; }
    if e == ERR_TIMEOUT { return "the server did not finish in time"; }
    if e == ERR_NO_ACCOUNT { return "no account yet"; }
    if e == ERR_PUBLISH { return "a challenge could not be published"; }
    return "";
}

// The status of an account, order, authorization or challenge (§7.1.6).
let ST_UNKNOWN:     i64 = 0;
let ST_PENDING:     i64 = 1;
let ST_READY:       i64 = 2;
let ST_PROCESSING:  i64 = 3;
let ST_VALID:       i64 = 4;
let ST_INVALID:     i64 = 5;
let ST_EXPIRED:     i64 = 6;
let ST_DEACTIVATED: i64 = 7;
let ST_REVOKED:     i64 = 8;

let STATUS_NAMES: const u8[:][] = ["", "pending", "ready", "processing", "valid", "invalid", "expired",
                                   "deactivated", "revoked"];

fn status_name(s: i64) -> const u8[:] { if s >= 0 && s < STATUS_NAMES.len { STATUS_NAMES[s] } else { "" } }

fn status_lookup(s: const u8[:]) -> i64 {
    for name, i in STATUS_NAMES {
        if i > 0 && name == s { return i; }
    }
    return ST_UNKNOWN;
}

// Revocation reasons (RFC 5280 §5.3.1) for revoke.
let REASON_NONE:                   i64 = -1;
let REASON_UNSPECIFIED:            i64 = 0;
let REASON_KEY_COMPROMISE:         i64 = 1;
let REASON_AFFILIATION_CHANGED:    i64 = 3;
let REASON_SUPERSEDED:             i64 = 4;
let REASON_CESSATION_OF_OPERATION: i64 = 5;

// --- Types ----------------------------------------------------------------------

// A problem document (RFC 9457, §6.7): its type (urn:ietf:params:acme:error:
// and the rest), what the server says, the HTTP status, and how many
// subproblems it had (§6.7.1).
struct Problem {
    status:      i64        = 0,
    kind:        u8[..256]  = [],
    detail:      u8[..1024] = [],
    subproblems: i64        = 0,
    truncated:   bool       = false,   // detail was cut at 1024 bytes
}

// The directory (§7.1.1): the URLs of the server's resources, and its
// metadata.
struct Directory {
    new_nonce:        u8[..512]  = [],
    new_account:      u8[..512]  = [],
    new_order:        u8[..512]  = [],
    new_authz:        u8[..512]  = [],
    revoke_cert:      u8[..512]  = [],
    key_change:       u8[..512]  = [],
    renewal_info:     u8[..512]  = [],    // RFC 9773 (ARI)
    terms_of_service: u8[..512]  = [],
    website:          u8[..512]  = [],
    eab_required:     bool       = false, // externalAccountRequired
    profiles:         u8[..1024] = [],    // the names of the profiles offered, one a line
    profiles_truncated: bool     = false, // profiles left empty: more than fit, or a name with a line end
}

// An ACME client: the server's directory, the account key and the
// account's URL once there is one, and the nonce the next request takes.
// `problem` is the last refusal; `retry_after_ms` the last Retry-After.
root struct Client {
    dir:             Directory = Directory { .. },
    key:             jwk::Key  = jwk::empty(),
    alg:             i64       = jwa::UNKNOWN,
    account:         u8[..512] = [],
    account_status:  i64       = ST_UNKNOWN,
    nonce:           u8[..256] = [],
    problem:         Problem   = Problem { .. },
    http_err:        i64       = 0,
    retry_after_ms:  i64       = 0,
    poll_ms:         i64       = 1000,    // between polls when the server gives no Retry-After
    poll_timeout_ms: i64       = 120000,  // how long wait_authz and wait_order wait
    nonce_retries:   i64       = 3,       // how often a request is sent again after a badNonce
}

// An order (§7.1.3). `authz` holds its authorizations' URLs, one a line.
struct Order {
    status:      i64       = ST_UNKNOWN,
    url:         u8[..512] = [],
    expires:     u8[..64]  = [],
    finalize:    u8[..512] = [],
    certificate: u8[..512] = [],
    profile:     u8[..64]  = [],
    error:       Problem   = Problem { .. },
    authz:       u8[>..]   = [],
}

// One challenge of an authorization (§7.1.5, §8).
struct Challenge {
    kind:   u8[..32]  = [],               // "http-01", "dns-01", "tls-alpn-01", ...
    url:    u8[..512] = [],
    token:  u8[..256] = [],
    status: i64       = ST_UNKNOWN,
    error:  Problem   = Problem { .. },
}

// An authorization (§7.1.4): the identifier, and the challenges that can
// prove control of it. A wildcard's identifier is the name without "*.".
struct Authz {
    url:        u8[..512]      = [],
    id_type:    u8[..16]       = [],      // "dns" or "ip"
    id_value:   u8[..256]      = [],
    status:     i64            = ST_UNKNOWN,
    wildcard:   bool           = false,
    expires:    u8[..64]       = [],
    challenges: Challenge[..8] = [],
}

// --- Keys -----------------------------------------------------------------------

// The JWS algorithm for an account key: ES256, ES384 or ES512 by the
// curve, RS256 for RSA, EdDSA for Ed25519 and Ed448 (which not every CA takes;
// Let's Encrypt takes ES256 and RS256). UNKNOWN for anything else.
fn alg_for(k: const jwk::Key&) -> i64 {
    if k.kty == jwa::KTY_EC {
        if k.crv == jwa::CRV_P256 { return jwa::ES256; }
        if k.crv == jwa::CRV_P384 { return jwa::ES384; }
        if k.crv == jwa::CRV_P521 { return jwa::ES512; }
    }
    if k.kty == jwa::KTY_RSA { return jwa::RS256; }
    if k.kty == jwa::KTY_OKP && (k.crv == jwa::CRV_ED25519 || k.crv == jwa::CRV_ED448) { return jwa::EDDSA; }
    return jwa::UNKNOWN;
}

// Sets the account key (a private key); ERR_KEY if it cannot sign.
fn set_key(a: Client&, k: const jwk::Key&) -> i64 {
    let alg = alg_for(k);
    if alg == jwa::UNKNOWN || !k.private { return ERR_KEY; }
    a.key = k;
    a.key.kid.clear();      // the header names the account by "kid" itself, or carries the key
    a.alg = alg;
    return OK;
}

// The key authorization for a challenge's token (§8.1): the token, a dot,
// and the account key's RFC 7638 thumbprint.
fn key_authorization(a: const Client&, token: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(token);
    out.push('.');
    out.append(jwk::thumbprint_b64(a.key));
    return out;
}

// What http-01 serves at http01_path(token): the key authorization.
fn http01_path(token: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("/.well-known/acme-challenge/");
    out.append(token);
    return out;
}

// The TXT record dns-01 asks for (§8.4): the key authorization's SHA-256,
// in base64url.
fn dns01_value(a: const Client&, token: const u8[:]) -> u8[>..] {
    let d = bignum::sha256(key_authorization(a, token));
    return jwx::b64_encode(d[..]);
}

// The name that TXT record goes on: _acme-challenge. and the domain, a
// wildcard's without its "*.".
fn dns01_name(domain: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("_acme-challenge.");
    out.append(if domain.len > 2 && domain[..2] == "*." { domain[2..] } else { domain });
    return out;
}

// What a challenge's block publishes: the key authorization for http-01
// (and tls-alpn-01), the TXT value for dns-01.
fn challenge_value(a: const Client&, ch: const Challenge&) -> u8[>..] {
    if ch.kind == "dns-01" { return dns01_value(a, ch.token); }
    return key_authorization(a, ch.token);
}

// --- JSON -------------------------------------------------------------------------

fn str_member(n: json::Node?, name: const u8[:]) -> const u8[:] {
    let s, ok = json::as_string(json::member(n, name));
    return if ok { s } else { "" };
}

// Sets a field (a URL, a date, a name): false when the value does not fit,
// so that a document with one is refused rather than read with it missing.
fn put_limited<A>(out: A&, s: const u8[:]) -> bool {
    out.clear();
    if s.len > out.cap { return false; }
    out.append(s);
    return true;
}

// Whether a challenge's token is what §8.1 says it is: base64url, and
// nothing that could name another file when http-01 serves or writes it.
fn valid_token(t: const u8[:]) -> bool {
    if t.len == 0 || t.len > 256 { return false; }
    for c in t {
        let ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if !ok { return false; }
    }
    return true;
}

// A problem document, and whether its type fits: a type over 256 bytes is
// not kept (a cut-short type could read as another), and detail says so.
// Only the detail, text for people, is cut, at 1024 bytes, with
// `truncated` set.
fn read_problem(n: json::Node?, status: i64) -> Problem, bool {
    var p = Problem { .. };
    p.status = status;
    let t = str_member(n, "type");
    let d = str_member(n, "detail");
    let subs = json::member(n, "subproblems");
    if subs { json::each(subs) { s => p.subproblems++; }; }
    if t.len > p.kind.cap {
        p.detail.append("a problem document with an over-long type");
        return p, false;
    }
    p.kind.append(t);
    p.truncated = d.len > p.detail.cap;
    p.detail.append(d[..min(d.len, p.detail.cap)]);
    return p, true;
}

// A problem from a response's body; a body that is not one still gives
// the status, with "detail" saying so.
fn problem_of(body: const u8[:], status: i64) -> Problem {
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(body, doc, decoded);
    guard root else {
        var p = Problem { .. };
        p.status = status;
        p.detail.append("not a problem document");
        return p;
    }
    let p, ok = read_problem(root, status);
    return p;
}

// Whether the last refusal was of this type, given without the
// "urn:ietf:params:acme:error:" before it: is_problem(a, "badNonce").
fn is_problem(a: const Client&, name: const u8[:]) -> bool {
    let prefix = "urn:ietf:params:acme:error:";
    let k = a.problem.kind[..];
    return k.len == prefix.len + name.len && k[..prefix.len] == prefix && k[prefix.len..] == name;
}

fn read_directory(text: const u8[:]) -> Directory, bool {
    var d = Directory { .. };
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return d, false; }
    var fits = put_limited(d.new_nonce, str_member(root, "newNonce"));
    fits = put_limited(d.new_account, str_member(root, "newAccount")) && fits;
    fits = put_limited(d.new_order, str_member(root, "newOrder")) && fits;
    fits = put_limited(d.new_authz, str_member(root, "newAuthz")) && fits;
    fits = put_limited(d.revoke_cert, str_member(root, "revokeCert")) && fits;
    fits = put_limited(d.key_change, str_member(root, "keyChange")) && fits;
    fits = put_limited(d.renewal_info, str_member(root, "renewalInfo")) && fits;
    let meta = json::member(root, "meta");
    if meta {
        fits = put_limited(d.terms_of_service, str_member(meta, "termsOfService")) && fits;
        fits = put_limited(d.website, str_member(meta, "website")) && fits;
        let eab, ok = json::as_bool(json::member(meta, "externalAccountRequired"));
        d.eab_required = ok && eab;
        let profiles = json::member(meta, "profiles");
        if profiles {
            // One a line, for the caller to read (obtain takes the profile
            // it is given): a name with a line end in it, or more than
            // fit, and the list is left empty, never cut, with
            // profiles_truncated set.
            json::each(profiles) { p =>
                if position(p.key, '\n') >= 0 || d.profiles.len + p.key.len + 1 > d.profiles.cap {
                    d.profiles_truncated = true;
                } else if !d.profiles_truncated {
                    d.profiles.append(p.key);
                    d.profiles.push('\n');
                }
            };
            if d.profiles_truncated { d.profiles.clear(); }
        }
    }
    let ok = fits && d.new_nonce.len > 0 && d.new_account.len > 0 && d.new_order.len > 0;
    return d, ok;
}

// An order from its JSON; `url` is where it lives (the Location of
// newOrder's response, or the URL it was fetched from).
fn read_order(text: const u8[:], url: const u8[:]) -> Order, bool {
    var o = Order { .. };
    var fits = put_limited(o.url, url);
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return o, false; }
    o.status = status_lookup(str_member(root, "status"));
    fits = put_limited(o.expires, str_member(root, "expires")) && fits;
    fits = put_limited(o.finalize, str_member(root, "finalize")) && fits;
    fits = put_limited(o.certificate, str_member(root, "certificate")) && fits;
    fits = put_limited(o.profile, str_member(root, "profile")) && fits;
    let err = json::member(root, "error");
    if err {
        let pe, pok = read_problem(err, 0);
        o.error = pe;
        fits = pok && fits;
    }
    let list = json::member(root, "authorizations");
    if list {
        json::each(list) { z =>
            let s, ok = json::as_string(z);
            // One a line: a URL with a line end in it would be two.
            if !ok || s.len == 0 || position(s, '\n') >= 0 { fits = false; }
            else {
                o.authz.append(s);
                o.authz.push('\n');
            }
        };
    }
    if o.authz.len > 0 { o.authz.pop(); }
    return o, fits && o.status != ST_UNKNOWN && o.finalize.len > 0;
}

fn read_authz(text: const u8[:], url: const u8[:]) -> Authz, bool {
    var z = Authz { .. };
    var fits = put_limited(z.url, url);
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return z, false; }
    z.status = status_lookup(str_member(root, "status"));
    let id = json::member(root, "identifier");
    let t = str_member(id, "type");
    let v = str_member(id, "value");
    if t.len > 16 || v.len > 256 { fits = false; } else {
        z.id_type.append(t);
        z.id_value.append(v);
    }
    let w, ok = json::as_bool(json::member(root, "wildcard"));
    z.wildcard = ok && w;
    fits = put_limited(z.expires, str_member(root, "expires")) && fits;
    let list = json::member(root, "challenges");
    if list {
        json::each(list) { c =>
            // More challenges than are kept: refused, not some dropped.
            if z.challenges.len == 8 { fits = false; }
            else {
                var ch = Challenge { .. };
                fits = put_limited(ch.kind, str_member(c, "type")) && fits;
                fits = put_limited(ch.url, str_member(c, "url")) && fits;
                // A token is published as a file name and a DNS value: one
                // that is not base64url is refused, not used.
                let tok = str_member(c, "token");
                if tok.len > 0 && !valid_token(tok) { fits = false; } else { ch.token.append(tok); }
                ch.status = status_lookup(str_member(c, "status"));
                let err = json::member(c, "error");
                if err {
                    let pe, pok = read_problem(err, 0);
                    ch.error = pe;
                    fits = pok && fits;
                }
                z.challenges.push(ch);
            }
        };
    }
    return z, fits && z.status != ST_UNKNOWN && z.id_value.len > 0;
}

// Names compared as DNS compares them, without regard to ASCII case.
fn same_name(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for c, i in a {
        let x = if c >= 'A' && c <= 'Z' { c + 32 } else { c };
        let y = if b[i] >= 'A' && b[i] <= 'Z' { b[i] + 32 } else { b[i] };
        if x != y { return false; }
    }
    return true;
}

// Whether an authorization is for one of the names ordered (one a line;
// a wildcard's authorization names the domain without its "*."), so that
// a server cannot have a challenge published for a name nobody asked for.
fn ordered(z: const Authz&, names: const u8[:]) -> bool {
    for n in split(names, '\n') {
        if n.len == 0 { continue; }
        let wild = n.len > 2 && n[..2] == "*.";
        let bare = if wild { n[2..] } else { n };
        if same_name(bare, z.id_value) && wild == z.wildcard { return true; }
    }
    return false;
}

// The index of the authorization's challenge of that kind, or -1.
fn find_challenge(z: const Authz&, kind: const u8[:]) -> i64 {
    for &ch, i in z.challenges {
        if ch.kind == kind { return i; }
    }
    return -1;
}

// The first challenge's error, for an authorization that went invalid.
fn authz_error(z: const Authz&) -> Problem {
    for &ch in z.challenges {
        if ch.error.kind.len > 0 || ch.error.detail.len > 0 { return ch.error; }
    }
    return Problem { .. };
}

// --- Requests ---------------------------------------------------------------------

// Retry-After (§8.2, RFC 9110 §10.2.3) as milliseconds from now: seconds,
// or an HTTP-date; 0 when absent or past.
fn retry_after_ms(value: const u8[:], now_ms: i64) -> i64 {
    if value.len == 0 { return 0; }
    var all_digits = true;
    for c in value {
        if c < '0' || c > '9' { all_digits = false; }
    }
    if all_digits {
        if value.len > 9 { return 0; }
        var s = 0;
        for c in value { s = s * 10 + (c - '0'); }
        return s * 1000;
    }
    let at, ok = http::parse_cookie_date(value);
    if !ok || at <= now_ms { return 0; }
    return at - now_ms;
}

fn take_nonce(a: Client&, r: const http::Response&) {
    let n, ok = http::response_header(r, "Replay-Nonce");
    if ok && n.len > 0 && n.len <= 256 {
        a.nonce.clear();
        a.nonce.append(n);
    }
}

fn take_retry_after(a: Client&, r: const http::Response&) {
    let v, ok = http::response_header(r, "Retry-After");
    a.retry_after_ms = if ok { retry_after_ms(v, time_ns() / 1000000) } else { 0 };
}

// A fresh nonce from newNonce (§7.2).
fn new_nonce(a: Client&, hc: http::Client&) -> i64 {
    if a.dir.new_nonce.len == 0 { return ERR_ARG; }
    let r = http::request(hc, "HEAD", a.dir.new_nonce, "", "");
    if r.err != 0 { a.http_err = r.err; return ERR_HTTP; }
    take_nonce(a, r);
    if a.nonce.len == 0 { return ERR_MALFORMED; }
    return OK;
}

// The JWS of a request (§6.2): flattened JSON, its protected header the
// algorithm, the account's URL as "kid" (or, with by_jwk, the account's
// public key as "jwk"), the nonce and the URL.
fn sign_request(a: const Client&, url: const u8[:], payload: const u8[:], by_jwk: bool) -> u8[>..], i64 {
    var s = jws::Signer { key: a.key, .. };
    s.header.alg = a.alg;
    if by_jwk {
        s.header.has_jwk = true;
        s.header.jwk = jwk::public_key(a.key);
    } else {
        var kid: u8[>..] = [];
        json::format_key(kid, "kid");
        json::format_string(kid, a.account);
        s.extra.append(kid);
        s.extra.push(',');
    }
    var rest: u8[>..] = [];
    json::format_key(rest, "nonce");
    json::format_string(rest, a.nonce);
    rest.push(',');
    json::format_key(rest, "url");
    json::format_string(rest, url);
    if s.extra.len + rest.len > 2048 { var none: u8[>..] = []; return none, ERR_ARG; }
    s.extra.append(rest);
    var signers: jws::Signer[>..] = [];
    signers.push(s);
    let out, err = jws::sign_json(payload, signers, true);
    return out, if err == jwx::OK { OK } else { ERR_KEY };
}

// POSTs payload to url as a signed request; `payload` "" is a
// POST-as-GET (§6.3). The response, read whole, and OK, ERR_PROBLEM (with
// a.problem set) or another error. A badNonce is answered by sending the
// request again with the nonce that came with it.
fn post(a: Client&, hc: http::Client&, url: const u8[:], payload: const u8[:], by_jwk: bool = false,
        accept: const u8[:] = "") -> http::Response, i64 {
    if a.alg == jwa::UNKNOWN { return http::empty_response(0), ERR_KEY; }
    if !by_jwk && a.account.len == 0 { return http::empty_response(0), ERR_NO_ACCOUNT; }
    var fields: u8[>..] = [];
    http::add_field(fields, "Content-Type", "application/jose+json");
    if accept.len > 0 { http::add_field(fields, "Accept", accept); }
    var tries = 0;
    loop {
        if a.nonce.len == 0 {
            let e = new_nonce(a, hc);
            if e != OK { return http::empty_response(0), e; }
        }
        let body, serr = sign_request(a, url, payload, by_jwk);
        if serr != OK { return http::empty_response(0), serr; }
        a.nonce.clear();          // used, whatever happens
        var r = http::request(hc, "POST", url, fields, body);
        if r.err != 0 {
            a.http_err = r.err;
            return r, ERR_HTTP;
        }
        take_nonce(a, r);
        take_retry_after(a, r);
        if r.status < 400 { return r, OK; }
        a.problem = problem_of(http::response_body(r), r.status);
        if is_problem(a, "badNonce") && tries < a.nonce_retries {
            tries++;
            continue;
        }
        return r, ERR_PROBLEM;
    }
}

// --- Directory and account --------------------------------------------------------

// Reads the server's directory.
fn open(a: Client&, hc: http::Client&, directory_url: const u8[:]) -> i64 {
    let r = http::request(hc, "GET", directory_url, "", "");
    if r.err != 0 { a.http_err = r.err; return ERR_HTTP; }
    if r.status != 200 {
        a.problem = problem_of(http::response_body(r), r.status);
        return ERR_PROBLEM;
    }
    let d, ok = read_directory(http::response_body(r));
    if !ok { return ERR_MALFORMED; }
    a.dir = d;
    return OK;
}

fn take_account(a: Client&, r: const http::Response&) -> i64 {
    let loc, ok = http::response_header(r, "Location");
    if !ok || loc.len == 0 || loc.len > 512 { return ERR_MALFORMED; }
    a.account.clear();
    a.account.append(loc);
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(http::response_body(r), doc, decoded);
    if root { a.account_status = status_lookup(str_member(root, "status")); }
    return OK;
}

// The externalAccountBinding member (§7.3.4): a JWS by the CA's MAC key
// (HS256) over the account's public key, naming the CA's key id.
fn eab_jws(a: const Client&, eab_kid: const u8[:], eab_key: const u8[:]) -> u8[>..], i64 {
    var mac = jwk::empty();
    mac.kty = jwa::KTY_OCT;
    mac.private = true;
    if eab_key.len == 0 || eab_key.len > jwk::MAX_OCT { var none: u8[>..] = []; return none, ERR_ARG; }
    mac.k.append(eab_key);
    var s = jws::Signer { key: mac, .. };
    s.header.alg = jwa::HS256;
    var extra: u8[>..] = [];
    json::format_key(extra, "kid");
    json::format_string(extra, eab_kid);
    extra.push(',');
    json::format_key(extra, "url");
    json::format_string(extra, a.dir.new_account);
    if extra.len > 2048 { var none: u8[>..] = []; return none, ERR_ARG; }
    s.extra.append(extra);
    var signers: jws::Signer[>..] = [];
    signers.push(s);
    let pub = jwk::public_key(a.key);
    let out, err = jws::sign_json(jwk::marshal(pub, false), signers, true);
    return out, if err == jwx::OK { OK } else { ERR_KEY };
}

// Registers the account key (§7.3): `contacts` are URLs ("mailto:..."), one
// a line, and may be empty; `agree` says the terms of service are agreed
// to. A key already registered gets its existing account. With eab_kid,
// the account is bound to the CA's account of that key id, by its MAC key
// eab_key (raw bytes: the CA hands it out in base64url).
fn new_account(a: Client&, hc: http::Client&, contacts: const u8[:], agree: bool,
               eab_kid: const u8[:] = "", eab_key: const u8[:] = "") -> i64 {
    var p: u8[>..] = [];
    p.append("{\"termsOfServiceAgreed\":");
    json::format_bool(p, agree);
    if contacts.len > 0 {
        p.append(",\"contact\":[");
        var first = true;
        for c in split(contacts, '\n') {
            if c.len == 0 { continue; }
            if !first { p.push(','); }
            json::format_string(p, c);
            first = false;
        }
        p.push(']');
    }
    if eab_kid.len > 0 {
        let eab, err = eab_jws(a, eab_kid, eab_key);
        if err != OK { return err; }
        p.append(",\"externalAccountBinding\":");
        p.append(eab);
    }
    p.push('}');
    let r, err = post(a, hc, a.dir.new_account, p, true);
    if err != OK { return err; }
    return take_account(a, r);
}

// The existing account of the key, without creating one (§7.3.1,
// onlyReturnExisting): ERR_PROBLEM with accountDoesNotExist if there is
// none.
fn find_account(a: Client&, hc: http::Client&) -> i64 {
    let r, err = post(a, hc, a.dir.new_account, "{\"onlyReturnExisting\":true}", true);
    if err != OK { return err; }
    return take_account(a, r);
}

// Deactivates the account (§7.3.6); the key can register no other.
fn deactivate_account(a: Client&, hc: http::Client&) -> i64 {
    let r, err = post(a, hc, a.account, "{\"status\":\"deactivated\"}");
    if err != OK { return err; }
    a.account_status = ST_DEACTIVATED;
    return OK;
}

// Rolls the account over to a new key (§7.3.5): the request, by the old
// key, carries a JWS by the new one naming the account and the old key.
// The client signs with the new key from then on.
fn key_change(a: Client&, hc: http::Client&, new_key: const jwk::Key&) -> i64 {
    let alg = alg_for(new_key);
    if alg == jwa::UNKNOWN || !new_key.private { return ERR_KEY; }
    if a.account.len == 0 { return ERR_NO_ACCOUNT; }
    var payload: u8[>..] = [];
    payload.append("{\"account\":");
    json::format_string(payload, a.account);
    payload.append(",\"oldKey\":");
    let old = jwk::public_key(a.key);
    jwk::marshal_to(payload, old, false);
    payload.push('}');
    var s = jws::Signer { key: new_key, .. };
    s.key.kid.clear();
    s.header.alg = alg;
    s.header.has_jwk = true;
    s.header.jwk = jwk::public_key(new_key);
    s.header.jwk.kid.clear();
    var extra: u8[>..] = [];
    json::format_key(extra, "url");
    json::format_string(extra, a.dir.key_change);
    s.extra.append(extra);
    var signers: jws::Signer[>..] = [];
    signers.push(s);
    let inner, jerr = jws::sign_json(payload, signers, true);
    if jerr != jwx::OK { return ERR_KEY; }
    let r, err = post(a, hc, a.dir.key_change, inner);
    if err != OK { return err; }
    return set_key(a, new_key);
}

// --- Orders -------------------------------------------------------------------------

// Whether an identifier is an IP address (RFC 8738) rather than a name.
fn is_ip(s: const u8[:]) -> bool {
    if position(s, ':') >= 0 { return true; }
    for c in s {
        if c != '.' && (c < '0' || c > '9') { return false; }
    }
    return s.len > 0;
}

// Orders a certificate for `names` (§7.4), one a line: DNS names
// (wildcards too) and IP addresses. `profile` names one of the
// directory's profiles (draft-ietf-acme-profiles); "" for the default.
fn new_order(a: Client&, hc: http::Client&, names: const u8[:], profile: const u8[:] = "") -> Order, i64 {
    var p: u8[>..] = [];
    p.append("{\"identifiers\":[");
    var first = true;
    for n in split(names, '\n') {
        if n.len == 0 { continue; }
        if !first { p.push(','); }
        p.append("{\"type\":");
        json::format_string(p, if is_ip(n) { "ip" } else { "dns" });
        p.append(",\"value\":");
        json::format_string(p, n);
        p.push('}');
        first = false;
    }
    p.push(']');
    if first { return Order { .. }, ERR_ARG; }
    if profile.len > 0 {
        p.append(",\"profile\":");
        json::format_string(p, profile);
    }
    p.push('}');
    let r, err = post(a, hc, a.dir.new_order, p);
    if err != OK { return Order { .. }, err; }
    let loc, has = http::response_header(r, "Location");
    let o, ok = read_order(http::response_body(r), if has { loc } else { "" });
    if !ok || o.url.len == 0 { return o, ERR_MALFORMED; }
    return o, OK;
}

// The order as it is now.
fn get_order(a: Client&, hc: http::Client&, o: Order&) -> i64 {
    let r, err = post(a, hc, o.url, "");
    if err != OK { return err; }
    let url = copy(o.url);
    let fresh, ok = read_order(http::response_body(r), url);
    if !ok { return ERR_MALFORMED; }
    o = copy(fresh);
    return OK;
}

fn pause(a: const Client&) {
    sleep_ms(if a.retry_after_ms > 0 { min(a.retry_after_ms, a.poll_timeout_ms) } else { a.poll_ms });
}

// Waits for the order to leave pending or processing: OK once it is ready
// or valid, ERR_INVALID if it went invalid (o.error says why).
fn wait_order(a: Client&, hc: http::Client&, o: Order&) -> i64 {
    let deadline = clock_ns() + a.poll_timeout_ms * 1000000;
    loop {
        if o.status == ST_READY || o.status == ST_VALID { return OK; }
        if o.status != ST_PENDING && o.status != ST_PROCESSING { return ERR_INVALID; }
        if clock_ns() >= deadline { return ERR_TIMEOUT; }
        pause(a);
        let err = get_order(a, hc, o);
        if err != OK { return err; }
    }
}

// Sends the CSR (DER) to finalize a ready order (§7.4) and waits until the
// certificate is issued.
fn finalize(a: Client&, hc: http::Client&, o: Order&, csr: const u8[:]) -> i64 {
    var p: u8[>..] = [];
    p.append("{\"csr\":\"");
    jwx::b64_append(p, csr);
    p.append("\"}");
    let r, err = post(a, hc, o.finalize, p);
    if err != OK { return err; }
    let url = copy(o.url);
    let fresh, ok = read_order(http::response_body(r), url);
    if !ok { return ERR_MALFORMED; }
    o = copy(fresh);
    let werr = wait_order(a, hc, o);
    if werr != OK { return werr; }
    return if o.status == ST_VALID && o.certificate.len > 0 { OK } else { ERR_INVALID };
}

// The issued chain (§7.4.2), PEM, the leaf first.
fn certificate(a: Client&, hc: http::Client&, o: const Order&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    if o.certificate.len == 0 { return out, ERR_ARG; }
    let r, err = post(a, hc, o.certificate, "", false, "application/pem-certificate-chain");
    if err != OK { return out, err; }
    out.append(http::response_body(r));
    return out, OK;
}

// --- Authorizations ---------------------------------------------------------------

fn get_authz(a: Client&, hc: http::Client&, url: const u8[:]) -> Authz, i64 {
    let r, err = post(a, hc, url, "");
    if err != OK { return Authz { .. }, err; }
    let z, ok = read_authz(http::response_body(r), url);
    return z, if ok { OK } else { ERR_MALFORMED };
}

// Tells the server the challenge is ready to be checked (§7.5.1).
fn accept(a: Client&, hc: http::Client&, ch: const Challenge&) -> i64 {
    let r, err = post(a, hc, ch.url, "{}");
    return err;
}

// Waits for the authorization to leave pending: OK once it is valid,
// ERR_INVALID (a.problem set to the challenge's error) when it is not.
fn wait_authz(a: Client&, hc: http::Client&, url: const u8[:]) -> Authz, i64 {
    let deadline = clock_ns() + a.poll_timeout_ms * 1000000;
    loop {
        let z, err = get_authz(a, hc, url);
        if err != OK { return z, err; }
        if z.status == ST_VALID { return z, OK; }
        if z.status != ST_PENDING {
            a.problem = authz_error(z);
            return z, ERR_INVALID;
        }
        if clock_ns() >= deadline { return z, ERR_TIMEOUT; }
        pause(a);
    }
}

// Gives up an authorization (§7.5.2).
fn deactivate_authz(a: Client&, hc: http::Client&, url: const u8[:]) -> i64 {
    let r, err = post(a, hc, url, "{\"status\":\"deactivated\"}");
    return err;
}

// --- Revocation -----------------------------------------------------------------

// Revokes a certificate (DER) the account holds (§7.6), with a reason
// code, or REASON_NONE for none.
fn revoke(a: Client&, hc: http::Client&, cert: const u8[:], reason: i64 = REASON_NONE) -> i64 {
    var p: u8[>..] = [];
    p.append("{\"certificate\":\"");
    jwx::b64_append(p, cert);
    p.push('"');
    if reason >= 0 {
        p.append(",\"reason\":");
        json::format_int(p, reason);
    }
    p.push('}');
    let r, err = post(a, hc, a.dir.revoke_cert, p);
    return err;
}

// --- The whole flow ------------------------------------------------------------------

// Orders a certificate for `names` (one a line), proves each name with the
// challenge `kind` ("http-01" or "dns-01"), finalizes with the CSR (DER)
// and gives the chain, PEM. F(z, ch, value) publishes a challenge before
// it is accepted: the key authorization to serve at http01_path(ch.token)
// for http-01, the TXT value for dns01_name(z.id_value) for dns-01. F is
// a block `{ z: const Authz&, ch: const Challenge&, value: const u8[:] =>
// ... }` that says whether it did; when it did not, nothing more is asked
// of the server and the result is ERR_PUBLISH. Authorizations already
// valid are passed over. `profile` as in new_order.
fn obtain<F>(a: Client&, hc: http::Client&, names: const u8[:], csr: const u8[:], kind: const u8[:],
             profile: const u8[:] = "") -> u8[>..], i64 {
    var none: u8[>..] = [];
    var o, err = new_order(a, hc, names, profile);
    if err != OK { return none, err; }
    for url in split(o.authz, '\n') {
        let z, zerr = get_authz(a, hc, url);
        if zerr != OK { return none, zerr; }
        if z.status == ST_VALID { continue; }
        if !ordered(z, names) { return none, ERR_MALFORMED; }
        let i = find_challenge(z, kind);
        if i < 0 { return none, ERR_ARG; }
        if !valid_token(z.challenges[i].token) { return none, ERR_MALFORMED; }
        if !F(z, z.challenges[i], challenge_value(a, z.challenges[i])) { return none, ERR_PUBLISH; }
        let aerr = accept(a, hc, z.challenges[i]);
        if aerr != OK { return none, aerr; }
        let done, werr = wait_authz(a, hc, url);
        if werr != OK { return none, werr; }
    }
    let gerr = get_order(a, hc, o);
    if gerr != OK { return none, gerr; }
    let werr = wait_order(a, hc, o);
    if werr != OK { return none, werr; }
    let ferr = finalize(a, hc, o, csr);
    if ferr != OK { return none, ferr; }
    let chain, cerr = certificate(a, hc, o);
    return chain, cerr;
}
