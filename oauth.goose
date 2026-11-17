// oauth: an OAuth 2.0 client (RFC 6749) and the extensions a client meets
// today: authorization server metadata (RFC 8414) and OpenID Connect
// discovery, the authorization code flow with PKCE (RFC 7636) and pushed
// authorization requests (RFC 9126), client credentials, refresh tokens,
// the device authorization grant (RFC 8628), token exchange (RFC 8693),
// introspection (RFC 7662) and revocation (RFC 7009); client
// authentication by secret (basic or post), by a signed JWT
// (private_key_jwt and client_secret_jwt, RFC 7523) or by a TLS client
// certificate (RFC 8705); and DPoP (RFC 9449) for sender-constrained
// tokens. oauth.oidc validates ID tokens, JWT access tokens (RFC 9068) and
// DPoP proofs against the issuer's keys, and reads UserInfo.
//
//   var hc = http::Client { .. };
//   var c = oauth::Client { .. };
//   oauth::discover(c, hc, "https://login.example.test/realms/demo");
//   oauth::set_secret(c, "my-client", secret, oauth::AUTH_SECRET_BASIC);
//   let t, err = oauth::client_credentials(c, hc, "api:read");
//
//   let ar, aerr = oauth::new_auth_request(c, "http://127.0.0.1:8400/cb", "openid profile");
//   let url = oauth::authorization_url(c, ar);          // send the user there
//   // ... the redirect comes back to the redirect URI with ?code=...&state=...
//   let code, cerr = oauth::parse_callback(c, ar, query);
//   let t, terr = oauth::exchange_code(c, hc, ar, code);
//
// Every refusal leaves the server's error response (RFC 6749 §5.2:
// error, error_description, error_uri) in c.error, as acme keeps its
// problem documents.
//
// Nothing is kept in part. An argument longer than the field it goes to is
// ERR_ARG; a response with a member longer than its field, or of another
// JSON type than the RFC's, is refused whole (ERR_MALFORMED), so that no
// value a check depends on is ever cut short or left out. Only an error
// response's text is cut to fit, and c.error.truncated then says so. The http::Client is the caller's: its TLS
// configuration says which CAs the server's certificate may chain to, and
// carries the client certificate for mutual TLS.

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
import entropy;
import crypto.tls;
import crypto.tls.handshake;
import net.http;
import net.http.client;
import net.http.fetch;
import net.http.url;
import net.http.auth;

// --- Errors -------------------------------------------------------------------

let OK:            i64 = 0;
let ERR_ARG:       i64 = 1;         // an argument that cannot be used (an endpoint the server has not got, say)
let ERR_HTTP:      i64 = 2;         // no response: the connection, TLS, a timeout (c.http_err says which)
let ERR_OAUTH:     i64 = 3;         // the server refused, with an error response (c.error)
let ERR_MALFORMED: i64 = 4;         // a response that is not what the RFCs say it is, or too large
let ERR_KEY:       i64 = 5;         // no key, or one that cannot sign
let ERR_STATE:     i64 = 6;         // the callback's state is not the request's
let ERR_TIMEOUT:   i64 = 7;         // the device code expired before the user finished
let ERR_ISSUER:    i64 = 8;         // the issuer is not the one asked for (metadata, callback, token)
let ERR_SIGNATURE: i64 = 9;         // the token's signature does not verify
let ERR_ALG:       i64 = 10;        // an algorithm not allowed ("none" never is)
let ERR_NO_KEY:    i64 = 11;        // no key of the issuer's set fits the token
let ERR_EXPIRED:   i64 = 12;        // exp is past (or nbf ahead), with the leeway
let ERR_IAT:       i64 = 13;        // iat is ahead, or missing
let ERR_AUDIENCE:  i64 = 14;        // not for this client (or resource), or for others it does not trust
let ERR_AZP:       i64 = 15;        // azp is another client's
let ERR_NONCE:     i64 = 16;        // the nonce is not the request's
let ERR_AT_HASH:   i64 = 17;        // at_hash is not the access token's
let ERR_C_HASH:    i64 = 18;        // c_hash is not the code's
let ERR_TYP:       i64 = 19;        // the JOSE header's typ is not the one this token must have
let ERR_CNF:       i64 = 20;        // a sender-constrained token presented without its key or certificate
let ERR_SCOPE:     i64 = 21;        // the token lacks a scope asked for
let ERR_AUTH_TIME: i64 = 22;        // auth_time missing, or older than max_age
let ERR_SUBJECT:   i64 = 23;        // the UserInfo response's sub is not the ID token's
let ERR_DPOP:      i64 = 24;        // a DPoP proof that is not one, or not for this request
let ERR_CLAIM:     i64 = 25;        // a claim that must be there is not
let ERR_INSECURE:  i64 = 26;        // an http:// issuer or endpoint that is not loopback (Client.allow_http)

fn error_text(e: i64) -> const u8[:] {
    if e == OK { return "ok"; }
    if e == ERR_ARG { return "an argument that cannot be used"; }
    if e == ERR_HTTP { return "the request failed"; }
    if e == ERR_OAUTH { return "the server refused the request"; }
    if e == ERR_MALFORMED { return "the server's response is not OAuth"; }
    if e == ERR_KEY { return "no key to sign with"; }
    if e == ERR_STATE { return "the state in the redirect is not the request's"; }
    if e == ERR_TIMEOUT { return "the device code expired"; }
    if e == ERR_ISSUER { return "the issuer is not the one expected"; }
    if e == ERR_SIGNATURE { return "the signature does not verify"; }
    if e == ERR_ALG { return "the algorithm is not allowed"; }
    if e == ERR_NO_KEY { return "no key of the issuer fits"; }
    if e == ERR_EXPIRED { return "the token has expired"; }
    if e == ERR_IAT { return "the token's iat is missing or in the future"; }
    if e == ERR_AUDIENCE { return "the token is not for this audience"; }
    if e == ERR_AZP { return "the token's azp is another client"; }
    if e == ERR_NONCE { return "the nonce is not the request's"; }
    if e == ERR_AT_HASH { return "at_hash does not match the access token"; }
    if e == ERR_C_HASH { return "c_hash does not match the code"; }
    if e == ERR_TYP { return "the token's typ is wrong"; }
    if e == ERR_CNF { return "the token is bound to another key or certificate"; }
    if e == ERR_SCOPE { return "the token lacks the scope"; }
    if e == ERR_AUTH_TIME { return "auth_time is missing or too old"; }
    if e == ERR_SUBJECT { return "the subject is not the one expected"; }
    if e == ERR_DPOP { return "the DPoP proof is not valid for this request"; }
    if e == ERR_CLAIM { return "a required claim is missing"; }
    if e == ERR_INSECURE { return "the URL is not https"; }
    return "";
}

// How the client authenticates to the token, PAR, device, introspection
// and revocation endpoints.
let AUTH_NONE:         i64 = 0;     // a public client: client_id in the form
let AUTH_SECRET_BASIC: i64 = 1;     // client_secret_basic (RFC 6749 §2.3.1)
let AUTH_SECRET_POST:  i64 = 2;     // client_secret_post
let AUTH_SECRET_JWT:   i64 = 3;     // client_secret_jwt: an HS256 assertion (RFC 7523, OIDC Core §9)
let AUTH_PRIVATE_KEY:  i64 = 4;     // private_key_jwt: an assertion signed by the client's key
let AUTH_TLS:          i64 = 5;     // tls_client_auth or self_signed_tls_client_auth (RFC 8705 §2)

let AUTH_NAMES: const u8[:][] = ["none", "client_secret_basic", "client_secret_post", "client_secret_jwt",
                                 "private_key_jwt", "tls_client_auth"];

fn auth_name(a: i64) -> const u8[:] { if a >= 0 && a < AUTH_NAMES.len { AUTH_NAMES[a] } else { "" } }

// RFC 8693 §3's token type identifiers.
let TT_ACCESS_TOKEN:  const u8[:] = "urn:ietf:params:oauth:token-type:access_token";
let TT_REFRESH_TOKEN: const u8[:] = "urn:ietf:params:oauth:token-type:refresh_token";
let TT_ID_TOKEN:      const u8[:] = "urn:ietf:params:oauth:token-type:id_token";
let TT_JWT:           const u8[:] = "urn:ietf:params:oauth:token-type:jwt";

let GRANT_DEVICE_CODE:    const u8[:] = "urn:ietf:params:oauth:grant-type:device_code";
let GRANT_TOKEN_EXCHANGE: const u8[:] = "urn:ietf:params:oauth:grant-type:token-exchange";
let GRANT_JWT_BEARER:     const u8[:] = "urn:ietf:params:oauth:grant-type:jwt-bearer";
let ASSERTION_JWT_BEARER: const u8[:] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

// --- Types --------------------------------------------------------------------

// An error response (RFC 6749 §5.2, RFC 6750 §3 for a resource server's
// WWW-Authenticate): the HTTP status, the error code, what the server
// says, and where it says more. `truncated` when the server said more than
// fits: error_description is then cut at 1024 bytes, and an error over 128
// bytes or an error_uri over 512 is left out (empty).
struct Error {
    status:      i64        = 0,
    code:        u8[..128]  = [],
    description: u8[..1024] = [],
    uri:         u8[..512]  = [],
    truncated:   bool       = false,
}

// The authorization server's metadata (RFC 8414 §2, OpenID Connect
// Discovery §3): its endpoints, the mutual-TLS aliases of them (RFC 8705
// §5), and what it supports. The lists hold their names one a line; they
// are for the caller (this package decides nothing by them), so one that
// does not fit, is not an array of strings or has a name with a line end
// is left empty with lists_truncated set, and discovery goes on.
struct Metadata {
    issuer:                 u8[..512]  = [],
    authorization_endpoint: u8[..512]  = [],
    token_endpoint:         u8[..512]  = [],
    userinfo_endpoint:      u8[..512]  = [],
    jwks_uri:               u8[..512]  = [],
    revocation_endpoint:    u8[..512]  = [],
    introspection_endpoint: u8[..512]  = [],
    device_endpoint:        u8[..512]  = [],    // device_authorization_endpoint
    par_endpoint:           u8[..512]  = [],    // pushed_authorization_request_endpoint
    end_session_endpoint:   u8[..512]  = [],
    registration_endpoint:  u8[..512]  = [],
    mtls_token:             u8[..512]  = [],    // mtls_endpoint_aliases
    mtls_revocation:        u8[..512]  = [],
    mtls_introspection:     u8[..512]  = [],
    mtls_device:            u8[..512]  = [],
    mtls_par:               u8[..512]  = [],
    mtls_userinfo:          u8[..512]  = [],
    require_par:            bool       = false, // require_pushed_authorization_requests
    iss_parameter:          bool       = false, // authorization_response_iss_parameter_supported (RFC 9207)
    bound_tokens:           bool       = false, // tls_client_certificate_bound_access_tokens
    scopes:                 u8[..8192] = [],
    grant_types:            u8[..1024] = [],
    response_types:         u8[..1024] = [],
    auth_methods:           u8[..512]  = [],    // token_endpoint_auth_methods_supported
    pkce_methods:           u8[..128]  = [],    // code_challenge_methods_supported
    id_token_algs:          u8[..512]  = [],    // id_token_signing_alg_values_supported
    dpop_algs:              u8[..512]  = [],    // dpop_signing_alg_values_supported
    lists_truncated:        bool       = false, // a list above left empty: too long, or not one
}

// A token response (RFC 6749 §5.1, OIDC Core §3.1.3.3, RFC 8693 §2.2.1).
// expires_at is the time in seconds it expires, 0 when expires_in was not
// given.
struct Token {
    token_type:        u8[..32]    = [],
    expires_in:        i64         = 0,
    expires_at:        i64         = 0,
    scope:             u8[..2048]  = [],
    issued_token_type: u8[..128]   = [],
    access_token:      u8[..12288] = [],
    refresh_token:     u8[..8192]  = [],
    id_token:          u8[..12288] = [],
}

// What an authorization request sent, kept until its redirect comes back:
// the state, the nonce (OpenID Connect; empty without "openid" in the
// scope), the PKCE code verifier, the redirect URI and the scope.
struct AuthRequest {
    state:        u8[..64]   = [],
    nonce:        u8[..64]   = [],
    verifier:     u8[..128]  = [],
    redirect_uri: u8[..512]  = [],
    scope:        u8[..1024] = [],
    max_age:      i64        = -1,      // asked for with max_age=, -1 for none (OIDC Core §3.1.2.1)
}

// A device authorization response (RFC 8628 §3.2). interval is in seconds.
struct Device {
    device_code:               u8[..1024] = [],
    user_code:                 u8[..128]  = [],
    verification_uri:          u8[..512]  = [],
    verification_uri_complete: u8[..1024] = [],
    expires_in:                i64        = 0,
    interval:                  i64        = 5,
}

// An introspection response (RFC 7662 §2.2), and the response itself in
// `raw` for the members not kept here. cnf_jkt and cnf_x5t are a
// sender-constrained token's confirmation (RFC 9449 §6.2, RFC 8705 §3.2).
struct Introspection {
    active:     bool       = false,
    scope:      u8[..2048] = [],
    client_id:  u8[..256]  = [],
    username:   u8[..256]  = [],
    token_type: u8[..64]   = [],
    exp:        i64        = 0,
    iat:        i64        = 0,
    nbf:        i64        = 0,
    sub:        u8[..256]  = [],
    aud:        u8[..1024] = [],     // the audiences, one a line
    iss:        u8[..512]  = [],
    jti:        u8[..256]  = [],
    cnf_jkt:    u8[..64]   = [],
    cnf_x5t:    u8[..64]   = [],
    raw:        u8[>..]    = [],
}

// An OAuth client: who it is and how it authenticates, the server's
// metadata, the DPoP key and the nonces servers handed out for it, and
// the issuer's keys (oauth.oidc). `error` is the last refusal.
root struct Client {
    client_id:           u8[..256]     = [],
    secret:              u8[>..]       = [],        // client_secret, for AUTH_SECRET_* (never printed)
    auth:                i64           = AUTH_NONE,
    key:                 jwk::Key      = jwk::empty(), // private_key_jwt's
    key_alg:             i64           = jwa::UNKNOWN,
    assertion_aud:       u8[..512]     = [],        // a client assertion's aud; empty: the issuer
    meta:                Metadata      = Metadata { .. },
    use_mtls:            bool          = false,        // send requests to the mtls_endpoint_aliases
    dpop_key:            jwk::Key      = jwk::empty(), // DPoP's, when set_dpop_key was called
    dpop_alg:            i64           = jwa::UNKNOWN,
    dpop_nonce:          u8[..512]     = [],        // the authorization server's last DPoP-Nonce
    rs_dpop_nonce:       u8[..512]     = [],        // the resource server's last DPoP-Nonce
    error:               Error         = Error { .. },
    http_err:            i64           = 0,
    now:                 i64           = 0,         // seconds since 1970; 0: the clock's (for tests)
    leeway:              i64           = 60,        // seconds exp, iat and nbf may be off by
    algs:                i64[..16]     = [],        // the JWS algs tokens may use; empty: RS*, PS*, ES*, EdDSA
    keys:                jwk::Key[>..] = [],        // the issuer's JWKS (oauth.oidc)
    jwks_fetched_ns:     i64           = 0,         // clock_ns() of the last fetch, 0 for never
    jwks_min_interval_s: i64           = 60,        // a refetch for an unknown kid waits at least this long
    jwks_fetches:        i64           = 0,
    allow_http:          bool          = false,     // let the issuer and endpoints be http:// to any host
}

// --- Small things -------------------------------------------------------------

// Whether the client may send a request to u: https (RFC 6749 §3.1, RFC
// 8414 §2, OIDC Discovery §3 require TLS), or http to localhost or a
// loopback address, or anything when c.allow_http. A URL that does not
// parse is left to http::request to refuse.
fn url_allowed(c: const Client&, u: const u8[:]) -> bool {
    if c.allow_http { return true; }
    let p, e = http::url_parse(u);
    if e != 0 { return true; }
    let scheme = http::url_scheme(p);
    if eq_fold(scheme, "https") { return true; }
    if !eq_fold(scheme, "http") { return false; }
    var host = http::url_host(p);
    if host.len >= 2 && host[0] == '[' && host[host.len - 1] == ']' { host = host[1..host.len - 1]; }
    if eq_fold(host, "localhost") { return true; }
    let ip, kind = http::parse_ip(host);
    return http::ip_is_loopback(ip, kind);
}

fn now_s(c: const Client&) -> i64 { if c.now != 0 { c.now } else { time_ns() / 1000000000 } }

// `n` random bytes in base64url: state, nonce, jti, PKCE verifiers.
fn random_string(n: i64) -> u8[>..] {
    var b: u8[64] = [0; 64];
    let k = min(n, 64);
    entropy::random_bytes(b[..k]);
    return jwx::b64_encode(b[..k]);
}

fn str_member(n: json::Node?, name: const u8[:]) -> const u8[:] {
    let s, ok = json::as_string(json::member(n, name));
    return if ok { s } else { "" };
}

fn int_member(n: json::Node?, name: const u8[:]) -> i64 {
    let v, ok = json::as_i64(json::member(n, name));
    if ok { return v; }
    let f, okf = json::as_f64(json::member(n, name));
    if okf && f == f && f < 9.0e18 && f > -9.0e18 { return f as! i64; }
    return 0;
}

fn bool_member(n: json::Node?, name: const u8[:]) -> bool {
    let v, ok = json::as_bool(json::member(n, name));
    return ok && v;
}

// Whether a member is missing, or null (as absent).
fn absent(n: json::Node?) -> bool {
    guard n else { return true; }
    match n.val {
        Null => { return true; },
        _ => { return false; },
    }
}

// A string member of a response, for a field of `cap` bytes: "" when
// absent or null; false when it is something other than a string, or
// longer than cap. The caller refuses the response then: a value is kept
// whole or not at all.
fn str_field(n: json::Node?, name: const u8[:], cap: i64) -> const u8[:], bool {
    let m = json::member(n, name);
    if absent(m) { return "", true; }
    let s, ok = json::as_string(m);
    if !ok || s.len > cap { return "", false; }
    return s, true;
}

// A boolean member: false when absent or null; not ok for anything else.
fn bool_field(n: json::Node?, name: const u8[:]) -> bool, bool {
    let m = json::member(n, name);
    if absent(m) { return false, true; }
    let v, ok = json::as_bool(m);
    return v, ok;
}

// A NumericDate member (RFC 7662 §2.2): 0 when absent or null; not ok for
// anything but a number in i64's range.
fn int_field(n: json::Node?, name: const u8[:]) -> i64, bool {
    let m = json::member(n, name);
    if absent(m) { return 0, true; }
    let v, ok = json::as_i64(m);
    if ok { return v, true; }
    let f, okf = json::as_f64(m);
    if okf && f == f && f < 9.0e18 && f > -9.0e18 { return f as! i64, true; }
    return 0, false;
}

// put(dst, n, name): the string member into a 512-byte field (a URL);
// false, and dst empty, when it is not a string or does not fit.
fn put(dst: u8[..512]&, n: json::Node?, name: const u8[:]) -> bool {
    dst.clear();
    let s, ok = str_field(n, name, 512);
    if ok { dst.append(s); }
    return ok;
}

// The strings of a JSON array, one a line, into out: false (out left
// empty) when it is not an array of strings, an element holds a line end
// (it would read as two), or the whole is over cap bytes. Absent or null
// is the empty list.
fn put_list(out: u8[>..]&, n: json::Node?, cap: i64) -> bool {
    if absent(n) { return true; }
    guard n else { return true; }
    match n.val {
        Arr => {},
        _ => { return false; },
    }
    var ok = true;
    json::each(n) { e =>
        let s, is_str = json::as_string(e);
        if !is_str || position(s, '\n') >= 0 || out.len + s.len + 1 > cap + 1 {
            ok = false;
        } else if ok {
            out.append(s);
            out.push('\n');
        }
    };
    if !ok { out.clear(); return false; }
    if out.len > 0 { out.pop(); }
    return true;
}

// A token's confirmation (RFC 7800 §3.1): cnf's jkt (RFC 9449 §6) and
// x5t#S256 (RFC 8705 §3.1). False for a cnf that is not an object, or a
// thumbprint that is not a string of at most 64 bytes: left out, it would
// make a bound token look like a bearer token.
fn read_cnf(root: json::Node?, jkt: u8[..64]&, x5t: u8[..64]&) -> bool {
    jkt.clear();
    x5t.clear();
    let cnf = json::member(root, "cnf");
    if absent(cnf) { return true; }
    guard cnf else { return true; }
    match cnf.val {
        Obj => {},
        _ => { return false; },
    }
    let j, okj = str_field(cnf, "jkt", 64);
    let x, okx = str_field(cnf, "x5t#S256", 64);
    if !okj || !okx { return false; }
    jkt.append(j);
    x5t.append(x);
    return true;
}

// Whether a list (one a line) or a scope (space-separated) has `name`.
fn has_name(list: const u8[:], name: const u8[:]) -> bool {
    for s in split(list, '\n') {
        if s == name { return true; }
    }
    return false;
}

fn has_scope(scope: const u8[:], name: const u8[:]) -> bool {
    for s in split(scope, ' ') {
        if s.len > 0 && s == name { return true; }
    }
    return false;
}

// Every scope of `want` (space-separated) is in `scope`.
fn has_scopes(scope: const u8[:], want: const u8[:]) -> bool {
    for s in split(want, ' ') {
        if s.len > 0 && !has_scope(scope, s) { return false; }
    }
    return true;
}

// --- Error responses ------------------------------------------------------------

// An error's text into e (RFC 6749 §5.2): the code whole or not at all
// (it is what is_error decides by), the description cut to fit, the URI
// whole or not at all; e.truncated when anything did not fit.
fn put_error(e: Error&, code: const u8[:], description: const u8[:], uri: const u8[:]) {
    if code.len <= 128 { e.code.append(code); } else { e.truncated = true; }
    e.description.append(description[..min(description.len, 1024)]);
    if description.len > 1024 { e.truncated = true; }
    if uri.len <= 512 { e.uri.append(uri); } else { e.truncated = true; }
}

// The error response in a body (RFC 6749 §5.2). A body that is not one
// still gives the status, and a description saying so.
fn error_of(body: const u8[:], status: i64) -> Error {
    var e = Error { .. };
    e.status = status;
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(body, doc, decoded);
    let code = str_member(root, "error");
    if code.len == 0 {
        e.description.append("the response is not an OAuth error");
        return e;
    }
    put_error(e, code, str_member(root, "error_description"), str_member(root, "error_uri"));
    return e;
}

// The error in a resource server's WWW-Authenticate (RFC 6750 §3, RFC 9449
// §7.1): its error and error_description of a Bearer or DPoP challenge.
fn challenge_error(r: const http::Response&) -> Error {
    var e = Error { .. };
    e.status = r.status;
    http::each_field(http::response_fields(r), "WWW-Authenticate") { v =>
        http::each_challenge(v) { scheme, params =>
            if e.code.len == 0 && !e.truncated && (eq_fold(scheme, "Bearer") || eq_fold(scheme, "DPoP")) {
                let code, has = http::auth_param(params, "error");
                let d, hd = http::auth_param(params, "error_description");
                put_error(e, code, d, "");
            }
        };
    };
    return e;
}

fn eq_fold(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    for i in a.len {
        var x = a[i];
        var y = b[i];
        if x >= 'A' && x <= 'Z' { x = x + 32; }
        if y >= 'A' && y <= 'Z' { y = y + 32; }
        if x != y { return false; }
    }
    return true;
}

// Whether the last refusal was this error code: is_error(c, "slow_down").
fn is_error(c: const Client&, code: const u8[:]) -> bool { c.error.code[..] == code }

// --- Metadata -----------------------------------------------------------------------

fn read_metadata(text: const u8[:]) -> Metadata, bool {
    var m = Metadata { .. };
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return m, false; }
    match root.val {
        Obj => {},
        _ => { return m, false; },
    }
    // Every member whole, or the metadata refused: an endpoint left out
    // would send requests elsewhere (an mTLS alias to the plain endpoint),
    // a flag misread would skip a check (RFC 9207's iss).
    var ok = put(m.issuer, root, "issuer");
    ok = put(m.authorization_endpoint, root, "authorization_endpoint") && ok;
    ok = put(m.token_endpoint, root, "token_endpoint") && ok;
    ok = put(m.userinfo_endpoint, root, "userinfo_endpoint") && ok;
    ok = put(m.jwks_uri, root, "jwks_uri") && ok;
    ok = put(m.revocation_endpoint, root, "revocation_endpoint") && ok;
    ok = put(m.introspection_endpoint, root, "introspection_endpoint") && ok;
    ok = put(m.device_endpoint, root, "device_authorization_endpoint") && ok;
    ok = put(m.par_endpoint, root, "pushed_authorization_request_endpoint") && ok;
    ok = put(m.end_session_endpoint, root, "end_session_endpoint") && ok;
    ok = put(m.registration_endpoint, root, "registration_endpoint") && ok;
    let al = json::member(root, "mtls_endpoint_aliases");
    if !absent(al) {
        guard al else { return m, false; }
        match al.val {
            Obj => {},
            _ => { return m, false; },
        }
        ok = put(m.mtls_token, al, "token_endpoint") && ok;
        ok = put(m.mtls_revocation, al, "revocation_endpoint") && ok;
        ok = put(m.mtls_introspection, al, "introspection_endpoint") && ok;
        ok = put(m.mtls_device, al, "device_authorization_endpoint") && ok;
        ok = put(m.mtls_par, al, "pushed_authorization_request_endpoint") && ok;
        ok = put(m.mtls_userinfo, al, "userinfo_endpoint") && ok;
    }
    let rp, ok1 = bool_field(root, "require_pushed_authorization_requests");
    let ip, ok2 = bool_field(root, "authorization_response_iss_parameter_supported");
    let bt, ok3 = bool_field(root, "tls_client_certificate_bound_access_tokens");
    m.require_par = rp;
    m.iss_parameter = ip;
    m.bound_tokens = bt;
    ok = ok && ok1 && ok2 && ok3;
    // The lists: none decides anything here, so one that cannot be kept
    // whole is left empty and flagged, never cut, and never fails discovery.
    var l: u8[>..] = [];
    if put_list(l, json::member(root, "scopes_supported"), 8192) { m.scopes.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "grant_types_supported"), 1024) { m.grant_types.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "response_types_supported"), 1024) { m.response_types.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "token_endpoint_auth_methods_supported"), 512) { m.auth_methods.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "code_challenge_methods_supported"), 128) { m.pkce_methods.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "id_token_signing_alg_values_supported"), 512) { m.id_token_algs.append(l); } else { m.lists_truncated = true; }
    l.clear();
    if put_list(l, json::member(root, "dpop_signing_alg_values_supported"), 512) { m.dpop_algs.append(l); } else { m.lists_truncated = true; }
    return m, ok && m.issuer.len > 0;
}

// Where the metadata of an issuer is: OpenID Connect's
// issuer + "/.well-known/openid-configuration" (Discovery §4), or RFC
// 8414's, the well-known part between the host and the issuer's path
// (§3.1).
fn metadata_url(issuer: const u8[:], oidc: bool) -> u8[>..] {
    var out: u8[>..] = [];
    var iss = issuer;
    if iss.len > 0 && iss[iss.len - 1] == '/' { iss = iss[..iss.len - 1]; }
    if oidc {
        out.append(iss);
        out.append("/.well-known/openid-configuration");
        return out;
    }
    let scheme_end = find(iss, "://");
    if scheme_end < 0 { out.append(iss); out.append("/.well-known/oauth-authorization-server"); return out; }
    let rest = iss[scheme_end + 3..];
    let slash = position(rest, '/');
    let host_end = if slash < 0 { iss.len } else { scheme_end + 3 + slash };
    out.append(iss[..host_end]);
    out.append("/.well-known/oauth-authorization-server");
    out.append(iss[host_end..]);
    return out;
}

// Whether every endpoint of m is one url_allowed lets the client use,
// those the browser is sent to (authorization, end_session) too.
fn endpoints_allowed(c: const Client&, m: const Metadata&) -> bool {
    for u in [m.authorization_endpoint[..], m.token_endpoint[..], m.userinfo_endpoint[..], m.jwks_uri[..],
              m.revocation_endpoint[..], m.introspection_endpoint[..], m.device_endpoint[..], m.par_endpoint[..],
              m.end_session_endpoint[..], m.registration_endpoint[..], m.mtls_token[..], m.mtls_revocation[..],
              m.mtls_introspection[..], m.mtls_device[..], m.mtls_par[..], m.mtls_userinfo[..]] {
        if u.len > 0 && !url_allowed(c, u) { return false; }
    }
    return true;
}

// Reads the issuer's metadata, by OpenID Connect discovery and then, if the
// server has none, RFC 8414's. The issuer in it must be `issuer` exactly
// (RFC 8414 §3.3, Discovery §4.3): ERR_ISSUER otherwise.
fn discover(c: Client&, hc: http::Client&, issuer: const u8[:]) -> i64 {
    if !url_allowed(c, issuer) { return ERR_INSECURE; }
    var last = ERR_MALFORMED;
    for which in 2 {
        let url = metadata_url(issuer, which == 0);
        let r = http::request(hc, "GET", url, "Accept: application/json\r\n", "");
        if r.err != 0 { c.http_err = r.err; return ERR_HTTP; }
        if r.status != 200 {
            c.error = error_of(http::response_body(r), r.status);
            last = ERR_OAUTH;
            continue;
        }
        let m, ok = read_metadata(http::response_body(r));
        if !ok { return ERR_MALFORMED; }
        if m.issuer[..] != issuer { return ERR_ISSUER; }
        if !endpoints_allowed(c, m) { return ERR_INSECURE; }
        c.meta = m;
        return OK;
    }
    return last;
}

// An endpoint by its plain URL, or its mutual-TLS alias when the client
// uses mutual TLS and the server has one.
fn endpoint(c: const Client&, plain: const u8[:], alias: const u8[:]) -> const u8[:] {
    return if c.use_mtls && alias.len > 0 { alias } else { plain };
}

fn token_endpoint(c: const Client&) -> const u8[:] { endpoint(c, c.meta.token_endpoint, c.meta.mtls_token) }

// --- Client authentication ---------------------------------------------------------

// The JWS alg for a key: ES256, ES384 or ES512 by the curve, RS256 for
// RSA, EdDSA for Ed25519 and Ed448 (RFC 8037); the key's own "alg" when it
// has one. UNKNOWN for anything else.
fn alg_for(k: const jwk::Key&) -> i64 {
    if k.alg != jwa::UNKNOWN && jwa::is_signature(k.alg) && k.alg != jwa::NONE && !jwa::is_hmac(k.alg) { return k.alg; }
    if k.kty == jwa::KTY_EC {
        if k.crv == jwa::CRV_P256 { return jwa::ES256; }
        if k.crv == jwa::CRV_P384 { return jwa::ES384; }
        if k.crv == jwa::CRV_P521 { return jwa::ES512; }
    }
    if k.kty == jwa::KTY_RSA { return jwa::RS256; }
    if k.kty == jwa::KTY_OKP && (k.crv == jwa::CRV_ED25519 || k.crv == jwa::CRV_ED448) { return jwa::EDDSA; }
    return jwa::UNKNOWN;
}

// A client with a secret: AUTH_SECRET_BASIC, AUTH_SECRET_POST or
// AUTH_SECRET_JWT.
fn set_secret(c: Client&, client_id: const u8[:], secret: const u8[:], method: i64 = AUTH_SECRET_BASIC) -> i64 {
    if client_id.len == 0 || client_id.len > 256 || secret.len == 0 { return ERR_ARG; }
    if method != AUTH_SECRET_BASIC && method != AUTH_SECRET_POST && method != AUTH_SECRET_JWT { return ERR_ARG; }
    // client_secret_jwt's secret is an HMAC key: at most jwk::MAX_OCT bytes.
    if method == AUTH_SECRET_JWT && secret.len > jwk::MAX_OCT { return ERR_ARG; }
    c.client_id.clear();
    c.client_id.append(client_id);
    c.secret.clear();
    c.secret.append(secret);
    c.auth = method;
    return OK;
}

// A public client (no secret): native and browser apps, with PKCE.
fn set_public(c: Client&, client_id: const u8[:]) -> i64 {
    if client_id.len == 0 || client_id.len > 256 { return ERR_ARG; }
    c.client_id.clear();
    c.client_id.append(client_id);
    c.auth = AUTH_NONE;
    return OK;
}

// private_key_jwt (RFC 7523 §2.2, OIDC Core §9): assertions signed by the
// client's private key, whose public half the server has registered.
fn set_private_key(c: Client&, client_id: const u8[:], key: const jwk::Key&) -> i64 {
    let alg = alg_for(key);
    if alg == jwa::UNKNOWN || !key.private { return ERR_KEY; }
    if client_id.len == 0 || client_id.len > 256 { return ERR_ARG; }
    c.client_id.clear();
    c.client_id.append(client_id);
    c.key = key;
    c.key_alg = alg;
    c.auth = AUTH_PRIVATE_KEY;
    return OK;
}

// tls_client_auth (RFC 8705 §2): the client is its certificate, which the
// http::Client presents (chain as concatenated DER, the leaf first; the
// key PKCS #8 or PKCS #1 DER). Requests go to the mtls_endpoint_aliases.
fn set_tls_client_auth(c: Client&, hc: http::Client&, client_id: const u8[:], chain: const u8[:],
                       key_der: const u8[:]) -> i64 {
    if client_id.len == 0 || client_id.len > 256 { return ERR_ARG; }
    if !tls::set_client_certificate(hc.tlscfg, chain, key_der) { return ERR_KEY; }
    c.client_id.clear();
    c.client_id.append(client_id);
    c.auth = AUTH_TLS;
    c.use_mtls = true;
    return OK;
}

// The client assertion of private_key_jwt or client_secret_jwt (RFC 7523
// §3): iss and sub the client, aud the issuer (as RFC 7523bis asks, or
// c.assertion_aud), a fresh jti, iat now and exp a minute on.
fn client_assertion(c: const Client&) -> u8[>..], i64 {
    var none: u8[>..] = [];
    var cl = jwt::new_claims();
    cl.iss.append(c.client_id);
    cl.sub.append(c.client_id);
    jwt::add_audience(cl, if c.assertion_aud.len > 0 { c.assertion_aud[..] } else { c.meta.issuer[..] });
    cl.jti.append(random_string(24));
    let now = now_s(c);
    jwt::set_issued_at(cl, now);
    jwt::set_expiry(cl, now + 60);
    var h = jws::Header { .. };
    h.typ.append("JWT");
    if c.auth == AUTH_SECRET_JWT {
        if c.secret.len == 0 { return none, ERR_KEY; }
        h.alg = jwa::HS256;
        var k = jwk::empty();
        k.kty = jwa::KTY_OCT;
        k.private = true;
        if c.secret.len > jwk::MAX_OCT { return none, ERR_KEY; }
        k.k.append(c.secret);
        let out, err = jws::sign_with(jwt::marshal(cl, true), k, h);
        return out, if err == jwx::OK { OK } else { ERR_KEY };
    }
    if c.key_alg == jwa::UNKNOWN { return none, ERR_KEY; }
    h.alg = c.key_alg;
    h.kid.append(c.key.kid);
    let out, err = jws::sign_with(jwt::marshal(cl, true), c.key, h);
    return out, if err == jwx::OK { OK } else { ERR_KEY };
}

// Adds the client's authentication to a request: to the form, or as an
// Authorization field (client_secret_basic: the id and secret each
// form-encoded first, RFC 6749 §2.3.1).
fn add_client_auth(c: const Client&, form: u8[>..]&, fields: u8[>..]&) -> i64 {
    if c.client_id.len == 0 { return ERR_ARG; }
    if c.auth == AUTH_SECRET_BASIC {
        var id:  u8[>..] = [];
        var sec: u8[>..] = [];
        http::query_escape(id, c.client_id);
        http::query_escape(sec, c.secret);
        var v: u8[>..] = [];
        http::basic_credentials(v, id, sec);
        http::add_field(fields, "Authorization", v);
        return OK;
    }
    http::form_add(form, "client_id", c.client_id);
    if c.auth == AUTH_SECRET_POST {
        http::form_add(form, "client_secret", c.secret);
    } else if c.auth == AUTH_SECRET_JWT || c.auth == AUTH_PRIVATE_KEY {
        let a, err = client_assertion(c);
        if err != OK { return err; }
        http::form_add(form, "client_assertion_type", ASSERTION_JWT_BEARER);
        http::form_add(form, "client_assertion", a);
    }
    return OK;
}

// --- PKCE (RFC 7636) ---------------------------------------------------------------

// A code verifier: 32 random bytes, base64url, 43 characters (§4.1).
fn new_verifier() -> u8[>..] { random_string(32) }

// The S256 code challenge of a verifier (§4.2): base64url(SHA-256(verifier)).
fn pkce_challenge(verifier: const u8[:]) -> u8[>..] {
    let d = bignum::sha256(verifier);
    return jwx::b64_encode(d[..]);
}

// --- DPoP (RFC 9449) ---------------------------------------------------------------

// The DPoP key (EC P-256 is what servers take most; RSA and Ed25519 too).
fn set_dpop_key(c: Client&, key: const jwk::Key&) -> i64 {
    let alg = alg_for(key);
    if alg == jwa::UNKNOWN || !key.private { return ERR_KEY; }
    c.dpop_key = key;
    c.dpop_key.kid.clear();
    c.dpop_alg = alg;
    return OK;
}

// The htu of a request (§4.2): its URL without query and fragment.
fn dpop_htu(url: const u8[:]) -> const u8[:] {
    var end = url.len;
    let q = position(url, '?');
    if q >= 0 { end = q; }
    let f = position(url[..end], '#');
    if f >= 0 { end = f; }
    return url[..end];
}

// ath (§4.2): base64url(SHA-256(the access token)).
fn dpop_ath(access_token: const u8[:]) -> u8[>..] {
    let d = bignum::sha256(access_token);
    return jwx::b64_encode(d[..]);
}

// A DPoP proof (§4.2): a JWT of typ "dpop+jwt" signed by `key`, carrying
// its public key, with a fresh jti, the method and URL, iat (`iat`, or now
// when 0), the server's nonce when there is one, and ath when an access
// token goes with it.
fn dpop_proof(key: const jwk::Key&, alg: i64, htm: const u8[:], htu: const u8[:], nonce: const u8[:] = "",
              access_token: const u8[:] = "", iat: i64 = 0) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if alg == jwa::UNKNOWN || alg == jwa::NONE || jwa::is_hmac(alg) || !key.private { return none, ERR_KEY; }
    var h = jws::Header { .. };
    h.alg = alg;
    h.typ.append("dpop+jwt");
    h.has_jwk = true;
    h.jwk = jwk::public_key(key);
    h.jwk.kid.clear();
    var p: u8[>..] = [];
    p.push('{');
    if access_token.len > 0 {
        jws::put_member_string(p, "ath", dpop_ath(access_token));
    }
    jws::put_member_string(p, "htm", htm);
    jws::put_member_string(p, "htu", dpop_htu(htu));
    jwx::put_comma(p);
    json::format_key(p, "iat");
    json::format_int(p, if iat != 0 { iat } else { time_ns() / 1000000000 });
    jws::put_member_string(p, "jti", random_string(24));
    if nonce.len > 0 { jws::put_member_string(p, "nonce", nonce); }
    p.push('}');
    let out, err = jws::sign_with(p, key, h);
    return out, if err == jwx::OK { OK } else { ERR_KEY };
}

// A server's DPoP-Nonce (§8, §9), kept for the next proof: false for one
// over 512 bytes, which refuses the response (an old nonce kept in its
// place would only fail later, and less clearly).
fn keep_dpop_nonce(dst: u8[..512]&, n: const u8[:], has: bool) -> bool {
    if !has || n.len == 0 { return true; }
    if n.len > 512 { return false; }
    dst.clear();
    dst.append(n);
    return true;
}

fn take_dpop_nonce(dst: u8[..512]&, r: const http::Response&) -> bool {
    let n, ok = http::response_header(r, "DPoP-Nonce");
    return keep_dpop_nonce(dst, n, ok);
}

// --- Requests to the authorization server ---------------------------------------------

// POSTs `params` (a form built with http::form_add) to an endpoint of the
// authorization server, with the client's authentication and, when the
// client has a DPoP key and `dpop` is true, a DPoP proof. A server that
// asks for a DPoP nonce (use_dpop_nonce, §8) is answered once with the
// nonce it sent. OK for a 2xx response; ERR_OAUTH with c.error otherwise.
fn post_form(c: Client&, hc: http::Client&, url: const u8[:], params: const u8[:], dpop: bool = true) -> http::Response, i64 {
    if url.len == 0 { return http::empty_response(0), ERR_ARG; }
    if !url_allowed(c, url) { return http::empty_response(0), ERR_INSECURE; }
    var tries = 0;
    loop {
        var form: u8[>..] = [];
        form.append(params);
        var fields: u8[>..] = [];
        http::add_field(fields, "Content-Type", "application/x-www-form-urlencoded");
        http::add_field(fields, "Accept", "application/json");
        let aerr = add_client_auth(c, form, fields);
        if aerr != OK { return http::empty_response(0), aerr; }
        if dpop && c.dpop_alg != jwa::UNKNOWN {
            let proof, perr = dpop_proof(c.dpop_key, c.dpop_alg, "POST", url, c.dpop_nonce, "", now_s(c));
            if perr != OK { return http::empty_response(0), perr; }
            http::add_field(fields, "DPoP", proof);
        }
        var r = http::request(hc, "POST", url, fields, form);
        if r.err != 0 {
            c.http_err = r.err;
            return r, ERR_HTTP;
        }
        if !take_dpop_nonce(c.dpop_nonce, r) { return r, ERR_MALFORMED; }
        if r.status >= 200 && r.status < 300 { return r, OK; }
        c.error = error_of(http::response_body(r), r.status);
        if is_error(c, "use_dpop_nonce") && dpop && c.dpop_alg != jwa::UNKNOWN && tries < 1 {
            tries++;
            continue;
        }
        return r, ERR_OAUTH;
    }
}

fn read_token(text: const u8[:], now: i64) -> Token, bool {
    var t = Token { .. };
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return t, false; }
    // Each whole or the response refused: a scope left out reads as the
    // one asked for (RFC 6749 §5.1), an ID token left out as none sent.
    let at, ok1 = str_field(root, "access_token", 12288);
    let tt, ok2 = str_field(root, "token_type", 32);
    let rt, ok3 = str_field(root, "refresh_token", 8192);
    let it, ok4 = str_field(root, "id_token", 12288);
    let sc, ok5 = str_field(root, "scope", 2048);
    let itt, ok6 = str_field(root, "issued_token_type", 128);
    if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6) || at.len == 0 || tt.len == 0 {
        return t, false;
    }
    t.access_token.append(at);
    t.token_type.append(tt);
    t.refresh_token.append(rt);
    t.id_token.append(it);
    t.scope.append(sc);
    t.issued_token_type.append(itt);
    t.expires_in = int_member(root, "expires_in");
    if t.expires_in > 0 { t.expires_at = now + t.expires_in; }
    return t, true;
}

// A request to the token endpoint for `grant_type`, with the grant's own
// parameters (`params`, a form built with http::form_add; may be empty).
// Every grant below is one of these.
fn grant(c: Client&, hc: http::Client&, grant_type: const u8[:], params: const u8[:]) -> Token, i64 {
    var form: u8[>..] = [];
    http::form_add(form, "grant_type", grant_type);
    if params.len > 0 {
        form.push('&');
        form.append(params);
    }
    let r, err = post_form(c, hc, token_endpoint(c), form);
    if err != OK { return Token { .. }, err; }
    let t, ok = read_token(http::response_body(r), now_s(c));
    return t, if ok { OK } else { ERR_MALFORMED };
}

// The client credentials grant (RFC 6749 §4.4). `extra` takes more
// parameters (resource=, audience=, ...) as a form.
fn client_credentials(c: Client&, hc: http::Client&, scope: const u8[:] = "", extra: const u8[:] = "") -> Token, i64 {
    var p: u8[>..] = [];
    if scope.len > 0 { http::form_add(p, "scope", scope); }
    if extra.len > 0 { if p.len > 0 { p.push('&'); } p.append(extra); }
    let t, err = grant(c, hc, "client_credentials", p);
    return t, err;
}

// A new access token for a refresh token (RFC 6749 §6). A server may send
// a new refresh token too (rotation); keep t.refresh_token when it does.
fn refresh(c: Client&, hc: http::Client&, refresh_token: const u8[:], scope: const u8[:] = "",
           extra: const u8[:] = "") -> Token, i64 {
    if refresh_token.len == 0 { return Token { .. }, ERR_ARG; }
    var p: u8[>..] = [];
    http::form_add(p, "refresh_token", refresh_token);
    if scope.len > 0 { http::form_add(p, "scope", scope); }
    if extra.len > 0 { p.push('&'); p.append(extra); }
    let t, err = grant(c, hc, "refresh_token", p);
    return t, err;
}

// Token exchange (RFC 8693 §2.1): the subject token and its type (TT_*);
// audience, resource, scope, requested_token_type and an actor token go in
// `extra` as a form.
fn token_exchange(c: Client&, hc: http::Client&, subject_token: const u8[:], subject_token_type: const u8[:],
                  extra: const u8[:] = "") -> Token, i64 {
    if subject_token.len == 0 || subject_token_type.len == 0 { return Token { .. }, ERR_ARG; }
    var p: u8[>..] = [];
    http::form_add(p, "subject_token", subject_token);
    http::form_add(p, "subject_token_type", subject_token_type);
    if extra.len > 0 { p.push('&'); p.append(extra); }
    let t, err = grant(c, hc, GRANT_TOKEN_EXCHANGE, p);
    return t, err;
}

// The JWT bearer grant (RFC 7523 §2.1): an assertion from another issuer
// for an access token.
fn jwt_bearer(c: Client&, hc: http::Client&, assertion: const u8[:], scope: const u8[:] = "") -> Token, i64 {
    var p: u8[>..] = [];
    http::form_add(p, "assertion", assertion);
    if scope.len > 0 { http::form_add(p, "scope", scope); }
    let t, err = grant(c, hc, GRANT_JWT_BEARER, p);
    return t, err;
}

// --- The authorization code flow --------------------------------------------------------

// A new authorization request: a fresh state, a PKCE verifier, and a nonce
// when the scope asks for OpenID Connect ("openid"). ERR_ARG for a
// redirect URI over 512 bytes or a scope over 1024.
fn new_auth_request(c: const Client&, redirect_uri: const u8[:], scope: const u8[:]) -> AuthRequest, i64 {
    var ar = AuthRequest { .. };
    if redirect_uri.len > 512 || scope.len > 1024 { return ar, ERR_ARG; }
    ar.state.append(random_string(24));
    ar.verifier.append(new_verifier());
    if has_scope(scope, "openid") { ar.nonce.append(random_string(24)); }
    ar.redirect_uri.append(redirect_uri);
    ar.scope.append(scope);
    return ar, OK;
}

// The authorization request's parameters (RFC 6749 §4.1.1, RFC 7636 §4.3,
// OIDC Core §3.1.2.1, RFC 9449 §10's dpop_jkt), then `extra` (prompt=,
// resource=, login_hint=, ...).
fn auth_params(c: const Client&, ar: const AuthRequest&, extra: const u8[:]) -> u8[>..] {
    var p: u8[>..] = [];
    http::form_add(p, "response_type", "code");
    http::form_add(p, "client_id", c.client_id);
    if ar.redirect_uri.len > 0 { http::form_add(p, "redirect_uri", ar.redirect_uri); }
    if ar.scope.len > 0 { http::form_add(p, "scope", ar.scope); }
    http::form_add(p, "state", ar.state);
    if ar.nonce.len > 0 { http::form_add(p, "nonce", ar.nonce); }
    http::form_add(p, "code_challenge", pkce_challenge(ar.verifier));
    http::form_add(p, "code_challenge_method", "S256");
    if ar.max_age >= 0 {
        var a: u8[>..] = [];
        format(a, ar.max_age);
        http::form_add(p, "max_age", a);
    }
    if c.dpop_alg != jwa::UNKNOWN { http::form_add(p, "dpop_jkt", jwk::thumbprint_b64(c.dpop_key)); }
    if extra.len > 0 { p.push('&'); p.append(extra); }
    return p;
}

fn with_query(base: const u8[:], q: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(base);
    out.push(if position(base, '?') >= 0 { '&' } else { '?' });
    out.append(q);
    return out;
}

// The URL to send the user to: the authorization endpoint with the
// request's parameters.
fn authorization_url(c: const Client&, ar: const AuthRequest&, extra: const u8[:] = "") -> u8[>..] {
    return with_query(c.meta.authorization_endpoint, auth_params(c, ar, extra));
}

// A pushed authorization request (RFC 9126): the parameters go to the PAR
// endpoint, authenticated, and the URL to send the user to carries only
// the client_id and the request_uri the server gave.
fn push_authorization_request(c: Client&, hc: http::Client&, ar: const AuthRequest&, extra: const u8[:] = "") -> u8[>..], i64 {
    var none: u8[>..] = [];
    let url = endpoint(c, c.meta.par_endpoint, c.meta.mtls_par);
    if url.len == 0 { return none, ERR_ARG; }
    var params = auth_params(c, ar, extra);
    // The client's authentication adds client_id again for most methods;
    // the server takes it once.
    var p: u8[>..] = [];
    var first = true;
    for pair in split(params, '&') {
        if pair.len > 10 && pair[..10] == "client_id=" { continue; }
        if !first { p.push('&'); }
        p.append(pair);
        first = false;
    }
    if c.auth == AUTH_SECRET_BASIC { http::form_add(p, "client_id", c.client_id); }
    let r, err = post_form(c, hc, url, p);
    if err != OK { return none, err; }
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(http::response_body(r), doc, decoded);
    let uri = str_member(root, "request_uri");
    if uri.len == 0 { return none, ERR_MALFORMED; }
    var q: u8[>..] = [];
    http::form_add(q, "client_id", c.client_id);
    http::form_add(q, "request_uri", uri);
    return with_query(c.meta.authorization_endpoint, q), OK;
}

// The code from the redirect back (RFC 6749 §4.1.2): `callback` is the
// redirect URL or its query. The state must be the request's (ERR_STATE);
// an "error" is the server's refusal (ERR_OAUTH, c.error); "iss", when
// there or when the server's metadata says it sends it, must be the
// issuer (RFC 9207, ERR_ISSUER).
fn parse_callback(c: Client&, ar: const AuthRequest&, callback: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    var q = callback;
    let qm = position(q, '?');
    if qm >= 0 { q = q[qm + 1..]; }
    let hash = position(q, '#');
    if hash >= 0 { q = q[..hash]; }
    let state, has_state = http::query_value(q, "state");
    if !has_state || state[..] != ar.state[..] { return none, ERR_STATE; }
    let iss, has_iss = http::query_value(q, "iss");
    if has_iss && iss[..] != c.meta.issuer[..] { return none, ERR_ISSUER; }
    if !has_iss && c.meta.iss_parameter { return none, ERR_ISSUER; }
    let e, has_err = http::query_value(q, "error");
    if has_err {
        c.error = Error { .. };
        let d, hd = http::query_value(q, "error_description");
        let u, hu = http::query_value(q, "error_uri");
        put_error(c.error, e, d, u);
        return none, ERR_OAUTH;
    }
    let code, has_code = http::query_value(q, "code");
    if !has_code || code.len == 0 { return none, ERR_MALFORMED; }
    return code, OK;
}

// The code for tokens (RFC 6749 §4.1.3), with the request's redirect URI
// and PKCE verifier (RFC 7636 §4.5).
fn exchange_code(c: Client&, hc: http::Client&, ar: const AuthRequest&, code: const u8[:], extra: const u8[:] = "") -> Token, i64 {
    if code.len == 0 { return Token { .. }, ERR_ARG; }
    var p: u8[>..] = [];
    http::form_add(p, "code", code);
    if ar.redirect_uri.len > 0 { http::form_add(p, "redirect_uri", ar.redirect_uri); }
    http::form_add(p, "code_verifier", ar.verifier);
    if extra.len > 0 { p.push('&'); p.append(extra); }
    let t, err = grant(c, hc, "authorization_code", p);
    return t, err;
}

// --- The device authorization grant (RFC 8628) ------------------------------------------

fn read_device(text: const u8[:]) -> Device, bool {
    var d = Device { .. };
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return d, false; }
    let dc, ok1 = str_field(root, "device_code", 1024);
    let uc, ok2 = str_field(root, "user_code", 128);
    let vu, ok3 = str_field(root, "verification_uri", 512);
    let vc, ok4 = str_field(root, "verification_uri_complete", 1024);
    if !(ok1 && ok2 && ok3 && ok4) || dc.len == 0 || uc.len == 0 || vu.len == 0 {
        return d, false;
    }
    d.device_code.append(dc);
    d.user_code.append(uc);
    d.verification_uri.append(vu);
    d.verification_uri_complete.append(vc);
    d.expires_in = int_member(root, "expires_in");
    let iv = int_member(root, "interval");
    if iv > 0 { d.interval = iv; }
    return d, d.expires_in > 0;
}

// Asks for a device code (§3.1): the user goes to d.verification_uri and
// enters d.user_code (or opens d.verification_uri_complete).
fn device_authorize(c: Client&, hc: http::Client&, scope: const u8[:] = "", extra: const u8[:] = "") -> Device, i64 {
    var p: u8[>..] = [];
    if scope.len > 0 { http::form_add(p, "scope", scope); }
    if extra.len > 0 { if p.len > 0 { p.push('&'); } p.append(extra); }
    let r, err = post_form(c, hc, endpoint(c, c.meta.device_endpoint, c.meta.mtls_device), p, false);
    if err != OK { return Device { .. }, err; }
    let d, ok = read_device(http::response_body(r));
    return d, if ok { OK } else { ERR_MALFORMED };
}

// One poll of the token endpoint for the device code (§3.4): the token, or
// ERR_OAUTH with c.error authorization_pending (ask again later),
// slow_down (and later, §3.5), access_denied or expired_token.
fn device_token(c: Client&, hc: http::Client&, d: const Device&) -> Token, i64 {
    var p: u8[>..] = [];
    http::form_add(p, "device_code", d.device_code);
    let t, err = grant(c, hc, GRANT_DEVICE_CODE, p);
    return t, err;
}

// Polls until the user has approved or denied, or the code expires: every
// d.interval seconds, five more after each slow_down (§3.5). ERR_TIMEOUT
// when it expires first.
fn device_wait(c: Client&, hc: http::Client&, d: const Device&) -> Token, i64 {
    var interval = max(d.interval, 1);
    let deadline = clock_ns() + d.expires_in * 1000000000;
    loop {
        if clock_ns() + interval * 1000000000 > deadline { return Token { .. }, ERR_TIMEOUT; }
        sleep_ms(interval * 1000);
        let t, err = device_token(c, hc, d);
        if err == ERR_OAUTH && is_error(c, "authorization_pending") { continue; }
        if err == ERR_OAUTH && is_error(c, "slow_down") { interval += 5; continue; }
        return t, err;
    }
}

// --- Introspection and revocation ---------------------------------------------------------

fn read_introspection(text: const u8[:]) -> Introspection, bool {
    var it = Introspection { .. };
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return it, false; }
    let am = json::member(root, "active");
    let active, ok = json::as_bool(am);
    if !ok { return it, false; }
    // Every member whole, or the response refused: what a resource server
    // decides by (scope, aud, client_id, sub, exp, cnf) is never part of
    // what the server said. A cnf left out would make a bound token look
    // bearer; an aud left out, a token for anyone.
    let sc, ok1 = str_field(root, "scope", 2048);
    let ci, ok2 = str_field(root, "client_id", 256);
    let un, ok3 = str_field(root, "username", 256);
    let tt, ok4 = str_field(root, "token_type", 64);
    let sub, ok5 = str_field(root, "sub", 256);
    let iss, ok6 = str_field(root, "iss", 512);
    let jti, ok7 = str_field(root, "jti", 256);
    let exp, ok8 = int_field(root, "exp");
    let iat, ok9 = int_field(root, "iat");
    let nbf, ok10 = int_field(root, "nbf");
    if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 && ok8 && ok9 && ok10) { return it, false; }
    var l: u8[>..] = [];
    let aud = json::member(root, "aud");
    let one, is_str = json::as_string(aud);
    if is_str {
        if one.len > 1024 || position(one, '\n') >= 0 { return it, false; }
        l.append(one);
    } else if !put_list(l, aud, 1024) {
        return it, false;
    }
    if !read_cnf(root, it.cnf_jkt, it.cnf_x5t) { return Introspection { .. }, false; }
    it.active = active;
    it.raw.append(text);
    it.scope.append(sc);
    it.client_id.append(ci);
    it.username.append(un);
    it.token_type.append(tt);
    it.exp = exp;
    it.iat = iat;
    it.nbf = nbf;
    it.sub.append(sub);
    it.iss.append(iss);
    it.jti.append(jti);
    it.aud.append(l);
    return it, true;
}

// What the server knows of a token (RFC 7662): it.active false for a
// token that is expired, revoked, or not the server's. `hint` is
// "access_token" or "refresh_token", or empty.
fn introspect(c: Client&, hc: http::Client&, token: const u8[:], hint: const u8[:] = "") -> Introspection, i64 {
    var p: u8[>..] = [];
    http::form_add(p, "token", token);
    if hint.len > 0 { http::form_add(p, "token_type_hint", hint); }
    let r, err = post_form(c, hc, endpoint(c, c.meta.introspection_endpoint, c.meta.mtls_introspection), p, false);
    if err != OK { return Introspection { .. }, err; }
    let it, ok = read_introspection(http::response_body(r));
    return it, if ok { OK } else { ERR_MALFORMED };
}

// Revokes a token (RFC 7009 §2): OK too for a token the server does not
// know (§2.2). `hint` as for introspect.
fn revoke(c: Client&, hc: http::Client&, token: const u8[:], hint: const u8[:] = "") -> i64 {
    var p: u8[>..] = [];
    http::form_add(p, "token", token);
    if hint.len > 0 { http::form_add(p, "token_type_hint", hint); }
    let r, err = post_form(c, hc, endpoint(c, c.meta.revocation_endpoint, c.meta.mtls_revocation), p, false);
    return err;
}

// --- Requests to resource servers -----------------------------------------------------------

// A request to a resource server with an access token: "Authorization:
// DPoP" and a proof bound to the token (RFC 9449 §7) when the token is a
// DPoP token and the client has the key, "Bearer" otherwise (RFC 6750
// §2.1). A 401 asking for a DPoP nonce is answered once with it. The
// response comes back whatever its status; ERR_OAUTH (c.error from
// WWW-Authenticate) for a 401 or 403.
fn resource_request(c: Client&, hc: http::Client&, method: const u8[:], url: const u8[:], t: const Token&,
                    fields: const u8[:] = "", body: const u8[:] = "") -> http::Response, i64 {
    let dpop = eq_fold(t.token_type, "DPoP");
    if dpop && c.dpop_alg == jwa::UNKNOWN { return http::empty_response(0), ERR_KEY; }
    if !url_allowed(c, url) { return http::empty_response(0), ERR_INSECURE; }
    var tries = 0;
    loop {
        var f: u8[>..] = [];
        f.append(fields);
        var authz: u8[>..] = [];
        authz.append(if dpop { "DPoP " } else { "Bearer " });
        authz.append(t.access_token);
        http::add_field(f, "Authorization", authz);
        if dpop {
            let proof, perr = dpop_proof(c.dpop_key, c.dpop_alg, method, url, c.rs_dpop_nonce, t.access_token, now_s(c));
            if perr != OK { return http::empty_response(0), perr; }
            http::add_field(f, "DPoP", proof);
        }
        var r = http::request(hc, method, url, f, body);
        if r.err != 0 {
            c.http_err = r.err;
            return r, ERR_HTTP;
        }
        if !take_dpop_nonce(c.rs_dpop_nonce, r) { return r, ERR_MALFORMED; }
        if r.status != 401 && r.status != 403 { return r, OK; }
        c.error = challenge_error(r);
        if dpop && c.error.code[..] == "use_dpop_nonce" && tries < 1 {
            tries++;
            continue;
        }
        return r, ERR_OAUTH;
    }
}
