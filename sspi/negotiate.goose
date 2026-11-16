// sspi.negotiate: HTTP's Negotiate authentication (RFC 4559) from the
// Windows login, as browsers and curl do it with SSPI: the Negotiate
// package picks Kerberos when the machine is in a domain and the server
// has an SPN (HTTP/host), NTLM otherwise; the server never sees a
// password. Or as another user, by name and password.
//
//   import gslib.sspi;
//   import gslib.sspi.negotiate;
//
//   var n, st = sspi::http_negotiate("web.example.com");   // or (..., package, user, password)
//   let h, st2 = sspi::http_authorization(n, "");       // the request's Authorization value
//   // ... a 401 with "WWW-Authenticate: Negotiate <token>" on the same connection:
//   let h2, st3 = sspi::http_authorization(n, www_authenticate);
//   // ... until the server answers 200; its last header (if any) completes n
//   sspi::http_close(n);
//
// The authentication belongs to the connection: every request of the
// exchange goes on one kept-alive HTTP/1.1 connection. The scheme is
// "Negotiate" (or "NTLM" for the NTLM package, which some servers offer
// alone).

namespace sspi;

import std;
import base64;

struct HttpAuth {
    cred:   i64,
    ctx:    i64,
    status: i64,             // the last step's
    done:   bool,            // the context is made
    scheme: u8[..16],        // "Negotiate" or "NTLM"
    target: u8[..512],       // HTTP/host
}

let HTTP_FLAGS: i64 = 0x00000810;   // ISC_REQ_CONFIDENTIALITY | ISC_REQ_CONNECTION, curl's

fn http_auth_with(cred: i64, host: const u8[:], package: const u8[:]) -> HttpAuth, i64 {
    var a = HttpAuth { cred: cred, ctx: 0, status: 0, done: false, scheme: [], target: [] };
    a.scheme.append(if fold_eq(package, NTLM) { "NTLM" } else { "Negotiate" });
    a.target.append("HTTP/");
    a.target.append(host[..min(host.len, 500)]);
    if cred < 0 { a.status = cred; return a, cred; }
    let ctx = context(cred);
    if ctx < 0 { free_credentials(cred); a.cred = 0; a.status = ctx; return a, ctx; }
    a.ctx = ctx;
    return a, OK;
}

// Negotiate for a server, host as in its URL: the state and OK, or a
// status. package: NEGOTIATE (the default), NTLM or KERBEROS. With user
// empty, as the logged-on user; else as that user (DOMAIN\user, or user
// with domain) by password.
fn http_negotiate(host: const u8[:], package: const u8[:] = "Negotiate", user: const u8[:] = "",
                  password: const u8[:] = "", domain: const u8[:] = "") -> HttpAuth, i64 {
    if user.len == 0 { return http_auth_with(acquire(package, CRED_OUTBOUND), host, package); }
    var u = user;
    var d = domain;
    var i = 0;
    while i < user.len && user[i] != '\\' { i++; }
    if i < user.len && domain.len == 0 { d = user[..i]; u = user[i + 1..]; }
    return http_auth_with(acquire_as(package, CRED_OUTBOUND, u, d, password), host, package);
}

// The token a WWW-Authenticate value carries for the scheme ("Negotiate
// <base64>", among other challenges separated by commas): ok false when
// the scheme is not there or its token is not base64; an empty token when
// the scheme is there alone.
fn http_challenge_token(value: const u8[:], scheme: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i < value.len {
        while i < value.len && (value[i] == ' ' || value[i] == '\t' || value[i] == ',') { i++; }
        var j = i;
        while j < value.len && value[j] != ' ' && value[j] != '\t' && value[j] != ',' { j++; }
        let name = value[i..j];
        var k = j;
        while k < value.len && (value[k] == ' ' || value[k] == '\t') { k++; }
        var e = k;
        while e < value.len && value[e] != ',' && value[e] != ' ' && value[e] != '\t' { e++; }
        if fold_eq(name, scheme) {
            let tok = value[k..e];
            // "Negotiate, NTLM": the scheme alone.
            if tok.len == 0 || (k < value.len && value[k] == ',') { return out, true; }
            if !base64::decode(out, tok) { out.clear(); return out, false; }
            return out, true;
        }
        i = if e > j { e } else { j };
    }
    return out, false;
}

// The Authorization value for the next request: with challenge "" the
// first ("Negotiate <token>"), then with each 401's WWW-Authenticate
// value. OK when the context is made (the value then is "" if there is
// nothing more to send), SEC_I_CONTINUE_NEEDED while the server has more
// to say, else an error. Give the 200's WWW-Authenticate (mutual
// authentication's last token, Kerberos') to the same call to finish.
fn http_authorization(a: HttpAuth&, challenge: const u8[:]) -> u8[>..], i64 {
    var value: u8[>..] = [];
    if a.ctx <= 0 { return value, if a.status < 0 { a.status } else { SEC_E_INVALID_HANDLE }; }
    var input: u8[>..] = [];
    if challenge.len > 0 {
        let tok, ok = http_challenge_token(challenge, a.scheme);
        if !ok { a.status = SEC_E_INVALID_TOKEN; return value, a.status; }
        if tok.len == 0 && a.done { return value, OK; }
        input.append(tok);
    }
    if a.done {
        // A context made already: the server's last token is mutual
        // authentication's, which only Kerberos sends; SSPI checks it.
        return value, OK;
    }
    var out: u8[>..] = [];
    let st = step(a.ctx, a.target, HTTP_FLAGS, input, out);
    a.status = st;
    if st < 0 { return value, st; }
    if st == OK { a.done = true; }
    if out.len > 0 {
        value.append(a.scheme);
        value.push(' ');
        base64::encode(value, out);
    }
    return value, st;
}

// The package the exchange settled on ("NTLM", "Kerberos"); "" before.
fn http_package(a: const HttpAuth&) -> u8[>..] { context_package(a.ctx) }

fn http_close(a: HttpAuth&) {
    if a.ctx > 0 { delete_context(a.ctx); a.ctx = 0; }
    if a.cred > 0 { free_credentials(a.cred); a.cred = 0; }
}
