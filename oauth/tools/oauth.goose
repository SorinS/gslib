// goose-oauth: tokens from an OAuth 2.0 / OpenID Connect server, on gslib's
// oauth:
//
//   goose-oauth --issuer URL --client-id ID [options] discover
//   goose-oauth --issuer URL --client-id ID [options] token          client credentials
//   goose-oauth --issuer URL --client-id ID [options] login          code + PKCE, a loopback redirect
//   goose-oauth --issuer URL --client-id ID [options] device         the device grant
//   goose-oauth --issuer URL --client-id ID [options] refresh --saved FILE
//   goose-oauth --issuer URL --client-id ID [options] exchange --token-file FILE [--token-type T]
//   goose-oauth --issuer URL --client-id ID [options] introspect|revoke (--token-file FILE | --saved FILE [--refresh])
//   goose-oauth --issuer URL --client-id ID [options] userinfo --saved FILE
//   goose-oauth --issuer URL --client-id ID [options] validate-id-token --saved FILE
//   goose-oauth --issuer URL [options] validate-access-token --token-file FILE --audience A
//
// The client authenticates by
//
//   --auth basic|post|secret-jwt   a secret from --client-secret-file FILE or $OAUTH_CLIENT_SECRET
//   --auth private-key-jwt --key FILE    a private JWK
//   --auth tls --cert FILE --cert-key FILE   a client certificate (PEM), RFC 8705
//   --auth none                     a public client (the default without a secret)
//
// and options: --ca-file FILE (the server's CAs, not the system's),
// --scope S, --resource R (repeatable), --audience A, --dpop-key FILE (a
// JWK, made P-256 0600 when not there: DPoP-bound tokens), --par (pushed
// authorization request), --port N (login's loopback port; 0 picks one),
// --timeout S, --save FILE (the whole token response, 0600), --nonce N.
//
// What it prints: the commands that get a token (token, login, device,
// refresh, exchange) print the access token alone on stdout, for a pipe or
// $(...), and say what came (type, lifetime, scope, whether a refresh or
// ID token did) on stderr; refresh and ID tokens go only to --save's file.
// discover, introspect, userinfo and the validate commands print JSON on
// stdout. Client secrets, private keys and refresh tokens are never
// printed, and secrets are not taken as arguments (ps shows those). Exit
// status 0 on success, 1 on failure, 2 on a usage error.
import std;
import os;
import json;
import gslib from "../..";
import gslib.oauth;
import gslib.oauth.oidc;
import gslib.jwx;
import gslib.jwx.jwa;
import gslib.jwx.jwk;
import gslib.net;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.net.http.url;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;
import gslib.dns;
import gslib.dns.client;
import gslib.dns.server;
import gslib.krb5.sys;

struct Options {
    issuer:      u8[..512]  = [],
    client_id:   u8[..256]  = [],
    auth:        u8[..32]   = [],
    secret_file: u8[..512]  = [],
    key:         u8[..512]  = [],
    cert:        u8[..512]  = [],
    cert_key:    u8[..512]  = [],
    ca_file:     u8[..512]  = [],
    scope:       u8[..1024] = [],
    resources:   u8[..2048] = [],    // one a line
    audience:    u8[..512]  = [],
    dpop_key:    u8[..512]  = [],
    par:         bool       = false,
    allow_http:  bool       = false,
    port:        i32        = 0,
    timeout:     i64        = 300,
    save:        u8[..512]  = [],
    saved:       u8[..512]  = [],
    token_file:  u8[..512]  = [],
    token_type:  u8[..128]  = [],
    hint:        u8[..32]   = [],
    use_refresh: bool       = false,
    nonce:       u8[..256]  = [],
}

// The most bytes an option's value may have (its field in Options): a
// longer one is a usage error, never cut. 0 for options that are numbers,
// -1 for no such option.
fn option_limit(s: const u8[:]) -> i64 {
    if s == "--client-id" { return 256; }
    if s == "--auth" || s == "--hint" { return 32; }
    if s == "--scope" { return 1024; }
    if s == "--resource" { return 2048; }
    if s == "--token-type" { return 128; }
    if s == "--nonce" { return 256; }
    if s == "--port" || s == "--timeout" { return 0; }
    if s == "--issuer" || s == "--client-secret-file" || s == "--key" || s == "--cert" || s == "--cert-key"
       || s == "--ca-file" || s == "--audience" || s == "--dpop-key" || s == "--save" || s == "--saved"
       || s == "--token-file" { return 512; }
    return -1;
}

// Whether a single-valued option already has its value.
fn option_set(o: const Options&, s: const u8[:]) -> bool {
    if s == "--issuer" { return o.issuer.len > 0; }
    if s == "--client-id" { return o.client_id.len > 0; }
    if s == "--auth" { return o.auth.len > 0; }
    if s == "--client-secret-file" { return o.secret_file.len > 0; }
    if s == "--key" { return o.key.len > 0; }
    if s == "--cert" { return o.cert.len > 0; }
    if s == "--cert-key" { return o.cert_key.len > 0; }
    if s == "--ca-file" { return o.ca_file.len > 0; }
    if s == "--scope" { return o.scope.len > 0; }
    if s == "--audience" { return o.audience.len > 0; }
    if s == "--dpop-key" { return o.dpop_key.len > 0; }
    if s == "--save" { return o.save.len > 0; }
    if s == "--saved" { return o.saved.len > 0; }
    if s == "--token-file" { return o.token_file.len > 0; }
    if s == "--token-type" { return o.token_type.len > 0; }
    if s == "--hint" { return o.hint.len > 0; }
    if s == "--nonce" { return o.nonce.len > 0; }
    return false;
}

fn usage() -> i32 {
    write_stderr("usage: goose-oauth --issuer URL --client-id ID [options] discover | token | login | device | refresh | exchange | introspect | revoke | userinfo | validate-id-token | validate-access-token\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-oauth: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str(s, "\n")); }

// What went wrong: the error, and the server's.
fn why(c: const oauth::Client&, e: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(oauth::error_text(e));
    if e == oauth::ERR_HTTP { out.append(": "); out.append(http::client_error_text(c.http_err)); }
    if e == oauth::ERR_OAUTH {
        if c.error.status > 0 { out.append(": HTTP "); format(out, c.error.status); }
        if c.error.code.len > 0 { out.append(": "); out.append(c.error.code); }
        if c.error.description.len > 0 { out.append(" ("); out.append(c.error.description); out.push(')'); }
    }
    return out;
}

fn write_private(path: const u8[:], data: const u8[:]) -> bool { krb5::krb5sys_write_private(path, data) == 0 }

// A file's text, or stdin's for "-", without the line end.
fn read_text(path: const u8[:]) -> u8[>..], bool {
    var text: u8[>..] = [];
    var out:  u8[>..] = [];
    var ok = true;
    if path == "-" {
        read_stdin(text, 1 << 20);
    } else {
        ok = read_file(path, text);
    }
    if ok { out.append(trim(text)); }
    return out, ok;
}

// The DPoP key from its file, or a new P-256 key written there (0600).
fn dpop_key(path: const u8[:]) -> jwk::Key, bool {
    var text: u8[>..] = [];
    if read_file(path, text) {
        let k, err = jwk::parse(text);
        return k, err == jwx::OK && k.private;
    }
    let k = jwk::generate_ec(jwa::CRV_P256);
    if !write_private(path, jwk::marshal(k, true)) { return k, false; }
    say(str("made a new DPoP key in ", path));
    return k, true;
}

// --- Saved token responses ---------------------------------------------------------

fn save_token(path: const u8[:], t: const oauth::Token&, nonce: const u8[:]) -> bool {
    var out: u8[>..] = [];
    out.append("{\"token_type\":");
    json::format_string(out, t.token_type);
    out.append(",\"access_token\":");
    json::format_string(out, t.access_token);
    if t.refresh_token.len > 0 { out.append(",\"refresh_token\":"); json::format_string(out, t.refresh_token); }
    if t.id_token.len > 0 { out.append(",\"id_token\":"); json::format_string(out, t.id_token); }
    if t.scope.len > 0 { out.append(",\"scope\":"); json::format_string(out, t.scope); }
    if t.expires_at > 0 { out.append(",\"expires_at\":"); json::format_int(out, t.expires_at); }
    if nonce.len > 0 { out.append(",\"nonce\":"); json::format_string(out, nonce); }
    out.append("}\n");
    return write_private(path, out);
}

fn load_token(path: const u8[:]) -> oauth::Token, u8[..256], bool {
    var t = oauth::Token { .. };
    var nonce: u8[..256] = [];
    var text:  u8[>..]   = [];
    if !read_file(path, text) { return t, nonce, false; }
    var doc:     json::Node[>..] = [];
    var decoded: u8[>..]         = [];
    let root, msg = json::parse(text, doc, decoded);
    guard root else { return t, nonce, false; }
    let tt = oauth::str_member(root, "token_type");
    let at = oauth::str_member(root, "access_token");
    let rt = oauth::str_member(root, "refresh_token");
    let it = oauth::str_member(root, "id_token");
    let sc = oauth::str_member(root, "scope");
    let n = oauth::str_member(root, "nonce");
    if tt.len > 32 || at.len > 12288 || rt.len > 8192 || it.len > 12288 || sc.len > 2048 || n.len > 256 { return t, nonce, false; }
    t.token_type.append(tt);
    t.access_token.append(at);
    t.refresh_token.append(rt);
    t.id_token.append(it);
    t.scope.append(sc);
    t.expires_at = oauth::int_member(root, "expires_at");
    nonce.append(n);
    return t, nonce, true;
}

// The token's description on stderr, the access token on stdout, the
// whole response to --save's file.
fn got_token(o: const Options&, t: const oauth::Token&, nonce: const u8[:]) -> i32 {
    var d: u8[>..] = [];
    d.append(str("got a ", t.token_type, " token"));
    if t.expires_in > 0 { d.append(str(" for ", t.expires_in, " s")); }
    if t.scope.len > 0 { d.append(str(", scope \"", t.scope, "\"")); }
    if t.refresh_token.len > 0 { d.append(", a refresh token"); }
    if t.id_token.len > 0 { d.append(", an ID token"); }
    if t.issued_token_type.len > 0 { d.append(str(", issued as ", t.issued_token_type)); }
    say(d);
    if o.save.len > 0 {
        if !save_token(o.save, t, nonce) { return fail(str("cannot write ", o.save)); }
        say(str("saved the token response to ", o.save));
    }
    print(t.access_token);
    return 0;
}

fn resource_params(o: const Options&) -> u8[>..] {
    var p: u8[>..] = [];
    for r in split(o.resources, '\n') {
        if r.len > 0 { http::form_add(p, "resource", r); }
    }
    if o.audience.len > 0 { http::form_add(p, "audience", o.audience); }
    return p;
}

// --- The loopback redirect (RFC 8252 §7.3) --------------------------------------------------

let PAGE: const u8[:] = "<!doctype html><title>goose-oauth</title><p>Done: you can close this window and go back to the terminal.</p>\n";

// Waits on the listening socket for the redirect to /callback, answers it,
// and gives its query.
fn wait_callback(fd: i64, timeout_s: i64) -> u8[>..], bool {
    var none: u8[>..] = [];
    let deadline = clock_ns() + timeout_s * 1000000000;
    var buf: u8[4096] = [0; 4096];
    while clock_ns() < deadline {
        let conn = dns::dnsnet_accept(fd, 1000);
        if conn < 0 { continue; }
        var req: u8[>..] = [];
        while find(req, "\r\n\r\n") < 0 && req.len < 16384 {
            let n = net::read(conn, buf, 5000);
            if n <= 0 { break; }
            req.append(buf[..n]);
        }
        let prefix = "GET /callback";
        if req.len > prefix.len && req[..prefix.len] == prefix && (req[prefix.len] == '?' || req[prefix.len] == ' ') {
            let line_end = find(req, "\r\n");
            let line = req[..if line_end < 0 { req.len } else { line_end }];
            let sp = rfind(line, " ");
            let target = line[4..if sp > 4 { sp } else { line.len }];
            var resp: u8[>..] = [];
            resp.append("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: ");
            format(resp, PAGE.len);
            resp.append("\r\nConnection: close\r\n\r\n");
            resp.append(PAGE);
            net::write(conn, resp, 5000);
            net::close(conn);
            var out: u8[>..] = [];
            out.append(target);
            return out, true;
        }
        net::write(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", 5000);
        net::close(conn);
    }
    return none, false;
}

fn login(c: oauth::Client&, hc: http::Client&, o: const Options&) -> i32 {
    let fd = dns::dnsnet_listen("127.0.0.1", o.port, 1);
    if fd < 0 { return fail(str("cannot listen on 127.0.0.1 port ", o.port)); }
    let port = dns::dnsnet_local_port(fd);
    let redirect = str("http://127.0.0.1:", port, "/callback");
    var scope: u8[>..] = [];
    scope.append(if o.scope.len > 0 { o.scope[..] } else { "openid" });
    let ar, aerr = oauth::new_auth_request(c, redirect, scope);
    if aerr != oauth::OK { dns::dnsnet_close(fd); return fail("the redirect URI or the scope is too long"); }
    let extra = resource_params(o);
    var url: u8[>..] = [];
    if o.par || c.meta.require_par {
        let u, err = oauth::push_authorization_request(c, hc, ar, extra);
        if err != oauth::OK { dns::dnsnet_close(fd); return fail(str("the pushed authorization request failed: ", why(c, err))); }
        url.append(u);
    } else {
        url.append(oauth::authorization_url(c, ar, extra));
    }
    say("open this URL in a browser to sign in:");
    say(url);
    let query, got = wait_callback(fd, o.timeout);
    dns::dnsnet_close(fd);
    if !got { return fail("no redirect came back in time"); }
    let code, cerr = oauth::parse_callback(c, ar, query);
    if cerr != oauth::OK { return fail(str("the redirect: ", why(c, cerr))); }
    let t, err = oauth::exchange_code(c, hc, ar, code, extra);
    if err != oauth::OK { return fail(why(c, err)); }
    if t.id_token.len > 0 {
        let id, ierr = oauth::validate_id_token(c, hc, t.id_token, ar.nonce, t.access_token);
        if ierr != oauth::OK { return fail(str("the ID token: ", oauth::error_text(ierr))); }
        say(str("the ID token is valid: sub ", id.sub));
    }
    return got_token(o, t, ar.nonce);
}

fn device(c: oauth::Client&, hc: http::Client&, o: const Options&) -> i32 {
    var p = resource_params(o);
    let d, err = oauth::device_authorize(c, hc, o.scope, p);
    if err != oauth::OK { return fail(why(c, err)); }
    say(str("to sign in, go to ", d.verification_uri, " and enter the code ", d.user_code));
    if d.verification_uri_complete.len > 0 { say(str("or open ", d.verification_uri_complete)); }
    say(str("(the code is good for ", d.expires_in, " s)"));
    let t, werr = oauth::device_wait(c, hc, d);
    if werr != oauth::OK { return fail(why(c, werr)); }
    return got_token(o, t, "");
}

// The token a command works on: --token-file's, or --saved's access token
// (refresh token with --refresh).
fn subject_token(o: const Options&) -> u8[>..], bool {
    var out: u8[>..] = [];
    if o.token_file.len > 0 {
        let t, ok = read_text(o.token_file);
        if ok { out.append(t); }
    } else if o.saved.len > 0 {
        let t, nonce, ok = load_token(o.saved);
        if ok { out.append(if o.use_refresh { t.refresh_token[..] } else { t.access_token[..] }); }
    }
    return out, out.len > 0;
}

fn print_metadata(m: const oauth::Metadata&) {
    var out: u8[>..] = [];
    out.append("{");
    var first = true;
    for pair in [["issuer", m.issuer[..]], ["authorization_endpoint", m.authorization_endpoint[..]],
                 ["token_endpoint", m.token_endpoint[..]], ["userinfo_endpoint", m.userinfo_endpoint[..]],
                 ["jwks_uri", m.jwks_uri[..]], ["revocation_endpoint", m.revocation_endpoint[..]],
                 ["introspection_endpoint", m.introspection_endpoint[..]],
                 ["device_authorization_endpoint", m.device_endpoint[..]],
                 ["pushed_authorization_request_endpoint", m.par_endpoint[..]],
                 ["end_session_endpoint", m.end_session_endpoint[..]]] {
        if pair[1].len == 0 { continue; }
        if !first { out.append(",\n "); }
        first = false;
        json::format_string(out, pair[0]);
        out.push(':');
        json::format_string(out, pair[1]);
    }
    out.append(",\n \"token_endpoint_auth_methods_supported\":");
    json::format_string(out, m.auth_methods);
    out.append(",\n \"dpop_signing_alg_values_supported\":");
    json::format_string(out, m.dpop_algs);
    out.append(",\n \"require_pushed_authorization_requests\":");
    json::format_bool(out, m.require_par);
    out.append(",\n \"tls_client_certificate_bound_access_tokens\":");
    json::format_bool(out, m.bound_tokens);
    out.append("}");
    print(out);
}

fn configure(c: oauth::Client&, hc: http::Client&, o: const Options&) -> i32 {
    if o.ca_file.len > 0 {
        var text: u8[>..] = [];
        if !read_file(o.ca_file, text) { return fail(str("cannot read ", o.ca_file)); }
        var pool = x509::new_pool();
        if x509::pool_append_pem(pool, text) <= 0 { return fail(str("no certificates in ", o.ca_file)); }
        hc.tlscfg = tls::client_config_pool("", pool);
    }
    var secret: u8[>..] = [];
    if o.secret_file.len > 0 {
        let s, ok = read_text(o.secret_file);
        if !ok || s.len == 0 { return fail(str("cannot read the client secret from ", o.secret_file)); }
        secret.append(s);
    } else {
        env("OAUTH_CLIENT_SECRET", secret);
    }
    let a = o.auth[..];
    let mode = if a.len > 0 { a } else if secret.len > 0 { "basic" } else { "none" };
    if o.client_id.len == 0 && mode != "none" { return fail("--client-id is needed"); }
    if mode == "basic" || mode == "post" || mode == "secret-jwt" {
        if secret.len == 0 { return fail("no client secret: --client-secret-file FILE or $OAUTH_CLIENT_SECRET"); }
        let m = if mode == "basic" { oauth::AUTH_SECRET_BASIC } else if mode == "post" { oauth::AUTH_SECRET_POST } else { oauth::AUTH_SECRET_JWT };
        if oauth::set_secret(c, o.client_id, secret, m) != oauth::OK { return fail("the client id or secret cannot be used"); }
    } else if mode == "private-key-jwt" {
        if o.key.len == 0 { return fail("private-key-jwt needs --key FILE"); }
        var text: u8[>..] = [];
        if !read_file(o.key, text) { return fail(str("cannot read ", o.key)); }
        let k, err = jwk::parse(text);
        if err != jwx::OK || oauth::set_private_key(c, o.client_id, k) != oauth::OK { return fail(str("no private JWK in ", o.key)); }
    } else if mode == "tls" {
        if o.cert.len == 0 || o.cert_key.len == 0 { return fail("tls needs --cert FILE and --cert-key FILE"); }
        var ct: u8[>..] = [];
        var kt: u8[>..] = [];
        if !read_file(o.cert, ct) || !read_file(o.cert_key, kt) { return fail("cannot read the certificate or its key"); }
        let certs, cok = asn1::pem_decode(ct, "CERTIFICATE");
        if !cok || certs.len == 0 { return fail(str("no certificate in ", o.cert)); }
        var chain: u8[>..] = [];
        for d in certs { chain.append(d); }
        let keys, kok = asn1::pem_decode(kt, "");
        var key_der: u8[>..] = [];
        for d in keys {
            let k, pok = x509::parse_private_key(d);
            if pok && key_der.len == 0 { key_der.append(d); }
        }
        if key_der.len == 0 { return fail(str("no private key in ", o.cert_key)); }
        if oauth::set_tls_client_auth(c, hc, o.client_id, chain, key_der) != oauth::OK { return fail("the certificate or key cannot be used"); }
    } else if mode == "none" {
        if o.client_id.len > 0 { oauth::set_public(c, o.client_id); }
    } else {
        return fail(str("no such --auth: ", mode));
    }
    c.allow_http = o.allow_http;
    if o.dpop_key.len > 0 {
        let k, ok = dpop_key(o.dpop_key);
        if !ok || oauth::set_dpop_key(c, k) != oauth::OK { return fail(str("cannot read or write the DPoP key ", o.dpop_key)); }
    }
    return 0;
}

fn run() -> i32 {
    let a = args();
    var o = Options { .. };
    var command: u8[..32] = [];
    var i = 1;
    while i < a.len {
        let s = a[i];
        let has_value = i + 1 < a.len;
        if s == "--par" { o.par = true; }
        else if s == "--refresh" { o.use_refresh = true; }
        else if s == "--allow-http" { o.allow_http = true; }
        else if s.len > 0 && s[0] != '-' {
            if command.len > 0 || s.len > 32 { return usage(); }
            command.append(s);
        }
        else if !has_value { return usage(); }
        else {
            i++;
            let v = a[i];
            let limit = option_limit(s);
            if limit < 0 { return usage(); }
            // --resource repeats: all of them, one a line, share its limit.
            let used = if s == "--resource" { o.resources.len + 1 } else { 0 };
            if limit > 0 && used + v.len > limit {
                write_stderr(str("goose-oauth: ", s, " is too long (at most ", limit, " bytes)\n"));
                return 2;
            }
            // Repeated, a single option's value would run into the last.
            if limit > 0 && s != "--resource" && option_set(o, s) {
                write_stderr(str("goose-oauth: ", s, " given twice\n"));
                return 2;
            }
            if s == "--issuer" { o.issuer.append(v); }
            else if s == "--client-id" { o.client_id.append(v); }
            else if s == "--auth" { o.auth.append(v); }
            else if s == "--client-secret-file" { o.secret_file.append(v); }
            else if s == "--key" { o.key.append(v); }
            else if s == "--cert" { o.cert.append(v); }
            else if s == "--cert-key" { o.cert_key.append(v); }
            else if s == "--ca-file" { o.ca_file.append(v); }
            else if s == "--scope" { o.scope.append(v); }
            else if s == "--resource" {
                // One a line: a value with a line end would be two resources.
                if position(v, '\n') >= 0 || v.len == 0 {
                    write_stderr("goose-oauth: a --resource is empty or holds a line end\n");
                    return 2;
                }
                o.resources.append(v);
                o.resources.push('\n');
            }
            else if s == "--audience" { o.audience.append(v); }
            else if s == "--dpop-key" { o.dpop_key.append(v); }
            else if s == "--port" { let p, ok = parse_int(v); if !ok || p < 0 || p > 65535 { return usage(); } o.port = p as! i32; }
            else if s == "--timeout" { let t, ok = parse_int(v); if !ok || t <= 0 { return usage(); } o.timeout = t; }
            else if s == "--save" { o.save.append(v); }
            else if s == "--saved" { o.saved.append(v); }
            else if s == "--token-file" { o.token_file.append(v); }
            else if s == "--token-type" { o.token_type.append(v); }
            else if s == "--hint" { o.hint.append(v); }
            else if s == "--nonce" { o.nonce.append(v); }
            else { return usage(); }
        }
        i++;
    }
    if command.len == 0 || o.issuer.len == 0 { return usage(); }

    var hc = http::Client { .. };
    var c = oauth::Client { .. };
    let cerr = configure(c, hc, o);
    if cerr != 0 { return cerr; }
    let derr = oauth::discover(c, hc, o.issuer);
    if derr != oauth::OK { return fail(str("cannot read the issuer's metadata: ", why(c, derr))); }

    if command == "discover" { print_metadata(c.meta); return 0; }
    if command == "token" {
        let t, err = oauth::client_credentials(c, hc, o.scope, resource_params(o));
        if err != oauth::OK { return fail(why(c, err)); }
        return got_token(o, t, "");
    }
    if command == "login" { return login(c, hc, o); }
    if command == "device" { return device(c, hc, o); }
    if command == "refresh" {
        if o.saved.len == 0 { return usage(); }
        let old, nonce, ok = load_token(o.saved);
        if !ok || old.refresh_token.len == 0 { return fail(str("no refresh token in ", o.saved)); }
        let t, err = oauth::refresh(c, hc, old.refresh_token, o.scope, resource_params(o));
        if err != oauth::OK { return fail(why(c, err)); }
        // A server that does not rotate refresh tokens sends none: keep the old one.
        var nt = t;
        if nt.refresh_token.len == 0 { nt.refresh_token.append(old.refresh_token); }
        return got_token(o, nt, "");
    }
    if command == "exchange" {
        let st, ok = subject_token(o);
        if !ok { return fail("exchange needs --token-file FILE or --saved FILE"); }
        var p = resource_params(o);
        if o.scope.len > 0 { http::form_add(p, "scope", o.scope); }
        let tt = if o.token_type.len > 0 { o.token_type[..] } else { oauth::TT_ACCESS_TOKEN };
        let t, err = oauth::token_exchange(c, hc, st, tt, p);
        if err != oauth::OK { return fail(why(c, err)); }
        return got_token(o, t, "");
    }
    if command == "introspect" || command == "revoke" {
        let tok, ok = subject_token(o);
        if !ok { return fail(str(command, " needs --token-file FILE or --saved FILE")); }
        let hint = if o.hint.len > 0 { o.hint[..] } else if o.use_refresh { "refresh_token" } else { "" };
        if command == "revoke" {
            let err = oauth::revoke(c, hc, tok, hint);
            if err != oauth::OK { return fail(why(c, err)); }
            say("revoked");
            return 0;
        }
        let it, err = oauth::introspect(c, hc, tok, hint);
        if err != oauth::OK { return fail(why(c, err)); }
        print(it.raw);
        return 0;
    }
    if command == "userinfo" {
        if o.saved.len == 0 { return usage(); }
        let t, nonce, ok = load_token(o.saved);
        if !ok { return fail(str("cannot read ", o.saved)); }
        var sub: u8[>..] = [];
        if t.id_token.len > 0 {
            let id, ierr = oauth::validate_id_token(c, hc, t.id_token, "");
            if ierr == oauth::OK { sub.append(id.sub); }
        }
        let info, err = oauth::userinfo(c, hc, t, sub);
        if err != oauth::OK { return fail(why(c, err)); }
        print(info);
        return 0;
    }
    if command == "validate-id-token" {
        var token:  u8[>..] = [];
        var nonce:  u8[>..] = [];
        var access: u8[>..] = [];
        if o.saved.len > 0 {
            let t, n, ok = load_token(o.saved);
            if !ok { return fail(str("cannot read ", o.saved)); }
            token.append(t.id_token);
            nonce.append(n);
            access.append(t.access_token);
        } else {
            let t, ok = read_text(o.token_file);
            if !ok { return fail("validate-id-token needs --saved FILE or --token-file FILE"); }
            token.append(t);
        }
        if o.nonce.len > 0 { nonce.clear(); nonce.append(o.nonce); }
        if token.len == 0 { return fail("no ID token"); }
        let id, err = oauth::validate_id_token(c, hc, token, nonce, access);
        if err != oauth::OK { return fail(str("invalid: ", oauth::error_text(err))); }
        say(str("valid: an ID token for ", id.sub, ", signed with ", jwa::name(id.alg)));
        print(id.claims);
        return 0;
    }
    if command == "validate-access-token" {
        let tok, ok = subject_token(o);
        if !ok || o.audience.len == 0 { return fail("validate-access-token needs --token-file FILE and --audience A"); }
        let at, err = oauth::validate_access_token(c, hc, tok, o.audience, o.scope);
        if err != oauth::OK { return fail(str("invalid: ", oauth::error_text(err))); }
        say(str("valid: an access token for ", at.sub, " from client ", at.client_id, ", signed with ", jwa::name(at.alg)));
        print(at.claims);
        return 0;
    }
    return usage();
}

fn main() { exit(run()); }
