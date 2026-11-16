// negotiate_get: a GET with HTTP Negotiate authentication (RFC 4559) from
// SSPI, over one kept-alive HTTP/1.1 connection: the Windows login's
// credentials (Kerberos in a domain, NTLM otherwise), or a user's by
// password. Prints each request's Authorization header (the token's
// size), the package agreed and the final status and body.
//
//   negotiate_get [--user DOMAIN\USER --password-env VAR] [--package NTLM|Negotiate|Kerberos]
//                 [--header-only] http://host[:port]/path
//
// --header-only prints the first "Authorization: Negotiate ..." value and
// stops, without connecting. The password comes from an environment
// variable, never the command line.

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.sspi;
import gslib.sspi.negotiate;

fn usage() {
    write_stderr("usage: negotiate_get [--user DOMAIN\\USER --password-env VAR] [--package P] [--header-only] http://host[:port]/path\n");
    exit(2);
}

fn fail(what: const u8[:]) {
    write_stderr(str("negotiate_get: ", what, "\n"));
    exit(1);
}

// The response's status, its WWW-Authenticate values joined by ", " and
// its body (Content-Length only; this is an example).
fn read_response(fd: i64) -> i64, u8[>..], u8[>..] {
    var data: u8[>..] = [];
    var buf:  u8[>..] = [];
    buf.resize(16384, 0);
    var head_end = -1;
    var auth:  u8[>..] = [];
    var bodyv: u8[>..] = [];
    while head_end < 0 {
        let n = net::read(fd, buf, 15000);
        if n <= 0 { return -1, auth, bodyv; }
        data.append(buf[..n]);
        var i = 0;
        while i + 4 <= data.len { if data[i..i + 4] == "\r\n\r\n" { head_end = i; break; } i++; }
    }
    let head = data[..head_end];
    var status = -1;
    if head.len > 12 {
        let s, ok = parse_int(head[9..12]);
        if ok { status = s; }
    }
    var length = 0;
    var start = 0;
    for i in 0..head.len + 1 {
        if i == head.len || head[i] == '\r' {
            let line = head[start..i];
            var c = 0;
            while c < line.len && line[c] != ':' { c++; }
            if c < line.len {
                let name = line[..c];
                var v = line[c + 1..];
                while v.len > 0 && v[0] == ' ' { v = v[1..]; }
                if sspi::fold_eq(name, "WWW-Authenticate") {
                    if auth.len > 0 { auth.append(", "); }
                    auth.append(v);
                } else if sspi::fold_eq(name, "Content-Length") {
                    let l, ok = parse_int(v);
                    if ok { length = l; }
                }
            }
            start = i + 2;
        }
    }
    bodyv.append(data[head_end + 4..]);
    while bodyv.len < length {
        let n = net::read(fd, buf, 15000);
        if n <= 0 { break; }
        bodyv.append(buf[..n]);
    }
    return status, auth, bodyv;
}

fn main() {
    let argv = args();
    var user:    const u8[:] = "";
    var pw_var:  const u8[:] = "";
    var package: const u8[:] = sspi::NEGOTIATE;
    var header_only = false;
    var url: const u8[:] = "";
    var i = 1;
    while i < argv.len {
        let a = argv[i];
        if a == "--user" && i + 1 < argv.len { i++; user = argv[i]; }
        else if a == "--password-env" && i + 1 < argv.len { i++; pw_var = argv[i]; }
        else if a == "--package" && i + 1 < argv.len { i++; package = argv[i]; }
        else if a == "--header-only" { header_only = true; }
        else if url.len == 0 && starts_with(a, "http://") { url = a; }
        else { usage(); }
        i++;
    }
    if url.len == 0 || (user.len > 0) != (pw_var.len > 0) { usage(); }
    let rest = url[7..];
    var slash = 0;
    while slash < rest.len && rest[slash] != '/' { slash++; }
    let hostport = rest[..slash];
    let path = if slash < rest.len { rest[slash..] } else { "/" };
    var colon = 0;
    while colon < hostport.len && hostport[colon] != ':' { colon++; }
    let host = hostport[..colon];
    var port = 80;
    if colon < hostport.len {
        let p, ok = parse_int(hostport[colon + 1..]);
        if !ok { usage(); }
        port = p;
    }

    var password: u8[>..] = [];
    if pw_var.len > 0 && !env(pw_var, password) { fail(str("no environment variable ", pw_var)); }
    var a, st = sspi::http_negotiate(host, package, user, password);
    for k in 0..password.len { password[k] = 0; }
    if st != sspi::OK { fail(sspi::error_text(st)); }

    let first, st1 = sspi::http_authorization(a, "");
    if st1 < 0 { fail(sspi::error_text(st1)); }
    if header_only {
        print(str("Authorization: ", first));
        sspi::http_close(a);
        return;
    }
    let fd = net::dial(host, port as! i32, 10000);
    if fd < 0 { fail("cannot connect"); }
    var value: u8[>..] = copy(first);
    var round = 0;
    while round < 5 {
        round++;
        var req: u8[>..] = [];
        req.append(str("GET ", path, " HTTP/1.1\r\nHost: ", hostport, "\r\nUser-Agent: goose-sspi\r\n"));
        if value.len > 0 { req.append(str("Authorization: ", value, "\r\n")); }
        req.append("\r\n");
        print(str("request ", round, if value.len > 0 { str(": ", a.scheme, " token, ", value.len, " characters") } else { str(": no Authorization") }));
        if net::write(fd, req, 10000) < 0 { fail("write failed"); }
        let status, auth, bodyv = read_response(fd);
        print(str("response ", round, ": ", status));
        if status == 401 {
            if a.done { fail("401 after the context was made: credentials refused"); }
            let next, st2 = sspi::http_authorization(a, auth);
            if st2 < 0 { fail(sspi::error_text(st2)); }
            value = copy(next);
            continue;
        }
        if auth.len > 0 { sspi::http_authorization(a, auth); }
        print(str("package: ", sspi::http_package(a)));
        print(str("body: ", bodyv));
        net::close(fd);
        sspi::http_close(a);
        exit(if status == 200 { 0 } else { 1 });
    }
    fail("too many rounds");
}
