// negotiate_server: an HTTP server whose every path needs Kerberos, by
// HTTP Negotiate (RFC 4559) as browsers, curl --negotiate and Windows'
// SSPI send it. The service's keys come from a keytab (ktpass's, or
// ktutil's); a request with a ticket for one of them is answered with
// who the client is and, from an Active Directory KDC, the SIDs in the
// ticket's PAC, verified with the service's key. The 200 carries the
// server's own token, for the client's mutual authentication.
//
//   negotiate_server --keytab FILE [--listen ADDR] [--port N] [--count N]
//
// It listens on 127.0.0.1 port 8080 unless told otherwise, and stops
// after --count authenticated requests (0: never). For an Active
// Directory service account:
//
//   setspn -S HTTP/web.example.com EXAMPLE\svc-web
//   ktpass /out web.keytab /princ HTTP/web.example.com@EXAMPLE.COM /mapuser EXAMPLE\svc-web
//          /pass * /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL
//
// and a client asks for http://web.example.com:8080/, the name resolving
// to this server (examples/sspi/negotiate_get.goose is one).

import std;
import os;
import gslib from "../..";
import gslib.krb5;
import gslib.krb5.keytab;
import gslib.krb5.service;
import gslib.krb5.gssapi;
import gslib.krb5.spnego;
import gslib.krb5.pac;
import gslib.krb5.ndr;
import gslib.net;
import gslib.net.http;
import gslib.net.http.conn1;

fn usage() {
    write_stderr("usage: negotiate_server --keytab FILE [--listen ADDR] [--port N] [--count N]\n");
    exit(2);
}

// Who the ticket's client is, and its PAC's SIDs when there is one.
fn describe(acc: const krb5::GssAccepted&) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(str("hello ", krb5::principal_string(acc.ap.client, acc.ap.client_realm), "\n"));
    let p, found, err = krb5::pac_verify(acc.ap, acc.ap.service_key);
    if !found { return out; }
    if err != krb5::OK { out.append(str("PAC: ", krb5::error_text(err), "\n")); return out; }
    if p.has_logon_info {
        for s in krb5::logon_sids(p.logon_info) { out.append(str("sid ", s, "\n")); }
    }
    return out;
}

// One connection's requests until it closes; each request is
// authenticated on its own, as HTTP Negotiate's are. Returns how many
// were.
fn serve_conn(c: i64, kt: const krb5::KeytabEntry[:], rc: krb5::ReplayEntry[>..]&) -> i64 {
    var hc = http::server_conn(http::server_options());
    var raw: u8[16384] = [0; 16384];
    var buf: u8[>..] = [];
    var body: u8[>..] = [];
    var trailer: u8[>..] = [];
    var out: u8[>..] = [];
    var auth: u8[>..] = [];
    var path: u8[>..] = [];
    var served = 0;
    while true {
        while true {
            let ev, h = http::server_read(hc, buf, body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                auth.clear();
                let s, has = http::get(buf, h, "authorization");
                if has { auth.append(buf[s.pos..s.end]); }
                path.clear();
                path.append(buf[h.target.pos..h.target.end]);
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED {
                if out.len > 0 { net::write(c, out, 10000); }
                return served;
            }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf.clear();
            buf.append(rest);
            if (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc) {
                var status = 401;
                var fields: u8[>..] = [];
                var reply: u8[>..] = [];
                let tok, ok = krb5::negotiate_token(auth);
                if auth.len == 0 || !ok || tok.len == 0 {
                    fields.append("WWW-Authenticate: Negotiate\r\n");
                    reply.append("authentication required\n");
                    print("GET ", path, ": challenge");
                } else {
                    var ctx = krb5::empty_spnego();
                    var t: u8[>..] = [];
                    let ns = time_ns();
                    let done, acc, err = krb5::spnego_accept(ctx, tok, kt, true, rc, ns / 1000000000, ns / 1000 % 1000000, 300, "", false, t);
                    if t.len > 0 { fields.append(str("WWW-Authenticate: ", krb5::negotiate_header(t), "\r\n")); }
                    if err == krb5::OK && done {
                        status = 200;
                        reply.append(describe(acc));
                        served++;
                        print("GET ", path, ": ", krb5::principal_string(acc.ap.client, acc.ap.client_realm),
                              " (", if ctx.raw { "Kerberos" } else { "SPNEGO" }, ")");
                    } else {
                        if t.len == 0 { fields.append("WWW-Authenticate: Negotiate\r\n"); }
                        reply.append(str("refused: ", krb5::error_text(err), "\n"));
                        print("GET ", path, ": refused: ", krb5::error_text(err));
                    }
                }
                fields.append("Content-Type: text/plain\r\n");
                http::server_respond(hc, status, fields, reply.len, out);
                http::server_body(hc, reply, out);
                http::server_end(hc, "", out);
                body.clear();
                net::write(c, out, 10000);
                out.clear();
                flush_stdout();
                if http::closing(hc) { return served; }
                continue;
            }
            if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
        }
        if out.len > 0 { net::write(c, out, 10000); out.clear(); }
        let n = net::read(c, raw, 30000);
        if n <= 0 { return served; }
        buf.append(raw[..n]);
    }
    return served;
}

fn main() {
    let argv = args();
    var keytab: const u8[:] = "";
    var addr: const u8[:] = "127.0.0.1";
    var port = 8080;
    var count = 0;
    var i = 1;
    while i < argv.len {
        let a = argv[i];
        if i + 1 >= argv.len { usage(); }
        i++;
        if a == "--keytab" { keytab = argv[i]; }
        else if a == "--listen" { addr = argv[i]; }
        else if a == "--port" || a == "--count" {
            let v, ok = parse_int(argv[i]);
            if !ok || v < 0 { usage(); }
            if a == "--port" { port = v; } else { count = v; }
        }
        else { usage(); }
        i++;
    }
    if keytab.len == 0 { usage(); }
    let kt, kerr = krb5::keytab_load(keytab);
    if kerr != krb5::OK { write_stderr(str("negotiate_server: ", keytab, ": ", krb5::error_text(kerr), "\n")); exit(1); }
    for e in kt { print("key: ", krb5::principal_string(e.name, e.realm), " kvno ", e.kvno, " etype ", e.key.etype); }

    let fd = net::listen(addr, port);
    if fd < 0 { write_stderr("negotiate_server: cannot listen\n"); exit(1); }
    print("serving on ", addr, " port ", net::local_port(fd));
    flush_stdout();
    var rc: krb5::ReplayEntry[>..] = [];
    var total = 0;
    loop {
        let c = net::accept(fd, 1000);
        if c < 0 { continue; }
        total += serve_conn(c, kt, rc);
        net::close(c);
        if count > 0 && total >= count { break; }
    }
}
