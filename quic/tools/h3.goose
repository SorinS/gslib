// goose-h3: an HTTP/3 client over QUIC, for trying the package against
// real servers: a GET (or a POST of --data) of a https URL, the status and
// headers to stderr, the body to stdout.
//
//   goose-h3 [-k] [--ca roots.pem] [--data BODY] [--alpn h3] [--header 'name: value']... URL
//
// The server's certificate is checked against the system's roots, or
// --ca's, unless -k. One line of the connection's progress goes to stderr
// with -v.

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.x509.pool;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.quic;
import gslib.quic.conn;
import gslib.quic.transport;
import gslib.quic.qpack;
import gslib.quic.h3;
import gslib.quic.http3;

fn die(msg: const u8[:]) {
    write_stderr("goose-h3: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

// https://host[:port]/path into its parts.
fn split_url(url: const u8[:]) -> const u8[:], i64, const u8[:], bool {
    if url.len < 9 || url[..8] != "https://" { return "", 0, "", false; }
    let rest = url[8..];
    let slash = find(rest, "/");
    let hostport = if slash >= 0 { rest[..slash] } else { rest };
    let path = if slash >= 0 { rest[slash..] } else { rest[rest.len..] };      // empty: "/"

    var host = hostport;
    var port: i64 = 443;
    let colon = rfind(hostport, ":");
    if colon > 0 && hostport[hostport.len - 1] != ']' {
        let p, ok = parse_int(hostport[colon + 1..]);
        if !ok || p <= 0 || p > 65535 { return "", 0, "", false; }
        host = hostport[..colon];
        port = p;
    }
    if host.len >= 2 && host[0] == '[' { host = host[1..host.len - 1]; }
    return host, port, path, host.len > 0;
}

fn main() {
    let a = args();
    var insecure = false;
    var verbose = false;
    var ca: u8[>..] = [];
    var data: u8[>..] = [];
    var post = false;
    var alpn: u8[>..] = [];
    alpn.append("h3");
    var hdrs: u8[>..] = [];
    var url: u8[>..] = [];
    var i = 1;
    while i < a.len {
        let x = a[i];
        if x == "-k" { insecure = true; }
        else if x == "-v" { verbose = true; }
        else if x == "--ca" && i + 1 < a.len { i++; ca.append(a[i]); }
        else if x == "--data" && i + 1 < a.len { i++; data.append(a[i]); post = true; }
        else if x == "--alpn" && i + 1 < a.len { i++; alpn.clear(); alpn.append(a[i]); }
        else if x == "--header" && i + 1 < a.len {
            i++;
            let colon = find(a[i], ":");
            if colon <= 0 { die("a header is 'name: value'"); }
            var name: u8[>..] = [];
            for ch in a[i][..colon] { name.push(if ch >= 'A' && ch <= 'Z' { ch + 32 } else { ch }); }
            quic::qpack_record(hdrs, name, trim(a[i][colon + 1..]));
        }
        else if url.len == 0 && x.len > 0 && x[0] != '-' { url.append(x); }
        else { die("usage: goose-h3 [-k] [-v] [--ca roots.pem] [--data BODY] [--alpn h3] [--header 'name: value']... URL"); }
        i++;
    }
    let host, port, path, ok = split_url(url);
    if !ok { die("an https:// URL is needed"); }
    var cfg = tls::client_config(host, "");
    if ca.len > 0 {
        var text: u8[>..] = [];
        if !read_file(ca, text) { die("cannot read --ca"); }
        let ders, okp = asn1::pem_decode(text, "CERTIFICATE");
        var roots: u8[>..] = [];
        for d in ders { roots.append(d); }
        cfg = tls::client_config(host, roots);
    } else {
        let pool, okr = x509::system_roots();
        cfg = tls::client_config_pool(host, pool);
    }
    cfg.verify = !insecure;
    tls::add_alpn(cfg.alpn, alpn);
    var c, fd, e = quic::dial(host, port, cfg, 10000);
    if e != 0 {
        var m: u8[>..] = [];
        m.append("no connection: ");
        if e == quic::ERR_CLOSED {
            let code, app, reason = quic::close_error(c);
            m.append(quic::error_name(code));
            m.push(' ');
            m.append(reason);
        } else { format(m, e); }
        die(m);
    }
    if verbose { write_stderr("goose-h3: connected, ALPN "); write_stderr(quic::alpn(c)); write_stderr("\n"); }
    var h = quic::h3(false);
    var authority: u8[>..] = [];
    authority.append(host);
    if port != 443 { authority.push(':'); format(authority, port); }
    var p: u8[>..] = [];
    p.append(if path.len > 0 { path } else { "/" });
    let id = quic::h3_send_request(c, h, if post { "POST" } else { "GET" }, "https", authority, p, hdrs, data);
    if id < 0 { die("the request does not go out"); }
    var body: u8[>..] = [];
    let deadline = quic::now_us() + 30000000;
    while !quic::h3_done(h, id) {
        if quic::step(fd, c, cfg, 50) != 0 { break; }
        quic::h3_poll(c, h);
        quic::h3_take_body(h, id, body);
        if body.len > 0 { write_stdout(body); body.clear(); }
        if quic::now_us() > deadline { die("no answer within 30 s"); }
    }
    quic::h3_take_body(h, id, body);
    write_stdout(body);
    if !quic::h3_done(h, id) || quic::h3_error(h, id) != 0 || quic::h3_status(h, id) == 0 {
        let code, app, reason = quic::close_error(c);
        var m: u8[>..] = [];
        m.append("the request failed: ");
        m.append(quic::h3_error_text(quic::h3_error(h, id)));
        m.push(' ');
        m.append(reason);
        die(m);
    }
    var line: u8[>..] = [];
    line.append("goose-h3: ");
    format(line, quic::h3_status(h, id));
    line.push('\n');
    let hh = quic::h3_headers(h, id);
    quic::each_qpack_field(hh) { name, value, never =>
        line.append("  ");
        line.append(name);
        line.append(": ");
        line.append(value);
        line.push('\n');
    };
    write_stderr(line);
    quic::hang_up(fd, c, 0x100, "");
    exit(if quic::h3_status(h, id) < 400 { 0 } else { 1 });
}
