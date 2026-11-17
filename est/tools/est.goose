// goose-est: certificates from an EST server (RFC 7030, RFC 8951), on
// gslib's est, and a test CA that answers EST over TLS:
//
//   goose-est --server URL [options] cacerts [--out FILE]
//   goose-est --server URL [options] csrattrs
//   goose-est --server URL [options] enroll --key FILE --subject DN [--dns NAME ...] --out FILE
//   goose-est --server URL [options] reenroll --cert FILE --key FILE [--new-key FILE] --out FILE
//   goose-est --server URL [options] serverkeygen --subject DN [--dns NAME ...] --out FILE --key-out FILE
//   goose-est serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--user NAME] [--pending N] [--csrattrs-example]
//
// The server's certificate is checked against --ca-file's PEM roots (the
// explicit trust anchor of RFC 7030 §3.6.1), else the system's. Clients
// authenticate by --user (the password from the environment's
// EST_PASSWORD, sent as HTTP Basic when the server asks; never on the
// command line, never printed) or by a TLS client certificate:
// --tls-cert and --tls-key, which reenroll takes from --cert and --key.
// enroll makes the key (P-256, PKCS #8 PEM, mode 0600; --key-type rsa2048
// for RSA) when --key's file is not there, and asks again while the CA
// answers 202 (--poll-timeout seconds). serverkeygen writes the key the
// CA made to --key-out (0600). --label puts a CA's path segment after
// /.well-known/est/.
//
// serve answers EST over TLS on 127.0.0.1 (--port 0: any; the first line
// on stdout is "listening on ADDR:PORT") as gslib's est::Server, with a
// server certificate for localhost and 127.0.0.1 it issues itself from
// --ca-cert: Basic credentials --user and EST_PASSWORD when given, client
// certificates the CA issued, --pending 202s for each key, RFC 7030's
// example CsrAttrs with --csrattrs-example. One line a request on stderr.
//
// Exit status 0 on success, 1 on failure, 2 on a usage error.
import std;
import os;
import gslib from "../..";
import gslib.est;
import gslib.net;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.net.http.conn1;
import gslib.net.http.h1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;
import gslib.sys;

struct Options {
    server:        u8[..1024] = [],
    label:         u8[..256]  = [],
    ca_file:       u8[..512]  = [],
    user:          u8[..256]  = [],
    tls_cert:      u8[..512]  = [],
    tls_key:       u8[..512]  = [],
    key:           u8[..512]  = [],
    key_type:      u8[..16]   = [],
    cert:          u8[..512]  = [],
    new_key:       u8[..512]  = [],
    subject:       u8[..1024] = [],
    dns:           u8[..4096] = [],   // one a line
    out:           u8[..512]  = [],
    key_out:       u8[..512]  = [],
    poll_timeout:  i64        = 300,
    ca_cert:       u8[..512]  = [],
    ca_key:        u8[..512]  = [],
    listen:        u8[..64]   = [],
    port:          i64        = 0,
    pending:       i64        = 0,
    example_attrs: bool       = false,
}

fn usage() -> i32 {
    write_stderr("usage: goose-est --server URL [--label NAME] [--ca-file FILE] [--user NAME] [--tls-cert FILE --tls-key FILE] cacerts [--out FILE] | csrattrs | enroll --key FILE --subject DN [--dns NAME ...] --out FILE | reenroll --cert FILE --key FILE [--new-key FILE] --out FILE | serverkeygen --subject DN --out FILE --key-out FILE\n       goose-est serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--user NAME] [--pending N] [--csrattrs-example]\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-est: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str(s, "\n")); }

fn why(c: const est::Client&, e: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(est::error_text(e));
    if e == est::ERR_HTTP { out.append(": "); out.append(http::client_error_text(c.http_err)); }
    if e == est::ERR_STATUS || e == est::ERR_AUTH {
        out.append(": HTTP ");
        format(out, c.status);
        let d = trim(c.detail);
        if d.len > 0 { out.append(" ("); out.append(d[..min(d.len, 200)]); out.push(')'); }
    }
    return out;
}

fn write_private(path: const u8[:], data: const u8[:]) -> bool { sys::write_private(path, data) == 0 }

fn load_key(path: const u8[:]) -> x509::PrivateKey, bool {
    var text: u8[>..] = [];
    if !read_file(path, text) { return x509::empty_key(), false; }
    let k, ok = x509::parse_private_key_pem(text);
    return k, ok;
}

fn load_or_make_key(path: const u8[:], kind: const u8[:]) -> x509::PrivateKey, bool {
    var text: u8[>..] = [];
    if read_file(path, text) {
        let k, ok = x509::parse_private_key_pem(text);
        return k, ok;
    }
    let k = if kind == "rsa2048" { x509::generate_key(x509::KEY_RSA, 2048) } else { x509::generate_key(x509::KEY_EC_P256) };
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(k));
    if !write_private(path, pem) { return k, false; }
    say(str("made a new key in ", path));
    return k, true;
}

fn load_certs(path: const u8[:]) -> u8[>..] {
    var out:  u8[>..] = [];
    var text: u8[>..] = [];
    if !read_file(path, text) { return out; }
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    for d in ders { out.append(d); }
    return out;
}

fn pem_certs(der: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var at = 0;
    while at < der.len {
        let t, ok = asn1::read(der, at, der.len);
        if !ok { break; }
        asn1::pem_encode(out, "CERTIFICATE", der[t.start..t.end]);
        at = t.end;
    }
    return out;
}

fn write_out(path: const u8[:], data: const u8[:]) -> i32 {
    if path.len == 0 { write_stdout(data); return 0; }
    if !write_file(path, data) { return fail(str("cannot write ", path)); }
    say(str("wrote ", path));
    return 0;
}

fn make_csr(subject_text: const u8[:], dns: const u8[:], k: const x509::PrivateKey&) -> u8[>..], bool {
    var none: u8[>..] = [];
    let subject, sok = x509::name_der(subject_text);
    if !sok { return none, false; }
    var san: u8[..4096] = [];
    for n in split(dns, '\n') { if n.len > 0 { x509::add_dns(san, n); } }
    let csr, e = x509::create_csr(subject, san, k);
    return csr, e == x509::OK;
}

// --- The client -------------------------------------------------------------------

fn client_cmd(command: const u8[:], o: const Options&) -> i32 {
    var hc = http::Client { .. };
    if o.ca_file.len > 0 {
        var text: u8[>..] = [];
        if !read_file(o.ca_file, text) { return fail(str("cannot read ", o.ca_file)); }
        var pool = x509::new_pool();
        if x509::pool_append_pem(pool, text) <= 0 { return fail(str("no certificates in ", o.ca_file)); }
        hc.tlscfg = tls::client_config_pool("", pool);
    }
    // The TLS client certificate: reenroll's --cert and --key, else --tls-cert and --tls-key.
    let tcert = if command == "reenroll" { o.cert[..] } else { o.tls_cert[..] };
    let tkey = if command == "reenroll" { o.key[..] } else { o.tls_key[..] };
    if tcert.len > 0 || tkey.len > 0 {
        let k, kok = load_key(tkey);
        let chain = load_certs(tcert);
        if !kok || chain.len == 0 { return fail("cannot read the TLS client certificate or its key"); }
        if !tls::set_client_certificate(hc.tlscfg, chain, x509::marshal_pkcs8(k)) { return fail("the TLS client certificate does not load"); }
    }
    if o.user.len > 0 {
        var pw: u8[>..] = [];
        if !env("EST_PASSWORD", pw) { return fail("--user needs the password in EST_PASSWORD"); }
        http::set_credentials(hc, o.user, pw);
    }
    var c = est::Client { .. };
    if est::set_server(c, o.server) != est::OK { return fail("--server must be a URL without a path"); }
    if est::set_label(c, o.label) != est::OK { return fail("--label must be one path segment"); }
    c.poll_timeout_ms = o.poll_timeout * 1000;

    if command == "cacerts" {
        let certs, e = est::cacerts(c, hc);
        if e != est::OK { return fail(str("cacerts: ", why(c, e))); }
        return write_out(o.out, pem_certs(certs));
    }
    if command == "csrattrs" {
        let a, e = est::csrattrs(c, hc);
        if e != est::OK { return fail(str("csrattrs: ", why(c, e))); }
        write_stdout(a.items);
        return 0;
    }
    if command == "enroll" {
        if o.key.len == 0 || o.subject.len == 0 || o.out.len == 0 { return usage(); }
        let k, kok = load_or_make_key(o.key, o.key_type);
        if !kok { return fail(str("cannot read or make a key in ", o.key)); }
        let csr, ok = make_csr(o.subject, o.dns, k);
        if !ok { return fail("cannot make the CSR (is --subject a DN?)"); }
        let certs, e = est::enroll(c, hc, csr, false);
        if e != est::OK { return fail(str("simpleenroll: ", why(c, e))); }
        return write_out(o.out, pem_certs(certs));
    }
    if command == "reenroll" {
        if o.key.len == 0 || o.cert.len == 0 || o.out.len == 0 { return usage(); }
        let old = est::first_cert(load_certs(o.cert));
        let oc, oe = x509::parse(old);
        if oe != x509::OK { return fail(str("no certificate in ", o.cert)); }
        var k = x509::empty_key();
        if o.new_key.len > 0 {
            let nk, nok = load_or_make_key(o.new_key, o.key_type);
            if !nok { return fail(str("cannot read or make a key in ", o.new_key)); }
            k = nk;
        } else {
            let ok2, okk = load_key(o.key);
            k = ok2;
        }
        // The same subject and SAN as the certificate renewed (§4.2.2).
        var san: u8[..4096] = [];
        if oc.has_san && oc.san.end - oc.san.off <= 4096 { san.append(oc.der[oc.san.off..oc.san.end]); }
        let csr, ce = x509::create_csr(oc.der[oc.subject.start..oc.subject.end], san, k);
        if ce != x509::OK { return fail("cannot make the CSR"); }
        let certs, e = est::enroll(c, hc, csr, true);
        if e != est::OK { return fail(str("simplereenroll: ", why(c, e))); }
        return write_out(o.out, pem_certs(certs));
    }
    if command == "serverkeygen" {
        if o.subject.len == 0 || o.out.len == 0 || o.key_out.len == 0 { return usage(); }
        // The CSR only names the subject; any key of ours signs it.
        let k = x509::generate_key(x509::KEY_EC_P256);
        let csr, ok = make_csr(o.subject, o.dns, k);
        if !ok { return fail("cannot make the CSR (is --subject a DN?)"); }
        let key, certs, e = est::server_keygen(c, hc, csr);
        if e != est::OK { return fail(str("serverkeygen: ", why(c, e))); }
        var pem: u8[>..] = [];
        asn1::pem_encode(pem, "PRIVATE KEY", key);
        if !write_private(o.key_out, pem) { return fail(str("cannot write ", o.key_out)); }
        say(str("wrote the key the CA made to ", o.key_out));
        return write_out(o.out, pem_certs(certs));
    }
    return usage();
}

// --- The test CA ------------------------------------------------------------------

// Reads one request from a TLS connection: method, target, the header
// fields as "Name: value\r\n" lines, and the body. False if the
// connection or its handshake failed, or the request was not HTTP.
fn read_request(fd: i64, tc: tls::Conn&, scfg: const tls::ServerConfig&, method: u8[>..]&, target: u8[>..]&,
                fields: u8[>..]&, body: u8[>..]&) -> bool {
    var opt = http::server_options();
    opt.max_body = 1 << 20;
    var hc = http::server_conn(opt);
    var buf:     u8[>..]   = [];
    var trailer: u8[>..]   = [];
    var out:     u8[>..]   = [];
    var wire:    u8[>..]   = [];
    var chunk:   u8[16384] = [0; 16384];
    var got_head = false;
    loop {
        let n = net::read(fd, chunk, 10000);
        if n <= 0 { return false; }
        let r = tls::server_feed(tc, scfg, chunk[..n], wire, buf);
        if wire.len > 0 { net::write(fd, wire, 5000); wire.clear(); }
        if r != 0 || tls::closed(tc) { return false; }
        if !tls::connected(tc) { continue; }
        loop {
            let ev, h = http::server_read(hc, buf, body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                method.clear();
                method.append(buf[h.method.pos..h.method.end]);
                target.clear();
                target.append(buf[h.target.pos..h.target.end]);
                fields.clear();
                for f in h.fields {
                    fields.append(buf[f.name.pos..f.name.end]);
                    fields.append(": ");
                    fields.append(buf[f.value.pos..f.value.end]);
                    fields.append("\r\n");
                }
                got_head = true;
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf = copy(rest);
            if out.len > 0 { tls::send(tc, out, wire); out.clear(); net::write(fd, wire, 5000); wire.clear(); }
            if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED { return false; }
            if got_head && http::request_complete(hc) { return true; }
            if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
        }
    }
    return false;
}

fn status_text(s: i64) -> const u8[:] {
    if s == 200 { return "OK"; }
    if s == 202 { return "Accepted"; }
    if s == 204 { return "No Content"; }
    if s == 400 { return "Bad Request"; }
    if s == 401 { return "Unauthorized"; }
    if s == 403 { return "Forbidden"; }
    if s == 404 { return "Not Found"; }
    if s == 415 { return "Unsupported Media Type"; }
    return "Error";
}

fn respond(fd: i64, tc: tls::Conn&, a: const est::Answer&) {
    var out: u8[>..] = [];
    out.append("HTTP/1.1 ");
    format(out, a.status);
    out.push(' ');
    out.append(status_text(a.status));
    out.append("\r\nContent-Type: ");
    out.append(a.content_type);
    out.append("\r\n");
    out.append(a.fields);
    out.append("Content-Length: ");
    format(out, a.body.len);
    out.append("\r\nConnection: close\r\n\r\n");
    out.append(a.body);
    var wire: u8[>..] = [];
    tls::send(tc, out, wire);
    tls::close(tc, wire);
    net::write(fd, wire, 10000);
}

// RFC 7030 §4.5.2's example CsrAttrs.
let EXAMPLE_ATTRS: const u8[:] = "MEEGCSqGSIb3DQEJBwYIKoZIzj0EAwMwFgYJKoZIhvcNAQkOMQkGBysGAQEBARYwEgYHKoZIzj0CATEHBgUrgQQAIg==";

fn serve(o: const Options&) -> i32 {
    if o.ca_cert.len == 0 || o.ca_key.len == 0 { return usage(); }
    var s = est::Server { .. };
    let k, kok = load_key(o.ca_key);
    if !kok { return fail("--ca-key must be a private key in PEM"); }
    s.ca_key = k;
    s.ca_cert = est::first_cert(load_certs(o.ca_cert));
    if s.ca_cert.len == 0 { return fail(str("no certificate in ", o.ca_cert)); }
    if o.user.len > 0 {
        s.user.append(o.user);
        if !env("EST_PASSWORD", s.password) { return fail("--user needs the password in EST_PASSWORD"); }
    }
    s.pending = o.pending;
    if o.example_attrs {
        let der, ok = est::decode_base64(EXAMPLE_ATTRS);
        s.attrs = copy(der);
    }
    // The server's own certificate, for localhost and 127.0.0.1.
    let sk = x509::generate_key(x509::KEY_EC_P256);
    let now = time_ns() / 1000000000;
    var t, okt = x509::template("CN=localhost", now - 300, now + 86400);
    x509::add_dns(t.san, "localhost");
    x509::add_ip(t.san, [127, 0, 0, 1]);
    t.basic_constraints = true;
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = x509::EKU_SERVER_AUTH;
    let scert, se = x509::create_certificate(t, x509::marshal_public_key(sk), s.ca_cert, s.ca_key);
    if se != x509::OK { return fail("cannot issue the server's certificate from --ca-cert"); }
    var chain: u8[>..] = [];
    chain.append(scert);
    chain.append(s.ca_cert);
    var scfg, ok = tls::server_config(chain, x509::marshal_pkcs8(sk));
    if !ok { return fail("the server's certificate does not load"); }
    tls::add_alpn(scfg.alpn, "http/1.1");
    scfg.client_auth = tls::VERIFY_CLIENT_CERT_IF_GIVEN;
    x509::pool_add(scfg.client_cas, s.ca_cert);

    let addr = if o.listen.len > 0 { o.listen[..] } else { "127.0.0.1" };
    let lfd = net::listen(addr, o.port);
    if lfd < 0 { return fail("cannot listen"); }
    print("listening on ", addr, ":", net::local_port(lfd));
    flush_stdout();
    var method: u8[>..] = [];
    var target: u8[>..] = [];
    var fields: u8[>..] = [];
    var body:   u8[>..] = [];
    loop {
        let fd = net::accept(lfd, 1000);
        if fd < 0 { continue; }
        var tc = tls::server(scfg);
        body.clear();
        if read_request(fd, tc, scfg, method, target, fields, body) {
            s.log.clear();
            let peer = tls::peer_certificates(tc);
            let a = est::serve(s, method, target, fields, body, peer, time_ns() / 1000000000);
            respond(fd, tc, a);
            var line: u8[>..] = [];
            line.append(method);
            line.push(' ');
            line.append(target);
            line.push(' ');
            format(line, a.status);
            if peer.len > 0 { line.append(" (client certificate)"); }
            if s.log.len > 0 { line.append(": "); line.append(trim(s.log)); }
            say(line);
        } else {
            say("a connection that failed, or was not HTTP over TLS");
        }
        net::close(fd);
    }
    return 0;
}

fn run() -> i32 {
    let a = args();
    var o = Options { .. };
    var command: u8[..16] = [];
    var i = 1;
    while i < a.len {
        let s = a[i];
        let has_value = i + 1 < a.len;
        if s == "--csrattrs-example" { o.example_attrs = true; }
        else if s == "cacerts" || s == "csrattrs" || s == "enroll" || s == "reenroll" || s == "serverkeygen" || s == "serve" {
            command.clear();
            command.append(s);
        }
        else if !has_value { return usage(); }
        else {
            i++;
            let v = a[i];
            if s == "--server" && v.len <= 1024 { o.server.append(v); }
            else if s == "--label" && v.len <= 256 { o.label.append(v); }
            else if s == "--ca-file" && v.len <= 512 { o.ca_file.append(v); }
            else if s == "--user" && v.len <= 256 { o.user.append(v); }
            else if s == "--tls-cert" && v.len <= 512 { o.tls_cert.append(v); }
            else if s == "--tls-key" && v.len <= 512 { o.tls_key.append(v); }
            else if s == "--key" && v.len <= 512 { o.key.append(v); }
            else if s == "--key-type" && (v == "ec256" || v == "rsa2048") { o.key_type.append(v); }
            else if s == "--cert" && v.len <= 512 { o.cert.append(v); }
            else if s == "--new-key" && v.len <= 512 { o.new_key.append(v); }
            else if s == "--subject" && v.len <= 1024 { o.subject.append(v); }
            else if s == "--dns" && o.dns.len + v.len + 1 <= 4096 && position(v, '\n') < 0 { o.dns.append(v); o.dns.push('\n'); }
            else if s == "--out" && v.len <= 512 { o.out.append(v); }
            else if s == "--key-out" && v.len <= 512 { o.key_out.append(v); }
            else if s == "--poll-timeout" { let n, ok = parse_int(v); if !ok || n < 0 || n > 86400 { return usage(); } o.poll_timeout = n; }
            else if s == "--ca-cert" && v.len <= 512 { o.ca_cert.append(v); }
            else if s == "--ca-key" && v.len <= 512 { o.ca_key.append(v); }
            else if s == "--listen" && v.len <= 64 { o.listen.append(v); }
            else if s == "--port" { let n, ok = parse_int(v); if !ok || n < 0 || n > 65535 { return usage(); } o.port = n; }
            else if s == "--pending" { let n, ok = parse_int(v); if !ok || n < 0 || n > 100 { return usage(); } o.pending = n; }
            else { return usage(); }
        }
        i++;
    }
    if command.len == 0 { return usage(); }
    if command == "serve" { return serve(o); }
    if o.server.len == 0 { return usage(); }
    return client_cmd(command, o);
}

fn main() { exit(run()); }
