// goose-scep: certificates from a SCEP server (RFC 8894), on gslib's scep,
// and a test CA that answers SCEP:
//
//   goose-scep --url URL [options] caps
//   goose-scep --url URL [options] getca [--out FILE]
//   goose-scep --url URL [options] enroll --key FILE --subject DN [--dns NAME ...] --out FILE
//   goose-scep --url URL [options] renew --key FILE --cert FILE --new-key FILE [--subject DN] --out FILE
//   goose-scep --url URL [options] getcert --key FILE --cert FILE [--out FILE]
//   goose-scep --url URL [options] getcrl --key FILE --cert FILE [--out FILE]
//   goose-scep serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--pending N] [--legacy]
//
// enroll makes the key (RSA 2048, PKCS #8 PEM, mode 0600) when --key's
// file is not there, signs the request with a self-signed certificate for
// it, and waits while the CA answers PENDING (--poll-interval, --poll-timeout,
// seconds). The challengePassword is read from the environment's
// SCEP_CHALLENGE, never from the command line, and never printed. renew
// signs a RenewalReq with --cert and --key for a CSR by --new-key (made if
// missing). getcert fetches --cert again by its issuer and serial; getcrl
// the CA's CRL; both sign with --key and --cert. Options:
//
//   --label NAME      GetCACert's message: which CA, for servers with several
//   --ca-file FILE    trust these PEM roots for an https URL, not the system's
//   --legacy          DES-EDE3 and SHA-1 to a server with nothing newer, and
//                     replies signed with SHA-1 or encrypted with DES taken
//   --aes256          AES-256-CBC in place of AES-128-CBC
//   --get             PKIOperation by GET even if the server takes POST
//
// serve answers SCEP on 127.0.0.1 (--port 0: any; the first line on stdout
// is "listening on ADDR:PORT"), as gslib's scep::Server: the
// challengePassword from SCEP_CHALLENGE (none asked if unset), each request
// held through --pending CertPolls, DES and SHA-1 taken with --legacy. One
// line a request goes to stderr.
//
// Exit status 0 on success, 1 on failure, 2 on a usage error.
import std;
import os;
import gslib from "../..";
import gslib.scep;
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
import gslib.dns;
import gslib.dns.server;
import gslib.krb5.sys;

struct Options {
    url:           u8[..1024] = [],
    label:         u8[..256]  = [],
    ca_file:       u8[..512]  = [],
    legacy:        bool       = false,
    aes256:        bool       = false,
    get:           bool       = false,
    key:           u8[..512]  = [],
    cert:          u8[..512]  = [],
    new_key:       u8[..512]  = [],
    subject:       u8[..1024] = [],
    dns:           u8[..4096] = [],    // one a line
    out:           u8[..512]  = [],
    poll_interval: i64        = 5,
    poll_timeout:  i64        = 300,
    ca_cert:       u8[..512]  = [],
    ca_key:        u8[..512]  = [],
    listen:        u8[..64]   = [],
    port:          i64        = 0,
    pending:       i64        = 0,
}

fn usage() -> i32 {
    write_stderr("usage: goose-scep --url URL [--label NAME] [--ca-file FILE] [--legacy] [--aes256] [--get] caps | getca [--out FILE] | enroll --key FILE --subject DN [--dns NAME ...] --out FILE | renew --key FILE --cert FILE --new-key FILE --out FILE | getcert --key FILE --cert FILE | getcrl --key FILE --cert FILE\n       goose-scep serve --ca-cert FILE --ca-key FILE [--listen ADDR] [--port N] [--pending N] [--legacy]\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-scep: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str(s, "\n")); }

fn why(c: const scep::Client&, e: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(scep::error_text(e));
    if e == scep::ERR_HTTP { out.append(": "); out.append(http::client_error_text(c.http_err)); }
    if e == scep::ERR_STATUS { out.append(": HTTP "); format(out, c.status); }
    if e == scep::ERR_FAILURE {
        out.append(": ");
        let n = scep::fail_name(c.fail_info);
        if n.len > 0 { out.append(n); } else { out.append("no failInfo"); }
        if c.fail_text.len > 0 { out.append(" ("); out.append(c.fail_text); out.push(')'); }
    }
    return out;
}

fn write_private(path: const u8[:], data: const u8[:]) -> bool { krb5::krb5sys_write_private(path, data) == 0 }

// The key in a PEM file, or a new RSA 2048 key written there (0600).
fn load_or_make_key(path: const u8[:]) -> x509::PrivateKey, bool {
    var text: u8[>..] = [];
    if read_file(path, text) {
        let k, ok = x509::parse_private_key_pem(text);
        return k, ok;
    }
    let k = x509::generate_key(x509::KEY_RSA, 2048);
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "PRIVATE KEY", x509::marshal_pkcs8(k));
    if !write_private(path, pem) { return k, false; }
    say(str("made a new key in ", path));
    return k, true;
}

fn load_key(path: const u8[:]) -> x509::PrivateKey, bool {
    var text: u8[>..] = [];
    if !read_file(path, text) { return x509::empty_key(), false; }
    let k, ok = x509::parse_private_key_pem(text);
    return k, ok;
}

// The certificates of a PEM file, DER laid end to end.
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

fn challenge() -> u8[>..] {
    var pw: u8[>..] = [];
    env("SCEP_CHALLENGE", pw);
    return pw;
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
    var c = scep::Client { .. };
    if scep::set_url(c, o.url) != scep::OK { return fail("--url must be a URL without a query"); }
    c.label.append(o.label);
    c.legacy = o.legacy;
    c.aes256 = o.aes256;
    c.poll_ms = o.poll_interval * 1000;
    c.poll_timeout_ms = o.poll_timeout * 1000;
    let ce = scep::get_caps(c, hc);
    if ce != scep::OK { return fail(str("GetCACaps: ", why(c, ce))); }
    if o.get { c.caps.post = false; }
    if command == "caps" {
        var line: u8[>..] = [];
        let k = c.caps;
        if k.aes { line.append("AES\n"); }
        if k.des3 { line.append("DES3\n"); }
        if k.get_next_ca { line.append("GetNextCACert\n"); }
        if k.post { line.append("POSTPKIOperation\n"); }
        if k.renewal { line.append("Renewal\n"); }
        if k.sha1 { line.append("SHA-1\n"); }
        if k.sha256 { line.append("SHA-256\n"); }
        if k.sha512 { line.append("SHA-512\n"); }
        if k.scep_standard { line.append("SCEPStandard\n"); }
        if k.update { line.append("Update\n"); }
        write_stdout(line);
        return 0;
    }
    let ge = scep::get_ca_cert(c, hc);
    if ge != scep::OK { return fail(str("GetCACert: ", why(c, ge))); }
    if command == "getca" { return write_out(o.out, pem_certs(c.ca_certs)); }

    if command == "enroll" {
        if o.key.len == 0 || o.subject.len == 0 || o.out.len == 0 { return usage(); }
        let k, kok = load_or_make_key(o.key);
        if !kok || k.kind != x509::KEY_RSA { return fail(str("cannot read or make an RSA key in ", o.key)); }
        let subject, sok = x509::name_der(o.subject);
        if !sok { return fail("--subject is not a DN this can encode"); }
        var san: u8[..4096] = [];
        for n in split(o.dns, '\n') { if n.len > 0 { x509::add_dns(san, n); } }
        let csr, e = scep::make_csr(subject, san, k, challenge());
        if e != scep::OK { return fail("cannot make the CSR"); }
        let signer, se = scep::self_signed(csr, k);
        if se != scep::OK { return fail("cannot make the self-signed certificate"); }
        let certs, err = scep::enroll(c, hc, csr, k, signer, false);
        if err != scep::OK { return fail(why(c, err)); }
        say(str("issued (transaction ", c.transaction_id, ")"));
        return write_out(o.out, pem_certs(certs));
    }
    if command == "renew" {
        if o.key.len == 0 || o.cert.len == 0 || o.new_key.len == 0 || o.out.len == 0 { return usage(); }
        let k, kok = load_key(o.key);
        if !kok { return fail(str("cannot read the key in ", o.key)); }
        let old = scep::first_cert(load_certs(o.cert));
        let oc, oe = x509::parse(old);
        if oe != x509::OK { return fail(str("no certificate in ", o.cert)); }
        let nk, nok = load_or_make_key(o.new_key);
        if !nok || nk.kind != x509::KEY_RSA { return fail(str("cannot read or make an RSA key in ", o.new_key)); }
        var subject: u8[>..] = [];
        if o.subject.len > 0 {
            let s, sok = x509::name_der(o.subject);
            if !sok { return fail("--subject is not a DN this can encode"); }
            subject.append(s);
        } else {
            subject.append(oc.der[oc.subject.start..oc.subject.end]);
        }
        var san: u8[..4096] = [];
        if oc.has_san && oc.san.end - oc.san.off <= 4096 { san.append(oc.der[oc.san.off..oc.san.end]); }
        for n in split(o.dns, '\n') { if n.len > 0 { x509::add_dns(san, n); } }
        let csr, e = scep::make_csr(subject, san, nk, challenge());
        if e != scep::OK { return fail("cannot make the CSR"); }
        if !c.caps.renewal && !c.caps.update { say("the server does not list Renewal: trying anyway"); }
        let certs, err = scep::enroll(c, hc, csr, k, old, true);
        if err != scep::OK { return fail(why(c, err)); }
        say(str("renewed (transaction ", c.transaction_id, ")"));
        return write_out(o.out, pem_certs(certs));
    }
    if command == "getcert" || command == "getcrl" {
        if o.key.len == 0 || o.cert.len == 0 { return usage(); }
        let k, kok = load_key(o.key);
        if !kok { return fail(str("cannot read the key in ", o.key)); }
        let mine = scep::first_cert(load_certs(o.cert));
        if mine.len == 0 { return fail(str("no certificate in ", o.cert)); }
        if command == "getcert" {
            let certs, err = scep::get_cert(c, hc, mine, k, mine);
            if err != scep::OK { return fail(why(c, err)); }
            return write_out(o.out, pem_certs(certs));
        }
        let crls, err = scep::get_crl(c, hc, mine, k, mine);
        if err != scep::OK { return fail(why(c, err)); }
        var pem: u8[>..] = [];
        var at = 0;
        while at < crls.len {
            let t, ok = asn1::read(crls, at, crls.len);
            if !ok { break; }
            asn1::pem_encode(pem, "X509 CRL", crls[t.start..t.end]);
            at = t.end;
        }
        return write_out(o.out, pem);
    }
    return usage();
}

// --- The test CA ------------------------------------------------------------------

// Reads one request from fd: its method, target and body; false if the
// connection failed or the request was not HTTP (an answer is sent then).
fn read_request(fd: i64, method: u8[>..]&, target: u8[>..]&, body: u8[>..]&) -> bool {
    var opt = http::server_options();
    opt.max_body = 1 << 20;
    var hc = http::server_conn(opt);
    var buf:     u8[>..]   = [];
    var trailer: u8[>..]   = [];
    var out:     u8[>..]   = [];
    var chunk:   u8[16384] = [0; 16384];
    var got_head = false;
    loop {
        loop {
            let ev, h = http::server_read(hc, buf, body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                method.clear();
                method.append(buf[h.method.pos..h.method.end]);
                target.clear();
                target.append(buf[h.target.pos..h.target.end]);
                got_head = true;
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf = copy(rest);
            if out.len > 0 { net::write(fd, out, 5000); out.clear(); }
            if ev.kind == http::EV_ERROR || ev.kind == http::EV_CLOSED { return false; }
            if got_head && http::request_complete(hc) { return true; }
            if ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT { break; }
        }
        let n = net::read(fd, chunk, 10000);
        if n <= 0 { return false; }
        buf.append(chunk[..n]);
    }
    return false;
}

fn respond(fd: i64, a: const scep::Answer&) {
    var out: u8[>..] = [];
    out.append("HTTP/1.1 ");
    format(out, a.status);
    out.append(if a.status == 200 { " OK" } else if a.status == 404 { " Not Found" } else if a.status == 400 { " Bad Request" } else { " Error" });
    out.append("\r\nContent-Type: ");
    out.append(a.content_type);
    out.append("\r\nContent-Length: ");
    format(out, a.body.len);
    out.append("\r\nConnection: close\r\n\r\n");
    out.append(a.body);
    net::write(fd, out, 10000);
}

fn serve(o: const Options&) -> i32 {
    if o.ca_cert.len == 0 || o.ca_key.len == 0 { return usage(); }
    var s = scep::Server { .. };
    let k, kok = load_key(o.ca_key);
    if !kok || k.kind != x509::KEY_RSA { return fail("--ca-key must be an RSA key in PEM"); }
    s.ca_key = k;
    s.ca_cert = scep::first_cert(load_certs(o.ca_cert));
    if s.ca_cert.len == 0 { return fail(str("no certificate in ", o.ca_cert)); }
    s.challenge = challenge();
    s.pending = o.pending;
    s.legacy = o.legacy;
    let addr = if o.listen.len > 0 { o.listen[..] } else { "127.0.0.1" };
    let lfd = dns::dnsnet_listen(addr, o.port as! i32, 1);
    if lfd < 0 { return fail("cannot listen"); }
    print("listening on ", addr, ":", dns::dnsnet_local_port(lfd));
    flush_stdout();
    var method: u8[>..] = [];
    var target: u8[>..] = [];
    var body:   u8[>..] = [];
    loop {
        let fd = dns::dnsnet_accept(lfd, 1000);
        if fd < 0 { continue; }
        body.clear();
        if read_request(fd, method, target, body) {
            s.log.clear();
            let a = scep::serve(s, method, target, body, time_ns() / 1000000000);
            respond(fd, a);
            var line: u8[>..] = [];
            line.append(method);
            line.push(' ');
            // The query's message is long and says nothing to the operator.
            let q = position(target, '&');
            line.append(if q > 0 { target[..q] } else { target[..] });
            line.push(' ');
            format(line, a.status);
            if s.log.len > 0 { line.append(": "); line.append(trim(s.log)); }
            say(line);
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
        if s == "--legacy" { o.legacy = true; }
        else if s == "--aes256" { o.aes256 = true; }
        else if s == "--get" { o.get = true; }
        else if s == "caps" || s == "getca" || s == "enroll" || s == "renew" || s == "getcert" || s == "getcrl" || s == "serve" {
            command.clear();
            command.append(s);
        }
        else if !has_value { return usage(); }
        else {
            i++;
            let v = a[i];
            if s == "--url" && v.len <= 1024 { o.url.append(v); }
            else if s == "--label" && v.len <= 256 { o.label.append(v); }
            else if s == "--ca-file" && v.len <= 512 { o.ca_file.append(v); }
            else if s == "--key" && v.len <= 512 { o.key.append(v); }
            else if s == "--cert" && v.len <= 512 { o.cert.append(v); }
            else if s == "--new-key" && v.len <= 512 { o.new_key.append(v); }
            else if s == "--subject" && v.len <= 1024 { o.subject.append(v); }
            else if s == "--dns" && o.dns.len + v.len + 1 <= 4096 && position(v, '\n') < 0 { o.dns.append(v); o.dns.push('\n'); }
            else if s == "--out" && v.len <= 512 { o.out.append(v); }
            else if s == "--poll-interval" { let n, ok = parse_int(v); if !ok || n < 0 || n > 3600 { return usage(); } o.poll_interval = n; }
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
    if o.url.len == 0 { return usage(); }
    return client_cmd(command, o);
}

fn main() { exit(run()); }
