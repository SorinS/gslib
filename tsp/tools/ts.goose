// goose-ts: RFC 3161 time-stamps, on gslib's tsp, as openssl ts makes and
// checks them, and a TSA:
//
//   goose-ts query   (--data FILE | --digest HEX) [--hash H] [--no-nonce] [--cert] [--policy OID] --out FILE
//   goose-ts request --url URL (--data FILE | --digest HEX | --queryfile FILE) [query options]
//                    [--out FILE] [--token-out FILE] [--ca-file FILE [--untrusted FILE]]
//   goose-ts verify  (--in REPLY | --token FILE) (--queryfile FILE | --data FILE | --digest HEX [--hash H])
//                    --ca-file FILE [--untrusted FILE] [--policy OID] [--sha1]
//   goose-ts reply   --queryfile FILE [TSA options] --out FILE
//   goose-ts serve   [--listen ADDR] --port N [--count N] [TSA options]
//   goose-ts show    (--in REPLY | --token FILE | --queryfile FILE)
//   goose-ts stamp   --in CMS --url URL --out FILE [--hash H] [--ca-file FILE [--untrusted FILE]]
//   goose-ts verify-stamp --in CMS --ca-file FILE [--untrusted FILE]
//
// H is sha256 (the default), sha384, sha512, or sha1 with --sha1. The TSA
// options are --signer FILE (its certificate, PEM), --key FILE (its key,
// PEM), --chain FILE (certificates to send with it), --policy OID (its
// policy; --other-policy OID for more it takes), --accuracy SECONDS,
// --accuracy-ms N, --precision DIGITS (of genTime's fraction), --ordering,
// --tsa-name, --serial-file FILE (hex, as openssl's: the next serial
// number, counted on; random 128-bit ones without it) and --sha1 (take
// SHA-1 imprints). `serve` answers POSTs of application/timestamp-query
// over HTTP/1.1 on ADDR (127.0.0.1) and PORT, one connection at a time,
// --count of them before it exits (0: forever). `stamp` time-stamps a CMS
// signature (DER or BER) and writes it with the token as an unsigned
// attribute (RFC 3161 Appendix A); `verify-stamp` checks that token.
//
// Nothing secret is printed. Exit status 0 on success, 1 on failure, 2 on a
// usage error.

import std;
import os;
import gslib from "../..";
import gslib.tsp;
import gslib.net;
import gslib.net.http;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.net.http.conn1;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;

struct Options {
    data:        u8[..512]  = [],
    digest:      u8[..256]  = [],
    hash:        i64        = tsp::SHA256,
    no_nonce:    bool       = false,
    cert:        bool       = false,
    policy:      u8[..128]  = [],
    others:      u8[..1024] = [],      // --other-policy, one a line
    out:         u8[..512]  = [],
    url:         u8[..2048] = [],
    queryfile:   u8[..512]  = [],
    token_out:   u8[..512]  = [],
    ca_file:     u8[..512]  = [],
    untrusted:   u8[..512]  = [],
    input:       u8[..512]  = [],
    token:       u8[..512]  = [],
    sha1:        bool       = false,
    signer:      u8[..512]  = [],
    key:         u8[..512]  = [],
    chain:       u8[..512]  = [],
    accuracy:    i64        = -1,
    accuracy_ms: i64        = -1,
    precision:   i64        = 0,
    ordering:    bool       = false,
    tsa_name:    bool       = false,
    serial_file: u8[..512]  = [],
    listen:      u8[..64]   = [],
    port:        i32        = -1,
    count:       i64        = 0,
}

fn usage() -> i32 {
    write_stderr("usage: goose-ts query|request|verify|reply|serve|show|stamp|verify-stamp [options] (see the comment at the top of tsp/tools/ts.goose)\n");
    return 2;
}

fn fail(s: const u8[:]) -> i32 {
    write_stderr(str("goose-ts: ", s, "\n"));
    return 1;
}

fn say(s: const u8[:]) { write_stderr(str(s, "\n")); }

fn why(e: i64, x: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(tsp::error_text(e));
    if x != 0 { out.append(" ("); out.append(x509::error_text(x)); out.push(')'); }
    return out;
}

fn read_all(path: const u8[:], out: u8[>..]&) -> bool { read_file(path, out) }

// The certificates in a PEM file, DER laid end to end.
fn pem_certs(path: const u8[:], out: u8[>..]&) -> bool {
    var text: u8[>..] = [];
    if !read_file(path, text) { return false; }
    let ders, ok = asn1::pem_decode(text, "CERTIFICATE");
    if !ok { return false; }
    for d in ders { out.append(d); }
    return ders.len > 0;
}

// The request the options describe: from --queryfile, or made from --data or --digest.
fn make_request(o: const Options&, der: u8[>..]&) -> tsp::Request, i64 {
    if o.queryfile.len > 0 {
        if !read_file(o.queryfile, der) { return tsp::Request { .. }, tsp::ERR_ARG; }
        let r, e = tsp::parse_request(der);
        return r, e;
    }
    var d: u8[>..] = [];
    if o.data.len > 0 {
        var data: u8[>..] = [];
        if !read_file(o.data, data) { return tsp::Request { .. }, tsp::ERR_ARG; }
        d = tsp::digest(o.hash, data);
    } else {
        let b, ok = tsp::unhex(o.digest);
        if !ok { return tsp::Request { .. }, tsp::ERR_ARG; }
        d = copy(b);
    }
    var r, e = tsp::request_for_digest(o.hash, d, o.cert, o.sha1);
    if e != tsp::OK { return r, e; }
    if o.no_nonce { r.nonce.clear(); }
    r.policy.append(o.policy);
    let q, qe = tsp::request_der(r);
    der.append(q);
    return r, qe;
}

// --- The TSA ---------------------------------------------------------------------------

fn serial_load(path: const u8[:]) -> i64 {
    var text: u8[>..] = [];
    if !read_file(path, text) { return 1; }
    let v, ok = parse_int(trim(text), 16);
    return if ok && v > 0 { v } else { -1 };
}

fn serial_save(path: const u8[:], next: i64) -> bool {
    var s: u8[>..] = [];
    format_int(s, next, 16, 2, '0');
    s.push('\n');
    return write_file_atomic(path, s);
}

fn tsa_setup(t: tsp::Tsa&, o: const Options&) -> i32 {
    if o.signer.len == 0 || o.key.len == 0 || o.policy.len == 0 { return usage(); }
    var cert: u8[>..] = [];
    if !pem_certs(o.signer, cert) { return fail(str("no certificate in ", o.signer)); }
    let first, okf = asn1::parse(cert);
    var keytext: u8[>..] = [];
    if !read_file(o.key, keytext) { return fail(str("cannot read ", o.key)); }
    let key, okk = x509::parse_private_key_pem(keytext);
    if !okk { return fail(str("no private key in ", o.key, " (an unencrypted PEM key is needed)")); }
    var chain: u8[>..] = [];
    if o.chain.len > 0 && !pem_certs(o.chain, chain) { return fail(str("no certificates in ", o.chain)); }
    let e = tsp::tsa_init(t, cert[first.start..first.end], key, chain, o.policy);
    if e != tsp::OK { return fail(str("cannot run a TSA: ", tsp::error_text(e))); }
    for p in split(o.others, '\n') {
        if p.len > 0 && tsp::tsa_add_policy(t, p) != tsp::OK { return fail(str("not a policy: ", p)); }
    }
    t.acc_seconds = o.accuracy;
    t.acc_millis = o.accuracy_ms;
    t.precision = o.precision;
    t.ordering = o.ordering;
    t.tsa_name = o.tsa_name;
    t.allow_sha1 = o.sha1;
    if o.serial_file.len > 0 {
        let s = serial_load(o.serial_file);
        if s < 0 { return fail(str("not a serial number in ", o.serial_file)); }
        t.next_serial = s;
    }
    return 0;
}

// One reply, the serial file brought up to date.
fn answer(t: tsp::Tsa&, o: const Options&, req: const u8[:]) -> u8[>..], i64 {
    let reply, status = tsp::respond(t, req, tsp::now_ns());
    if o.serial_file.len > 0 && status == tsp::GRANTED && !serial_save(o.serial_file, t.next_serial) {
        say(str("goose-ts: cannot write ", o.serial_file));
    }
    return reply, status;
}

// The HTTP answer to one request.
fn http_answer(hc: http::ServerConn&, t: tsp::Tsa&, o: const Options&, method: const u8[:], ctype: const u8[:],
               body: const u8[:], out: u8[>..]&) {
    var f: u8[>..] = [];
    if method != "POST" {
        http::add_field(f, "Allow", "POST");
        http::server_respond(hc, 405, f, 0, out);
        http::server_end(hc, "", out);
        return;
    }
    let semi = position(ctype, ';');
    let base = trim(if semi >= 0 { ctype[..semi] } else { ctype });
    if !http::eq_fold(base, "application/timestamp-query") {
        http::server_respond(hc, 415, f, 0, out);
        http::server_end(hc, "", out);
        return;
    }
    let reply, status = answer(t, o, body);
    say(str("goose-ts: ", tsp::status_name(status)));
    http::add_field(f, "Content-Type", "application/timestamp-reply");
    http::server_respond(hc, 200, f, reply.len, out);
    http::server_body(hc, reply, out);
    http::server_end(hc, "", out);
}

fn serve_conn(c: i64, t: tsp::Tsa&, o: const Options&) {
    var hc = http::server_conn(http::server_options());
    var raw:     u8[16384] = [0; 16384];
    var buf:     u8[>..]   = [];
    var out:     u8[>..]   = [];
    var body:    u8[>..]   = [];
    var trailer: u8[>..]   = [];
    var method:  u8[>..]   = [];
    var ctype:   u8[>..]   = [];
    loop {
        let n = net::read(c, raw, 10000);
        if n <= 0 { break; }
        buf.append(raw[..n]);
        var stop = false;
        loop {
            let ev, h = http::server_read(hc, buf, body, trailer, out);
            if ev.kind == http::EV_REQUEST {
                method.clear();
                method.append(buf[h.method.pos..h.method.end]);
                ctype.clear();
                let s, has = http::get(buf, h, "content-type");
                if has { ctype.append(buf[s.pos..s.end]); }
                body.clear();
                trailer.clear();
                if ev.continue_expected { http::server_continue(hc, out); }
            }
            if ev.kind == http::EV_ERROR { stop = true; }
            var rest: u8[>..] = [];
            rest.append(buf[ev.used..]);
            buf.clear();
            buf.append(rest);
            if (ev.kind == http::EV_REQUEST || ev.kind == http::EV_END) && http::request_complete(hc) {
                http_answer(hc, t, o, method, ctype, body, out);
                if http::closing(hc) { stop = true; }
            }
            if stop || ev.kind == http::EV_NEED_MORE || ev.kind == http::EV_WAIT || ev.kind == http::EV_ERROR ||
               ev.kind == http::EV_CLOSED { break; }
        }
        if out.len > 0 {
            if net::write(c, out, 10000) != out.len { break; }
            out.clear();
        }
        if stop || http::closing(hc) { break; }
    }
    net::close(c);
}

fn serve(t: tsp::Tsa&, o: const Options&) -> i32 {
    if o.port < 0 { return usage(); }
    let addr = if o.listen.len > 0 { o.listen[..] } else { "127.0.0.1" };
    let fd = net::listen(addr, o.port);
    if fd < 0 { return fail(str("cannot listen on ", addr, " port ", o.port)); }
    say(str("goose-ts: serving on ", addr, " port ", net::local_port(fd)));
    var served = 0;
    while o.count == 0 || served < o.count {
        let c = net::accept(fd, 1000);
        if c < 0 { continue; }
        serve_conn(c, t, o);
        served++;
    }
    net::close(fd);
    return 0;
}

// --- Checking --------------------------------------------------------------------------

fn roots_of(o: const Options&, roots: x509::CertPool&) -> bool {
    var text: u8[>..] = [];
    if !read_file(o.ca_file, text) { return false; }
    return x509::pool_append_pem(roots, text) > 0;
}

fn verify_options(o: const Options&) -> tsp::VerifyOptions {
    var v = tsp::VerifyOptions { allow_sha1: o.sha1, .. };
    if o.policy.len > 0 { v.policy.append(o.policy); }
    return v;
}

fn report(info: const tsp::TstInfo&, e: i64, x: i64) -> i32 {
    if e != tsp::OK { return fail(str("verification failed: ", why(e, x))); }
    write_stdout(tsp::info_text(info));
    print("Verification: OK");
    return 0;
}

fn verify(o: const Options&) -> i32 {
    if o.ca_file.len == 0 || (o.input.len == 0 && o.token.len == 0) { return usage(); }
    var roots = x509::new_pool();
    if !roots_of(o, roots) { return fail(str("no certificates in ", o.ca_file)); }
    var untrusted: u8[>..] = [];
    if o.untrusted.len > 0 && !pem_certs(o.untrusted, untrusted) { return fail(str("no certificates in ", o.untrusted)); }
    let vo = verify_options(o);
    var token: u8[>..] = [];
    if o.input.len > 0 {
        var der: u8[>..] = [];
        if !read_file(o.input, der) { return fail(str("cannot read ", o.input)); }
        let r, pe = tsp::parse_response(der);
        if pe != tsp::OK { return fail(str(o.input, ": not a time-stamp reply")); }
        if r.status != tsp::GRANTED && r.status != tsp::GRANTED_WITH_MODS {
            return fail(str("the TSA refused: ", tsp::status_name(r.status), " ", tsp::fail_info_text(r.fail_info), " ", r.status_text));
        }
        if o.queryfile.len > 0 {
            var q: u8[>..] = [];
            let req, qe = make_request(o, q);
            if qe != tsp::OK { return fail(str(o.queryfile, ": not a time-stamp query")); }
            let info, e, x = tsp::verify_reply(r, req, roots, untrusted, vo);
            return report(info, e, x);
        }
        token.append(r.token);
    } else if !read_file(o.token, token) {
        return fail(str("cannot read ", o.token));
    }
    var d: u8[>..] = [];
    var h = o.hash;
    if o.queryfile.len > 0 {
        var q: u8[>..] = [];
        let req, qe = make_request(o, q);
        if qe != tsp::OK { return fail(str(o.queryfile, ": not a time-stamp query")); }
        h = req.hash;
        d.append(req.imprint);
    } else if o.data.len > 0 {
        var data: u8[>..] = [];
        if !read_file(o.data, data) { return fail(str("cannot read ", o.data)); }
        // The hash the token was made with.
        let sd, info0, e0 = tsp::parse_token(token);
        if e0 != tsp::OK { return fail("not a time-stamp token"); }
        h = info0.hash;
        if tsp::hash_len(h) == 0 { return fail("the token's hash is not one this knows"); }
        d = tsp::digest(h, data);
    } else if o.digest.len > 0 {
        let b, ok = tsp::unhex(o.digest);
        if !ok { return usage(); }
        d.append(b);
    } else {
        return usage();
    }
    let info, e, x = tsp::verify_token(token, h, d, roots, untrusted, vo);
    return report(info, e, x);
}

fn show(o: const Options&) -> i32 {
    var der: u8[>..] = [];
    if o.queryfile.len > 0 {
        if !read_file(o.queryfile, der) { return fail(str("cannot read ", o.queryfile)); }
        let r, e = tsp::parse_request(der);
        if e != tsp::OK { return fail("not a time-stamp query"); }
        var s: u8[>..] = [];
        s.append("Version: 1\nHash Algorithm: "); s.append(tsp::hash_name(r.hash));
        s.append("\nMessage data: "); tsp::hex(s, r.imprint);
        s.append("\nPolicy OID: "); s.append(if r.policy.len > 0 { r.policy[..] } else { "unspecified" });
        s.append("\nNonce: "); if r.nonce.len > 0 { s.append("0x"); tsp::hex(s, r.nonce); } else { s.append("unspecified"); }
        s.append("\nCertificate required: "); s.append(if r.cert_req { "yes" } else { "no" });
        s.append("\nExtensions: "); s.append(if r.extensions { "yes" } else { "none" });
        print(s);
        return 0;
    }
    var token: u8[>..] = [];
    if o.input.len > 0 {
        if !read_file(o.input, der) { return fail(str("cannot read ", o.input)); }
        let r, e = tsp::parse_response(der);
        if e != tsp::OK { return fail("not a time-stamp reply"); }
        print("Status: ", tsp::status_name(r.status));
        if r.status_text.len > 0 { print("Status text: ", r.status_text); }
        if r.fail_info != 0 { print("Failure info: ", tsp::fail_info_text(r.fail_info)); }
        if r.token.len == 0 { return 0; }
        token.append(r.token);
    } else if o.token.len > 0 {
        if !read_file(o.token, token) { return fail(str("cannot read ", o.token)); }
    } else {
        return usage();
    }
    let sd, info, e = tsp::parse_token(token);
    if e != tsp::OK { return fail("not a time-stamp token"); }
    write_stdout(tsp::info_text(info));
    return 0;
}

// --- Asking a TSA -------------------------------------------------------------------------

fn request(o: const Options&) -> i32 {
    if o.url.len == 0 { return usage(); }
    var q: u8[>..] = [];
    let req, e = make_request(o, q);
    if e != tsp::OK { return fail(str("no request: ", tsp::error_text(e))); }
    var hc = http::Client { .. };
    let reply, he, hs = tsp::post(hc, o.url, q);
    if he != tsp::OK {
        return fail(str("no reply from ", o.url, ": ", if hs >= 100 { str("HTTP ", hs) } else { str(http::client_error_text(hs)) }));
    }
    if o.out.len > 0 && !write_file(o.out, reply) { return fail(str("cannot write ", o.out)); }
    let r, pe = tsp::parse_response(reply);
    if pe != tsp::OK { return fail("the reply is not a TimeStampResp"); }
    if r.status != tsp::GRANTED && r.status != tsp::GRANTED_WITH_MODS {
        return fail(str("the TSA refused: ", tsp::status_name(r.status), " ", tsp::fail_info_text(r.fail_info), " ", r.status_text));
    }
    if o.token_out.len > 0 && !write_file(o.token_out, r.token) { return fail(str("cannot write ", o.token_out)); }
    if o.ca_file.len == 0 {
        say("granted (not verified: no --ca-file)");
        return 0;
    }
    var roots = x509::new_pool();
    if !roots_of(o, roots) { return fail(str("no certificates in ", o.ca_file)); }
    var untrusted: u8[>..] = [];
    if o.untrusted.len > 0 && !pem_certs(o.untrusted, untrusted) { return fail(str("no certificates in ", o.untrusted)); }
    let vo = verify_options(o);
    let info, ve, x = tsp::verify_reply(r, req, roots, untrusted, vo);
    return report(info, ve, x);
}

// Appendix A: a CMS signature time-stamped.
fn stamp(o: const Options&) -> i32 {
    if o.input.len == 0 || o.url.len == 0 || o.out.len == 0 { return usage(); }
    var cms: u8[>..] = [];
    if !read_file(o.input, cms) { return fail(str("cannot read ", o.input)); }
    let req, e = tsp::signature_request(cms, o.hash, true);
    if e != tsp::OK { return fail(str(o.input, ": not a CMS signature with one signer")); }
    let q, qe = tsp::request_der(req);
    var hc = http::Client { .. };
    let reply, he, hs = tsp::post(hc, o.url, q);
    if he != tsp::OK { return fail(str("no reply from ", o.url)); }
    let r, pe = tsp::parse_response(reply);
    if pe != tsp::OK { return fail("the reply is not a TimeStampResp"); }
    if r.status != tsp::GRANTED && r.status != tsp::GRANTED_WITH_MODS {
        return fail(str("the TSA refused: ", tsp::fail_info_text(r.fail_info), " ", r.status_text));
    }
    if o.ca_file.len > 0 {
        var roots = x509::new_pool();
        if !roots_of(o, roots) { return fail(str("no certificates in ", o.ca_file)); }
        var untrusted: u8[>..] = [];
        if o.untrusted.len > 0 && !pem_certs(o.untrusted, untrusted) { return fail(str("no certificates in ", o.untrusted)); }
        let vo = verify_options(o);
        let info, ve, x = tsp::verify_reply(r, req, roots, untrusted, vo);
        if ve != tsp::OK { return fail(str("the token does not verify: ", why(ve, x))); }
    }
    let stamped, ae = tsp::add_signature_token(cms, r.token);
    if ae != tsp::OK { return fail(str("cannot add the token: ", tsp::error_text(ae))); }
    if !write_file(o.out, stamped) { return fail(str("cannot write ", o.out)); }
    say(str("time-stamped into ", o.out));
    return 0;
}

fn verify_stamp(o: const Options&) -> i32 {
    if o.input.len == 0 || o.ca_file.len == 0 { return usage(); }
    var cms: u8[>..] = [];
    if !read_file(o.input, cms) { return fail(str("cannot read ", o.input)); }
    var roots = x509::new_pool();
    if !roots_of(o, roots) { return fail(str("no certificates in ", o.ca_file)); }
    var untrusted: u8[>..] = [];
    if o.untrusted.len > 0 && !pem_certs(o.untrusted, untrusted) { return fail(str("no certificates in ", o.untrusted)); }
    let vo = verify_options(o);
    let info, e, x = tsp::verify_signature_token(cms, roots, untrusted, vo);
    return report(info, e, x);
}

// --- Arguments ----------------------------------------------------------------------------

fn run() -> i32 {
    let a = args();
    if a.len < 2 { return usage(); }
    let command = a[1];
    var o = Options { .. };
    var i = 2;
    while i < a.len {
        let s = a[i];
        if s == "--no-nonce" { o.no_nonce = true; }
        else if s == "--cert" { o.cert = true; }
        else if s == "--sha1" { o.sha1 = true; }
        else if s == "--ordering" { o.ordering = true; }
        else if s == "--tsa-name" { o.tsa_name = true; }
        else {
            i++;
            if i >= a.len { return usage(); }
            let v = a[i];
            if s == "--data" && v.len <= 512 { o.data.append(v); }
            else if s == "--digest" && v.len <= 256 { o.digest.append(v); }
            else if s == "--hash" { o.hash = tsp::hash_by_name(v); if o.hash == 0 { return usage(); } }
            else if s == "--policy" && v.len <= 128 { o.policy.append(v); }
            else if s == "--other-policy" && o.others.len + v.len + 1 <= 1024 && position(v, '\n') < 0 {
                o.others.append(v);
                o.others.push('\n');
            }
            else if s == "--out" && v.len <= 512 { o.out.append(v); }
            else if s == "--url" && v.len <= 2048 { o.url.append(v); }
            else if s == "--queryfile" && v.len <= 512 { o.queryfile.append(v); }
            else if s == "--token-out" && v.len <= 512 { o.token_out.append(v); }
            else if s == "--ca-file" && v.len <= 512 { o.ca_file.append(v); }
            else if s == "--untrusted" && v.len <= 512 { o.untrusted.append(v); }
            else if s == "--in" && v.len <= 512 { o.input.append(v); }
            else if s == "--token" && v.len <= 512 { o.token.append(v); }
            else if s == "--signer" && v.len <= 512 { o.signer.append(v); }
            else if s == "--key" && v.len <= 512 { o.key.append(v); }
            else if s == "--chain" && v.len <= 512 { o.chain.append(v); }
            else if s == "--serial-file" && v.len <= 512 { o.serial_file.append(v); }
            else if s == "--listen" && v.len <= 64 { o.listen.append(v); }
            else if s == "--accuracy" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.accuracy = n; }
            else if s == "--accuracy-ms" { let n, ok = parse_int(v); if !ok || n < 1 || n > 999 { return usage(); } o.accuracy_ms = n; }
            else if s == "--precision" { let n, ok = parse_int(v); if !ok || n < 0 || n > 9 { return usage(); } o.precision = n; }
            else if s == "--port" { let n, ok = parse_int(v); if !ok || n < 0 || n > 65535 { return usage(); } o.port = n as! i32; }
            else if s == "--count" { let n, ok = parse_int(v); if !ok || n < 0 { return usage(); } o.count = n; }
            else { return usage(); }
        }
        i++;
    }
    if o.hash == tsp::SHA1 && !o.sha1 && command != "reply" && command != "serve" {
        return fail("SHA-1 needs --sha1");
    }

    if command == "query" {
        if o.out.len == 0 || (o.data.len == 0 && o.digest.len == 0) { return usage(); }
        var q: u8[>..] = [];
        let r, e = make_request(o, q);
        if e != tsp::OK { return fail(str("no request: ", tsp::error_text(e))); }
        if !write_file(o.out, q) { return fail(str("cannot write ", o.out)); }
        return 0;
    }
    if command == "request" {
        if o.data.len == 0 && o.digest.len == 0 && o.queryfile.len == 0 { return usage(); }
        return request(o);
    }
    if command == "verify" { return verify(o); }
    if command == "show" { return show(o); }
    if command == "stamp" { return stamp(o); }
    if command == "verify-stamp" { return verify_stamp(o); }
    if command == "reply" || command == "serve" {
        var t = tsp::Tsa { .. };
        let se = tsa_setup(t, o);
        if se != 0 { return se; }
        if command == "serve" { return serve(t, o); }
        if o.queryfile.len == 0 || o.out.len == 0 { return usage(); }
        var q: u8[>..] = [];
        if !read_file(o.queryfile, q) { return fail(str("cannot read ", o.queryfile)); }
        let reply, status = answer(t, o, q);
        if !write_file(o.out, reply) { return fail(str("cannot write ", o.out)); }
        say(str("goose-ts: ", tsp::status_name(status)));
        return if status == tsp::GRANTED { 0 } else { 1 };
    }
    return usage();
}

fn main() { exit(run()); }
