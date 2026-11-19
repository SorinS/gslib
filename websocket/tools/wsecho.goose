// goose-wsecho: a WebSocket echo server, over TCP or TLS, for trying the
// package against real clients (Autobahn's fuzzingclient among them):
// each text or binary message comes back as it came.
//
//   goose-wsecho [--listen 127.0.0.1] [--port 9001] [--cert chain.pem --key key.pem]
//                [--no-compression] [--stream] [--origin-any] [--protocol P,...]
//                [--max-conns 1024] [--max-message BYTES]
//
// permessage-deflate is taken when offered, unless --no-compression.
// --stream echoes each message a frame at a time as it is read
// (next_message, read_part, write_part) instead of whole. Each connection
// runs on a thread of its own, at most --max-conns at once; one line a
// connection goes to stderr. It listens on 127.0.0.1 unless told
// otherwise.

import std;
import gslib from "../..";
import gslib.net;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.websocket;
import gslib.websocket.deflate;
import gslib.websocket.handshake;
import gslib.websocket.conn;
import gslib.websocket.server;

fn die(msg: const u8[:]) {
    write_stderr("goose-wsecho: ");
    write_stderr(msg);
    write_stderr("\n");
    exit(2);
}

fn pem_der(path: const u8[:], labels: const u8[:][:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die("cannot read a PEM file"); }
    var out: u8[>..] = [];
    for label in labels {
        let ders, ok = asn1::pem_decode(text, label);
        for d in ders { out.append(d); }
        if out.len > 0 { return out; }
    }
    die("no PEM block of the expected kind");
    return out;
}

// What every connection is given beside its socket.
struct Site {
    on_tls: bool,
    stream: bool,
    max_message: i64,
    up: websocket::Upgrader,
}

fn log(fd: i64, what: const u8[:], code: i64) {
    var l: u8[>..] = [];
    l.append("goose-wsecho: ");
    format(l, fd);
    l.push(' ');
    l.append(what);
    if code != 0 {
        l.push(' ');
        format(l, code);
    }
    l.push('\n');
    write_stderr(l);
}

// Echoes messages whole until the connection ends.
fn echo_whole(c: websocket::Conn&) -> i64 {
    var msg: u8[>..] = [];
    loop {
        let kind, e = websocket::read_message(c, msg);
        if e != websocket::OK { return e; }
        let w = websocket::write_message(c, kind, msg);
        if w != websocket::OK { return w; }
    }
    return websocket::OK;
}

// Echoes each message as its frames come.
fn echo_stream(c: websocket::Conn&) -> i64 {
    var part: u8[>..] = [];
    loop {
        let kind, e = websocket::next_message(c);
        if e != websocket::OK { return e; }
        let b = websocket::begin_message(c, kind);
        if b != websocket::OK { return b; }
        loop {
            part.clear();
            let n, end, re = websocket::read_part(c, part);
            if re != websocket::OK { return re; }
            let w = websocket::write_part(c, part);
            if w != websocket::OK { return w; }
            if end { break; }
        }
        let f = websocket::end_message(c);
        if f != websocket::OK { return f; }
    }
    return websocket::OK;
}

fn serve(fd: i64, site: const Site&, scfg: const tls::ServerConfig&) {
    var c = websocket::Conn { .. };
    c.opt.read_limit = site.max_message;
    let e = if site.on_tls { websocket::accept_tls(c, fd, scfg, site.up, 10000) } else { websocket::accept(c, fd, site.up, 10000) };
    if e != websocket::OK {
        log(fd, "handshake failed", c.status);
        net::close(fd);
        return;
    }
    let r = if site.stream { echo_stream(c) } else { echo_whole(c) };
    if !websocket::closed(c) { websocket::close(c, websocket::CLOSE_NORMAL, ""); }
    log(fd, if r == websocket::ERR_CLOSED { "closed" } else { websocket::error_text(r) }, c.close_code);
}

// --- Running connections, as goose-httpd runs them -----------------------------

struct Slot { free: bool }
struct Running { id: i64, fd: i64 }

thread_fn conn_worker(fd: i64, site: Site, scfg: tls::ServerConfig) {
    serve(fd, site, scfg);
    qput(Slot { free: true });
}

thread_fn reaper() {
    loop {
        let r = qget<Running>();
        var msg: u8[>..] = [];
        if !thread_wait(r.id, msg) {
            net::close(r.fd);
            qput(Slot { free: true });
            var line: u8[>..] = [];
            line.append("goose-wsecho: a connection ended in an abort: ");
            line.append(msg);
            line.push('\n');
            write_stderr(line);
        }
    }
}

fn main() {
    let a = args();
    var listen: u8[>..] = [];
    listen.append("127.0.0.1");
    var port: i64 = 9001;
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var max_conns: i64 = 1024;
    var site = Site { on_tls: false, stream: false, max_message: 64 << 20, up: websocket::upgrader() };
    site.up.compression = true;
    var i = 1;
    while i < a.len {
        if a[i] == "--no-compression" { site.up.compression = false; i++; continue; }
        if a[i] == "--stream" { site.stream = true; i++; continue; }
        if a[i] == "--origin-any" { site.up.origin_policy = websocket::ORIGIN_ANY; i++; continue; }
        if i + 1 >= a.len { die("each option takes a value"); }
        let v = a[i + 1];
        if a[i] == "--listen" { listen.clear(); listen.append(v); }
        else if a[i] == "--port" {
            let n, ok = parse_int(v);
            if !ok || n < 0 || n > 65535 { die("bad --port"); }
            port = n;
        }
        else if a[i] == "--cert" { cert.append(v); }
        else if a[i] == "--key" { key.append(v); }
        else if a[i] == "--protocol" { site.up.subprotocols.clear(); site.up.subprotocols.append(v); }
        else if a[i] == "--max-conns" {
            let n, ok = parse_int(v);
            if !ok || n < 1 || n > 100000 { die("bad --max-conns"); }
            max_conns = n;
        }
        else if a[i] == "--max-message" {
            let n, ok = parse_int(v);
            if !ok || n < 0 { die("bad --max-message"); }
            site.max_message = n;
        }
        else { die("usage: goose-wsecho [--listen ADDR] [--port N] [--cert chain.pem --key key.pem] [--no-compression] [--stream] [--origin-any] [--protocol P,...] [--max-conns N] [--max-message BYTES]"); }
        i += 2;
    }
    site.on_tls = cert.len > 0;
    var chain: u8[>..] = [];
    var key_der: u8[>..] = [];
    if site.on_tls {
        if key.len == 0 { die("--cert needs --key"); }
        chain = pem_der(cert, ["CERTIFICATE"]);
        key_der = pem_der(key, ["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"]);
    }
    var scfg, ok = tls::server_config(chain, key_der);
    if site.on_tls && !ok { die("the certificate and key do not load"); }
    tls::add_alpn(scfg.alpn, "http/1.1");
    let lfd = net::listen(listen, port);
    if lfd < 0 { die("cannot listen"); }
    var line: u8[>..] = [];
    line.append("goose-wsecho: listening on ");
    line.append(listen);
    line.push(':');
    format(line, net::local_port(lfd));
    line.append(if site.on_tls { " (TLS)\n" } else { "\n" });
    write_stderr(line);
    for k in max_conns { qput(Slot { free: true }); }
    thread_spawn(reaper);
    loop {
        let slot = qget<Slot>();
        let fd = net::accept(lfd, 0);
        if fd < 0 { qput(slot); continue; }
        let id = thread_spawn_contained(conn_worker, fd, site, copy(scfg));
        qput(Running { id: id, fd: fd });
    }
}
