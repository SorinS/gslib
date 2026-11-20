// HTTP/3 over QUIC on 127.0.0.1: a server and a client in one program,
// over UDP, taking turns in one thread. The client GETs a page and POSTs
// a body; the server answers both. With a URL argument, the client GETs
// that instead (a real HTTP/3 server, its certificate checked against the
// system's roots).
//
//   goose examples/quic/h3_get.goose [-- https://cloudflare-quic.com/]

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.quic;
import gslib.quic.conn;
import gslib.quic.transport;
import gslib.quic.qpack;
import gslib.quic.http3;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;

fn fetch(url: const u8[:]) {
    let host_end = find(url[8..], "/");
    let host = if host_end >= 0 { url[8..8 + host_end] } else { url[8..] };
    let path = if host_end >= 0 { url[8 + host_end..] } else { url[url.len..] };
    let pool, okp = x509::system_roots();
    var cfg = tls::client_config_pool(host, pool);
    tls::add_alpn(cfg.alpn, "h3");
    var c, fd, e = quic::dial(host, 443, cfg, 10000);
    if e != 0 { print("no connection: ", e); return; }
    var h = quic::h3(false);
    var p: u8[>..] = [];
    p.append(if path.len > 0 { path } else { "/" });
    let id = quic::h3_send_request(c, h, "GET", "https", host, p, "", "");
    var body: u8[>..] = [];
    while !quic::h3_done(h, id) {
        if quic::step(fd, c, cfg, 50) != 0 { break; }
        quic::h3_poll(c, h);
        quic::h3_take_body(h, id, body);
    }
    quic::h3_take_body(h, id, body);
    print("status ", quic::h3_status(h, id), ", ", body.len, " bytes");
    quic::hang_up(fd, c, 0x100, "");
}

fn main() {
    let a = args();
    if a.len > 1 { fetch(a[1]); return; }
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=localhost", 1700000000, 2000000000);
    x509::add_dns(t.san, "localhost");
    let cert, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    var sc, oks = tls::server_config(cert, x509::marshal_pkcs8(k));
    tls::add_alpn(sc.alpn, "h3");
    var cc = tls::client_config("localhost", cert);
    tls::add_alpn(cc.alpn, "h3");

    // The server, on a port the system picks.
    var srv, le = quic::listen("127.0.0.1", 0);
    let addr, ae = net::local_addr(srv.fd);
    var hs = quic::h3(true);
    // The client: its handshake, the server stepping in turn.
    var c = quic::client(cc, quic::now_us());
    let fd = net::dial_udp("127.0.0.1", addr.port);
    var h = quic::h3(false);
    var get: i64 = -1;
    var post: i64 = -1;
    for round in 2000 {
        let r = quic::step(fd, c, cc, 2);
        quic::serve_step(srv, sc, 2);
        if srv.conns.len > 0 {
            quic::h3_poll(srv.conns[0], hs);
            loop {
                let id = quic::h3_next_request(hs);
                if id < 0 { break; }
                var rh: u8[>..] = [];
                quic::qpack_record(rh, "content-type", "text/plain");
                let path = quic::h3_field(hs, id, ":path");
                if quic::h3_field(hs, id, ":method") == "POST" {
                    let sent = quic::h3_respond(srv.conns[0], hs, id, 200, rh, str("you sent: ", quic::h3_body(hs, id)));
                } else {
                    let sent = quic::h3_respond(srv.conns[0], hs, id, 200, rh, str("hello at ", path));
                }
            }
        }
        if quic::established(c) && c.confirmed {
            quic::h3_poll(c, h);
            if get < 0 {
                get = quic::h3_send_request(c, h, "GET", "https", "localhost", "/index", "", "");
                post = quic::h3_send_request(c, h, "POST", "https", "localhost", "/form", "", "a=1&b=2");
            }
            if quic::h3_done(h, get) && quic::h3_done(h, post) { break; }
        }
    }
    var b1: u8[>..] = [];
    quic::h3_take_body(h, get, b1);
    var b2: u8[>..] = [];
    quic::h3_take_body(h, post, b2);
    print("GET: ", quic::h3_status(h, get), " ", b1);
    print("POST: ", quic::h3_status(h, post), " ", b2);
    quic::hang_up(fd, c, 0x100, "");
    quic::shut_down(srv);
}
