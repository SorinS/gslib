// A client and a server over UDP on 127.0.0.1, in one thread: the
// handshake through quic.transport's dial and serve_step, a request and an
// answer on a stream, the client hanging up.

import std;
import gslib from "../..";
import gslib.net;
import gslib.quic;
import gslib.quic.conn;
import gslib.quic.transport;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

var checks = 0;

fn check(ok: bool, what: const u8[:]) {
    checks++;
    if !ok {
        print("FAIL ", what);
        exit(1);
    }
}

fn certificate() -> u8[>..], u8[>..] {
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=localhost", 1700000000, 2000000000);
    x509::add_dns(t.san, "localhost");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    return der, x509::marshal_pkcs8(k);
}

fn main() {
    let cert, key = certificate();
    var sc, ok = tls::server_config(cert, key);
    tls::add_alpn(sc.alpn, "h3");
    var cc = tls::client_config("localhost", cert);
    tls::add_alpn(cc.alpn, "h3");
    var srv, e = quic::listen("127.0.0.1", 0);
    check(e == 0, "a UDP socket");
    let local, le = net::local_addr(srv.fd);
    // The client's handshake, the server stepping in between.
    var c = quic::client(cc, quic::now_us());
    let fd = net::dial_udp("127.0.0.1", local.port);
    for i in 400 {
        let r = quic::step(fd, c, cc, 5);
        quic::serve_step(srv, sc, 5);
        if quic::established(c) && c.confirmed { break; }
    }
    check(quic::established(c) && c.confirmed, "the handshake over UDP");
    let k = quic::accept(srv);
    check(k == 0 && quic::established(srv.conns[0]), "the server's connection");
    let id = quic::open_stream(c, true);
    let w = quic::stream_write(c, id, "hello over UDP", true);
    var got: u8[>..] = [];
    var sid: i64 = -1;
    for i in 400 {
        let r = quic::step(fd, c, cc, 5);
        quic::serve_step(srv, sc, 5);
        if sid < 0 { sid = quic::accept_stream(srv.conns[0]); }
        if sid >= 0 { let n = quic::stream_read(srv.conns[0], sid, got, 100); }
        if sid >= 0 && quic::stream_finished(srv.conns[0], sid) { break; }
    }
    check(got == "hello over UDP", "a request");
    let w2 = quic::stream_write(srv.conns[0], sid, "and back", true);
    var back: u8[>..] = [];
    for i in 400 {
        quic::serve_step(srv, sc, 5);
        let r = quic::step(fd, c, cc, 5);
        let n = quic::stream_read(c, id, back, 100);
        if quic::stream_finished(c, id) { break; }
    }
    check(back == "and back", "an answer");
    quic::hang_up(fd, c, 0, "done");
    for i in 100 {
        quic::serve_step(srv, sc, 5);
        if quic::closing(srv.conns[0]) { break; }
    }
    let code, app, reason = quic::close_error(srv.conns[0]);
    check(quic::closing(srv.conns[0]) && app && reason == "done", "the client hung up");
    quic::shut_down(srv);
    print("udp: ", checks, " checks");
}
