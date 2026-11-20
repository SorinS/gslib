// A QUIC client and server in one program, with no network: datagrams
// are handed from one to the other. The handshake (TLS 1.3 inside QUIC),
// a bidirectional stream each way, and the connection closed.
//
//   goose examples/quic/in_memory.goose

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.conn;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

// What each side has to send goes to the other, until neither has more.
fn exchange(c: quic::Conn&, cc: const tls::ClientConfig&, s: quic::Conn&, sc: const tls::ServerConfig&, now: i64&) {
    for round in 100 {
        var moved = false;
        loop { let d = quic::poll(c, now); if d.len == 0 { break; } quic::recv(s, sc, d, now); moved = true; }
        loop { let d = quic::poll(s, now); if d.len == 0 { break; } quic::recv(c, cc, d, now); moved = true; }
        now += 1000;
        if !moved {
            // Nothing in flight: let the timers run (delayed ACKs, closing).
            let t = quic::next_timeout(c);
            if t != 0 && t <= now + 50000 { now = ::max(now, t); quic::on_timeout(c, now); }
            let u = quic::next_timeout(s);
            if u != 0 && u <= now + 50000 { now = ::max(now, u); quic::on_timeout(s, now); }
            if quic::poll(c, now).len == 0 && quic::poll(s, now).len == 0 { return; }
        }
    }
}

fn main() {
    // A certificate for "localhost", made here; the client trusts it.
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=localhost", 1700000000, 2000000000);
    x509::add_dns(t.san, "localhost");
    let cert, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    var sc, oks = tls::server_config(cert, x509::marshal_pkcs8(k));
    tls::add_alpn(sc.alpn, "demo");
    var cc = tls::client_config("localhost", cert);
    tls::add_alpn(cc.alpn, "demo");

    var now = time_ns() / 1000;
    var c = quic::client(cc, now);
    let first = quic::poll(c, now);
    print("the client's first datagram: ", first.len, " bytes");
    var s = quic::server(sc, first, now);
    quic::recv(s, sc, first, now);
    exchange(c, cc, s, sc, now);
    print("connected: ", quic::established(c) && quic::established(s), ", ALPN ", quic::alpn(c));

    let id = quic::open_stream(c, true);
    let w = quic::stream_write(c, id, "ping", true);
    exchange(c, cc, s, sc, now);
    let sid = quic::accept_stream(s);
    var got: u8[>..] = [];
    let n = quic::stream_read(s, sid, got, 100);
    print("the server read on stream ", sid, ": ", got);
    let w2 = quic::stream_write(s, sid, "pong", true);
    exchange(c, cc, s, sc, now);
    var back: u8[>..] = [];
    let n2 = quic::stream_read(c, id, back, 100);
    print("the client read: ", back, ", the stream finished: ", quic::stream_finished(c, id));

    quic::close(c, 0, "done");
    exchange(c, cc, s, sc, now);
    let code, app, reason = quic::close_error(s);
    print("the server saw the close: ", reason);
}
