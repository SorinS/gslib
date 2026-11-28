// Fuzz target: quic. The first byte picks a path (data[0] % 7); the rest
// is the input:
//   0: frames read one after another (and an ACK's ranges);
//   1: frames handled by an established server connection, as a 1-RTT
//      packet's payload after decryption: streams, flow control, ACKs of
//      packets never sent, closes, connection IDs;
//   2: frames handled by a server in the middle of its handshake, as a
//      Handshake packet's (CRYPTO into TLS);
//   3: a datagram received by both of those connections (headers,
//      coalescing, decryption failing, Version Negotiation, Retry);
//   4: transport parameters, as a client's and as a server's;
//   5: QPACK: a field section decoded, the encoder and decoder streams;
//   6: HTTP/3: a request and a response stream fed in two pieces, a
//      control stream, SETTINGS.
// The connections are made once, in main, by a handshake in memory; each
// input works on a copy.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.packet;
import gslib.quic.frame;
import gslib.quic.params;
import gslib.quic.conn;
import gslib.quic.qpack;
import gslib.quic.h3;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

fn no_server_cfg() -> tls::ServerConfig { let sc, ok = tls::server_config("", ""); return sc; }

var SC = no_server_cfg();
var CC = tls::client_config("localhost", "");
var EST = quic::new_conn(true);
var MID = quic::new_conn(true);

let NOW: i64 = 1800000000000000;

fn frames(m: const u8[:]) {
    var at = 0;
    while at < m.len {
        let f, next, err = quic::read_frame(m, at);
        if err != 0 { return; }
        if f.ftype == quic::FT_ACK || f.ftype == quic::FT_ACK + 1 {
            var r: u64[>..] = [];
            quic::ack_ranges(m, f, r);
        }
        let allowed = quic::frame_allowed(f.ftype, quic::PT_INITIAL);
        at = next;
    }
}

fn established(m: const u8[:]) {
    var s = EST;
    let e = quic::handle_frames(s, SC, quic::SPACE_APP, m);
    let d = quic::poll(s, NOW + 1000);
    var buf: u8[>..] = [];
    loop {
        let id = quic::accept_stream(s);
        if id < 0 { break; }
        let n = quic::stream_read(s, id, buf, 1 << 20);
    }
}

fn mid_handshake(m: const u8[:]) {
    var s = MID;
    let e = quic::handle_frames(s, SC, quic::SPACE_HANDSHAKE, m);
    let d = quic::poll(s, NOW + 1000);
}

fn datagram(m: const u8[:]) {
    var s = EST;
    quic::recv(s, SC, m, NOW + 1000);
    var t = MID;
    quic::recv(t, SC, m, NOW + 1000);
    let ok = quic::server_accepts(m);
    let vn = quic::version_negotiation(m);
}

fn params(m: const u8[:]) {
    let p1, e1 = quic::read_params(m, true);
    let p2, e2 = quic::read_params(m, false);
    if e1 == 0 { var out: u8[>..] = []; quic::put_params(out, p1, true); }
}

fn qpack(m: const u8[:]) {
    var recs: u8[>..] = [];
    let e = quic::qpack_decode(m, 65536, recs);
    if e == 0 {
        let r = quic::validate_request(recs);
        let s = quic::validate_response(recs);
        var again: u8[>..] = [];
        quic::qpack_encode(again, recs);
    }
    let a = quic::qpack_encoder_stream(m);
    let b = quic::qpack_decoder_stream(m);
}

fn h3(m: const u8[:]) {
    let cut = if m.len > 0 { m[0] % (m.len + 1) } else { 0 };
    for is_request in 2 {
        var msg = quic::h3_message(is_request == 1);
        var n = 0;
        let e1 = quic::h3_message_feed(msg, m[..cut], false) { kind, bytes => n++; };
        if e1 == 0 { let e2 = quic::h3_message_feed(msg, m[cut..], true) { kind, bytes => n++; }; }
    }
    var ctl = quic::h3_control(true);
    let e3 = quic::h3_control_feed(ctl, m, false);
    let st, e4 = quic::h3_read_settings(m);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let m = data[1..];
    let sel = data[0] % 7;
    if sel == 0 { frames(m); }
    else if sel == 1 { established(m); }
    else if sel == 2 { mid_handshake(m); }
    else if sel == 3 { datagram(m); }
    else if sel == 4 { params(m); }
    else if sel == 5 { qpack(m); }
    else { h3(m); }
    return 0;
}

fn main() {
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=localhost", 1700000000, 2000000000);
    x509::add_dns(t.san, "localhost");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    let sc, okc = tls::server_config(der, x509::marshal_pkcs8(k));
    SC = copy(sc);
    tls::add_alpn(SC.alpn, "h3");
    CC = tls::client_config("localhost", der);
    tls::add_alpn(CC.alpn, "h3");
    // A handshake in memory; MID is the server after the client's first flight.
    var c = quic::client(CC, NOW);
    let first = quic::poll(c, NOW);
    var s = quic::server(SC, first, NOW);
    quic::recv(s, SC, first, NOW);
    MID = s;
    var now = NOW;
    for round in 50 {
        now += 1000;
        loop { let d = quic::poll(s, now); if d.len == 0 { break; } quic::recv(c, CC, d, now); }
        loop { let d = quic::poll(c, now); if d.len == 0 { break; } quic::recv(s, SC, d, now); }
        if quic::established(c) && quic::established(s) && c.confirmed { break; }
    }
    // A stream of the client's open, so that frames about it mean something.
    let id = quic::open_stream(c, true);
    let w = quic::stream_write(c, id, "a request", false);
    loop { let d = quic::poll(c, now); if d.len == 0 { break; } quic::recv(s, SC, d, now); }
    EST = s;
}
