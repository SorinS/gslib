// A QUIC client and server in one program, datagrams passed between them
// in memory with a simulated clock: the handshake (the client verifying a
// certificate made here), streams both ways with data larger than a
// window, the connection closed by the application; then a channel that
// drops and reorders datagrams, where loss detection and PTO probes must
// still deliver everything; idle timeout; a Retry; data at the wrong
// version answered by Version Negotiation.

import std;
import gslib from "../..";
import gslib.quic;
import gslib.quic.packet;
import gslib.quic.conn;
import gslib.quic.http3;
import gslib.quic.qpack;
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

// A self-signed certificate for "localhost", and its key.
fn certificate() -> u8[>..], u8[>..] {
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=localhost", 1700000000, 2000000000);
    x509::add_dns(t.san, "localhost");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    assert(ok && e == x509::OK);
    return der, x509::marshal_pkcs8(k);
}

let NOW0: i64 = 1800000000000000;

// A deterministic generator, for the lossy channel.
var seed: u64 = 12345;
fn rnd(n: i64) -> i64 {
    seed = seed * 6364136223846793005 + 1442695040888963407;
    return ((seed >> 33) % n as! u64) as! i64;
}

struct Wire {
    loss: i64,                 // percent of datagrams dropped
    to_server: u8[..1300][32], n_ts: i64,
    to_client: u8[..1300][32], n_tc: i64,
}

fn wire(loss: i64) -> Wire { Wire { loss: loss, to_server: [[]; 32], n_ts: 0, to_client: [[]; 32], n_tc: 0 } }

// Runs both ends until neither has anything to send and no timer is due
// before `until`, or until `until`: datagrams go across (maybe dropped,
// maybe reordered), timers fire as the clock reaches them.
fn run<F>(c: quic::Conn&, cc: const tls::ClientConfig&, s: quic::Conn&, sc: const tls::ServerConfig&, w: Wire&, now: i64&, until: i64) {
    var still = 0;                 // rounds in a row in which neither the clock nor a datagram moved
    for step in 20000 {
        // Everything each side has to send now.
        for k in 64 {
            let d = quic::poll(c, now);
            if d.len == 0 { break; }
            if rnd(100) >= w.loss && w.n_ts < 32 { w.to_server[w.n_ts].clear(); w.to_server[w.n_ts].append(d); w.n_ts++; }
        }
        for k in 64 {
            let d = quic::poll(s, now);
            if d.len == 0 { break; }
            if rnd(100) >= w.loss && w.n_tc < 32 { w.to_client[w.n_tc].clear(); w.to_client[w.n_tc].append(d); w.n_tc++; }
        }
        if w.n_ts == 0 && w.n_tc == 0 {
            if F(c, s) || now >= until { return; }
            // Nothing in flight: the clock jumps to the next timer.
            var t = quic::next_timeout(c);
            let ts = quic::next_timeout(s);
            if ts != 0 && (t == 0 || ts < t) { t = ts; }
            if t == 0 || t > until { now = until; return; }
            if t > now { now = t; still = 0; }
            else { still++; check(still < 10, "a timer due that does nothing"); }
            if quic::next_timeout(c) != 0 && quic::next_timeout(c) <= now { quic::on_timeout(c, now); }
            if quic::next_timeout(s) != 0 && quic::next_timeout(s) <= now { quic::on_timeout(s, now); }
            continue;
        }
        // A millisecond of flight; with loss on, the order may change.
        now += 1000;
        let swap = w.loss > 0 && rnd(4) == 0;
        if swap && w.n_ts >= 2 { let tmp = w.to_server[0]; w.to_server[0] = w.to_server[1]; w.to_server[1] = tmp; }
        if swap && w.n_tc >= 2 { let tmp = w.to_client[0]; w.to_client[0] = w.to_client[1]; w.to_client[1] = tmp; }
        for k in w.n_ts { quic::recv(s, sc, w.to_server[k], now); }
        w.n_ts = 0;
        for k in w.n_tc { quic::recv(c, cc, w.to_client[k], now); }
        w.n_tc = 0;
        if quic::next_timeout(c) != 0 && quic::next_timeout(c) <= now { quic::on_timeout(c, now); }
        if quic::next_timeout(s) != 0 && quic::next_timeout(s) <= now { quic::on_timeout(s, now); }
    }
}

fn both_up(c: const quic::Conn&, s: const quic::Conn&) -> bool { quic::established(c) && quic::established(s) && c.confirmed }
fn both_closed(c: const quic::Conn&, s: const quic::Conn&) -> bool { quic::closed(c) && quic::closed(s) }
fn never(c: const quic::Conn&, s: const quic::Conn&) -> bool { false }

fn configs() -> tls::ClientConfig, tls::ServerConfig {
    let cert, key = certificate();
    var sc, ok = tls::server_config(cert, key);
    tls::add_alpn(sc.alpn, "h3");
    var cc = tls::client_config("localhost", cert);
    tls::add_alpn(cc.alpn, "h3");
    return cc, sc;
}

// The first datagram reaches the server, which makes its connection.
fn connect(cc: const tls::ClientConfig&, sc: const tls::ServerConfig&, now: i64) -> quic::Conn, quic::Conn {
    var c = quic::client(cc, now);
    let first = quic::poll(c, now);
    check(quic::server_accepts(first), "the server takes the first Initial");
    var s = quic::server(sc, first, now);
    quic::recv(s, sc, first, now);
    return c, s;
}

// Sends `n` bytes from one side's stream, reading them on the other;
// whether they all arrived in order with the end.
fn transfer(c: quic::Conn&, cc: const tls::ClientConfig&, s: quic::Conn&, sc: const tls::ServerConfig&, w: Wire&,
            now: i64&, n: i64) -> bool {
    let id = quic::open_stream(c, true);
    if id < 0 { return false; }
    var sent = 0;
    var got: u8[>..] = [];
    var sid: i64 = -1;
    for round in 4000 {
        if sent < n {
            var chunk: u8[>..] = [];
            for i in ::min(4096, n - sent) { chunk.push(((sent + i) * 7 % 251) as! u8); }
            let k = quic::stream_write(c, id, chunk, sent + chunk.len == n);
            sent += ::max(k, 0);
        }
        run(c, cc, s, sc, w, now, now + 20000, never);
        if sid < 0 { sid = quic::accept_stream(s); }
        if sid >= 0 { let r = quic::stream_read(s, sid, got, 1 << 20); }
        if sid >= 0 && quic::stream_finished(s, sid) { break; }
    }
    if got.len != n || sid != id { return false; }
    for i in n { if got[i] != (i * 7 % 251) as! u8 { return false; } }
    // And back on the same stream.
    let k = quic::stream_write(s, sid, "pong", true);
    run(c, cc, s, sc, w, now, now + 2000000, never);
    var back: u8[>..] = [];
    let r = quic::stream_read(c, id, back, 100);
    return k == 4 && back == "pong" && quic::stream_finished(c, id);
}

fn clean() {
    let cc, sc = configs();
    var now = NOW0;
    var c, s = connect(cc, sc, now);
    var w = wire(0);
    run(c, cc, s, sc, w, now, now + 5000000, both_up);
    check(quic::established(c) && quic::established(s), "the handshake");
    check(c.confirmed && s.confirmed, "confirmed both ways (HANDSHAKE_DONE)");
    check(c.discarded[0] && c.discarded[1] && s.discarded[0] && s.discarded[1], "the Initial and Handshake keys discarded");
    check(quic::alpn(c) == "h3" && quic::alpn(s) == "h3", "ALPN");
    check(transfer(c, cc, s, sc, w, now, 200000), "200 KB across a stream, and an answer");
    let u = quic::open_stream(s, false);
    let wr = quic::stream_write(s, u, "one way", true);
    run(c, cc, s, sc, w, now, now + 1000000, never);
    let cu = quic::accept_stream(c);
    var got: u8[>..] = [];
    let r = quic::stream_read(c, cu, got, 100);
    check(u == 3 && cu == 3 && got == "one way" && quic::stream_finished(c, cu), "a server's unidirectional stream");
    // Key updates: the client starts one, then the server; data still flows.
    check(quic::update_keys(c) && c.key_phase, "the client updates its keys");
    check(!quic::update_keys(c), "not again before the new phase is acknowledged");
    check(transfer(c, cc, s, sc, w, now, 50000) && s.key_phase, "data after it, the server following");
    check(quic::update_keys(s) && !s.key_phase, "the server updates its keys");
    check(transfer(c, cc, s, sc, w, now, 50000) && !c.key_phase, "data after it, the client following");
    quic::close(c, 0x100, "bye");
    run(c, cc, s, sc, w, now, now + 10000000, both_closed);
    let code, app, reason = quic::close_error(s);
    check(quic::closed(c) && quic::closed(s) && code == 0x100 && app && reason == "bye", "closed by the application");
}

fn lossy() {
    let cc, sc = configs();
    var now = NOW0;
    var c, s = connect(cc, sc, now);
    var w = wire(15);
    run(c, cc, s, sc, w, now, now + 60000000, both_up);
    check(quic::established(c) && quic::established(s) && c.confirmed, "the handshake with 15% loss");
    check(transfer(c, cc, s, sc, w, now, 300000), "300 KB across a stream with 15% loss and reordering");
    check(c.rec.cwnd > 0 && s.rec.has_rtt, "an RTT estimate");
}

// NEW_CONNECTION_ID with Retire Prior To: a step of two retires the old
// IDs, each in a RETIRE_CONNECTION_ID frame; a step far beyond what was
// issued closes with CONNECTION_ID_LIMIT_ERROR instead of queueing that
// many frames (found by fuzzing: 2^62 of them).
fn connection_ids() {
    let cc, sc = configs();
    var now = NOW0;
    var c, s = connect(cc, sc, now);
    var w = wire(0);
    run(c, cc, s, sc, w, now, now + 5000000, both_up);
    let cid: u8[8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let token: u8[16] = [7; 16];
    var f: u8[>..] = [];
    quic::put_new_connection_id(f, 2, 2, cid, token);
    let e1 = quic::handle_frames(s, sc, quic::SPACE_APP, f);
    let d = quic::poll(s, now);
    check(e1 && !quic::closing(s) && d.len > 0 && s.retire_seq == 2 && s.retire_pending == 0 && s.dcid == cid,
          "Retire Prior To 2: two IDs retired, the new one used");
    f.clear();
    quic::put_new_connection_id(f, 1 << 40, 1 << 40, cid, token);
    let e2 = quic::handle_frames(s, sc, quic::SPACE_APP, f);
    let d2 = quic::poll(s, now);
    let code, app, reason = quic::close_error(s);
    check(quic::closing(s) && code == quic::CONNECTION_ID_LIMIT_ERROR && !app && d2.len < 1300,
          "Retire Prior To 2^40: CONNECTION_ID_LIMIT_ERROR");
}

// What fuzzing and review found, kept: a received-packet history that
// is full taking a packet older than all of it (it aborted on an index
// past its end, from 33 Initials with no handshake); a Retry whose token
// is longer than a client keeps (it aborted the client).
fn hostile() {
    var sp = quic::space();
    var pn: i64 = 300;
    for k in 32 { quic::note_pn(sp, pn); pn -= 2; }
    quic::note_pn(sp, 100);
    check(sp.n_recv == 32 && quic::seen_pn(sp, 100) && quic::seen_pn(sp, 50) && !quic::seen_pn(sp, 239),
          "a full history: an older packet taken as seen, not stored");
    quic::note_pn(sp, 1000);
    check(sp.n_recv == 32 && quic::seen_pn(sp, 1000) && quic::seen_pn(sp, 238) && quic::seen_pn(sp, 240) && !quic::seen_pn(sp, 241),
          "a new range: the lowest dropped, the floor above it");
    let cc, sc = configs();
    var c = quic::client(cc, NOW0);
    let first = quic::poll(c, NOW0);
    let new_cid: u8[8] = [9, 8, 7, 6, 5, 4, 3, 2];
    var r: u8[>..] = [];
    r.push(0xf5);
    quic::put_u32be(r, quic::VERSION_1);
    r.push(c.scid.len as! u8);
    r.append(c.scid);
    r.push(8);
    r.append(new_cid);
    for i in 1000 { r.push(0x41); }
    let tag = quic::retry_tag(c.odcid, r);
    r.append(tag);
    quic::recv(c, cc, r, NOW0 + 1000);
    check(!c.retried && c.token.len == 0 && !quic::closed(c), "a Retry with a 1000-byte token: ignored");
}

fn idle() {
    let cc, sc = configs();
    var now = NOW0;
    var c, s = connect(cc, sc, now);
    var w = wire(0);
    run(c, cc, s, sc, w, now, now + 5000000, both_up);
    run(c, cc, s, sc, w, now, now + 40000000, both_closed);
    let code, app, reason = quic::close_error(c);
    check(quic::closed(c) && quic::closed(s) && reason == "idle timeout", "closed when idle for 30 s");
}

fn retry() {
    let cc, sc = configs();
    var c = quic::client(cc, NOW0);
    let first = quic::poll(c, NOW0);
    let new_cid: u8[8] = [9, 8, 7, 6, 5, 4, 3, 2];
    // A Retry naming the client's own Destination Connection ID: ignored.
    var bad: u8[>..] = [];
    bad.push(0xf0);
    quic::put_u32be(bad, quic::VERSION_1);
    bad.push(c.scid.len as! u8);
    bad.append(c.scid);
    bad.push(c.dcid.len as! u8);
    bad.append(c.dcid);
    bad.append("token");
    let btag = quic::retry_tag(c.odcid, bad);
    bad.append(btag);
    quic::recv(c, cc, bad, NOW0 + 1000);
    check(!c.retried, "a Retry with the client's own ID ignored");
    var r: u8[>..] = [];
    r.push(0xf5);
    quic::put_u32be(r, quic::VERSION_1);
    r.push(c.scid.len as! u8);
    r.append(c.scid);
    r.push(8);
    r.append(new_cid);
    r.append("the token");
    var tampered: u8[>..] = [];
    tampered.append(r);
    let tag = quic::retry_tag(c.odcid, r);
    r.append(tag);
    tampered.append(tag);
    tampered[tampered.len - 1] ^= 1;
    quic::recv(c, cc, tampered, NOW0 + 1000);
    check(!c.retried, "a Retry with a bad tag ignored");
    quic::recv(c, cc, r, NOW0 + 1000);
    check(c.retried && c.dcid[..] == new_cid[..], "a Retry taken");
    var again = quic::poll(c, NOW0 + 2000);
    let h, ok = quic::read_header(again, 0, 8);
    check(again.len == 1200 && ok && h.ptype == quic::PT_INITIAL && again[h.dcid_at..h.dcid_at + 8] == new_cid[..] &&
          again[h.token_at..h.token_at + h.token_len] == "the token", "the Initial again, to the new ID with the token");
    let k = quic::initial_keys(new_cid, true);
    let pn, he, oko = quic::open(k, again, h.pn_at, h.end, -1);
    check(oko, "under the new ID's Initial keys");
    quic::recv(c, cc, r, NOW0 + 3000);
    check(c.dcid[..] == new_cid[..], "a second Retry ignored");
}

fn version_negotiation() {
    var d: u8[>..] = [];
    d.push(0xc0);
    quic::put_u32be(d, 0x1a2a3a4a);
    d.push(8);
    for i in 8 { d.push(i as! u8); }
    d.push(4);
    for i in 4 { d.push(0xa0 + i as! u8); }
    while d.len < 1200 { d.push(0); }
    check(!quic::server_accepts(d), "an unknown version is not accepted");
    let vn = quic::version_negotiation(d);
    check(vn.len == 1 + 4 + 1 + 4 + 1 + 8 + 4 && vn[0] & 0x80 != 0 && quic::u32be(vn, 1) == 0 &&
          vn[6..10] == d[15..19] && quic::u32be(vn, vn.len - 4) == quic::VERSION_1, "answered with Version Negotiation");
    // A client that gets one without version 1 gives up.
    let cc, sc = configs();
    var c = quic::client(cc, NOW0);
    let first = quic::poll(c, NOW0);
    var vn2: u8[>..] = [];
    vn2.push(0x80);
    quic::put_u32be(vn2, 0);
    vn2.push(c.scid.len as! u8);
    vn2.append(c.scid);
    vn2.push(c.dcid.len as! u8);
    vn2.append(c.dcid);
    quic::put_u32be(vn2, 0xff00001d);
    quic::recv(c, cc, vn2, NOW0 + 1000);
    check(quic::closed(c), "a client offered no version it has");
}

// HTTP/3: a GET and a POST, and the server's answers.
fn http3() {
    let cc, sc = configs();
    var now = NOW0;
    var c, s = connect(cc, sc, now);
    var w = wire(0);
    run(c, cc, s, sc, w, now, now + 5000000, both_up);
    var hc = quic::h3(false);
    var hs = quic::h3(true);
    var hdrs: u8[>..] = [];
    quic::qpack_record(hdrs, "user-agent", "gslib");
    let get = quic::h3_send_request(c, hc, "GET", "https", "localhost", "/hello", hdrs, "");
    let post = quic::h3_send_request(c, hc, "POST", "https", "localhost", "/echo", "", "posted body");
    var answered = 0;
    for round in 200 {
        run(c, cc, s, sc, w, now, now + 20000, never);
        quic::h3_poll(c, hc);
        quic::h3_poll(s, hs);
        loop {
            let id = quic::h3_next_request(hs);
            if id < 0 { break; }
            let path = quic::h3_field(hs, id, ":path");
            var rh: u8[>..] = [];
            quic::qpack_record(rh, "content-type", "text/plain");
            if path == "/hello" {
                let ok = quic::h3_respond(s, hs, id, 200, rh, str("hello, ", quic::h3_field(hs, id, "user-agent")));
            } else {
                let ok = quic::h3_respond(s, hs, id, 201, rh, quic::h3_body(hs, id));
            }
            answered++;
        }
        if quic::h3_done(hc, get) && quic::h3_done(hc, post) { break; }
    }
    check(answered == 2, "the server read two requests");
    var b1: u8[>..] = [];
    quic::h3_take_body(hc, get, b1);
    var b2: u8[>..] = [];
    quic::h3_take_body(hc, post, b2);
    let gh = quic::h3_headers(hc, get);
    let ct, okc = quic::qpack_get(gh, "content-type");
    check(quic::h3_status(hc, get) == 200 && b1 == "hello, gslib" && okc && ct == "text/plain", "a GET answered");
    check(quic::h3_status(hc, post) == 201 && b2 == "posted body", "a POST echoed");
    check(quic::h3_got_settings(hc) && quic::h3_got_settings(hs), "both sides read the other's SETTINGS");
    check(hc.error == 0 && hs.error == 0 && quic::established(c), "no errors");
    // Twenty malformed requests (an empty :path), more than a connection's
    // 16 exchanges: each is the stream's error, its slot freed, and a good
    // request after them is still answered.
    var bad_done = 0;
    for i in 20 {
        let bad = quic::h3_send_request(c, hc, "GET", "https", "localhost", "", "", "");
        for round in 50 {
            run(c, cc, s, sc, w, now, now + 20000, never);
            quic::h3_poll(c, hc);
            quic::h3_poll(s, hs);
            if bad >= 0 && quic::h3_done(hc, bad) { bad_done++; quic::h3_forget(hc, bad); break; }
        }
    }
    let good = quic::h3_send_request(c, hc, "GET", "https", "localhost", "/hello", hdrs, "");
    for round in 200 {
        run(c, cc, s, sc, w, now, now + 20000, never);
        quic::h3_poll(c, hc);
        quic::h3_poll(s, hs);
        let id = quic::h3_next_request(hs);
        if id >= 0 { let ok = quic::h3_respond(s, hs, id, 200, "", "still here"); }
        if quic::h3_done(hc, good) { break; }
    }
    var b3: u8[>..] = [];
    quic::h3_take_body(hc, good, b3);
    check(bad_done == 20 && quic::h3_status(hc, good) == 200 && b3 == "still here" && hs.error == 0,
          "twenty malformed requests, then one answered");
}

fn main() {
    clean();
    http3();
    lossy();
    connection_ids();
    hostile();
    idle();
    retry();
    version_negotiation();
    print("loopback: ", checks, " checks");
}
