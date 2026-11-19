// websocket.server: gorilla's Upgrader.Upgrade, for a server that reads
// the request itself (accept, accept_tls) or one whose HTTP server read
// it (upgrade, upgrade_tls: net.http.conn1's EV_REQUEST, its head and
// what came after it in the buffer).
//
//   let fd = net::accept(listener, 0);
//   var c = websocket::Conn { .. };
//   var u = websocket::upgrader();
//   u.compression = true;
//   if websocket::accept(c, fd, u, 10000) == websocket::OK { ... }
//
// A request that cannot be upgraded is answered (400, 403, 405, 426, as
// gorilla answers) and the call fails with ERR_HANDSHAKE, c.status the
// status, c.why why; the socket is then the caller's to close.

namespace websocket;

import std;
import net;
import net.http;
import net.http.h1;
import crypto.tls;
import crypto.tls.handshake;
import websocket;
import websocket.deflate;
import websocket.handshake;
import websocket.conn;

fn server_reset(c: Conn&, fd: i64) {
    c.fd = fd;
    c.is_client = false;
    c.on_tls = false;
    c.status = 0;
    c.why.clear();
    c.head.clear();
    c.inbuf.clear();
    c.inpos = 0;
    c.wire.clear();
    c.st = new_state();
}

// Answers the request head h (parsed from m) on the Conn's socket, and
// starts the connection with rest, the bytes that came after the head.
fn answer(c: Conn&, m: const u8[:], h: const http::Head&, rest: const u8[:], u: const Upgrader&) -> i64 {
    c.head.clear();
    c.head.append(m[..h.len]);
    let a = check_request(m, h, u);
    c.status = a.status;
    c.wire.clear();
    if a.status != 101 {
        c.why.clear();
        c.why.append(a.why);
        put_refusal(c.wire, a);
        let e = flush(c);
        return ERR_HANDSHAKE;
    }
    c.subprotocol.clear();
    c.subprotocol.append(a.subprotocol);
    var resp: u8[>..] = [];
    put_accept(resp, a, u);
    var early: u8[>..] = [];
    early.append(rest);
    start(c, false, a.pmd, early);
    c.wire.append(resp);
    return flush(c);
}

// Upgrades a request that an HTTP/1.1 server read on fd (-1: bytes the
// caller carries; the answer is then in take_output).
fn upgrade(c: Conn&, fd: i64, m: const u8[:], h: const http::Head&, rest: const u8[:], u: const Upgrader&) -> i64 {
    server_reset(c, fd);
    return answer(c, m, h, rest, u);
}

// The same over a TLS connection the server made (the configuration it
// was made with goes along, for what TLS still sends).
fn upgrade_tls(c: Conn&, fd: i64, tc: const tls::Conn&, cfg: const tls::ServerConfig&, m: const u8[:],
               h: const http::Head&, rest: const u8[:], u: const Upgrader&) -> i64 {
    server_reset(c, fd);
    c.on_tls = true;
    c.tc.clear();
    c.tc.push(copy(tc));
    c.scfg = copy(cfg);
    return answer(c, m, h, rest, u);
}

// Reads a request head on the Conn's socket and answers it.
fn read_request(c: Conn&, u: const Upgrader&, timeout_ms: i32) -> i64 {
    let lim = http::default_limits();
    loop {
        let h, n = http::parse_request(c.inbuf[c.inpos..], lim);
        if n > 0 {
            var m: u8[>..] = [];
            m.append(c.inbuf[c.inpos..]);
            if http::check_request(m, h) != 0 {
                var a = Accepted { status: 400, why: [], key: [], subprotocol: [], pmd: no_pmd() };
                a.why.append("malformed request");
                c.status = 400;
                c.wire.clear();
                put_refusal(c.wire, a);
                let e = flush(c);
                return ERR_HANDSHAKE;
            }
            return answer(c, m, h, m[n..], u);
        }
        if n < 0 {
            var a = Accepted { status: 0 - n, why: [], key: [], subprotocol: [], pmd: no_pmd() };
            a.why.append("malformed request");
            c.status = a.status;
            c.wire.clear();
            put_refusal(c.wire, a);
            let e = flush(c);
            return ERR_HANDSHAKE;
        }
        let e = fill(c, timeout_ms);
        if e != OK { return if e == ERR_CLOSED { ERR_HANDSHAKE } else { e }; }
    }
    return ERR_HANDSHAKE;
}

// Reads the upgrade request on a TCP connection a listener accepted and
// answers it, within timeout_ms (0: none).
fn accept(c: Conn&, fd: i64, u: const Upgrader&, timeout_ms: i32) -> i64 {
    server_reset(c, fd);
    return read_request(c, u, timeout_ms);
}

// The same with TLS first, as cfg has it.
fn accept_tls(c: Conn&, fd: i64, cfg: const tls::ServerConfig&, u: const Upgrader&, timeout_ms: i32) -> i64 {
    server_reset(c, fd);
    c.on_tls = true;
    c.scfg = copy(cfg);
    c.tc.clear();
    c.tc.push(tls::server(c.scfg));
    while !tls::connected(c.tc[0]) {
        c.raw.resize(65536, 0);
        let n = net::read(fd, c.raw, timeout_ms);
        if n == 0 { return ERR_TLS; }
        if n < 0 { return net_error(n); }
        var data: u8[>..] = [];
        data.append(c.raw[..n]);
        c.rec.clear();
        let r = tls::server_feed(c.tc[0], c.scfg, data, c.rec, c.inbuf);
        if c.rec.len > 0 && net::write(fd, c.rec, timeout_ms) < 0 { return ERR_NETWORK; }
        if r < 0 { return ERR_TLS; }
        if tls::closed(c.tc[0]) { return ERR_TLS; }
    }
    return read_request(c, u, timeout_ms);
}
