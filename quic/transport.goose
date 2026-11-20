// quic.transport: QUIC over UDP, through net. A client is one
// connection on a dial_udp socket; a server is a socket from listen_udp
// and the connections it has, each found by the Destination Connection ID
// of what arrives (its own Source Connection ID, or for a client's first
// Initials the ID the client chose). Both are driven by step: what the
// connections have to send goes out, the socket is waited on until a
// datagram or the next timer, and timers fire. The application works on
// the connections between steps.
//
//   var c, fd, e = quic::dial("example.com", 443, cfg, 5000);
//   let id = quic::open_stream(c, true);
//   let n = quic::stream_write(c, id, request, true);
//   while !quic::stream_finished(c, id) { let r = quic::step(fd, c, cfg, 100); ... }

namespace quic;

import std;
import net;
import quic;
import quic.packet;
import quic.conn;
import crypto.tls;

let ERR_CLOSED: i64 = -100;

fn now_us() -> i64 { time_ns() / 1000 }

// The milliseconds to wait for a datagram: until the connection's next
// timer, at most max_ms, at least 1 when a timer is set.
fn wait_ms(c: const Conn&, now: i64, max_ms: i64) -> i32 {
    let t = next_timeout(c);
    if t == 0 { return max_ms as! i32; }
    let ms = (t - now + 999) / 1000;
    return ::max(::min(ms, max_ms), 1) as! i32;
}

// Sends what the connection has, on a dial_udp socket.
fn flush(fd: i64, c: Conn&) {
    for k in 256 {
        let d = poll(c, now_us());
        if d.len == 0 { break; }
        let n = net::send(fd, d);
    }
}

// One round on a client connection: send, wait up to max_ms for a
// datagram (less when a timer is due sooner), take every datagram there,
// fire the timers, send again. 0, or ERR_CLOSED once the connection is
// closed.
fn step(fd: i64, c: Conn&, cfg: const tls::ClientConfig&, max_ms: i64) -> i64 {
    flush(fd, c);
    var buf: u8[2048] = [0; 2048];
    var timeout = wait_ms(c, now_us(), max_ms);
    loop {
        let n = net::recv(fd, buf, timeout);
        if n <= 0 { break; }
        recv(c, cfg, buf[..n], now_us());
        timeout = -1;                     // then whatever else is waiting, without waiting
    }
    let now = now_us();
    let t = next_timeout(c);
    if t != 0 && t <= now { on_timeout(c, now); }
    flush(fd, c);
    return if closed(c) { ERR_CLOSED } else { 0 };
}

// A connection to host:port, its handshake done within timeout_ms: the
// connection, its socket, and 0; or an error (net's for the socket,
// ERR_CLOSED for a handshake that failed, net::ERR_TIMEOUT).
fn dial(host: const u8[:], port: i64, cfg: const tls::ClientConfig&, timeout_ms: i64) -> Conn, i64, i64 {
    var c = client(cfg, now_us());
    let fd = net::dial_udp(host, port);
    if fd < 0 { return c, fd, fd; }
    let deadline = now_us() + timeout_ms * 1000;
    while !established(c) || !c.confirmed {
        if step(fd, c, cfg, 50) != 0 { net::close(fd); return c, -1, ERR_CLOSED; }
        if now_us() > deadline { net::close(fd); return c, -1, net::ERR_TIMEOUT; }
    }
    return c, fd, 0;
}

// Closes a client connection: CONNECTION_CLOSE sent, the socket closed.
fn hang_up(fd: i64, c: Conn&, code: u64, reason: const u8[:]) {
    close(c, code, reason);
    flush(fd, c);
    net::close(fd);
}

// --- Server ---------------------------------------------------------------------

let MAX_PEERS: i64 = 16;

struct Server {
    fd: i64,
    addrs: net::AddrPort[16],          // each connection's peer
    live: bool[16],
    fresh: bool[16],                   // made in the last step, not yet seen by accept
    conns: Conn[>..],
}

// A server socket on addr:port (port 0: one the system picks).
fn no_addr() -> net::AddrPort { net::AddrPort { addr: net::Addr { ip: [0; 16], kind: 0, zone: [] }, port: 0 } }

fn listen(addr: const u8[:], port: i64) -> Server, i64 {
    var s = Server { fd: -1, addrs: [no_addr(); 16], live: [false; 16], fresh: [false; 16], conns: [] };
    let fd = net::listen_udp(addr, port);
    if fd < 0 { return s, fd; }
    s.fd = fd;
    return s, 0;
}

// The connection a datagram is for: by its Destination Connection ID.
fn route(s: const Server&, d: const u8[:]) -> i64 {
    let h, ok = read_header(d, 0, CID_LEN);
    if !ok { return -1; }
    let dcid = d[h.dcid_at..h.dcid_at + h.dcid_len];
    for k in s.conns.len {
        if !s.live[k] { continue; }
        if s.conns[k].scid[..] == dcid { return k; }
        if h.long && s.conns[k].odcid[..] == dcid { return k; }
    }
    return -1;
}

fn server_flush(s: Server&, k: i64) {
    for j in 256 {
        let d = poll(s.conns[k], now_us());
        if d.len == 0 { break; }
        let n = net::send_to(s.fd, d, s.addrs[k]);
    }
}

// One round of a server: what every connection has goes out, datagrams
// are taken for up to max_ms (less when a timer is due), new connections
// made for clients' first Initials, timers fired, closed connections
// dropped.
fn serve_step(s: Server&, cfg: const tls::ServerConfig&, max_ms: i64) {
    for k in s.conns.len { if s.live[k] { server_flush(s, k); } }
    var next: i64 = 0;
    for k in s.conns.len {
        if !s.live[k] { continue; }
        let t = next_timeout(s.conns[k]);
        if t != 0 && (next == 0 || t < next) { next = t; }
    }
    let now0 = now_us();
    var timeout: i32 = max_ms as! i32;
    if next != 0 { timeout = ::max(::min((next - now0 + 999) / 1000, max_ms), 1) as! i32; }
    var buf: u8[2048] = [0; 2048];
    loop {
        let n, from = net::recv_from(s.fd, buf, timeout);
        if n <= 0 { break; }
        timeout = -1;
        let d = buf[..n];
        var k = route(s, d);
        if k < 0 {
            if server_accepts(d) {
                k = add_peer(s, cfg, d, from);
            } else {
                let vn = version_negotiation(d);
                if vn.len > 0 { let w = net::send_to(s.fd, vn, from); }
                continue;
            }
            if k < 0 { continue; }
        }
        s.addrs[k] = from;                 // the peer's address as it is now
        recv(s.conns[k], cfg, d, now_us());
    }
    let now = now_us();
    for k in s.conns.len {
        if !s.live[k] { continue; }
        let t = next_timeout(s.conns[k]);
        if t != 0 && t <= now { on_timeout(s.conns[k], now); }
        server_flush(s, k);
        if closed(s.conns[k]) { s.live[k] = false; }
    }
}

fn add_peer(s: Server&, cfg: const tls::ServerConfig&, d: const u8[:], from: const net::AddrPort&) -> i64 {
    var k: i64 = -1;
    for j in s.conns.len { if k < 0 && !s.live[j] { k = j; } }
    if k < 0 {
        if s.conns.len >= MAX_PEERS { return -1; }
        let c = server(cfg, d, now_us());
        s.conns.push(c);
        k = s.conns.len - 1;
    } else {
        s.conns[k] = server(cfg, d, now_us());
    }
    s.live[k] = true;
    s.fresh[k] = true;
    s.addrs[k] = from;
    return k;
}

// A connection made since the last call, or -1.
fn accept(s: Server&) -> i64 {
    for k in s.conns.len { if s.live[k] && s.fresh[k] { s.fresh[k] = false; return k; } }
    return -1;
}

fn shut_down(s: Server&) {
    for k in s.conns.len {
        if s.live[k] { close(s.conns[k], 0, "shutting down"); server_flush(s, k); }
    }
    net::close(s.fd);
    s.fd = -1;
}
