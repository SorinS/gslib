// net's sockets on 127.0.0.1 (and ::1 where the host has it): listening,
// accepting with a timeout, both ends' addresses, reads and writes,
// waiting on several sockets, half-closing, partial writes; UDP connected
// and unconnected, with the sender's address; the system resolver; the
// errors. Only failures are printed.

import std;
import gslib from "../..";
import gslib.net;
import gslib.net.ip;

var failed = 0;

fn check(ok: bool, what: const u8[:]) {
    if !ok { print("FAIL ", what); failed += 1; }
}

fn tcp(host: const u8[:]) {
    let l = net::listen(host, 0);
    check(l >= 0, str("listen ", host));
    if l < 0 { return; }
    let la, le = net::local_addr(l);
    check(le == 0 && la.port > 0 && net::addr_string(la.addr) == host, str("local_addr ", host));
    check(net::accept(l, 50) == net::ERR_TIMEOUT, "accept: nothing yet");

    let c = net::dial(host, la.port as! i32, 2000);
    let s = net::accept(l, 2000);
    check(c >= 0 && s >= 0, str("dial and accept ", host));
    let peer, pe = net::peer_addr(s);
    let mine, me = net::local_addr(c);
    check(pe == 0 && me == 0 && peer.port == mine.port && net::addr_equal(peer.addr, mine.addr), "peer_addr is the dialer's local_addr");
    let back, be = net::peer_addr(c);
    check(be == 0 && back.port == la.port, "the dialer's peer is the listener");

    // c can take a write at once; s has nothing until c writes.
    let fds: i64[3] = [s, c, -1];
    let want: u8[3] = [net::WANT_READ, net::WANT_WRITE, net::WANT_READ];
    var ready: u8[3] = [0; 3];
    check(net::poll(fds, want, ready, 1000) == 1 && ready[0] == 0 && ready[1] == net::WANT_WRITE && ready[2] == 0, "poll: writable, not readable");
    check(net::write(c, "ping", 1000) == 4, "write");
    check(net::poll(fds[..1], want[..1], ready[..1], 2000) == 1 && ready[0] == net::WANT_READ, "poll: readable");
    var buf: u8[64] = [0; 64];
    let n = net::read(s, buf, 1000);
    check(n == 4 && buf[..4] == "ping", "read");
    check(net::read(s, buf, 50) == net::ERR_TIMEOUT, "read: times out");
    check(net::wait2(s, -1, 50) == net::ERR_TIMEOUT, "wait2: nothing");

    // write_some never waits: a peer that does not read fills the socket.
    var big: u8[>..] = [];
    big.resize(1 << 16, 'x');
    var sent: i64 = 0;
    var full = false;
    for k in 2000 {
        let w = net::write_some(c, big);
        if w < 0 { break; }
        if w == 0 { full = true; break; }
        sent += w;
    }
    check(full && sent > 0, "write_some: stops at a full socket");
    var drained: i64 = 0;
    var chunk: u8[>..] = [];
    chunk.resize(1 << 16, 0);
    while drained < sent {
        let r = net::read(s, chunk, 2000);
        if r <= 0 { break; }
        drained += r;
    }
    check(drained == sent, "everything write_some sent arrives");

    // Half-closed: s reads the end, and can still write to c.
    check(net::shutdown(c, net::SHUT_WRITE) == 0, "shutdown");
    check(net::read(s, buf, 1000) == 0, "the end after shutdown");
    check(net::write(s, "pong", 1000) == 4 && net::read(c, buf, 1000) == 4 && buf[..4] == "pong", "the other way still open");
    check(net::shutdown(s, net::SHUT_WRITE) == 0 && net::wait2(-1, c, 1000) == 2 && net::read(c, buf, 1000) == 0, "wait2: the end is news");
    net::close(c);
    net::close(s);
    net::close(l);
}

fn udp() {
    let u = net::listen_udp("127.0.0.1", 0);
    let port = net::local_port(u);
    check(u >= 0 && port > 0, "listen_udp");
    var buf: u8[64] = [0; 64];
    check(net::recv(u, buf, 50) == net::ERR_TIMEOUT && net::recv(u, buf, -1) == net::ERR_TIMEOUT, "recv: nothing");
    let c = net::dial_udp("127.0.0.1", port);
    check(c >= 0 && net::send(c, "hello") == 5, "dial_udp, send");
    let n, from = net::recv_from(u, buf, 2000);
    check(n == 5 && buf[..5] == "hello", "recv_from");
    check(net::addr_string(from.addr) == "127.0.0.1" && from.port == net::local_port(c), "the sender's address");
    check(net::send_to(u, "back", from) == 4, "send_to");
    let r = net::recv(c, buf, 2000);
    check(r == 4 && buf[..4] == "back", "the reply");
    // Truncated: the rest of a datagram larger than the buffer is lost.
    check(net::send(c, "0123456789") == 10, "send 10");
    var small: u8[4] = [0; 4];
    let t, tf = net::recv_from(u, small, 2000);
    check(t == 4 && small[..] == "0123", "a datagram cut to the buffer");
    check(net::recv(u, buf, 50) == net::ERR_TIMEOUT, "and the rest gone");
    let none = net::AddrPort { addr: net::no_addr(), port: 1 };
    check(net::send_to(u, "x", none) == net::ERR_ARG, "send_to: no address");
    check(net::send(c, big_datagram()) == net::ERR_ARG, "send: more than 65535 bytes");
    net::close(c);
    net::close(u);
}

fn big_datagram() -> u8[>..] {
    var b: u8[>..] = [];
    b.resize(70000, 0);
    return b;
}

fn resolver() {
    let hs, he = net::lookup_host("localhost");
    var seen = false;
    for a in hs { if net::is_loopback(a) { seen = true; } }
    check(he == 0 && seen, "lookup_host localhost");
    let lit, le = net::lookup_host("192.0.2.7");
    check(le == 0 && lit.len == 1 && net::addr_string(lit[0]) == "192.0.2.7", "lookup_host of an address");
    let bad, be = net::lookup_host("no-such-host.invalid");
    check(be == net::ERR_RESOLVE && bad.len == 0, "lookup_host: no such name");
    let lo = net::addr_v4(127, 0, 0, 1);
    let name, ne = net::lookup_addr(lo);
    check((ne == 0 && name.len > 0) || ne == net::ERR_RESOLVE, "lookup_addr");
}

fn errors() {
    check(net::dial("", 80, 1000) == net::ERR_ARG && net::dial("h", 0, 1000) == net::ERR_ARG, "dial: bad arguments");
    check(net::dial("no-such-host.invalid", 80, 2000) == net::ERR_RESOLVE, "dial: no such name");
    let l = net::listen("127.0.0.1", 0);
    let port = net::local_port(l);
    net::close(l);
    // Windows tries a refused SYN again for about two seconds.
    check(net::dial("127.0.0.1", port as! i32, 10000) == net::ERR_CONNECT, "dial: refused");
    check(net::listen("127.0.0.1", 70000) == net::ERR_ARG && net::listen_udp("127.0.0.1", -1) == net::ERR_ARG, "listen: bad port");
    check(net::listen("192.0.2.1", 0) == net::ERR_CONNECT, "listen: not this machine's address");
    check(net::dial_unix("/no/such/dir/sock") == net::ERR_CONNECT, "dial_unix: nothing there");
    var long: u8[>..] = [];
    long.resize(300, 'a');
    check(net::dial_unix(long) == net::ERR_ARG, "dial_unix: path too long");
    let none: i64[1] = [-1];
    let want: u8[1] = [net::WANT_READ];
    var ready: u8[1] = [0];
    check(net::poll(none, want, ready, 10) == net::ERR_ARG, "poll: nothing to wait on");
}

fn main() {
    tcp("127.0.0.1");
    // IPv6 where the host has it.
    let six = net::listen("::1", 0);
    if six >= 0 { net::close(six); tcp("::1"); }
    udp();
    resolver();
    errors();
    if failed > 0 { print(failed, " failed"); exit(1); }
    print("sockets: all passed");
}
