// net: sockets, after Go's net package, for the libraries that talk to a
// server or are one (http, ldap, dns, krb5, the tools' servers) and for
// programs: TCP connections with a deadline on connecting, reads and
// writes with timeouts, and a check whether an idle connection has been
// closed; listening and accepting; UDP, connected to one server or
// answering many; Unix-domain stream sockets; waiting on several sockets
// at once; the system resolver. POSIX (macOS, Linux) and Windows
// (Winsock). The C is net/src/net.c, compiled only into programs that
// call it. Addresses are net.ip's (Addr, AddrPort); host names outside
// ASCII, net.idna's.
//
//   import gslib.net;        // from a program; `import net;` inside gslib
//
//   let fd = net::dial("example.com", 80, 5000);
//   if fd < 0 { ... }                     // one of the ERR_* below
//   net::write(fd, req, 5000);
//   let n = net::read(fd, buf, 5000);     // > 0 bytes, 0 at the end, < 0 error
//   net::close(fd);
//
//   let l = net::listen("127.0.0.1", 8080);
//   let c = net::accept(l, 0);            // a connection, as dial's
//   let peer, e = net::peer_addr(c);      // an AddrPort
//
// A socket is an i64, as the system has it (a descriptor, a SOCKET), not
// a type of its own: the libraries above pass it around, wait on it and
// hand it to TLS, and a wrapper struct would only stand between them.
// Every result >= 0 is a success; a negative one is one of the ERR_*
// below. A timeout of 0 (or less) means none: read and write wait for
// ever, dial until the OS gives up.
//
// The libraries in net/ (http, ldap) are modules of their own, with their
// own namespaces; this one, ip and idna are `net::`.

namespace net;

import std;
import net.ip;

extern fn gsnet_dial(host: const u8[:], port: i32, timeout_ms: i32) -> i64;
extern fn gsnet_read(fd: i64, buf: u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_write(fd: i64, data: const u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_readable(fd: i64) -> i32;
extern fn gsnet_close(fd: i64);
extern fn gsnet_local_addr(fd: i64, out: u8[:]) -> i64;
extern fn gsnet_peer_addr(fd: i64, out: u8[:]) -> i64;
extern fn gsnet_lookup(host: const u8[:], out: u8[:]) -> i64;
extern fn gsnet_lookup_addr(addr: const u8[:], out: u8[:]) -> i64;
extern fn gsnet_listen(addr: const u8[:], port: i32, tcp: i32) -> i64;
extern fn gsnet_accept(fd: i64, timeout_ms: i32) -> i64;
extern fn gsnet_dial_udp(host: const u8[:], port: i32) -> i64;
extern fn gsnet_send(fd: i64, data: const u8[:]) -> i64;
extern fn gsnet_recv(fd: i64, buf: u8[:], from: u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_send_to(fd: i64, data: const u8[:], to: const u8[:]) -> i64;
extern fn gsnet_poll(fds: const i64[:], want: const u8[:], ready: u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_write_some(fd: i64, data: const u8[:]) -> i64;
extern fn gsnet_shutdown(fd: i64, how: i32) -> i64;
extern fn gsnet_dial_unix(path: const u8[:]) -> i64;

let ERR_ARG:     i64 = -1;  // a host or port that cannot be used (empty, too long, a NUL in it, port not 1-65535)
let ERR_RESOLVE: i64 = -2;  // the name does not resolve
let ERR_CONNECT: i64 = -3;  // refused or unreachable, at every address of the name
let ERR_TIMEOUT: i64 = -4;  // the timeout passed first
let ERR_IO:      i64 = -5;  // reset, or another error on the socket

let ADDR_LEN: i64 = 24;     // an address record, as net/src/net.c gives and takes it

// A connection to host:port: the socket, or ERR_ARG, ERR_RESOLVE,
// ERR_CONNECT or ERR_TIMEOUT. The host is a name or a numeric address,
// without brackets; each of its addresses is tried in turn until
// timeout_ms has passed. The timeout bounds connecting, not the name's
// lookup: getaddrinfo, which has no timeout of its own, takes as long as
// the system's resolver does (its own timeouts and retries), and the
// time it took comes off what is left to connect in. Give a
// numeric address to leave the resolver out. The socket has TCP_NODELAY
// set, and writing to one the peer closed gives ERR_IO, not SIGPIPE.
fn dial(host: const u8[:], port: i32, timeout_ms: i32) -> i64 {
    return gsnet_dial(host, port, timeout_ms);
}

// Up to buf.len bytes into buf: how many, 0 at the end of the stream,
// ERR_TIMEOUT if nothing came within timeout_ms, or ERR_IO.
fn read(fd: i64, buf: u8[:], timeout_ms: i32) -> i64 {
    return gsnet_read(fd, buf, timeout_ms);
}

// All of data: data.len, or ERR_TIMEOUT if the peer took nothing for
// timeout_ms (some of data may have gone), or ERR_IO.
fn write(fd: i64, data: const u8[:], timeout_ms: i32) -> i64 {
    return gsnet_write(fd, data, timeout_ms);
}

// Whether something has come on an idle connection, without waiting:
// bytes, its end, or an error. Either way a client cannot send it a new
// request, so a pool drops it.
fn readable(fd: i64) -> bool {
    return gsnet_readable(fd) != 0;
}

// Closes the connection; a negative fd is ignored.
fn close(fd: i64) {
    gsnet_close(fd);
}

// --- Addresses -------------------------------------------------------------

// An address record from the C: the 16 bytes, the kind, the port, the
// IPv6 scope id (as the zone's text: its number).
fn addr_port_of(r: const u8[:]) -> AddrPort {
    var ap = AddrPort { addr: no_addr(), port: 0 };
    if r.len < ADDR_LEN || (r[16] != 4 && r[16] != 6) { return ap; }
    for i in 16 { ap.addr.ip[i] = r[i]; }
    ap.addr.kind = r[16];
    ap.port = ((r[18] as i64) << 8) | r[19];
    let scope = ((r[20] as i64) << 24) | ((r[21] as i64) << 16) | ((r[22] as i64) << 8) | r[23];
    if scope != 0 { format_int(ap.addr.zone, scope, 10, 0, ' '); }
    return ap;
}

// An address and port as a record for the C; false for no address, a
// port out of range, or a zone that is not a scope id's number.
fn addr_record(ap: const AddrPort&, r: u8[:]) -> bool {
    if ap.addr.kind == 0 || ap.port < 0 || ap.port > 65535 || r.len < ADDR_LEN { return false; }
    for i in ADDR_LEN { r[i] = 0; }
    for i in 16 { r[i] = ap.addr.ip[i]; }
    r[16] = ap.addr.kind as! u8;
    r[18] = (ap.port >> 8) as! u8;
    r[19] = ap.port as! u8;
    var scope: i64 = 0;
    for c in ap.addr.zone {
        if c < '0' || c > '9' || scope > 0xfffffff { return false; }
        scope = scope * 10 + (c - '0');
    }
    if scope > 0xffffffff { return false; }
    r[20] = (scope >> 24) as! u8;
    r[21] = (scope >> 16) as! u8;
    r[22] = (scope >> 8) as! u8;
    r[23] = scope as! u8;
    return true;
}

// The address and port a socket is bound to (a listener's, after port
// 0), and 0; or an error.
fn local_addr(fd: i64) -> AddrPort, i64 {
    var r: u8[24] = [0; 24];
    let e = gsnet_local_addr(fd, r);
    return addr_port_of(r), if e < 0 { e } else { 0 };
}

fn local_port(fd: i64) -> i64 {
    let ap, e = local_addr(fd);
    return if e < 0 { e } else { ap.port };
}

// The other end of a connected socket (an accepted client), and 0; or an error.
fn peer_addr(fd: i64) -> AddrPort, i64 {
    var r: u8[24] = [0; 24];
    let e = gsnet_peer_addr(fd, r);
    return addr_port_of(r), if e < 0 { e } else { 0 };
}

// The system resolver's addresses for a host name (getaddrinfo: the hosts
// file, DNS, as the system is set up), each once, in its order; an
// address given as text comes back as it is. ERR_RESOLVE when there are
// none. For DNS itself, record by record, see gslib's dns.
fn lookup_host(host: const u8[:]) -> Addr[>..], i64 {
    var out: Addr[>..] = [];
    var r: u8[24 * 64] = [0; 24 * 64];
    let n = gsnet_lookup(host, r);
    if n < 0 { return out, n; }
    for i in n { out.push(copy(addr_port_of(r[i * ADDR_LEN..(i + 1) * ADDR_LEN]).addr)); }
    return out, 0;
}

// The name the system resolver has for an address (reverse DNS, the
// hosts file), and 0; ERR_RESOLVE when it has none.
fn lookup_addr(a: const Addr&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    var r: u8[24] = [0; 24];
    let ap = AddrPort { addr: copy(a), port: 0 };
    if !addr_record(ap, r) { return out, ERR_ARG; }
    var name: u8[1025] = [0; 1025];
    let n = gsnet_lookup_addr(r, name);
    if n < 0 { return out, n; }
    out.append(name[..n]);
    return out, 0;
}

// --- Listening -------------------------------------------------------------

// A TCP socket listening on addr:port: addr "" for every address (IPv6's
// and IPv4's where the system has one socket for both), port 0 for one
// the system picks (local_port says which). SO_REUSEADDR is set, the
// backlog is 64. The socket, or ERR_ARG, ERR_RESOLVE, or ERR_CONNECT (the
// address is in use, or not this machine's).
fn listen(addr: const u8[:], port: i64) -> i64 {
    if port < 0 || port > 65535 { return ERR_ARG; }
    return gsnet_listen(addr, port as! i32, 1);
}

// A connection on a listening socket, or ERR_TIMEOUT if none came within
// timeout_ms (0: wait for ever). It is as dial's are: blocking for
// read and write's timeouts, TCP_NODELAY, no SIGPIPE.
fn accept(fd: i64, timeout_ms: i32) -> i64 {
    return gsnet_accept(fd, timeout_ms);
}

// --- UDP -------------------------------------------------------------------

// A UDP socket for host:port: datagrams from anyone else are dropped by
// the system, and the source port is its random one. send and recv.
fn dial_udp(host: const u8[:], port: i64) -> i64 {
    if port <= 0 || port > 65535 { return ERR_ARG; }
    return gsnet_dial_udp(host, port as! i32);
}

// A UDP socket bound to addr:port (as listen's), for recv_from and send_to.
fn listen_udp(addr: const u8[:], port: i64) -> i64 {
    if port < 0 || port > 65535 { return ERR_ARG; }
    return gsnet_listen(addr, port as! i32, 0);
}

// One datagram on a dial_udp socket: its length, or ERR_ARG (more than
// 65535 bytes) or ERR_IO.
fn send(fd: i64, data: const u8[:]) -> i64 {
    return gsnet_send(fd, data);
}

// One datagram, up to buf.len bytes (the rest of a longer one is lost):
// its length, or ERR_TIMEOUT if none came within timeout_ms (0: wait for
// ever, < 0: only if one is there already). On a dial_udp socket a port
// that refused the last datagram shows as ERR_CONNECT.
fn recv(fd: i64, buf: u8[:], timeout_ms: i32) -> i64 {
    var none: u8[0] = [];
    return gsnet_recv(fd, buf, none, timeout_ms);
}

// recv, with who sent the datagram.
fn recv_from(fd: i64, buf: u8[:], timeout_ms: i32) -> i64, AddrPort {
    var r: u8[24] = [0; 24];
    let n = gsnet_recv(fd, buf, r, timeout_ms);
    return n, addr_port_of(r);
}

// One datagram to an address: its length, or an error.
fn send_to(fd: i64, data: const u8[:], to: const AddrPort&) -> i64 {
    var r: u8[24] = [0; 24];
    if !addr_record(to, r) { return ERR_ARG; }
    return gsnet_send_to(fd, data, r);
}

// --- Waiting, partial writes, shutting down --------------------------------

let WANT_READ: u8 = 1;
let WANT_WRITE: u8 = 2;

// Waits up to timeout_ms (0: wait for ever, < 0: not at all) for any of
// fds (at most 256; negative ones skipped) to be ready: to read (or at its
// end, or failed) where want[i] has WANT_READ, to take a write where it
// has WANT_WRITE. ready[i] gets the bits of want[i] that are: how many
// fds are ready, or ERR_TIMEOUT. On POSIX any descriptor (pipes,
// terminals) may be waited on, on Windows sockets only.
fn poll(fds: const i64[:], want: const u8[:], ready: u8[:], timeout_ms: i32) -> i64 {
    return gsnet_poll(fds, want, ready, timeout_ms);
}

// Which of two sockets (-1: none) has something to read: 1 for a, 2 for
// b, 3 for both, or ERR_TIMEOUT.
fn wait2(a: i64, b: i64, timeout_ms: i32) -> i64 {
    let fds: i64[2] = [a, b];
    let want: u8[2] = [WANT_READ, WANT_READ];
    var ready: u8[2] = [0; 2];
    let n = gsnet_poll(fds, want, ready, timeout_ms);
    if n < 0 { return n; }
    return (if ready[0] != 0 { 1 } else { 0 }) | (if ready[1] != 0 { 2 } else { 0 });
}

// One write of what fits without waiting: how many bytes went (0 when
// the socket is full; poll for WANT_WRITE), or ERR_IO.
fn write_some(fd: i64, data: const u8[:]) -> i64 {
    return gsnet_write_some(fd, data);
}

let SHUT_READ: i32 = 1;
let SHUT_WRITE: i32 = 2;
let SHUT_BOTH: i32 = 3;

// Ends reading, writing (the peer reads the end of the stream; reading
// goes on) or both: 0, or ERR_IO.
fn shutdown(fd: i64, how: i32) -> i64 {
    return gsnet_shutdown(fd, how);
}

// --- Unix-domain sockets ---------------------------------------------------

// A stream connection to the Unix-domain socket at path (an ldapi:// one,
// a daemon's), as dial's: the socket, ERR_ARG for a path too long (about
// 100 bytes), or ERR_CONNECT. Windows 10 1803 and later have them too.
fn dial_unix(path: const u8[:]) -> i64 {
    return gsnet_dial_unix(path);
}
