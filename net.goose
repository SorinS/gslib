// net: TCP client sockets, after the client half of Go's net package, for
// the libraries that talk to a server (http.client, dns, krb5) and for
// programs: a connection with a deadline on connecting, reads and writes
// with timeouts, and a check whether an idle connection has been closed.
// POSIX (macOS, Linux) and Windows (Winsock). The C is net/src/net.c,
// compiled only into programs that call it.
//
//   import gslib.net;        // from a program; `import net;` inside gslib
//
//   let fd = net::dial("example.com", 80, 5000);
//   if fd < 0 { ... }                     // one of the ERR_* below
//   net::write(fd, req, 5000);
//   let n = net::read(fd, buf, 5000);     // > 0 bytes, 0 at the end, < 0 error
//   net::close(fd);
//
// A connection is an i64, the socket. Every result >= 0 is a success; a
// negative one is one of the ERR_* below. A timeout of 0 (or less) means
// none: read and write wait for ever, dial until the OS gives up.
//
// The libraries in net/ (http, ldap) are modules of their own, with their
// own namespaces; this one is `net::`.

namespace net;

extern fn gsnet_dial(host: const u8[:], port: i32, timeout_ms: i32) -> i64;
extern fn gsnet_read(fd: i64, buf: u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_write(fd: i64, data: const u8[:], timeout_ms: i32) -> i64;
extern fn gsnet_readable(fd: i64) -> i32;
extern fn gsnet_close(fd: i64);

let ERR_ARG:     i64 = -1;  // a host or port that cannot be used (empty, too long, a NUL in it, port not 1-65535)
let ERR_RESOLVE: i64 = -2;  // the name does not resolve
let ERR_CONNECT: i64 = -3;  // refused or unreachable, at every address of the name
let ERR_TIMEOUT: i64 = -4;  // the timeout passed first
let ERR_IO:      i64 = -5;  // reset, or another error on the socket

// A connection to host:port: the socket, or ERR_ARG, ERR_RESOLVE,
// ERR_CONNECT or ERR_TIMEOUT. The host is a name or a numeric address,
// without brackets; each of its addresses is tried in turn until
// timeout_ms has passed. The socket has TCP_NODELAY set, and writing to
// one the peer closed gives ERR_IO, not SIGPIPE.
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
