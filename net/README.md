# net

Sockets and IP addresses for Goose, after Go's `net` and `net/netip`, on
POSIX (macOS, Linux) and Windows (Winsock). It is what gslib's http, ldap,
dns and krb5 talk through, and what their tools serve on. Three modules,
one namespace:

| Module | What | Go |
|---|---|---|
| `gslib.net` | TCP connections and listeners, UDP, Unix-domain stream sockets, waiting on several sockets, the system resolver | net |
| `gslib.net.ip` | IP addresses and prefixes: parsing, canonical printing, classes, host:port | net/netip, net.SplitHostPort |
| `gslib.net.idna` | host names outside ASCII as `xn--` Punycode | x/net/idna's ToASCII, as cookiejar uses it |

```goose
import gslib from "SorinS/gslib@v0.9.4";
import gslib.net;
import gslib.net.ip;

fn main() {
    let l = net::listen("127.0.0.1", 0);           // port 0: the system picks
    let at, e = net::local_addr(l);
    let c = net::dial("127.0.0.1", at.port as! i32, 5000);
    let s = net::accept(l, 5000);
    net::write(c, "ping", 5000);
    var buf: u8[64] = [0; 64];
    let n = net::read(s, buf, 5000);
    let peer, pe = net::peer_addr(s);
    print(buf[..n], " from ", peer);              // ping from 127.0.0.1:52811
}
```

A socket is an `i64`, as the system has it (a descriptor, a `SOCKET`),
not a type of its own: the libraries above pass it around, wait on it and
hand it to TLS, and a wrapper would stand between them. Every result >= 0
is a success; a negative one is an `ERR_*`: `ERR_ARG` (a host, port or
buffer that cannot be used), `ERR_RESOLVE`, `ERR_CONNECT` (refused,
unreachable, or an address in use), `ERR_TIMEOUT`, `ERR_IO`. A timeout of
0 means none.

## net: sockets

| | |
|---|---|
| `dial(host, port, timeout_ms)` | A TCP connection: each of the name's addresses in turn until the timeout; TCP_NODELAY, no SIGPIPE |
| `read(fd, buf, timeout_ms)`, `write(fd, data, timeout_ms)` | Up to `buf.len` bytes (0 at the end), all of `data`; neither ever blocks past its timeout, a peer that stops reading included |
| `readable(fd)`, `close(fd)` | Whether an idle connection has news (its end, most often), for a pool |
| `listen(addr, port)`, `accept(fd, timeout_ms)` | A listener (`addr` "" for every address, port 0 for any), SO_REUSEADDR, a backlog of 64; a connection, as dial's |
| `local_addr(fd)`, `local_port(fd)`, `peer_addr(fd)` | Both ends, as `AddrPort` |
| `dial_udp(host, port)`, `send(fd, data)`, `recv(fd, buf, timeout_ms)` | UDP connected to one peer: the system drops anyone else's datagrams |
| `listen_udp(addr, port)`, `recv_from(fd, buf, timeout_ms)`, `send_to(fd, data, to)` | UDP answering many, with each sender's `AddrPort` |
| `poll(fds, want, ready, timeout_ms)`, `wait2(a, b, timeout_ms)` | Waiting on up to 256 sockets for `WANT_READ` and `WANT_WRITE` (on POSIX any descriptor) |
| `write_some(fd, data)`, `shutdown(fd, how)` | What fits without waiting; ending reading, writing (`SHUT_WRITE`: the peer reads the end) or both |
| `dial_unix(path)` | A Unix-domain stream socket (an `ldapi://` one); Windows 10 1803 and later have them too |
| `lookup_host(name)`, `lookup_addr(addr)` | The system resolver (getaddrinfo: the hosts file, DNS), and the name an address has back. DNS itself, record by record, is gslib's dns |

`recv` takes a timeout below 0 as "only if one is there already", which
is what a server that has just polled wants.

## net.ip: addresses

An `Addr` keeps 16 bytes (IPv4 as `::ffff:a.b.c.d`), its kind (4, 6, or
0 for none) and an IPv6 zone. Parsing follows Go's netip: no leading zeros
in IPv4 parts, at most four hex digits a group, `::` for at least one
group. An IPv4-mapped address is IPv6 and prints as `::ffff:1.2.3.4`;
`unmap` makes it IPv4.

| | |
|---|---|
| `parse_addr(s)`, `addr_from_bytes(b)`, `addr_v4(a, b, c, d)`, `addr_bytes(a)` | From text, from 4 or 16 wire bytes, and back |
| `format(out, a)`, `addr_string(a)` | Dotted IPv4; IPv6 as RFC 5952 has it (lower case, the longest run of zero groups as `::`); `print` takes an `Addr` |
| `is_loopback`, `is_private`, `is_unspecified`, `is_link_local_unicast`, `is_link_local_multicast`, `is_multicast`, `is_global_unicast` | As Go's, a mapped address judged as the IPv4 one |
| `addr_equal`, `is_4`, `is_6`, `is_4_in_6`, `unmap` | |
| `parse_addr_port(s)`, `addr_port_string(ap)` | `1.2.3.4:80`, `[::1]:80`, `[fe80::1%eth0]:80` |
| `split_host_port(s)`, `join_host_port(host, port)` | Go's: brackets for a host with a colon |
| `parse_prefix(s)`, `prefix_contains(p, a)`, `prefix_masked(p)`, `prefix_string(p)` | `10.0.0.0/8`, `2001:db8::/32`; an IPv4 prefix does not hold a mapped address |
| `parse_ip(s)`, `parse_ip_zone(s)`, `is_ip(s)`, `ip_is_loopback(ip, kind)` | The bytes and kind alone, as http's URL and cookie code use them |

## net.idna

`to_ascii_host(name)` gives each label with a byte past 0x7f as `xn--`
and its Punycode (RFC 3492), letters lowered in such labels only; names
already ASCII come back unchanged. `punycode_encode(out, label)` is one
label's. There is no IDNA2008 mapping or validation beyond that.

## How it works

The C is `net/src/net.c`, named in `gslib.build` and compiled only into
programs that call it. An address crosses between it and Goose as a
24-byte record (the 16 bytes, the kind, the port, the scope id), never as
a sockaddr. Connections are blocking sockets that `read` and `write`
drive with poll and short non-blocking calls, so no call waits past its
timeout; listening and UDP sockets are non-blocking, and `accept` and
`recv` wait for them, so a connection reset before accept or a datagram
dropped for its checksum cannot hang a server. Windows needs ws2_32 and
nothing else.

## Examples and tests

```bash
goose examples/net/echo.goose            # a TCP echo server and clients in one program, by poll
goose examples/net/udp.goose             # datagrams both ways, with the sender's address
goose examples/net/lookup.goose -- example.com
goose examples/net/addresses.goose       # parsing, printing, classes, an allow list of prefixes
python3 net/scripts/run_tests.py [--native]
python3 net/scripts/net_check.py [--cc CC | --msvc]   # src/net.c alone, without Goose
```

`test/ip.goose` checks parsing (Go's cases, accepted and refused),
printing and its round trip, every class, host:port, prefixes and
Go's cookiejar Punycode vectors. `test/sockets.goose` runs on 127.0.0.1
(and `::1` where the host has it): accept timing out, both ends'
addresses, poll for reading and writing, `write_some` filling a socket
that is not read, half-closing, UDP both ways with a datagram cut to its
buffer, the resolver, and each error. `scripts/net_check.py` builds
`test/native/net_drive.c` with `src/net.c` and runs it against servers
of its own.
