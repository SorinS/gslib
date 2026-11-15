// dns.client: queries, as miekg's Client has them: a message over UDP or
// TCP to a server, its reply matched by ID and question, TSIG on both,
// and zone transfers in (AXFR, IXFR); resolv.conf read as miekg's
// ClientConfigFromFile reads it.
//
//   var c = dns::Client { .. };
//   var q = dns::Msg { .. };
//   dns::set_question(q, "example.org.", dns::TYPE_MX);
//   var r = dns::Msg { .. };
//   let e = dns::exchange(c, q, "192.0.2.53", r);       // "host", "host:port", "[v6]:port"
//
// Over UDP the socket is connected to the server, so the kernel drops
// datagrams from anyone else, and a datagram that is not the reply (its ID
// or question differ, or it does not parse) is ignored until the timeout.
// A truncated reply comes back as it is (miekg does the same), unless
// tcp_fallback is set, which asks again over TCP.

namespace dns;

import std;
import os;
import dns;
import dns.rdata;
import dns.msg;
import dns.edns;
import dns.tsig;
import dns.zone;
import net;

extern fn dnsnet_udp_open(host: const u8[:], port: i32) -> i64;
extern fn dnsnet_send(fd: i64, data: const u8[:]) -> i64;
extern fn dnsnet_recv(fd: i64, buf: u8[:], timeout_ms: i32) -> i64;
extern fn dnsnet_close(fd: i64);

let NET_UDP: u8 = 0;
let NET_TCP: u8 = 1;

struct Client {
    net: u8 = 0,                   // NET_UDP or NET_TCP
    timeout_ms: i32 = 2000,        // miekg's dial and read timeouts
    tcp_fallback: bool = false,    // ask again over TCP when a UDP reply is truncated
    udp_size: u16 = 0,             // the buffer for UDP replies: 0 for the query's EDNS0 size, else 512
    tsig_name: u8[..255] = "",     // TSIG: key name (text), algorithm, secret; none when the name is ""
    tsig_alg: u8[..64] = "hmac-sha256.",
    tsig_secret: u8[..128] = "",
    tsig_fudge: u16 = 300,
}

// "host", "host:port", "[v6]" or "[v6]:port": the host and port (53 when
// none is given); a bare IPv6 address is a host too.
fn split_host_port(s: const u8[:]) -> const u8[:], i32, bool {
    if s.len > 0 && s[0] == '[' {
        var i = 1;
        while i < s.len && s[i] != ']' { i++; }
        if i >= s.len { return s, 0, false; }
        let host = s[1..i];
        if i + 1 == s.len { return host, 53, true; }
        if s[i + 1] != ':' { return s, 0, false; }
        let p = uint_parse(s[i + 2 ..], 65535);
        return host, p as! i32, p > 0;
    }
    var colons = 0;
    var last = -1;
    for i in s.len { if s[i] == ':' { colons++; last = i; } }
    if colons != 1 { return s, 53, s.len > 0; }
    let p = uint_parse(s[last + 1 ..], 65535);
    return s[..last], p as! i32, p > 0 && last > 0;
}

fn net_error(n: i64) -> i64 {
    if n == -4 { return ERR_TIMEOUT; }
    return ERR_IO;
}

// Whether reply answers query: the same ID, and the same question when it
// has one (a FORMERR may come back without).
fn reply_matches(query: const u8[:], reply: const u8[:]) -> bool {
    if reply.len < 12 || get16(reply, 0) != get16(query, 0) || get16(reply, 2) & 0x8000 == 0 { return false; }
    if get16(reply, 4) == 0 { return true; }
    if get16(query, 4) == 0 { return true; }
    let qn, qe, e1 = read_name(query, 12);
    let rn, re, e2 = read_name(reply, 12);
    if e1 != OK || e2 != OK || qe + 4 > query.len || re + 4 > reply.len { return false; }
    return name_equal(qn, rn) && query[qe .. qe + 4] == reply[re .. re + 4];
}

// The packed query, TSIG-signed if the client has a key: its MAC.
fn pack_query(c: const Client&, m: Msg&, w: u8[>..]&) -> u8[>..], i64 {
    var mac: u8[>..] = [];
    let e = pack(m, w);
    if e != OK { return mac, e; }
    if c.tsig_name.len > 0 {
        let secret, ok = tsig_secret(c.tsig_secret);
        if !ok { return mac, ERR_SECRET; }
        let m2, e2 = tsig_sign(w, c.tsig_name, c.tsig_alg, secret, c.tsig_fudge, time_ns() / 1000000000, [], false);
        return m2, e2;
    }
    return mac, OK;
}

fn check_reply_tsig(c: const Client&, w: const u8[:], request_mac: const u8[:], timers_only: bool) -> u8[>..], i64 {
    var none: u8[>..] = [];
    if c.tsig_name.len == 0 { return none, OK; }
    let secret, ok = tsig_secret(c.tsig_secret);
    let mac, e = tsig_verify(w, secret, request_mac, timers_only, time_ns() / 1000000000);
    return mac, e;
}

// One query over UDP: the raw reply into out.
fn exchange_udp(c: const Client&, query: const u8[:], host: const u8[:], port: i32, bufsize: i64, out: u8[>..]&) -> i64 {
    let fd = dnsnet_udp_open(host, port);
    if fd < 0 { return if fd == -2 { ERR_IO } else { ERR_IO }; }
    defer dnsnet_close(fd);
    if dnsnet_send(fd, query) != query.len { return ERR_IO; }
    let deadline = clock_ns() + c.timeout_ms as i64 * 1000000;
    // Room for any datagram, whatever was asked for: one larger than
    // bufsize is not cut short (and misread) by the receive.
    var buf: u8[>..] = [];
    buf.resize(65535, 0);
    while true {
        let left = (deadline - clock_ns()) / 1000000;
        if left <= 0 { return ERR_TIMEOUT; }
        let n = dnsnet_recv(fd, buf, left as! i32);
        if n < 0 { return net_error(n); }
        if reply_matches(query, buf[..n]) {
            out.append(buf[..n]);
            return OK;
        }
    }
    return ERR_TIMEOUT;
}

// Milliseconds left until deadline (clock_ns); 0 once it has passed.
fn ms_left(deadline: i64) -> i32 {
    let l = (deadline - clock_ns()) / 1000000;
    return if l <= 0 { 0 } else if l > 0x7fffffff { 0x7fffffff } else { l as! i32 };
}

// Reads exactly n bytes from a TCP connection onto out, all of them by
// deadline (clock_ns): a peer that trickles them in gets no more time.
fn read_full(fd: i64, n: i64, out: u8[>..]&, deadline: i64) -> i64 {
    let start = out.len;
    out.resize(start + n, 0);
    var got = 0;
    while got < n {
        let left = ms_left(deadline);
        if left == 0 { out.resize(start); return ERR_TIMEOUT; }
        let r = net::read(fd, out[start + got .. start + n], left);
        if r <= 0 { out.resize(start); return if r == 0 { ERR_IO } else { net_error(r) }; }
        got += r;
    }
    return OK;
}

// One message off a TCP stream (RFC 1035 §4.2.2's two-byte length first),
// the whole of it within timeout_ms.
fn read_tcp_msg(fd: i64, out: u8[>..]&, timeout_ms: i32) -> i64 {
    return read_tcp_msg_by(fd, out, clock_ns() + timeout_ms as i64 * 1000000);
}

fn read_tcp_msg_by(fd: i64, out: u8[>..]&, deadline: i64) -> i64 {
    var len: u8[>..] = [];
    let e = read_full(fd, 2, len, deadline);
    if e != OK { return e; }
    return read_full(fd, get16(len, 0), out, deadline);
}

fn write_tcp_msg(fd: i64, w: const u8[:], timeout_ms: i32) -> i64 {
    if w.len > 65535 { return ERR_BUF; }
    var framed: u8[>..] = [];
    put16(framed, w.len as! u16);
    framed.append(w);
    return if net::write(fd, framed, timeout_ms) == framed.len { OK } else { ERR_IO };
}

fn exchange_tcp(c: const Client&, query: const u8[:], host: const u8[:], port: i32, out: u8[>..]&) -> i64 {
    let fd = net::dial(host, port, c.timeout_ms);
    if fd < 0 { return net_error(fd); }
    defer net::close(fd);
    let we = write_tcp_msg(fd, query, c.timeout_ms);
    if we != OK { return we; }
    while true {
        let start = out.len;
        let e = read_tcp_msg(fd, out, c.timeout_ms);
        if e != OK { return e; }
        if reply_matches(query, out[start..]) { return OK; }
        out.resize(start);
    }
    return ERR_IO;
}

// Sends m to server and reads the reply into r (miekg's Client.Exchange).
// OK, ERR_TIMEOUT, ERR_IO, an unpacking error, or a TSIG one.
fn exchange(c: const Client&, m: Msg&, server: const u8[:], r: Msg&) -> i64 {
    var raw: u8[>..] = [];
    return exchange_raw(c, m, server, r, raw);
}

// The same, keeping the reply's bytes in raw.
fn exchange_raw(c: const Client&, m: Msg&, server: const u8[:], r: Msg&, raw: u8[>..]&) -> i64 {
    let host, port, ok = split_host_port(server);
    if !ok { return ERR_IO; }
    var w: u8[>..] = [];
    let mac, pe = pack_query(c, m, w);
    if pe != OK { return pe; }
    raw.clear();
    var e: i64 = OK;
    if c.net == NET_TCP {
        e = exchange_tcp(c, w, host, port, raw);
    } else {
        var size = c.udp_size as i64;
        if size == 0 { size = udp_size(m); }
        if size < 512 { size = 512; }
        e = exchange_udp(c, w, host, port, size, raw);
        if e == OK && c.tcp_fallback && raw.len >= 4 && get16(raw, 2) & 0x0200 != 0 {
            raw.clear();
            e = exchange_tcp(c, w, host, port, raw);
        }
    }
    if e != OK { return e; }
    let ue = unpack(raw, r);
    if ue != OK { return ue; }
    let rm, te = check_reply_tsig(c, raw, mac, false);
    return te;
}

// A query for name and type to the server (miekg's dns.Exchange with a
// fresh message): recursion desired, EDNS0 with a 1232-byte buffer, over
// UDP, then TCP if the reply is truncated.
fn query(server: const u8[:], qname: const u8[:], qtype: u16, r: Msg&) -> i64 {
    var c = Client { .. };
    c.tcp_fallback = true;
    var m = Msg { .. };
    let e = set_question(m, qname, qtype);
    if e != OK { return e; }
    set_edns0(m, 1232, false);
    return exchange(c, m, server, r);
}

// --- Zone transfers ------------------------------------------------------------------

// The serial of an SOA record's rdata; false if the rdata is not an SOA's.
fn soa_serial_of(rd: const u8[:]) -> u32, bool {
    if !rdata_valid(TYPE_SOA, rd) { return 0, false; }
    let a = name_len_at(rd, 0);
    let b = name_len_at(rd, a);
    return get32(rd, a + b), true;
}

// The serial of an SOA record's rdata, 0 if the rdata is not an SOA's.
fn soa_serial(rd: const u8[:]) -> u32 {
    let s, ok = soa_serial_of(rd);
    return s;
}

// One message of a zone transfer's reply, raw, to the query w, into r:
// it must answer w, say NOERROR, and, when the client has a key, be
// signed over mac (the request's MAC for the first, else the message
// before's), which then becomes its MAC.
fn xfr_message(c: const Client&, w: const u8[:], raw: const u8[:], r: Msg&, mac: u8[>..]&, first: bool) -> i64 {
    if !reply_matches(w, raw) { return ERR_ID; }
    let ue = unpack(raw, r);
    if ue != OK { return ue; }
    if r.hdr.rcode != RCODE_SUCCESS { return ERR_XFR; }
    if c.tsig_name.len > 0 {
        let m2, te = check_reply_tsig(c, raw, mac, !first);
        if te != OK { return te; }
        mac.clear();
        mac.append(m2);
    }
    return OK;
}

// A zone transfer in (miekg's Transfer.In): m is an AXFR query, or an
// IXFR query with the SOA the client has in its authority section. Every
// message of the reply is passed to F(r) as it arrives, TSIG-verified
// when the client has a key (the first over the request's MAC, the rest
// over the one before, timers only); the transfer ends at the closing SOA.
// With a key every message must be signed: RFC 8945 §5.3.1 lets a server
// sign only every 100th, and miekg takes the unsigned ones between, but
// those could be anyone's. ERR_XFR for a refused or broken transfer,
// ERR_SOA when the first record is not an SOA.
fn transfer_in<F>(c: const Client&, m: Msg&, server: const u8[:]) -> i64 {
    let host, port, ok = split_host_port(server);
    if !ok { return ERR_IO; }
    var w: u8[>..] = [];
    var mac, pe = pack_query(c, m, w);
    if pe != OK { return pe; }
    var ixfr = false;
    each_question(m.question) { q => ixfr = q.qtype == TYPE_IXFR; };
    let fd = net::dial(host, port, c.timeout_ms);
    if fd < 0 { return net_error(fd); }
    defer net::close(fd);
    let we = write_tcp_msg(fd, w, c.timeout_ms);
    if we != OK { return we; }
    var first = true;
    var first_serial: u32 = 0;
    var soas = 0;
    var r = Msg { .. };
    var raw: u8[>..] = [];
    while true {
        raw.clear();
        let e = read_tcp_msg(fd, raw, c.timeout_ms);
        if e != OK { return e; }
        let xe = xfr_message(c, w, raw, r, mac, first);
        if xe != OK { return xe; }
        var done = false;
        var k = 0;
        each_rr(r.answer) { rr =>
            var serial: u32 = 0;
            if rr.rtype == TYPE_SOA {
                let s, sok = soa_serial_of(rr.rdata(r.answer));
                if !sok { return ERR_XFR; }
                serial = s;
            }
            if first && k == 0 {
                if rr.rtype != TYPE_SOA { return ERR_SOA; }
                first_serial = serial;
            }
            if rr.rtype == TYPE_SOA && serial == first_serial {
                soas++;
                // AXFR: the second SOA closes it. IXFR: the first SOA's serial again,
                // as the last record, closes it (one SOA alone: nothing changed).
                if (!ixfr && soas == 2) || (ixfr && soas >= 2 && k > 0) { done = true; }
            }
            k++;
        };
        if ixfr && first && rr_count(r.answer) == 1 { done = true; }
        first = false;
        F(r);
        if done { return OK; }
    }
    return ERR_XFR;
}

// --- resolv.conf -----------------------------------------------------------------------

// What resolv.conf says (miekg's ClientConfig): servers, search domains,
// the port, ndots, the timeout in seconds and the attempts.
struct ClientConfig {
    servers: u8[..64][..8] = [],
    search: u8[..253][..6] = [],
    port: i32 = 53,
    ndots: i64 = 1,
    timeout: i64 = 5,
    attempts: i64 = 2,
}

// Reads resolv.conf text (miekg's ClientConfigFromReader): nameserver,
// domain and search (the last one wins), and options ndots: (0 to 15),
// timeout: and attempts: (at least 1); a value that is not a number is 0.
fn client_config(text: const u8[:]) -> ClientConfig {
    var c = ClientConfig { .. };
    each_split(text, '\n') { line =>
        let ws = words(line);
        if ws.len > 0 {
            let k = ws[0];
            if k == "nameserver" && ws.len > 1 && c.servers.len < 8 && ws[1].len <= 64 {
                var s: u8[..64] = [];
                s.append(ws[1]);
                c.servers.push(s);
            } else if k == "domain" || k == "search" {
                c.search.clear();
                let last = if k == "domain" { min(ws.len, 2) } else { ws.len };
                for i in 1 .. last {
                    if c.search.len < 6 && ws[i].len <= 253 {
                        var s: u8[..253] = [];
                        s.append(ws[i]);
                        c.search.push(s);
                    }
                }
            } else if k == "options" {
                for i in 1 .. ws.len {
                    let name, val, has = split_once(ws[i], ':');
                    var n, ok = parse_int(val);
                    if !ok { n = 0; }
                    if has && name == "ndots" { c.ndots = if n < 0 { 0 } else if n > 15 { 15 } else { n }; }
                    else if has && name == "timeout" { c.timeout = if n < 1 { 1 } else { n }; }
                    else if has && name == "attempts" { c.attempts = if n < 1 { 1 } else { n }; }
                }
            }
        }
    };
    return c;
}

fn client_config_file(path: const u8[:]) -> ClientConfig, bool {
    var text: u8[>..] = [];
    if !read_file(path, text) { return ClientConfig { .. }, false; }
    return client_config(text), true;
}

// The names to try for name, in order (miekg's ClientConfig.NameList): a
// fully qualified name alone; else the name first when it has more labels
// than ndots, then with each search domain, then the name last if it was
// not first.
fn name_list(cfg: const ClientConfig&, name: const u8[:]) -> u8[..256][>..] {
    var out: u8[..256][>..] = [];
    var one: u8[..256] = [];
    if is_fqdn(name) { one.append(name); out.push(one); return out; }
    let n, e = name_parse(name, [0]);
    let has_ndots = e == OK && label_count(n) > cfg.ndots;
    if has_ndots { one.append(name); one.push('.'); out.push(one); }
    for s in cfg.search {
        if name.len + 2 + s.len <= 256 {
            one.clear(); one.append(name); one.push('.'); one.append(s);
            if !is_fqdn(one) { one.push('.'); }
            out.push(one);
        }
    }
    if !has_ndots { one.clear(); one.append(name); one.push('.'); out.push(one); }
    return out;
}
