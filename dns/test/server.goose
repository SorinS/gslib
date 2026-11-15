// dns.server in one process: the handler's Peer over UDP and TCP, on
// 127.0.0.1 and (where the host has it) ::1, carries the transport and the
// client's address. Client and server take turns, as in
// examples/dns/loopback.goose: the query is sent first, serve handles one
// request, then the reply is read. UDP replies capped at max_udp_size,
// BADVERS and FORMERR for EDNS0 that is wrong, a TCP client that stops
// mid-query holding up no UDP query, and tcp_queries.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
import gslib.dns.edns;
import gslib.dns.client;
import gslib.dns.server;
import gslib.net;

var failures = 0;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

// One query to a server on host, over TCP or UDP: the Peer the handler saw.
fn ask(host: const u8[:], tcp: bool) -> dns::Peer {
    var cfg = dns::ServerConfig { .. };
    cfg.addr.append(host);
    cfg.port = 0;
    cfg.max_requests = 1;
    var seen = dns::Peer { false, "", 0, false };
    var srv = dns::server_open(cfg);
    if srv.err != dns::OK { return seen; }
    var q = dns::Msg { .. };
    dns::set_question(q, "www.example.com.", dns::TYPE_A);
    var w: u8[>..] = [];
    dns::pack(q, w);
    var reply: u8[>..] = [];
    if tcp {
        let fd = net::dial(host, srv.port, 2000);
        if fd >= 0 && dns::write_tcp_msg(fd, w, 2000) == dns::OK {
            dns::serve(srv, cfg) { req, resp, peer => seen = peer; };
            dns::read_tcp_msg(fd, reply, 2000);
        }
        if fd >= 0 { net::close(fd); }
    } else {
        let fd = dns::dnsnet_udp_open(host, srv.port);
        if fd >= 0 && dns::dnsnet_send(fd, w) == w.len {
            dns::serve(srv, cfg) { req, resp, peer => seen = peer; };
            reply.resize(512, 0);
            let n = dns::dnsnet_recv(fd, reply, 2000);
            reply.resize(if n > 0 { n } else { 0 }, 0);
        }
        if fd >= 0 { dns::dnsnet_close(fd); }
    }
    dns::server_close(srv);
    check(str(host, if tcp { " tcp" } else { " udp" }, ": a reply"), reply.len > 0 && dns::reply_matches(w, reply));
    return seen;
}

fn query_bytes(qname: const u8[:], edns: bool) -> u8[>..] {
    var q = dns::Msg { .. };
    dns::set_question(q, qname, dns::TYPE_TXT);
    if edns { dns::set_edns0(q, 4096, false); }
    var w: u8[>..] = [];
    dns::pack(q, w);
    return w;
}

fn recv_reply(fd: i64) -> u8[>..] {
    var reply: u8[>..] = [];
    reply.resize(65535, 0);
    let n = dns::dnsnet_recv(fd, reply, 2000);
    reply.resize(if n > 0 { n } else { 0 }, 0);
    return reply;
}

fn local_cfg(max_requests: i64) -> dns::ServerConfig {
    var cfg = dns::ServerConfig { .. };
    cfg.addr.append("127.0.0.1");
    cfg.port = 0;
    cfg.max_requests = max_requests;
    return cfg;
}

// One UDP query w to a server whose handler fills 60 TXT records: the reply,
// and whether the handler ran.
fn udp_once(w: const u8[:]) -> u8[>..], bool {
    let cfg = local_cfg(1);
    var srv = dns::server_open(cfg);
    var reply: u8[>..] = [];
    var ran = false;
    let fd = dns::dnsnet_udp_open("127.0.0.1", srv.port);
    if srv.err == dns::OK && fd >= 0 && dns::dnsnet_send(fd, w) == w.len {
        dns::serve(srv, cfg) { req, resp, peer =>
            ran = true;
            for i in 60 { dns::new_rr(resp.answer, str("big.example. 60 IN TXT \"record number ", i, " of sixty, padded out a little\"")); }
        };
        reply = recv_reply(fd);
    }
    if fd >= 0 { dns::dnsnet_close(fd); }
    dns::server_close(srv);
    return reply, ran;
}

// UDP replies: no larger than max_udp_size, whatever the client asks for;
// EDNS0 errors answered before the handler.
fn udp_limits() {
    let big, ran = udp_once(query_bytes("big.example.", true));
    var m = dns::Msg { .. };
    check(str("UDP reply capped at 1232: ", big.len), ran && big.len > 512 && big.len <= 1232);
    check("capped reply truncated", dns::unpack(big, m) == dns::OK && m.hdr.truncated);

    var q = dns::Msg { .. };
    dns::set_question(q, "big.example.", dns::TYPE_TXT);
    dns::set_edns0(q, 1232, false);
    dns::rr_set_ttl(q.extra, dns::rr_at(q.extra, 0), 1 << 16);       // EDNS version 1
    var w: u8[>..] = [];
    dns::pack(q, w);
    let r1, ran1 = udp_once(w);
    check("EDNS version 1: BADVERS", !ran1 && dns::unpack(r1, m) == dns::OK && m.hdr.rcode == dns::RCODE_BAD_VERS && dns::opt_offset(m) >= 0);

    var q2 = dns::Msg { .. };
    dns::set_question(q2, "big.example.", dns::TYPE_TXT);
    dns::set_edns0(q2, 1232, false);
    dns::rr_copy(q2.extra, q.extra, dns::rr_at(q.extra, 0));
    var w2: u8[>..] = [];
    dns::pack(q2, w2);
    let r2, ran2 = udp_once(w2);
    check("two OPT records: FORMERR", !ran2 && dns::unpack(r2, m) == dns::OK && m.hdr.rcode == dns::RCODE_FORMAT_ERROR);

    var q3 = dns::Msg { .. };
    dns::set_question(q3, "big.example.", dns::TYPE_TXT);
    dns::set_edns0(q3, 1232, false);
    let short: u8[3] = [0, 10, 0];             // an option cut short
    q3.extra.clear();
    dns::rr_append(q3.extra, [0], dns::TYPE_OPT, 1232, 0, short);
    var w3: u8[>..] = [];
    dns::pack(q3, w3);
    let r3, ran3 = udp_once(w3);
    check("short EDNS option: FORMERR", !ran3 && dns::unpack(r3, m) == dns::OK && m.hdr.rcode == dns::RCODE_FORMAT_ERROR);
}

// A TCP client that sends one byte and stops holds up no UDP query: the
// datagram that comes while the server waits on it is answered at once.
fn slow_tcp() {
    var cfg = local_cfg(2);
    cfg.idle_ms = 5000;
    var srv = dns::server_open(cfg);
    if srv.err != dns::OK { check("slow TCP: server", false); return; }
    let t = net::dial("127.0.0.1", srv.port, 2000);
    let one: u8[1] = [0];
    check("slow TCP: one byte", t >= 0 && net::write(t, one, 2000) == 1);
    let u1 = dns::dnsnet_udp_open("127.0.0.1", srv.port);
    let u2 = dns::dnsnet_udp_open("127.0.0.1", srv.port);
    let w1 = query_bytes("one.example.", false);
    let w2 = query_bytes("two.example.", false);
    dns::dnsnet_send(u1, w1);
    var n = 0;
    let start = clock_ns();
    // The first query's handler sends the second, which comes while the
    // server has the TCP connection.
    dns::serve(srv, cfg) { req, resp, peer =>
        if n == 0 { dns::dnsnet_send(u2, w2); }
        n++;
    };
    let ms = (clock_ns() - start) / 1000000;
    check(str("slow TCP: both UDP queries, in ", ms, " ms"), n == 2 && ms < 2500);
    let r2 = recv_reply(u2);
    check("slow TCP: second reply", dns::reply_matches(w2, r2));
    dns::dnsnet_close(u1);
    dns::dnsnet_close(u2);
    net::close(t);
    dns::server_close(srv);
}

// A TCP connection is closed after tcp_queries queries.
fn tcp_query_cap() {
    var cfg = local_cfg(2);
    cfg.tcp_queries = 1;
    var srv = dns::server_open(cfg);
    if srv.err != dns::OK { check("TCP cap: server", false); return; }
    let t = net::dial("127.0.0.1", srv.port, 2000);
    let w = query_bytes("one.example.", false);
    check("TCP cap: two queries sent", t >= 0 && dns::write_tcp_msg(t, w, 2000) == dns::OK && dns::write_tcp_msg(t, w, 2000) == dns::OK);
    let u = dns::dnsnet_udp_open("127.0.0.1", srv.port);
    let wu = query_bytes("udp.example.", false);
    var tcp_seen = 0;
    dns::serve(srv, cfg) { req, resp, peer =>
        if peer.tcp { tcp_seen++; dns::dnsnet_send(u, wu); }
    };
    var r: u8[>..] = [];
    check("TCP cap: first answered", dns::read_tcp_msg(t, r, 2000) == dns::OK && dns::reply_matches(w, r));
    r.clear();
    check("TCP cap: then closed", tcp_seen == 1 && dns::read_tcp_msg(t, r, 2000) != dns::OK);
    check("TCP cap: UDP answered", dns::reply_matches(wu, recv_reply(u)));
    dns::dnsnet_close(u);
    net::close(t);
    dns::server_close(srv);
}

fn main() {
    udp_limits();
    slow_tcp();
    tcp_query_cap();
    for tcp in [false, true] {
        let p = ask("127.0.0.1", tcp);
        check(str("127.0.0.1 tcp flag ", tcp), p.tcp == tcp);
        check(str("127.0.0.1 addr ", tcp, ": ", p.addr), p.addr == "127.0.0.1");
    }
    // ::1 only where an IPv6 loopback can be bound.
    var probe = dns::ServerConfig { .. };
    probe.addr.append("::1");
    probe.port = 0;
    var s6 = dns::server_open(probe);
    let has6 = s6.err == dns::OK;
    dns::server_close(s6);
    if has6 {
        for tcp in [false, true] {
            let p = ask("::1", tcp);
            check(str("::1 tcp flag ", tcp), p.tcp == tcp);
            check(str("::1 addr ", tcp, ": ", p.addr), p.addr == "::1");
        }
    }
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("server: ok", if has6 { "" } else { " (no IPv6 loopback)" });
}
