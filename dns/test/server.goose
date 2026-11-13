// dns.server in one process: the handler's Peer over UDP and TCP, on
// 127.0.0.1 and (where the host has it) ::1, carries the transport and the
// client's address. Client and server take turns, as in
// examples/dns/loopback.goose: the query is sent first, serve handles one
// request, then the reply is read.
import std;
import gslib from "../..";
import gslib.dns;
import gslib.dns.msg;
import gslib.dns.zone;
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

fn main() {
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
