// dns.server: serving over UDP and TCP, as miekg's Server does, with the
// handler a block:
//
//   var cfg = dns::ServerConfig { .. };
//   cfg.port = 5353;
//   var srv = dns::server_open(cfg);           // srv.err, srv.port (the bound one)
//   dns::serve(srv, cfg) { req, resp, peer =>
//       // resp is already a reply to req (set_reply); fill it in.
//       dns::new_rr(resp.answer, "example.org. 60 IN A 192.0.2.1");
//   };
//
// One request at a time, UDP and TCP from one loop. Requests that are
// responses, or have no single question, get FORMERR (miekg's default
// MsgAcceptFunc); other opcodes than QUERY, NOTIFY and UPDATE get NOTIMP.
// With a TSIG key, a signed request is verified first: one that fails gets
// NOTAUTH with the TSIG error (RFC 8945 §5.2) and never reaches the
// handler, and replies to signed requests are signed. A UDP reply is cut
// to the client's EDNS0 size (512 without) and marked truncated; a TCP
// reply too large for one message (a zone transfer) goes in several, each
// signed over the one before (RFC 8945 §5.3.1). serve returns after
// max_requests requests (0: never), or when the handler returns from
// its own function.

namespace dns;

import std;
import dns;
import dns.rdata;
import dns.msg;
import dns.edns;
import dns.tsig;
import dns.client;
import net;

extern fn dnsnet_listen(addr: const u8[:], port: i32, tcp: i32) -> i64;
extern fn dnsnet_local_port(fd: i64) -> i32;
extern fn dnsnet_recvfrom(fd: i64, buf: u8[:], from: u8[:], from_len: u8[:]) -> i64;
extern fn dnsnet_peername(fd: i64, from: u8[:], from_len: u8[:]) -> i64;
extern fn dnsnet_sendto(fd: i64, data: const u8[:], to: const u8[:]) -> i64;
extern fn dnsnet_addr_text(sa: const u8[:], out: u8[:]) -> i64;
extern fn dnsnet_accept(fd: i64, timeout_ms: i32) -> i64;
extern fn dnsnet_wait2(a: i64, b: i64, timeout_ms: i32) -> i32;

struct ServerConfig {
    addr:         u8[..64]  = "",   // "" for every address
    port:         i32       = 53,   // 0 for one the OS picks (server_open says which)
    udp:          bool      = true,
    tcp:          bool      = true,
    tsig_name:    u8[..255] = "",   // a TSIG key: name (text), secret (base64)
    tsig_secret:  u8[..128] = "",
    tsig_fudge:   u16       = 300,
    max_requests: i64       = 0,
    idle_ms:      i32       = 8000, // how long a TCP connection may wait for its next query
}

struct Server { udp: i64, tcp: i64, port: i32, err: i64 }

// Who asked, and how: the transport, the client's address as text, the
// TSIG check's result (OK, ERR_NO_SIG for an unsigned request), and drop,
// which the handler sets to send no reply at all.
struct Peer { tcp: bool, addr: u8[..64], tsig: i64, drop: bool }

// Opens the sockets the config asks for. Port 0 takes the port the system
// gives UDP for TCP too; when TCP's is taken, it tries again with another.
fn server_open(cfg: const ServerConfig&) -> Server {
    var s = Server { -1, -1, cfg.port, OK };
    let tries = if cfg.port == 0 && cfg.udp && cfg.tcp { 20 } else { 1 };
    for t in tries {
        s = Server { -1, -1, cfg.port, OK };
        if cfg.udp {
            s.udp = dnsnet_listen(cfg.addr, cfg.port, 0);
            if s.udp < 0 { s.err = ERR_IO; return s; }
            s.port = dnsnet_local_port(s.udp);
        }
        if cfg.tcp {
            s.tcp = dnsnet_listen(cfg.addr, s.port, 1);
            if s.tcp < 0 {
                s.err = ERR_IO;
                if s.udp >= 0 { dnsnet_close(s.udp); s.udp = -1; }
                continue;
            }
            s.port = dnsnet_local_port(s.tcp);
        }
        return s;
    }
    return s;
}

fn server_close(s: Server&) {
    if s.udp >= 0 { dnsnet_close(s.udp); s.udp = -1; }
    if s.tcp >= 0 { dnsnet_close(s.tcp); s.tcp = -1; }
}

// The FORMERR or NOTIMP for a request the server will not hand on, or
// RCODE_SUCCESS for one it will (miekg's DefaultMsgAcceptFunc).
fn accept_check(w: const u8[:]) -> u16 {
    if w.len < 12 { return RCODE_FORMAT_ERROR; }
    let flags = get16(w, 2);
    if flags & 0x8000 != 0 { return 0xFFFF; }        // a response: ignored
    let op = ((flags >> 11) & 15) as! u8;
    if op != OPCODE_QUERY && op != OPCODE_NOTIFY && op != OPCODE_UPDATE { return RCODE_NOT_IMPLEMENTED; }
    if get16(w, 4) != 1 { return RCODE_FORMAT_ERROR; }
    if op != OPCODE_UPDATE && (get16(w, 6) > 1 || get16(w, 8) > 1) { return RCODE_FORMAT_ERROR; }
    if get16(w, 10) > 2 { return RCODE_FORMAT_ERROR; }
    return RCODE_SUCCESS;
}

// A bare reply to the raw request: its ID, opcode and question if it has
// one that reads, the rcode.
fn error_reply(w: const u8[:], rcode: u16, out: u8[>..]&) {
    var r = Msg { .. };
    var q = Msg { .. };
    let e = unpack(w, q);
    if e == OK { set_reply(r, q); } else { r.hdr.id = get16(w, 0); r.hdr.response = true; r.hdr.opcode = ((get16(w, 2) >> 11) & 15) as! u8; }
    r.hdr.rcode = rcode;
    pack(r, out);
}

// Handles one request: the reply's messages (several only for a large
// TCP reply) go to S(bytes). H is the handler.
fn handle<H, S>(cfg: const ServerConfig&, w: const u8[:], peer: Peer&) {
    let ac = accept_check(w);
    if ac == 0xFFFF { return; }
    var out: u8[>..] = [];
    if ac != RCODE_SUCCESS { error_reply(w, ac, out); S(out); return; }
    var req = Msg { .. };
    let ue = unpack(w, req);
    if ue != OK { error_reply(w, RCODE_FORMAT_ERROR, out); S(out); return; }
    // TSIG first: a request that fails it is answered here.
    var request_mac: u8[>..] = [];
    var secret:      u8[>..] = [];
    peer.tsig = ERR_NO_SIG;
    let toff, trd, te = find_tsig(w);
    if te == OK {
        let kn, an, ke = tsig_key(w);
        let want, wn = name_parse(cfg.tsig_name, []);
        let sec, sok = tsig_secret(cfg.tsig_secret);
        secret.append(sec);
        let now = time_ns() / 1000000000;
        var err: u16 = 0;
        if cfg.tsig_name.len == 0 || wn != OK || !name_equal(kn, want) || tsig_hash(name_text(an)) == 0 {
            err = RCODE_BAD_KEY;
        } else {
            let mac, ve = tsig_verify(w, secret, [], false, now);
            if ve == ERR_TIME { err = RCODE_BAD_TIME; request_mac.append(mac); }
            else if ve != OK { err = RCODE_BAD_SIG; }
            else { request_mac.append(mac); }
        }
        // The TSIG record itself is not the handler's.
        var ex: u8[>..] = [];
        each_rr(req.extra) { rr => if rr.rtype != TYPE_TSIG { rr_copy(ex, req.extra, rr); } };
        req.extra.clear();
        req.extra.append(ex);
        if err != 0 {
            var r = Msg { .. };
            set_reply(r, req);
            r.hdr.rcode = RCODE_NOT_AUTH;
            pack(r, out);
            var other: u8[>..] = [];
            if err == RCODE_BAD_TIME { put48(other, now as! u64); }
            let alg = name_text(an);
            let m2, e2 = tsig_sign_error(out, name_text(kn), alg, secret, cfg.tsig_fudge, now, request_mac, false, err, other);
            S(out);
            return;
        }
        peer.tsig = OK;
    }
    var resp = Msg { .. };
    set_reply(resp, req);
    peer.drop = false;
    H(req, resp, peer);
    if peer.drop { return; }
    let kn, an, ke = tsig_key(w);
    if !peer.tcp {
        // Cut to what the client can take, leaving room for a TSIG.
        let room = if peer.tsig == OK { 100 + kn.len + an.len + 64 } else { 0 };
        truncate(resp, udp_size(req) - room);
        let e = pack(resp, out);
        if e != OK { out.clear(); error_reply(w, RCODE_SERVER_FAILURE, out); }
        if peer.tsig == OK { tsig_sign(out, name_text(kn), name_text(an), secret, cfg.tsig_fudge, time_ns() / 1000000000, request_mac, false); }
        S(out);
        return;
    }
    // TCP: one message if it fits, else the answer section across several.
    let e = pack(resp, out);
    if e != OK { out.clear(); error_reply(w, RCODE_SERVER_FAILURE, out); S(out); return; }
    if out.len <= 65000 {
        if peer.tsig == OK { tsig_sign(out, name_text(kn), name_text(an), secret, cfg.tsig_fudge, time_ns() / 1000000000, request_mac, false); }
        S(out);
        return;
    }
    var mac: u8[>..] = [];
    mac.append(request_mac);
    var first = true;
    var part = Msg { .. };
    var pos = 0;
    while pos < resp.answer.len || first {
        copy_msg(part, resp);
        part.answer.clear();
        if !first { part.question.clear(); part.ns.clear(); part.extra.clear(); }
        // Records until the packed message would pass 64000 bytes.
        var size = 0;
        out.clear();
        pack(part, out);
        size = out.len;
        while pos < resp.answer.len {
            let rr = rr_at(resp.answer, pos);
            let l = rr.end - rr.off;
            if size + l > 64000 && part.answer.len > 0 { break; }
            rr_copy(part.answer, resp.answer, rr);
            size += l;
            pos = rr.end;
        }
        out.clear();
        pack(part, out);
        if peer.tsig == OK {
            let m2, e2 = tsig_sign(out, name_text(kn), name_text(an), secret, cfg.tsig_fudge, time_ns() / 1000000000, mac, !first);
            mac.clear();
            mac.append(m2);
        }
        S(out);
        first = false;
    }
}

// Serves until max_requests requests (0: for ever).
fn serve<F>(srv: Server&, cfg: const ServerConfig&) {
    var handled = 0;
    var buf: u8[>..] = [];
    buf.resize(65535, 0);
    var from: u8[>..] = [];
    from.resize(256, 0);
    var flen: u8[1] = [0];
    var peer = Peer { false, "", ERR_NO_SIG, false };
    var text: u8[64] = [0; 64];
    while cfg.max_requests == 0 || handled < cfg.max_requests {
        let ready = dnsnet_wait2(srv.udp, srv.tcp, 0);
        if ready < 0 { continue; }
        if ready & 1 != 0 {
            let n = dnsnet_recvfrom(srv.udp, buf, from, flen);
            if n >= 0 {
                let to = from[..flen[0]];
                peer.tcp = false;
                peer.addr.clear();
                let tl = dnsnet_addr_text(to, text);
                if tl > 0 { peer.addr.append(text[..tl]); }
                handle(cfg, buf[..n], peer, F) { out => dnsnet_sendto(srv.udp, out, to); };
                handled++;
            }
        }
        if ready & 2 != 0 {
            let c = dnsnet_accept(srv.tcp, 1000);
            if c >= 0 {
                peer.tcp = true;
                peer.addr.clear();
                if dnsnet_peername(c, from, flen) >= 0 {
                    let tl = dnsnet_addr_text(from[..flen[0]], text);
                    if tl > 0 { peer.addr.append(text[..tl]); }
                }
                // Queries on the connection until it closes or idles.
                var req: u8[>..] = [];
                while cfg.max_requests == 0 || handled < cfg.max_requests {
                    req.clear();
                    let e = read_tcp_msg(c, req, cfg.idle_ms);
                    if e != OK { break; }
                    handle(cfg, req, peer, F) { out => write_tcp_msg(c, out, cfg.idle_ms); };
                    handled++;
                }
                net::close(c);
            }
        }
    }
}
