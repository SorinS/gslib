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
// MsgAcceptFunc); other opcodes than QUERY, NOTIFY and UPDATE get NOTIMP;
// more than one OPT record, or options that do not parse, FORMERR, and an
// EDNS version above 0 BADVERS (RFC 6891 §6.1.1, §6.1.3).
// With a TSIG key, a signed request is verified first: one that fails gets
// NOTAUTH with the TSIG error (RFC 8945 §5.2) and never reaches the
// handler, and replies to signed requests are signed. The request's time
// must be within the server's fudge, whatever fudge the request names. A
// UDP reply is cut to the client's EDNS0 size (512 without), but to no
// more than max_udp_size (1232, RFC 9715's advice), and marked truncated;
// a TCP reply too large for one message (a zone transfer) goes in several,
// each signed over the one before (RFC 8945 §5.3.1).
//
// A TCP connection has idle_ms for each query, all of it, and its replies
// as long to go out; it is closed after tcp_queries queries. While it is
// open, UDP is served between its bytes, so a slow client holds up only
// itself. serve returns after max_requests requests (0: never), or when
// the handler returns from its own function.

namespace dns;

import std;
import dns;
import dns.rdata;
import dns.msg;
import dns.edns;
import dns.tsig;
import dns.client;
import net;
import net.ip;

struct ServerConfig {
    addr:         u8[..64]  = "",   // "" for every address
    port:         i32       = 53,   // 0 for one the OS picks (server_open says which)
    udp:          bool      = true,
    tcp:          bool      = true,
    tsig_name:    u8[..255] = "",   // a TSIG key: name (text), secret (base64)
    tsig_secret:  u8[..128] = "",
    tsig_alg:     u8[..64]  = "",   // the key's algorithm ("hmac-sha256."); "" for any tsig_hash knows
    tsig_fudge:   u16       = 300,  // also the most a request's time may be off
    max_requests: i64       = 0,
    idle_ms:      i32       = 8000, // how long a TCP connection has for each query, all of it
    tcp_queries:  i64       = 128,  // queries on one TCP connection before it is closed (0: no limit; miekg's MaxTCPQueries)
    max_udp_size: i64       = 1232, // the largest UDP reply, whatever the client's EDNS0 size says
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
            s.udp = net::listen_udp(cfg.addr, cfg.port);
            if s.udp < 0 { s.err = ERR_IO; return s; }
            s.port = net::local_port(s.udp) as! i32;
        }
        if cfg.tcp {
            s.tcp = net::listen(cfg.addr, s.port);
            if s.tcp < 0 {
                s.err = ERR_IO;
                if s.udp >= 0 { net::close(s.udp); s.udp = -1; }
                continue;
            }
            s.port = net::local_port(s.tcp) as! i32;
        }
        return s;
    }
    return s;
}

fn server_close(s: Server&) {
    if s.udp >= 0 { net::close(s.udp); s.udp = -1; }
    if s.tcp >= 0 { net::close(s.tcp); s.tcp = -1; }
}

// The FORMERR or NOTIMP for a request the server will not hand on, or
// RCODE_SUCCESS for one it will (miekg's DefaultMsgAcceptFunc), or 0xFFFF
// for one it drops unanswered: a response, or anything shorter than a
// header (as miekg and BIND drop it: there is no ID to answer to).
fn accept_check(w: const u8[:]) -> u16 {
    if w.len < 12 { return 0xFFFF; }
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
// Nothing for a request shorter than a header.
fn error_reply(w: const u8[:], rcode: u16, out: u8[>..]&) {
    if w.len < 12 { return; }
    var r = Msg { .. };
    var q = Msg { .. };
    let e = unpack(w, q);
    if e == OK { set_reply(r, q); } else { r.hdr.id = get16(w, 0); r.hdr.response = true; r.hdr.opcode = ((get16(w, 2) >> 11) & 15) as! u8; }
    r.hdr.rcode = rcode;
    pack(r, out);
}

// RCODE_SUCCESS for a request whose EDNS0 is fine (or absent); FORMERR for
// more than one OPT or options that do not parse; BADVERS for a version
// above 0.
fn edns_check(req: const Msg&) -> u16 {
    var opts = 0;
    var rc = RCODE_SUCCESS;
    each_rr(req.extra) { rr =>
        if rr.rtype == TYPE_OPT {
            opts++;
            if opts > 1 || !options_valid(rr.rdata(req.extra)) || rr.name(req.extra).len != 1 { rc = RCODE_FORMAT_ERROR; }
            else if opt_version(rr) != 0 { rc = RCODE_BAD_VERS; }
        }
    };
    return rc;
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
        let pinned = cfg.tsig_alg.len == 0 || tsig_hash(name_text(an)) == tsig_hash(cfg.tsig_alg);
        if cfg.tsig_name.len == 0 || wn != OK || !name_equal(kn, want) || tsig_hash(name_text(an)) == 0 || !pinned {
            err = RCODE_BAD_KEY;
        } else {
            let mac, ve = tsig_verify_fudge(w, secret, [], false, now, cfg.tsig_fudge);
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
    let ee = edns_check(req);
    if ee != RCODE_SUCCESS {
        // Not the handler's: FORMERR, or BADVERS with an OPT of version 0.
        if ee == RCODE_BAD_VERS { set_edns0(resp, 1232, false); }
        resp.hdr.rcode = ee;
    } else {
        H(req, resp, peer);
        if peer.drop { return; }
    }
    let kn, an, ke = tsig_key(w);
    if !peer.tcp {
        // Cut to what the client can take (no more than max_udp_size: a
        // small query must not draw a large reply to an address it forged),
        // leaving room for a TSIG.
        let room = if peer.tsig == OK { 100 + kn.len + an.len + 64 } else { 0 };
        let size = if udp_size(req) < cfg.max_udp_size { udp_size(req) } else { cfg.max_udp_size };
        truncate(resp, size - room);
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

fn more(cfg: const ServerConfig&, handled: i64) -> bool { cfg.max_requests == 0 || handled < cfg.max_requests }

// One datagram off the UDP socket, handled and answered; false if none was
// there.
fn serve_udp<F>(srv: const Server&, cfg: const ServerConfig&, buf: u8[:]) -> bool {
    let n, to = net::recv_from(srv.udp, buf, -1);
    if n < 0 { return false; }
    var peer = Peer { false, "", ERR_NO_SIG, false };
    peer.addr.append(net::addr_string(to.addr));
    let w = buf[..n];
    handle(cfg, w, peer, F) { out =>
        if net::send_to(srv.udp, out, to) != out.len {
            // Too large for the path, or a send error: a bare truncated
            // reply instead, which sends the client to TCP.
            var q = Msg { .. };
            var r = Msg { .. };
            if unpack(w, q) == OK {
                set_reply(r, q);
                r.hdr.truncated = true;
                var small: u8[>..] = [];
                if pack(r, small) == OK { net::send_to(srv.udp, small, to); }
            }
        }
    };
    return true;
}

// Writes one framed message by deadline (clock_ns), in pieces, so a peer
// that reads slowly gets no more time than that.
fn write_tcp_msg_by(fd: i64, w: const u8[:], deadline: i64) -> i64 {
    if w.len > 65535 { return ERR_BUF; }
    var framed: u8[>..] = [];
    put16(framed, w.len as! u16);
    framed.append(w);
    var i = 0;
    while i < framed.len {
        let left = ms_left(deadline);
        if left == 0 { return ERR_TIMEOUT; }
        let e = if i + 4096 < framed.len { i + 4096 } else { framed.len };
        if net::write(fd, framed[i..e], left) != e - i { return ERR_IO; }
        i = e;
    }
    return OK;
}

// Serves until max_requests requests (0: for ever).
fn serve<F>(srv: Server&, cfg: const ServerConfig&) {
    var handled = 0;
    var buf: u8[>..] = [];
    buf.resize(65535, 0);
    var peer = Peer { true, "", ERR_NO_SIG, false };
    var req: u8[>..] = [];
    var chunk: u8[>..] = [];
    chunk.resize(65537, 0);
    let idle_ns = cfg.idle_ms as i64 * 1000000;
    while more(cfg, handled) {
        let ready = net::wait2(srv.udp, srv.tcp, 0);
        if ready < 0 { continue; }
        if ready & 1 != 0 {
            if serve_udp(srv, cfg, buf, F) { handled++; }
        }
        if ready & 2 == 0 || !more(cfg, handled) { continue; }
        let c = net::accept(srv.tcp, 1000);
        if c < 0 { continue; }
        peer.addr.clear();
        let pa, pe = net::peer_addr(c);
        if pe >= 0 { peer.addr.append(net::addr_string(pa.addr)); }
        // Queries on the connection until it closes, is slow, or has had
        // its tcp_queries. Each is read as its bytes come, by its deadline,
        // with datagrams served between.
        var queries = 0;
        var alive = true;
        while alive && more(cfg, handled) && (cfg.tcp_queries == 0 || queries < cfg.tcp_queries) {
            let deadline = clock_ns() + idle_ns;
            req.clear();
            var need = 2;
            while req.len < need && more(cfg, handled) {
                let left = ms_left(deadline);
                if left == 0 { alive = false; break; }
                let r = net::wait2(srv.udp, c, left);
                if r < 0 { alive = false; break; }
                if r & 1 != 0 && more(cfg, handled) {
                    if serve_udp(srv, cfg, buf, F) { handled++; }
                }
                if r & 2 != 0 {
                    let n = net::read(c, chunk[.. need - req.len], 1);
                    if n <= 0 { alive = false; break; }
                    req.append(chunk[..n]);
                    if need == 2 && req.len == 2 { need = 2 + get16(req, 0) as i64; }
                }
            }
            if !alive || !more(cfg, handled) { break; }
            queries++;
            handle(cfg, req[2..], peer, F) { out =>
                if alive && write_tcp_msg_by(c, out, clock_ns() + idle_ns) != OK { alive = false; }
            };
            handled++;
        }
        net::close(c);
    }
}
