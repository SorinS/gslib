// radiusd: a small RADIUS server on gslib's radius: authentication and
// accounting over UDP, and RadSec (RADIUS over TLS, RFC 6614) with
// client certificates; users with passwords for PAP, CHAP, MS-CHAPv2 and
// the EAP methods, EAP-TLS for certificates from a CA.
//
//   radiusd --cert server.pem --key server.key [options]
//
//   --addr A          the address to listen on (127.0.0.1)
//   --port N          authentication (1812); accounting is the next port
//   --radsec-port N   RadSec (0: none)
//   --coa-port N      as a NAS: CoA- and Disconnect-Requests, ACKed for
//                     the users it knows (0: none)
//   --secret S        the shared secret (testing123)
//   --ca FILE         the CA of EAP-TLS's and RadSec's client certificates
//   --user NAME:PW    a user (as many as wanted)
//   --methods LIST    EAP methods offered, in order: peap,ttls,tls,mschapv2,md5
//   --tls12           EAP's TLS at most 1.2
//   --count N         stop after N requests (0: never)
//
// It prints a line for each request it answers.

import std;
import os;
import gslib from "../..";
import gslib.net;
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.server;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;

fn die(what: const u8[:]) { print("radiusd: ", what); exit(2); }

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die(str("cannot read ", path)); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    if out.len == 0 { die(str("no ", label, " in ", path)); }
    return out;
}

// A RadSec connection: its socket, TLS, and what came out of it.
struct Radsec { fd: i64, rbuf: u8[..8192], conn: tls::Conn }

fn main() {
    let a = args();
    var addr: u8[>..] = [];
    addr.append("127.0.0.1");
    var port: i64 = 1812;
    var radsec_port: i64 = 0;
    var coa_port: i64 = 0;
    var secret: u8[>..] = [];
    secret.append("testing123");
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var ca: u8[>..] = [];
    var users: u8[>..] = [];          // name, 0, password, 0, ...
    var methods: u8[>..] = [];
    var tls12 = false;
    var limit: i64 = 0;
    var i = 1;
    while i < a.len {
        let o = a[i];
        guard i + 1 < a.len || o == "--tls12" else { die(str("missing value for ", o)); }
        if o == "--addr" { addr.clear(); addr.append(a[i + 1]); i += 2; }
        else if o == "--port" { let v, ok = parse_int(a[i + 1], 10); port = v; i += 2; }
        else if o == "--radsec-port" { let v, ok = parse_int(a[i + 1], 10); radsec_port = v; i += 2; }
        else if o == "--coa-port" { let v, ok = parse_int(a[i + 1], 10); coa_port = v; i += 2; }
        else if o == "--secret" { secret.clear(); secret.append(a[i + 1]); i += 2; }
        else if o == "--cert" { cert.append(a[i + 1]); i += 2; }
        else if o == "--key" { key.append(a[i + 1]); i += 2; }
        else if o == "--ca" { ca.append(a[i + 1]); i += 2; }
        else if o == "--user" {
            let c = find(a[i + 1], ":");
            if c <= 0 { die("--user NAME:PASSWORD"); }
            users.append(a[i + 1][..c]);
            users.push(0);
            users.append(a[i + 1][c + 1..]);
            users.push(0);
            i += 2;
        }
        else if o == "--methods" {
            for m in split(a[i + 1], ',') {
                if m == "peap" { methods.push(radius::EAP_PEAP); }
                else if m == "ttls" { methods.push(radius::EAP_TTLS); }
                else if m == "tls" { methods.push(radius::EAP_TLS); }
                else if m == "mschapv2" { methods.push(radius::EAP_MSCHAPV2); }
                else if m == "md5" { methods.push(radius::EAP_MD5); }
                else { die(str("no such method: ", m)); }
            }
            i += 2;
        }
        else if o == "--tls12" { tls12 = true; i++; }
        else if o == "--count" { let v, ok = parse_int(a[i + 1], 10); limit = v; i += 2; }
        else { die(str("unknown option ", o)); }
    }
    if cert.len == 0 || key.len == 0 { die("usage: radiusd --cert server.pem --key server.key [options]"); }
    if methods.len == 0 {
        let all: u8[5] = [radius::EAP_PEAP, radius::EAP_TTLS, radius::EAP_TLS, radius::EAP_MSCHAPV2, radius::EAP_MD5];
        methods.append(all);
    }

    // EAP's TLS: client certificates checked when given (EAP-TLS needs one).
    var t, okt = tls::server_config(pem_der(cert, "CERTIFICATE"), pem_der(key, "PRIVATE KEY"));
    if !okt { die("the server's certificate and key"); }
    if tls12 { t.max_version = tls::VERSION_TLS12; }
    if ca.len > 0 {
        t.client_auth = tls::VERIFY_CLIENT_CERT_IF_GIVEN;
        if !x509::pool_add(t.client_cas, pem_der(ca, "CERTIFICATE")) { die("the CA"); }
    }
    let cfg = radius::eap_config(methods, t);
    // RadSec's TLS: a client certificate required.
    var rt = copy(t);
    rt.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    rt.max_version = tls::VERSION_TLS13;
    rt.tickets = 0;

    var srv = radius::server(secret);
    var rs = radius::server("radsec");
    let auth_fd = net::listen_udp(addr, port);
    let acct_fd = net::listen_udp(addr, port + 1);
    if auth_fd < 0 || acct_fd < 0 { die("cannot listen"); }
    var rl_fd: i64 = -1;
    var coa_fd: i64 = -1;
    if coa_port > 0 {
        coa_fd = net::listen_udp(addr, coa_port);
        if coa_fd < 0 { die("cannot listen for CoA"); }
    }
    if radsec_port > 0 {
        rl_fd = net::listen(addr, radsec_port);
        if rl_fd < 0 { die("cannot listen for RadSec"); }
    }
    print("radiusd: listening on ", addr, " ", port, "/", port + 1, if radsec_port > 0 { str(", RadSec ", radsec_port) } else { str("") });

    // The password of a user, empty for none.
    fn password_of(user: const u8[:]) -> u8[>..] {
        var pw: u8[>..] = [];
        var k = 0;
        var name_start = 0;
        var is_name = true;
        var name_matches = false;
        for j in users.len {
            if users[j] != 0 { continue; }
            if is_name { name_matches = users[name_start..j] == user; }
            else if name_matches { pw.append(users[name_start..j]); return pw; }
            is_name = !is_name;
            name_start = j + 1;
        }
        return pw;
    }

    var conns: Radsec[>..] = [];
    var buf: u8[4096] = [0; 4096];
    var rbuf: u8[16384] = [0; 16384];
    var served: i64 = 0;
    while limit == 0 || served < limit {
        var fds: i64[>..] = [];
        var want: u8[>..] = [];
        fds.push(auth_fd); want.push(net::WANT_READ);
        fds.push(acct_fd); want.push(net::WANT_READ);
        fds.push(rl_fd); want.push(net::WANT_READ);
        fds.push(coa_fd); want.push(net::WANT_READ);
        for c in conns { fds.push(c.fd); want.push(net::WANT_READ); }
        var ready: u8[>..] = [];
        for k in fds.len { ready.push(0); }
        let n = net::poll(fds, want, ready, 0);
        if n <= 0 { continue; }
        for k in 2 {
            if ready[k] == 0 { continue; }
            let fd = fds[k];
            let got, from = net::recv_from(fd, buf, -1);
            if got <= 0 { continue; }
            var reply: u8[>..] = [];
            let req, e = radius::handle(srv, cfg, buf[..got], reply, password_of);
            print(radius::code_name(req.code), " ", radius::get_text(req, radius::USER_NAME), ": ",
                  if e != radius::OK { radius::error_text(e) } else { radius::code_name(reply[0]) });
            if reply.len > 0 { let w = net::send_to(fd, reply, from); }
            served++;
        }
        if coa_fd >= 0 && ready[3] != 0 {
            let got, from = net::recv_from(coa_fd, buf, -1);
            if got > 0 {
                var reply: u8[>..] = [];
                let req, e = radius::handle_dynamic(secret, buf[..got], reply) { r, resp =>
                    let known = password_of(radius::get_text(r, radius::USER_NAME)).len > 0;
                    if !known { radius::add_u32(resp, radius::ERROR_CAUSE, radius::CAUSE_SESSION_NOT_FOUND); }
                    known
                };
                print(radius::code_name(req.code), " ", radius::get_text(req, radius::USER_NAME), ": ",
                      if e != radius::OK { radius::error_text(e) } else { radius::code_name(reply[0]) });
                if reply.len > 0 { let w = net::send_to(coa_fd, reply, from); }
                served++;
            }
        }
        let polled = conns.len;
        if rl_fd >= 0 && ready[2] != 0 {
            let fd = net::accept(rl_fd, 1000);
            if fd >= 0 { conns.push(Radsec { fd: fd, rbuf: [], conn: tls::server(rt) }); }
        }
        // The RadSec connections polled, from the last, so that a closed
        // one can go.
        var k = polled - 1;
        while k >= 0 {
            if ready[4 + k] == 0 { k--; continue; }
            var closed = false;
            let got = net::read(conns[k].fd, rbuf, 1000);
            if got <= 0 { closed = true; }
            else {
                var out: u8[>..] = [];
                var app: u8[>..] = [];
                let fr = tls::feed(conns[k].conn, rt, rbuf[..got], out, app);
                if fr < 0 || conns[k].rbuf.len + app.len > conns[k].rbuf.cap { closed = true; }
                else { conns[k].rbuf.append(app); }
                // Every whole packet that came.
                loop {
                    if closed { break; }
                    let need = radius::packet_length(conns[k].rbuf);
                    if need < 0 { closed = true; break; }
                    if need == 0 || conns[k].rbuf.len < need { break; }
                    var reply: u8[>..] = [];
                    let req, e = radius::handle(rs, cfg, conns[k].rbuf[..need], reply, password_of);
                    print("RadSec ", radius::code_name(req.code), " ", radius::get_text(req, radius::USER_NAME), ": ",
                          if e != radius::OK { radius::error_text(e) } else { radius::code_name(reply[0]) });
                    var rest: u8[>..] = [];
                    rest.append(conns[k].rbuf[need..]);
                    conns[k].rbuf.clear();
                    conns[k].rbuf.append(rest);
                    if reply.len > 0 && !tls::send(conns[k].conn, reply, out) { closed = true; }
                    served++;
                }
                if out.len > 0 && net::write(conns[k].fd, out, 1000) < 0 { closed = true; }
            }
            if closed {
                net::close(conns[k].fd);
                let gone = remove_at(conns, k);
            }
            k--;
        }
    }
}
