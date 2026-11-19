// goose-kmipd: a KMIP server over TLS (KMIP 1.0 to 2.0), the in-memory
// one of kmip.server: objects live as long as the program. Clients show a
// certificate the CA issued; the certificate's commonName is whose the
// objects they make are.
//
//   goose-kmipd --cert server.pem --key server.key --ca ca.pem [options]
//
//   --addr A      the address to listen on (127.0.0.1)
//   --port N      5696
//   --tls12       TLS 1.2 at most
//   --http        KMIP over HTTPS (KMIP Profiles §5.3): POSTs to /kmip in
//                 TTLV, XML or JSON, each answered in its own encoding
//   --path P      the target --http takes (/kmip)
//   --limit N     stop after N connections have closed (0: never)

import std;
import gslib from "../..";
import gslib.net;
import gslib.kmip;
import gslib.kmip.server;
import gslib.kmip.https;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;

fn die(what: const u8[:]) { print("goose-kmipd: ", what); exit(2); }

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { die(str("cannot read ", path)); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    if out.len == 0 { die(str("no ", label, " in ", path)); }
    return out;
}

// A client's connection: what came out of TLS and is not yet a whole
// message, and who it is once the handshake is done.
struct Client { fd: i64, owner: u8[..128], known: bool, rbuf: u8[..262144], conn: tls::Conn, web: kmip::HttpConn }

fn main() {
    let a = args();
    var addr: u8[>..] = [];
    addr.append("127.0.0.1");
    var port: i64 = 5696;
    var cert: u8[>..] = [];
    var key: u8[>..] = [];
    var ca: u8[>..] = [];
    var tls12 = false;
    var limit: i64 = 0;
    var http = false;
    var path: u8[>..] = [];
    path.append("/kmip");
    var i = 1;
    while i < a.len {
        let o = a[i];
        let more = i + 1 < a.len;
        if o == "--addr" && more { addr.clear(); addr.append(a[i + 1]); i += 2; }
        else if o == "--port" && more { let v, ok = parse_int(a[i + 1], 10); port = v; i += 2; }
        else if o == "--cert" && more { cert.append(a[i + 1]); i += 2; }
        else if o == "--key" && more { key.append(a[i + 1]); i += 2; }
        else if o == "--ca" && more { ca.append(a[i + 1]); i += 2; }
        else if o == "--tls12" { tls12 = true; i++; }
        else if o == "--http" { http = true; i++; }
        else if o == "--path" && more { path.clear(); path.append(a[i + 1]); i += 2; }
        else if o == "--limit" && more { let v, ok = parse_int(a[i + 1], 10); limit = v; i += 2; }
        else { die(str("unknown option ", o)); }
    }
    if cert.len == 0 || key.len == 0 || ca.len == 0 { die("usage: goose-kmipd --cert server.pem --key server.key --ca ca.pem [options]"); }

    var t, okt = tls::server_config(pem_der(cert, "CERTIFICATE"), pem_der(key, "PRIVATE KEY"));
    if !okt { die("the server's certificate and key"); }
    if tls12 { t.max_version = tls::VERSION_TLS12; }
    t.client_auth = tls::REQUIRE_AND_VERIFY_CLIENT_CERT;
    if !x509::pool_add(t.client_cas, pem_der(ca, "CERTIFICATE")) { die("the CA"); }
    // KMIP's TLS 1.2 suites (CBC with SHA-256) after the defaults.
    let more: u16[3] = [tls::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
                        tls::TLS_RSA_WITH_AES_128_CBC_SHA256];
    for s in more { if t.suites12.len < t.suites12.cap { t.suites12.push(s); } }

    let lfd = net::listen(addr, port);
    if lfd < 0 { die("cannot listen"); }
    let what: u8[>..] = if http { str(", HTTPS at ", path) } else { "" };
    print("goose-kmipd: listening on ", addr, " ", port, what);

    var srv = kmip::server();
    var conns: Client[>..] = [];
    var rbuf: u8[16384] = [0; 16384];
    var closed_count: i64 = 0;
    while limit == 0 || closed_count < limit {
        var fds: i64[>..] = [];
        var want: u8[>..] = [];
        fds.push(lfd); want.push(net::WANT_READ);
        for c in conns { fds.push(c.fd); want.push(net::WANT_READ); }
        var ready: u8[>..] = [];
        for k in fds.len { ready.push(0); }
        let n = net::poll(fds, want, ready, 1000);
        if n <= 0 { continue; }
        let polled = conns.len;
        if ready[0] != 0 {
            let fd = net::accept(lfd, 1000);
            if fd >= 0 { conns.push(Client { fd: fd, owner: [], known: false, rbuf: [], conn: tls::server(t), web: kmip::http_conn(path) }); }
        }
        // The connections polled, from the last, so that a closed one can go.
        var k = polled - 1;
        while k >= 0 {
            if ready[1 + k] == 0 { k--; continue; }
            var closed = false;
            let got = net::read(conns[k].fd, rbuf, 1000);
            if got <= 0 { closed = true; }
            else {
                var out: u8[>..] = [];
                var app: u8[>..] = [];
                let fr = tls::feed(conns[k].conn, t, rbuf[..got], out, app);
                if fr < 0 || conns[k].rbuf.len + app.len > conns[k].rbuf.cap { closed = true; }
                else { conns[k].rbuf.append(app); }
                if !closed && !conns[k].known && tls::connected(conns[k].conn) {
                    let id = kmip::peer_identity(tls::peer_certificates(conns[k].conn));
                    conns[k].owner.append(id[..::min(id.len, 128)]);
                    conns[k].known = true;
                    print("connection from ", conns[k].owner);
                }
                // Over HTTPS: every whole request that came.
                if http && !closed {
                    var reply: u8[>..] = [];
                    var owner: u8[..128] = [];
                    owner.append(conns[k].owner);
                    let used, done = kmip::http_serve(srv, owner, conns[k].web, conns[k].rbuf, reply);
                    var rest: u8[>..] = [];
                    rest.append(conns[k].rbuf[used..]);
                    conns[k].rbuf.clear();
                    conns[k].rbuf.append(rest);
                    if reply.len > 0 && !tls::send(conns[k].conn, reply, out) { closed = true; }
                    if done {
                        var bye: u8[>..] = [];
                        tls::close(conns[k].conn, bye);
                        out.append(bye);
                        let w = net::write(conns[k].fd, out, 1000);
                        out.clear();
                        closed = true;
                    }
                }
                // Every whole message that came.
                loop {
                    if http || closed || conns[k].rbuf.len < 8 { break; }
                    let need = kmip::message_length(conns[k].rbuf[..8]);
                    if need < 0 || need > conns[k].rbuf.cap { closed = true; break; }
                    if conns[k].rbuf.len < need { break; }
                    var reply: u8[>..] = [];
                    var owner: u8[..128] = [];
                    owner.append(conns[k].owner);
                    kmip::handle(srv, owner, conns[k].rbuf[..need], reply);
                    var rest: u8[>..] = [];
                    rest.append(conns[k].rbuf[need..]);
                    conns[k].rbuf.clear();
                    conns[k].rbuf.append(rest);
                    if !tls::send(conns[k].conn, reply, out) { closed = true; }
                }
                if out.len > 0 && net::write(conns[k].fd, out, 1000) < 0 { closed = true; }
                if tls::closed(conns[k].conn) { closed = true; }
            }
            if closed {
                net::close(conns[k].fd);
                let gone = remove_at(conns, k);
                closed_count++;
            }
            k--;
        }
    }
    print("goose-kmipd: ", kmip::object_count(srv), " objects at the end");
}
