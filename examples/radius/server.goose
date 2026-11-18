// server: a RADIUS server in a few lines: PAP, CHAP, MS-CHAPv2 and PEAP
// and TTLS for one user, over UDP on 127.0.0.1:11812, answering until
// stopped. Its certificate (for PEAP and TTLS) is made at the start; a
// supplicant that should trust it needs that CA, so test it with
// radtest (PAP, CHAP) or with gslib's own radtest tool (radius/tools).
//
//   goose examples/radius/server.goose
//   radtest alice alice-pw 127.0.0.1:11812 0 testing123

import std;
import gslib from "../..";
import gslib.net;
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.server;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

fn main() {
    let k = x509::generate_key(x509::KEY_EC_P256);
    let now = time_ns() / 1000000000;
    var t, okt = x509::template("CN=radius.example.com", now - 60, now + 30 * 86400);
    x509::add_dns(t.san, "radius.example.com");
    let cert, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    var tc, ok = tls::server_config(cert, x509::marshal_pkcs8(k));
    if !okt || e != x509::OK || !ok { print("server: no certificate"); exit(1); }
    let methods: u8[2] = [radius::EAP_PEAP, radius::EAP_TTLS];
    let cfg = radius::eap_config(methods, tc);

    var srv = radius::server("testing123");
    let fd = net::listen_udp("127.0.0.1", 11812);
    if fd < 0 { print("server: cannot listen"); exit(1); }
    print("RADIUS on 127.0.0.1:11812, secret testing123, user alice / alice-pw");
    var buf: u8[4096] = [0; 4096];
    loop {
        let n, from = net::recv_from(fd, buf, 0);
        if n <= 0 { continue; }
        var reply: u8[>..] = [];
        let req, er = radius::handle(srv, cfg, buf[..n], reply) { user =>
            var pw: u8[>..] = [];
            if user == "alice" { pw.append("alice-pw"); }
            pw
        };
        if reply.len > 0 {
            print(radius::code_name(req.code), " for ", radius::get_text(req, radius::USER_NAME), ": ", radius::code_name(reply[0]));
            let w = net::send_to(fd, reply, from);
        }
    }
}
