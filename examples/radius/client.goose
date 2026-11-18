// client: a NAS's side of RADIUS against a real server: PAP, then PEAP
// with MS-CHAPv2 inside (the MS-MPPE keys checked against the
// supplicant's MSK), then an accounting Start and Stop (to port 1813
// over UDP). Over UDP, or over
// RadSec (RADIUS over TLS) with a client certificate.
//
//   goose examples/radius/client.goose -- HOST SECRET USER PASSWORD CA.pem
//   goose examples/radius/client.goose -- HOST radsec USER PASSWORD CA.pem CERT.pem KEY.pem
//
// CA.pem is the CA of the server's certificate (PEAP's, and RadSec's),
// whose name is taken to be radius.example.com.

import std;
import os;
import gslib from "../..";
import gslib.radius;
import gslib.radius.mschap;
import gslib.radius.eap;
import gslib.radius.client;
import gslib.encoding.asn1;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;

fn pem_der(path: const u8[:], label: const u8[:]) -> u8[>..] {
    var text: u8[>..] = [];
    if !read_file(path, text) { print("client: cannot read ", path); exit(2); }
    var out: u8[>..] = [];
    let ders, ok = asn1::pem_decode(text, label);
    for d in ders { out.append(d); }
    return out;
}

// UDP with the secret, or RadSec with a certificate (cert, key: files).
fn connect(host: const u8[:], secret: const u8[:], cc: const tls::ClientConfig&, cert: const u8[:],
           key: const u8[:]) -> radius::Client, i64 {
    if secret != "radsec" { return radius::dial(host, 1812, secret); }
    var rc = copy(cc);
    if cert.len == 0 || !tls::set_client_certificate(rc, pem_der(cert, "CERTIFICATE"), pem_der(key, "PRIVATE KEY")) {
        print("client: RadSec needs CERT.pem and KEY.pem");
        exit(2);
    }
    return radius::dial_radsec(host, 2083, rc);
}

fn accounting(c: radius::Client&, user: const u8[:]) {
    let base = radius::request(radius::ACCOUNTING_REQUEST);
    let r1, e1 = radius::account(c, radius::ACCT_START, "example-1", user, base);
    let r2, e2 = radius::account(c, radius::ACCT_STOP, "example-1", user, base);
    print("accounting: ", radius::error_text(e1), ", ", radius::error_text(e2));
}

fn main() {
    let a = args();
    if a.len < 6 { print("usage: client.goose -- HOST SECRET|radsec USER PASSWORD CA.pem [CERT.pem KEY.pem]"); exit(2); }
    let cc = tls::client_config("radius.example.com", pem_der(a[5], "CERTIFICATE"));
    var c, e = connect(a[1], a[2], cc, if a.len > 6 { a[6] } else { "" }, if a.len > 7 { a[7] } else { "" });
    if e != radius::OK { print("client: ", radius::error_text(e)); exit(1); }

    let r1, e1 = radius::authenticate_pap(c, a[3], a[4]);
    print("PAP: ", radius::error_text(e1), if e1 == radius::OK { str(" (", radius::get_text(r1, radius::REPLY_MESSAGE), ")") } else { str("") });

    var pc = radius::peer_config(a[3], a[4], radius::EAP_PEAP);
    pc.outer_identity.append("anonymous");
    pc.tls = copy(cc);
    var p = radius::peer(pc);
    let r2, e2 = radius::authenticate_eap(c, p, pc);
    print("PEAP: ", radius::error_text(e2), if e2 == radius::OK { ", MS-MPPE keys = the MSK" } else { "" });

    // Accounting: over UDP to its own port, 1813; RadSec carries both.
    if a[2] == "radsec" {
        accounting(c, a[3]);
    } else {
        var ac, ea = radius::dial(a[1], 1813, a[2]);
        accounting(ac, a[3]);
        radius::close(ac);
    }
    radius::close(c);
}
