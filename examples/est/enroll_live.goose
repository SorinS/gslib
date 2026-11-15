// enroll_live: a certificate from an EST server you name: /cacerts with
// the server checked against a PEM file of roots you trust for it (RFC
// 7030's explicit trust anchor), then /simpleenroll for a new P-256 key,
// asking again while the CA answers 202. Credentials, if the server wants
// them, from EST_USER and EST_PASSWORD. Needs a server, so `make test` only
// type-checks it.
//
//   goose examples/est/enroll_live.goose -- https://127.0.0.1:8443 roots.pem CN=device-0042

import std;
import os;
import gslib from "../..";
import gslib.est;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.tls;
import gslib.crypto.tls.handshake;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.encoding.asn1;

fn main() {
    let a = args();
    if a.len < 4 { print("usage: enroll_live.goose -- URL ROOTS.pem SUBJECT"); exit(2); }
    var hc = http::Client { .. };
    var text: u8[>..] = [];
    if !read_file(a[2], text) { print("cannot read ", a[2]); exit(2); }
    var pool = x509::new_pool();
    if x509::pool_append_pem(pool, text) <= 0 { print("no certificates in ", a[2]); exit(2); }
    hc.tlscfg = tls::client_config_pool("", pool);
    var user: u8[>..] = [];
    var pw:   u8[>..] = [];
    if env("EST_USER", user) && env("EST_PASSWORD", pw) { http::set_credentials(hc, user, pw); }

    var c = est::Client { .. };
    if est::set_server(c, a[1]) != est::OK { print("not a URL without a path"); exit(2); }
    let cas, e1 = est::cacerts(c, hc);
    if e1 != est::OK { print("/cacerts: ", est::error_text(e1)); exit(1); }
    let k = x509::generate_key(x509::KEY_EC_P256);
    let subject, sok = x509::name_der(a[3]);
    if !sok { print("not a DN"); exit(2); }
    let csr, ce = x509::create_csr(subject, "", k);
    let certs, e2 = est::enroll(c, hc, csr, false);
    if e2 != est::OK { print("/simpleenroll: ", est::error_text(e2), " (HTTP ", c.status, ")"); exit(1); }
    let cert, pe = x509::parse(est::first_cert(certs));
    print("issued: ", x509::subject_text(cert), ", serial ", x509::serial_hex(cert));
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "CERTIFICATE", est::first_cert(certs));
    print(pem);
}
