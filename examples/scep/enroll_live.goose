// enroll_live: a certificate from a SCEP server you name, the whole of it
// in one call: GetCACaps, GetCACert, then PKCSReq with a fresh RSA key,
// polling while the CA holds the request. The challenge password comes
// from SCEP_CHALLENGE. Needs a server, so `make test` only type-checks it.
//
//   SCEP_CHALLENGE=... goose examples/scep/enroll_live.goose -- http://127.0.0.1:8080/scep CN=device-0042
//
// (micromdm's scepserver, for one; add `legacy` after the subject for a
// server built on Go's pkcs7, which replies with SHA-1 and DES whatever
// its caps say.)

import std;
import os;
import gslib from "../..";
import gslib.scep;
import gslib.net.http.client;
import gslib.net.http.fetch;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.encoding.asn1;

fn main() {
    let a = args();
    if a.len < 3 { print("usage: enroll_live.goose -- URL SUBJECT [legacy]"); exit(2); }
    var hc = http::Client { .. };
    var c = scep::Client { .. };
    if scep::set_url(c, a[1]) != scep::OK { print("not a URL without a query"); exit(2); }
    c.legacy = a.len > 3 && a[3] == "legacy";
    if scep::get_caps(c, hc) != scep::OK { print("GetCACaps failed"); exit(1); }
    let ge = scep::get_ca_cert(c, hc);
    if ge != scep::OK { print("GetCACert: ", scep::error_text(ge)); exit(1); }

    let k = x509::generate_key(x509::KEY_RSA, 2048);
    let subject, sok = x509::name_der(a[2]);
    if !sok { print("not a DN"); exit(2); }
    var pw: u8[>..] = [];
    env("SCEP_CHALLENGE", pw);
    let csr, e = scep::make_csr(subject, "", k, pw);
    let signer, se = scep::self_signed(csr, k);
    if e != scep::OK || se != scep::OK { print("cannot make the request"); exit(1); }
    let certs, err = scep::enroll(c, hc, csr, k, signer, false);
    if err != scep::OK {
        print("enroll: ", scep::error_text(err), " ", scep::fail_name(c.fail_info));
        exit(1);
    }
    let cert, pe = x509::parse(scep::first_cert(certs));
    print("issued: ", x509::subject_text(cert), ", serial ", x509::serial_hex(cert));
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "CERTIFICATE", scep::first_cert(certs));
    print(pem);
}
