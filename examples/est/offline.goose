// offline: EST's requests without a network. A test CA (est::Server) that
// asks for HTTP Basic credentials and holds each new key once (202,
// Retry-After); a device asks for /cacerts and /csrattrs, then
// /simpleenroll: refused without credentials, held, then issued, the
// certificate read from its certs-only reply as est::enroll reads it; then
// /serverkeygen, the key and certificate from its multipart reply.
//
//   goose examples/est/offline.goose

import std;
import base64;
import gslib from "../..";
import gslib.est;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let NOW: i64 = 1800000000;

fn fields(with_credentials: bool) -> u8[>..] {
    var f: u8[>..] = [];
    f.append("Content-Type: application/pkcs10\r\n");
    if with_credentials {
        var cred: u8[>..] = [];
        base64::encode(cred, "device-0042:enrolment secret");
        f.append(str("Authorization: Basic ", cred, "\r\n"));
    }
    return f;
}

fn main() {
    var s = est::Server { .. };
    s.ca_key = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template("CN=Example EST CA,O=Example", NOW - 3600, NOW + 365 * 86400);
    t.basic_constraints = true;
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let ca, ce = x509::create_certificate(t, x509::marshal_public_key(s.ca_key), "", s.ca_key);
    assert(ce == x509::OK);
    s.ca_cert = copy(ca);
    s.user.append("device-0042");
    s.password.append("enrolment secret");
    s.pending = 1;
    s.retry_s = 30;

    let a1 = est::serve(s, "GET", "/.well-known/est/cacerts", "", "", "", NOW);
    let der1, ok1 = est::decode_base64(a1.body);
    let cas, e1 = est::read_certs_only(der1);
    assert(e1 == est::OK);
    let cac, cae = x509::parse(est::first_cert(cas));
    print("/cacerts: ", x509::subject_text(cac));
    let a2 = est::serve(s, "GET", "/.well-known/est/csrattrs", "", "", "", NOW);
    print("/csrattrs: ", a2.status, " (nothing asked)");

    let k = x509::generate_key(x509::KEY_EC_P256);
    let subject, sok = x509::name_der("CN=device-0042");
    var san: u8[..4096] = [];
    x509::add_dns(san, "device-0042.example.org");
    let csr, cerr = x509::create_csr(subject, san, k);
    assert(cerr == x509::OK);
    let body = est::encode_base64(csr);
    let r1 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields(false), body, "", NOW);
    print("/simpleenroll without credentials: ", r1.status);
    let r2 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields(true), body, "", NOW);
    let after = est::retry_after_ms("30", 0);
    print("/simpleenroll: ", r2.status, ", ask again in ", after / 1000, " s");
    let r3 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields(true), body, "", NOW);
    let der3, ok3 = est::decode_base64(r3.body);
    let certs, e3 = est::read_certs_only(der3);
    let issued, found = est::issued_first(certs, x509::marshal_public_key(k));
    assert(r3.status == 200 && e3 == est::OK && found);
    let ic, ie = x509::parse(est::first_cert(issued));
    print("/simpleenroll: ", r3.status, ", ", x509::subject_text(ic), " issued by ", x509::issuer_text(ic));

    let r4 = est::serve(s, "POST", "/.well-known/est/serverkeygen", fields(true), body, "", NOW);
    let key, kcerts, e4 = est::read_keygen(r4.content_type, r4.body);
    assert(e4 == est::OK);
    print("/serverkeygen: a PKCS #8 key of ", key.len, " bytes and its certificate");
}
