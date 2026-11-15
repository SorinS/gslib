// est without a network: RFC 7030 §4.5.2's CsrAttrs example, base64
// with and without line breaks (RFC 8951 §3), labels and server URLs,
// Retry-After; then each request through the test CA (est::serve) and its
// answer read back as the client reads it: /cacerts, /csrattrs (and 204
// for none), /simpleenroll with HTTP Basic (401 without it, or with the
// wrong password), with a client certificate instead, 202 and Retry-After
// then the certificate, /simplereenroll (only with the client's
// certificate, for its own subject), /serverkeygen's multipart key and
// certificate, under a label. And what a hostile server might send:
// certs-only that is signed, holds no certificate, or a certificate for
// another key; base64 that is not; CsrAttrs that are not; multipart with
// two keys, no certificate, a key that is not the certificate's, or an
// encrypted key; all refused.
import std;
import os;
import base64;
import gslib from "../..";
import gslib.est;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.cms;
import gslib.encoding.asn1;
import gslib.net.http;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn file(path: const u8[:]) -> u8[>..] {
    var t: u8[>..] = [];
    assert(read_file(path, t));
    return t;
}

fn pem_cert(path: const u8[:]) -> u8[>..] {
    let ders, ok = asn1::pem_decode(file(path), "CERTIFICATE");
    var out: u8[>..] = [];
    for d in ders { out.append(d); }
    return out;
}

fn key(path: const u8[:]) -> x509::PrivateKey {
    let k, ok = x509::parse_private_key_pem(file(path));
    assert(ok);
    return k;
}

let NOW: i64 = 1800000000;

// RFC 7030 §4.5.2's example: challengePassword, ecdsa-with-SHA384, an
// extensionRequest for macAddress, and an EC key on P-384.
let RFC_CSRATTRS: const u8[:] = "MEEGCSqGSIb3DQEJBwYIKoZIzj0EAwMwFgYJKoZIhvcNAQkOMQkGBysGAQEBARYwEgYHKoZIzj0CATEHBgUrgQQAIg==";

fn csr_for(k: const x509::PrivateKey&, cn: const u8[:]) -> u8[>..] {
    let n, ok = x509::name_der(str("CN=", cn));
    assert(ok);
    var san: u8[..4096] = [];
    x509::add_dns(san, cn);
    let csr, e = x509::create_csr(n, san, k);
    assert(e == x509::OK);
    return csr;
}

fn spki_of(csr: const u8[:]) -> u8[>..] {
    let r, e = x509::parse_csr(csr);
    var out: u8[>..] = [];
    out.append(r.der[r.spki.start..r.spki.end]);
    return out;
}

fn basics() {
    let der, ok = est::decode_base64(RFC_CSRATTRS);
    let a, e = est::parse_csrattrs(der);
    check("RFC 7030's CsrAttrs", ok && e == est::OK && a.items[..] ==
          "1.2.840.113549.1.9.7\n1.2.840.10045.4.3.3\n1.2.840.113549.1.9.14=1.3.6.1.1.1.1.22\n1.2.840.10045.2.1=1.3.132.0.34\n");
    check("challengePassword asked", est::csrattrs_has(a, "1.2.840.113549.1.9.7"));
    check("the curve asked", est::csrattrs_values(a, "1.2.840.10045.2.1") == "1.3.132.0.34");
    check("nothing else", !est::csrattrs_has(a, "1.2.3") && est::csrattrs_values(a, "1.2.840.113549.1.9.7").len == 0);
    // An attribute with a value that is not an OID: as hex.
    var v: u8[>..] = [];
    asn1::put_oid(v, "1.2.3.4");
    var set: u8[>..] = [];
    asn1::put_i64(set, 42);
    asn1::put(v, asn1::SET, set);
    var attr: u8[>..] = [];
    asn1::put(attr, asn1::SEQUENCE, v);
    var all: u8[>..] = [];
    asn1::put(all, asn1::SEQUENCE, attr);
    let a2, e2 = est::parse_csrattrs(all);
    check("a value that is not an OID, in hex", e2 == est::OK && a2.items[..] == "1.2.3.4=#02012A\n");
    // Not CsrAttrs: an attribute without its SET, or a stray INTEGER.
    var bad: u8[>..] = [];
    var b1:  u8[>..] = [];
    asn1::put_oid(b1, "1.2.3.4");
    asn1::put_i64(b1, 1);
    var ba: u8[>..] = [];
    asn1::put(ba, asn1::SEQUENCE, b1);
    asn1::put(bad, asn1::SEQUENCE, ba);
    let a3, e3 = est::parse_csrattrs(bad);
    var bad2: u8[>..] = [];
    var b2:   u8[>..] = [];
    asn1::put_i64(b2, 7);
    asn1::put(bad2, asn1::SEQUENCE, b2);
    let a4, e4 = est::parse_csrattrs(bad2);
    let a5, e5 = est::parse_csrattrs("junk");
    check("malformed CsrAttrs refused", e3 == est::ERR_MALFORMED && e4 == est::ERR_MALFORMED && e5 == est::ERR_MALFORMED);

    // base64 with CRLF, LF, spaces (RFC 8951 §3); not base64 refused.
    let x1, o1 = est::decode_base64("Zm9v\r\nYmFy\r\n");
    let x2, o2 = est::decode_base64("  Zm9v YmFy\n");
    let x3, o3 = est::decode_base64("Zm9v*mFy");
    let x4, o4 = est::decode_base64("\r\n");
    check("base64 with line breaks", o1 && x1 == "foobar" && o2 && x2 == "foobar");
    check("not base64, or nothing", !o3 && !o4);
    let enc = est::encode_base64(der);
    let back, okb = est::decode_base64(enc);
    check("base64 out in lines", find(enc, "\r\n") == 64 && okb && back == der);

    var c = est::Client { .. };
    check("a server with a path is refused", est::set_server(c, "https://est.example.org/x") == est::ERR_ARG);
    check("a server with a port", est::set_server(c, "https://est.example.org:8443") == est::OK);
    check("the default URL", est::op_url(c, "cacerts") == "https://est.example.org:8443/.well-known/est/cacerts");
    check("a label", est::set_label(c, "arbitraryLabel1") == est::OK &&
          est::op_url(c, "simpleenroll") == "https://est.example.org:8443/.well-known/est/arbitraryLabel1/simpleenroll");
    check("labels that would be another path refused", est::set_label(c, "a/b") == est::ERR_ARG &&
          est::set_label(c, "..") == est::ERR_ARG && est::set_label(c, "a?b") == est::ERR_ARG &&
          est::set_label(c, "a%2fb") == est::ERR_ARG && est::set_label(c, "a b") == est::ERR_ARG &&
          est::set_label(c, "a\nb") == est::ERR_ARG);
    check("Retry-After in seconds", est::retry_after_ms("120", 0) == 120000);
    check("Retry-After as a date", est::retry_after_ms("Wed, 21 Oct 2015 07:28:00 GMT", 1445412470000) == 10000);
    check("Retry-After unreadable or past", est::retry_after_ms("soon", 0) == 0 &&
          est::retry_after_ms("Wed, 21 Oct 2015 07:28:00 GMT", 1445412490000) == 0);
}

fn fields_of(user: const u8[:], pw: const u8[:]) -> u8[>..] {
    var f: u8[>..] = [];
    f.append("Content-Type: application/pkcs10\r\n");
    if user.len > 0 {
        var cred: u8[>..] = [];
        base64::encode(cred, str(user, ":", pw));
        f.append(str("Authorization: Basic ", cred, "\r\n"));
    }
    return f;
}

// The certificates of an /simpleenroll-like answer, as the client reads them.
fn certs_of(a: const est::Answer&) -> u8[>..], i64 {
    let der, ok = est::decode_base64(a.body);
    if !ok { var none: u8[>..] = []; return none, est::ERR_MALFORMED; }
    let certs, e = est::read_certs_only(der);
    return certs, e;
}

fn through_server() {
    var s = est::Server { .. };
    s.ca_key = key("vectors/ca.key");
    s.ca_cert = pem_cert("vectors/ca.pem");
    s.user.append("estuser");
    s.password.append("est pass");
    let rfc, rok = est::decode_base64(RFC_CSRATTRS);
    s.attrs = copy(rfc);

    let a1 = est::serve(s, "GET", "/.well-known/est/cacerts", "", "", "", NOW);
    let cas, e1 = certs_of(a1);
    check("cacerts", a1.status == 200 && find(a1.content_type, "application/pkcs7-mime") == 0 && e1 == est::OK &&
          cas[..] == s.ca_cert[..]);
    let a2 = est::serve(s, "GET", "/.well-known/est/csrattrs", "", "", "", NOW);
    let der2, ok2 = est::decode_base64(a2.body);
    let at2, e2 = est::parse_csrattrs(der2);
    check("csrattrs", a2.status == 200 && e2 == est::OK && est::csrattrs_has(at2, "1.2.840.113549.1.9.7"));

    let k = key("vectors/client.key");
    let csr = csr_for(k, "device.example.org");
    let body = est::encode_base64(csr);
    let a3 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("", ""), body, "", NOW);
    check("simpleenroll without credentials: 401 with a Basic challenge", a3.status == 401 && find(a3.fields, "Basic") > 0);
    let a4 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "wrong"), body, "", NOW);
    check("the wrong password: 401", a4.status == 401);
    let a5 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "est pass"), body, "", NOW);
    let certs5, e5 = certs_of(a5);
    let issued5, f5 = est::issued_first(certs5, spki_of(csr));
    check("simpleenroll with Basic", a5.status == 200 && e5 == est::OK && f5);
    let leaf = est::first_cert(issued5);
    let lc, le = x509::parse(leaf);
    let cac, cae = x509::parse(s.ca_cert);
    check("issued by the CA for the CSR's name", le == x509::OK && x509::check_signature(lc, cac) == x509::OK &&
          x509::subject_text(lc) == "CN=device.example.org");
    let a6 = est::serve(s, "POST", "/.well-known/est/simpleenroll", "Content-Type: text/plain\r\n", body, leaf, NOW);
    check("not application/pkcs10: 415", a6.status == 415);
    let a7 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "est pass"), "bm90IGEgQ1NS", "", NOW);
    check("not a CSR: 400", a7.status == 400);

    // A client certificate in place of credentials; re-enrolment with it.
    let a8 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("", ""), body, leaf, NOW);
    check("simpleenroll by client certificate", a8.status == 200);
    let k2 = key("vectors/client2.key");
    let csr2 = csr_for(k2, "device.example.org");
    let a9 = est::serve(s, "POST", "/.well-known/est/simplereenroll", fields_of("", ""), est::encode_base64(csr2), leaf, NOW);
    let certs9, e9 = certs_of(a9);
    let issued9, f9 = est::issued_first(certs9, spki_of(csr2));
    check("simplereenroll for a new key", a9.status == 200 && f9);
    let a10 = est::serve(s, "POST", "/.well-known/est/simplereenroll", fields_of("estuser", "est pass"), est::encode_base64(csr2), "", NOW);
    check("simplereenroll without the certificate: 403", a10.status == 403);
    let other = csr_for(k2, "someone.example.org");
    let a11 = est::serve(s, "POST", "/.well-known/est/simplereenroll", fields_of("", ""), est::encode_base64(other), leaf, NOW);
    check("simplereenroll for another subject: 400", a11.status == 400);
    let a12 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("", ""), body, s.ca_cert, NOW);
    check("a client certificate the CA did not issue does not count", a12.status == 401);

    // Held: 202 and Retry-After, twice, then the certificate.
    s.pending = 2;
    s.retry_s = 7;
    let k3 = x509::generate_key(x509::KEY_EC_P256);
    let csr3 = csr_for(k3, "held.example.org");
    let b3 = est::encode_base64(csr3);
    let h1 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "est pass"), b3, "", NOW);
    let h2 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "est pass"), b3, "", NOW);
    let h3 = est::serve(s, "POST", "/.well-known/est/simpleenroll", fields_of("estuser", "est pass"), b3, "", NOW);
    let rv, hasr = http::field_value(h1.fields, "Retry-After");
    check("held: 202 with Retry-After", h1.status == 202 && h2.status == 202 && hasr && rv == "7");
    check("then issued", h3.status == 200);
    s.pending = 0;

    // serverkeygen, under a label.
    let a13 = est::serve(s, "POST", "/.well-known/est/arbitraryLabel1/serverkeygen", fields_of("estuser", "est pass"), body, "", NOW);
    let kder, kcerts, ke = est::read_keygen(a13.content_type, a13.body);
    let gk, gok = x509::parse_private_key(kder);
    let kleaf, kc = x509::parse(est::first_cert(kcerts));
    check("serverkeygen: a key and its certificate", a13.status == 200 && ke == est::OK && gok &&
          kleaf.der[kleaf.spki.start..kleaf.spki.end] == x509::marshal_public_key(gk)[..]);
    let a14 = est::serve(s, "GET", "/.well-known/est/a/b/cacerts", "", "", "", NOW);
    let a15 = est::serve(s, "GET", "/.well-known/est/../cacerts", "", "", "", NOW);
    check("two labels, or one that is a dot-dot: 404", a14.status == 404 && a15.status == 404);
    s.attrs.clear();
    let a16 = est::serve(s, "GET", "/.well-known/est/csrattrs", "", "", "", NOW);
    check("no csrattrs: 204", a16.status == 204);
}

fn part(out: u8[>..]&, ct: const u8[:], der: const u8[:]) {
    out.append(str("--b0\r\nContent-Type: ", ct, "\r\nContent-Transfer-Encoding: base64\r\n\r\n"));
    out.append(est::encode_base64(der));
}

fn hostile() {
    let ca_key = key("vectors/ca.key");
    let ca = pem_cert("vectors/ca.pem");
    let cac, cae = x509::parse(ca);
    let k = key("vectors/client.key");
    let csr = csr_for(k, "device.example.org");
    // Certs-only that is signed, or empty.
    let signed, oks = x509::cms_sign(x509::OID_CMS_DATA, "x", ca_key, cac, "", x509::SIG_ECDSA, 256);
    let c1, e1 = est::read_certs_only(signed);
    let c2, e2 = est::read_certs_only(x509::cms_certs_only("", ""));
    let c3, e3 = est::read_certs_only("junk");
    check("certs-only signed, empty or junk: refused", e1 == est::ERR_MALFORMED && e2 == est::ERR_MALFORMED && e3 == est::ERR_MALFORMED);
    // A certificate for another key.
    let c4, f4 = est::issued_first(ca, spki_of(csr));
    check("a certificate for another key: not taken", !f4);

    // serverkeygen's multipart, made wrong in each way.
    let gk = x509::generate_key(x509::KEY_EC_P256);
    var t, okt = x509::template("CN=device.example.org", NOW - 60, NOW + 86400);
    let cert, ce = x509::create_certificate(t, x509::marshal_public_key(gk), ca, ca_key);
    let co = x509::cms_certs_only(cert, "");
    let p8 = x509::marshal_pkcs8(gk);
    let ct = "multipart/mixed; boundary=b0";
    var good: u8[>..] = [];
    part(good, "application/pkcs8", p8);
    part(good, "application/pkcs7-mime; smime-type=certs-only", co);
    good.append("--b0--\r\n");
    let k0, cs0, e0 = est::read_keygen(ct, good);
    check("serverkeygen's answer", e0 == est::OK && k0[..] == p8[..]);
    let kb, csb, eb = est::read_keygen("multipart/mixed", good);
    let kc2, csc2, ec2 = est::read_keygen("application/pkcs8", good);
    check("no boundary, or not multipart: refused", eb == est::ERR_MALFORMED && ec2 == est::ERR_MALFORMED);
    var two: u8[>..] = [];
    part(two, "application/pkcs8", p8);
    part(two, "application/pkcs8", p8);
    part(two, "application/pkcs7-mime; smime-type=certs-only", co);
    two.append("--b0--\r\n");
    let k5, cs5, e5 = est::read_keygen(ct, two);
    check("two keys: refused", e5 == est::ERR_MALFORMED && k5.len == 0);
    var nocert: u8[>..] = [];
    part(nocert, "application/pkcs8", p8);
    nocert.append("--b0--\r\n");
    let k6, cs6, e6 = est::read_keygen(ct, nocert);
    check("no certificate: refused", e6 == est::ERR_MALFORMED && k6.len == 0);
    let other = x509::generate_key(x509::KEY_EC_P256);
    var swapped: u8[>..] = [];
    part(swapped, "application/pkcs8", x509::marshal_pkcs8(other));
    part(swapped, "application/pkcs7-mime; smime-type=certs-only", co);
    swapped.append("--b0--\r\n");
    let k7, cs7, e7 = est::read_keygen(ct, swapped);
    check("a key that is not the certificate's: refused", e7 == est::ERR_KEY && k7.len == 0);
    var enc: u8[>..] = [];
    part(enc, "application/pkcs7-mime; smime-type=server-generated-key", "an EnvelopedData would be here");
    part(enc, "application/pkcs7-mime; smime-type=certs-only", co);
    enc.append("--b0--\r\n");
    let k8, cs8, e8 = est::read_keygen(ct, enc);
    check("an encrypted key: unsupported, said so", e8 == est::ERR_UNSUPPORTED);
    var notb64: u8[>..] = [];
    notb64.append("--b0\r\nContent-Type: application/pkcs8\r\n\r\n***\r\n--b0--\r\n");
    let k9, cs9, e9 = est::read_keygen(ct, notb64);
    let k10, cs10, e10 = est::read_keygen(ct, "no parts at all");
    check("not base64, or no parts: refused", e9 == est::ERR_MALFORMED && e10 == est::ERR_MALFORMED);
}

fn main() {
    basics();
    through_server();
    hostile();
    print("est: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
