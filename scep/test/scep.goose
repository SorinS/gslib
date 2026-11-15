// scep without a network: GetCACaps' keywords and the algorithms they
// choose; a CSR with a challengePassword; PKCSReq through the test CA
// (scep::serve) and its CertRep read back as the client reads it (signed
// by the CA, transactionID and nonces, the envelope opened, the issued
// certificate's key the request's); PENDING then CertPoll; a wrong
// challenge refused with badRequest; RenewalReq signed by the issued
// certificate, and refused when signed by a stranger; GetCert and GetCRL;
// PKIOperation by GET in base64. Then what a hostile server might send:
// a CertRep signed by another key under the CA's own name, unsigned, with
// a signature changed, with another transactionID or recipientNonce, an
// attribute twice, SHA-1 or DES where c.legacy is off, a certificate for
// another key, garbage; all refused before anything in it is used.
import std;
import os;
import base64;
import gslib from "../..";
import gslib.scep;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.cms_env;
import gslib.encoding.asn1;
import gslib.net.http.url;

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

let NOW: i64 = 1800000000;      // 2027-01-15

fn subject(cn: const u8[:]) -> u8[>..] {
    let n, ok = x509::name_der(str("CN=", cn, ",O=Example"));
    assert(ok);
    return n;
}

fn caps() {
    let k = scep::parse_caps("Renewal\r\nSHA-1\r\nSHA-256\r\nAES\r\nDES3\r\nSCEPStandard\r\nPOSTPKIOperation");
    check("micromdm's caps", k.renewal && k.sha1 && k.sha256 && k.aes && k.des3 && k.post && k.scep_standard && !k.sha512);
    let k2 = scep::parse_caps("aes\nsha-512\ngetnextcacert\nunknown-thing\n");
    check("caps without regard to case", k2.aes && k2.sha512 && k2.get_next_ca && !k2.post && !k2.sha256);
    let k3 = scep::parse_caps("SCEPStandard\n");
    check("SCEPStandard has AES, POST and SHA-256", k3.aes && k3.post && k3.sha256);
    let c1, h1, e1 = scep::choose_algorithms(k, false, false);
    check("AES-128 and SHA-256 by the caps", e1 == scep::OK && c1 == x509::CMS_AES128_CBC && h1 == 256);
    let c2, h2, e2 = scep::choose_algorithms(k, false, true);
    check("AES-256 when asked", e2 == scep::OK && c2 == x509::CMS_AES256_CBC);
    let none = scep::parse_caps("");
    let c3, h3, e3 = scep::choose_algorithms(none, false, false);
    check("no caps: refused without legacy", e3 == scep::ERR_ALGORITHM);
    let c4, h4, e4 = scep::choose_algorithms(none, true, false);
    check("no caps: DES-EDE3 and SHA-1 with legacy", e4 == scep::OK && c4 == x509::CMS_DES3_CBC && h4 == 160);
    let c5, h5, e5 = scep::choose_algorithms(k2, false, false);
    check("SHA-512 when there is no SHA-256", e5 == scep::OK && h5 == 512);
}

fn csr() {
    let k = key("vectors/client.key");
    var san: u8[..4096] = [];
    x509::add_dns(san, "device.example.org");
    let req, e = scep::make_csr(subject("device.example.org"), san, k, "s3cret pw");
    check("a CSR with a challengePassword", e == scep::OK);
    let r, pe = x509::parse_csr(req);
    check("it verifies", pe == x509::OK && x509::check_csr(r) == x509::OK);
    let pw, n = x509::csr_attribute(r, scep::OID_CHALLENGE_PASSWORD);
    let text, ok = asn1::read_string(r.der, pw);
    check("its challengePassword, a PrintableString", n == 1 && pw.tag == asn1::PRINTABLE_STRING && ok && text == "s3cret pw");
    let req2, e2 = scep::make_csr(subject("device"), "", k, "pässwort");
    let r2, pe2 = x509::parse_csr(req2);
    let pw2, n2 = x509::csr_attribute(r2, scep::OID_CHALLENGE_PASSWORD);
    check("a password that is not printable goes as UTF8String", e2 == scep::OK && n2 == 1 && pw2.tag == 0x0c);
    let req3, e3 = scep::make_csr(subject("device"), "", k, "");
    let r3, pe3 = x509::parse_csr(req3);
    let pw3, n3 = x509::csr_attribute(r3, scep::OID_CHALLENGE_PASSWORD);
    check("no password, no attribute", e3 == scep::OK && n3 == 0);
    let ec = x509::generate_key(x509::KEY_EC_P256);
    let req4, e4 = scep::make_csr(subject("device"), "", ec, "x");
    check("an EC key is refused: the CA encrypts to it by RSA", e4 == scep::ERR_ARG);
    check("transactionID: the key's SHA-256 in hex", scep::transaction_id("abc")
          == "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
}

// A request as the client sends it, and what it sent, to check the reply by.
fn request(mt: i64, payload: const u8[:], k: const x509::PrivateKey&, signer: const u8[:], tid: const u8[:],
           ca: const u8[:]) -> u8[>..], scep::Attrs {
    var a = scep::Attrs { .. };
    a.message_type = mt;
    a.transaction_id.append(tid);
    let n = scep::new_nonce();
    a.sender_nonce.append(n[..]);
    let msg, e = scep::build_message(a, payload, ca, x509::CMS_AES128_CBC, k, signer, 256);
    assert(e == scep::OK);
    return msg, a;
}

// The client's reading of a CertRep: the certificates, or the error.
fn read_rep(c: scep::Client&, body: const u8[:], sent: const scep::Attrs&, k: const x509::PrivateKey&,
            signer: const u8[:]) -> u8[>..], u8[>..], i64 {
    var none:  u8[>..] = [];
    var none2: u8[>..] = [];
    let m, e = scep::read_message(body, c.ca_certs, c.legacy);
    if e != scep::OK { return none, none2, e; }
    let ce = scep::check_reply(c, m, sent);
    if ce != scep::OK { return none, none2, ce; }
    let inner, oe = scep::open_envelope(m, k, signer, c.legacy);
    if oe != scep::OK { return none, none2, oe; }
    let certs, crls, ie = scep::read_certs_only(inner);
    return certs, crls, ie;
}

fn enroll_through_server() {
    var s = scep::Server { .. };
    s.ca_key = key("vectors/ca.key");
    s.ca_cert = pem_cert("vectors/ca.pem");
    s.challenge.append("s3cret pw");
    var c = scep::Client { .. };
    c.ca_certs = copy(s.ca_cert);

    // GetCACaps and GetCACert as the server answers them.
    let a1 = scep::serve(s, "GET", "/scep?operation=GetCACaps", "", NOW);
    let k = scep::parse_caps(a1.body);
    check("GetCACaps", a1.status == 200 && k.aes && k.post && k.sha256 && k.renewal);
    let a2 = scep::serve(s, "GET", "/scep?operation=GetCACert&message=anything", "", NOW);
    let cc, ce = scep::ca_certs_of(a2.body, false);
    check("GetCACert: the CA's certificate", a2.status == 200 && a2.content_type == "application/x-x509-ca-cert" &&
          ce == scep::OK && cc[..] == s.ca_cert[..]);
    check("the CA is the recipient", scep::recipient_cert(cc)[..] == s.ca_cert[..]);

    // PKCSReq signed by a self-signed certificate.
    let ck = key("vectors/client.key");
    var san: u8[..4096] = [];
    x509::add_dns(san, "device.example.org");
    let req, e = scep::make_csr(subject("device.example.org"), san, ck, "s3cret pw");
    let signer, se = scep::self_signed(req, ck);
    check("the self-signed signer", se == scep::OK);
    let r, pe = x509::parse_csr(req);
    var spki: u8[>..] = [];
    spki.append(r.der[r.spki.start..r.spki.end]);
    let tid = scep::transaction_id(spki);
    let msg, sent = request(scep::MSG_PKCS_REQ, req, ck, signer, tid, s.ca_cert);
    let rep = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg, NOW);
    check("PKIOperation answered", rep.status == 200 && rep.content_type == "application/x-pki-message");
    let certs, crls, re = read_rep(c, rep.body, sent, ck, signer);
    check("PKCSReq: issued", re == scep::OK);
    let chain, found = scep::issued_first(certs, spki);
    check("the issued certificate has the request's key", found);
    let issued = scep::first_cert(chain);
    let ic, ie = x509::parse(issued);
    check("issued by the CA, the subject and SAN the CSR's", ie == x509::OK && x509::subject_text(ic) == "CN=device.example.org,O=Example" &&
          x509::dns_names(ic).len == 1);
    let cac, cae = x509::parse(s.ca_cert);
    check("its signature is the CA's", x509::check_signature(ic, cac) == x509::OK);

    // The same request by GET, the message in base64 (§4.3).
    let msg2, sent2 = request(scep::MSG_PKCS_REQ, req, ck, signer, tid, s.ca_cert);
    var b64: u8[>..] = [];
    base64::encode(b64, msg2);
    var target: u8[>..] = [];
    target.append("/scep?operation=PKIOperation&message=");
    http::query_escape(target, b64);
    let rep2 = scep::serve(s, "GET", target, "", NOW);
    let certs2, crls2, re2 = read_rep(c, rep2.body, sent2, ck, signer);
    check("PKIOperation by GET", re2 == scep::OK);

    // A wrong challenge: FAILURE, badRequest.
    let bad, be = scep::make_csr(subject("device.example.org"), "", ck, "guess");
    let msg3, sent3 = request(scep::MSG_PKCS_REQ, bad, ck, signer, tid, s.ca_cert);
    let rep3 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg3, NOW);
    let x3, y3, re3 = read_rep(c, rep3.body, sent3, ck, signer);
    check("a wrong challengePassword: FAILURE badRequest", re3 == scep::ERR_FAILURE && c.fail_info == scep::FAIL_BAD_REQUEST);

    // RenewalReq signed by the issued certificate, for a new key.
    let nk = key("vectors/client2.key");
    let req4, e4 = scep::make_csr(subject("device.example.org"), "", nk, "");
    let r4, pe4 = x509::parse_csr(req4);
    var spki4: u8[>..] = [];
    spki4.append(r4.der[r4.spki.start..r4.spki.end]);
    let msg4, sent4 = request(scep::MSG_RENEWAL_REQ, req4, ck, issued, scep::transaction_id(spki4), s.ca_cert);
    let rep4 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg4, NOW);
    let certs4, crls4, re4 = read_rep(c, rep4.body, sent4, ck, issued);
    let renewed, found4 = scep::issued_first(certs4, spki4);
    check("RenewalReq: issued for the new key", re4 == scep::OK && found4);
    let msg5, sent5 = request(scep::MSG_RENEWAL_REQ, req4, ck, signer, scep::transaction_id(spki4), s.ca_cert);
    let rep5 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg5, NOW);
    let x5, y5, re5 = read_rep(c, rep5.body, sent5, ck, signer);
    check("RenewalReq signed by a stranger: refused", re5 == scep::ERR_FAILURE && c.fail_info == scep::FAIL_BAD_REQUEST);

    // GetCert by issuer and serial; GetCRL.
    let ias, okias = scep::issuer_and_serial(issued);
    let msg6, sent6 = request(scep::MSG_GET_CERT, ias, ck, signer, scep::random_tid(), s.ca_cert);
    let rep6 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg6, NOW);
    let certs6, crls6, re6 = read_rep(c, rep6.body, sent6, ck, signer);
    check("GetCert", re6 == scep::OK && certs6[..] == issued[..]);
    let ias2, okias2 = scep::issuer_and_serial(s.ca_cert);
    var unknown = copy(ias);
    unknown[unknown.len - 1] = unknown[unknown.len - 1] ^ 1;
    let msg7, sent7 = request(scep::MSG_GET_CERT, unknown, ck, signer, scep::random_tid(), s.ca_cert);
    let rep7 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg7, NOW);
    let x7, y7, re7 = read_rep(c, rep7.body, sent7, ck, signer);
    check("GetCert of a serial not issued: badCertId", re7 == scep::ERR_FAILURE && c.fail_info == scep::FAIL_BAD_CERT_ID);
    let msg8, sent8 = request(scep::MSG_GET_CRL, ias, ck, signer, scep::random_tid(), s.ca_cert);
    let rep8 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg8, NOW);
    let certs8, crls8, re8 = read_rep(c, rep8.body, sent8, ck, signer);
    check("GetCRL", re8 == scep::OK && crls8.len > 0 && certs8.len == 0);
}

fn pending() {
    var s = scep::Server { .. };
    s.ca_key = key("vectors/ca.key");
    s.ca_cert = pem_cert("vectors/ca.pem");
    s.pending = 2;
    var c = scep::Client { .. };
    c.ca_certs = copy(s.ca_cert);
    let ck = key("vectors/client.key");
    let req, e = scep::make_csr(subject("held.example.org"), "", ck, "");
    let signer, se = scep::self_signed(req, ck);
    let r, pe = x509::parse_csr(req);
    var spki: u8[>..] = [];
    spki.append(r.der[r.spki.start..r.spki.end]);
    let tid = scep::transaction_id(spki);
    let msg, sent = request(scep::MSG_PKCS_REQ, req, ck, signer, tid, s.ca_cert);
    let rep = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg, NOW);
    let x, y, re = read_rep(c, rep.body, sent, ck, signer);
    check("held: PENDING", re == scep::ERR_PENDING);
    let cac, cae = x509::parse(s.ca_cert);
    let poll = scep::issuer_and_subject(cac.der[cac.subject.start..cac.subject.end], r.der[r.subject.start..r.subject.end]);
    let m1, s1 = request(scep::MSG_CERT_POLL, poll, ck, signer, tid, s.ca_cert);
    let rep1 = scep::serve(s, "POST", "/scep?operation=PKIOperation", m1, NOW);
    let x1, y1, re1 = read_rep(c, rep1.body, s1, ck, signer);
    check("first CertPoll: still PENDING", re1 == scep::ERR_PENDING);
    let m2, s2 = request(scep::MSG_CERT_POLL, poll, ck, signer, tid, s.ca_cert);
    let rep2 = scep::serve(s, "POST", "/scep?operation=PKIOperation", m2, NOW);
    let certs, crls, re2 = read_rep(c, rep2.body, s2, ck, signer);
    let issued, found = scep::issued_first(certs, spki);
    check("second CertPoll: issued", re2 == scep::OK && found);
    let m3, s3 = request(scep::MSG_CERT_POLL, poll, ck, signer, tid, s.ca_cert);
    let rep3 = scep::serve(s, "POST", "/scep?operation=PKIOperation", m3, NOW);
    let x3, y3, re3 = read_rep(c, rep3.body, s3, ck, signer);
    check("a CertPoll for nothing held: badCertId", re3 == scep::ERR_FAILURE && c.fail_info == scep::FAIL_BAD_CERT_ID);
}

// A CertRep as a server would make it, from a request's attributes.
fn reply(sent: const scep::Attrs&, status: i64, payload: const u8[:], to: const u8[:], k: const x509::PrivateKey&,
         signer: const u8[:], h: i64, cipher: i64) -> u8[>..] {
    var a = scep::Attrs { .. };
    a.message_type = scep::MSG_CERT_REP;
    a.status = status;
    a.transaction_id.append(sent.transaction_id);
    let n = scep::new_nonce();
    a.sender_nonce.append(n[..]);
    a.recipient_nonce.append(sent.sender_nonce);
    let msg, e = scep::build_message(a, payload, to, cipher, k, signer, h);
    assert(e == scep::OK);
    return msg;
}

fn hostile() {
    let ca_key = key("vectors/ca.key");
    let ca = pem_cert("vectors/ca.pem");
    let rogue_key = key("vectors/rogue.key");
    let rogue = pem_cert("vectors/rogue.pem");
    let ck = key("vectors/client.key");
    let req, e = scep::make_csr(subject("device.example.org"), "", ck, "");
    let signer, se = scep::self_signed(req, ck);
    let r, pe = x509::parse_csr(req);
    var spki: u8[>..] = [];
    spki.append(r.der[r.spki.start..r.spki.end]);
    var c = scep::Client { .. };
    c.ca_certs = copy(ca);
    var sent = scep::Attrs { .. };
    sent.message_type = scep::MSG_PKCS_REQ;
    sent.transaction_id.append(scep::transaction_id(spki));
    let n = scep::new_nonce();
    sent.sender_nonce.append(n[..]);

    // A certificate for this key, issued by the CA, as a good reply has it.
    var t, okt = x509::template("CN=device.example.org", NOW - 60, NOW + 86400);
    let good_cert, gce = x509::create_certificate(t, spki, ca, ca_key);
    let payload = x509::cms_certs_only(good_cert, "");
    let good = reply(sent, scep::STATUS_SUCCESS, payload, signer, ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c0, l0, e0 = read_rep(c, good, sent, ck, signer);
    check("the good reply", e0 == scep::OK && c0[..] == good_cert[..]);

    // Signed by another key under the CA's own name, carrying its certificate.
    let forged = reply(sent, scep::STATUS_SUCCESS, payload, signer, rogue_key, rogue, 256, x509::CMS_AES128_CBC);
    let c1, l1, e1 = read_rep(c, forged, sent, ck, signer);
    check("signed by a stranger with the CA's name: refused", e1 == scep::ERR_SIGNATURE);
    // A signature changed: the last byte of the SignerInfo's signature.
    var tampered = copy(good);
    tampered[tampered.len - 1] = tampered[tampered.len - 1] ^ 0x01;
    let c2, l2, e2 = read_rep(c, tampered, sent, ck, signer);
    check("a signature changed: refused", e2 == scep::ERR_SIGNATURE);
    // Unsigned: a SignedData with no signers.
    let unsigned = x509::cms_unsigned(x509::OID_CMS_DATA, payload);
    let c3, l3, e3 = read_rep(c, unsigned, sent, ck, signer);
    check("unsigned: refused", e3 == scep::ERR_SIGNATURE);
    // Another transaction, or a nonce not ours.
    var other = copy(sent);
    other.transaction_id.clear();
    other.transaction_id.append("SOMEONE-ELSES");
    let wrong_tid = reply(other, scep::STATUS_SUCCESS, payload, signer, ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c4, l4, e4 = read_rep(c, wrong_tid, sent, ck, signer);
    check("another transactionID: refused", e4 == scep::ERR_MISMATCH);
    var other2 = copy(sent);
    other2.sender_nonce[0] = other2.sender_nonce[0] ^ 0xff;
    let wrong_nonce = reply(other2, scep::STATUS_SUCCESS, payload, signer, ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c5, l5, e5 = read_rep(c, wrong_nonce, sent, ck, signer);
    check("a recipientNonce not our senderNonce: refused", e5 == scep::ERR_MISMATCH);
    // Not a CertRep.
    var a6 = copy(sent);
    let n6 = scep::new_nonce();
    a6.sender_nonce.clear();
    a6.sender_nonce.append(n6[..]);
    a6.recipient_nonce.append(sent.sender_nonce);
    let m6, be6 = scep::build_message(a6, payload, signer, x509::CMS_AES128_CBC, ca_key, ca, 256);
    let c6, l6, e6 = read_rep(c, m6, sent, ck, signer);
    check("a PKCSReq for a reply: refused", e6 == scep::ERR_MISMATCH);
    // A transactionID twice.
    var dup = scep::Attrs { .. };
    dup.message_type = scep::MSG_CERT_REP;
    dup.status = scep::STATUS_SUCCESS;
    dup.transaction_id.append(sent.transaction_id);
    dup.recipient_nonce.append(sent.sender_nonce);
    dup.sender_nonce.append(n[..]);
    let ad, okad = scep::attrs_der(dup);
    var so = x509::CmsSignOptions { .. };
    so.extra_attrs.append(ad);
    var t2: u8[>..] = [];
    scep::put_printable_attr(t2, scep::OID_TRANSACTION_ID, "OTHER");
    so.extra_attrs.append(t2);
    let cac, cae = x509::parse(ca);
    var o = x509::CmsEncryptOptions { .. };
    o.cipher = x509::CMS_AES128_CBC;
    let env, ee = x509::cms_encrypt(x509::OID_CMS_DATA, payload, signer, o);
    let twice, okt2 = x509::cms_sign_with(x509::OID_CMS_DATA, env, ca_key, cac, "", x509::SIG_RSA_PKCS1, 256, so);
    let c7, l7, e7 = read_rep(c, twice, sent, ck, signer);
    check("a transactionID twice: refused", okt2 && e7 == scep::ERR_MALFORMED);
    // SHA-1 and DES, as Go's pkcs7 sends them: only with legacy.
    let sha1 = reply(sent, scep::STATUS_SUCCESS, payload, signer, ca_key, ca, 160, x509::CMS_AES128_CBC);
    let c8, l8, e8 = read_rep(c, sha1, sent, ck, signer);
    check("signed with SHA-1: refused without legacy", e8 == scep::ERR_ALGORITHM);
    let des3 = reply(sent, scep::STATUS_SUCCESS, payload, signer, ca_key, ca, 256, x509::CMS_DES3_CBC);
    let c9, l9, e9 = read_rep(c, des3, sent, ck, signer);
    check("DES-EDE3: refused without legacy", e9 == scep::ERR_ALGORITHM);
    c.legacy = true;
    let c10, l10, e10 = read_rep(c, sha1, sent, ck, signer);
    let c11, l11, e11 = read_rep(c, des3, sent, ck, signer);
    check("SHA-1 and DES-EDE3 with legacy", e10 == scep::OK && e11 == scep::OK && c11[..] == good_cert[..]);
    c.legacy = false;
    // Encrypted to someone else: the envelope does not open.
    let to_ca = reply(sent, scep::STATUS_SUCCESS, payload, ca, ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c12, l12, e12 = read_rep(c, to_ca, sent, ck, signer);
    check("an envelope not for us: refused", e12 == scep::ERR_DECRYPT);
    // SUCCESS without an envelope.
    let empty = reply(sent, scep::STATUS_SUCCESS, "", "", ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c13, l13, e13 = read_rep(c, empty, sent, ck, signer);
    check("SUCCESS without an envelope: refused", e13 == scep::ERR_MALFORMED);
    // A certificate for another key.
    let nk = key("vectors/client2.key");
    let other_spki = x509::marshal_public_key(nk);
    let wrong_key_cert, wkce = x509::create_certificate(t, other_spki, ca, ca_key);
    let swapped = reply(sent, scep::STATUS_SUCCESS, x509::cms_certs_only(wrong_key_cert, ""), signer, ca_key, ca, 256,
                        x509::CMS_AES128_CBC);
    let c14, l14, e14 = read_rep(c, swapped, sent, ck, signer);
    let i14, f14 = scep::issued_first(c14, spki);
    check("a certificate for another key: not taken", e14 == scep::OK && !f14);
    // Garbage, truncated, and an empty body.
    let c15, l15, e15 = read_rep(c, "not DER at all", sent, ck, signer);
    let c16, l16, e16 = read_rep(c, good[..good.len / 2], sent, ck, signer);
    let c17, l17, e17 = read_rep(c, "", sent, ck, signer);
    check("garbage, truncated, empty: malformed", e15 == scep::ERR_MALFORMED && e16 == scep::ERR_MALFORMED && e17 == scep::ERR_MALFORMED);
    // PENDING without an envelope is what servers send, with eContent
    // absent or empty.
    let pend = reply(sent, scep::STATUS_PENDING, "", "", ca_key, ca, 256, x509::CMS_AES128_CBC);
    let c18, l18, e18 = read_rep(c, pend, sent, ck, signer);
    check("PENDING", e18 == scep::ERR_PENDING);
    // GetCACert answers that are not certificates.
    let cc1, ce1 = scep::ca_certs_of("junk", false);
    let cc2, ce2 = scep::ca_certs_of(x509::cms_certs_only("", ""), true);
    check("GetCACert: junk or no certificates refused", ce1 == scep::ERR_MALFORMED && ce2 == scep::ERR_MALFORMED);
    // A certs-only with signers is not certs-only.
    let cc3, cl3, ce3 = scep::read_certs_only(good);
    check("a signed message is not certs-only", ce3 == scep::ERR_MALFORMED);
    var url_c = scep::Client { .. };
    check("a URL with a query is refused", scep::set_url(url_c, "http://ca.example.org/scep?x=1") == scep::ERR_ARG);
}

// A message whose attributes are made by hand: a transactionID or a
// failInfoText the reader must refuse, not abort on or cut short.
fn odd_attrs(tid: const u8[:], fail_text: const u8[:]) -> u8[>..] {
    let ck = key("vectors/client.key");
    let req, e = scep::make_csr(subject("device.example.org"), "", ck, "");
    let signer, se = scep::self_signed(req, ck);
    let sc, pe = x509::parse(signer);
    var ad: u8[>..] = [];
    var v: u8[>..] = [];
    asn1::put(v, asn1::PRINTABLE_STRING, tid);
    scep::put_attr(ad, scep::OID_TRANSACTION_ID, v);
    scep::put_number_attr(ad, scep::OID_MESSAGE_TYPE, scep::MSG_PKCS_REQ);
    let n = scep::new_nonce();
    scep::put_octets_attr(ad, scep::OID_SENDER_NONCE, n[..]);
    if fail_text.len > 0 {
        var ft: u8[>..] = [];
        asn1::put_utf8_string(ft, fail_text);
        scep::put_attr(ad, scep::OID_FAIL_INFO_TEXT, ft);
    }
    var so = x509::CmsSignOptions { .. };
    so.extra_attrs.append(ad);
    let msg, okm = x509::cms_sign_with(x509::OID_CMS_DATA, "", ck, sc, "", x509::SIG_RSA_PKCS1, 256, so);
    assert(okm);
    return msg;
}

fn hostile_attrs() {
    let m0, e0 = scep::read_message(odd_attrs("abc", ""), "", false);
    check("hand-made attributes read", e0 == scep::OK && m0.attrs.transaction_id == "abc");
    let bad = odd_attrs("a@b", "");
    let m1, e1 = scep::read_message(bad, "", false);
    check("transactionID not printable: refused", e1 == scep::ERR_MALFORMED);
    var s = scep::Server { .. };
    s.ca_key = key("vectors/ca.key");
    s.ca_cert = pem_cert("vectors/ca.pem");
    let a = scep::serve(s, "POST", "/scep?operation=PKIOperation", bad, NOW);
    check("transactionID not printable: the CA answers", a.status != 200);
    var long: u8[>..] = [];
    for i in 2049 { long.push('x'); }
    let m2, e2 = scep::read_message(odd_attrs("abc", long[..2048]), "", false);
    check("failInfoText of 2048", e2 == scep::OK && m2.attrs.fail_text.len == 2048);
    let m3, e3 = scep::read_message(odd_attrs("abc", long), "", false);
    check("failInfoText past 2048: refused", e3 == scep::ERR_MALFORMED);
}

fn main() {
    caps();
    csr();
    enroll_through_server();
    pending();
    hostile();
    hostile_attrs();
    print("scep: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
