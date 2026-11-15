// offline: SCEP's messages without a network. A test CA (scep::Server)
// with a challenge password; a device makes an RSA key, a CSR carrying the
// password, and the self-signed certificate that signs its PKCSReq; the
// CA answers with a CertRep, which the device reads as scep::enroll does:
// signed by the CA it trusts, its transactionID and recipientNonce its
// own, the envelope opened with its key, the certificate's key its key.
// Then a request with the wrong password, refused with badRequest.
//
//   goose examples/scep/offline.goose

import std;
import gslib from "../..";
import gslib.scep;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;

let NOW: i64 = 1800000000;

// What scep::transact does with a CertRep: the certificates, or the error.
fn read_reply(c: scep::Client&, body: const u8[:], sent: const scep::Attrs&, k: const x509::PrivateKey&,
              signer: const u8[:]) -> u8[>..], i64 {
    var none: u8[>..] = [];
    let m, e = scep::read_message(body, c.ca_certs, c.legacy);
    if e != scep::OK { return none, e; }
    let ce = scep::check_reply(c, m, sent);
    if ce != scep::OK { return none, ce; }
    let inner, oe = scep::open_envelope(m, k, signer, c.legacy);
    if oe != scep::OK { return none, oe; }
    let certs, crls, ie = scep::read_certs_only(inner);
    return certs, ie;
}

fn request(csr: const u8[:], k: const x509::PrivateKey&, signer: const u8[:], ca: const u8[:]) -> u8[>..], scep::Attrs {
    let r, e = x509::parse_csr(csr);
    var a = scep::Attrs { .. };
    a.message_type = scep::MSG_PKCS_REQ;
    a.transaction_id.append(scep::transaction_id(r.der[r.spki.start..r.spki.end]));
    let n = scep::new_nonce();
    a.sender_nonce.append(n[..]);
    let msg, be = scep::build_message(a, csr, ca, x509::CMS_AES128_CBC, k, signer, 256);
    assert(be == scep::OK);
    return msg, a;
}

fn main() {
    // The CA: an RSA key and a self-signed certificate.
    var s = scep::Server { .. };
    s.ca_key = x509::generate_key(x509::KEY_RSA, 2048);
    var t, ok = x509::template("CN=Example SCEP CA,O=Example", NOW - 3600, NOW + 365 * 86400);
    t.basic_constraints = true;
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN | x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_ENCIPHERMENT;
    let ca, ce = x509::create_certificate(t, x509::marshal_public_key(s.ca_key), "", s.ca_key);
    assert(ce == x509::OK);
    s.ca_cert = copy(ca);
    s.challenge.append("one-time password");

    // The device: what GetCACert gave it, its key, its CSR, its signer.
    var c = scep::Client { .. };
    let caa = scep::serve(s, "GET", "/scep?operation=GetCACert", "", NOW);
    let cas, cae = scep::ca_certs_of(caa.body, false);
    assert(cae == scep::OK);
    c.ca_certs = copy(cas);
    let k = x509::generate_key(x509::KEY_RSA, 2048);
    let subject, sok = x509::name_der("CN=device-0042,O=Example");
    var san: u8[..4096] = [];
    x509::add_dns(san, "device-0042.example.org");
    let csr, e = scep::make_csr(subject, san, k, "one-time password");
    assert(e == scep::OK);
    let signer, se = scep::self_signed(csr, k);
    assert(se == scep::OK);

    let msg, sent = request(csr, k, signer, c.ca_certs);
    print("PKCSReq: ", msg.len, " bytes, transaction ", sent.transaction_id[..16], "...");
    let rep = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg, NOW);
    let certs, re = read_reply(c, rep.body, sent, k, signer);
    assert(re == scep::OK);
    let r, pe = x509::parse_csr(csr);
    let chain, found = scep::issued_first(certs, r.der[r.spki.start..r.spki.end]);
    assert(found);
    let cert, pce = x509::parse(scep::first_cert(chain));
    print("CertRep SUCCESS: ", x509::subject_text(cert), ", issued by ", x509::issuer_text(cert));

    let bad, be = scep::make_csr(subject, "", k, "a guess");
    let msg2, sent2 = request(bad, k, signer, c.ca_certs);
    let rep2 = scep::serve(s, "POST", "/scep?operation=PKIOperation", msg2, NOW);
    let none, re2 = read_reply(c, rep2.body, sent2, k, signer);
    assert(re2 == scep::ERR_FAILURE);
    print("the wrong password: FAILURE, ", scep::fail_name(c.fail_info));
}
