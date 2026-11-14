// smime_pq: a message signed with ML-DSA and encrypted to an ML-KEM
// certificate (S/MIME 4.0 with RFC 9882 and RFC 9936, through mail.smime),
// then opened by the recipient: decrypted, the signature verified, the
// signer checked against the CA and the From address. The CA (ML-DSA-65),
// Zoe's signing certificate (ML-DSA-65) and Bob's encryption certificate
// (ML-KEM-768) are made here, for this run only. No network, no files.
//
//   goose examples/mail/smime_pq.goose

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.create;
import gslib.crypto.x509.pool;
import gslib.mail;
import gslib.mail.message;
import gslib.mail.smime;

let DAY: i64 = 86400;

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("smime_pq: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

// An end-entity certificate for key k and address addr, from the CA.
fn issue(subject: const u8[:], addr: const u8[:], k: const x509::PrivateKey&, usage: u32, ca: const u8[:],
         ca_key: const x509::PrivateKey&, now: i64) -> x509::Cert {
    var t, ok = x509::template(subject, now - DAY, now + 365 * DAY);
    t.key_usage = usage;
    t.ext_key_usage = x509::EKU_EMAIL_PROTECTION;
    x509::add_email(t.san, addr);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), ca, ca_key);
    let c, ep = x509::parse(der);
    if !ok || e != x509::OK || ep != x509::OK { print("smime_pq: ", subject, ": ", x509::error_text(e)); exit(1); }
    return c;
}

fn main() {
    let now = time() as i64;
    let ca_key = x509::generate_key(x509::KEY_MLDSA65);
    var ct, okc = x509::template("CN=Example PQ Mail CA,O=Example", now - DAY, now + 5 * 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN;
    let ca, eca = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    if !okc || eca != x509::OK { print("smime_pq: the CA: ", x509::error_text(eca)); exit(1); }
    let zoe_key = x509::generate_key(x509::KEY_MLDSA65);
    let zoe = issue("CN=Zoe (signing)", "zoe@example.com", zoe_key, x509::KU_DIGITAL_SIGNATURE, ca, ca_key, now);
    let bob_key = x509::generate_key(x509::KEY_MLKEM768);
    let bob = issue("CN=Bob (encryption)", "bob@example.org", bob_key, x509::KU_KEY_ENCIPHERMENT, ca, ca_key, now);

    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Zoe <zoe@example.com>"));
    must("to", mail::add_to(m, "Bob <bob@example.org>"));
    must("subject", mail::set_subject(m, "Quantum-safe minutes"));
    mail::set_date(m, now);
    must("text", mail::set_body(m, mail::TEXT_PLAIN, "The minutes are attached, signed and sealed.\n"));
    must("attach", mail::attach(m, "minutes.txt", "1. Opening.\n2. Keys: ML-DSA and ML-KEM.\n3. Close.\n"));

    // Signed by Zoe (multipart/signed, micalg sha-512, the CA sent along),
    // then encrypted to Bob (AES-256-GCM: authEnveloped-data).
    let o = smime::Options { cipher: x509::CMS_AES256_GCM, .. };
    var out: u8[>..] = [];
    must("sign-encrypt", smime::sign_encrypt(m, zoe_key, zoe, ca, bob.der, o, out));
    let ct_at = find(out, "Content-Type: application/pkcs7-mime");
    print(out[..ct_at + find(out[ct_at..], "\r\n\r\n") + 2]);
    print("[", out.len, " bytes in all]");

    // Bob opens it.
    var r = smime::Opened { .. };
    must("open", smime::open(out, bob_key, bob, r));
    print("encrypted: ", r.encrypted, ", signed: ", r.signed, ", by ", x509::subject_text(r.signer));
    var roots = x509::new_pool();
    let ca_cert, ecc = x509::parse(ca);
    let added = x509::pool_add_cert(roots, ca_cert);
    must("signer", smime::check_signer(r, roots, now, smime::from_address(out)));
    print("the signer is ", smime::from_address(out), ", as From says, certified by the CA");
    if find(r.entity, "signed and sealed") < 0 || find(r.entity, "minutes.txt") < 0 { print("smime_pq: the message is not inside"); exit(1); }

    // Not for Zoe: her ML-DSA key and certificate are no recipient's.
    var r2 = smime::Opened { .. };
    let rc = smime::open(out, zoe_key, zoe, r2);
    print("opened with Zoe's key: ", mail::error_text(rc));
    if rc != mail::ERR_DECRYPT { exit(1); }
}
