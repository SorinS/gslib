// S/MIME (mail.smime) with the test PKI of smime/ (a root, an
// intermediate, and Alice RSA-2048, Bob P-256, Carol P-384, Dave
// Ed25519, Eve P-256 for server authentication only; made by
// scripts/interop_smime.py --write-vectors, test keys only):
//
//   - a mail::Msg signed by each key (PKCS #1 v1.5 and PSS for RSA) as
//     multipart/signed: the header outside, the entity signed exactly as
//     sent, micalg, and back through verify with the signer, the entity
//     and the signing time; a changed byte refused; check_signer's path,
//     usage and From checks;
//   - opaque signing, encryption (CBC and GCM, OAEP and PKCS #1 v1.5,
//     ECDH, several recipients), sign-then-encrypt, read back; not a
//     recipient, a wrong key, a changed ciphertext refused; 8bit bodies
//     refused for multipart/signed; messages that are not S/MIME;
//   - messages openssl made (smime/ossl-*.eml): signed every way, BER,
//     encrypted every way, signed then encrypted;
//   - post-quantum, with the PKI of smime/pq/ (an ML-DSA-65 root; Frank,
//     Grace and Heidi each with an ML-DSA signing certificate, -65, -44
//     and -87, and an ML-KEM encryption one, -768, -512 and -1024; made by
//     scripts/interop_smime.py --write-pq-vectors): signed by each ML-DSA
//     key (micalg sha-512) and checked to the root, opaque; encrypted to
//     every ML-KEM set with a classic recipient beside them; signed then
//     encrypted; and the messages openssl made (smime/pq/ossl-*.eml).
import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.pool;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.cms_env;
import gslib.mail;
import gslib.mail.message;
import gslib.mail.smime;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { print("FAIL ", what); failures++; }
}

fn check_rc(what: const u8[:], got: i64, want: i64) {
    checks++;
    if got != want { print("FAIL ", what, ": ", mail::error_text(got), ", want ", mail::error_text(want)); failures++; }
}

fn contains(s: const u8[:], sub: const u8[:]) -> bool { find(s, sub) >= 0 }

// Whether sub is in s before `at`.
fn before(s: const u8[:], sub: const u8[:], at: i64) -> bool {
    let i = find(s, sub);
    return i >= 0 && i < at;
}

let NOW:  i64 = 1893456000;      // 2030-01-01, inside the certificates' validity
let TIME: i64 = 1790000000;      // the signing time written

let ROOT_PEM = embed_file("smime/root.pem");
let INTER_PEM = embed_file("smime/inter.pem");
let ALICE_PEM = embed_file("smime/alice.pem");
let ALICE_KEY = embed_file("smime/alice.key");
let BOB_PEM = embed_file("smime/bob.pem");
let BOB_KEY = embed_file("smime/bob.key");
let CAROL_PEM = embed_file("smime/carol.pem");
let CAROL_KEY = embed_file("smime/carol.key");
let DAVE_PEM = embed_file("smime/dave.pem");
let DAVE_KEY = embed_file("smime/dave.key");
let ENTITY = embed_file("smime/entity.txt");
let PQ_ROOT_PEM = embed_file("smime/pq/root.pem");
let FRANK_PEM = embed_file("smime/pq/frank.pem");
let FRANK_KEY = embed_file("smime/pq/frank.key");
let FRANK_KEM_PEM = embed_file("smime/pq/frank-kem.pem");
let FRANK_KEM_KEY = embed_file("smime/pq/frank-kem.key");
let GRACE_PEM = embed_file("smime/pq/grace.pem");
let GRACE_KEY = embed_file("smime/pq/grace.key");
let GRACE_KEM_PEM = embed_file("smime/pq/grace-kem.pem");
let GRACE_KEM_KEY = embed_file("smime/pq/grace-kem.key");
let HEIDI_PEM = embed_file("smime/pq/heidi.pem");
let HEIDI_KEY = embed_file("smime/pq/heidi.key");
let HEIDI_KEM_PEM = embed_file("smime/pq/heidi-kem.pem");
let HEIDI_KEM_KEY = embed_file("smime/pq/heidi-kem.key");

fn cert(pem: const u8[:]) -> x509::Cert {
    let c, e = x509::parse_pem(pem);
    assert(e == x509::OK);
    return c;
}

fn key(pem: const u8[:]) -> x509::PrivateKey {
    let k, ok = x509::parse_private_key_pem(pem);
    assert(ok);
    return k;
}

fn der(pem: const u8[:]) -> u8[>..] {
    let c = cert(pem);
    var out: u8[>..] = [];
    out.append(c.der);
    return out;
}

fn roots() -> x509::CertPool {
    var p = x509::new_pool();
    assert(x509::pool_append_pem(p, ROOT_PEM) == 1);
    return p;
}

// The message every test sends: text and an attachment, so the entity
// signed is a multipart/mixed.
fn build(m: mail::Msg&) {
    assert(mail::set_from(m, "Alice <alice@example.com>") == mail::OK);
    assert(mail::add_to(m, "Bob <bob@example.org>") == mail::OK);
    assert(mail::set_subject(m, "Quarterly figures") == mail::OK);
    mail::set_date(m, 1790000000);
    assert(mail::set_message_id(m, "smime-test@example.com") == mail::OK);
    assert(mail::set_boundary(m, "test") == mail::OK);
    assert(mail::set_body(m, mail::TEXT_PLAIN, "The figures are attached.\nFrom here on, 3% more.\n") == mail::OK);
    assert(mail::attach(m, "figures.csv", "q,amount\n1,100\n2,103\n") == mail::OK);
}

// What mail::write puts in the entity: its Content-* fields and body.
fn inner_of(m: mail::Msg&) -> u8[>..] {
    var raw: u8[>..] = [];
    assert(mail::write(m, raw) == mail::OK);
    var outer: u8[>..] = [];
    var inner: u8[>..] = [];
    smime::split_message(raw, outer, inner);
    return inner;
}

// A byte of the body changed, at the first `at`.
fn changed(s: const u8[:], at: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(s);
    let i = find(out, at);
    assert(i >= 0);
    out[i] ^= 1;
    return out;
}

fn signing() {
    let pool = roots();
    let others = der(INTER_PEM);
    for i in 5 {
        let pem = if i < 2 { ALICE_PEM } else if i == 2 { BOB_PEM } else if i == 3 { CAROL_PEM } else { DAVE_PEM };
        let kpem = if i < 2 { ALICE_KEY } else if i == 2 { BOB_KEY } else if i == 3 { CAROL_KEY } else { DAVE_KEY };
        let what = if i == 0 { "sign rsa" } else if i == 1 { "sign rsa-pss" } else if i == 2 { "sign p256" }
                   else if i == 3 { "sign p384" } else { "sign ed25519" };
        let c = cert(pem);
        let k = key(kpem);
        var m = mail::Msg { .. };
        build(m);
        let inner = inner_of(m);
        var o = smime::Options { pss: i == 1, signing_time: TIME, by_key_id: i == 2, .. };
        if i == 3 { o.hash = 384; }
        o.boundary.append("signed-boundary");
        var out: u8[>..] = [];
        check_rc(what, smime::sign(m, k, c, others, o, out), mail::OK);
        // The header outside, the entity inside exactly as written, micalg.
        let ct = find(out, "Content-Type: multipart/signed;");
        check(what, before(out, "From: \"Alice\" <alice@example.com>\r\n", ct) && before(out, "Subject: Quarterly figures\r\n", ct) &&
                    before(out, "Message-ID: <smime-test@example.com>\r\n", ct) && before(out, "MIME-Version: 1.0\r\n", ct));
        check(what, contains(out, if i == 3 { "micalg=sha-384" } else if i == 4 { "micalg=sha-512" } else { "micalg=sha-256" }));
        var framed: u8[>..] = [];
        framed.append("--signed-boundary\r\n");
        framed.append(inner);
        framed.append("\r\n--signed-boundary\r\n");
        check(what, contains(out, framed));
        check(what, smime::is_7bit(out));
        // Back.
        var r = smime::Opened { .. };
        check_rc(what, smime::verify(out, r), mail::OK);
        check(what, r.signed && !r.encrypted && r.signer.der == c.der && r.entity == inner);
        check(what, r.has_signing_time && r.signing_time == TIME);
        check(what, starts(r.message, "Date: ") && ends(r.message, inner));
        let from = smime::from_address(out);
        check(what, from == "alice@example.com");
        // Alice's own messages pass check_signer; the others' From is Alice.
        check_rc(what, smime::check_signer(r, pool, NOW, from), if i < 2 { mail::OK } else { mail::ERR_CERT });
        check(what, smime::check_path(r, pool, NOW) == x509::OK);
        // A changed byte, in the text and in the attachment.
        var r2 = smime::Opened { .. };
        check_rc(what, smime::verify(changed(out, "figures are"), r2), mail::ERR_SIGNATURE);
        check_rc(what, smime::verify(changed(out, "MSwxMDAK"), r2), mail::ERR_SIGNATURE);
        // The same with LF line ends: read as CRLF.
        var lf: u8[>..] = [];
        for j in out.len { if out[j] != '\r' { lf.push(out[j]); } }
        check_rc(what, smime::verify(lf, r2), mail::OK);
        check(what, r2.entity == inner);
    }
}

fn starts(s: const u8[:], p: const u8[:]) -> bool { s.len >= p.len && s[..p.len] == p }
fn ends(s: const u8[:], p: const u8[:]) -> bool { s.len >= p.len && s[s.len - p.len..] == p }

fn signer_checks() {
    let pool = roots();
    let c = cert(ALICE_PEM);
    let k = key(ALICE_KEY);
    var m = mail::Msg { .. };
    build(m);
    var o = smime::Options { signing_time: TIME, .. };
    var out: u8[>..] = [];
    check_rc("check_signer", smime::sign(m, k, c, der(INTER_PEM), o, out), mail::OK);
    var r = smime::Opened { .. };
    check_rc("check_signer", smime::verify(out, r), mail::OK);
    check_rc("check_signer", smime::check_signer(r, pool, NOW, "Alice <alice@example.com>"), mail::OK);
    check_rc("check_signer, ALICE@EXAMPLE.COM", smime::check_signer(r, pool, NOW, "alice@EXAMPLE.COM"), mail::OK);
    check_rc("check_signer, Alice@", smime::check_signer(r, pool, NOW, "Alice@example.com"), mail::ERR_CERT);
    check_rc("check_signer, bob", smime::check_signer(r, pool, NOW, "bob@example.org"), mail::ERR_CERT);
    check_rc("check_signer, no From", smime::check_signer(r, pool, NOW, ""), mail::OK);
    check("check_path, before", smime::check_path(r, pool, 1700000000) == x509::ERR_NOT_YET_VALID);
    var empty = x509::new_pool();
    check("check_path, no roots", smime::check_path(r, empty, NOW) == x509::ERR_UNKNOWN_ISSUER);
    // Without the intermediate sent, no path.
    var out2: u8[>..] = [];
    check_rc("no chain", smime::sign(m, k, c, "", o, out2), mail::OK);
    var r2 = smime::Opened { .. };
    check_rc("no chain", smime::verify(out2, r2), mail::OK);
    check_rc("no chain", smime::check_signer(r2, pool, NOW, "alice@example.com"), mail::ERR_CERT);
    // The wrong key for the certificate; a key that cannot sign.
    var out3: u8[>..] = [];
    let bk = key(BOB_KEY);
    let bc = cert(BOB_PEM);
    check_rc("wrong key", smime::sign(m, bk, c, "", o, out3), mail::ERR_KEY);
    check("wrong key: out as it was", out3.len == 0);
    var bad = smime::Options { hash: 224, .. };
    check_rc("hash 224", smime::sign(m, k, c, "", bad, out3), mail::ERR_ARG);
    // A boundary that is in the entity; one that is not a boundary.
    var ob = smime::Options { .. };
    ob.boundary.append("test-mixed");
    check_rc("boundary in the entity", smime::sign(m, k, c, "", ob, out3), mail::ERR_ARG);
    // 8bit: refused for multipart/signed, fine inside pkcs7-mime.
    assert(mail::set_encoding(m, mail::ENC_8BIT) == mail::OK);
    check_rc("8bit", smime::sign(m, k, c, "", o, out3), mail::ERR_ARG);
    check_rc("8bit opaque", smime::sign_opaque(m, bk, bc, "", o, out3), mail::OK);
}

fn opaque() {
    let c = cert(BOB_PEM);
    let k = key(BOB_KEY);
    var m = mail::Msg { .. };
    build(m);
    let inner = inner_of(m);
    var o = smime::Options { signing_time: -1, .. };
    var out: u8[>..] = [];
    check_rc("opaque", smime::sign_opaque(m, k, c, der(INTER_PEM), o, out), mail::OK);
    check("opaque", contains(out, "Content-Type: application/pkcs7-mime; smime-type=signed-data; name=smime.p7m\r\n"));
    var r = smime::Opened { .. };
    check_rc("opaque", smime::verify(out, r), mail::OK);
    check("opaque", r.signed && r.signer.der == c.der && r.entity == inner && !r.has_signing_time);
    let pool = roots();
    check("opaque", smime::check_path(r, pool, NOW) == x509::OK);
}

fn encryption() {
    let alice = cert(ALICE_PEM);
    let bob = cert(BOB_PEM);
    let carol = cert(CAROL_PEM);
    let dave = cert(DAVE_PEM);
    let ak = key(ALICE_KEY);
    let bk = key(BOB_KEY);
    let ck = key(CAROL_KEY);
    let dk = key(DAVE_KEY);
    var rs: u8[>..] = [];
    rs.append(bob.der);
    rs.append(carol.der);
    rs.append(alice.der);
    var m = mail::Msg { .. };
    build(m);
    let inner = inner_of(m);
    var n = 0;
    for cipher in [x509::CMS_AES256_CBC, x509::CMS_AES128_GCM, x509::CMS_AES128_CBC, x509::CMS_AES256_GCM] {
        let gcm = cipher == x509::CMS_AES128_GCM || cipher == x509::CMS_AES256_GCM;
        let o = smime::Options { cipher: cipher, rsa_pkcs1: n == 2, by_key_id: n == 3, .. };
        var out: u8[>..] = [];
        check_rc("encrypt", smime::encrypt(m, rs, o, out), mail::OK);
        check("encrypt", contains(out, if gcm { "smime-type=authEnveloped-data" } else { "smime-type=enveloped-data" }));
        check("encrypt: header outside", starts(out, "Date: ") && contains(out, "To: \"Bob\" <bob@example.org>\r\n"));
        check("encrypt: nothing inside shows", !contains(out, "figures are"));
        var r = smime::Opened { .. };
        // Bob and Carol each time; Alice (RSA, the slow one) once by OAEP and once by PKCS #1 v1.5.
        check_rc("decrypt bob", smime::open(out, bk, bob, r), mail::OK);
        check("decrypt bob", r.encrypted && !r.signed && r.entity == inner);
        check("decrypt bob: the message", starts(r.message, "Date: ") && ends(r.message, inner));
        check_rc("decrypt carol", smime::open(out, ck, carol, r), mail::OK);
        check("decrypt carol", r.entity == inner);
        if n == 1 || n == 2 {
            check_rc("decrypt alice", smime::open(out, ak, alice, r), mail::OK);
            check("decrypt alice", r.entity == inner);
        }
        // Bob's certificate with Carol's key; Dave, who is not a recipient;
        // no key at all.
        check_rc("wrong key", smime::open(out, ck, bob, r), mail::ERR_DECRYPT);
        check_rc("not a recipient", smime::open(out, dk, dave, r), mail::ERR_DECRYPT);
        check("not a recipient", r.cms_error == x509::ERR_CMS_NOT_RECIPIENT);
        check_rc("no key", smime::verify(out, r), mail::ERR_KEY);
        if gcm {
            // GCM's tag catches any change (CBC has none to catch it).
            let at = smime::find(out, "\r\n\r\n", find(out, "smime-type")) + 4;
            var bad: u8[>..] = [];
            bad.append(out);
            let p = at + (bad.len - at) * 3 / 4;
            bad[p] = if bad[p] == 'A' { 'B' } else { 'A' };
            check_rc("changed ciphertext", smime::open(bad, bk, bob, r), mail::ERR_DECRYPT);
        }
        n++;
    }
    // A recipient that cannot be (Ed25519), none at all, a cipher there is not.
    var out: u8[>..] = [];
    let o = smime::Options { .. };
    check_rc("ed25519 recipient", smime::encrypt(m, der(DAVE_PEM), o, out), mail::ERR_CERT);
    check_rc("no recipient", smime::encrypt(m, "", o, out), mail::ERR_CERT);
    let o2 = smime::Options { cipher: x509::CMS_AES192_CBC, .. };
    check_rc("aes-192", smime::encrypt(m, rs, o2, out), mail::ERR_ARG);
}

fn sign_then_encrypt() {
    let alice = cert(ALICE_PEM);
    let bob = cert(BOB_PEM);
    var m = mail::Msg { .. };
    build(m);
    let inner = inner_of(m);
    let o = smime::Options { signing_time: TIME, cipher: x509::CMS_AES256_GCM, .. };
    var out: u8[>..] = [];
    let ak = key(ALICE_KEY);
    let bk = key(BOB_KEY);
    check_rc("sign-encrypt", smime::sign_encrypt(m, ak, alice, der(INTER_PEM), bob.der, o, out), mail::OK);
    var r = smime::Opened { .. };
    check_rc("sign-encrypt", smime::open(out, bk, bob, r), mail::OK);
    check("sign-encrypt", r.signed && r.encrypted && r.signer.der == alice.der && r.entity == inner);
    let pool = roots();
    check_rc("sign-encrypt", smime::check_signer(r, pool, NOW, smime::from_address(out)), mail::OK);
}

fn not_smime() {
    var m = mail::Msg { .. };
    build(m);
    var raw: u8[>..] = [];
    assert(mail::write(m, raw) == mail::OK);
    var r = smime::Opened { .. };
    check_rc("plain", smime::verify(raw, r), mail::ERR_FORMAT);
    let pgp = "From: a@example.com\r\nContent-Type: multipart/signed; protocol=\"application/pgp-signature\"; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b\r\nContent-Type: application/pgp-signature\r\n\r\nsig\r\n--b--\r\n";
    check_rc("pgp", smime::verify(pgp, r), mail::ERR_FORMAT);
    let broken = "Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; boundary=b\r\n\r\n--b\r\n\r\nx\r\n--b--\r\n";
    check_rc("one part", smime::verify(broken, r), mail::ERR_FORMAT);
    let junk = "Content-Type: application/pkcs7-mime; smime-type=signed-data\r\nContent-Transfer-Encoding: base64\r\n\r\nMIIB\r\n";
    check_rc("junk", smime::verify(junk, r), mail::ERR_FORMAT);
    // A raw message signed: no MIME-Version of its own, one is added.
    var out: u8[>..] = [];
    let o = smime::Options { .. };
    let bk = key(BOB_KEY);
    let bc = cert(BOB_PEM);
    check_rc("raw", smime::sign("From: bob@example.org\nSubject: hi\n\nhello\n", bk, bc, "", o, out), mail::OK);
    check("raw", starts(out, "From: bob@example.org\r\nSubject: hi\r\nMIME-Version: 1.0\r\nContent-Type: multipart/signed"));
    check_rc("raw", smime::verify(out, r), mail::OK);
    check("raw", r.entity == "\r\nhello\r\n");
    // Opaque-signed content with LF lines (as openssl -binary keeps a
    // file's): verified as it is, its entity read with CRLF.
    let so = x509::CmsSignOptions { .. };
    let lf = "Content-Type: text/plain\n\nhi\n";
    let der, oks = x509::cms_sign_with(x509::OID_CMS_DATA, lf, bk, bc, "", x509::SIG_ECDSA, 256, so);
    var p7m: u8[>..] = [];
    smime::put_pkcs7_mime(p7m, "signed-data", der);
    check_rc("lf entity", smime::verify(p7m, r), mail::OK);
    check("lf entity", oks && r.entity == "Content-Type: text/plain\r\n\r\nhi\r\n");
}

// Messages openssl made.
fn openssl() {
    let pool = roots();
    var r = smime::Opened { .. };
    for i in 6 {
        let msg = if i == 0 { embed_file("smime/ossl-signed-rsa.eml") } else if i == 1 { embed_file("smime/ossl-signed-pss.eml") }
                  else if i == 2 { embed_file("smime/ossl-signed-p256-opaque.eml") } else if i == 3 { embed_file("smime/ossl-signed-p384.eml") }
                  else if i == 4 { embed_file("smime/ossl-signed-ed25519.eml") } else { embed_file("smime/ossl-signed-stream.eml") };
        let signer = if i == 2 { BOB_PEM } else if i == 3 { CAROL_PEM } else if i == 4 { DAVE_PEM } else { ALICE_PEM };
        let rc = smime::verify(msg, r);
        check_rc(str("openssl signed ", i), rc, mail::OK);
        check(str("openssl signed ", i), r.signed && r.signer.der == cert(signer).der && r.entity == ENTITY && r.has_signing_time);
        check(str("openssl signed ", i), smime::check_path(r, pool, NOW) == x509::OK);
        check_rc(str("openssl signed ", i), smime::check_signer(r, pool, NOW, smime::from_address(msg)),
                 if signer == ALICE_PEM { mail::OK } else { mail::ERR_CERT });
    }
    check_rc("openssl signed, changed", smime::verify(changed(embed_file("smime/ossl-signed-rsa.eml"), "Hello from"), r),
             mail::ERR_SIGNATURE);
    let eve = embed_file("smime/ossl-signed-eve.eml");
    check_rc("openssl signed eve", smime::verify(eve, r), mail::OK);
    check("openssl signed eve: not for email", smime::check_path(r, pool, NOW) == x509::ERR_EXTENDED_KEY_USAGE);
    // Encrypted: each for whom it was.
    let alice = cert(ALICE_PEM);
    let bob = cert(BOB_PEM);
    let carol = cert(CAROL_PEM);
    let ak = key(ALICE_KEY);
    let bk = key(BOB_KEY);
    let ck = key(CAROL_KEY);
    check_rc("openssl rsa pkcs1", smime::open(embed_file("smime/ossl-enc-rsa-pkcs1.eml"), ak, alice, r), mail::OK);
    check("openssl rsa pkcs1", r.encrypted && r.entity == ENTITY && contains(r.message, "Subject: From OpenSSL"));
    check_rc("openssl rsa oaep", smime::open(embed_file("smime/ossl-enc-rsa-oaep.eml"), ak, alice, r), mail::OK);
    check("openssl rsa oaep", r.entity == ENTITY);
    check_rc("openssl p256", smime::open(embed_file("smime/ossl-enc-p256.eml"), bk, bob, r), mail::OK);
    check("openssl p256", r.entity == ENTITY);
    check_rc("openssl gcm", smime::open(embed_file("smime/ossl-enc-gcm.eml"), bk, bob, r), mail::OK);
    check("openssl gcm", r.entity == ENTITY);
    check_rc("openssl multi", smime::open(embed_file("smime/ossl-enc-multi.eml"), ck, carol, r), mail::OK);
    check("openssl multi", r.entity == ENTITY);
    check_rc("openssl not for carol", smime::open(embed_file("smime/ossl-enc-p256.eml"), ck, carol, r), mail::ERR_DECRYPT);
    let se = embed_file("smime/ossl-sign-encrypt.eml");
    check_rc("openssl sign-encrypt", smime::open(se, bk, bob, r), mail::OK);
    check("openssl sign-encrypt", r.signed && r.encrypted && r.signer.der == alice.der && r.entity == ENTITY);
}

// --- Post-quantum ------------------------------------------------------------------

fn pq_roots() -> x509::CertPool {
    var p = x509::new_pool();
    assert(x509::pool_append_pem(p, PQ_ROOT_PEM) == 1);
    return p;
}

fn pq_build(m: mail::Msg&, from: const u8[:]) {
    assert(mail::set_from(m, from) == mail::OK);
    assert(mail::add_to(m, "Grace <grace@example.org>") == mail::OK);
    assert(mail::set_subject(m, "Post-quantum figures") == mail::OK);
    mail::set_date(m, 1790000000);
    assert(mail::set_message_id(m, "smime-pq@example.com") == mail::OK);
    assert(mail::set_boundary(m, "test") == mail::OK);
    assert(mail::set_body(m, mail::TEXT_PLAIN, "The figures are attached.\nSigned by a lattice.\n") == mail::OK);
    assert(mail::attach(m, "figures.csv", "q,amount\n1,100\n2,103\n") == mail::OK);
}

fn pq_signing() {
    let frank_key = key(FRANK_KEY);
    let frank = cert(FRANK_PEM);
    let frank_kem_key = key(FRANK_KEM_KEY);
    let frank_kem = cert(FRANK_KEM_PEM);
    let pool = pq_roots();
    for i in 3 {
        let pem = if i == 0 { FRANK_PEM } else if i == 1 { GRACE_PEM } else { HEIDI_PEM };
        let kpem = if i == 0 { FRANK_KEY } else if i == 1 { GRACE_KEY } else { HEIDI_KEY };
        let from = if i == 0 { "Frank <frank@example.com>" } else if i == 1 { "grace@example.org" } else { "Heidi <heidi@example.com>" };
        let what = if i == 0 { "sign ml-dsa-65" } else if i == 1 { "sign ml-dsa-44" } else { "sign ml-dsa-87" };
        let c = cert(pem);
        let k = key(kpem);
        check(what, x509::is_mldsa(k.kind) && k.kind == c.key_type);
        var m = mail::Msg { .. };
        pq_build(m, from);
        let inner = inner_of(m);
        // Options.hash is not ML-DSA's: SHA-512 whatever it says.
        var o = smime::Options { hash: 256, signing_time: TIME, by_key_id: i == 2, .. };
        o.boundary.append("signed-boundary");
        var out: u8[>..] = [];
        check_rc(what, smime::sign(m, k, c, "", o, out), mail::OK);
        check(what, contains(out, "micalg=sha-512"));
        var r = smime::Opened { .. };
        check_rc(what, smime::verify(out, r), mail::OK);
        check(what, r.signed && r.signer.der == c.der && r.entity == inner && r.signing_time == TIME);
        check_rc(what, smime::check_signer(r, pool, NOW, smime::from_address(out)), mail::OK);
        check_rc(what, smime::check_signer(r, pool, NOW, "alice@example.com"), mail::ERR_CERT);
        var r2 = smime::Opened { .. };
        check_rc(what, smime::verify(changed(out, "figures are"), r2), mail::ERR_SIGNATURE);
        // Opaque.
        var op: u8[>..] = [];
        check_rc(what, smime::sign_opaque(m, k, c, "", o, op), mail::OK);
        check_rc(what, smime::verify(op, r2), mail::OK);
        check(what, r2.signed && r2.entity == inner && smime::check_path(r2, pool, NOW) == x509::OK);
        // The ML-DSA root does not know the classic chain, nor the other way.
        let classic = roots();
        check_rc(what, smime::check_signer(r, classic, NOW, ""), mail::ERR_CERT);
    }
    // An ML-KEM key cannot sign; nor an ML-DSA key with an ML-KEM certificate.
    var m = mail::Msg { .. };
    pq_build(m, "frank@example.com");
    var out: u8[>..] = [];
    let o = smime::Options { .. };
    check_rc("ml-kem signs", smime::sign(m, frank_kem_key, frank_kem, "", o, out), mail::ERR_KEY);
    check_rc("ml-dsa key, ml-kem cert", smime::sign(m, frank_key, frank_kem, "", o, out), mail::ERR_KEY);
}

fn pq_encryption() {
    let frank_key = key(FRANK_KEY);
    let frank = cert(FRANK_PEM);
    let frank_kem = cert(FRANK_KEM_PEM);
    let grace_kem_key = key(GRACE_KEM_KEY);
    let grace_kem = cert(GRACE_KEM_PEM);
    var rs: u8[>..] = [];
    rs.append(der(FRANK_KEM_PEM));
    rs.append(der(GRACE_KEM_PEM));
    rs.append(der(HEIDI_KEM_PEM));
    rs.append(der(BOB_PEM));
    var m = mail::Msg { .. };
    pq_build(m, "frank@example.com");
    let inner = inner_of(m);
    var n = 0;
    for cipher in [x509::CMS_AES256_CBC, x509::CMS_AES256_GCM] {
        let o = smime::Options { cipher: cipher, by_key_id: n == 1, .. };
        var out: u8[>..] = [];
        check_rc("pq encrypt", smime::encrypt(m, rs, o, out), mail::OK);
        var r = smime::Opened { .. };
        for i in 4 {
            let c = cert(if i == 0 { FRANK_KEM_PEM } else if i == 1 { GRACE_KEM_PEM } else if i == 2 { HEIDI_KEM_PEM } else { BOB_PEM });
            let k = key(if i == 0 { FRANK_KEM_KEY } else if i == 1 { GRACE_KEM_KEY } else if i == 2 { HEIDI_KEM_KEY } else { BOB_KEY });
            let rc = smime::open(out, k, c, r);
            check_rc(str("pq decrypt ", i), rc, mail::OK);
            check(str("pq decrypt ", i), r.encrypted && r.entity == inner);
        }
        check_rc("pq wrong key", smime::open(out, grace_kem_key, frank_kem, r), mail::ERR_DECRYPT);
        check_rc("pq signing cert", smime::open(out, frank_key, frank, r), mail::ERR_DECRYPT);
        check("pq signing cert", r.cms_error == x509::ERR_CMS_NOT_RECIPIENT);
        n++;
    }
    var out: u8[>..] = [];
    let o = smime::Options { .. };
    check_rc("ml-dsa recipient", smime::encrypt(m, der(FRANK_PEM), o, out), mail::ERR_CERT);
    // Signed by ML-DSA, encrypted to ML-KEM.
    let so = smime::Options { signing_time: TIME, cipher: x509::CMS_AES128_GCM, .. };
    var se: u8[>..] = [];
    check_rc("pq sign-encrypt", smime::sign_encrypt(m, frank_key, frank, "", der(GRACE_KEM_PEM), so, se), mail::OK);
    var r = smime::Opened { .. };
    check_rc("pq sign-encrypt", smime::open(se, grace_kem_key, grace_kem, r), mail::OK);
    check("pq sign-encrypt", r.signed && r.encrypted && r.signer.der == cert(FRANK_PEM).der && r.entity == inner);
    let pool = pq_roots();
    check_rc("pq sign-encrypt", smime::check_signer(r, pool, NOW, smime::from_address(se)), mail::OK);
}

// Post-quantum messages openssl made.
fn pq_openssl() {
    let frank_kem_key = key(FRANK_KEM_KEY);
    let frank_kem = cert(FRANK_KEM_PEM);
    let grace_kem_key = key(GRACE_KEM_KEY);
    let grace_kem = cert(GRACE_KEM_PEM);
    let heidi_kem_key = key(HEIDI_KEM_KEY);
    let heidi_kem = cert(HEIDI_KEM_PEM);
    let pool = pq_roots();
    var r = smime::Opened { .. };
    for i in 3 {
        let msg = if i == 0 { embed_file("smime/pq/ossl-signed-mldsa65.eml") }
                  else if i == 1 { embed_file("smime/pq/ossl-signed-mldsa44-opaque.eml") }
                  else { embed_file("smime/pq/ossl-signed-mldsa87-sha512.eml") };
        let signer = if i == 0 { FRANK_PEM } else if i == 1 { GRACE_PEM } else { HEIDI_PEM };
        let rc = smime::verify(msg, r);
        check_rc(str("openssl pq signed ", i), rc, mail::OK);
        check(str("openssl pq signed ", i), r.signed && r.signer.der == cert(signer).der && r.entity == ENTITY);
        check(str("openssl pq signed ", i), smime::check_path(r, pool, NOW) == x509::OK);
        // From is Frank's: only his passes.
        check_rc(str("openssl pq signed ", i), smime::check_signer(r, pool, NOW, smime::from_address(msg)),
                 if i == 0 { mail::OK } else { mail::ERR_CERT });
    }
    check_rc("openssl pq signed, changed", smime::verify(changed(embed_file("smime/pq/ossl-signed-mldsa65.eml"), "Hello from"), r),
             mail::ERR_SIGNATURE);
    check_rc("openssl mlkem768", smime::open(embed_file("smime/pq/ossl-enc-mlkem768.eml"), frank_kem_key, frank_kem, r), mail::OK);
    check("openssl mlkem768", r.encrypted && r.entity == ENTITY && contains(r.message, "Subject: From OpenSSL"));
    check_rc("openssl mlkem512 gcm", smime::open(embed_file("smime/pq/ossl-enc-mlkem512-gcm.eml"), grace_kem_key, grace_kem, r), mail::OK);
    check("openssl mlkem512 gcm", r.entity == ENTITY);
    check_rc("openssl mlkem1024 keyid", smime::open(embed_file("smime/pq/ossl-enc-mlkem1024-keyid.eml"), heidi_kem_key, heidi_kem, r), mail::OK);
    check("openssl mlkem1024 keyid", r.entity == ENTITY);
    let ukm = embed_file("smime/pq/ossl-enc-mlkem-ukm.eml");
    check_rc("openssl mlkem ukm", smime::open(ukm, frank_kem_key, frank_kem, r), mail::OK);
    check("openssl mlkem ukm", r.entity == ENTITY);
    check_rc("openssl mlkem ukm, grace", smime::open(ukm, grace_kem_key, grace_kem, r), mail::OK);
    check_rc("openssl mlkem not for heidi", smime::open(ukm, heidi_kem_key, heidi_kem, r), mail::ERR_DECRYPT);
    let se = embed_file("smime/pq/ossl-sign-encrypt.eml");
    check_rc("openssl pq sign-encrypt", smime::open(se, grace_kem_key, grace_kem, r), mail::OK);
    check("openssl pq sign-encrypt", r.signed && r.encrypted && r.signer.der == cert(FRANK_PEM).der && r.entity == ENTITY);
    check_rc("openssl pq sign-encrypt", smime::check_signer(r, pool, NOW, smime::from_address(se)), mail::OK);
}

fn main() {
    signing();
    signer_checks();
    opaque();
    encryption();
    sign_then_encrypt();
    not_smime();
    openssl();
    pq_signing();
    pq_encryption();
    pq_openssl();
    print("smime: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
