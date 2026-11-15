// COSE_Key: the WebAuthn spec's ES256 credential key read and written back
// byte for byte; keys of every kind (P-256, P-384, P-521, Ed25519, Ed448,
// RSA 2048) through SubjectPublicKeyInfo, JWK and COSE and back; every
// algorithm signing and verifying (ECDSA as DER and as r || s, PSS and
// PKCS #1 at each hash, EdDSA by both names); and the hostile cases: an
// algorithm on the wrong key (ES256 with an RSA key, RS256 with an EC2
// key, ES384 on P-256, Ed448 on Ed25519), a key whose own alg is another,
// RS1 refused unless asked, unknown algorithms, a signature changed,
// private parts in a public key, a compressed point, a point off its
// curve, wrong lengths, an RSA key too short, a key type that is not
// one, members of the wrong type, duplicate labels.
import std;
import os;
import gslib from "../../..";
import gslib.encoding.cbor;
import gslib.encoding.cbor.cose;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.sha256;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    cbor::put_hex(out, b);
    return out;
}

// A key's COSE form, from its SubjectPublicKeyInfo.
fn cose_of(pk: const x509::PrivateKey&) -> cose::Key {
    let spki = x509::marshal_public_key(pk);
    let k, e = cose::from_spki(spki);
    check(str("from_spki kind ", pk.kind, ": ", cose::error_text(e)), e == cose::OK);
    return k;
}

fn sign_and_verify(name: const u8[:], pk: const x509::PrivateKey&, alg: i64, sig_alg: i64, h: i64) {
    var k = cose_of(pk);
    let msg = "authenticatorData || SHA-256(clientDataJSON)";
    let sig, oks = x509::sign(pk, sig_alg, h, msg);
    check(str(name, " sign"), oks);
    check(str(name, " verify"), cose::verify(k, alg, msg, sig) == cose::OK);
    var bad = copy(sig);
    bad[bad.len / 2] ^= 1;
    check(str(name, " changed signature"), cose::verify(k, alg, msg, bad) == cose::ERR_SIGNATURE);
    check(str(name, " other message"), cose::verify(k, alg, "another message", sig) == cose::ERR_SIGNATURE);
    // Through COSE's encoding and back, and through a JWK and SPKI.
    k.alg = alg;
    let enc = cose::encode(k);
    let back, eb = cose::decode(enc);
    check(str(name, " decode(encode)"), eb == cose::OK && cose::same_key(back, k) && back.alg == alg);
    var doc: cbor::Node[>..] = [];
    let root, ed = cbor::decode(enc, cbor::Options { deterministic: true, .. }, doc);
    check(str(name, " encoding deterministic"), ed == cbor::OK);
    check(str(name, " verify after round trip"), cose::verify(back, alg, msg, sig) == cose::OK);
    let j, ej = cose::to_jwk(k);
    let kj, ekj = cose::from_jwk(j);
    check(str(name, " JWK round trip"), ej == cose::OK && ekj == cose::OK && cose::same_key(kj, k));
    let spki, es = cose::to_spki(k);
    check(str(name, " SPKI is x509's"), es == cose::OK && spki[..] == x509::marshal_public_key(pk)[..]);
    // The key's own alg binds it.
    for other in [cose::ES256, cose::ES384, cose::ES512, cose::EDDSA, cose::ED25519, cose::ED448,
                  cose::RS256, cose::RS384, cose::RS512, cose::PS256, cose::PS384, cose::PS512] {
        if other != alg { check(str(name, " with its alg, not ", cose::alg_name(other)), cose::verify(k, other, msg, sig) == cose::ERR_ALG_MISMATCH); }
    }
}

fn spec_key() {
    // §16.2's ES256 credential public key, from its attestationObject.
    let h = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    let b = unhex(h);
    let k, e = cose::decode(b);
    check("spec key", e == cose::OK && k.kty == cose::KTY_EC2 && k.crv == cose::CRV_P256 && k.alg == cose::ES256);
    check("spec key written back", hex(cose::encode(k))[..] == h);
    // Followed by more (authData's extensions): decode_at says where it ends.
    var more = copy(b);
    more.append("\xa0");
    let k2, end, e2 = cose::decode_at(more, 0);
    check("decode_at", e2 == cose::OK && end == b.len);
    let k3, e3 = cose::decode(more);
    check("trailing bytes", e3 == cose::ERR_MALFORMED);
    // Its §16.2 authentication signature over authData || SHA-256(clientDataJSON).
    let ad = unhex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000");
    let cdj = unhex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d");
    let sig = unhex("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87");
    var msg = copy(ad);
    msg.append(bignum_sha256(cdj));
    check("spec assertion", cose::verify(k, cose::ES256, msg, sig) == cose::OK);
    check("spec assertion as ESP256 (the key says ES256)", cose::verify(k, cose::ESP256, msg, sig) == cose::ERR_ALG_MISMATCH);
    var k4 = k;
    k4.alg = 0;
    check("spec assertion as ESP256, no alg in the key", cose::verify(k4, cose::ESP256, msg, sig) == cose::OK);
    check("spec assertion as RS256", cose::verify(k4, cose::RS256, msg, sig) == cose::ERR_ALG_MISMATCH);
}

fn bignum_sha256(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(bignum::sha256(b));
    return out;
}

fn hostile() {
    let xy = "215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220";
    var cases: u8[][>..] = [];
    var wants: i64[>..]  = [];
    // Private parts: d.
    cases.push(str("a50102200121", xy[2..], "235820", "6e68e7a58484a3264f66b77f5d6dc5bc36a47085b615c9727ab334e8c369c2ee"));
    wants.push(cose::ERR_KEY);
    // A compressed point: y as a bool.
    var c: u8[>..] = [];
    format(c, "a4010220012158", "20afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61", "22f5");
    cases.push(copy(c));
    wants.push(cose::ERR_UNSUPPORTED);
    // y off the curve.
    var off: u8[>..] = [];
    format(off, "a40102200121", "5820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61", "225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9221");
    cases.push(copy(off));
    wants.push(cose::ERR_KEY);
    // x too short.
    cases.push(str("a40102200121581fafefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df", "225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"));
    wants.push(cose::ERR_KEY);
    // A P-256 point labelled P-384.
    cases.push(str("a40102200221", xy[2..]));
    wants.push(cose::ERR_KEY);
    // No kty; a symmetric key (kty 4); kty as text; an unknown curve.
    cases.push(str("a3200121", xy[2..]));
    wants.push(cose::ERR_MALFORMED);
    cases.push(str("a2010420", "4401020304"));
    wants.push(cose::ERR_UNSUPPORTED);
    cases.push(str("a4016345433220012158", "20afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"));
    wants.push(cose::ERR_MALFORMED);
    cases.push(str("a40102200921", xy[2..]));
    wants.push(cose::ERR_UNSUPPORTED);
    // An algorithm nobody knows; alg as text.
    cases.push(str("a501020339ffff200121", xy[2..]));
    wants.push(cose::ERR_UNKNOWN_ALG);
    cases.push(str("a5010203654553323536200121", xy[2..]));
    wants.push(cose::ERR_MALFORMED);
    // Duplicate labels.
    cases.push(str("a501020102200121", xy[2..]));
    wants.push(cose::ERR_MALFORMED);
    // OKP with a y; Ed25519 of 31 bytes; an X25519 key (not for signatures).
    cases.push(str("a40101200621", "5820", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "2241"));
    wants.push(cose::ERR_MALFORMED);
    cases.push(str("a30101200621581f", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af466"));
    wants.push(cose::ERR_KEY);
    cases.push(str("a3010120042158", "20", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"));
    wants.push(cose::ERR_UNSUPPORTED);
    // Not a map; nothing.
    cases.push(str("83010203"));
    wants.push(cose::ERR_MALFORMED);
    cases.push(str(""));
    wants.push(cose::ERR_MALFORMED);
    var i = 0;
    for h in cases {
        let k, e = cose::decode(unhex(h));
        check(str("hostile key ", i, ": ", cose::error_text(e), " want ", cose::error_text(wants[i])), e == wants[i]);
        i++;
    }
}

fn rsa_cases() {
    var pem: u8[>..] = [];
    guard read_file("data/rsa2048.key", pem) else { print("cannot read data/rsa2048.key"); exit(1); }
    let rk, okr = x509::parse_private_key_pem(pem);
    check("rsa key", okr);
    sign_and_verify("RS256", rk, cose::RS256, x509::SIG_RSA_PKCS1, 256);
    sign_and_verify("RS384", rk, cose::RS384, x509::SIG_RSA_PKCS1, 384);
    sign_and_verify("RS512", rk, cose::RS512, x509::SIG_RSA_PKCS1, 512);
    sign_and_verify("PS256", rk, cose::PS256, x509::SIG_RSA_PSS, 256);
    sign_and_verify("PS384", rk, cose::PS384, x509::SIG_RSA_PSS, 384);
    sign_and_verify("PS512", rk, cose::PS512, x509::SIG_RSA_PSS, 512);
    let k = cose_of(rk);
    let msg = "m";
    let s1, ok1 = x509::sign(rk, x509::SIG_RSA_PKCS1, 256, msg);
    check("PKCS1 is not PSS", cose::verify(k, cose::PS256, msg, s1) == cose::ERR_SIGNATURE);
    check("RS1 refused", cose::verify(k, cose::RS1, msg, s1) == cose::ERR_FORBIDDEN);
    check("RS1 asked, wrong hash", cose::verify(k, cose::RS1, msg, s1, false, true) == cose::ERR_SIGNATURE);
    check("unknown alg", cose::verify(k, -260, msg, s1) == cose::ERR_UNKNOWN_ALG);
    check("RSA key with ES256", cose::verify(k, cose::ES256, msg, s1) == cose::ERR_ALG_MISMATCH);
    check("RSA key with EdDSA", cose::verify(k, cose::EDDSA, msg, s1) == cose::ERR_ALG_MISMATCH);
    // Too short for the default; a leading zero in n; private parts.
    var k2 = k;
    let small, es = cose::decode(cose::encode(k), 4096);
    check("RSA 2048 under a 4096 minimum", es == cose::ERR_KEY);
    var nz: u8[>..] = [0];
    nz.append(k.n);
    k2.n.clear();
    k2.n.append(nz);
    check("leading zero in n", cose::validate(k2) == cose::ERR_KEY);
    var enc = cose::encode(k);
    // Add d (-3) as a fourth pair: a3 -> a4, then sort again.
    enc[0] = 0xa4;
    cbor::put_int(enc, -3);
    cbor::put_bytes(enc, "\x01");
    check("sort", cbor::sort_map(enc, 0) == cbor::OK);
    let kd, ed = cose::decode(enc);
    check("RSA private part", ed == cose::ERR_KEY);
}

fn main() {
    spec_key();
    hostile();
    let p256 = x509::generate_key(x509::KEY_EC_P256);
    let p384 = x509::generate_key(x509::KEY_EC_P384);
    let p521 = x509::generate_key(x509::KEY_EC_P521);
    let ed = x509::generate_key(x509::KEY_ED25519);
    let e448 = x509::generate_key(x509::KEY_ED448);
    sign_and_verify("ES256", p256, cose::ES256, x509::SIG_ECDSA, 256);
    sign_and_verify("ES384", p384, cose::ES384, x509::SIG_ECDSA, 384);
    sign_and_verify("ES512", p521, cose::ES512, x509::SIG_ECDSA, 512);
    sign_and_verify("ESP256", p256, cose::ESP256, x509::SIG_ECDSA, 256);
    sign_and_verify("ESP512", p521, cose::ESP512, x509::SIG_ECDSA, 512);
    sign_and_verify("EdDSA", ed, cose::EDDSA, x509::SIG_ED25519, 0);
    sign_and_verify("Ed25519", ed, cose::ED25519, x509::SIG_ED25519, 0);
    sign_and_verify("EdDSA 448", e448, cose::EDDSA, x509::SIG_ED448, 0);
    sign_and_verify("Ed448", e448, cose::ED448, x509::SIG_ED448, 0);
    let k256 = cose_of(p256);
    let k384 = cose_of(p384);
    let ked = cose_of(ed);
    let msg = "m";
    let s, oks = x509::sign(p256, x509::SIG_ECDSA, 256, msg);
    check("ES384 on P-256", cose::verify(k256, cose::ES384, msg, s) == cose::ERR_ALG_MISMATCH);
    check("ES256 on P-384", cose::verify(k384, cose::ES256, msg, s) == cose::ERR_ALG_MISMATCH);
    check("RS256 on EC2", cose::verify(k256, cose::RS256, msg, s) == cose::ERR_ALG_MISMATCH);
    check("Ed448 on Ed25519", cose::verify(ked, cose::ED448, msg, s) == cose::ERR_ALG_MISMATCH);
    check("ES256 on OKP", cose::verify(ked, cose::ES256, msg, s) == cose::ERR_ALG_MISMATCH);
    // ECDSA as r || s, COSE_Sign1's form.
    let c256 = bignum::p256();
    let rs, okrs = bignum::ecdsa_sig_from_der(c256, s);
    check("raw ECDSA", okrs && cose::verify(k256, cose::ES256, msg, rs, true) == cose::OK);
    check("raw ECDSA as DER", cose::verify(k256, cose::ES256, msg, rs) == cose::ERR_SIGNATURE);
    check("DER as raw", cose::verify(k256, cose::ES256, msg, s, true) == cose::ERR_SIGNATURE);
    // Certificates' keys, as attestation compares them.
    rsa_cases();
    print("cose: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
