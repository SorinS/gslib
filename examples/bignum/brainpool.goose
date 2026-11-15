// The Brainpool curves of RFC 5639 (brainpoolP256r1, P384r1, P512r1), as
// TLS 1.3's ecdsa_brainpoolP256r1tls13_sha256 and its kin use them: the
// ECDH example of RFC 7027, then on each curve a key exchange, a
// deterministic ECDSA signature, a compressed point, and the time each
// takes beside P-256.
//
//   goose examples/bignum/brainpool.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.ec;

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn us(t: f64, reps: i64) -> i64 { (t / reps * 1000000.0) as i64 }

fn demo(name: const u8[:], c: const bignum::Curve&) {
    let a, apk = bignum::ec_keypair(c);
    let b, bpk = bignum::ec_keypair(c);
    let s1, ok1 = bignum::ecdh_shared(c, a, bpk);
    let s2, ok2 = bignum::ecdh_shared(c, b, apk);
    assert(ok1 && ok2 && s1 == s2);
    let sig = bignum::ecdsa_sign(c, a, "hello");
    assert(bignum::ecdsa_sign(c, a, "hello") == sig);           // RFC 6979: no randomness
    assert(bignum::ecdsa_verify(c, apk, "hello", sig));
    assert(!bignum::ecdsa_verify(c, apk, "hellO", sig));
    // The 1 + len byte compressed form decodes back to the same key.
    let pt, okp = bignum::ec_decode(c, apk);
    let comp = bignum::ec_encode_compressed(c, pt);
    let back, okb = bignum::ec_decode_compressed(c, comp);
    assert(okp && okb && bignum::ec_encode(c, back) == apk);
    let reps = 5;
    var t0 = clock();
    for i in reps { let s, ok = bignum::ecdh_shared(c, a, bpk); }
    let te = us(clock() - t0, reps);
    t0 = clock();
    for i in reps { let s = bignum::ecdsa_sign(c, a, "hello"); }
    let ts = us(clock() - t0, reps);
    t0 = clock();
    for i in reps { let v = bignum::ecdsa_verify(c, apk, "hello", sig); }
    let tv = us(clock() - t0, reps);
    print(name, ": ECDH ", te, " us, sign ", ts, " us, verify ", tv, " us (", comp.len,
          "-byte compressed key, ", sig.len, "-byte signature)");
}

fn main() {
    // RFC 7027 A.1: A's private key with B's public key gives x_Z.
    let bp256 = bignum::bp256();
    let da = unhex("81db1ee100150ff2ea338d708271be38300cb54241d79950f77b063039804f1d");
    var qb = unhex("04");
    qb.append(unhex("8d2d688c6cf93e1160ad04cc4429117dc2c41825e1e9fca0addd34e6f1b39f7b"));    // x_qB
    qb.append(unhex("990c57520812be512641e47034832106bc7d3e8dd0e4c7f1136d7006547cec6a"));    // y_qB
    let z, ok = bignum::ecdh_shared(bp256, da, qb);
    assert(ok && z == unhex("89afc39d41d3b327814b80940b042590f96556ec91e6ae7939bce31f3a18bf2b"));
    print("RFC 7027 A.1 shared secret matches");
    // A P-256 point is not on brainpoolP256r1, though both are 256-bit.
    let p256 = bignum::p256();
    let g = bignum::ec_generator(p256);
    let pt, onc = bignum::ec_decode(bp256, bignum::ec_encode(p256, g));
    assert(!onc);

    demo("P-256          ", p256);
    demo("brainpoolP256r1", bp256);
    let bp384 = bignum::bp384();
    demo("brainpoolP384r1", bp384);
    let bp512 = bignum::bp512();
    demo("brainpoolP512r1", bp512);
}
