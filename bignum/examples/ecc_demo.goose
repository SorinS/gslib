// The elliptic-curve side of TLS 1.3: ECDHE on P-256 and P-384, ECDSA
// signatures with SHA-256 and SHA-384, Ed25519, and HKDF turning a shared
// secret into keys. Each operation is timed.
//
//   goose examples/ecc_demo.goose
import std;
import os;
import bignum from "..";
import bignum.ec;
import bignum.ed25519;
import bignum.hmac;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn us(t: f64, reps: i64) -> i64 { (t / reps * 1000000.0) as i64 }

fn curve_demo(name: const u8[:], c: const bignum::Curve&) {
    let a, apk = bignum::ec_keypair(c);
    let b, bpk = bignum::ec_keypair(c);
    let s1, ok1 = bignum::ecdh_shared(c, a, bpk);
    let s2, ok2 = bignum::ecdh_shared(c, b, apk);
    print(name, " ECDH agree: ", ok1 && ok2 && s1 == s2);
    let sig = bignum::ecdsa_sign(c, a, "hello");
    print(name, " ECDSA: ", bignum::ecdsa_verify(c, apk, "hello", sig),
          ", DER ", hex(bignum::ecdsa_sig_to_der(sig))[..16], "...");
    let reps = 20;
    var t0 = clock();
    for i in reps { let s, ok = bignum::ecdh_shared(c, a, bpk); }
    let te = us(clock() - t0, reps);
    t0 = clock();
    for i in reps { let s = bignum::ecdsa_sign(c, a, "hello"); }
    let ts = us(clock() - t0, reps);
    t0 = clock();
    for i in reps { let v = bignum::ecdsa_verify(c, apk, "hello", sig); }
    let tv = us(clock() - t0, reps);
    print(name, ": ECDH ", te, " us, sign ", ts, " us, verify ", tv, " us");
}

fn main() {
    let p256 = bignum::p256();
    let p384 = bignum::p384();
    curve_demo("P-256", p256);
    curve_demo("P-384", p384);
    let p521 = bignum::p521();
    curve_demo("P-521", p521);

    let seed, pk = bignum::ed25519_keypair();
    let sig = bignum::ed25519_sign(seed, "hello");
    print("Ed25519: ", bignum::ed25519_verify(pk, "hello", sig),
          ", on another message: ", bignum::ed25519_verify(pk, "hellO", sig));
    let reps = 20;
    var t0 = clock();
    for i in reps { let s = bignum::ed25519_sign(seed, "hello"); }
    let ts = us(clock() - t0, reps);
    t0 = clock();
    for i in reps { let v = bignum::ed25519_verify(pk, "hello", sig); }
    print("Ed25519: sign ", ts, " us, verify ", us(clock() - t0, reps), " us");

    // From a shared secret to traffic keys, the TLS 1.3 way (simplified).
    let a, apk = bignum::ec_keypair(p256);
    let b, bpk = bignum::ec_keypair(p256);
    let shared, ok = bignum::ecdh_shared(p256, a, bpk);
    let prk = bignum::hkdf_extract(256, "", shared);
    let key = bignum::hkdf_expand(256, prk, "demo key", 16);
    let iv = bignum::hkdf_expand(256, prk, "demo iv", 12);
    print("HKDF key ", hex(key), " iv ", hex(iv));
}
