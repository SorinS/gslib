// The Curve448 pair: an X448 key exchange (RFC 7748), and Ed448
// signatures (RFC 8032) with a context and the prehashed Ed448ph, timed.
//
//   goose examples/bignum/x448_ed448.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.x448;
import gslib.crypto.bignum.ed448;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("x448_ed448: ", what); exit(1); }

fn main() {
    // X448: each side makes a key pair, they swap public keys (56 bytes),
    // and each combines its private key with the other's public key.
    let alice_sk, alice_pk = bignum::x448_keypair();
    let bob_sk, bob_pk = bignum::x448_keypair();
    let s1, ok1 = bignum::x448_shared(alice_sk, bob_pk);
    let s2, ok2 = bignum::x448_shared(bob_sk, alice_pk);
    guard ok1 && ok2 && s1 == s2 else { fail("X448 secrets differ"); }
    print("X448 shared secret: ", hex(s1[..16]), "...");
    // A low-order point (u = 0) gives an all-zero secret, which
    // x448_shared reports so the protocol can refuse it.
    let zero: u8[56] = [0; 56];
    let bad, okbad = bignum::x448_shared(alice_sk, zero);
    guard !okbad else { fail("low-order peer accepted"); }

    // Ed448: a 57-byte seed and public key, 114-byte signatures.
    let seed, pk = bignum::ed448_keypair();
    let msg = "release v1.4.2";
    let sig = bignum::ed448_sign(seed, msg);
    print("Ed448 signature: ", hex(sig[..16]), "...");
    guard bignum::ed448_verify(pk, msg, sig) else { fail("signature refused"); }
    guard !bignum::ed448_verify(pk, "release v1.4.3", sig) else { fail("other message accepted"); }
    // A context binds a signature to one use; it verifies under that
    // context only.
    let csig = bignum::ed448_sign(seed, msg, "build-server");
    guard bignum::ed448_verify(pk, msg, csig, "build-server") && !bignum::ed448_verify(pk, msg, csig) else {
        fail("context");
    }
    // Ed448ph signs the message's SHAKE256 digest, so a large message can
    // be hashed in pieces first.
    let digest = bignum::ed448_prehash(msg);
    let psig = bignum::ed448_sign_ph(seed, digest);
    guard bignum::ed448_verify_ph(pk, digest, psig) && !bignum::ed448_verify(pk, msg, psig) else { fail("Ed448ph"); }
    print("contexts and Ed448ph: ok");

    let n = 20;
    var t0 = clock();
    for i in n { let r = bignum::x448_base(alice_sk); }
    let tx = clock() - t0;
    t0 = clock();
    for i in n { let r = bignum::ed448_sign(seed, msg); }
    let ts = clock() - t0;
    t0 = clock();
    for i in n { guard bignum::ed448_verify(pk, msg, sig) else { fail("verify"); } }
    let tv = clock() - t0;
    print("x448: ", (tx * 1000000.0 / n) as i64, " us, ed448 sign: ", (ts * 1000000.0 / n) as i64,
          " us, verify: ", (tv * 1000000.0 / n) as i64, " us");
}
