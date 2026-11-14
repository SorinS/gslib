// SLH-DSA (FIPS 205), stateless hash-based post-quantum signatures: key
// generation, hedged and deterministic signing, verification, a context
// string that binds a signature to its use, and HashSLH-DSA (signing a
// digest of the message). Its security rests on the hash alone. The "f"
// (fast) sets sign in a fraction of a second with larger signatures; the
// "s" (small) sets take seconds.
//
//   goose examples/bignum/slhdsa_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.slhdsa;
import gslib.crypto.bignum.hmac;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("slhdsa_demo: ", what); exit(1); }

fn ms(t: f64) -> i64 { (t * 1000.0) as! i64 }

fn main() {
    let set = bignum::SLHDSA_SHAKE_128F;
    var t0 = clock();
    let sk, pk = bignum::slhdsa_keygen(set);
    print(bignum::slhdsa_name(set), ": private key ", sk.len, " bytes, public key ", pk.len, " bytes (",
          ms(clock() - t0), " ms)");
    guard bignum::slhdsa_public_key(set, sk) == pk else { fail("public key not in the private key"); }

    // Hedged signing mixes in fresh randomness, so two signatures of one
    // message differ; both verify.
    let msg = "release v1.4.2, sha256 3f5a...";
    t0 = clock();
    let s1 = bignum::slhdsa_sign(set, sk, msg);
    let sign_ms = ms(clock() - t0);
    let s2 = bignum::slhdsa_sign(set, sk, msg);
    t0 = clock();
    let ok = bignum::slhdsa_verify(set, pk, msg, s1);
    let verify_ms = ms(clock() - t0);
    print("signature ", s1.len, " bytes: ", hex(s1[..24]), "... (signed in ", sign_ms, " ms, verified in ",
          verify_ms, " ms)");
    guard ok && s1 != s2 && bignum::slhdsa_verify(set, pk, msg, s2) else { fail("hedged signatures"); }
    // Deterministic signing gives the same bytes each time.
    let d1 = bignum::slhdsa_sign_deterministic(set, sk, msg);
    let d2 = bignum::slhdsa_sign_deterministic(set, sk, msg);
    guard d1 == d2 && bignum::slhdsa_verify(set, pk, msg, d1) else { fail("deterministic signatures"); }

    // Refusals: a tampered message, a changed signature, another key.
    var bad = copy(s1);
    bad[100] ^= 1;
    let sk2, pk2 = bignum::slhdsa_keygen(set);
    guard !bignum::slhdsa_verify(set, pk, "release v1.4.3, sha256 3f5a...", s1) &&
          !bignum::slhdsa_verify(set, pk, msg, bad) && !bignum::slhdsa_verify(set, pk2, msg, s1) else {
        fail("a bad signature verified");
    }
    print("tampered message, changed signature and other key refused");

    // A context (up to 255 bytes) separates uses of one key.
    let sc = bignum::slhdsa_sign(set, sk, msg, "firmware");
    guard bignum::slhdsa_verify(set, pk, msg, sc, "firmware") && !bignum::slhdsa_verify(set, pk, msg, sc, "email") &&
          !bignum::slhdsa_verify(set, pk, msg, sc) else {
        fail("contexts");
    }
    print("context binds: verifies under \"firmware\" only");

    // HashSLH-DSA signs SHA-512(msg) under SHA-512's OID; it is a separate
    // domain, so it is no pure signature, and no other hash's.
    let sh = bignum::slhdsa_hash_sign(set, sk, msg, bignum::HASH_SHA512);
    guard bignum::slhdsa_hash_verify(set, pk, msg, sh, bignum::HASH_SHA512) &&
          !bignum::slhdsa_hash_verify(set, pk, msg, sh, bignum::HASH_SHA256) && !bignum::slhdsa_verify(set, pk, msg, sh) else {
        fail("HashSLH-DSA");
    }
    print("HashSLH-DSA with SHA-512 verifies, and only as that");

    // The twelve sets: n, public key and signature sizes.
    for s in 1..13 {
        print("  ", bignum::slhdsa_name(s), ": n = ", bignum::slhdsa_n(s), ", public key ", bignum::slhdsa_pk_len(s),
              ", signature ", bignum::slhdsa_sig_len(s));
    }
}
