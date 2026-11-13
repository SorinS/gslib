// ML-DSA (FIPS 204), post-quantum signatures: key generation, hedged and
// deterministic signing, verification, a context string that binds a
// signature to its use, and external mu (signing a message
// representative computed elsewhere, as an HSM does).
//
//   goose examples/bignum/mldsa_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.mldsa;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("mldsa_demo: ", what); exit(1); }

fn main() {
    // The set is 44, 65 or 87; 65 is ML-DSA-65.
    let set = 65;
    let seed, pk = bignum::mldsa_keygen(set);
    print("ML-DSA-65: seed ", seed.len, " bytes, public key ", pk.len, " bytes");
    guard bignum::mldsa_public_key(set, seed) == pk else { fail("public key not recomputed from the seed"); }

    // Hedged signing mixes in fresh randomness, so two signatures of one
    // message differ; both verify.
    let msg = "release v1.4.2, sha256 3f5a...";
    let s1 = bignum::mldsa_sign(set, seed, msg);
    let s2 = bignum::mldsa_sign(set, seed, msg);
    print("signature ", s1.len, " bytes: ", hex(s1[..24]), "...");
    guard s1 != s2 && bignum::mldsa_verify(set, pk, msg, s1) && bignum::mldsa_verify(set, pk, msg, s2) else {
        fail("hedged signatures");
    }
    // Deterministic signing gives the same bytes each time.
    let d1 = bignum::mldsa_sign_deterministic(set, seed, msg);
    let d2 = bignum::mldsa_sign_deterministic(set, seed, msg);
    guard d1 == d2 && bignum::mldsa_verify(set, pk, msg, d1) else { fail("deterministic signatures"); }

    // Refusals: another message, a changed signature, another key.
    var bad = copy(s1);
    bad[10] ^= 1;
    let seed2, pk2 = bignum::mldsa_keygen(set);
    guard !bignum::mldsa_verify(set, pk, "release v1.4.3", s1) && !bignum::mldsa_verify(set, pk, msg, bad) &&
          !bignum::mldsa_verify(set, pk2, msg, s1) else {
        fail("a bad signature verified");
    }
    print("other message, changed signature and other key refused");

    // A context (up to 255 bytes) separates uses of one key: a signature
    // made for "firmware" does not verify as one for "email".
    let sc = bignum::mldsa_sign(set, seed, msg, "firmware");
    guard bignum::mldsa_verify(set, pk, msg, sc, "firmware") && !bignum::mldsa_verify(set, pk, msg, sc, "email") &&
          !bignum::mldsa_verify(set, pk, msg, sc) else {
        fail("contexts");
    }
    print("context binds: verifies under \"firmware\" only");

    // External mu: the 64-byte representative of (public key, context,
    // message), made where the message is, signed where the key is.
    let mu, okmu = bignum::mldsa_mu(pk, msg, "firmware");
    guard okmu else { fail("mu"); }
    let sm = bignum::mldsa_sign_mu(set, seed, mu);
    guard bignum::mldsa_verify_mu(set, pk, mu, sm) && bignum::mldsa_verify(set, pk, msg, sm, "firmware") else {
        fail("external mu");
    }
    print("signature over external mu verifies as an ordinary one");
}
