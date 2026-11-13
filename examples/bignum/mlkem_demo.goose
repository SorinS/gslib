// ML-KEM (FIPS 203), post-quantum key encapsulation: the receiver makes a
// key pair, the sender encapsulates a fresh shared secret to its public
// key, and the receiver decapsulates the same secret. A changed
// ciphertext gives an unrelated secret (implicit rejection), and a
// malformed public key is refused. Then a secret turned into keys by HKDF.
//
//   goose examples/bignum/mlkem_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.mlkem;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.ct;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    // k = 2, 3 or 4: ML-KEM-512, -768 (the usual choice) or -1024.
    let k = 3;
    let seed, ek = bignum::mlkem_keygen(k);
    print("ML-KEM-768: private seed ", seed.len, " bytes, encapsulation key ", ek.len, " bytes");

    // The sender: a secret and the ciphertext that carries it.
    let ss_sender, ct, ok = bignum::mlkem_encaps(k, ek);
    guard ok else { print("mlkem_demo: encapsulation refused a good key"); exit(1); }
    print("ciphertext ", ct.len, " bytes; sender's secret   ", hex(ss_sender));

    // The receiver: the same secret, from the 64-byte seed alone.
    let ss_receiver, okd = bignum::mlkem_decaps(k, seed, ct);
    print("                      receiver's secret ", hex(ss_receiver));
    guard okd && bignum::ct_eq_bytes(ss_sender, ss_receiver) == 1 else {
        print("mlkem_demo: the secrets differ");
        exit(1);
    }

    // Keeping the expanded key instead saves rebuilding it on every decaps.
    let ek2, dk = bignum::mlkem_keys_from_seed(k, seed);
    let ss2, ok2 = bignum::mlkem_decaps_dk(k, dk, ct);
    guard ok2 && ek2 == ek && ss2 == ss_receiver else { print("mlkem_demo: expanded key disagrees"); exit(1); }

    // A changed ciphertext still decapsulates, but to a pseudorandom
    // secret, so the attacker learns nothing from the receiver's reaction.
    var bad = copy(ct);
    bad[100] ^= 1;
    let ss_bad, okb = bignum::mlkem_decaps(k, seed, bad);
    guard okb && bignum::ct_eq_bytes(ss_bad, ss_sender) == 0 else { print("mlkem_demo: implicit rejection failed"); exit(1); }
    print("changed ciphertext -> unrelated secret ", hex(ss_bad));

    // A public key of the wrong length (or with coefficients out of
    // range) is refused before use.
    let x, y, okm = bignum::mlkem_encaps(k, ek[..ek.len - 1]);
    guard !okm else { print("mlkem_demo: a truncated key was used"); exit(1); }

    // The 32-byte secret is key material: derive what the protocol needs.
    let keys = bignum::hkdf(256, "", ss_sender, "example v1 traffic keys", 64);
    print("client key ", hex(keys[..32]));
    print("server key ", hex(keys[32..]));
    print("key agreement checked");
}
