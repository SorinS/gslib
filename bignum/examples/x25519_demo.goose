// Two parties agree on a secret over an open channel with X25519: each
// makes a key pair, they swap public keys, and each combines its own
// private key with the other's public key.
//
//   goose examples/x25519_demo.goose
import std;
import os;
import bignum from "..";
import bignum.x25519;
import bignum.ct;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    let alice_sk, alice_pk = bignum::x25519_keypair();
    let bob_sk, bob_pk = bignum::x25519_keypair();
    print("alice public: ", hex(alice_pk));
    print("bob public:   ", hex(bob_pk));
    let s1, ok1 = bignum::x25519_shared(alice_sk, bob_pk);
    let s2, ok2 = bignum::x25519_shared(bob_sk, alice_pk);
    assert(ok1 && ok2);
    print("alice shared: ", hex(s1));
    print("bob shared:   ", hex(s2));
    print("agree: ", bignum::ct_eq_bytes(s1, s2) == 1);
    // A low-order point (here u = 0) gives an all-zero secret, which
    // x25519_shared reports so the protocol can refuse it.
    let zero: u8[32] = [0; 32];
    let bad, okbad = bignum::x25519_shared(alice_sk, zero);
    print("low-order peer rejected: ", !okbad);
    let t0 = clock();
    for i in 1000 { let r = bignum::x25519_base(alice_sk); }
    print("x25519: ", ((clock() - t0) * 1000.0) as i64, " us per operation");
}
