// Finite-field Diffie-Hellman over RFC 3526's 2048-bit MODP group 14, as
// SSH's diffie-hellman-group14-sha256 uses it: each side makes a secret
// exponent and a public value, checks the other's value is in range, and
// raises it to its own exponent. Both reach the same secret, which is
// hashed into a key. Values 1 and p - 1 are refused.
//
//   goose examples/bignum/ffdh_demo.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.ffdh;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.ct;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("ffdh_demo: ", what); exit(1); }

fn main() {
    let p = bignum::ffdh_prime(14);          // 15 and 16: 3072 and 4096 bits
    // 32-byte exponents: at least 28 (224 bits) for this group.
    let xa, ya = bignum::ffdh_keygen(p, 32);
    let xb, yb = bignum::ffdh_keygen(p, 32);
    print("group 14, ", p.len * 8, "-bit p; client sends ", hex(ya[..16]), "...");
    print("                    server sends ", hex(yb[..16]), "...");

    // Each side checks the peer's value (ffdh_shared does) and combines.
    let ka, oka = bignum::ffdh_shared(xa, yb, p);
    let kb, okb = bignum::ffdh_shared(xb, ya, p);
    guard oka && okb && bignum::ct_eq_bytes(ka, kb) == 1 else { fail("the shared secrets differ"); }
    // The secret is a group element, not a key: hash it (SSH hashes it
    // with the whole handshake into the exchange hash).
    let key = bignum::hkdf(256, "", ka, "example v1", 32);
    print("shared secret agrees; derived key ", hex(key));

    // A peer sending 1 or p - 1 would force a known secret: refused.
    var one: u8[>..] = [];
    one.push(1);
    var pm1 = copy(p);
    pm1[pm1.len - 1] -= 1;
    let s1, ok1 = bignum::ffdh_shared(xa, one, p);
    let s2, ok2 = bignum::ffdh_shared(xa, pm1, p);
    guard !ok1 && !ok2 && !bignum::ffdh_value_ok(one, p) && bignum::ffdh_value_ok(yb, p) else {
        fail("a degenerate peer value was taken");
    }
    print("peer values 1 and p - 1 refused");
}
