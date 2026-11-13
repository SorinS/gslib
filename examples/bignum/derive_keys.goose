// Key derivation: HKDF turns a shared secret into several independent
// keys (RFC 5869's first test case, then extract and expand by hand);
// PBKDF2 and scrypt stretch a password into a key. Each is checked
// against a known answer.
//
//   goose examples/bignum/derive_keys.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.kdf;
import gslib.crypto.bignum.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    // HKDF-SHA256 in one call: RFC 5869 A.1.
    let ikm = unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let okm = bignum::hkdf(256, unhex("000102030405060708090a0b0c"), ikm, unhex("f0f1f2f3f4f5f6f7f8f9"), 42);
    guard hex(okm) == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865" else {
        print("derive_keys: hkdf is wrong");
        exit(1);
    }
    print("hkdf (RFC 5869 A.1)  ", hex(okm));

    // Extract once, then expand with a different label for each key, so
    // the client and server keys are independent of each other.
    var secret: u8[32] = [0; 32];
    bignum::random_bytes(secret);
    var salt: u8[16] = [0; 16];
    bignum::random_bytes(salt);
    let prk = bignum::hkdf_extract(256, salt, secret);
    let client_key = bignum::hkdf_expand(256, prk, "example v1 client key", 32);
    let server_key = bignum::hkdf_expand(256, prk, "example v1 server key", 32);
    guard client_key != server_key && client_key == bignum::hkdf(256, salt, secret, "example v1 client key", 32) else {
        print("derive_keys: hkdf expand disagrees");
        exit(1);
    }
    print("client key           ", hex(client_key));
    print("server key           ", hex(server_key));

    // PBKDF2-HMAC-SHA256: RFC 7914 §11's vector, at one iteration. A real
    // password wants a random salt and 600,000 iterations or more (OWASP).
    let pb = bignum::pbkdf2(256, "passwd", "salt", 1, 16);
    guard hex(pb) == "55ac046e56e3089fec1691c22544b605" else { print("derive_keys: pbkdf2 is wrong"); exit(1); }
    let wrapped = bignum::pbkdf2(256, "correct horse battery staple", salt, 10000, 32);
    print("pbkdf2 (10k rounds)  ", hex(wrapped));

    // scrypt: RFC 7914 §12's second case, N = 1024, r = 8, p = 16. Real use
    // takes N = 2^15 or more; bad parameters give false.
    let sc, ok = bignum::scrypt("password", "NaCl", 1024, 8, 16, 16);
    guard ok && hex(sc) == "fdbabe1c9d3472007856e7190d01e9fe" else { print("derive_keys: scrypt is wrong"); exit(1); }
    print("scrypt (RFC 7914)    ", hex(sc));
    let bad, okbad = bignum::scrypt("password", "NaCl", 1000, 8, 1, 16);
    guard !okbad else { print("derive_keys: scrypt took an N that is not a power of 2"); exit(1); }
    print("all derivations checked");
}
