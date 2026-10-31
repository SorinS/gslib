// RSA with SHA-256: make a key, sign and verify with PSS and PKCS #1 v1.5,
// encrypt a short secret with OAEP, and time each operation.
//
//   goose examples/rsa_demo.goose [bits]
import std;
import os;
import bignum from "..";
import bignum.rsa;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn ms(t: f64) -> f64 { (t * 10000.0) as i64 / 10.0 }

fn main() {
    var bits = 2048;
    let a = args();
    if a.len > 1 {
        let v, ok = parse_int(a[1], 10);
        if ok { bits = v; }
    }
    var t0 = clock();
    let key = bignum::rsa_generate(bits);
    print(bits, "-bit key generated in ", ms(clock() - t0), " ms");
    let pub = bignum::rsa_public(key);
    print("n = ", hex(bignum::to_bytes_be(bignum::big_of(pub.n), bignum::rsa_size(pub)))[..32], "...");

    let msg = "the quick brown fox";
    let sig, ok_sig = bignum::rsa_sign_pss(key, msg);
    print("PSS signature verifies: ", bignum::rsa_verify_pss(pub, msg, sig),
          ", on another message: ", bignum::rsa_verify_pss(pub, "the quick brown cat", sig));
    let sig1, ok_sig1 = bignum::rsa_sign_pkcs1(key, msg);
    print("PKCS #1 v1.5 signature verifies: ", bignum::rsa_verify_pkcs1(pub, msg, sig1));

    let ct = bignum::rsa_encrypt_oaep(pub, "attack at dawn");
    let pt, ok = bignum::rsa_decrypt_oaep(key, ct);
    print("OAEP round trip: ", ok, " \"", pt, "\"");

    let reps = 20;
    t0 = clock();
    for i in reps { let s, ok_s = bignum::rsa_sign_pss(key, msg); }
    let ts = (clock() - t0) / reps;
    t0 = clock();
    for i in reps { let v = bignum::rsa_verify_pss(pub, msg, sig); }
    let tv = (clock() - t0) / reps;
    print("sign (private key): ", ms(ts), " ms, verify (public key): ", ms(tv), " ms");
}
