// RSA against vectors/rsa.txt: keys of 1024 bits, 1025 bits from unbalanced
// primes (PSS's encoding a byte shorter than the modulus), 1536 bits with
// e = 3, and 2048 bits (one more for SHA-384 and SHA-512 signatures,
// lines pkcs1h and pssh); for each, PKCS #1 v1.5 and PSS signatures and OAEP
// ciphertexts made by a Python transcription of RFC 8017 and checked
// against openssl. Signing and encrypting with the same salt or seed must
// give the same bytes, and verification and decryption must accept them
// and reject any change. Then the largest key taken, 8192 bits
// (vectors/rsa8192.txt): openssl's signatures and ciphertext.
import std;
import bignum from "..";
import bignum.rsa;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn num(s: const u8[:]) -> bignum::BigInt {
    let v, ok = bignum::parse(s, 16);
    assert(ok);
    return v;
}

// An 8192-bit key from openssl, as bignum's largest: imported, openssl's
// PKCS #1 v1.5 signature made again byte for byte, its PSS signature
// verified, its OAEP ciphertext decrypted; changed ones refused.
fn field8192(name: const u8[:]) -> u8[>..] {
    for line in split(embed_file("vectors/rsa8192.txt"), '\n') {
        let w = words(line);
        if w.len == 2 && w[0] == name { return unhex(w[1]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

fn rsa8192() {
    let key, ok = bignum::rsa_key_from_bytes(field8192("n"), field8192("e"), field8192("d"), field8192("p"), field8192("q"));
    check("8192: key", ok && bignum::rsa_bits(key) == 8192);
    let sig, oks = bignum::rsa_sign_pkcs1(key, "a message", 256);
    check("8192: PKCS #1 v1.5 as openssl", oks && sig == field8192("pkcs1"));
    check("8192: PKCS #1 v1.5 verifies", bignum::rsa_verify_pkcs1(key, "a message", field8192("pkcs1"), 256));
    check("8192: PSS verifies", bignum::rsa_verify_pss(key, "a message", field8192("pss"), 32, 256));
    var bad = field8192("pss");
    bad[100] ^= 1;
    check("8192: changed PSS refused", !bignum::rsa_verify_pss(key, "a message", bad, 32, 256));
    let pt, okd = bignum::rsa_decrypt_oaep(key, field8192("oaep"), "", 256);
    check("8192: OAEP decrypts", okd && pt == "a message");
    var badc = field8192("oaep");
    badc[5] ^= 1;
    let pt2, okd2 = bignum::rsa_decrypt_oaep(key, badc, "", 256);
    check("8192: changed OAEP refused", !okd2);
}

fn main() {
    var key = bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
    for line in split(embed_file("vectors/rsa.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "key" {
            let k, ok = bignum::rsa_key_from(num(w[2]), num(w[3]), num(w[4]), num(w[5]), num(w[6]));
            check(line, ok);
            key = k;
            continue;
        }
        let pub = bignum::rsa_public(key);
        let msg = unhex(w[2]);
        if w[0] == "pkcs1h" || w[0] == "pssh" {
            let bits, okb = parse_int(w[1], 10);
            if w[0] == "pkcs1h" {
                let sig = unhex(w[3]);
                let sg, oks = bignum::rsa_sign_pkcs1(key, msg, bits);
                check(line, oks && sg == sig);
                check(line, bignum::rsa_verify_pkcs1(pub, msg, sig, bits));
                // The same signature under another hash does not verify.
                check("pkcs1 other hash", !bignum::rsa_verify_pkcs1(pub, msg, sig, if bits == 256 { 384 } else { 256 }));
            } else {
                let salt = unhex(w[3]);
                let sig = unhex(w[4]);
                let sg, oks = bignum::rsa_sign_pss_with_salt(key, msg, salt, bits);
                check(line, oks && sg == sig);
                check(line, bignum::rsa_verify_pss(pub, msg, sig, salt.len, bits));
                check("pss other hash", !bignum::rsa_verify_pss(pub, msg, sig, salt.len, if bits == 512 { 384 } else { 512 }));
                let fresh, ok_fresh = bignum::rsa_sign_pss(key, msg, -1, bits);
                check("pss default salt", bignum::rsa_verify_pss(pub, msg, fresh, -1, bits));
            }
            continue;
        }
        if w[0] == "pkcs1" {
            let sig = unhex(w[3]);
            let sg, oks = bignum::rsa_sign_pkcs1(key, msg);
            check(line, oks && sg == sig);
            check(line, bignum::rsa_verify_pkcs1(pub, msg, sig));
            var other = copy(msg);
            other.push(1);
            check("pkcs1 other message", !bignum::rsa_verify_pkcs1(pub, other, sig));
            var bad = copy(sig);
            bad[bad.len / 2] ^= 4;
            check("pkcs1 changed signature", !bignum::rsa_verify_pkcs1(pub, msg, bad));
            check("pkcs1 short signature", !bignum::rsa_verify_pkcs1(pub, msg, sig[1..]));
        } else if w[0] == "pss" {
            let salt = unhex(w[3]);
            let sig = unhex(w[4]);
            let sg, oks = bignum::rsa_sign_pss_with_salt(key, msg, salt);
            check(line, oks && sg == sig);
            check(line, bignum::rsa_verify_pss(pub, msg, sig, salt.len));
            check("pss wrong salt length", !bignum::rsa_verify_pss(pub, msg, sig, salt.len + 1));
            var other = copy(msg);
            other.push(1);
            check("pss other message", !bignum::rsa_verify_pss(pub, other, sig, salt.len));
            var bad = copy(sig);
            bad[bad.len - 1] ^= 1;
            check("pss changed signature", !bignum::rsa_verify_pss(pub, msg, bad, salt.len));
            // A fresh random salt verifies too.
            let fresh, ok_fresh = bignum::rsa_sign_pss(key, msg, salt.len);
            check("pss random salt", bignum::rsa_verify_pss(pub, msg, fresh, salt.len));
        } else if w[0] == "oaep" {
            let label = unhex(w[3]);
            let seed = unhex(w[4]);
            let ct = unhex(w[5]);
            check(line, bignum::rsa_encrypt_oaep_with_seed(pub, msg, label, seed) == ct);
            let m, ok = bignum::rsa_decrypt_oaep(key, ct, label);
            check(line, ok && m == msg);
            var other = copy(label);
            other.push(0x41);
            let m2, ok2 = bignum::rsa_decrypt_oaep(key, ct, other);
            check("oaep wrong label", !ok2 && m2.len == 0);
            var bad = copy(ct);
            bad[3] ^= 0x10;
            let m3, ok3 = bignum::rsa_decrypt_oaep(key, bad, label);
            check("oaep changed ciphertext", !ok3);
            let m4, ok4 = bignum::rsa_decrypt_oaep(key, bignum::rsa_encrypt_oaep(pub, msg, label), label);
            check("oaep random seed", ok4 && m4 == msg);
        }
    }
    rsa8192();
    print("rsa vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
