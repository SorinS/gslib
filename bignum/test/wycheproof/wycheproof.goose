// Wycheproof (github.com/C2SP/wycheproof) against bignum. Each line of the
// file named on the command line is one test, converted from Wycheproof's
// JSON by scripts/wycheproof.py:
//
//	<kind> <tcId> <result> <fields...>
//
// fields hex, '-' for empty. result is valid (must succeed, with Wycheproof's
// output), invalid (must fail) or acceptable (either: counted apart). The
// counts go to stdout as one line, then a line per failure:
//
//	<valid passed> <valid failed> <invalid refused> <invalid accepted> <acceptable taken> <acceptable refused>
//
// Not part of run_tests.py: it needs a Wycheproof checkout.

import std;
import os;
import bignum from "../..";
import bignum.gcm;
import bignum.chacha20;
import bignum.modes;
import bignum.hmac;
import bignum.ec;
import bignum.ed25519;
import bignum.x25519;
import bignum.rsa;
import bignum.dsa;
import bignum.mlkem;
import bignum.mldsa;
import bignum.kdf;
import bignum.aes;

var valid_ok = 0;
var valid_bad = 0;
var invalid_ok = 0;
var invalid_bad = 0;
var acc_taken = 0;
var acc_refused = 0;
var failed: u8[>..] = [];

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn curve(bits: i64) -> bignum::Curve {
    if bits == 224 { return bignum::p224(); }
    if bits == 384 { return bignum::p384(); }
    if bits == 521 { return bignum::p521(); }
    return bignum::p256();
}

// Records whether the test went as its result says: `took` is whether the
// operation succeeded with Wycheproof's output.
fn record(line: const u8[:], result: const u8[:], took: bool) {
    if result == "valid" {
        if took { valid_ok++; } else { valid_bad++; failed.append(line[..::min(line.len, 120)]); failed.push('\n'); }
    } else if result == "invalid" {
        if !took { invalid_ok++; } else { invalid_bad++; failed.append(line[..::min(line.len, 120)]); failed.push('\n'); }
    } else {
        if took { acc_taken++; } else { acc_refused++; }
    }
}

// One test: whether it succeeded with the expected output.
fn run(w: const u8[:][:]) -> bool {
    let k = w[0];
    if k == "aead_gcm" || k == "aead_chacha" || k == "aead_xchacha" {
        let key = unhex(w[3]);
        let iv = unhex(w[4]);
        let aad = unhex(w[5]);
        let msg = unhex(w[6]);
        let ct = unhex(w[7]);
        let tag = unhex(w[8]);
        // gcm_encrypt and _decrypt assert a nonce (Go's NewGCMWithNonceSize
        // refuses size 0): refused before the call.
        if k == "aead_gcm" && iv.len == 0 { return false; }
        if k == "aead_chacha" && (key.len != 32 || iv.len != 12) { return false; }
        if k == "aead_xchacha" && (key.len != 32 || iv.len != 24) { return false; }
        var data: u8[>..] = [];
        data.append(ct);
        var ok = false;
        if k == "aead_gcm" {
            let g = bignum::gcm_init(key);
            ok = bignum::gcm_decrypt(g, iv, aad, data, tag);
            // Sealing gives the same ciphertext and tag.
            if ok {
                var again: u8[>..] = [];
                again.append(msg);
                let t2 = bignum::gcm_encrypt(g, iv, aad, again);
                ok = again == ct && t2[..] == tag[..];
            }
        } else if k == "aead_chacha" {
            ok = bignum::chacha20_poly1305_decrypt(key, iv, aad, data, tag);
        } else {
            ok = bignum::xchacha20_poly1305_decrypt(key, iv, aad, data, tag);
        }
        return ok && data == msg;
    }
    if k == "cbc" {
        let key = unhex(w[3]);
        let iv = unhex(w[4]);
        let msg = unhex(w[5]);
        let ct = unhex(w[6]);
        if ct.len == 0 || ct.len % 16 != 0 || iv.len != 16 { return false; }
        let a = bignum::aes_init(key);
        var data: u8[>..] = [];
        data.append(ct);
        bignum::cbc_decrypt(a, iv, data);
        let pt, ok = bignum::pkcs7_unpad(data);
        return ok && pt == msg;
    }
    if k == "xts" {
        let key = unhex(w[3]);
        // The tweak: Wycheproof's 8 bytes, as the sector number xts_* takes
        // (little-endian in the tweak block).
        let iv = unhex(w[4]);
        var sector: u64 = 0;
        for i in iv.len { sector = sector | ((iv[i] as u64) << (8 * i)); }
        let msg = unhex(w[5]);
        let ct = unhex(w[6]);
        let half = key.len / 2;
        let k1 = bignum::aes_init(key[..half]);
        let k2 = bignum::aes_init(key[half..]);
        var data: u8[>..] = [];
        data.append(msg);
        bignum::xts_encrypt(k1, k2, sector, data);
        if data != ct { return false; }
        bignum::xts_decrypt(k1, k2, sector, data);
        return data == msg;
    }
    if k == "mac" {
        let h = num(w[3]);
        let tag = unhex(w[6]);
        let full = bignum::hmac(h, unhex(w[4]), unhex(w[5]));
        return tag.len <= full.len && full[..tag.len] == tag[..];
    }
    if k == "hkdf" {
        let h = num(w[3]);
        let size = num(w[7]);
        // hkdf_expand asserts len <= 255 * HashLen (RFC 5869 §2.3).
        if size > 255 * bignum::hash_len(h) { return false; }
        return bignum::hkdf(h, unhex(w[5]), unhex(w[4]), unhex(w[6]), size) == unhex(w[8]);
    }
    if k == "pbkdf2" {
        let h = num(w[3]);
        let iter = num(w[6]);
        let dklen = num(w[7]);
        if iter < 1 || dklen < 1 { return false; }
        return bignum::pbkdf2(h, unhex(w[4]), unhex(w[5]), iter, dklen) == unhex(w[8]);
    }
    if k == "ecdh" {
        let c = curve(num(w[3]));
        let shared, ok = bignum::ecdh_shared(c, unhex(w[5]), unhex(w[4]));
        return ok && shared == unhex(w[6]);
    }
    if k == "ecdsa" {
        let c = curve(num(w[3]));
        let digest = bignum::hash_bits(num(w[4]), unhex(w[6]));
        var sig: u8[>..] = [];
        if w[8] == "der" {
            let raw, ok = bignum::ecdsa_sig_from_der(c, unhex(w[7]));
            if !ok { return false; }
            sig.append(raw);
        } else {
            sig.append(unhex(w[7]));
        }
        return bignum::ecdsa_verify_digest(c, unhex(w[5]), digest, sig);
    }
    if k == "ed25519" {
        return bignum::ed25519_verify(unhex(w[3]), unhex(w[4]), unhex(w[5]));
    }
    if k == "x25519" {
        let shared, ok = bignum::x25519_shared(unhex(w[4]), unhex(w[3]));
        return ok && shared[..] == unhex(w[5])[..];
    }
    if k == "rsa_pkcs1_verify" || k == "rsa_pss_verify" {
        let h = num(w[3]);
        let off = if k == "rsa_pss_verify" { 5 } else { 4 };
        let pub, okp = bignum::rsa_public_from(bignum::from_bytes_be(unhex(w[off])), bignum::from_bytes_be(unhex(w[off + 1])));
        if !okp { return false; }
        if k == "rsa_pkcs1_verify" { return bignum::rsa_verify_pkcs1(pub, unhex(w[6]), unhex(w[7]), h); }
        return bignum::rsa_verify_pss(pub, unhex(w[7]), unhex(w[8]), num(w[4]), h);
    }
    if k == "rsa_pkcs1_sign" {
        let key, ok = bignum::rsa_key_from_bytes(unhex(w[4]), unhex(w[5]), unhex(w[6]), unhex(w[7]), unhex(w[8]));
        if !ok { return false; }
        let sig, oks = bignum::rsa_sign_pkcs1(key, unhex(w[9]), num(w[3]));
        return oks && sig == unhex(w[10]);
    }
    if k == "rsa_oaep" {
        let key, ok = bignum::rsa_key_from_bytes(unhex(w[4]), unhex(w[5]), unhex(w[6]), unhex(w[7]), unhex(w[8]));
        if !ok { return false; }
        let pt, okd = bignum::rsa_decrypt_oaep(key, unhex(w[10]), unhex(w[11]), num(w[3]));
        return okd && pt == unhex(w[9]);
    }
    if k == "rsa_pkcs1_dec" {
        let key, ok = bignum::rsa_key_from_bytes(unhex(w[3]), unhex(w[4]), unhex(w[5]), unhex(w[6]), unhex(w[7]));
        if !ok { return false; }
        let pt, okd = bignum::rsa_decrypt_pkcs1(key, unhex(w[9]));
        return okd && pt == unhex(w[8]);
    }
    if k == "dsa" {
        let key, ok = bignum::dsa_key_from(unhex(w[4]), unhex(w[5]), unhex(w[6]), unhex(w[7]));
        if !ok { return false; }
        let digest = bignum::hash_bits(num(w[3]), unhex(w[8]));
        var sig: u8[>..] = [];
        if w[10] == "der" {
            let raw, okd = bignum::dsa_sig_from_der(key, unhex(w[9]));
            if !okd { return false; }
            sig.append(raw);
        } else {
            sig.append(unhex(w[9]));
        }
        return bignum::dsa_verify(key, digest, sig);
    }
    // mlkem_keys_from_seed, mlkem_decaps and mldsa's seed-taking functions
    // assert their seed's length (64 and 32 bytes) rather than return an
    // error: refused before the call.
    if k == "mlkem_keygen" {
        let kk = num(w[3]);
        if unhex(w[4]).len != 64 { return false; }
        let ek, dk = bignum::mlkem_keys_from_seed(kk, unhex(w[4]));
        return ek == unhex(w[5]) && dk == unhex(w[6]);
    }
    if k == "mlkem_dec" {
        let kk = num(w[3]);
        let seed = unhex(w[4]);
        if seed.len != 64 { return false; }
        let ek, dk = bignum::mlkem_keys_from_seed(kk, seed);
        let want_ek = unhex(w[5]);
        if want_ek.len > 0 && ek != want_ek { return false; }
        let key, ok = bignum::mlkem_decaps(kk, seed, unhex(w[6]));
        return ok && key == unhex(w[7]);
    }
    if k == "mlkem_encaps" {
        let key, c, ok = bignum::mlkem_encaps_with(num(w[3]), unhex(w[5]), unhex(w[4]));
        return ok && c == unhex(w[6]) && key == unhex(w[7]);
    }
    if k == "mlkem_semi" {
        let key, ok = bignum::mlkem_decaps_dk(num(w[3]), unhex(w[4]), unhex(w[5]));
        return ok && key == unhex(w[6]);
    }
    if k == "mldsa_verify" {
        return bignum::mldsa_verify(num(w[3]), unhex(w[4]), unhex(w[5]), unhex(w[6]), unhex(w[7]));
    }
    if k == "mldsa_sign" {
        let set = num(w[3]);
        let seed = unhex(w[4]);
        if seed.len != 32 { return false; }
        let pk = bignum::mldsa_public_key(set, seed);
        if pk != unhex(w[5]) { return false; }
        let want_mu = unhex(w[8]);
        var mu: u8[>..] = [];
        if w[11] == "1" {
            let m, ok = bignum::mldsa_mu(pk, unhex(w[6]), unhex(w[7]));
            if !ok { return false; }
            if want_mu.len > 0 && m != want_mu { return false; }
            mu.append(m);
        } else {
            if want_mu.len != 64 { return false; }               // an external mu, as given
            mu.append(want_mu);
        }
        var rnd: u8[32] = [0; 32];
        let r = unhex(w[9]);
        if r.len == 32 { for i in 32 { rnd[i] = r[i]; } } else if r.len != 0 { return false; }
        return bignum::mldsa_sign_internal(set, seed, mu, rnd) == unhex(w[10]);
    }
    if k == "prime" {
        let v = unhex(w[3]);
        if v.len > 0 && v[0] >= 0x80 { return false; }            // negative (two's complement)
        let primes = bignum::small_primes();
        return bignum::dsa_probably_prime(bignum::from_bytes_be(v), primes);
    }
    print("unknown kind ", k);
    assert(false);
    return false;
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: wycheproof <converted file>"); exit(2); }
    var text: u8[>..] = [];
    if !read_file(a[1], text) { print("cannot read ", a[1]); exit(2); }
    for line in split(text, '\n') {
        if line.len == 0 { continue; }
        let w = words(line);
        record(line, w[2], run(w));
    }
    print(valid_ok, " ", valid_bad, " ", invalid_ok, " ", invalid_bad, " ", acc_taken, " ", acc_refused);
    print(failed);
}
