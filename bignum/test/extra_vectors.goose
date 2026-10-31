// vectors/extra.txt: XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha's
// vectors and a transcription of it), cSHAKE (SP 800-185's samples and a
// transcription checked against openssl's KMAC), Ed25519ctx and
// Ed25519ph (RFC 8032 §7.2 and §7.3, and openssl), and on one 2048-bit
// key, OAEP over SHA-1, SHA-2 and SHA-3 and PKCS #1 v1.5 encryption,
// decrypted by openssl, with malformed padding refused.
import std;
import bignum from "..";
import bignum.chacha20;
import bignum.sha3;
import bignum.sha512;
import bignum.ed25519;
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

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    assert(ok);
    return v;
}

fn big(s: const u8[:]) -> bignum::BigInt {
    let v, ok = bignum::parse(s, 16);
    assert(ok);
    return v;
}

fn main() {
    var key = bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
    for line in split(embed_file("vectors/extra.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "xchacha" {
            let k = unhex(w[1]);
            let nonce = unhex(w[2]);
            let aad = unhex(w[3]);
            let pt = unhex(w[4]);
            let sealed = unhex(w[5]);
            check(line, bignum::xchacha20_poly1305_seal(k, nonce, aad, pt) == sealed);
            let opened, ok = bignum::xchacha20_poly1305_open(k, nonce, aad, sealed);
            check(line, ok && opened == pt);
            var bad = copy(sealed);
            bad[bad.len - 1] ^= 1;
            let o2, ok2 = bignum::xchacha20_poly1305_open(k, nonce, aad, bad);
            check("xchacha tag", !ok2);
            var n2 = copy(nonce);
            n2[20] ^= 1;                         // the part outside HChaCha20
            let o3, ok3 = bignum::xchacha20_poly1305_open(k, n2, aad, sealed);
            check("xchacha nonce", !ok3);
            // The stream alone is ChaCha20 from block 1, as in the AEAD.
            var x: u8[>..] = [];
            x.append(pt);
            bignum::xchacha20_xor(k, 1, nonce, x);
            check("xchacha20", x == sealed[..pt.len]);
        } else if w[0] == "hchacha" {
            check(line, bignum::hchacha20(unhex(w[1]), unhex(w[2])) == unhex(w[3]));
        } else if w[0] == "cshake" {
            let bits = num(w[1]);
            let name = unhex(w[2]);
            let custom = unhex(w[3]);
            let data = unhex(w[4]);
            let n = num(w[5]);
            let want = unhex(w[6]);
            check(line, bignum::cshake(bits, name, custom, data, n) == want);
            // Fed and read in pieces.
            var s = bignum::cshake_init(bits, name, custom);
            let half = data.len / 3;
            bignum::sha3_update(s, data[..half]);
            bignum::sha3_update(s, data[half..]);
            var out: u8[>..] = [];
            out.resize(n, 0);
            let cut = n / 2;
            bignum::shake_read(s, out[..cut]);
            bignum::shake_read(s, out[cut..]);
            check(line, out == want);
            if name.len == 0 && custom.len == 0 { check("plain shake", bignum::shake(bits, data, n) == want); }
        } else if w[0] == "edctx" || w[0] == "edph" {
            let seed = unhex(w[1]);
            let msg = unhex(w[2]);
            let ctx = unhex(w[3]);
            let sig = unhex(w[4]);
            let pk = bignum::ed25519_public(seed);
            if w[0] == "edctx" {
                check(line, bignum::ed25519_sign_ctx(seed, msg, ctx) == sig);
                check(line, bignum::ed25519_verify_ctx(pk, msg, sig, ctx));
                check("ctx is not plain", !bignum::ed25519_verify(pk, msg, sig));
                var c2 = copy(ctx);
                c2[0] ^= 1;
                check("other context", !bignum::ed25519_verify_ctx(pk, msg, sig, c2));
            } else {
                let d = bignum::sha512(msg);
                check(line, bignum::ed25519_sign_ph(seed, d, ctx) == sig);
                check(line, bignum::ed25519_verify_ph(pk, d, sig, ctx));
                check("ph is not plain", !bignum::ed25519_verify(pk, d, sig));
                var c2: u8[>..] = [];
                c2.append(ctx);
                c2.push(0);
                check("other context", !bignum::ed25519_verify_ph(pk, d, sig, c2));
            }
        } else if w[0] == "key" {
            let k, ok = bignum::rsa_key_from(big(w[2]), big(w[3]), big(w[4]), big(w[5]), big(w[6]));
            check(line, ok);
            key = k;
        } else if w[0] == "oaeph" {
            let hash = num(w[1]);
            let msg = unhex(w[2]);
            let label = unhex(w[3]);
            let seed = unhex(w[4]);
            let ct = unhex(w[5]);
            let pub = bignum::rsa_public(key);
            check(line, bignum::rsa_encrypt_oaep_with_seed(pub, msg, label, seed, hash) == ct);
            let m, ok = bignum::rsa_decrypt_oaep(key, ct, label, hash);
            check(line, ok && m == msg);
            let m2, ok2 = bignum::rsa_decrypt_oaep(key, ct, label, if hash == 256 { 384 } else { 256 });
            check("oaep other hash", !ok2);
            check("oaep max", bignum::rsa_oaep_max(pub, hash) == 256 - 2 * bignum::hash_len(hash) - 2);
        } else if w[0] == "pkcs1enc" {
            let msg = unhex(w[1]);
            let ct = unhex(w[2]);
            let m, ok = bignum::rsa_decrypt_pkcs1(key, ct);
            check(line, ok && m == msg);
            // As a session key of the right length it is taken, of another
            // length it is not.
            var sk: u8[>..] = [];
            sk.resize(msg.len, 0x5a);
            check(line, bignum::rsa_decrypt_pkcs1_session_key(key, ct, sk) && sk == msg);
            var other: u8[>..] = [];
            other.resize(if msg.len > 0 { msg.len - 1 } else { 1 }, 0x5a);
            check(line, bignum::rsa_decrypt_pkcs1_session_key(key, ct, other));
            var untouched = true;
            for b in other { if b != 0x5a { untouched = false; } }
            check("session key of another length", untouched);
            // A key longer than the padding allows is refused outright.
            var huge: u8[246] = [0; 246];
            check("session key too long", !bignum::rsa_decrypt_pkcs1_session_key(key, ct, huge));
        } else if w[0] == "pkcs1bad" {
            let ct = unhex(w[1]);
            let m, ok = bignum::rsa_decrypt_pkcs1(key, ct);
            check(line, !ok);
            var sk: u8[16] = [0x33; 16];
            check(line, bignum::rsa_decrypt_pkcs1_session_key(key, ct, sk));
            var untouched = true;
            for b in sk { if b != 0x33 { untouched = false; } }
            check("bad session key untouched", untouched);
        }
    }
    // Round trips of fresh encryptions.
    let pub = bignum::rsa_public(key);
    for n in [0, 1, 32, 245] {
        var msg: u8[>..] = [];
        for i in n { msg.push((i * 13) as! u8); }
        let c = bignum::rsa_encrypt_pkcs1(pub, msg);
        let m, ok = bignum::rsa_decrypt_pkcs1(key, c);
        check("pkcs1 round trip", ok && m == msg);
        if n <= bignum::rsa_oaep_max(pub, 512) {
            let c2 = bignum::rsa_encrypt_oaep(pub, msg, "l", 512);
            let m2, ok2 = bignum::rsa_decrypt_oaep(key, c2, "l", 512);
            check("oaep-512 round trip", ok2 && m2 == msg);
        }
    }
    print("extra vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
