// vectors/blake2.txt: BLAKE2Xb and BLAKE2Xs (the reference KATs at every
// output length from 1 to 256, the unknown-length form, and random ones
// from a transcription checked against them), one-shot and read in uneven
// pieces; HMAC, HKDF and PBKDF2 over BLAKE2b-256, -384, -512 and
// BLAKE2s-256; RSA-PSS over BLAKE2 and PKCS #1 v1.5 over MD5. Go's
// x/crypto and crypto/* agree with every line. Then ECDSA over a BLAKE2
// digest, and PKCS #1 v1.5 refusing BLAKE2.
import std;
import bignum from "..";
import bignum.blake2;
import bignum.kdf;
import bignum.rsa;
import bignum.ec;

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

// The XOF fed in pieces of growing size, then read in pieces of another
// pattern, up to want.len; a known length gives nothing past its end.
fn xof_pieces(wide: bool, n: i64, key: const u8[:], m: const u8[:], want: const u8[:]) -> bool {
    var got: u8[>..] = [];
    got.resize(want.len, 0);
    var extra: u8[3] = [0; 3];
    var past: i64 = 0;
    if wide {
        var x = bignum::blake2xb_init(n, key);
        var off = 0;
        var step = 1;
        while off < m.len {
            let end = ::min(m.len, off + step);
            bignum::blake2xb_update(x, m[off..end]);
            off = end;
            step += 9;
        }
        off = 0;
        step = 1;
        while off < got.len {
            let end = ::min(got.len, off + step);
            if bignum::blake2xb_read(x, got[off..end]) != end - off { return false; }
            off = end;
            step = step * 3 % 101;
        }
        past = bignum::blake2xb_read(x, extra);
    } else {
        var x = bignum::blake2xs_init(n, key);
        var off = 0;
        var step = 1;
        while off < m.len {
            let end = ::min(m.len, off + step);
            bignum::blake2xs_update(x, m[off..end]);
            off = end;
            step += 5;
        }
        off = 0;
        step = 1;
        while off < got.len {
            let end = ::min(got.len, off + step);
            if bignum::blake2xs_read(x, got[off..end]) != end - off { return false; }
            off = end;
            step = step * 3 % 67;
        }
        past = bignum::blake2xs_read(x, extra);
    }
    return got == want && past == (if n == 0 { 3 } else { 0 });
}

fn main() {
    var key = bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
    for line in split(embed_file("vectors/blake2.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "blake2xb" || w[0] == "blake2xs" {
            let wide = w[0] == "blake2xb";
            let n = num(w[1]);
            let k = unhex(w[2]);
            let m = unhex(w[3]);
            let want = unhex(w[4]);
            if n > 0 {
                let got = if wide { bignum::blake2xb(m, n, k) } else { bignum::blake2xs(m, n, k) };
                check(line, got == want);
            }
            check(line, xof_pieces(wide, n, k, m, want));
        } else if w[0] == "hmac" {
            check(line, bignum::hmac(num(w[1]), unhex(w[2]), unhex(w[3])) == unhex(w[4]));
        } else if w[0] == "hkdf" {
            let got = bignum::hkdf(num(w[1]), unhex(w[2]), unhex(w[3]), unhex(w[4]), num(w[5]));
            check(line, got == unhex(w[6]));
        } else if w[0] == "pbkdf2" {
            let dk = bignum::pbkdf2(num(w[1]), unhex(w[2]), unhex(w[3]), num(w[4]), num(w[5]));
            check(line, dk == unhex(w[6]));
        } else if w[0] == "key" {
            let k, ok = bignum::rsa_key_from(big(w[1]), big(w[2]), big(w[3]), big(w[4]), big(w[5]));
            check(line, ok);
            key = k;
        } else if w[0] == "pss" {
            let hash = num(w[1]);
            let salt = unhex(w[2]);
            let msg = unhex(w[3]);
            let sig = unhex(w[4]);
            let sg, oks = bignum::rsa_sign_pss_with_salt(key, msg, salt, hash);
            check(line, oks && sg == sig);
            check(line, bignum::rsa_verify_pss(key, msg, sig, salt.len, hash));
            let other = if hash == bignum::HASH_BLAKE2B_512 { bignum::HASH_BLAKE2S_256 } else { bignum::HASH_BLAKE2B_512 };
            check(line, !bignum::rsa_verify_pss(key, msg, sig, salt.len, other));
        } else if w[0] == "pkcs1" {
            let msg = unhex(w[2]);
            let sig = unhex(w[3]);
            let sg, oks = bignum::rsa_sign_pkcs1(key, msg, num(w[1]));
            check(line, oks && sg == sig);
            check(line, bignum::rsa_verify_pkcs1(key, msg, sig, num(w[1])));
            check(line, !bignum::rsa_verify_pkcs1(key, msg, sig, bignum::HASH_SHA1));
            check(line, !bignum::rsa_verify_pkcs1(key, msg, sig, bignum::HASH_BLAKE2B_512));
        }
    }
    // The one-shot hashes behind the ids.
    check("blake2b-384 id", bignum::hash_bits(bignum::HASH_BLAKE2B_384, "abc") == bignum::blake2b("abc", 48));
    check("blake2s-256 id", bignum::hash_bits(bignum::HASH_BLAKE2S_256, "abc") == bignum::blake2s("abc"));
    // ECDSA on P-256 over BLAKE2 digests, the RFC 6979 nonce from HMAC on
    // the same hash.
    let c = bignum::p256();
    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = (i * 7 + 1) as! u8; }
    let pk = bignum::ec_public_key(c, sk);
    for id in [bignum::HASH_BLAKE2B_256, bignum::HASH_BLAKE2S_256, bignum::HASH_BLAKE2B_512] {
        let d = bignum::hash_bits(id, "message");
        let sig = bignum::ecdsa_sign_digest(c, sk, d, id);
        check("ecdsa blake2", bignum::ecdsa_verify_digest(c, pk, d, sig));
        check("ecdsa blake2 repeats", bignum::ecdsa_sign_digest(c, sk, d, id) == sig);
        let other = bignum::hash_bits(id, "messagf");
        check("ecdsa blake2 other message", !bignum::ecdsa_verify_digest(c, pk, other, sig));
    }
    print("blake2 vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
