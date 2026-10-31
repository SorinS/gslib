// The block modes, DES, triple DES, MD5 and RC4 against vectors/legacy.txt
// (transcriptions of SP 800-38A, FIPS 46-3 and RC4, with hashlib for MD5,
// all checked against openssl): CBC, CFB, OFB and CTR over AES at each
// key size, DES and triple DES, at lengths around the block, each way and
// in place; single blocks; MD5 around its padding boundary and HMAC-MD5;
// RC4 with keys of 1 to 256 bytes. Then PKCS #7 padding, good and bad.
import std;
import bignum from "..";
import bignum.modes;
import bignum.hmac;
import bignum.rc4;

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

// One mode both ways with one cipher's key.
fn mode_case<K>(line: const u8[:], k: const K&, mode: const u8[:], iv: const u8[:], pt: const u8[:], ct: const u8[:]) {
    var x: u8[>..] = [];
    x.append(pt);
    if mode == "cbc" { bignum::cbc_encrypt(k, iv, x); }
    else if mode == "cfb" { bignum::cfb_encrypt(k, iv, x); }
    else if mode == "ofb" { bignum::ofb_xor(k, iv, x); }
    else { bignum::ctr_xor(k, iv, x); }
    check(line, x == ct);
    if mode == "cbc" { bignum::cbc_decrypt(k, iv, x); }
    else if mode == "cfb" { bignum::cfb_decrypt(k, iv, x); }
    else if mode == "ofb" { bignum::ofb_xor(k, iv, x); }
    else { bignum::ctr_xor(k, iv, x); }
    check(line, x == pt);
}

fn main() {
    for line in split(embed_file("vectors/legacy.txt"), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "cbc" || w[0] == "cfb" || w[0] == "ofb" || w[0] == "ctr" {
            let key = unhex(w[2]);
            let iv = unhex(w[3]);
            let pt = unhex(w[4]);
            let ct = unhex(w[5]);
            if w[1] == "aes" {
                let k = bignum::aes_init(key);
                mode_case(line, k, w[0], iv, pt, ct);
                if w[0] == "ctr" {
                    var y = copy(pt);
                    bignum::aes_ctr(k, iv, y);
                    check("aes_ctr", y == ct);
                }
            } else if w[1] == "des" {
                let k = bignum::des_init(key);
                mode_case(line, k, w[0], iv, pt, ct);
            } else {
                let k = bignum::des3_init(key);
                mode_case(line, k, w[0], iv, pt, ct);
            }
        } else if w[0] == "block" {
            let key = unhex(w[2]);
            let pt = unhex(w[3]);
            let ct = unhex(w[4]);
            if w[1] == "des" {
                let k = bignum::des_init(key);
                check(line, bignum::des_encrypt_block(k, pt) == ct);
                check(line, bignum::des_decrypt_block(k, ct) == pt);
            } else {
                let k = bignum::des3_init(key);
                check(line, bignum::des3_encrypt_block(k, pt) == ct);
                check(line, bignum::des3_decrypt_block(k, ct) == pt);
                // Three equal keys are single DES.
                var same: u8[>..] = [];
                for i in 3 { same.append(key[..8]); }
                let k3 = bignum::des3_init(same);
                let k1 = bignum::des_init(key[..8]);
                check("3des = des", bignum::des3_encrypt_block(k3, pt) == bignum::des_encrypt_block(k1, pt));
            }
        } else if w[0] == "md5" {
            let m = unhex(w[1]);
            let want = unhex(w[2]);
            check(line, bignum::md5(m) == want);
            var s = bignum::md5_init();
            var off = 0;
            var step = 1;
            while off < m.len {
                let end = ::min(m.len, off + step);
                bignum::md5_update(s, m[off..end]);
                off = end;
                step += 5;
            }
            check(line, bignum::md5_final(s) == want);
            check(line, bignum::hash_bits(bignum::HASH_MD5, m) == want);
        } else if w[0] == "hmac" {
            check(line, bignum::hmac(num(w[1]), unhex(w[2]), unhex(w[3])) == unhex(w[4]));
        } else if w[0] == "rc4" {
            let pt = unhex(w[2]);
            var r = bignum::rc4_init(unhex(w[1]));
            var x = copy(pt);
            // In two pieces: the state carries over.
            let half = x.len / 2;
            bignum::rc4_xor(r, x[..half]);
            bignum::rc4_xor(r, x[half..]);
            check(line, x == unhex(w[3]));
        }
    }
    // PKCS #7.
    for n in 40 {
        var m: u8[>..] = [];
        for i in n { m.push((i * 7) as! u8); }
        for bs in [8, 16] {
            let p = bignum::pkcs7_pad(m, bs);
            check("pad length", p.len % bs == 0 && p.len > m.len && p.len - m.len <= bs);
            let back, ok = bignum::pkcs7_unpad(p, bs);
            check("unpad", ok && back == m);
            // Every change to the padding is refused, and so is a ragged length.
            let padn = p.len - m.len;
            for j in padn {
                var bad = copy(p);
                bad[p.len - 1 - j] ^= 0x40;
                let b2, ok2 = bignum::pkcs7_unpad(bad, bs);
                check("bad pad", !ok2);
            }
            let b3, ok3 = bignum::pkcs7_unpad(p[..p.len - 1], bs);
            check("ragged", !ok3);
        }
    }
    var zero: u8[16] = [0; 16];
    let z, okz = bignum::pkcs7_unpad(zero, 16);
    check("pad 0", !okz);
    var big: u8[16] = [17; 16];
    let bg, okb = bignum::pkcs7_unpad(big, 16);
    check("pad 17", !okb);
    var full: u8[16] = [16; 16];
    let f, okf = bignum::pkcs7_unpad(full, 16);
    check("pad 16", okf && f.len == 0);
    let e, oke = bignum::pkcs7_unpad("", 16);
    check("empty", !oke);
    print("modes vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
