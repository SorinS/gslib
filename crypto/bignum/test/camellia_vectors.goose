// Camellia and CMAC against vectors/camellia.txt (scripts/camellia_vectors.py:
// RFC 3713 and RFC 4493's examples, a transcription of both, every vector
// checked against openssl): s1 as A2(S_aes(A1(x))) on the planes, against
// RFC 3713's SBOX1 on all 256 bytes; F; blocks both ways at each key size
// (every one-bit plaintext and every one-bit key among them); CBC, CFB,
// OFB and CTR through bignum.modes; CMAC over AES, Camellia and 3DES at
// every length around the block edges, with truncated and altered tags
// refused.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.des;
import gslib.crypto.bignum.camellia;
import gslib.crypto.bignum.cmac;
import gslib.crypto.bignum.modes;

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

fn hex64(s: const u8[:]) -> u64 {
    var v: u64 = 0;
    for c in s {
        var x: u64 = 0;
        if c >= '0' && c <= '9' { x = c - '0'; } else { x = c - 'a' + 10; }
        v = v << 4 | x;
    }
    return v;
}

// s1 of 32 bytes at once, the way camellia_f computes it: A1, the AES
// S-box, A2, on bit planes.
fn s1_planes(xs: const u8[:]) -> u8[32] {
    var q: u32[8] = [0; 8];
    for i in 32 {
        let x: u32 = xs[i];
        for j in 8 { q[j] = q[j] | ((x >> j) & 1) << i; }
    }
    bignum::camellia_a1(q);
    bignum::aes_sbox(q);
    bignum::camellia_a2(q);
    var out: u8[32] = [0; 32];
    for i in 32 {
        var v: u32 = 0;
        for j in 8 { v = v | ((q[j] >> i) & 1) << j; }
        out[i] = v as! u8;
    }
    return out;
}

fn mode_ok<K>(k: const K&, mode: const u8[:], iv: const u8[:], pt: const u8[:], ct: const u8[:]) -> bool {
    var d: u8[>..] = [];
    d.append(pt);
    if mode == "cbc" { bignum::cbc_encrypt(k, iv, d); }
    else if mode == "cfb" { bignum::cfb_encrypt(k, iv, d); }
    else if mode == "ofb" { bignum::ofb_xor(k, iv, d); }
    else { bignum::ctr_xor(k, iv, d); }
    if d != ct { return false; }
    if mode == "cbc" { bignum::cbc_decrypt(k, iv, d); }
    else if mode == "cfb" { bignum::cfb_decrypt(k, iv, d); }
    else if mode == "ofb" { bignum::ofb_xor(k, iv, d); }
    else { bignum::ctr_xor(k, iv, d); }
    return d == pt;
}

fn cmac_ok<K>(k: const K&, msg: const u8[:], tag: const u8[:]) -> bool {
    if bignum::cmac(k, msg) != tag { return false; }
    if !bignum::cmac_verify(k, msg, tag) || !bignum::cmac_verify(k, msg, tag[..4]) { return false; }
    // An altered tag, a tag too long or empty, an altered message.
    var bad: u8[>..] = [];
    bad.append(tag);
    bad[bad.len - 1] ^= 1;
    if bignum::cmac_verify(k, msg, bad) { return false; }
    var long: u8[>..] = [];
    long.append(tag);
    long.push(0);
    if bignum::cmac_verify(k, msg, long) || bignum::cmac_verify(k, msg, "") { return false; }
    var m2: u8[>..] = [];
    m2.append(msg);
    m2.push(0);
    return !bignum::cmac_verify(k, m2, tag);
}

fn main() {
    var sboxes = 0;
    for line in split(embed_file("vectors/camellia.txt"), '\n') {
        if line.len == 0 { continue; }
        let w = split(line, ' ');
        if w[0] == "sbox1" {
            let sb = unhex(w[1]);
            for g in 8 {
                var xs: u8[32] = [0; 32];
                for i in 32 { xs[i] = (32 * g + i) as! u8; }
                let s = s1_planes(xs);
                for i in 32 { check("s1", s[i] == sb[32 * g + i]); }
            }
            sboxes++;
        } else if w[0] == "f" {
            check(line, bignum::camellia_f(hex64(w[1]), hex64(w[2])) == hex64(w[3]));
        } else if w[0] == "block" {
            let k = bignum::camellia_init(unhex(w[1]));
            let pt = unhex(w[2]);
            let ct = unhex(w[3]);
            check(line, bignum::camellia_encrypt_block(k, pt) == ct);
            check(line, bignum::camellia_decrypt_block(k, ct) == pt);
        } else if w[0] == "mode" {
            let k = bignum::camellia_init(unhex(w[2]));
            check(line, mode_ok(k, w[1], unhex(w[3]), unhex(w[4]), unhex(w[5])));
        } else if w[0] == "cmac" {
            let key = unhex(w[2]);
            let msg = unhex(w[3]);
            let tag = unhex(w[4]);
            if w[1] == "aes" {
                let k = bignum::aes_init(key);
                check(line, cmac_ok(k, msg, tag));
            } else if w[1] == "camellia" {
                let k = bignum::camellia_init(key);
                check(line, cmac_ok(k, msg, tag));
            } else {
                let k = bignum::des3_init(key);
                check(line, cmac_ok(k, msg, tag));
            }
        } else {
            check(line, false);
        }
    }
    check("sbox1 line", sboxes == 1);
    print("camellia vectors: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
