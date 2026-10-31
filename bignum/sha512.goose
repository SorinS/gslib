// bignum.sha512: SHA-512, SHA-384, SHA-512/224 and SHA-512/256 (FIPS
// 180-4), which share one compression function and differ in their
// initial values and output length. Streaming like bignum.sha256: sha512_init or sha384_init,
// sha512_update, sha512_final; or sha512(data) and sha384(data). Nothing
// branches on the data, only on lengths.

namespace bignum;

import std;

struct Sha512 { h: u64[8], buf: u8[128], used: i64, total: u64, outlen: i64 }

let SHA512_K: u64[80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

let SHA512_IV: u64[8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];

let SHA384_IV: u64[8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
];

// SHA-512/224 and SHA-512/256 (FIPS 180-4 §5.3.6).
let SHA512_224_IV: u64[8] = [
    0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
    0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1
];

let SHA512_256_IV: u64[8] = [
    0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
    0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2
];

fn rotr64(x: u64, n: u64) -> u64 { (x >> n) | (x << (64 - n)) }

fn sha512_init() -> Sha512 {
    Sha512 { h: SHA512_IV, buf: [0; 128], used: 0, total: 0, outlen: 64 }
}

fn sha384_init() -> Sha512 {
    Sha512 { h: SHA384_IV, buf: [0; 128], used: 0, total: 0, outlen: 48 }
}

fn sha512_224_init() -> Sha512 {
    Sha512 { h: SHA512_224_IV, buf: [0; 128], used: 0, total: 0, outlen: 28 }
}

fn sha512_256_init() -> Sha512 {
    Sha512 { h: SHA512_256_IV, buf: [0; 128], used: 0, total: 0, outlen: 32 }
}

fn sha512_block(s: Sha512&, p: const u8[:]) {
    var w: u64[80] = [0; 80];
    for i in 16 {
        var x: u64 = 0;
        for k in 8 { x = (x << 8) | p[8 * i + k]; }
        w[i] = x;
    }
    for i in 16..80 {
        let s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3];
    var e = s.h[4]; var f = s.h[5]; var g = s.h[6]; var h = s.h[7];
    for i in 80 {
        let t1 = h + (rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)) + ((e & f) ^ (~e & g))
               + SHA512_K[i] + w[i];
        let t2 = (rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
    s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}

fn sha512_update(s: Sha512&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(128 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 128 { return; }
        let blk = s.buf;
        sha512_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 128 {
        sha512_block(s, data[i..i + 128]);
        i += 128;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

// The digest: 64 bytes, or 48 for a context from sha384_init.
fn sha512_final(s: Sha512&) -> u8[>..] {
    let bits = s.total * 8;
    var tail: u8[144] = [0; 144];
    tail[0] = 0x80;
    // The length takes 16 bytes; messages stay below 2^61 bytes, so the top
    // 8 are zero.
    let padlen = if s.used < 112 { 112 - s.used } else { 240 - s.used };
    for k in 8 { tail[padlen + 8 + k] = (bits >> (56 - 8 * k)) as! u8; }
    sha512_update(s, tail[..padlen + 16]);
    var out: u8[>..] = [];
    for i in s.outlen { out.push((s.h[i / 8] >> (56 - 8 * (i % 8))) as! u8); }
    return out;
}

fn sha512(data: const u8[:]) -> u8[>..] {
    var s = sha512_init();
    sha512_update(s, data);
    return sha512_final(s);
}

fn sha384(data: const u8[:]) -> u8[>..] {
    var s = sha384_init();
    sha512_update(s, data);
    return sha512_final(s);
}
