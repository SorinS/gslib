// bignum.ripemd160: RIPEMD-160 (Dobbertin, Bosselaers and Preneel, 1996),
// as Go's x/crypto/ripemd160 has it, for Bitcoin addresses and old PGP and
// X.509 data. Two lines of 80 steps over each block, combined at the end.

namespace bignum;

import std;

struct Ripemd160 { h: u32[5], buf: u8[64], used: i64, total: u64 }

// The word each step reads, and its rotation, in the left and right lines.
let RMD_R: u8[80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
];
let RMD_RR: u8[80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
];
let RMD_S: u32[80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
];
let RMD_SR: u32[80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
];
let RMD_K: u32[5] = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
let RMD_KR: u32[5] = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

fn ripemd160_init() -> Ripemd160 {
    Ripemd160 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], buf: [0; 64], used: 0, total: 0 }
}

fn rmd_rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

// The step function of round j / 16 (0 to 4).
fn rmd_f(round: i64, x: u32, y: u32, z: u32) -> u32 {
    if round == 0 { return x ^ y ^ z; }
    if round == 1 { return (x & y) | (~x & z); }
    if round == 2 { return (x | ~y) ^ z; }
    if round == 3 { return (x & z) | (y & ~z); }
    return x ^ (y | ~z);
}

fn ripemd160_block(s: Ripemd160&, p: const u8[:]) {
    var m: u32[16] = [0; 16];
    for i in 16 {
        let b0: u32 = p[4 * i];
        m[i] = b0 | (p[4 * i + 1] as u32) << 8 | (p[4 * i + 2] as u32) << 16 | (p[4 * i + 3] as u32) << 24;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3]; var e = s.h[4];
    var ar = a; var br = b; var cr = c; var dr = d; var er = e;
    for j in 80 {
        let round = j / 16;
        let t = rmd_rotl(a + rmd_f(round, b, c, d) + m[RMD_R[j]] + RMD_K[round], RMD_S[j]) + e;
        a = e; e = d; d = rmd_rotl(c, 10); c = b; b = t;
        let tr = rmd_rotl(ar + rmd_f(4 - round, br, cr, dr) + m[RMD_RR[j]] + RMD_KR[round], RMD_SR[j]) + er;
        ar = er; er = dr; dr = rmd_rotl(cr, 10); cr = br; br = tr;
    }
    let t = s.h[1] + c + dr;
    s.h[1] = s.h[2] + d + er;
    s.h[2] = s.h[3] + e + ar;
    s.h[3] = s.h[4] + a + br;
    s.h[4] = s.h[0] + b + cr;
    s.h[0] = t;
}

fn ripemd160_update(s: Ripemd160&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(64 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 64 { return; }
        let blk = s.buf;
        ripemd160_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 64 {
        ripemd160_block(s, data[i..i + 64]);
        i += 64;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

fn ripemd160_final(s: Ripemd160&) -> u8[20] {
    let bits = s.total * 8;
    var tail: u8[72] = [0; 72];
    tail[0] = 0x80;
    let padlen = if s.used < 56 { 56 - s.used } else { 120 - s.used };
    for k in 8 { tail[padlen + k] = (bits >> (8 * k)) as! u8; }
    ripemd160_update(s, tail[..padlen + 8]);
    var out: u8[20] = [0; 20];
    for i in 5 {
        for k in 4 { out[4 * i + k] = (s.h[i] >> (8 * k)) as! u8; }
    }
    return out;
}

fn ripemd160(data: const u8[:]) -> u8[20] {
    var s = ripemd160_init();
    ripemd160_update(s, data);
    return ripemd160_final(s);
}
