// bignum.camellia: Camellia-128/192/256 (RFC 3713), constant time.
//
// No table lookups: Camellia's s1 is affine-equivalent to the AES S-box,
// s1(x) = A2(S_aes(A1(x))), so F's eight S-boxes run as bignum.aes's
// bitsliced Boyar-Peralta circuit on eight bit planes, one lane a byte.
// A1 and A2 are XORs of planes (A1 carries the spec's 0xc5); s2 = s1 <<< 1,
// s3 = s1 <<< 7 and s4 = s1(x <<< 1) rotate the bits of their lanes, which
// on planes is a masked shift between neighbouring planes. A1, A2 were
// found by a linear-equivalence search and checked on all 256 inputs
// against RFC 3713's SBOX1 (scripts/extra_vectors.py repeats the check).
// The rest of Camellia is XORs, ANDs, ORs and fixed rotations.

namespace bignum;

import std;
import crypto.bignum.aes;

// The subkeys in encryption order: kw1..kw4, k1..k18 or k1..k24, ke1..ke4
// or ke1..ke6. Decryption takes them in reverse (RFC 3713 §2.3.3).
struct Camellia { rounds: i64, kw: u64[4], k: u64[24], ke: u64[6] }

let CAMELLIA_SIGMA: u64[6] = [
    0xA09E667F3BCC908B, 0xB67AE8584CAA73B2, 0xC6EF372FE94F82BE,
    0x54FF53A5F1D36F1C, 0x10E527FADE682D1D, 0xB05688C2B3E6C1FD,
];

// The 8x8 bit matrix of x (byte r its row r, bit c its column c),
// transposed: byte j of the result holds bit j of every byte of x.
fn camellia_transpose(x0: u64) -> u64 {
    var x = x0;
    var t = (x ^ (x >> 7)) & 0x00AA00AA00AA00AA;
    x = x ^ t ^ (t << 7);
    t = (x ^ (x >> 14)) & 0x0000CCCC0000CCCC;
    x = x ^ t ^ (t << 14);
    t = (x ^ (x >> 28)) & 0x00000000F0F0F0F0;
    x = x ^ t ^ (t << 28);
    return x;
}

// In the lanes of m, bit j takes bit (j + d) % 8: d = 7 rotates those
// bytes left by one, d = 1 right by one.
fn camellia_rot_lanes(p: u32[:], m: u32, d: i64) {
    var o: u32[8] = [0; 8];
    for j in 8 { o[j] = p[j]; }
    for j in 8 { p[j] = (o[j] & ~m) | (o[(j + d) % 8] & m); }
}

// A1(x) = L1(x) ^ 0x08, on planes (q[0] the low bit).
fn camellia_a1(q: u32[:]) {
    let p0 = q[0]; let p1 = q[1]; let p2 = q[2]; let p3 = q[3];
    let p4 = q[4]; let p5 = q[5]; let p6 = q[6]; let p7 = q[7];
    q[0] = p0 ^ p1 ^ p2 ^ p3 ^ p4 ^ p5 ^ p6 ^ p7;
    q[1] = p3 ^ p4 ^ p5;
    q[2] = p4;
    q[3] = ~(p1 ^ p3 ^ p7);
    q[4] = p1 ^ p2 ^ p5 ^ p7;
    q[5] = p2 ^ p3 ^ p4 ^ p6;
    q[6] = p6 ^ p7;
    q[7] = p2 ^ p3 ^ p4 ^ p5 ^ p7;
}

// A2(x) = L2(x) ^ 0x11.
fn camellia_a2(q: u32[:]) {
    let p0 = q[0]; let p1 = q[1]; let p2 = q[2]; let p3 = q[3];
    let p4 = q[4]; let p5 = q[5]; let p6 = q[6]; let p7 = q[7];
    q[0] = ~(p0 ^ p1 ^ p2 ^ p5);
    q[1] = p0 ^ p2;
    q[2] = p1 ^ p2;
    q[3] = p2 ^ p4 ^ p5 ^ p7;
    q[4] = ~(p0 ^ p1 ^ p4 ^ p5);
    q[5] = p2 ^ p3 ^ p4 ^ p6 ^ p7;
    q[6] = p3 ^ p5;
    q[7] = p0 ^ p1 ^ p4 ^ p5 ^ p6 ^ p7;
}

// Lanes are bytes from the low end: t8 is lane 0, t1 lane 7. F takes
// t1..t8 through s1 s2 s3 s4 s2 s3 s4 s1.
let CAMELLIA_LANES_S2: u32 = 0x48;   // t2, t5
let CAMELLIA_LANES_S3: u32 = 0x24;   // t3, t6
let CAMELLIA_LANES_S4: u32 = 0x12;   // t4, t7

fn camellia_byte(x: u64, i: i64) -> u64 { (x >> (56 - 8 * i)) & 255 }

// The F-function (RFC 3713 §2.4.1).
fn camellia_f(fin: u64, ke: u64) -> u64 {
    let x = camellia_transpose(fin ^ ke);
    var q: u32[8] = [0; 8];
    for j in 8 { q[j] = ((x >> (8 * j)) & 255) as! u32; }
    camellia_rot_lanes(q, CAMELLIA_LANES_S4, 7);
    camellia_a1(q);
    aes_sbox(q);
    camellia_a2(q);
    camellia_rot_lanes(q, CAMELLIA_LANES_S2, 7);
    camellia_rot_lanes(q, CAMELLIA_LANES_S3, 1);
    var y: u64 = 0;
    for j in 8 { y |= ((q[j] & 255) as u64) << (8 * j); }
    let t = camellia_transpose(y);
    let t1 = camellia_byte(t, 0); let t2 = camellia_byte(t, 1);
    let t3 = camellia_byte(t, 2); let t4 = camellia_byte(t, 3);
    let t5 = camellia_byte(t, 4); let t6 = camellia_byte(t, 5);
    let t7 = camellia_byte(t, 6); let t8 = camellia_byte(t, 7);
    // The P-function.
    let y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    let y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    let y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    let y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    let y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    let y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    let y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    let y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    return y1 << 56 | y2 << 48 | y3 << 40 | y4 << 32 | y5 << 24 | y6 << 16 | y7 << 8 | y8;
}

fn camellia_rotl32(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

// FL and FL^-1 (RFC 3713 §2.4.2).
fn camellia_fl(fin: u64, ke: u64) -> u64 {
    var x1 = (fin >> 32) as! u32;
    var x2 = fin as! u32;
    let k1 = (ke >> 32) as! u32;
    let k2 = ke as! u32;
    x2 ^= camellia_rotl32(x1 & k1, 1);
    x1 ^= x2 | k2;
    return (x1 as u64) << 32 | x2;
}

fn camellia_flinv(fin: u64, ke: u64) -> u64 {
    var y1 = (fin >> 32) as! u32;
    var y2 = fin as! u32;
    let k1 = (ke >> 32) as! u32;
    let k2 = ke as! u32;
    y1 ^= y2 | k2;
    y2 ^= camellia_rotl32(y1 & k1, 1);
    return (y1 as u64) << 32 | y2;
}

fn camellia_be64(b: const u8[:], off: i64) -> u64 {
    var v: u64 = 0;
    for i in 8 { v = v << 8 | b[off + i]; }
    return v;
}

fn camellia_put_be64(b: u8[:], off: i64, v: u64) {
    for i in 8 { b[off + i] = (v >> (56 - 8 * i)) as! u8; }
}

// The left (high) or right (low) half of the 128-bit hi:lo rotated left
// by n (a public constant).
fn camellia_half(hi: u64, lo: u64, n0: i64, left: bool) -> u64 {
    var h = hi;
    var l = lo;
    var n = n0;
    if n >= 64 {
        h = lo;
        l = hi;
        n -= 64;
    }
    if n > 0 {
        let s = n as! u64;
        let h2 = h << s | l >> (64 - s);
        let l2 = l << s | h >> (64 - s);
        h = h2;
        l = l2;
    }
    return if left { h } else { l };
}

// The key schedule (RFC 3713 §2.2) for a 16-, 24- or 32-byte key.
fn camellia_init(key: const u8[:]) -> Camellia {
    assert(key.len == 16 || key.len == 24 || key.len == 32);
    let klh = camellia_be64(key, 0);
    let kll = camellia_be64(key, 8);
    var krh: u64 = 0;
    var krl: u64 = 0;
    if key.len == 24 {
        krh = camellia_be64(key, 16);
        krl = ~krh;
    } else if key.len == 32 {
        krh = camellia_be64(key, 16);
        krl = camellia_be64(key, 24);
    }
    var d1 = klh ^ krh;
    var d2 = kll ^ krl;
    d2 ^= camellia_f(d1, CAMELLIA_SIGMA[0]);
    d1 ^= camellia_f(d2, CAMELLIA_SIGMA[1]);
    d1 ^= klh;
    d2 ^= kll;
    d2 ^= camellia_f(d1, CAMELLIA_SIGMA[2]);
    d1 ^= camellia_f(d2, CAMELLIA_SIGMA[3]);
    let kah = d1;
    let kal = d2;
    d1 = kah ^ krh;
    d2 = kal ^ krl;
    d2 ^= camellia_f(d1, CAMELLIA_SIGMA[4]);
    d1 ^= camellia_f(d2, CAMELLIA_SIGMA[5]);
    let kbh = d1;
    let kbl = d2;

    var c = Camellia { rounds: 18, kw: [0; 4], k: [0; 24], ke: [0; 6] };
    if key.len == 16 {
        c.kw[0] = camellia_half(klh, kll, 0, true);
        c.kw[1] = camellia_half(klh, kll, 0, false);
        c.k[0] = camellia_half(kah, kal, 0, true);
        c.k[1] = camellia_half(kah, kal, 0, false);
        c.k[2] = camellia_half(klh, kll, 15, true);
        c.k[3] = camellia_half(klh, kll, 15, false);
        c.k[4] = camellia_half(kah, kal, 15, true);
        c.k[5] = camellia_half(kah, kal, 15, false);
        c.ke[0] = camellia_half(kah, kal, 30, true);
        c.ke[1] = camellia_half(kah, kal, 30, false);
        c.k[6] = camellia_half(klh, kll, 45, true);
        c.k[7] = camellia_half(klh, kll, 45, false);
        c.k[8] = camellia_half(kah, kal, 45, true);
        c.k[9] = camellia_half(klh, kll, 60, false);
        c.k[10] = camellia_half(kah, kal, 60, true);
        c.k[11] = camellia_half(kah, kal, 60, false);
        c.ke[2] = camellia_half(klh, kll, 77, true);
        c.ke[3] = camellia_half(klh, kll, 77, false);
        c.k[12] = camellia_half(klh, kll, 94, true);
        c.k[13] = camellia_half(klh, kll, 94, false);
        c.k[14] = camellia_half(kah, kal, 94, true);
        c.k[15] = camellia_half(kah, kal, 94, false);
        c.k[16] = camellia_half(klh, kll, 111, true);
        c.k[17] = camellia_half(klh, kll, 111, false);
        c.kw[2] = camellia_half(kah, kal, 111, true);
        c.kw[3] = camellia_half(kah, kal, 111, false);
        return c;
    }
    c.rounds = 24;
    c.kw[0] = camellia_half(klh, kll, 0, true);
    c.kw[1] = camellia_half(klh, kll, 0, false);
    c.k[0] = camellia_half(kbh, kbl, 0, true);
    c.k[1] = camellia_half(kbh, kbl, 0, false);
    c.k[2] = camellia_half(krh, krl, 15, true);
    c.k[3] = camellia_half(krh, krl, 15, false);
    c.k[4] = camellia_half(kah, kal, 15, true);
    c.k[5] = camellia_half(kah, kal, 15, false);
    c.ke[0] = camellia_half(krh, krl, 30, true);
    c.ke[1] = camellia_half(krh, krl, 30, false);
    c.k[6] = camellia_half(kbh, kbl, 30, true);
    c.k[7] = camellia_half(kbh, kbl, 30, false);
    c.k[8] = camellia_half(klh, kll, 45, true);
    c.k[9] = camellia_half(klh, kll, 45, false);
    c.k[10] = camellia_half(kah, kal, 45, true);
    c.k[11] = camellia_half(kah, kal, 45, false);
    c.ke[2] = camellia_half(klh, kll, 60, true);
    c.ke[3] = camellia_half(klh, kll, 60, false);
    c.k[12] = camellia_half(krh, krl, 60, true);
    c.k[13] = camellia_half(krh, krl, 60, false);
    c.k[14] = camellia_half(kbh, kbl, 60, true);
    c.k[15] = camellia_half(kbh, kbl, 60, false);
    c.k[16] = camellia_half(klh, kll, 77, true);
    c.k[17] = camellia_half(klh, kll, 77, false);
    c.ke[4] = camellia_half(kah, kal, 77, true);
    c.ke[5] = camellia_half(kah, kal, 77, false);
    c.k[18] = camellia_half(krh, krl, 94, true);
    c.k[19] = camellia_half(krh, krl, 94, false);
    c.k[20] = camellia_half(kah, kal, 94, true);
    c.k[21] = camellia_half(kah, kal, 94, false);
    c.k[22] = camellia_half(klh, kll, 111, true);
    c.k[23] = camellia_half(klh, kll, 111, false);
    c.kw[2] = camellia_half(kbh, kbl, 111, true);
    c.kw[3] = camellia_half(kbh, kbl, 111, false);
    return c;
}

// One block: the Feistel rounds with FL/FL^-1 every six rounds (RFC 3713
// §2.3); decryption is the same with the subkeys reversed.
fn camellia_crypt(c: const Camellia&, b: const u8[:], decrypt: bool) -> u8[16] {
    assert(b.len == 16);
    let n = c.rounds;
    let nke = n / 3 - 2;
    var w: u64[4] = [c.kw[0], c.kw[1], c.kw[2], c.kw[3]];
    if decrypt { w = [c.kw[2], c.kw[3], c.kw[0], c.kw[1]]; }
    var d1 = camellia_be64(b, 0) ^ w[0];
    var d2 = camellia_be64(b, 8) ^ w[1];
    for r in n / 2 {
        let i1 = if decrypt { n - 1 - 2 * r } else { 2 * r };
        let i2 = if decrypt { n - 2 - 2 * r } else { 2 * r + 1 };
        d2 ^= camellia_f(d1, c.k[i1]);
        d1 ^= camellia_f(d2, c.k[i2]);
        if r % 3 == 2 && r != n / 2 - 1 {
            let j = r / 3;
            let j1 = if decrypt { nke - 1 - 2 * j } else { 2 * j };
            let j2 = if decrypt { nke - 2 - 2 * j } else { 2 * j + 1 };
            d1 = camellia_fl(d1, c.ke[j1]);
            d2 = camellia_flinv(d2, c.ke[j2]);
        }
    }
    d2 ^= w[2];
    d1 ^= w[3];
    var out: u8[16] = [0; 16];
    camellia_put_be64(out, 0, d2);
    camellia_put_be64(out, 8, d1);
    return out;
}

fn camellia_encrypt_block(c: const Camellia&, b: const u8[:]) -> u8[16] { camellia_crypt(c, b, false) }
fn camellia_decrypt_block(c: const Camellia&, b: const u8[:]) -> u8[16] { camellia_crypt(c, b, true) }

// For bignum.modes and bignum.cmac.
fn cipher_block_len(k: const Camellia&) -> i64 { 16 }
fn cipher_encrypt(k: const Camellia&, b: const u8[:]) -> u8[16] { camellia_encrypt_block(k, b) }
fn cipher_decrypt(k: const Camellia&, b: const u8[:]) -> u8[16] { camellia_decrypt_block(k, b) }
