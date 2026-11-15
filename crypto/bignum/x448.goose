// bignum.x448: Diffie-Hellman over Curve448 (RFC 7748), constant time.
//
// A field element of GF(p), p = 2^448 - 2^224 - 1, is sixteen signed limbs
// in radix 2^28. Carried limbs stay within 2^27 (and a few units) of zero,
// so a product of two is below 2^55 and the 38 that at most land on one
// limb after reduction sum below 2^61: everything fits an i64, with no
// wider multiply. Reduction uses p's golden-ratio shape, 2^448 == 2^224 + 1
// (mod p): limb 16 + i folds onto limbs i and 8 + i. Every function runs
// the same operations whatever the values: the ladder takes 448 fixed
// steps and swaps with masks, never a branch on a secret.

namespace bignum;

import std;
import crypto.bignum.ct;
import crypto.bignum.entropy;

struct Fe448 { v: i64[16] }

let FE448_MASK: i64 = (1 << 28) - 1;

fn fe448_zero() -> Fe448 { Fe448 { v: [0; 16] } }

fn fe448_one() -> Fe448 {
    var r = fe448_zero();
    r.v[0] = 1;
    return r;
}

// Brings every limb within 2^27 + 17 of zero, rounding each carry to
// nearest; the carry out of limb 15 is 2^448, which goes back in at limbs
// 0 and 8.
fn fe448_carry(h: Fe448&) {
    for i in 15 {
        let c = (h.v[i] + (1 << 27)) >> 28;
        h.v[i + 1] += c;
        h.v[i] -= c * (1 << 28);
    }
    let c = (h.v[15] + (1 << 27)) >> 28;
    h.v[15] -= c * (1 << 28);
    h.v[0] += c;
    h.v[8] += c;
    let c0 = (h.v[0] + (1 << 27)) >> 28;
    h.v[0] -= c0 * (1 << 28);
    h.v[1] += c0;
    let c8 = (h.v[8] + (1 << 27)) >> 28;
    h.v[8] -= c8 * (1 << 28);
    h.v[9] += c8;
}

// Sums and differences come back carried, so any result can be multiplied.
fn fe448_add(f: Fe448, g: Fe448) -> Fe448 {
    var r = fe448_zero();
    for i in 16 { r.v[i] = f.v[i] + g.v[i]; }
    fe448_carry(r);
    return r;
}

fn fe448_sub(f: Fe448, g: Fe448) -> Fe448 {
    var r = fe448_zero();
    for i in 16 { r.v[i] = f.v[i] - g.v[i]; }
    fe448_carry(r);
    return r;
}

fn fe448_neg(f: Fe448) -> Fe448 { fe448_sub(fe448_zero(), f) }

// h = f * g. Limb k of the 31-limb product is c_k; c_k for k >= 16 is
// c_k 2^448 2^(28 (k - 16)), so it adds to c_(k - 16) and c_(k - 8),
// from the top down so that c_24 to c_30 fold twice. Unrolled, so it
// compiles to straight-line multiplies.
fn fe448_mul(f: Fe448, g: Fe448) -> Fe448 {
    let f0 = f.v[0]; let f1 = f.v[1]; let f2 = f.v[2]; let f3 = f.v[3]; let f4 = f.v[4]; let f5 = f.v[5]; let f6 = f.v[6]; let f7 = f.v[7];
    let f8 = f.v[8]; let f9 = f.v[9]; let f10 = f.v[10]; let f11 = f.v[11]; let f12 = f.v[12]; let f13 = f.v[13]; let f14 = f.v[14]; let f15 = f.v[15];
    let g0 = g.v[0]; let g1 = g.v[1]; let g2 = g.v[2]; let g3 = g.v[3]; let g4 = g.v[4]; let g5 = g.v[5]; let g6 = g.v[6]; let g7 = g.v[7];
    let g8 = g.v[8]; let g9 = g.v[9]; let g10 = g.v[10]; let g11 = g.v[11]; let g12 = g.v[12]; let g13 = g.v[13]; let g14 = g.v[14]; let g15 = g.v[15];
    var c0 = f0 * g0;
    var c1 = f0 * g1 + f1 * g0;
    var c2 = f0 * g2 + f1 * g1 + f2 * g0;
    var c3 = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0;
    var c4 = f0 * g4 + f1 * g3 + f2 * g2 + f3 * g1 + f4 * g0;
    var c5 = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1
        + f5 * g0;
    var c6 = f0 * g6 + f1 * g5 + f2 * g4 + f3 * g3 + f4 * g2
        + f5 * g1 + f6 * g0;
    var c7 = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3
        + f5 * g2 + f6 * g1 + f7 * g0;
    var c8 = f0 * g8 + f1 * g7 + f2 * g6 + f3 * g5 + f4 * g4
        + f5 * g3 + f6 * g2 + f7 * g1 + f8 * g0;
    var c9 = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5
        + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;
    var c10 = f0 * g10 + f1 * g9 + f2 * g8 + f3 * g7 + f4 * g6
        + f5 * g5 + f6 * g4 + f7 * g3 + f8 * g2 + f9 * g1
        + f10 * g0;
    var c11 = f0 * g11 + f1 * g10 + f2 * g9 + f3 * g8 + f4 * g7
        + f5 * g6 + f6 * g5 + f7 * g4 + f8 * g3 + f9 * g2
        + f10 * g1 + f11 * g0;
    var c12 = f0 * g12 + f1 * g11 + f2 * g10 + f3 * g9 + f4 * g8
        + f5 * g7 + f6 * g6 + f7 * g5 + f8 * g4 + f9 * g3
        + f10 * g2 + f11 * g1 + f12 * g0;
    var c13 = f0 * g13 + f1 * g12 + f2 * g11 + f3 * g10 + f4 * g9
        + f5 * g8 + f6 * g7 + f7 * g6 + f8 * g5 + f9 * g4
        + f10 * g3 + f11 * g2 + f12 * g1 + f13 * g0;
    var c14 = f0 * g14 + f1 * g13 + f2 * g12 + f3 * g11 + f4 * g10
        + f5 * g9 + f6 * g8 + f7 * g7 + f8 * g6 + f9 * g5
        + f10 * g4 + f11 * g3 + f12 * g2 + f13 * g1 + f14 * g0;
    var c15 = f0 * g15 + f1 * g14 + f2 * g13 + f3 * g12 + f4 * g11
        + f5 * g10 + f6 * g9 + f7 * g8 + f8 * g7 + f9 * g6
        + f10 * g5 + f11 * g4 + f12 * g3 + f13 * g2 + f14 * g1
        + f15 * g0;
    var c16 = f1 * g15 + f2 * g14 + f3 * g13 + f4 * g12 + f5 * g11
        + f6 * g10 + f7 * g9 + f8 * g8 + f9 * g7 + f10 * g6
        + f11 * g5 + f12 * g4 + f13 * g3 + f14 * g2 + f15 * g1;
    var c17 = f2 * g15 + f3 * g14 + f4 * g13 + f5 * g12 + f6 * g11
        + f7 * g10 + f8 * g9 + f9 * g8 + f10 * g7 + f11 * g6
        + f12 * g5 + f13 * g4 + f14 * g3 + f15 * g2;
    var c18 = f3 * g15 + f4 * g14 + f5 * g13 + f6 * g12 + f7 * g11
        + f8 * g10 + f9 * g9 + f10 * g8 + f11 * g7 + f12 * g6
        + f13 * g5 + f14 * g4 + f15 * g3;
    var c19 = f4 * g15 + f5 * g14 + f6 * g13 + f7 * g12 + f8 * g11
        + f9 * g10 + f10 * g9 + f11 * g8 + f12 * g7 + f13 * g6
        + f14 * g5 + f15 * g4;
    var c20 = f5 * g15 + f6 * g14 + f7 * g13 + f8 * g12 + f9 * g11
        + f10 * g10 + f11 * g9 + f12 * g8 + f13 * g7 + f14 * g6
        + f15 * g5;
    var c21 = f6 * g15 + f7 * g14 + f8 * g13 + f9 * g12 + f10 * g11
        + f11 * g10 + f12 * g9 + f13 * g8 + f14 * g7 + f15 * g6;
    var c22 = f7 * g15 + f8 * g14 + f9 * g13 + f10 * g12 + f11 * g11
        + f12 * g10 + f13 * g9 + f14 * g8 + f15 * g7;
    let c23 = f8 * g15 + f9 * g14 + f10 * g13 + f11 * g12 + f12 * g11
        + f13 * g10 + f14 * g9 + f15 * g8;
    let c24 = f9 * g15 + f10 * g14 + f11 * g13 + f12 * g12 + f13 * g11
        + f14 * g10 + f15 * g9;
    let c25 = f10 * g15 + f11 * g14 + f12 * g13 + f13 * g12 + f14 * g11
        + f15 * g10;
    let c26 = f11 * g15 + f12 * g14 + f13 * g13 + f14 * g12 + f15 * g11;
    let c27 = f12 * g15 + f13 * g14 + f14 * g13 + f15 * g12;
    let c28 = f13 * g15 + f14 * g14 + f15 * g13;
    let c29 = f14 * g15 + f15 * g14;
    let c30 = f15 * g15;
    c14 += c30; c22 += c30;
    c13 += c29; c21 += c29;
    c12 += c28; c20 += c28;
    c11 += c27; c19 += c27;
    c10 += c26; c18 += c26;
    c9 += c25; c17 += c25;
    c8 += c24; c16 += c24;
    c7 += c23; c15 += c23;
    c6 += c22; c14 += c22;
    c5 += c21; c13 += c21;
    c4 += c20; c12 += c20;
    c3 += c19; c11 += c19;
    c2 += c18; c10 += c18;
    c1 += c17; c9 += c17;
    c0 += c16; c8 += c16;
    var h = fe448_zero();
    h.v[0] = c0; h.v[1] = c1; h.v[2] = c2; h.v[3] = c3; h.v[4] = c4; h.v[5] = c5; h.v[6] = c6; h.v[7] = c7;
    h.v[8] = c8; h.v[9] = c9; h.v[10] = c10; h.v[11] = c11; h.v[12] = c12; h.v[13] = c13; h.v[14] = c14; h.v[15] = c15;
    fe448_carry(h);
    return h;
}

// f * f, with the symmetric products counted once and doubled.
fn fe448_sq(f: Fe448) -> Fe448 {
    let f0 = f.v[0]; let f1 = f.v[1]; let f2 = f.v[2]; let f3 = f.v[3]; let f4 = f.v[4]; let f5 = f.v[5]; let f6 = f.v[6]; let f7 = f.v[7];
    let f8 = f.v[8]; let f9 = f.v[9]; let f10 = f.v[10]; let f11 = f.v[11]; let f12 = f.v[12]; let f13 = f.v[13]; let f14 = f.v[14]; let f15 = f.v[15];
    let f0_2 = 2 * f0; let f1_2 = 2 * f1; let f2_2 = 2 * f2; let f3_2 = 2 * f3; let f4_2 = 2 * f4; let f5_2 = 2 * f5; let f6_2 = 2 * f6; let f7_2 = 2 * f7;
    let f8_2 = 2 * f8; let f9_2 = 2 * f9; let f10_2 = 2 * f10; let f11_2 = 2 * f11; let f12_2 = 2 * f12; let f13_2 = 2 * f13; let f14_2 = 2 * f14;
    var c0 = f0 * f0;
    var c1 = f0_2 * f1;
    var c2 = f0_2 * f2 + f1 * f1;
    var c3 = f0_2 * f3 + f1_2 * f2;
    var c4 = f0_2 * f4 + f1_2 * f3 + f2 * f2;
    var c5 = f0_2 * f5 + f1_2 * f4 + f2_2 * f3;
    var c6 = f0_2 * f6 + f1_2 * f5 + f2_2 * f4 + f3 * f3;
    var c7 = f0_2 * f7 + f1_2 * f6 + f2_2 * f5 + f3_2 * f4;
    var c8 = f0_2 * f8 + f1_2 * f7 + f2_2 * f6 + f3_2 * f5 + f4 * f4;
    var c9 = f0_2 * f9 + f1_2 * f8 + f2_2 * f7 + f3_2 * f6 + f4_2 * f5;
    var c10 = f0_2 * f10 + f1_2 * f9 + f2_2 * f8 + f3_2 * f7 + f4_2 * f6
        + f5 * f5;
    var c11 = f0_2 * f11 + f1_2 * f10 + f2_2 * f9 + f3_2 * f8 + f4_2 * f7
        + f5_2 * f6;
    var c12 = f0_2 * f12 + f1_2 * f11 + f2_2 * f10 + f3_2 * f9 + f4_2 * f8
        + f5_2 * f7 + f6 * f6;
    var c13 = f0_2 * f13 + f1_2 * f12 + f2_2 * f11 + f3_2 * f10 + f4_2 * f9
        + f5_2 * f8 + f6_2 * f7;
    var c14 = f0_2 * f14 + f1_2 * f13 + f2_2 * f12 + f3_2 * f11 + f4_2 * f10
        + f5_2 * f9 + f6_2 * f8 + f7 * f7;
    var c15 = f0_2 * f15 + f1_2 * f14 + f2_2 * f13 + f3_2 * f12 + f4_2 * f11
        + f5_2 * f10 + f6_2 * f9 + f7_2 * f8;
    var c16 = f1_2 * f15 + f2_2 * f14 + f3_2 * f13 + f4_2 * f12 + f5_2 * f11
        + f6_2 * f10 + f7_2 * f9 + f8 * f8;
    var c17 = f2_2 * f15 + f3_2 * f14 + f4_2 * f13 + f5_2 * f12 + f6_2 * f11
        + f7_2 * f10 + f8_2 * f9;
    var c18 = f3_2 * f15 + f4_2 * f14 + f5_2 * f13 + f6_2 * f12 + f7_2 * f11
        + f8_2 * f10 + f9 * f9;
    var c19 = f4_2 * f15 + f5_2 * f14 + f6_2 * f13 + f7_2 * f12 + f8_2 * f11
        + f9_2 * f10;
    var c20 = f5_2 * f15 + f6_2 * f14 + f7_2 * f13 + f8_2 * f12 + f9_2 * f11
        + f10 * f10;
    var c21 = f6_2 * f15 + f7_2 * f14 + f8_2 * f13 + f9_2 * f12 + f10_2 * f11;
    var c22 = f7_2 * f15 + f8_2 * f14 + f9_2 * f13 + f10_2 * f12 + f11 * f11;
    let c23 = f8_2 * f15 + f9_2 * f14 + f10_2 * f13 + f11_2 * f12;
    let c24 = f9_2 * f15 + f10_2 * f14 + f11_2 * f13 + f12 * f12;
    let c25 = f10_2 * f15 + f11_2 * f14 + f12_2 * f13;
    let c26 = f11_2 * f15 + f12_2 * f14 + f13 * f13;
    let c27 = f12_2 * f15 + f13_2 * f14;
    let c28 = f13_2 * f15 + f14 * f14;
    let c29 = f14_2 * f15;
    let c30 = f15 * f15;
    c14 += c30; c22 += c30;
    c13 += c29; c21 += c29;
    c12 += c28; c20 += c28;
    c11 += c27; c19 += c27;
    c10 += c26; c18 += c26;
    c9 += c25; c17 += c25;
    c8 += c24; c16 += c24;
    c7 += c23; c15 += c23;
    c6 += c22; c14 += c22;
    c5 += c21; c13 += c21;
    c4 += c20; c12 += c20;
    c3 += c19; c11 += c19;
    c2 += c18; c10 += c18;
    c1 += c17; c9 += c17;
    c0 += c16; c8 += c16;
    var h = fe448_zero();
    h.v[0] = c0; h.v[1] = c1; h.v[2] = c2; h.v[3] = c3; h.v[4] = c4; h.v[5] = c5; h.v[6] = c6; h.v[7] = c7;
    h.v[8] = c8; h.v[9] = c9; h.v[10] = c10; h.v[11] = c11; h.v[12] = c12; h.v[13] = c13; h.v[14] = c14; h.v[15] = c15;
    fe448_carry(h);
    return h;
}

// f^(2^n)
fn fe448_sqn(f: Fe448, n: i64) -> Fe448 {
    var r = f;
    for i in n { r = fe448_sq(r); }
    return r;
}

// f * k for a small k (|k| < 2^20), such as the curve constant 39081.
fn fe448_mul_small(f: Fe448, k: i64) -> Fe448 {
    var h = fe448_zero();
    for i in 16 { h.v[i] = f.v[i] * k; }
    fe448_carry(h);
    return h;
}

// z^((p - 3) / 4) = z^(2^446 - 2^222 - 1), the square root's exponent
// (p is 3 mod 4). x_n below is z^(2^n - 1).
fn fe448_pow_p34(z: Fe448) -> Fe448 {
    let x2 = fe448_mul(fe448_sq(z), z);
    let x3 = fe448_mul(fe448_sq(x2), z);
    let x6 = fe448_mul(fe448_sqn(x3, 3), x3);
    let x12 = fe448_mul(fe448_sqn(x6, 6), x6);
    let x24 = fe448_mul(fe448_sqn(x12, 12), x12);
    let x30 = fe448_mul(fe448_sqn(x24, 6), x6);
    let x48 = fe448_mul(fe448_sqn(x24, 24), x24);
    let x96 = fe448_mul(fe448_sqn(x48, 48), x48);
    let x192 = fe448_mul(fe448_sqn(x96, 96), x96);
    let x222 = fe448_mul(fe448_sqn(x192, 30), x30);
    let x223 = fe448_mul(fe448_sq(x222), z);
    return fe448_mul(fe448_sqn(x223, 223), x222);       // (2^223 - 1) 2^223 + 2^222 - 1
}

// z^(p - 2) == 1/z (and 0 for 0): 4 (p - 3) / 4 + 1.
fn fe448_invert(z: Fe448) -> Fe448 { fe448_mul(fe448_sqn(fe448_pow_p34(z), 2), z) }

// Swaps f and g when bit is 1.
fn fe448_cswap(f: Fe448&, g: Fe448&, bit: i64) {
    let mask = 0 - bit;
    for i in 16 {
        let t = mask & (f.v[i] ^ g.v[i]);
        f.v[i] ^= t;
        g.v[i] ^= t;
    }
}

// mask ? f : g, with mask 0 or -1.
fn fe448_select(f: Fe448, g: Fe448, mask: i64) -> Fe448 {
    var r = g;
    for i in 16 { r.v[i] = g.v[i] ^ (mask & (f.v[i] ^ g.v[i])); }
    return r;
}

// 56 little-endian bytes, every bit used: a value up to 2^448 - 1, which
// may be p or more (RFC 7748 §5 takes such u mod p).
fn fe448_from_bytes(s: const u8[:]) -> Fe448 {
    assert(s.len == 56);
    var h = fe448_zero();
    for i in 8 {
        var x: u64 = 0;
        for k in 7 { x = x | (s[7 * i + k] as u64) << (8 * k); }
        h.v[2 * i] = (x & 0xfffffff) as! i64;
        h.v[2 * i + 1] = (x >> 28) as! i64;
    }
    fe448_carry(h);
    return h;
}

// The canonical encoding, fully reduced into [0, p).
fn fe448_to_bytes(f: Fe448) -> u8[56] {
    var h = f;
    fe448_carry(h);
    // |h| < 2^448 < 2p, so h + 2p is positive and below 4p. 2p in limbs:
    // 2^29 - 2 each, 2^29 - 4 at limb 8.
    for i in 16 { h.v[i] += (1 << 29) - 2; }
    h.v[8] -= 2;
    // Three passes of carries, each putting what leaves limb 15 back at
    // limbs 0 and 8, leave h below 2^448 in 28-bit limbs: the second
    // carries out at most 1, and then h is small enough that the third
    // carries out nothing.
    for pass in 3 {
        for i in 15 {
            h.v[i + 1] += h.v[i] >> 28;
            h.v[i] = h.v[i] & FE448_MASK;
        }
        let c = h.v[15] >> 28;
        h.v[15] = h.v[15] & FE448_MASK;
        h.v[0] += c;
        h.v[8] += c;
    }
    // h < 2^448 < 2p: subtract p once unless that borrows.
    var t = fe448_zero();
    var borrow: i64 = 0;
    for i in 16 {
        let pi = if i == 8 { FE448_MASK - 1 } else { FE448_MASK };
        let d = h.v[i] - pi - borrow;
        borrow = 0 - (d >> 28);                      // 1 when d < 0
        t.v[i] = d & FE448_MASK;
    }
    h = fe448_select(h, t, 0 - borrow);
    var out: u8[56] = [0; 56];
    for i in 8 {
        let x = (h.v[2 * i] as! u64) | (h.v[2 * i + 1] as! u64) << 28;
        for k in 7 { out[7 * i + k] = (x >> (8 * k)) as! u8; }
    }
    return out;
}

// The X448 function: scalar times the point with u-coordinate u.
fn x448(scalar: const u8[:], u: const u8[:]) -> u8[56] {
    assert(scalar.len == 56 && u.len == 56);
    var k: u8[56] = [0; 56];
    for i in 56 { k[i] = scalar[i]; }
    k[0] = k[0] & 252;
    k[55] = k[55] | 128;

    let x1 = fe448_from_bytes(u);
    var x2 = fe448_one();
    var z2 = fe448_zero();
    var x3 = x1;
    var z3 = fe448_one();
    var swap = 0;
    var t = 448;
    while t > 0 {
        t--;
        let bit: i64 = (k[t / 8] >> (t % 8)) & 1;
        swap ^= bit;
        fe448_cswap(x2, x3, swap);
        fe448_cswap(z2, z3, swap);
        swap = bit;
        let a = fe448_add(x2, z2);
        let aa = fe448_sq(a);
        let b = fe448_sub(x2, z2);
        let bb = fe448_sq(b);
        let e = fe448_sub(aa, bb);
        let c = fe448_add(x3, z3);
        let d = fe448_sub(x3, z3);
        let da = fe448_mul(d, a);
        let cb = fe448_mul(c, b);
        x3 = fe448_sq(fe448_add(da, cb));
        z3 = fe448_mul(x1, fe448_sq(fe448_sub(da, cb)));
        x2 = fe448_mul(aa, bb);
        z2 = fe448_mul(e, fe448_add(aa, fe448_mul_small(e, 39081)));
    }
    fe448_cswap(x2, x3, swap);
    fe448_cswap(z2, z3, swap);
    return fe448_to_bytes(fe448_mul(x2, fe448_invert(z2)));
}

// The public key for a private scalar: scalar times the base point u = 5.
fn x448_base(scalar: const u8[:]) -> u8[56] {
    var five: u8[56] = [0; 56];
    five[0] = 5;
    return x448(scalar, five);
}

// A fresh key pair from the OS's entropy: private, public.
fn x448_keypair() -> u8[56], u8[56] {
    var sk: u8[56] = [0; 56];
    random_bytes(sk);
    return sk, x448_base(sk);
}

// The shared secret of a key exchange, and whether it is usable: an
// all-zero result means the peer sent a low-order point (RFC 7748 §6.2),
// and a protocol must then abort.
fn x448_shared(sk: const u8[:], peer: const u8[:]) -> u8[56], bool {
    let s = x448(sk, peer);
    let zero: u8[56] = [0; 56];
    return s, ct_eq_bytes(s, zero) == 0;
}
