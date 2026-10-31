// bignum.x25519: Diffie-Hellman over Curve25519 (RFC 7748), constant time.
//
// A field element of GF(2^255 - 19) is ten signed limbs in radix 2^25.5
// (alternately 26 and 25 bits, as in the ref10 implementation), so a limb
// product fits in an i64 with room for the sums. Every function runs the
// same operations whatever the values: the ladder takes 255 fixed steps
// and swaps with masks, never a branch on a secret.

namespace bignum;

import std;
import ct;
import entropy;

struct Fe { v: i64[10] }

// Limb i holds bits [FE_OFF[i], FE_OFF[i] + FE_W[i]).
let FE_W: i64[10] = [26, 25, 26, 25, 26, 25, 26, 25, 26, 25];
let FE_OFF: i64[10] = [0, 26, 51, 77, 102, 128, 153, 179, 204, 230];

fn fe_zero() -> Fe { Fe { v: [0; 10] } }

fn fe_one() -> Fe {
    var r = fe_zero();
    r.v[0] = 1;
    return r;
}

fn fe_small(x: i64) -> Fe {
    var r = fe_zero();
    r.v[0] = x;
    return r;
}

fn fe_add(f: Fe, g: Fe) -> Fe {
    var r = fe_zero();
    for i in 10 { r.v[i] = f.v[i] + g.v[i]; }
    return r;
}

fn fe_sub(f: Fe, g: Fe) -> Fe {
    var r = fe_zero();
    for i in 10 { r.v[i] = f.v[i] - g.v[i]; }
    return r;
}

// Brings every limb back within its width (give or take a few bits), so
// the result can be multiplied again. The carries round to nearest.
fn fe_carry(h: Fe&) {
    for i in 9 {
        let w = FE_W[i];
        let c = (h.v[i] + (1 << (w - 1))) >> w;
        h.v[i + 1] += c;
        h.v[i] -= c * (1 << w);
    }
    let c9 = (h.v[9] + (1 << 24)) >> 25;
    h.v[0] += c9 * 19;                       // 2^255 == 19 (mod p)
    h.v[9] -= c9 * (1 << 25);
    let c0 = (h.v[0] + (1 << 25)) >> 26;
    h.v[1] += c0;
    h.v[0] -= c0 * (1 << 26);
}

// h = f * g: limb i + j collects f[i] * g[j], wrapping past limb 9 as a
// factor 19 (2^255 == 19), and doubled when both limbs are odd, since
// those sit half a bit short of their product's weight. Unrolled as in
// ref10, so it compiles to straight-line multiplies.
fn fe_mul(f: Fe, g: Fe) -> Fe {
    let f0 = f.v[0]; let f1 = f.v[1]; let f2 = f.v[2]; let f3 = f.v[3]; let f4 = f.v[4];
    let f5 = f.v[5]; let f6 = f.v[6]; let f7 = f.v[7]; let f8 = f.v[8]; let f9 = f.v[9];
    let g0 = g.v[0]; let g1 = g.v[1]; let g2 = g.v[2]; let g3 = g.v[3]; let g4 = g.v[4];
    let g5 = g.v[5]; let g6 = g.v[6]; let g7 = g.v[7]; let g8 = g.v[8]; let g9 = g.v[9];
    var h = fe_zero();
    h.v[0] = f0 * g0 + 38 * f1 * g9 + 19 * f2 * g8 + 38 * f3 * g7 + 19 * f4 * g6
           + 38 * f5 * g5 + 19 * f6 * g4 + 38 * f7 * g3 + 19 * f8 * g2 + 38 * f9 * g1;
    h.v[1] = f0 * g1 + f1 * g0 + 19 * f2 * g9 + 19 * f3 * g8 + 19 * f4 * g7
           + 19 * f5 * g6 + 19 * f6 * g5 + 19 * f7 * g4 + 19 * f8 * g3 + 19 * f9 * g2;
    h.v[2] = f0 * g2 + 2 * f1 * g1 + f2 * g0 + 38 * f3 * g9 + 19 * f4 * g8
           + 38 * f5 * g7 + 19 * f6 * g6 + 38 * f7 * g5 + 19 * f8 * g4 + 38 * f9 * g3;
    h.v[3] = f0 * g3 + f1 * g2 + f2 * g1 + f3 * g0 + 19 * f4 * g9
           + 19 * f5 * g8 + 19 * f6 * g7 + 19 * f7 * g6 + 19 * f8 * g5 + 19 * f9 * g4;
    h.v[4] = f0 * g4 + 2 * f1 * g3 + f2 * g2 + 2 * f3 * g1 + f4 * g0
           + 38 * f5 * g9 + 19 * f6 * g8 + 38 * f7 * g7 + 19 * f8 * g6 + 38 * f9 * g5;
    h.v[5] = f0 * g5 + f1 * g4 + f2 * g3 + f3 * g2 + f4 * g1
           + f5 * g0 + 19 * f6 * g9 + 19 * f7 * g8 + 19 * f8 * g7 + 19 * f9 * g6;
    h.v[6] = f0 * g6 + 2 * f1 * g5 + f2 * g4 + 2 * f3 * g3 + f4 * g2
           + 2 * f5 * g1 + f6 * g0 + 38 * f7 * g9 + 19 * f8 * g8 + 38 * f9 * g7;
    h.v[7] = f0 * g7 + f1 * g6 + f2 * g5 + f3 * g4 + f4 * g3
           + f5 * g2 + f6 * g1 + f7 * g0 + 19 * f8 * g9 + 19 * f9 * g8;
    h.v[8] = f0 * g8 + 2 * f1 * g7 + f2 * g6 + 2 * f3 * g5 + f4 * g4
           + 2 * f5 * g3 + f6 * g2 + 2 * f7 * g1 + f8 * g0 + 38 * f9 * g9;
    h.v[9] = f0 * g9 + f1 * g8 + f2 * g7 + f3 * g6 + f4 * g5
           + f5 * g4 + f6 * g3 + f7 * g2 + f8 * g1 + f9 * g0;
    fe_carry(h);
    return h;
}

// f * f, with the symmetric products counted once and doubled.
fn fe_sq(f: Fe) -> Fe {
    let f0 = f.v[0]; let f1 = f.v[1]; let f2 = f.v[2]; let f3 = f.v[3]; let f4 = f.v[4];
    let f5 = f.v[5]; let f6 = f.v[6]; let f7 = f.v[7]; let f8 = f.v[8]; let f9 = f.v[9];
    var h = fe_zero();
    h.v[0] = f0 * f0 + 76 * f1 * f9 + 38 * f2 * f8 + 76 * f3 * f7 + 38 * f4 * f6 + 38 * f5 * f5;
    h.v[1] = 2 * f0 * f1 + 38 * f2 * f9 + 38 * f3 * f8 + 38 * f4 * f7 + 38 * f5 * f6;
    h.v[2] = 2 * f0 * f2 + 2 * f1 * f1 + 76 * f3 * f9 + 38 * f4 * f8 + 76 * f5 * f7 + 19 * f6 * f6;
    h.v[3] = 2 * f0 * f3 + 2 * f1 * f2 + 38 * f4 * f9 + 38 * f5 * f8 + 38 * f6 * f7;
    h.v[4] = 2 * f0 * f4 + 4 * f1 * f3 + f2 * f2 + 76 * f5 * f9 + 38 * f6 * f8 + 38 * f7 * f7;
    h.v[5] = 2 * f0 * f5 + 2 * f1 * f4 + 2 * f2 * f3 + 38 * f6 * f9 + 38 * f7 * f8;
    h.v[6] = 2 * f0 * f6 + 4 * f1 * f5 + 2 * f2 * f4 + 2 * f3 * f3 + 76 * f7 * f9 + 19 * f8 * f8;
    h.v[7] = 2 * f0 * f7 + 2 * f1 * f6 + 2 * f2 * f5 + 2 * f3 * f4 + 38 * f8 * f9;
    h.v[8] = 2 * f0 * f8 + 4 * f1 * f7 + 2 * f2 * f6 + 4 * f3 * f5 + f4 * f4 + 38 * f9 * f9;
    h.v[9] = 2 * f0 * f9 + 2 * f1 * f8 + 2 * f2 * f7 + 2 * f3 * f6 + 2 * f4 * f5;
    fe_carry(h);
    return h;
}

// f^(2^n)
fn fe_sqn(f: Fe, n: i64) -> Fe {
    var r = f;
    for i in n { r = fe_sq(r); }
    return r;
}

// f * 121665, the curve constant (A - 2) / 4.
fn fe_mul_a24(f: Fe) -> Fe {
    var h = fe_zero();
    for i in 10 { h.v[i] = f.v[i] * 121665; }
    fe_carry(h);
    return h;
}

// f^(p - 2) == 1/f (and 0 for 0), by the ref10 addition chain.
fn fe_invert(z: Fe) -> Fe {
    let z2 = fe_sq(z);                                   // 2
    let z9 = fe_mul(z, fe_sqn(z2, 2));                   // 9
    let z11 = fe_mul(z2, z9);                            // 11
    let z_5 = fe_mul(z9, fe_sq(z11));                    // 2^5 - 1
    let z_10 = fe_mul(fe_sqn(z_5, 5), z_5);              // 2^10 - 1
    let z_20 = fe_mul(fe_sqn(z_10, 10), z_10);           // 2^20 - 1
    let z_40 = fe_mul(fe_sqn(z_20, 20), z_20);           // 2^40 - 1
    let z_50 = fe_mul(fe_sqn(z_40, 10), z_10);           // 2^50 - 1
    let z_100 = fe_mul(fe_sqn(z_50, 50), z_50);          // 2^100 - 1
    let z_200 = fe_mul(fe_sqn(z_100, 100), z_100);       // 2^200 - 1
    let z_250 = fe_mul(fe_sqn(z_200, 50), z_50);         // 2^250 - 1
    return fe_mul(fe_sqn(z_250, 5), z11);                // 2^255 - 21 == p - 2
}

// Swaps f and g when bit is 1.
fn fe_cswap(f: Fe&, g: Fe&, bit: i64) {
    let mask = 0 - bit;
    for i in 10 {
        let t = mask & (f.v[i] ^ g.v[i]);
        f.v[i] ^= t;
        g.v[i] ^= t;
    }
}

// 32 little-endian bytes, the top bit ignored (RFC 7748 §5).
fn fe_from_bytes(s: const u8[:]) -> Fe {
    assert(s.len == 32);
    var h = fe_zero();
    for i in 10 {
        let off = FE_OFF[i];
        var x: u64 = 0;
        for k in 5 {
            let idx = off / 8 + k;
            if idx < 32 { x = x | (s[idx] as u64) << (8 * k); }
        }
        h.v[i] = ((x >> (off % 8)) & ((1 << FE_W[i]) - 1)) as! i64;
    }
    return h;
}

// The canonical encoding, fully reduced into [0, p).
fn fe_to_bytes(f: Fe) -> u8[32] {
    var h = f;
    fe_carry(h);
    // q = 1 when h >= p, computed through the carry of h + 19.
    var q = (19 * h.v[9] + (1 << 24)) >> 25;
    for i in 10 { q = (h.v[i] + q) >> FE_W[i]; }
    h.v[0] += 19 * q;
    for i in 9 {
        let w = FE_W[i];
        let c = h.v[i] >> w;
        h.v[i + 1] += c;
        h.v[i] -= c * (1 << w);
    }
    h.v[9] = h.v[9] & ((1 << 25) - 1);       // drop 2^255, which q already took off
    var out: u8[32] = [0; 32];
    var acc: u64 = 0;
    var nbits = 0;
    var o = 0;
    for i in 10 {
        acc = acc | (h.v[i] as! u64) << nbits;
        nbits += FE_W[i];
        while nbits >= 8 {
            out[o] = (acc & 255) as! u8;
            acc = acc >> 8;
            nbits -= 8;
            o++;
        }
    }
    out[o] = (acc & 255) as! u8;
    return out;
}

// The X25519 function: scalar times the point with u-coordinate u.
fn x25519(scalar: const u8[:], u: const u8[:]) -> u8[32] {
    assert(scalar.len == 32 && u.len == 32);
    var k: u8[32] = [0; 32];
    for i in 32 { k[i] = scalar[i]; }
    k[0] = k[0] & 248;
    k[31] = (k[31] & 127) | 64;

    let x1 = fe_from_bytes(u);
    var x2 = fe_one();
    var z2 = fe_zero();
    var x3 = x1;
    var z3 = fe_one();
    var swap = 0;
    var t = 255;
    while t > 0 {
        t--;
        let bit: i64 = (k[t / 8] >> (t % 8)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;
        let a = fe_add(x2, z2);
        let aa = fe_sq(a);
        let b = fe_sub(x2, z2);
        let bb = fe_sq(b);
        let e = fe_sub(aa, bb);
        let c = fe_add(x3, z3);
        let d = fe_sub(x3, z3);
        let da = fe_mul(d, a);
        let cb = fe_mul(c, b);
        x3 = fe_sq(fe_add(da, cb));
        z3 = fe_mul(x1, fe_sq(fe_sub(da, cb)));
        x2 = fe_mul(aa, bb);
        z2 = fe_mul(e, fe_add(aa, fe_mul_a24(e)));
    }
    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);
    return fe_to_bytes(fe_mul(x2, fe_invert(z2)));
}

// The public key for a private scalar: scalar times the base point u = 9.
fn x25519_base(scalar: const u8[:]) -> u8[32] {
    var nine: u8[32] = [0; 32];
    nine[0] = 9;
    return x25519(scalar, nine);
}

// A fresh key pair from the OS's entropy: private, public.
fn x25519_keypair() -> u8[32], u8[32] {
    var sk: u8[32] = [0; 32];
    random_bytes(sk);
    return sk, x25519_base(sk);
}

// The shared secret of a key exchange, and whether it is usable: an
// all-zero result means the peer sent a low-order point (RFC 7748 §6.1),
// and a protocol must then abort.
fn x25519_shared(sk: const u8[:], peer: const u8[:]) -> u8[32], bool {
    let s = x25519(sk, peer);
    let zero: u8[32] = [0; 32];
    return s, ct_eq_bytes(s, zero) == 0;
}
