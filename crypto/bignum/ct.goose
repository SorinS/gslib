// bignum.ct: constant-time building blocks over fixed-width limb slices.
//
// Nothing here branches on, or indexes by, the values it is given: only
// on lengths, which are public. A mask is 0 or 0xffffffff, and a "bit" is
// 0 or 1. Slices are little-endian u32 limbs, as in BigInt. These are the
// pieces a constant-time modular layer is built from; the C compiler can
// still undo them, so check the generated code (goose -o out.c) of
// anything that matters.

namespace bignum;

import std;

// 0 -> 0, 1 -> 0xffffffff.
fn ct_mask(bit: u32) -> u32 { 0 - (bit & 1) }

// 1 if x == 0, else 0.
fn ct_is_zero_u32(x: u32) -> u32 { ((x | (0 - x)) >> 31) ^ 1 }

// 1 if a == b, else 0.
fn ct_eq_u32(a: u32, b: u32) -> u32 { ct_is_zero_u32(a ^ b) }

// 1 if a < b, else 0.
fn ct_lt_u32(a: u32, b: u32) -> u32 { (a ^ ((a ^ b) | ((a - b) ^ b))) >> 31 }

// mask ? a : b
fn ct_select_u32(mask: u32, a: u32, b: u32) -> u32 { b ^ (mask & (a ^ b)) }

// dst = mask ? a : b, limb by limb.
fn ct_select(dst: u32[:], mask: u32, a: const u32[:], b: const u32[:]) {
    assert(dst.len == a.len && dst.len == b.len);
    for i in dst.len { dst[i] = b[i] ^ (mask & (a[i] ^ b[i])); }
}

// Swaps a and b when mask is all ones.
fn ct_cswap(mask: u32, a: u32[:], b: u32[:]) {
    assert(a.len == b.len);
    for i in a.len {
        let t = mask & (a[i] ^ b[i]);
        a[i] = a[i] ^ t;
        b[i] = b[i] ^ t;
    }
}

// 1 if every limb of a is zero, else 0.
fn ct_is_zero(a: const u32[:]) -> u32 {
    var acc: u32 = 0;
    for x in a { acc = acc | x; }
    return ct_is_zero_u32(acc);
}

// 1 if a == b, else 0; no early exit.
fn ct_eq(a: const u32[:], b: const u32[:]) -> u32 {
    assert(a.len == b.len);
    var acc: u32 = 0;
    for i in a.len { acc = acc | (a[i] ^ b[i]); }
    return ct_is_zero_u32(acc);
}

// 1 if the byte strings are equal, else 0: for comparing MACs and tags.
fn ct_eq_bytes(a: const u8[:], b: const u8[:]) -> u32 {
    assert(a.len == b.len);
    var acc: u8 = 0;
    for i in a.len { acc = acc | (a[i] ^ b[i]); }
    return ct_is_zero_u32(acc);
}

// r = a + b over the common width, returning the carry (0 or 1).
fn ct_add(r: u32[:], a: const u32[:], b: const u32[:]) -> u32 {
    assert(r.len == a.len && r.len == b.len);
    var carry: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let t = ai + b[i] + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
    return carry as! u32;
}

// r = a - b over the common width, returning the borrow (0 or 1).
fn ct_sub(r: u32[:], a: const u32[:], b: const u32[:]) -> u32 {
    assert(r.len == a.len && r.len == b.len);
    var borrow: u64 = 0;
    for i in r.len {
        let ai: u64 = a[i];
        let t = ai - b[i] - borrow;
        r[i] = t as! u32;
        borrow = t >> 63;
    }
    return borrow as! u32;
}

// 1 if a < b as numbers of the same width, else 0.
fn ct_lt(a: const u32[:], b: const u32[:]) -> u32 {
    assert(a.len == b.len);
    var borrow: u64 = 0;
    for i in a.len {
        let ai: u64 = a[i];
        let t = ai - b[i] - borrow;
        borrow = t >> 63;
    }
    return borrow as! u32;
}

// r = r - m when r >= m, else r unchanged, in the same time either way.
// `hi` is a carry limb above r (0 or 1), as an addition leaves one.
fn ct_cond_sub(r: u32[:], hi: u32, m: const u32[:]) {
    assert(r.len == m.len);
    // Subtract unconditionally, then keep the difference unless it borrowed
    // past hi.
    var borrow: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - m[i] - borrow;
        borrow = t >> 63;
    }
    let keep = ct_mask(ct_lt_u32(hi, borrow as! u32));   // hi:r < m: keep r
    borrow = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - m[i] - borrow;
        borrow = t >> 63;
        r[i] = ct_select_u32(keep, r[i], t as! u32);
    }
}

// r = (a + b) mod m, for a, b < m, all of one width.
fn ct_mod_add(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:]) {
    let c = ct_add(r, a, b);
    ct_cond_sub(r, c, m);
}

// r = (a - b) mod m, for a, b < m, all of one width.
fn ct_mod_sub(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:]) {
    let borrow = ct_sub(r, a, b);
    // Add m back when the subtraction went below zero.
    let mask = ct_mask(borrow);
    var carry: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri + (m[i] & mask) + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
}

// 1 if a == 1, else 0.
fn ct_is_one(a: const u32[:]) -> u32 {
    var acc: u32 = a[0] ^ 1;
    for i in 1..a.len { acc = acc | a[i]; }
    return ct_is_zero_u32(acc);
}

// r = r - (b & mask), returning the borrow.
fn ct_sub_masked(r: u32[:], b: const u32[:], mask: u32) -> u32 {
    assert(r.len == b.len);
    var borrow: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri - (b[i] & mask) - borrow;
        r[i] = t as! u32;
        borrow = t >> 63;
    }
    return borrow as! u32;
}

// r = r + (b & mask), returning the carry.
fn ct_add_masked(r: u32[:], b: const u32[:], mask: u32) -> u32 {
    assert(r.len == b.len);
    var carry: u64 = 0;
    for i in r.len {
        let ri: u64 = r[i];
        let t = ri + (b[i] & mask) + carry;
        r[i] = t as! u32;
        carry = t >> 32;
    }
    return carry as! u32;
}

// r = r >> 1.
fn ct_shr1(r: u32[:]) {
    for i in r.len {
        let hi: u32 = if i + 1 < r.len { r[i + 1] << 31 } else { 0 };
        r[i] = (r[i] >> 1) | hi;
    }
}

// a mod d for a public 2 <= d < 2^16, with no division of secret data:
// each step's quotient comes from a multiply by floor(2^32 / d), one short
// at most, and a masked subtraction makes up for it. (A division
// instruction's time can depend on its operands.)
fn ct_mod_small(a: const u32[:], d: u32) -> u32 {
    assert(d >= 2 && d < 65536);
    let dd: u64 = d;
    let inv: u64 = 4294967296 / dd;
    var r: u64 = 0;
    var i = a.len;
    while i > 0 {
        i--;
        r = ct_mod_small_step(r, a[i] >> 16, dd, inv);
        r = ct_mod_small_step(r, a[i] & 0xffff, dd, inv);
    }
    return r as! u32;
}

// (r 2^16 + chunk) mod d, for r < d.
fn ct_mod_small_step(r: u64, chunk: u64, d: u64, inv: u64) -> u64 {
    let x = (r << 16) | chunk;                   // < 2^32
    let y = x - ((x * inv) >> 32) * d;           // < 2d
    let t = y - d;
    let keep = 0 - (t >> 63);                    // y < d
    return t ^ (keep & (t ^ y));
}

// r = a / e for a public odd e and an a that e divides exactly
// (r.len == a.len): each quotient limb is the low limb times 1/e mod 2^32
// (Jebelean's exact division), so nothing is divided.
fn ct_div_exact(r: u32[:], a: const u32[:], e: u32) {
    assert(r.len == a.len && (e & 1) == 1);
    var inv = e;                                 // 1/e mod 2^32 by Newton
    for i in 4 { inv = inv * (2 - e * inv); }
    let ee: u64 = e;
    var borrow: u64 = 0;
    for i in a.len {
        let ai: u64 = a[i];
        let t = ai - borrow;
        let q = (t as! u32) * inv;
        r[i] = q;
        let qq: u64 = q;
        borrow = ((qq * ee) >> 32) + (t >> 63);
    }
}
