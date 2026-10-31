// bignum.mont: constant-time modular arithmetic for an odd modulus m, over
// u32[:] limbs of m's width (little-endian, as in BigInt). Montgomery
// multiplication (CIOS), R^2 mod m by doubling, reduction of a wider
// number, and a fixed-window exponentiation whose table is read by
// scanning every entry. The loops depend on lengths only, which are
// public; values of m, the operands and the exponent are not branched on.
// Here R = 2^(32 * m.len).

namespace bignum;

import std;
import ct;

// -1/m mod 2^32 for odd m0, by Newton's iteration (each step doubles the
// correct low bits; m0 is its own inverse mod 8).
fn mont_m0i(m0: u32) -> u32 {
    var x = m0;
    for i in 4 { x = x * (2 - m0 * x); }
    return 0 - x;
}

// r = a * b / R mod m, for a, b < m. t is scratch of m.len + 2 limbs; r
// may be the same storage as a or b only through a copy.
fn mont_mul(r: u32[:], a: const u32[:], b: const u32[:], m: const u32[:], m0i: u32, t: u32[:]) {
    let n = m.len;
    assert(a.len == n && b.len == n && r.len == n && t.len == n + 2);
    for &x in t { x = 0; }
    for i in n {
        let bi: u64 = b[i];
        var c: u64 = 0;
        for j in n {
            let aj: u64 = a[j];
            let s = t[j] + aj * bi + c;
            t[j] = s as! u32;
            c = s >> 32;
        }
        let s = t[n] + c;
        t[n] = s as! u32;
        t[n + 1] = (s >> 32) as! u32;
        // Add mi * m, which makes the low limb zero, and shift down a limb.
        let mi: u64 = t[0] * m0i;
        let m0: u64 = m[0];
        c = (t[0] + mi * m0) >> 32;
        for j in 1..n {
            let mj: u64 = m[j];
            let s2 = t[j] + mi * mj + c;
            t[j - 1] = s2 as! u32;
            c = s2 >> 32;
        }
        let s3 = t[n] + c;
        t[n - 1] = s3 as! u32;
        t[n] = t[n + 1] + (s3 >> 32) as! u32;
    }
    // t < 2m: one conditional subtraction.
    ct_cond_sub(t[..n], t[n], m);
    for i in n { r[i] = t[i]; }
}

// r = 2r mod m, for r < m.
fn ct_mod_double(r: u32[:], m: const u32[:]) {
    var hi: u32 = 0;
    for i in r.len {
        let x = r[i];
        r[i] = (x << 1) | hi;
        hi = x >> 31;
    }
    ct_cond_sub(r, hi, m);
}

// r = R^2 mod m, for m > 1: one doubled 64 * m.len times.
fn mont_r2(r: u32[:], m: const u32[:]) {
    assert(r.len == m.len);
    for &x in r { x = 0; }
    r[0] = 1;
    for i in 64 * m.len { ct_mod_double(r, m); }
}

// r = x mod m for x of any width (m > 1), shifting x in a bit at a time
// from the top: r = 2r + bit, reduced, keeps r < m.
fn ct_reduce(r: u32[:], x: const u32[:], m: const u32[:]) {
    assert(r.len == m.len);
    for &v in r { v = 0; }
    var i = x.len;
    while i > 0 {
        i--;
        var k = 32;
        while k > 0 {
            k--;
            var carry = (x[i] >> k) & 1;
            for j in r.len {
                let v = r[j];
                r[j] = (v << 1) | carry;
                carry = v >> 31;
            }
            ct_cond_sub(r, carry, m);
        }
    }
}

// r = a * b exactly, r.len == a.len + b.len; no data-dependent shortcuts.
fn ct_mul(r: u32[:], a: const u32[:], b: const u32[:]) {
    assert(r.len == a.len + b.len);
    for &x in r { x = 0; }
    for i in a.len {
        let ai: u64 = a[i];
        var carry: u64 = 0;
        for j in b.len {
            let bj: u64 = b[j];
            let t = r[i + j] + ai * bj + carry;
            r[i + j] = t as! u32;
            carry = t >> 32;
        }
        r[i + b.len] = carry as! u32;
    }
}

// The window of 4 exponent bits at bit position 4 * w.
fn exp_window(e: const u32[:], w: i64) -> u32 {
    (e[w / 8] >> (4 * (w % 8))) & 15
}

// r = x^e mod m for odd m > 1 and x < m, in normal (not Montgomery)
// form. Every window of e is processed, so the time depends on e.len
// alone; r2 is R^2 mod m (mont_r2).
fn mont_modexp(r: u32[:], x: const u32[:], e: const u32[:], m: const u32[:], m0i: u32,
               r2: const u32[:]) {
    let n = m.len;
    assert(r.len == n && x.len == n && r2.len == n);
    var buf: u32[>..] = [];
    buf.resize(21 * n + 2, 0);
    let tab = buf[..16 * n];
    let acc = buf[16 * n..17 * n];
    let sel = buf[17 * n..18 * n];
    let tmp = buf[18 * n..19 * n];
    let one = buf[19 * n..20 * n];
    let t = buf[20 * n..];
    one[0] = 1;
    mont_mul(tab[..n], r2, one, m, m0i, t);              // R mod m, the Montgomery 1
    mont_mul(tab[n..2 * n], x, r2, m, m0i, t);           // x R
    for i in 2..16 {
        mont_mul(tab[i * n..(i + 1) * n], tab[(i - 1) * n..i * n], tab[n..2 * n], m, m0i, t);
    }
    for i in n { acc[i] = tab[i]; }
    var w = 8 * e.len;
    while w > 0 {
        w--;
        for s in 4 {
            mont_mul(tmp, acc, acc, m, m0i, t);
            for i in n { acc[i] = tmp[i]; }
        }
        let win = exp_window(e, w);
        for &v in sel { v = 0; }
        for k in 16 {
            let mask = ct_mask(ct_eq_u32(win, k as! u32));
            let row = tab[k * n..(k + 1) * n];
            for i in n { sel[i] = sel[i] | (row[i] & mask); }
        }
        mont_mul(tmp, acc, sel, m, m0i, t);
        for i in n { acc[i] = tmp[i]; }
    }
    mont_mul(r, acc, one, m, m0i, t);                    // out of Montgomery form
}

// Big-endian bytes into limbs, and back, at fixed widths.
fn limbs_from_be(dst: u32[:], b: const u8[:]) {
    assert(b.len <= 4 * dst.len);
    for &x in dst { x = 0; }
    for i in b.len {
        let pos = b.len - 1 - i;
        dst[pos / 4] = dst[pos / 4] | (b[i] as u32) << (8 * (pos % 4));
    }
}

fn be_from_limbs(out: u8[:], src: const u32[:]) {
    for i in out.len {
        let pos = out.len - 1 - i;
        out[i] = if pos / 4 < src.len { (src[pos / 4] >> (8 * (pos % 4))) as! u8 } else { 0 };
    }
}

// r = a^-1 mod m for odd m > 1 and a < m, returning 1; 0 (and r = 0) when
// gcd(a, m) != 1. Binary extended Euclid in Moller's constant-time form
// (GMP's mpn_sec_invert): with x = a, y = m, u = 1, v = 0, every step keeps
// x = u a and y = v a (mod m) and y odd. An odd x smaller than y swaps
// with it; an odd x has y taken away; then x halves (and u, mod m). Each
// step shortens x and y together by a bit or more, so 64 m.len steps take
// x to 0, leaving y = gcd(a, m) and v = 1/a when it is 1. Every step does
// the same work whatever the values.
fn ct_mod_inv(r: u32[:], a: const u32[:], m: const u32[:]) -> u32 {
    let n = m.len;
    assert(r.len == n && a.len == n && (m[0] & 1) == 1);
    var buf: u32[>..] = [];
    buf.resize(6 * n, 0);
    let x = buf[..n];
    let y = buf[n..2 * n];
    let u = buf[2 * n..3 * n];
    let v = buf[3 * n..4 * n];
    let half = buf[4 * n..5 * n];                // (m + 1) / 2
    let one = buf[5 * n..];
    for i in n { x[i] = a[i]; y[i] = m[i]; half[i] = m[i]; }
    u[0] = 1;
    ct_shr1(half);
    one[0] = 1;
    ct_add(half, half, one);                     // m odd: no carry
    for i in 64 * n {
        let odd = x[0] & 1;
        let swap = ct_mask(odd & ct_lt(x, y));
        ct_cswap(swap, x, y);
        ct_cswap(swap, u, v);
        let take = ct_mask(odd);
        ct_sub_masked(x, y, take);               // x >= y here: no borrow
        ct_add_masked(u, m, ct_mask(ct_sub_masked(u, v, take)));
        ct_shr1(x);
        let uodd = ct_mask(u[0] & 1);
        ct_shr1(u);
        ct_add_masked(u, half, uodd);            // u/2 mod m: (u - 1)/2 + (m + 1)/2
    }
    let ok = ct_is_one(y);
    ct_select(r, ct_mask(ok), v, x);             // x is 0 by now
    return ok;
}

