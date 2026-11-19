// bignum.shamir: secret sharing as KMIP's Split Keys do it (KMIP 2.1
// §13.1, after Shamir's "How to share a secret"): XOR (every part needed),
// and polynomial sharing in GF(2^8), in GF(2^16) and in a prime field,
// where any `threshold` of the parts give the secret back and fewer give
// nothing about it.
//
// The secret is the constant term of a random polynomial of degree
// threshold - 1, and part x (1, 2, ...: KMIP's Key Part Identifier) is the
// polynomial at x; joining is Lagrange interpolation at 0. In the binary
// fields this is done byte by byte (GF(2^8)) or two bytes at a time
// (GF(2^16)); in a prime field the secret is one big-endian integer, below
// the prime, and each part one integer below it, written at the prime's
// width.
//
// GF(2^8) is KMIP's: x^8 + x^4 + x^3 + x^2 + 1 (0x11D, which the OASIS
// test cases' parts bear out; AES's field is 0x11B). GF(2^16) is GF(2^8)[y]
// / (y^2 + y + m) with m = 0x3A, its elements uy + v two bytes (u, v).
//
// Constant time in the secret, the coefficients and the parts: the field
// arithmetic is masks and shifts (no tables), the prime field's is
// bignum.mont's. The part numbers, counts and lengths are public, and
// checks on them branch.
//
//   var parts: u8[>..] = [];
//   let ok = bignum::split_gf8(secret, 5, 3, parts);     // 5 parts of secret.len
//   let xs: i64[3] = [1, 3, 5];
//   var back: u8[>..] = [];
//   let ok2 = bignum::join_gf8(xs, picked, secret.len, back);

namespace bignum;

import std;
import entropy;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.mont;
import crypto.bignum.rsa;

// --- GF(2^8) and GF(2^16) ---------------------------------------------------------

let GF8_POLY: u32 = 0x11D;
let GF16_M: u8 = 0x3A;

fn gf8_mul(a: u8, b: u8) -> u8 {
    var r: u32 = 0;
    var x: u32 = a;
    let bb: u32 = b;
    for i in 8 {
        r = r ^ (x & (0 - ((bb >> i as! u32) & 1)));
        x = x << 1;
        x = x ^ (GF8_POLY & (0 - (x >> 8)));
    }
    return r as! u8;
}

// a^254 = a^-1 (0 for 0), by a fixed chain of squarings and products.
fn gf8_inv(a: u8) -> u8 {
    var r: u8 = 1;
    var p = a;
    for i in 8 {
        // 254 = 0b11111110: every bit but the lowest.
        if i > 0 { r = gf8_mul(r, p); }
        p = gf8_mul(p, p);
    }
    return r;
}

// uy + v as u << 8 | v.
fn gf16_mul(a: u16, b: u16) -> u16 {
    let r = (a >> 8) as! u8;
    let s = (a & 0xff) as! u8;
    let u = (b >> 8) as! u8;
    let v = (b & 0xff) as! u8;
    let sv = gf8_mul(s, v);
    let hi = gf8_mul(r ^ s, u ^ v) ^ sv;
    let lo = gf8_mul(gf8_mul(r, u), GF16_M) ^ sv;
    return (hi as u16) << 8 | lo;
}

// (uy + v)^-1 = u d^-1 y + (u + v) d^-1, d = (u + v) v + m u^2.
fn gf16_inv(a: u16) -> u16 {
    let u = (a >> 8) as! u8;
    let v = (a & 0xff) as! u8;
    let d = gf8_mul(u ^ v, v) ^ gf8_mul(GF16_M, gf8_mul(u, u));
    let di = gf8_inv(d);
    return (gf8_mul(u, di) as u16) << 8 | gf8_mul(u ^ v, di);
}

// --- Checks on the public values ---------------------------------------------------

// n parts, any t of them enough, x running 1..n below the field's size.
fn shares_ok(n: i64, t: i64, field: i64) -> bool { t >= 1 && n >= t && n < field }

// Distinct part numbers from 1 to below the field's size.
fn xs_ok(xs: const i64[:], field: i64) -> bool {
    if xs.len == 0 { return false; }
    for i in xs.len {
        if xs[i] < 1 || xs[i] >= field { return false; }
        for j in i { if xs[j] == xs[i] { return false; } }
    }
    return true;
}

fn coefficients(len: i64) -> u8[>..] {
    var r: u8[>..] = [];
    r.resize(len, 0);
    entropy::random_bytes(r);
    return r;
}

// --- XOR ------------------------------------------------------------------------

// n parts that all XOR to the secret: n - 1 of them rand ((n - 1) *
// secret.len bytes), the last the secret with them taken off.
fn split_xor_with(secret: const u8[:], n: i64, rand: const u8[:], out: u8[>..]&) -> bool {
    let len = secret.len;
    if n < 1 || rand.len != (n - 1) * len { return false; }
    out.clear();
    out.append(rand);
    var last: u8[>..] = [];
    last.append(secret);
    for i in n - 1 { for k in len { last[k] = last[k] ^ rand[i * len + k]; } }
    out.append(last);
    return true;
}

fn split_xor(secret: const u8[:], n: i64, out: u8[>..]&) -> bool {
    if n < 1 { return false; }
    let r = coefficients((n - 1) * secret.len);
    return split_xor_with(secret, n, r, out);
}

// The secret from all the parts, len bytes each, one after another.
fn join_xor(parts: const u8[:], len: i64, out: u8[>..]&) -> bool {
    if len <= 0 || parts.len % len != 0 { return false; }
    out.clear();
    out.resize(len, 0);
    var at = 0;
    while at < parts.len {
        for k in len { out[k] = out[k] ^ parts[at + k]; }
        at += len;
    }
    return true;
}

// --- Polynomial sharing in GF(2^8) ---------------------------------------------------

// n parts of secret.len bytes, one after another, part x at (x - 1) *
// secret.len; any t give the secret. rand holds the t - 1 higher
// coefficients of each byte's polynomial: (t - 1) * secret.len bytes, the
// coefficient of x^j for byte k at (j - 1) * secret.len + k.
fn split_gf8_with(secret: const u8[:], n: i64, t: i64, rand: const u8[:], out: u8[>..]&) -> bool {
    let len = secret.len;
    if !shares_ok(n, t, 256) || rand.len != (t - 1) * len { return false; }
    out.clear();
    out.resize(n * len, 0);
    for i in n {
        let x = (i + 1) as! u8;
        for k in len {
            // Horner, from the top coefficient down to the secret.
            var acc: u8 = 0;
            var j = t - 1;
            while j >= 1 { acc = gf8_mul(acc, x) ^ rand[(j - 1) * len + k]; j--; }
            out[i * len + k] = gf8_mul(acc, x) ^ secret[k];
        }
    }
    return true;
}

fn split_gf8(secret: const u8[:], n: i64, t: i64, out: u8[>..]&) -> bool {
    if !shares_ok(n, t, 256) { return false; }
    let r = coefficients((t - 1) * secret.len);
    return split_gf8_with(secret, n, t, r, out);
}

// The secret (len bytes) from the parts numbered xs, len bytes each in the
// same order. As many parts as were needed or more; with fewer, what comes
// out is not the secret (nothing here can tell).
fn join_gf8(xs: const i64[:], parts: const u8[:], len: i64, out: u8[>..]&) -> bool {
    if !xs_ok(xs, 256) || len <= 0 || parts.len != xs.len * len { return false; }
    out.clear();
    out.resize(len, 0);
    for i in xs.len {
        // The Lagrange coefficient of part i at 0: the product of x_j /
        // (x_j - x_i) over the others (minus is plus here).
        var num: u8 = 1;
        var den: u8 = 1;
        for j in xs.len {
            if j != i {
                num = gf8_mul(num, xs[j] as! u8);
                den = gf8_mul(den, (xs[j] ^ xs[i]) as! u8);
            }
        }
        let l = gf8_mul(num, gf8_inv(den));
        for k in len { out[k] = out[k] ^ gf8_mul(parts[i * len + k], l); }
    }
    return true;
}

// --- Polynomial sharing in GF(2^16) --------------------------------------------------

fn get16(b: const u8[:], at: i64) -> u16 { (b[at] as u16) << 8 | b[at + 1] }

fn put16(b: u8[:], at: i64, v: u16) {
    b[at] = (v >> 8) as! u8;
    b[at + 1] = (v & 0xff) as! u8;
}

// As split_gf8_with, two bytes (one element (u, v)) at a time: the secret
// is of an even length, and so is each part.
fn split_gf16_with(secret: const u8[:], n: i64, t: i64, rand: const u8[:], out: u8[>..]&) -> bool {
    let len = secret.len;
    if !shares_ok(n, t, 65536) || len % 2 != 0 || rand.len != (t - 1) * len { return false; }
    out.clear();
    out.resize(n * len, 0);
    for i in n {
        let x = (i + 1) as! u16;
        var k = 0;
        while k < len {
            var acc: u16 = 0;
            var j = t - 1;
            while j >= 1 { acc = gf16_mul(acc, x) ^ get16(rand, (j - 1) * len + k); j--; }
            put16(out[i * len..], k, gf16_mul(acc, x) ^ get16(secret, k));
            k += 2;
        }
    }
    return true;
}

fn split_gf16(secret: const u8[:], n: i64, t: i64, out: u8[>..]&) -> bool {
    if !shares_ok(n, t, 65536) || secret.len % 2 != 0 { return false; }
    let r = coefficients((t - 1) * secret.len);
    return split_gf16_with(secret, n, t, r, out);
}

fn join_gf16(xs: const i64[:], parts: const u8[:], len: i64, out: u8[>..]&) -> bool {
    if !xs_ok(xs, 65536) || len <= 0 || len % 2 != 0 || parts.len != xs.len * len { return false; }
    out.clear();
    out.resize(len, 0);
    for i in xs.len {
        var num: u16 = 1;
        var den: u16 = 1;
        for j in xs.len {
            if j != i {
                num = gf16_mul(num, xs[j] as! u16);
                den = gf16_mul(den, (xs[j] ^ xs[i]) as! u16);
            }
        }
        let l = gf16_mul(num, gf16_inv(den));
        var k = 0;
        while k < len {
            put16(out, k, get16(out, k) ^ gf16_mul(get16(parts, i * len + k), l));
            k += 2;
        }
    }
    return true;
}

// --- Polynomial sharing in a prime field ---------------------------------------------

// Whether prime (big-endian) will do for a secret of len bytes: a prime
// (Miller-Rabin, 40 rounds; it is public) above every len-byte number.
fn prime_field_ok(prime: const u8[:], len: i64) -> bool {
    let p = from_bytes_be(prime);
    if cmp_i64(p, 5) < 0 || !is_odd(p) || bit_len(p) <= 8 * len { return false; }
    return miller_rabin_vartime(p, 40);
}

// The prime field's pieces: the modulus's limbs, its Montgomery constants.
struct Field { n: i64, m0i: u32, m: u32[>..] }

fn field_of(prime: const u8[:]) -> Field {
    var f = Field { n: (prime.len + 3) / 4, m0i: 0, m: [] };
    f.m.resize(f.n, 0);
    limbs_from_be(f.m, prime);
    f.m0i = mont_m0i(f.m[0]);
    return f;
}

// r = a * b mod m: a * b / R, then times R^2 / R.
fn field_mul(f: const Field&, r: u32[:], a: const u32[:], b: const u32[:], r2: const u32[:], t: u32[:], tmp: u32[:]) {
    mont_mul(tmp, a, b, f.m, f.m0i, t);
    mont_mul(r, tmp, r2, f.m, f.m0i, t);
}

fn small_limbs(n: i64, v: i64) -> u32[>..] {
    var r: u32[>..] = [];
    r.resize(n, 0);
    r[0] = v as! u32;
    if n > 1 { r[1] = (v >> 32) as! u32; }
    return r;
}

// n parts of prime.len bytes each; the secret (an integer, big-endian)
// is below the prime (prime_field_ok). rand gives each higher coefficient
// prime.len + 8 bytes, reduced mod the prime: (t - 1) * (prime.len + 8).
fn split_prime_with(secret: const u8[:], prime: const u8[:], n: i64, t: i64, rand: const u8[:], out: u8[>..]&) -> bool {
    let w = prime.len;
    if !shares_ok(n, t, 1 << 31) || secret.len > w || rand.len != (t - 1) * (w + 8) { return false; }
    if cmp_i64(from_bytes_be(prime), n) <= 0 { return false; }
    let f = field_of(prime);
    let nl = f.n;
    var r2 = small_limbs(nl, 0);
    mont_r2(r2, f.m);
    var t2 = small_limbs(nl + 2, 0);
    var tmp = small_limbs(nl, 0);
    var s = small_limbs(nl, 0);
    limbs_from_be(s, secret);
    if ct_lt(s, f.m) == 0 { return false; }
    // The coefficients, each reduced into the field.
    var coef: u32[>..] = [];
    coef.resize((t - 1) * nl, 0);
    var wide: u32[>..] = [];
    wide.resize((w + 8 + 3) / 4, 0);
    for j in t - 1 {
        limbs_from_be(wide, rand[j * (w + 8)..(j + 1) * (w + 8)]);
        ct_reduce(coef[j * nl..(j + 1) * nl], wide, f.m);
    }
    out.clear();
    out.resize(n * w, 0);
    var acc = small_limbs(nl, 0);
    var prod = small_limbs(nl, 0);
    for i in n {
        let x = small_limbs(nl, i + 1);
        for &a in acc { a = 0; }
        var j = t - 1;
        while j >= 1 {
            field_mul(f, prod, acc, x, r2, t2, tmp);
            ct_mod_add(acc, prod, coef[(j - 1) * nl..j * nl], f.m);
            j--;
        }
        field_mul(f, prod, acc, x, r2, t2, tmp);
        ct_mod_add(acc, prod, s, f.m);
        be_from_limbs(out[i * w..(i + 1) * w], acc);
    }
    return true;
}

fn split_prime(secret: const u8[:], prime: const u8[:], n: i64, t: i64, out: u8[>..]&) -> bool {
    if !shares_ok(n, t, 1 << 31) { return false; }
    let r = coefficients((t - 1) * (prime.len + 8));
    return split_prime_with(secret, prime, n, t, r, out);
}

// The secret, len bytes, from the parts numbered xs (prime.len bytes
// each, below the prime). False when the result does not fit len bytes,
// which parts that are not the secret's (too few, or others) mostly give.
fn join_prime(xs: const i64[:], parts: const u8[:], prime: const u8[:], len: i64, out: u8[>..]&) -> bool {
    let w = prime.len;
    if !xs_ok(xs, 1 << 31) || len <= 0 || len > w || parts.len != xs.len * w { return false; }
    let pb = from_bytes_be(prime);
    for x in xs { if cmp_i64(pb, x) <= 0 { return false; } }
    let f = field_of(prime);
    let nl = f.n;
    var r2 = small_limbs(nl, 0);
    mont_r2(r2, f.m);
    var t2 = small_limbs(nl + 2, 0);
    var tmp = small_limbs(nl, 0);
    var sum = small_limbs(nl, 0);
    var y = small_limbs(nl, 0);
    var num = small_limbs(nl, 0);
    var den = small_limbs(nl, 0);
    var prod = small_limbs(nl, 0);
    var inv = small_limbs(nl, 0);
    var diff = small_limbs(nl, 0);
    for i in xs.len {
        limbs_from_be(y, parts[i * w..(i + 1) * w]);
        if ct_lt(y, f.m) == 0 { return false; }
        for &a in num { a = 0; }
        num[0] = 1;
        for &a in den { a = 0; }
        den[0] = 1;
        let xi = small_limbs(nl, xs[i]);
        for j in xs.len {
            if j != i {
                let xj = small_limbs(nl, xs[j]);
                field_mul(f, prod, num, xj, r2, t2, tmp);
                for k in nl { num[k] = prod[k]; }
                ct_mod_sub(diff, xj, xi, f.m);
                field_mul(f, prod, den, diff, r2, t2, tmp);
                for k in nl { den[k] = prod[k]; }
            }
        }
        if ct_mod_inv(inv, den, f.m) == 0 { return false; }
        field_mul(f, prod, num, inv, r2, t2, tmp);       // the coefficient
        field_mul(f, inv, y, prod, r2, t2, tmp);         // times the part
        ct_mod_add(prod, sum, inv, f.m);
        for k in nl { sum[k] = prod[k]; }
    }
    var full: u8[>..] = [];
    full.resize(w, 0);
    be_from_limbs(full, sum);
    var high: u32 = 0;
    for k in w - len { high = high | full[k]; }
    out.clear();
    out.append(full[w - len..]);
    return high == 0;
}
