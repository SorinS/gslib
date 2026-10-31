// bignum.ct against BigInt, on random fixed-width operands and the values
// at the edges of a width (0, 1, m - 1, all ones).
import std;
import bignum from "..";
import bignum.ct;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

// The limbs of v at exactly n limbs.
fn limbs(v, n: i64) -> u32[>..] {
    var out: u32[>..] = [];
    for i in n { out.push(if i < v.mag.len { v.mag[i] } else { 0 }); }
    return out;
}

fn value(xs: const u32[:]) -> bignum::BigInt {
    var r = bignum::zero();
    for x in xs { r.mag.push(x); }
    bignum::mag_trim(r.mag);
    return r;
}

fn random_below(r: rng&, m, n: i64) -> u32[>..] {
    var x = bignum::zero();
    for i in n { x.mag.push(r.rand_u64() as! u32); }
    bignum::mag_trim(x.mag);
    return limbs(bignum::mod_floor(x, m), n);
}

fn main() {
    // Scalars.
    let vals: u32[6] = [0, 1, 2, 2147483648, 4294967294, 4294967295];
    for a in vals {
        check("is_zero", bignum::ct_is_zero_u32(a) == (if a == 0 { 1 } else { 0 }));
        for b in vals {
            check("eq", bignum::ct_eq_u32(a, b) == (if a == b { 1 } else { 0 }));
            check("lt", bignum::ct_lt_u32(a, b) == (if a < b { 1 } else { 0 }));
            check("select", bignum::ct_select_u32(bignum::ct_mask(1), a, b) == a);
            check("select", bignum::ct_select_u32(bignum::ct_mask(0), a, b) == b);
        }
    }
    check("eq_bytes", bignum::ct_eq_bytes("tag-123", "tag-123") == 1);
    check("eq_bytes", bignum::ct_eq_bytes("tag-123", "tag-124") == 0);

    var r = rng { 7 };
    for n in 1..9 {
        let mod_bits = n * 32 - r.rand_int(16);           // at least 16 bits, so m > 0
        var m = bignum::sub(bignum::shl(bignum::one(), mod_bits), bignum::big(r.rand_int(1000) + 1));
        let ml = limbs(m, n);
        for t in 40 {
            var a = random_below(r, m, n);
            var b = random_below(r, m, n);
            if t == 0 { a = limbs(bignum::sub(m, bignum::one()), n); b = limbs(bignum::sub(m, bignum::one()), n); }
            if t == 1 { a = limbs(bignum::zero(), n); }
            let va = value(a);
            let vb = value(b);
            var out: u32[>..] = [];
            out.resize(n, 0);
            bignum::ct_mod_add(out, a, b, ml);
            check("mod_add", bignum::eq(value(out), bignum::mod_floor(bignum::add(va, vb), m)));
            bignum::ct_mod_sub(out, a, b, ml);
            check("mod_sub", bignum::eq(value(out), bignum::mod_floor(bignum::sub(va, vb), m)));
            let c = bignum::ct_add(out, a, b);
            let sum = bignum::add(value(out), bignum::shl(bignum::big(c), 32 * n));
            check("add", bignum::eq(sum, bignum::add(va, vb)));
            check("lt", (bignum::ct_lt(a, b) == 1) == bignum::lt(va, vb));
            check("eq", (bignum::ct_eq(a, b) == 1) == bignum::eq(va, vb));
            check("eq self", bignum::ct_eq(a, a) == 1);
            check("is_zero", (bignum::ct_is_zero(a) == 1) == bignum::is_zero(va));
            var x = copy(a);
            var y = copy(b);
            bignum::ct_cswap(bignum::ct_mask(1), x, y);
            check("cswap", x == b && y == a);
            bignum::ct_cswap(bignum::ct_mask(0), x, y);
            check("cswap 0", x == b && y == a);
            bignum::ct_select(out, bignum::ct_mask(1), a, b);
            check("select", out == a);
        }
    }
    // ct_mod_small, ct_div_exact, ct_is_one and the masked add, subtract
    // and shift, against BigInt.
    var r = rng { 11 };
    for n in 1..10 {
        for t in 20 {
            var a: u32[>..] = [];
            for i in n { a.push(if t == 0 { 4294967295 } else if t == 1 { 0 } else { r.rand_u64() as! u32 }); }
            let av = bignum::big_of(a);
            for d in [2, 3, 7, 1999, 65521, 65535] {
                let dv = d as u32;
                check("mod_small", bignum::cmp_i64(bignum::rem(av, bignum::big(d)), bignum::ct_mod_small(a, dv)) == 0);
            }
            let e = (r.rand_u64() as! u32) | 1;
            var prod: u32[>..] = [];
            prod.resize(n + 1, 0);
            var carry: u64 = 0;
            for i in n + 1 {
                let x: u64 = if i < n { a[i] } else { 0 };
                let s = x * e + carry;
                prod[i] = s as! u32;
                carry = s >> 32;
            }
            var q: u32[>..] = [];
            q.resize(n + 1, 0);
            bignum::ct_div_exact(q, prod, e);
            check("div_exact", bignum::eq(bignum::big_of(q), av));
            check("is_one", bignum::ct_is_one(a) == (if bignum::cmp_i64(av, 1) == 0 { 1 } else { 0 }));
            var b: u32[>..] = [];
            for i in n { b.push(r.rand_u64() as! u32); }
            let bv = bignum::big_of(b);
            var s1 = copy(a);
            let borrow = bignum::ct_sub_masked(s1, b, 0xffffffff);
            let wrap = bignum::shl(bignum::one(), 32 * n);
            check("sub_masked", bignum::eq(bignum::big_of(s1), bignum::mod_floor(bignum::sub(av, bv), wrap))
                  && (borrow == 1) == bignum::lt(av, bv));
            var s2 = copy(a);
            check("sub_masked 0", bignum::ct_sub_masked(s2, b, 0) == 0 && s2 == a);
            var s3 = copy(a);
            let c = bignum::ct_add_masked(s3, b, 0xffffffff);
            let sum = bignum::add(av, bv);
            check("add_masked", bignum::eq(bignum::big_of(s3), bignum::mod_floor(sum, wrap))
                  && (c == 1) == bignum::ge(sum, wrap));
            var s4 = copy(a);
            bignum::ct_shr1(s4);
            check("shr1", bignum::eq(bignum::big_of(s4), bignum::shr(av, 1)));
        }
    }
    print("ct: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
