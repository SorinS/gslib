// bignum.mont against BigInt: Montgomery exponentiation, R^2, reduction of
// wider numbers and exact products, for random odd moduli of 1 to 12 limbs
// and all-ones ones, with exponents of several widths, zero among them.
import std;
import bignum from "..";
import bignum.mont;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 10 { print("FAIL ", what); } }
}

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

fn random_limbs(r: rng&, n: i64) -> bignum::BigInt {
    var x = bignum::zero();
    for i in n { x.mag.push(r.rand_u64() as! u32); }
    bignum::mag_trim(x.mag);
    return x;
}

fn main() {
    check("m0i", bignum::mont_m0i(1) == 4294967295);
    for m0 in [3, 5, 65537, 4294967295] {
        let m = m0 as u32;
        check("m0i", m * bignum::mont_m0i(m) == 4294967295);   // m * (-1/m) == -1
    }
    var r = rng { 5 };
    for n in 1..13 {
        for t in 8 {
            var m = random_limbs(r, n);
            m.mag[n - 1] = m.mag[n - 1] | 1;
            m.mag[0] = m.mag[0] | 1;
            if t == 0 { m = bignum::sub(bignum::shl(bignum::one(), 32 * n), bignum::one()); }
            if t == 1 && n == 1 { m = bignum::big(3); }
            let ml = limbs(m, n);
            let m0i = bignum::mont_m0i(ml[0]);
            var r2 = limbs(bignum::zero(), n);
            bignum::mont_r2(r2, ml);
            check("r2", bignum::eq(value(r2), bignum::mod_floor(bignum::shl(bignum::one(), 64 * n), m)));

            let x = if t == 2 { bignum::sub(m, bignum::one()) } else { bignum::mod_floor(random_limbs(r, n + 1), m) };
            let e = if t == 3 { bignum::zero() } else { random_limbs(r, (t % 3) + 1) };
            var out = limbs(bignum::zero(), n);
            bignum::mont_modexp(out, limbs(x, n), limbs(e, ::max(e.mag.len, 1)), ml, m0i, r2);
            check("modexp", bignum::eq(value(out), bignum::modpow(x, e, m)));

            let y = bignum::mod_floor(random_limbs(r, n), m);
            var t1 = limbs(bignum::zero(), n);
            var t2 = limbs(bignum::zero(), n);
            var scratch = limbs(bignum::zero(), n + 2);
            bignum::mont_mul(t1, limbs(x, n), limbs(y, n), ml, m0i, scratch);
            bignum::mont_mul(t2, t1, r2, ml, m0i, scratch);
            check("mont_mul", bignum::eq(value(t2), bignum::mod_floor(bignum::mul(x, y), m)));

            let wide = random_limbs(r, 3 * n + 1);
            var red = limbs(bignum::zero(), n);
            bignum::ct_reduce(red, limbs(wide, 3 * n + 1), ml);
            check("reduce", bignum::eq(value(red), bignum::mod_floor(wide, m)));

            let a = random_limbs(r, n);
            let b = random_limbs(r, n + 2);
            var prod = limbs(bignum::zero(), 2 * n + 2);
            bignum::ct_mul(prod, limbs(a, n), limbs(b, n + 2));
            check("ct_mul", bignum::eq(value(prod), bignum::mul(a, b)));

            // ct_mod_inv: x, 0, 1, m - 1 and another random value; the
            // all-ones moduli have small factors, so some are not invertible.
            for k in 5 {
                let v = if k == 0 { copy(x) } else if k == 1 { bignum::zero() } else if k == 2 { bignum::one() }
                        else if k == 3 { bignum::sub(m, bignum::one()) } else { bignum::mod_floor(random_limbs(r, n), m) };
                var inv = limbs(bignum::zero(), n);
                let ok = bignum::ct_mod_inv(inv, limbs(v, n), ml);
                let want, want_ok = bignum::modinv(v, value(ml));
                check("ct_mod_inv ok", (ok == 1) == want_ok);
                check("ct_mod_inv", if want_ok { bignum::eq(value(inv), want) } else { bignum::is_zero(value(inv)) });
            }
            // Not invertible: a shares the factor g with m = g h.
            if n >= 2 {
                let g = bignum::bit_or(random_limbs(r, 1), bignum::one());
                let h = bignum::bit_or(random_limbs(r, n - 1), bignum::one());
                let gh = bignum::mul(g, h);
                let w = gh.mag.len;
                let a2 = bignum::mul(g, bignum::big(5));
                if bignum::cmp_i64(g, 1) > 0 && bignum::lt(a2, gh) {
                    var inv = limbs(bignum::zero(), w);
                    check("ct_mod_inv factor", bignum::ct_mod_inv(inv, limbs(a2, w), limbs(gh, w)) == 0);
                }
            }
        }
    }
    print("mont ops: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
