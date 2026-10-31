// The API's edges: conversions at the limits, in-place forms (aliased
// too), bytes, parse errors, and the identities between operations.
import std;
import bignum from "..";

fn eqs(a, s: const u8[:]) -> bool { bignum::to_str(a) == s }

fn main() {
    // Conversions at the i64/u64 limits.
    let mn = bignum::big(-9223372036854775808);
    assert(eqs(mn, "-9223372036854775808"));
    let v, ok = bignum::to_i64(mn);
    assert(ok && v == -9223372036854775808);
    let below = bignum::sub(mn, bignum::one());
    let v2, ok2 = bignum::to_i64(below);
    assert(!ok2);
    let um = bignum::from_u64(18446744073709551615);
    let u, oku = bignum::to_u64(um);
    assert(oku && u == 18446744073709551615);
    let u2, oku2 = bignum::to_u64(bignum::add(um, bignum::one()));
    assert(!oku2);
    assert(bignum::to_f64(bignum::pow(bignum::big(2), 70)) == 1180591620717411303424.0);

    // Zero is never negative.
    let z = bignum::add(bignum::big(5), bignum::big(-5));
    assert(bignum::is_zero(z) && !bignum::is_neg(z) && bignum::sign(z) == 0);
    assert(!bignum::is_neg(bignum::neg(bignum::zero())));
    assert(!bignum::is_neg(bignum::mul(bignum::big(-3), bignum::zero())));
    assert(eqs(bignum::shr(bignum::big(-1), 100), "-1"));
    assert(eqs(bignum::shl(bignum::zero(), 100), "0"));

    // In-place forms, including x op= x.
    var x = bignum::big(12345);
    bignum::add_to(x, x);
    assert(eqs(x, "24690"));
    bignum::sub_from(x, x);
    assert(bignum::is_zero(x));
    x = bignum::big(-7);
    bignum::add_i64_to(x, 10);
    assert(eqs(x, "3"));
    bignum::add_i64_to(x, -10);
    assert(eqs(x, "-7"));
    bignum::mul_to(x, x);
    assert(eqs(x, "49"));
    var f = bignum::one();
    for i in 1..31 { bignum::mul_add_small_to(f, i as u32, 0); }
    assert(eqs(f, "265252859812191058636308480000000"));     // 30!
    let r = bignum::div_small_to(f, 1000000007);
    let f2 = bignum::add(bignum::mul(f, bignum::big(1000000007)), bignum::big(r));
    assert(eqs(f2, "265252859812191058636308480000000"));

    // Truncating and floor division, all sign combinations.
    for sa in 2 {
        for sb in 2 {
            let a = bignum::big(if sa == 0 { 17 } else { -17 });
            let b = bignum::big(if sb == 0 { 5 } else { -5 });
            let q, rr = bignum::divmod(a, b);
            let fq, fr = bignum::divmod_floor(a, b);
            print(a, " / ", b, ": trunc ", q, " ", rr, ", floor ", fq, " ", fr);
            assert(bignum::eq(bignum::add(bignum::mul(q, b), rr), a));
            assert(bignum::eq(bignum::add(bignum::mul(fq, b), fr), a));
        }
    }

    // Parsing.
    let p1, k1 = bignum::parse("-0x1F", 16);
    assert(k1 && eqs(p1, "-31"));
    let p2, k2 = bignum::parse("+000123");
    assert(k2 && eqs(p2, "123"));
    let p3, k3 = bignum::parse("-0");
    assert(k3 && !bignum::is_neg(p3));
    let p4, k4 = bignum::parse("12a");
    assert(!k4);
    let p5, k5 = bignum::parse("");
    assert(!k5);
    let p6, k6 = bignum::parse("-");
    assert(!k6);
    let p7, k7 = bignum::parse("zz", 36);
    assert(k7 && eqs(p7, "1295"));
    print(bignum::to_str(bignum::big(-255), 2), " ", bignum::to_str(bignum::big(1295), 36));

    // Bytes.
    let key = bignum::from_bytes_be("\x01\x02\x03\x04\x05");
    assert(bignum::to_hex(key) == "102030405");
    assert(bignum::to_bytes_be(key, 7) == "\x00\x00\x01\x02\x03\x04\x05");
    assert(bignum::to_bytes_le(key, 5) == "\x05\x04\x03\x02\x01");
    assert(bignum::eq(bignum::from_bytes_le("\x05\x04\x03\x02\x01"), key));

    // Number theory identities.
    let m = bignum::sub(bignum::pow(bignum::big(2), 127), bignum::one());   // a Mersenne prime
    let a = bignum::big(123456789);
    let inv, okinv = bignum::modinv(a, m);
    assert(okinv && eqs(bignum::mod_floor(bignum::mul(a, inv), m), "1"));
    // Fermat: a^(m-1) == 1 mod m
    assert(eqs(bignum::modpow(a, bignum::sub(m, bignum::one()), m), "1"));
    let g, gx, gy = bignum::ext_gcd(bignum::big(240), bignum::big(-46));
    print("ext_gcd(240, -46) = ", g, " ", gx, " ", gy);
    assert(bignum::eq(bignum::add(bignum::mul(bignum::big(240), gx), bignum::mul(bignum::big(-46), gy)), g));
    assert(eqs(bignum::lcm(bignum::big(-4), bignum::big(6)), "12"));
    assert(eqs(bignum::isqrt(bignum::pow(bignum::big(10), 40)), "100000000000000000000"));
    print("bit_len(2^127-1) = ", bignum::bit_len(m));
    print("ok");
}
