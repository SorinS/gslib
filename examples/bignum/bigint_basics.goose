// BigInt, integers of any size: parsing and printing in several bases,
// arithmetic, truncating and floor division with negative operands,
// number theory (gcd, modular inverse and power, square root), bit
// operations in two's complement, bytes, and the in-place forms. BigInt is
// variable time: never use it on secrets (bignum.mont and bignum.ct are
// for those).
//
//   goose examples/bignum/bigint_basics.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;

fn fail(what: const u8[:]) { print("bigint_basics: ", what); exit(1); }

fn main() {
    // Text in and out: decimal by default, any base from 2 to 36.
    let a, oka = bignum::parse("123456789012345678901234567890");
    let h, okh = bignum::parse("0xdeadbeefcafebabe", 16);
    let b = bignum::pow(bignum::big(2), 100);
    guard oka && okh else { fail("parse"); }
    print("a       = ", a);                      // print and str render decimal
    print("2^100   = ", b, " = 0x", bignum::to_hex(b));
    print("h       = ", h, " = ", bignum::to_str(h, 36), " in base 36");
    let bad, okbad = bignum::parse("12x4");
    guard !okbad else { fail("bad digits accepted"); }

    // Arithmetic is named functions (Goose has no operator overloading).
    let c = bignum::add(bignum::mul(a, b), bignum::big(7));
    print("a*2^100+7 = ", c);
    guard bignum::eq(bignum::sub(c, bignum::big(7)), bignum::mul(b, a)) else { fail("add/sub/mul"); }

    // Division: truncating like C, or floor like Python.
    let n = bignum::big(-17);
    let d = bignum::big(5);
    let q1, r1 = bignum::divmod(n, d);
    let q2, r2 = bignum::divmod_floor(n, d);
    print("-17 / 5: truncating ", q1, " rem ", r1, "; floor ", q2, " mod ", r2);
    guard bignum::cmp_i64(q1, -3) == 0 && bignum::cmp_i64(r1, -2) == 0 && bignum::cmp_i64(q2, -4) == 0 &&
          bignum::cmp_i64(r2, 3) == 0 else {
        fail("division");
    }

    // Number theory: RSA's textbook numbers p = 61, q = 53, e = 17.
    let phi = bignum::mul(bignum::big(60), bignum::big(52));
    let dk, inv = bignum::modinv(bignum::big(17), phi);
    let m = bignum::big(3233);
    let ct = bignum::modpow(bignum::big(65), bignum::big(17), m);
    let pt = bignum::modpow(ct, dk, m);
    print("d = 1/17 mod 3120 = ", dk, "; 65^17 mod 3233 = ", ct, ", and back: ", pt);
    guard inv && bignum::cmp_i64(dk, 2753) == 0 && bignum::cmp_i64(pt, 65) == 0 else { fail("modinv/modpow"); }
    let g, x, y = bignum::ext_gcd(bignum::big(240), bignum::big(46));
    print("gcd(240, 46) = ", g, " = 240*", x, " + 46*", y, "; lcm = ", bignum::lcm(bignum::big(240), bignum::big(46)));
    guard bignum::eq(bignum::isqrt(bignum::mul(a, a)), a) else { fail("isqrt"); }

    // Bits: negatives act as infinite two's complement, so shr rounds down.
    print("-17 >> 2 = ", bignum::shr(n, 2), ", -17 & 0xff = ", bignum::bit_and(n, bignum::big(255)),
          ", bit_len(2^100) = ", bignum::bit_len(b));

    // Bytes, as keys and wire formats hold numbers: fixed-width big-endian.
    let bytes = bignum::to_bytes_be(h, 16);
    guard bytes.len == 16 && bignum::eq(bignum::from_bytes_be(bytes), h) else { fail("bytes"); }

    // In place: `x = add(x, y)` would build over its own input, so it does
    // not compile; use add_to (or `let t = add(x, y); x = copy(t);`).
    var f = bignum::one();
    for i in 1..31 { bignum::mul_to(f, bignum::big(i)); }
    print("30! = ", f);
    let v, fits = bignum::to_i64(f);                   // too big for an i64
    let want, okw = bignum::parse("265252859812191058636308480000000");
    guard !fits && okw && bignum::eq(f, want) else { fail("30!"); }
    print("all BigInt checks passed");
}
