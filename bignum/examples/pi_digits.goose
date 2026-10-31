// The first n decimal digits of pi by Machin's formula,
//   pi = 16 atan(1/5) - 4 atan(1/239),
// in fixed point: every number is scaled by 10^(n + 10), and the series
// steps are in-place divisions by machine-sized divisors.
//
//   goose examples/pi_digits.goose -- 2000
import std;
import os;
import bignum from "..";

// atan(1/x) * scale
fn atan_inv(x: u32, scale) -> bignum::BigInt {
    var term = bignum::div(scale, bignum::big(x));     // scale / x^(2k+1)
    var sum = copy(term);
    let x2 = x * x;
    var k: u32 = 1;
    while !bignum::is_zero(term) {
        bignum::div_small_to(term, x2);
        var part = copy(term);
        bignum::div_small_to(part, 2 * k + 1);
        if k % 2 == 1 { bignum::sub_from(sum, part); } else { bignum::add_to(sum, part); }
        k++;
    }
    return sum;
}

fn main() {
    var n = 1000;
    let args = args();
    if args.len > 1 {
        let v, ok = parse_int(args[1]);
        if ok && v > 0 { n = v; }
    }
    let t0 = clock();
    let scale = bignum::pow(bignum::big(10), (n + 10) as u64);
    var pi = bignum::mul(bignum::big(16), atan_inv(5, scale));
    bignum::sub_from(pi, bignum::mul(bignum::big(4), atan_inv(239, scale)));
    let digits = bignum::to_str(bignum::div(pi, bignum::pow(bignum::big(10), 10)));
    let ms = ((clock() - t0) * 1000.0) as i64;
    print(digits[..1], ".", digits[1..::min(digits.len, 61)], "...");
    print("last digits: ...", digits[digits.len - 20..]);
    print(n, " digits in ", ms, " ms");
    assert(digits[..50] == "31415926535897932384626433832795028841971693993751");
}
