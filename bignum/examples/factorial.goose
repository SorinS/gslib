// n! for a large n, its digit count and digit sum, then the same number
// through a different road: the product of the primes' powers in it
// (Legendre's formula), multiplied by binary splitting.
//
//   goose examples/factorial.goose -- 5000
import std;
import os;
import bignum from "..";

// The product of xs by binary splitting, so the multiplies are balanced
// and the large ones go through Karatsuba. Bottom-up: neighbours pair
// until one number is left. A BigInt cannot be an array element (it is
// resizable), so a level is one limb array and where each number starts.
fn product(xs: const u32[:]) -> bignum::BigInt {
    var acc = bignum::zero();
    var level: u32[>..] = [];
    var starts: i64[>..] = [];
    for x in xs { starts.push(level.len); level.push(x); }
    starts.push(level.len);
    while starts.len > 2 {
        var next: u32[>..] = [];
        var nstarts: i64[>..] = [];
        var i = 0;
        while i + 1 < starts.len {
            nstarts.push(next.len);
            let a = level[starts[i]..starts[i + 1]];
            if i + 2 < starts.len {
                let b = level[starts[i + 1]..starts[i + 2]];
                var p: u32[>..] = [];
                bignum::mag_mul(p, a, b);
                for limb in p { next.push(limb); }
            } else {
                for limb in a { next.push(limb); }
            }
            i += 2;
        }
        nstarts.push(next.len);
        level = copy(next);
        starts = copy(nstarts);
    }
    for limb in level { acc.mag.push(limb); }
    bignum::mag_trim(acc.mag);
    if acc.mag.len == 0 { acc = bignum::one(); }
    return acc;
}

fn main() {
    var n = 3000;
    let args = args();
    if args.len > 1 {
        let v, ok = parse_int(args[1]);
        if ok && v > 1 { n = v; }
    }
    // The direct way: n multiply-by-small steps.
    var t0 = clock();
    var f = bignum::one();
    for i in 2..n + 1 { bignum::mul_add_small_to(f, i as u32, 0); }
    let t_direct = clock() - t0;
    let text = bignum::to_str(f);
    var digit_sum = 0;
    for c in text { digit_sum += c - '0'; }
    print(n, "! has ", text.len, " digits, digit sum ", digit_sum);
    let k = ::min(20, text.len);
    print("  starts ", text[..k], "..., ends ...", text[text.len - k..]);

    // The other way: n! = prod over primes p <= n of p^(n/p + n/p^2 + ...).
    t0 = clock();
    var sieve: bool[>..] = [];
    sieve.resize(n + 1, true);
    var factors: u32[>..] = [];
    for p in 2..n + 1 {
        if !sieve[p] { continue; }
        var q = p * p;
        while q <= n { sieve[q] = false; q += p; }
        var e = 0;
        var pk = p;
        while pk <= n { e += n / pk; pk *= p; }
        for k in e { factors.push(p as u32); }
    }
    let g = product(factors);
    let t_split = clock() - t0;
    print("  by prime powers and binary splitting: equal = ", bignum::eq(f, g));
    print("  direct ", (t_direct * 1000.0) as i64, " ms, split ", (t_split * 1000.0) as i64, " ms");
    assert(bignum::eq(f, g));
}
