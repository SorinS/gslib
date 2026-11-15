// The GF(2^448 - 2^224 - 1) arithmetic of bignum.x448 against BigInt:
// random and edge-case encodings (0, 1, p - 1, p, p + 1, 2^448 - 1,
// 2^224, 2^447), through each operation and through the ladder's
// add/sub-then-multiply; then elements whose limbs sit at the carried
// bound (2^27 + 17, either sign), so --debug's overflow checks see the
// largest products the code can form.
import std;
import gslib from "../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.x448;

var failures = 0;
var checks = 0;

fn p448() -> bignum::BigInt {
    bignum::sub(bignum::sub(bignum::shl(bignum::one(), 448), bignum::shl(bignum::one(), 224)), bignum::one())
}

fn value(b: const u8[:]) -> bignum::BigInt { bignum::mod_floor(bignum::from_bytes_le(b), p448()) }

// The value of limbs as they stand, reduced.
fn limb_value(f: const bignum::Fe448&) -> bignum::BigInt {
    var v = bignum::zero();
    var i = 16;
    while i > 0 {
        i--;
        let next = bignum::add(bignum::shl(v, 28), bignum::big(f.v[i]));
        v = copy(next);
    }
    return bignum::mod_floor(v, p448());
}

fn expect(what: const u8[:], got: const u8[:], want) {
    checks++;
    let w = bignum::to_bytes_le(want, 56);
    if got != w {
        failures++;
        if failures <= 10 { print("FAIL ", what, ": got ", bignum::from_bytes_le(got), " want ", want); }
    }
}

fn encode(v) -> u8[56] {
    let b = bignum::to_bytes_le(v, 56);
    var out: u8[56] = [0; 56];
    for i in 56 { out[i] = b[i]; }
    return out;
}

fn main() {
    let p = p448();
    let one = bignum::one();
    var samples: u8[56][>..] = [];
    samples.push(encode(bignum::zero()));
    samples.push(encode(one));
    samples.push(encode(bignum::sub(p, one)));
    samples.push(encode(p));
    samples.push(encode(bignum::add(p, one)));
    samples.push(encode(bignum::sub(bignum::shl(one, 448), one)));      // all ones
    samples.push(encode(bignum::shl(one, 224)));
    samples.push(encode(bignum::shl(one, 447)));
    samples.push(encode(bignum::sub(bignum::shl(one, 224), one)));
    var r = rng { 20261114 };
    for i in 50 {
        var b: u8[56] = [0; 56];
        for j in 56 { b[j] = (r.rand_u64() & 255) as! u8; }
        samples.push(b);
    }
    let pm2 = bignum::sub(p, bignum::big(2));
    let p34 = bignum::shr(bignum::sub(p, bignum::big(3)), 2);
    for sa in samples {
        let fa = bignum::fe448_from_bytes(sa);
        let va = value(sa);
        expect("canonical", bignum::fe448_to_bytes(fa), va);
        expect("neg", bignum::fe448_to_bytes(bignum::fe448_neg(fa)), bignum::mod_floor(bignum::neg(va), p));
        expect("sq", bignum::fe448_to_bytes(bignum::fe448_sq(fa)), bignum::mod_floor(bignum::mul(va, va), p));
        expect("39081", bignum::fe448_to_bytes(bignum::fe448_mul_small(fa, 39081)), bignum::mod_floor(bignum::mul(va, bignum::big(39081)), p));
        expect("invert", bignum::fe448_to_bytes(bignum::fe448_invert(fa)), bignum::modpow(va, pm2, p));
        expect("pow (p-3)/4", bignum::fe448_to_bytes(bignum::fe448_pow_p34(fa)), bignum::modpow(va, p34, p));
        for sb in samples[..14] {
            let fb = bignum::fe448_from_bytes(sb);
            let vb = value(sb);
            expect("mul", bignum::fe448_to_bytes(bignum::fe448_mul(fa, fb)), bignum::mod_floor(bignum::mul(va, vb), p));
            expect("add", bignum::fe448_to_bytes(bignum::fe448_add(fa, fb)), bignum::mod_floor(bignum::add(va, vb), p));
            expect("sub", bignum::fe448_to_bytes(bignum::fe448_sub(fa, fb)), bignum::mod_floor(bignum::sub(va, vb), p));
            let s = bignum::fe448_add(bignum::fe448_mul(fa, fb), bignum::fe448_sq(fb));
            let d = bignum::fe448_sub(bignum::fe448_sq(fa), bignum::fe448_mul(fb, fa));
            let vs = bignum::add(bignum::mul(va, vb), bignum::mul(vb, vb));
            let vd = bignum::sub(bignum::mul(va, va), bignum::mul(vb, va));
            expect("mul(sum, diff)", bignum::fe448_to_bytes(bignum::fe448_mul(s, d)), bignum::mod_floor(bignum::mul(vs, vd), p));
            var x = fa;
            var y = fb;
            bignum::fe448_cswap(x, y, 1);
            expect("cswap", bignum::fe448_to_bytes(x), vb);
            bignum::fe448_cswap(x, y, 0);
            expect("no swap", bignum::fe448_to_bytes(y), va);
        }
    }
    // Limbs at the carried bound, in every sign pattern of a few kinds.
    let top: i64 = (1 << 27) + 17;
    var edges: bignum::Fe448[>..] = [];
    for kind in 4 {
        var f = bignum::fe448_zero();
        for i in 16 {
            f.v[i] = if kind == 0 { top } else if kind == 1 { 0 - top }
                     else if kind == 2 { if i % 2 == 0 { top } else { 0 - top } }
                     else { if i < 8 { 0 - top } else { top } };
        }
        edges.push(f);
    }
    for ea in edges {
        let va = limb_value(ea);
        expect("edge canonical", bignum::fe448_to_bytes(ea), va);
        expect("edge sq", bignum::fe448_to_bytes(bignum::fe448_sq(ea)), bignum::mod_floor(bignum::mul(va, va), p));
        for eb in edges {
            let vb = limb_value(eb);
            expect("edge mul", bignum::fe448_to_bytes(bignum::fe448_mul(ea, eb)), bignum::mod_floor(bignum::mul(va, vb), p));
        }
    }
    print("x448 field: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
