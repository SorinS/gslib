// The GF(2^255 - 19) arithmetic of bignum.x25519 against BigInt: random
// and edge-case encodings (0, 1, p - 1, p, p + 1, 2^255 - 1, all ones),
// through each operation and through the ladder's add/sub-then-multiply.
import std;
import bignum from "..";
import bignum.x25519;

var failures = 0;
var checks = 0;

fn p25519() -> bignum::BigInt { bignum::sub(bignum::shl(bignum::one(), 255), bignum::big(19)) }

// The value an encoding stands for: the top bit dropped, reduced mod p.
fn value(b: const u8[:]) -> bignum::BigInt {
    let low = bignum::sub(bignum::shl(bignum::one(), 255), bignum::one());
    return bignum::mod_floor(bignum::bit_and(bignum::from_bytes_le(b), low), p25519());
}

fn expect(what: const u8[:], got: const u8[:], want) {
    checks++;
    let w = bignum::to_bytes_le(want, 32);
    if got != w {
        failures++;
        if failures <= 10 { print("FAIL ", what, ": got ", bignum::from_bytes_le(got), " want ", want); }
    }
}

fn encode(v) -> u8[32] {
    let b = bignum::to_bytes_le(v, 32);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = b[i]; }
    return out;
}

fn main() {
    let p = p25519();
    var samples: u8[32][>..] = [];
    samples.push(encode(bignum::zero()));
    samples.push(encode(bignum::one()));
    samples.push(encode(bignum::sub(p, bignum::one())));
    samples.push(encode(p));
    samples.push(encode(bignum::add(p, bignum::one())));
    samples.push(encode(bignum::add(p, bignum::big(18))));                     // 2^255 - 1
    samples.push(encode(bignum::sub(bignum::shl(bignum::one(), 256), bignum::one())));   // all ones
    samples.push(encode(bignum::shl(bignum::one(), 254)));
    var r = rng { 20261025 };
    for i in 60 {
        var b: u8[32] = [0; 32];
        for j in 32 { b[j] = (r.rand_u64() & 255) as! u8; }
        samples.push(b);
    }
    let pm2 = bignum::sub(p, bignum::big(2));
    for sa in samples {
        let fa = bignum::fe_from_bytes(sa);
        let va = value(sa);
        expect("canonical", bignum::fe_to_bytes(fa), va);
        expect("sq", bignum::fe_to_bytes(bignum::fe_sq(fa)), bignum::mod_floor(bignum::mul(va, va), p));
        expect("a24", bignum::fe_to_bytes(bignum::fe_mul_a24(fa)), bignum::mod_floor(bignum::mul(va, bignum::big(121665)), p));
        expect("invert", bignum::fe_to_bytes(bignum::fe_invert(fa)), bignum::modpow(va, pm2, p));
        for sb in samples[..12] {
            let fb = bignum::fe_from_bytes(sb);
            let vb = value(sb);
            expect("mul", bignum::fe_to_bytes(bignum::fe_mul(fa, fb)), bignum::mod_floor(bignum::mul(va, vb), p));
            expect("add", bignum::fe_to_bytes(bignum::fe_add(fa, fb)), bignum::mod_floor(bignum::add(va, vb), p));
            expect("sub", bignum::fe_to_bytes(bignum::fe_sub(fa, fb)), bignum::mod_floor(bignum::sub(va, vb), p));
            // The ladder multiplies sums and differences of products.
            let s = bignum::fe_add(bignum::fe_mul(fa, fb), bignum::fe_sq(fb));
            let d = bignum::fe_sub(bignum::fe_sq(fa), bignum::fe_mul(fb, fa));
            let vs = bignum::add(bignum::mul(va, vb), bignum::mul(vb, vb));
            let vd = bignum::sub(bignum::mul(va, va), bignum::mul(vb, va));
            expect("mul(sum, diff)", bignum::fe_to_bytes(bignum::fe_mul(s, d)), bignum::mod_floor(bignum::mul(vs, vd), p));
        }
    }
    print("x25519 field: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
