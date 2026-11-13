// The constant-time layer, for building a protocol of your own on secret
// numbers: bignum.ct's masks and comparisons, and bignum.mont's
// Montgomery exponentiation and inverse over fixed-width limbs, whose time
// depends on the lengths alone. Each result is checked against BigInt,
// which is variable time and fit only for public values.
//
//   goose examples/bignum/constant_time.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.ct;
import gslib.crypto.bignum.mont;
import gslib.crypto.bignum.ffdh;
import gslib.crypto.bignum.entropy;

fn fail(what: const u8[:]) { print("constant_time: ", what); exit(1); }

// Limbs of a big-endian number, at the width of `width` bytes.
fn limbs(b: const u8[:], width: i64) -> u32[>..] {
    var out: u32[>..] = [];
    out.resize((width + 3) / 4, 0);
    bignum::limbs_from_be(out, b);
    return out;
}

fn main() {
    // Comparisons with no early exit: for tags, MACs and passwords.
    let a = "expected tag 0123";
    guard bignum::ct_eq_bytes(a, "expected tag 0123") == 1 && bignum::ct_eq_bytes(a, "expected tag 0124") == 0 else {
        fail("ct_eq_bytes");
    }
    // Select without a branch: a mask is 0 or all ones, from a 0/1 bit.
    let secret_bit: u32 = 1;
    let m = bignum::ct_mask(secret_bit);
    guard bignum::ct_select_u32(m, 10, 20) == 10 && bignum::ct_select_u32(bignum::ct_mask(0), 10, 20) == 20 else {
        fail("ct_select_u32");
    }
    var x: u32[4] = [1, 2, 3, 4];
    var y: u32[4] = [5, 6, 7, 8];
    bignum::ct_cswap(m, x, y);
    guard x[0] == 5 && y[0] == 1 && bignum::ct_lt(x, y) == 0 else { fail("ct_cswap/ct_lt"); }
    print("masks, selects, swaps and comparisons ok");

    // A secret exponent raised in constant time, mod the 2048-bit RFC 3526
    // prime (what bignum.ffdh does inside): g^e mod p.
    let p = bignum::ffdh_prime(14);
    var e: u8[32] = [0; 32];
    bignum::random_bytes(e);
    let pm = limbs(p, p.len);
    let gl = limbs("\x02", p.len);
    let el = limbs(e, e.len);
    var r2 = limbs("", p.len);
    bignum::mont_r2(r2, pm);                 // R^2 mod p, once per modulus
    var r = limbs("", p.len);
    let t0 = clock();
    bignum::mont_modexp(r, gl, el, pm, bignum::mont_m0i(pm[0]), r2);
    let ms = ((clock() - t0) * 1000.0) as i64;
    var out: u8[>..] = [];
    out.resize(p.len, 0);
    bignum::be_from_limbs(out, r);
    let want = bignum::modpow(bignum::big(2), bignum::from_bytes_be(e), bignum::from_bytes_be(p));
    guard bignum::eq(bignum::from_bytes_be(out), want) else { fail("mont_modexp"); }
    print("2^e mod p (2048-bit p, 256-bit e) in ", ms, " ms, equal to BigInt's modpow");

    // A constant-time inverse mod an odd modulus: a * (1/a) = 1 mod p.
    var inv = limbs("", p.len);
    let al = limbs(out, p.len);
    let invertible = bignum::ct_mod_inv(inv, al, pm);
    let check = bignum::mod_floor(bignum::mul(bignum::from_bytes_be(out), bignum::big_of(inv)), bignum::from_bytes_be(p));
    guard invertible == 1 && bignum::cmp_i64(check, 1) == 0 else { fail("ct_mod_inv"); }
    print("inverse mod p checked");
}
