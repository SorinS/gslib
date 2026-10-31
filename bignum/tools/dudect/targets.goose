// bignum's constant-time code as C functions, for dudect's own harness
// (github.com/oreparaz/dudect, tools/dudect/harness.c): each target takes
// one input, the class's bytes, and returns a byte of its result so that
// nothing is optimized away. scripts/dudect.py builds it (goose -o with
// --header) and runs every target.
//
// The fixed operands (an RSA key, the moduli, the base) are made once, in
// main, which goose_init runs.

import std;
import bignum from "../..";
import bignum.mont;
import bignum.rsa;
import bignum.x25519;
import bignum.ec;
import bignum.ed25519;

var rsa_key = bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
var m512: u32[..16] = [];           // an odd 512-bit modulus, with its R^2 and -1/m
var r2_512: u32[..16] = [];
var m0i_512: u32 = 0;
var x512: u32[..16] = [];
var m1024: u32[..32] = [];
var big_m: u8[..64] = [];           // the control's modulus, as bytes
var big_x: u8[..64] = [];

fn pseudo(seed: u32, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    var s = seed;
    for i in n {
        s = s * 1664525 + 1013904223;
        out.push((s >> 24) as! u8);
    }
    return out;
}

fn main() {
    rsa_key = bignum::rsa_generate(1024);
    var mb = pseudo(7, 64);
    mb[0] = mb[0] | 0x80;
    mb[63] = mb[63] | 1;
    m512.resize(16, 0);
    bignum::limbs_from_be(m512, mb);
    m0i_512 = bignum::mont_m0i(m512[0]);
    r2_512.resize(16, 0);
    bignum::mont_r2(r2_512, m512);
    var xb = pseudo(8, 64);
    xb[0] = xb[0] & 0x7f;
    x512.resize(16, 0);
    bignum::limbs_from_be(x512, xb);
    var mb2 = pseudo(9, 128);
    mb2[0] = mb2[0] | 0x80;
    mb2[127] = mb2[127] | 1;
    m1024.resize(32, 0);
    bignum::limbs_from_be(m1024, mb2);
    big_m.append(mb);
    big_x.append(xb);
}

// The control, which must be caught: BigInt's modpow, whose time follows
// the exponent's bits.
export fn dut_control_modpow(data: const u8[:]) -> u8 {
    let y = bignum::modpow(bignum::from_bytes_be(big_x), bignum::from_bytes_be(data), bignum::from_bytes_be(big_m));
    let b = bignum::to_bytes_be(y, 64);
    return b[63];
}

// x^e mod m, 512 bits, e the input (64 bytes).
export fn dut_mont_modexp(data: const u8[:]) -> u8 {
    var e: u32[16] = [0; 16];
    bignum::limbs_from_be(e, data[..64]);
    var out: u32[16] = [0; 16];
    bignum::mont_modexp(out, x512, e, m512, m0i_512, r2_512);
    return out[0] as! u8;
}

// 1/a mod m, 1024 bits, a the input (128 bytes, its top bit cleared).
export fn dut_ct_mod_inv(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    a[31] = a[31] & 0x7fffffff;
    var inv: u32[32] = [0; 32];
    let ok = bignum::ct_mod_inv(inv, a, m1024);
    return (inv[0] as! u8) ^ (ok as! u8);
}

// A negative control, constant time by construction: ct_mod_small's
// instruction mix (multiplies by constants, shifts, xors, no select)
// over the same input, to show what this machine's noise floor is at the
// same number of measurements.
export fn dut_plain_mix(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    var r: u64 = 0;
    var i = 32;
    while i > 0 {
        i--;
        let x = (r << 16) | ((a[i] >> 16) as u64);
        r = (x - ((x * 2148557) >> 32) * 1999) & 0xffffffff;
        let y = (r << 16) | ((a[i] & 0xffff) as u64);
        r = (y - ((y * 2148557) >> 32) * 1999) & 0xffffffff;
    }
    return r as! u8;
}

// a mod 1999, a the input as 32 limbs (128 bytes).
export fn dut_ct_mod_small(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    return bignum::ct_mod_small(a, 1999) as! u8;
}

// The RSA private operation, 1024 bits, on the input (128 bytes, first 0).
export fn dut_rsa_private_op(data: const u8[:]) -> u8 {
    var x: u8[128] = [0; 128];
    for i in 1..128 { x[i] = data[i]; }
    let y, ok = bignum::rsa_private_op(rsa_key, x);
    return if ok { y[127] } else { 0 };
}

// RSA's x^e mod n in constant time (encryption of a secret), on the input.
export fn dut_rsa_public_op_ct(data: const u8[:]) -> u8 {
    var x: u8[128] = [0; 128];
    for i in 1..128 { x[i] = data[i]; }
    let y, ok = bignum::rsa_public_op_ct(rsa_key, x);
    return if ok { y[127] } else { 0 };
}

// X25519 on the base point, the input the scalar (32 bytes).
export fn dut_x25519_base(data: const u8[:]) -> u8 {
    let pk = bignum::x25519_base(data[..32]);
    return pk[0];
}

// ECDSA P-256 signing of one message, the input the private key (32
// bytes, top bit cleared so that it is below n).
export fn dut_ecdsa_p256_sign(data: const u8[:]) -> u8 {
    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = data[i]; }
    sk[0] = sk[0] & 0x7f;
    let curve = bignum::p256();
    let sig = bignum::ecdsa_sign(curve, sk, "a message");
    return sig[0];
}

// Ed25519 signing of one message, the input the seed (32 bytes).
export fn dut_ed25519_sign(data: const u8[:]) -> u8 {
    let sig = bignum::ed25519_sign(data[..32], "a message");
    return sig[0];
}
