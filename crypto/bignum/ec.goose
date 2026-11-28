// bignum.ec: the NIST curves P-224, P-256, P-384 and P-521 (y^2 = x^3 -
// 3x + b over a prime field) and the Brainpool curves brainpoolP256r1,
// P384r1 and P512r1 (y^2 = x^3 + ax + b, RFC 5639): ECDH key agreement,
// and ECDSA with SHA-224 on P-224, SHA-256 on P-256 and brainpoolP256r1,
// SHA-384 on P-384 and brainpoolP384r1 and SHA-512 on P-521 and
// brainpoolP512r1, its nonces derived deterministically (RFC 6979).
//
// One generic implementation serves all seven: field elements are
// limbs of the curve's width (7, 8, 12, 16 or 17) in Montgomery form, multiplied by
// bignum.mont. Points are projective and added by the complete formulas of
// Renes, Costello and Batina (2016: algorithm 4 for a = -3, algorithm 1
// for any a), which have no exceptional cases, so doubling is an addition
// and the point at infinity needs no branch. Scalar multiplication takes
// 4-bit windows over the full scalar width with a table read by scanning,
// so its time does not depend on the scalar or the point. Verifying, whose
// inputs are all public, computes u1 G + u2 Q in one variable-time pass.

namespace bignum;

import std;
import crypto.bignum;
import crypto.bignum.ct;
import crypto.bignum.mont;
import crypto.bignum.hmac;
import entropy;

// The field prime p and group order n with their Montgomery constants, and
// p - 2, n - 2 for inversion by Fermat. a, b, b3 = 3b, gx and gy are in
// Montgomery form; a_is_minus3 picks the faster addition (public).
struct Curve {
    nl: i64, len: i64, bits: i64, hash: i64,     // limbs, bytes and bits of n, the signing hash
    p: u32[..17], p0i: u32, r2p: u32[..17], pm2: u32[..17],
    n: u32[..17], n0i: u32, r2n: u32[..17], nm2: u32[..17],
    a: u32[..17], b: u32[..17], b3: u32[..17], gx: u32[..17], gy: u32[..17],
    a_is_minus3: bool,
}

// Projective (X : Y : Z), Montgomery form; (0 : 1 : 0) is infinity.
struct EcPoint { x: u32[..17], y: u32[..17], z: u32[..17] }

fn ec_zero(c: const Curve&) -> u32[..17] {
    var r: u32[..17] = [];
    r.resize(c.nl, 0);
    return r;
}

fn ec_limbs(c: const Curve&, v) -> u32[..17] {
    var r = ec_zero(c);
    for i in v.mag.len { r[i] = v.mag[i]; }
    return r;
}

fn ec_hex(c: const Curve&, s: const u8[:]) -> u32[..17] {
    let v, ok = parse(s, 16);
    assert(ok);
    return ec_limbs(c, v);
}

// Field arithmetic mod p.
fn fmul(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    var t: u32[19] = [0; 19];
    mont_mul(r[..], a, b, c.p[..], c.p0i, t[..c.nl + 2]);
    return r;
}

fn fadd(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_add(r[..], a, b, c.p[..]);
    return r;
}

fn fsub(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_sub(r[..], a, b, c.p[..]);
    return r;
}

fn to_mont(c: const Curve&, a: const u32[:]) -> u32[..17] { fmul(c, a, c.r2p[..]) }

fn from_mont(c: const Curve&, a: const u32[:]) -> u32[..17] {
    var one = ec_zero(c);
    one[0] = 1;
    return fmul(c, a, one[..]);
}

// 1/a mod p in normal form (0 for 0).
fn finv(c: const Curve&, a: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    mont_modexp(r[..], a, c.pm2[..], c.p[..], c.p0i, c.r2p[..]);
    return r;
}

// Arithmetic mod n, in normal form.
fn nmul(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    var t1 = ec_zero(c);
    var t: u32[19] = [0; 19];
    mont_mul(t1[..], a, b, c.n[..], c.n0i, t[..c.nl + 2]);
    mont_mul(r[..], t1[..], c.r2n[..], c.n[..], c.n0i, t[..c.nl + 2]);
    return r;
}

fn nadd(c: const Curve&, a: const u32[:], b: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    ct_mod_add(r[..], a, b, c.n[..]);
    return r;
}

fn ninv(c: const Curve&, a: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    mont_modexp(r[..], a, c.nm2[..], c.n[..], c.n0i, c.r2n[..]);
    return r;
}

// x mod n for x < 2n, as any value below p is (p < 2n on every curve here:
// n is within 2 sqrt(p) of p, the cofactor being 1).
fn nreduce(c: const Curve&, x: const u32[:]) -> u32[..17] {
    var r = ec_zero(c);
    for i in c.nl { r[i] = x[i]; }
    ct_cond_sub(r[..], 0, c.n[..]);
    return r;
}

// x -= 2, for any x >= 2 (the borrow runs through, as P-224's prime ends
// in ...0001).
fn ec_sub2(x: u32[:]) {
    var borrow: u64 = 2;
    for i in x.len {
        let t = x[i] - borrow;
        x[i] = t as! u32;
        borrow = (t >> 32) & 1;
    }
}

// A curve from its hex constants; an empty a means a = -3.
fn ec_curve(nl: i64, bits: i64, hash: i64, p: const u8[:], a: const u8[:], n: const u8[:],
            b: const u8[:], gx: const u8[:], gy: const u8[:]) -> Curve {
    var c = Curve {
        nl: nl, len: (bits + 7) / 8, bits: bits, hash: hash,
        p: [], p0i: 0, r2p: [], pm2: [], n: [], n0i: 0, r2n: [], nm2: [],
        a: [], b: [], b3: [], gx: [], gy: [], a_is_minus3: a.len == 0,
    };
    c.p = ec_hex(c, p);
    c.n = ec_hex(c, n);
    c.p0i = mont_m0i(c.p[0]);
    c.n0i = mont_m0i(c.n[0]);
    c.r2p = ec_zero(c);
    mont_r2(c.r2p[..], c.p[..]);
    c.r2n = ec_zero(c);
    mont_r2(c.r2n[..], c.n[..]);
    c.pm2 = c.p;
    ec_sub2(c.pm2[..]);
    c.nm2 = c.n;
    ec_sub2(c.nm2[..]);
    if c.a_is_minus3 {
        var three = ec_zero(c);
        three[0] = 3;
        c.a = fsub(c, ec_zero(c)[..], to_mont(c, three[..])[..]);
    } else {
        c.a = to_mont(c, ec_hex(c, a)[..]);
    }
    c.b = to_mont(c, ec_hex(c, b)[..]);
    c.b3 = fadd(c, fadd(c, c.b[..], c.b[..])[..], c.b[..]);
    c.gx = to_mont(c, ec_hex(c, gx)[..]);
    c.gy = to_mont(c, ec_hex(c, gy)[..]);
    return c;
}

// secp224r1 (FIPS 186-4 D.1.2.2), signing with SHA-224.
fn p224() -> Curve {
    ec_curve(7, 224, 224,
        "ffffffffffffffffffffffffffffffff000000000000000000000001",
        "",
        "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
        "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
        "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
        "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34")
}

// secp256r1 (FIPS 186-4 D.1.2.3), signing with SHA-256.
fn p256() -> Curve {
    ec_curve(8, 256, 256,
        "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
        "",
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}

// secp384r1 (FIPS 186-4 D.1.2.4), signing with SHA-384.
fn p384() -> Curve {
    ec_curve(12, 384, 384,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
        "",
        "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
        "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
        "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
        "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
}

// secp521r1 (FIPS 186-4 D.1.2.5), signing with SHA-512.
fn p521() -> Curve {
    ec_curve(17, 521, 512,
        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "",
        "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
        "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
        "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
        "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650")
}

// brainpoolP256r1 (RFC 5639 §3.4), signing with SHA-256.
fn bp256() -> Curve {
    ec_curve(8, 256, 256,
        "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
        "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
        "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
        "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
        "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
        "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997")
}

// brainpoolP384r1 (RFC 5639 §3.6), signing with SHA-384.
fn bp384() -> Curve {
    ec_curve(12, 384, 384,
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53",
        "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826",
        "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565",
        "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11",
        "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e",
        "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315")
}

// brainpoolP512r1 (RFC 5639 §3.7), signing with SHA-512.
fn bp512() -> Curve {
    ec_curve(16, 512, 512,
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
        "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
        "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
        "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
        "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
        "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892")
}

// secp256k1 (SEC 2 §2.4.1), a = 0, signing with SHA-256: Bitcoin's
// curve, which KMIP's Recommended Curve names.
fn secp256k1() -> Curve {
    ec_curve(8, 256, 256,
        "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
        "00",
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "0000000000000000000000000000000000000000000000000000000000000007",
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
}

fn ec_infinity(c: const Curve&) -> EcPoint {
    var y = ec_zero(c);
    y[0] = 1;
    return EcPoint { x: ec_zero(c), y: to_mont(c, y[..]), z: ec_zero(c) };
}

fn ec_generator(c: const Curve&) -> EcPoint {
    var z = ec_zero(c);
    z[0] = 1;
    return EcPoint { x: c.gx, y: c.gy, z: to_mont(c, z[..]) };
}

// p + q by the complete formulas: algorithm 4 of Renes, Costello and Batina
// when a = -3, else their algorithm 1. The choice is the curve's, public.
fn ec_add(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    if c.a_is_minus3 { return ec_add_m3(c, p, q); }
    return ec_add_any(c, p, q);
}

// Algorithm 4 (a = -3): 12 multiplications and 2 by b.
fn ec_add_m3(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    var t0 = fmul(c, p.x[..], q.x[..]);
    var t1 = fmul(c, p.y[..], q.y[..]);
    var t2 = fmul(c, p.z[..], q.z[..]);
    var t3 = fadd(c, p.x[..], p.y[..]);
    var t4 = fadd(c, q.x[..], q.y[..]);
    t3 = fmul(c, t3[..], t4[..]);
    t4 = fadd(c, t0[..], t1[..]);
    t3 = fsub(c, t3[..], t4[..]);
    t4 = fadd(c, p.y[..], p.z[..]);
    var x3 = fadd(c, q.y[..], q.z[..]);
    t4 = fmul(c, t4[..], x3[..]);
    x3 = fadd(c, t1[..], t2[..]);
    t4 = fsub(c, t4[..], x3[..]);
    x3 = fadd(c, p.x[..], p.z[..]);
    var y3 = fadd(c, q.x[..], q.z[..]);
    x3 = fmul(c, x3[..], y3[..]);
    y3 = fadd(c, t0[..], t2[..]);
    y3 = fsub(c, x3[..], y3[..]);
    var z3 = fmul(c, c.b[..], t2[..]);
    x3 = fsub(c, y3[..], z3[..]);
    z3 = fadd(c, x3[..], x3[..]);
    x3 = fadd(c, x3[..], z3[..]);
    z3 = fsub(c, t1[..], x3[..]);
    x3 = fadd(c, t1[..], x3[..]);
    y3 = fmul(c, c.b[..], y3[..]);
    t1 = fadd(c, t2[..], t2[..]);
    t2 = fadd(c, t1[..], t2[..]);
    y3 = fsub(c, y3[..], t2[..]);
    y3 = fsub(c, y3[..], t0[..]);
    t1 = fadd(c, y3[..], y3[..]);
    y3 = fadd(c, t1[..], y3[..]);
    t1 = fadd(c, t0[..], t0[..]);
    t0 = fadd(c, t1[..], t0[..]);
    t0 = fsub(c, t0[..], t2[..]);
    t1 = fmul(c, t4[..], y3[..]);
    t2 = fmul(c, t0[..], y3[..]);
    y3 = fmul(c, x3[..], z3[..]);
    y3 = fadd(c, y3[..], t2[..]);
    x3 = fmul(c, t3[..], x3[..]);
    x3 = fsub(c, x3[..], t1[..]);
    z3 = fmul(c, t4[..], z3[..]);
    t1 = fmul(c, t3[..], t0[..]);
    z3 = fadd(c, z3[..], t1[..]);
    return EcPoint { x: x3, y: y3, z: z3 };
}

// Algorithm 1 (any a): 12 multiplications, 3 by a and 2 by b3 = 3b.
fn ec_add_any(c: const Curve&, p: const EcPoint&, q: const EcPoint&) -> EcPoint {
    var t0 = fmul(c, p.x[..], q.x[..]);
    var t1 = fmul(c, p.y[..], q.y[..]);
    var t2 = fmul(c, p.z[..], q.z[..]);
    var t3 = fadd(c, p.x[..], p.y[..]);
    var t4 = fadd(c, q.x[..], q.y[..]);
    t3 = fmul(c, t3[..], t4[..]);
    t4 = fadd(c, t0[..], t1[..]);
    t3 = fsub(c, t3[..], t4[..]);                // X1 Y2 + X2 Y1
    t4 = fadd(c, p.x[..], p.z[..]);
    var t5 = fadd(c, q.x[..], q.z[..]);
    t4 = fmul(c, t4[..], t5[..]);
    t5 = fadd(c, t0[..], t2[..]);
    t4 = fsub(c, t4[..], t5[..]);                // X1 Z2 + X2 Z1
    t5 = fadd(c, p.y[..], p.z[..]);
    var x3 = fadd(c, q.y[..], q.z[..]);
    t5 = fmul(c, t5[..], x3[..]);
    x3 = fadd(c, t1[..], t2[..]);
    t5 = fsub(c, t5[..], x3[..]);                // Y1 Z2 + Y2 Z1
    var z3 = fmul(c, c.a[..], t4[..]);
    x3 = fmul(c, c.b3[..], t2[..]);
    z3 = fadd(c, x3[..], z3[..]);
    x3 = fsub(c, t1[..], z3[..]);
    z3 = fadd(c, t1[..], z3[..]);
    var y3 = fmul(c, x3[..], z3[..]);
    t1 = fadd(c, t0[..], t0[..]);
    t1 = fadd(c, t1[..], t0[..]);
    t2 = fmul(c, c.a[..], t2[..]);
    t4 = fmul(c, c.b3[..], t4[..]);
    t1 = fadd(c, t1[..], t2[..]);
    t2 = fsub(c, t0[..], t2[..]);
    t2 = fmul(c, c.a[..], t2[..]);
    t4 = fadd(c, t4[..], t2[..]);
    t0 = fmul(c, t1[..], t4[..]);
    y3 = fadd(c, y3[..], t0[..]);
    t0 = fmul(c, t5[..], t4[..]);
    x3 = fmul(c, t3[..], x3[..]);
    x3 = fsub(c, x3[..], t0[..]);
    t0 = fmul(c, t3[..], t1[..]);
    z3 = fmul(c, t5[..], z3[..]);
    z3 = fadd(c, z3[..], t0[..]);
    return EcPoint { x: x3, y: y3, z: z3 };
}

// dst = src when mask is all ones.
fn ec_select(c: const Curve&, dst: EcPoint&, src: const EcPoint&, mask: u32) {
    for i in c.nl {
        dst.x[i] = ct_select_u32(mask, src.x[i], dst.x[i]);
        dst.y[i] = ct_select_u32(mask, src.y[i], dst.y[i]);
        dst.z[i] = ct_select_u32(mask, src.z[i], dst.z[i]);
    }
}

// k * p for a scalar of the curve's width, in constant time.
fn ec_mul(c: const Curve&, k: const u32[:], p: const EcPoint&) -> EcPoint {
    var tab: EcPoint[16] = [ec_infinity(c); 16];
    tab[1] = p;
    for i in 2..16 { tab[i] = ec_add(c, tab[i - 1], p); }
    var acc = ec_infinity(c);
    var w = 8 * k.len;
    while w > 0 {
        w--;
        for s in 4 {
            let d = ec_add(c, acc, acc);
            acc = d;
        }
        let win = exp_window(k, w);
        var sel = ec_infinity(c);
        for j in 16 { ec_select(c, sel, tab[j], ct_mask(ct_eq_u32(win, j as! u32))); }
        let sum = ec_add(c, acc, sel);
        acc = sum;
    }
    return acc;
}

// u1 g + u2 q in one pass (Straus: both scalars' 4-bit windows under the
// same doublings), for verifying, where every input is public. The time
// depends on the scalars: a zero window adds nothing, and the doublings
// start at the first nonzero window.
fn ec_mul2_vartime(c: const Curve&, u1: const u32[:], g: const EcPoint&, u2: const u32[:], q: const EcPoint&) -> EcPoint {
    var tg: EcPoint[16] = [ec_infinity(c); 16];
    var tq: EcPoint[16] = [ec_infinity(c); 16];
    tg[1] = g;
    tq[1] = q;
    for i in 2..16 {
        tg[i] = ec_add(c, tg[i - 1], g);
        tq[i] = ec_add(c, tq[i - 1], q);
    }
    var acc = ec_infinity(c);
    var started = false;
    var w = 8 * u1.len;
    while w > 0 {
        w--;
        if started {
            for s in 4 {
                let d = ec_add(c, acc, acc);
                acc = d;
            }
        }
        let w1 = exp_window(u1, w);
        if w1 != 0 {
            let sum = ec_add(c, acc, tg[w1]);
            acc = sum;
            started = true;
        }
        let w2 = exp_window(u2, w);
        if w2 != 0 {
            let sum = ec_add(c, acc, tq[w2]);
            acc = sum;
            started = true;
        }
    }
    return acc;
}

// Affine x and y in normal form, and false for infinity.
fn ec_affine(c: const Curve&, p: const EcPoint&) -> u32[..17], u32[..17], bool {
    let z = from_mont(c, p.z[..]);
    let ok = ct_is_zero(z[..]) == 0;
    let zi = to_mont(c, finv(c, z[..])[..]);
    let x = from_mont(c, fmul(c, p.x[..], zi[..])[..]);
    let y = from_mont(c, fmul(c, p.y[..], zi[..])[..]);
    return x, y, ok;
}

// The uncompressed encoding 04 || x || y (SEC 1 §2.3.3), as TLS sends it.
fn ec_encode(c: const Curve&, p: const EcPoint&) -> u8[>..] {
    let x, y, ok = ec_affine(c, p);
    assert(ok);
    var out: u8[>..] = [];
    out.resize(1 + 2 * c.len, 0);
    out[0] = 4;
    be_from_limbs(out[1..1 + c.len], x[..]);
    be_from_limbs(out[1 + c.len..], y[..]);
    return out;
}

// x^3 + ax + b, for x in Montgomery form.
fn ec_rhs(c: const Curve&, xm: const u32[:]) -> u32[..17] {
    let x2 = fmul(c, xm, xm);
    let x3 = fmul(c, x2[..], xm);
    let ax = fmul(c, c.a[..], xm);
    return fadd(c, fadd(c, x3[..], ax[..])[..], c.b[..]);
}

// A point from its uncompressed encoding, checked to lie on the curve
// (which, with cofactor 1, also puts it in the group). Public data.
fn ec_decode(c: const Curve&, s: const u8[:]) -> EcPoint, bool {
    var p = ec_infinity(c);
    if s.len != 1 + 2 * c.len || s[0] != 4 { return p, false; }
    var x = ec_zero(c);
    var y = ec_zero(c);
    limbs_from_be(x[..], s[1..1 + c.len]);
    limbs_from_be(y[..], s[1 + c.len..]);
    if ct_lt(x[..], c.p[..]) == 0 || ct_lt(y[..], c.p[..]) == 0 { return p, false; }
    let xm = to_mont(c, x[..]);
    let ym = to_mont(c, y[..]);
    // y^2 == x^3 + ax + b
    let lhs = fmul(c, ym[..], ym[..]);
    let rhs = ec_rhs(c, xm[..]);
    if ct_eq(lhs[..], rhs[..]) == 0 { return p, false; }
    p.x = xm;
    p.y = ym;
    var one = ec_zero(c);
    one[0] = 1;
    p.z = to_mont(c, one[..]);
    return p, true;
}

// -p: (X : -Y : Z).
fn ec_neg(c: const Curve&, p: const EcPoint&) -> EcPoint {
    return EcPoint { x: p.x, y: fsub(c, ec_zero(c)[..], p.y[..]), z: p.z };
}

// The compressed encoding 02 or 03 (y's parity) || x (SEC 1 §2.3.3).
fn ec_encode_compressed(c: const Curve&, p: const EcPoint&) -> u8[>..] {
    let x, y, ok = ec_affine(c, p);
    assert(ok);
    var out: u8[>..] = [];
    out.resize(1 + c.len, 0);
    out[0] = 2 | ((y[0] & 1) as! u8);
    be_from_limbs(out[1..], x[..]);
    return out;
}

// A point from its compressed encoding (SEC 1 §2.3.4): y the square root
// of x^3 + ax + b of the parity asked, v^((p+1)/4) as p = 3 (mod 4) on
// P-256, P-384, P-521 and the three Brainpool curves (false on P-224,
// whose p is not). False for an x not below p or with no point. Public data.
fn ec_decode_compressed(c: const Curve&, s: const u8[:]) -> EcPoint, bool {
    var p = ec_infinity(c);
    if s.len != 1 + c.len || (s[0] != 2 && s[0] != 3) || c.p[0] & 3 != 3 { return p, false; }
    var x = ec_zero(c);
    limbs_from_be(x[..], s[1..]);
    if ct_lt(x[..], c.p[..]) == 0 { return p, false; }
    let xm = to_mont(c, x[..]);
    let rhs = ec_rhs(c, xm[..]);
    // (p + 1) / 4 = (p >> 2) + 1, as p = 3 (mod 4).
    var e = ec_zero(c);
    for i in c.nl {
        e[i] = c.p[i] >> 2;
        if i + 1 < c.nl { e[i] = e[i] | c.p[i + 1] << 30; }
    }
    var carry: u64 = 1;
    for i in c.nl {
        let t = e[i] + carry;
        e[i] = t as! u32;
        carry = t >> 32;
    }
    var y = ec_zero(c);
    mont_modexp(y[..], from_mont(c, rhs[..])[..], e[..], c.p[..], c.p0i, c.r2p[..]);
    var ym = to_mont(c, y[..]);
    if ct_eq(fmul(c, ym[..], ym[..])[..], rhs[..]) == 0 { return p, false; }
    if (y[0] & 1) != (s[0] & 1) { ym = fsub(c, ec_zero(c)[..], ym[..]); }
    p.x = xm;
    p.y = ym;
    var one = ec_zero(c);
    one[0] = 1;
    p.z = to_mont(c, one[..]);
    return p, true;
}

// A private scalar from its big-endian bytes; false unless 1 <= k < n.
fn ec_scalar(c: const Curve&, sk: const u8[:]) -> u32[..17], bool {
    var k = ec_zero(c);
    if sk.len != c.len { return k, false; }
    limbs_from_be(k[..], sk);
    let ok = (ct_lt(k[..], c.n[..]) & (ct_is_zero(k[..]) ^ 1)) == 1;
    return k, ok;
}

// The public key for a private key: 1 + 2 * len bytes.
fn ec_public_key(c: const Curve&, sk: const u8[:]) -> u8[>..] {
    let k, ok = ec_scalar(c, sk);
    assert(ok);
    let g = ec_generator(c);
    let pt = ec_mul(c, k[..], g);
    return ec_encode(c, pt);
}

// A fresh key pair from the OS's entropy: private (len bytes), public.
fn ec_keypair(c: const Curve&) -> u8[>..], u8[>..] {
    var sk: u8[>..] = [];
    sk.resize(c.len, 0);
    loop {
        entropy::random_bytes(sk);
        let k, ok = ec_scalar(c, sk);
        if ok { break; }
    }
    return sk, ec_public_key(c, sk);
}

// ECDH: the x-coordinate of sk * peer (len bytes), and false when the
// peer's key is not a valid point or the private key is out of range.
fn ecdh_shared(c: const Curve&, sk: const u8[:], peer: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let q, okq = ec_decode(c, peer);
    let k, okk = ec_scalar(c, sk);
    if !okq || !okk { return out, false; }
    let pt = ec_mul(c, k[..], q);
    let x, y, ok = ec_affine(c, pt);
    if !ok { return out, false; }
    out.resize(c.len, 0);
    be_from_limbs(out, x[..]);
    return out, true;
}

// The leftmost bits of a string, as many as the order has, as a scalar
// (bits2int of RFC 6979 §2.3.2).
fn ec_bits2int(c: const Curve&, h: const u8[:]) -> u32[..17] {
    var e = ec_zero(c);
    let nb = ::min(h.len, c.len);
    limbs_from_be(e[..], h[..nb]);
    let excess = 8 * nb - c.bits;
    if excess > 0 {
        let sh: u32 = excess as! u32;
        for i in c.nl {
            let hi: u32 = if i + 1 < c.nl { e[i + 1] << (32 - sh) } else { 0 };
            e[i] = (e[i] >> sh) | hi;
        }
    }
    return e;
}

// ECDSA signature of msg, hashed with the curve's hash: r || s, each len
// bytes. The nonce comes from HMAC-DRBG over the key and the hash (RFC
// 6979 §3.2), so signing needs no randomness and repeats exactly.
fn ecdsa_sign(c: const Curve&, sk: const u8[:], msg: const u8[:]) -> u8[>..] {
    let h = hash_bits(c.hash, msg);
    return ecdsa_sign_digest(c, sk, h, c.hash);
}

// ECDSA over a digest made by the hash `hash_id` (a bignum.hmac id), which
// RFC 6979's HMAC-DRBG then uses too. A digest of another length (a
// caller's own, as PKCS #11's CKM_ECDSA takes) is taken as bits2int
// takes any: its leftmost bits, as many as the order has.
fn ecdsa_sign_digest(c: const Curve&, sk: const u8[:], h: const u8[:], hash_id: i64) -> u8[>..] {
    let d, okd = ec_scalar(c, sk);
    assert(okd);
    assert(h.len > 0);
    let e = nreduce(c, ec_bits2int(c, h)[..]);
    let hl = hash_len(hash_id);
    var h1: u8[>..] = [];
    h1.resize(c.len, 0);
    be_from_limbs(h1, e[..]);
    var v: u8[>..] = [];
    v.resize(hl, 1);
    var k: u8[>..] = [];
    k.resize(hl, 0);
    var m: u8[>..] = [];
    for round in 2 {
        m.clear();
        m.append(v);
        m.push(round as! u8);
        m.append(sk);
        m.append(h1);
        let nk = hmac(hash_id, k, m);
        k = copy(nk);
        let nv = hmac(hash_id, k, v);
        v = copy(nv);
    }
    let g = ec_generator(c);
    loop {
        // T: HMAC blocks until there are as many bits as the order has.
        var tt: u8[>..] = [];
        while tt.len < c.len {
            let nv = hmac(hash_id, k, v);
            v = copy(nv);
            tt.append(v);
        }
        let kk = ec_bits2int(c, tt);
        let okk = (ct_lt(kk[..], c.n[..]) & (ct_is_zero(kk[..]) ^ 1)) == 1;
        if okk {
            let kg = ec_mul(c, kk[..], g);
            let x, y, ok = ec_affine(c, kg);
            let r = nreduce(c, x[..]);
            if ct_is_zero(r[..]) == 0 {
                let s = nmul(c, ninv(c, kk[..])[..], nadd(c, e[..], nmul(c, r[..], d[..])[..])[..]);
                if ct_is_zero(s[..]) == 0 {
                    var sig: u8[>..] = [];
                    sig.resize(2 * c.len, 0);
                    be_from_limbs(sig[..c.len], r[..]);
                    be_from_limbs(sig[c.len..], s[..]);
                    return sig;
                }
            }
        }
        m.clear();
        m.append(v);
        m.push(0);
        let nk = hmac(hash_id, k, m);
        k = copy(nk);
        let nv = hmac(hash_id, k, v);
        v = copy(nv);
    }
}

// Verifies an r || s signature on a digest made by any hash.
fn ecdsa_verify_digest(c: const Curve&, pk: const u8[:], digest: const u8[:], sig: const u8[:]) -> bool {
    if sig.len != 2 * c.len { return false; }
    let q, okq = ec_decode(c, pk);
    let r, okr = ec_scalar(c, sig[..c.len]);
    let s, oks = ec_scalar(c, sig[c.len..]);
    if !okq || !okr || !oks { return false; }
    let e = nreduce(c, ec_bits2int(c, digest)[..]);
    let w = ninv(c, s[..]);
    let u1 = nmul(c, e[..], w[..]);
    let u2 = nmul(c, r[..], w[..]);
    let g = ec_generator(c);
    let pt = ec_mul2_vartime(c, u1[..], g, u2[..], q);
    let x, y, ok = ec_affine(c, pt);
    if !ok { return false; }
    return ct_eq(nreduce(c, x[..])[..], r[..]) == 1;
}

// Verifies an r || s signature on msg, hashed with the curve's hash.
fn ecdsa_verify(c: const Curve&, pk: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool {
    ecdsa_verify_digest(c, pk, hash_bits(c.hash, msg), sig)
}

// r || s as the DER SEQUENCE { INTEGER r, INTEGER s } of TLS and X.509.
fn der_uint(out: u8[>..]&, v: const u8[:]) {
    var i = 0;
    while i < v.len - 1 && v[i] == 0 { i++; }
    let lead0 = v[i] >= 0x80;
    out.push(2);
    out.push((v.len - i + (if lead0 { 1 } else { 0 })) as! u8);
    if lead0 { out.push(0); }
    out.append(v[i..]);
}

fn ecdsa_sig_to_der(raw: const u8[:]) -> u8[>..] {
    assert(raw.len % 2 == 0 && raw.len <= 132);
    let half = raw.len / 2;
    var body: u8[>..] = [];
    der_uint(body, raw[..half]);
    der_uint(body, raw[half..]);
    var out: u8[>..] = [];
    out.push(0x30);
    if body.len >= 128 { out.push(0x81); }      // P-521's and brainpoolP512r1's can pass 127 bytes
    out.push(body.len as! u8);
    out.append(body);
    return out;
}

// Reads one minimally encoded non-negative INTEGER of at most len bytes
// into out (right-aligned); returns the offset after it, or -1.
fn der_read_uint(der: const u8[:], at: i64, out: u8[:]) -> i64 {
    if at + 2 > der.len || der[at] != 2 { return -1; }
    let n: i64 = der[at + 1];
    let start = at + 2;
    if n == 0 || n >= 128 || start + n > der.len { return -1; }
    if der[start] >= 0x80 { return -1; }                         // negative
    if n > 1 && der[start] == 0 && der[start + 1] < 0x80 { return -1; }   // not minimal
    var v = der[start..start + n];
    if v.len > 1 && v[0] == 0 { v = v[1..]; }
    if v.len > out.len { return -1; }
    for i in out.len { out[i] = 0; }
    for i in v.len { out[out.len - v.len + i] = v[i]; }
    return start + n;
}

// A DER signature back to r || s of 2 * len bytes; strict, so a signature
// has exactly one accepted encoding.
fn ecdsa_sig_from_der(c: const Curve&, der: const u8[:]) -> u8[>..], bool {
    let raw, ok = sig_from_der(c.len, der);
    return raw, ok;
}

// The same for any width of r and s.
fn sig_from_der(len: i64, der: const u8[:]) -> u8[>..], bool {
    var raw: u8[>..] = [];
    raw.resize(2 * len, 0);
    // The SEQUENCE's length in the short form, or 0x81 and a byte >= 128.
    var hdr = 2;
    var ok = der.len >= 2 && der[0] == 0x30;
    if ok && der[1] == 0x81 {
        ok = der.len >= 3 && der[2] >= 128 && der[2] as i64 + 3 == der.len;
        hdr = 3;
    } else if ok {
        ok = der[1] < 128 && der[1] as i64 + 2 == der.len;
    }
    if ok {
        let mid = der_read_uint(der, hdr, raw[..len]);
        ok = mid >= 0 && der_read_uint(der, mid, raw[len..]) == der.len;
    }
    if !ok { raw.clear(); }
    return raw, ok;
}
