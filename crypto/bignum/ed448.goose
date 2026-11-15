// bignum.ed448: Ed448 signatures (RFC 8032 §5.2) and Ed448ph, on the field
// arithmetic of bignum.x448.
//
// Points are projective (X : Y : Z) on the untwisted x^2 + y^2 = 1 + d x^2 y^2,
// d = -39081, added by the RFC's formulas, which are complete on this
// curve, and doubled by its doubling formulas, also complete. Signing
// multiplies the base point by secret scalars with 4-bit windows over all
// 456 bits of a 57-byte scalar and a table read by scanning, and reduces
// its scalars mod L with bignum.mont, so it runs in constant time.
// Verification works on public data only. Every signature carries
// dom4(phflag, context), so a context of 0 to 255 bytes is allowed for
// Ed448 and Ed448ph alike.

namespace bignum;

import std;
import crypto.bignum.ct;
import crypto.bignum.mont;
import crypto.bignum.sha3;
import crypto.bignum.x448;
import crypto.bignum.entropy;

struct Ed448Point { x: Fe448, y: Fe448, z: Fe448 }

// The base point (x even), as field limbs.
let ED448_BX: Fe448 = Fe448 { v: [118276190, 40534716, 9670182, 135141552, 85017403, 259173222, 68333082, 171784774,
                                  174973732, 15824510, 73756743, 57518561, 94773951, 248652241, 107736333, 82941708] };
let ED448_BY: Fe448 = Fe448 { v: [36764180, 8885695, 130592152, 20104429, 163904957, 30304195, 121295871, 5901357,
                                  125344798, 171541512, 175338348, 209069246, 3626697, 38307682, 24032956, 110359655] };

// The group order L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885.
let ED448_L: u32[14] = [0xab5844f3, 0x2378c292, 0x8dc58f55, 0x216cc272, 0xaed63690, 0xc44edb49, 0x7cca23e9,
                        0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x3fffffff];

fn fe448_eq(f: Fe448, g: Fe448) -> bool { fe448_to_bytes(f) == fe448_to_bytes(g) }

fn fe448_is_odd(f: Fe448) -> i64 { fe448_to_bytes(f)[0] & 1 }

// d * f, d = -39081.
fn fe448_mul_d(f: Fe448) -> Fe448 { fe448_mul_small(f, -39081) }

fn e448_identity() -> Ed448Point { Ed448Point { x: fe448_zero(), y: fe448_one(), z: fe448_one() } }

fn e448_base() -> Ed448Point { Ed448Point { x: ED448_BX, y: ED448_BY, z: fe448_one() } }

// RFC 8032 §5.2.4's addition.
fn e448_add(p: const Ed448Point&, q: const Ed448Point&) -> Ed448Point {
    let a = fe448_mul(p.z, q.z);
    let b = fe448_sq(a);
    let c = fe448_mul(p.x, q.x);
    let d = fe448_mul(p.y, q.y);
    let e = fe448_mul_d(fe448_mul(c, d));
    let f = fe448_sub(b, e);
    let g = fe448_add(b, e);
    let h = fe448_mul(fe448_add(p.x, p.y), fe448_add(q.x, q.y));
    return Ed448Point {
        x: fe448_mul(fe448_mul(a, f), fe448_sub(fe448_sub(h, c), d)),
        y: fe448_mul(fe448_mul(a, g), fe448_sub(d, c)),
        z: fe448_mul(f, g),
    };
}

// RFC 8032 §5.2.4's doubling.
fn e448_double(p: const Ed448Point&) -> Ed448Point {
    let b = fe448_sq(fe448_add(p.x, p.y));
    let c = fe448_sq(p.x);
    let d = fe448_sq(p.y);
    let e = fe448_add(c, d);
    let h = fe448_sq(p.z);
    let j = fe448_sub(e, fe448_add(h, h));
    return Ed448Point { x: fe448_mul(fe448_sub(b, e), j), y: fe448_mul(e, fe448_sub(c, d)), z: fe448_mul(e, j) };
}

fn e448_select(dst: Ed448Point&, src: const Ed448Point&, mask: i64) {
    dst.x = fe448_select(src.x, dst.x, mask);
    dst.y = fe448_select(src.y, dst.y, mask);
    dst.z = fe448_select(src.z, dst.z, mask);
}

// k * p for a 57-byte little-endian scalar, in constant time.
fn e448_mul(k: const u8[:], p: const Ed448Point&) -> Ed448Point {
    assert(k.len == 57);
    var tab: Ed448Point[16] = [e448_identity(); 16];
    tab[1] = p;
    for i in 2..16 { tab[i] = e448_add(tab[i - 1], p); }
    var acc = e448_identity();
    var w = 114;
    while w > 0 {
        w--;
        for s in 4 {
            let d = e448_double(acc);
            acc = d;
        }
        let win: u32 = (k[w / 2] >> (4 * (w % 2))) & 15;
        var sel = e448_identity();
        for j in 16 { e448_select(sel, tab[j], 0 - (ct_eq_u32(win, j as! u32) as i64)); }
        let sum = e448_add(acc, sel);
        acc = sum;
    }
    return acc;
}

fn e448_encode(p: const Ed448Point&) -> u8[57] {
    let zi = fe448_invert(p.z);
    let x = fe448_mul(p.x, zi);
    let y = fe448_to_bytes(fe448_mul(p.y, zi));
    var s: u8[57] = [0; 57];
    for i in 56 { s[i] = y[i]; }
    s[56] = (fe448_is_odd(x) as! u8) << 7;
    return s;
}

// RFC 8032 §5.2.3; false for a y that is not canonical or not on the
// curve, and for x = 0 with the sign bit set.
fn e448_decode(s: const u8[:]) -> Ed448Point, bool {
    var p = e448_identity();
    if s.len != 57 || (s[56] & 127) != 0 { return p, false; }
    let xsign: i64 = s[56] >> 7;
    let y = fe448_from_bytes(s[..56]);
    if fe448_to_bytes(y)[..] != s[..56] { return p, false; }    // y >= p
    let y2 = fe448_sq(y);
    let u = fe448_sub(y2, fe448_one());
    let v = fe448_sub(fe448_mul_d(y2), fe448_one());
    // x = u^3 v (u^5 v^3)^((p - 3) / 4), a square root of u / v if there is one.
    let u2 = fe448_sq(u);
    let u3v = fe448_mul(fe448_mul(u2, u), v);
    let u5v3 = fe448_mul(fe448_mul(u3v, u2), fe448_sq(v));
    var x = fe448_mul(u3v, fe448_pow_p34(u5v3));
    if !fe448_eq(fe448_mul(v, fe448_sq(x)), u) { return p, false; }
    let zero: u8[56] = [0; 56];
    if fe448_to_bytes(x) == zero && xsign == 1 { return p, false; }
    if fe448_is_odd(x) != xsign { x = fe448_neg(x); }
    p.x = x;
    p.y = y;
    return p, true;
}

// x mod L for a little-endian byte string of any length, as 57 bytes.
fn e448_reduce(x: const u8[:]) -> u8[57] {
    var limbs: u32[>..] = [];
    limbs.resize((x.len + 3) / 4, 0);
    for i in x.len { limbs[i / 4] = limbs[i / 4] | (x[i] as u32) << (8 * (i % 4)); }
    var r: u32[14] = [0; 14];
    ct_reduce(r, limbs, ED448_L);
    var out: u8[57] = [0; 57];
    for i in 56 { out[i] = (r[i / 4] >> (8 * (i % 4))) as! u8; }
    return out;
}

// The low 56 bytes of a scalar as limbs.
fn e448_limbs(b: const u8[:]) -> u32[14] {
    var r: u32[14] = [0; 14];
    for i in 56 { r[i / 4] = r[i / 4] | (b[i] as u32) << (8 * (i % 4)); }
    return r;
}

// (r + k a) mod L for r, k, a < L, as 57 little-endian bytes.
fn e448_muladd(r: const u8[:], k: const u8[:], a: const u8[:]) -> u8[57] {
    var r2: u32[14] = [0; 14];
    mont_r2(r2, ED448_L);
    let m0i = mont_m0i(ED448_L[0]);
    var t:    u32[16] = [0; 16];
    var ka:   u32[14] = [0; 14];
    var prod: u32[14] = [0; 14];
    mont_mul(ka, e448_limbs(k), e448_limbs(a), ED448_L, m0i, t);
    mont_mul(prod, ka, r2, ED448_L, m0i, t);
    var s: u32[14] = [0; 14];
    ct_mod_add(s, prod, e448_limbs(r), ED448_L);
    var out: u8[57] = [0; 57];
    for i in 56 { out[i] = (s[i / 4] >> (8 * (i % 4))) as! u8; }
    return out;
}

// The secret scalar (clamped) and the nonce prefix of a 57-byte seed.
fn e448_expand(seed: const u8[:]) -> u8[57], u8[57] {
    assert(seed.len == 57);
    let h = shake(256, seed, 114);
    var a:      u8[57] = [0; 57];
    var prefix: u8[57] = [0; 57];
    for i in 57 { a[i] = h[i]; prefix[i] = h[57 + i]; }
    a[0] = a[0] & 252;
    a[55] = a[55] | 128;
    a[56] = 0;
    return a, prefix;
}

// The public key of a 57-byte private key (the seed).
fn ed448_public(seed: const u8[:]) -> u8[57] {
    let a, prefix = e448_expand(seed);
    let b = e448_base();
    let pa = e448_mul(a, b);
    return e448_encode(pa);
}

// A fresh key pair from the OS's entropy: private seed, public key.
fn ed448_keypair() -> u8[57], u8[57] {
    var seed: u8[57] = [0; 57];
    random_bytes(seed);
    return seed, ed448_public(seed);
}

// SHAKE256(d || a || b || c, 114) mod L; d is RFC 8032's dom4 prefix.
fn e448_hram(d: const u8[:], a: const u8[:], b: const u8[:], c: const u8[:]) -> u8[57] {
    var s = shake_init(256);
    sha3_update(s, d);
    sha3_update(s, a);
    sha3_update(s, b);
    sha3_update(s, c);
    var h: u8[114] = [0; 114];
    shake_read(s, h);
    return e448_reduce(h);
}

// dom4(phflag, context) of RFC 8032 §5.2.
fn e448_dom4(ph: bool, ctx: const u8[:]) -> u8[>..] {
    assert(ctx.len <= 255);
    var d: u8[>..] = [];
    d.append("SigEd448");
    d.push(if ph { 1 } else { 0 });
    d.push(ctx.len as! u8);
    d.append(ctx);
    return d;
}

fn e448_sign_dom(seed: const u8[:], dom: const u8[:], msg: const u8[:]) -> u8[114] {
    let a, prefix = e448_expand(seed);
    let b = e448_base();
    let pa = e448_mul(a, b);
    let pk = e448_encode(pa);
    let r = e448_hram(dom, prefix, msg, "");
    let pr = e448_mul(r, b);
    let rs = e448_encode(pr);
    let k = e448_hram(dom, rs, pk, msg);
    let s = e448_muladd(r, k, e448_reduce(a));
    var sig: u8[114] = [0; 114];
    for i in 57 { sig[i] = rs[i]; sig[57 + i] = s[i]; }
    return sig;
}

// The 114-byte signature R || S of msg, under a context of up to 255
// bytes (empty by default). Deterministic.
fn ed448_sign(seed: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[114] {
    let d = e448_dom4(false, ctx);
    return e448_sign_dom(seed, d, msg);
}

// Ed448ph's prehash: SHAKE256(msg, 64).
fn ed448_prehash(msg: const u8[:]) -> u8[64] {
    var s = shake_init(256);
    sha3_update(s, msg);
    var out: u8[64] = [0; 64];
    shake_read(s, out);
    return out;
}

// Ed448ph: a signature of the message's 64-byte SHAKE256 digest
// (ed448_prehash), as ed25519_sign_ph takes a SHA-512 digest, with a
// context of up to 255 bytes.
fn ed448_sign_ph(seed: const u8[:], digest: const u8[:], ctx: const u8[:] = "") -> u8[114] {
    assert(digest.len == 64);
    let d = e448_dom4(true, ctx);
    return e448_sign_dom(seed, d, digest);
}

// [4][S]B == [4]R + [4][k]A, with A and R decoded strictly and S < L.
fn e448_verify_dom(pk: const u8[:], dom: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool {
    if pk.len != 57 || sig.len != 114 { return false; }
    let a, oka = e448_decode(pk);
    let r, okr = e448_decode(sig[..57]);
    if !oka || !okr { return false; }
    if sig[113] != 0 || ct_lt(e448_limbs(sig[57..113]), ED448_L) == 0 { return false; }
    let k = e448_hram(dom, sig[..57], pk, msg);
    let b = e448_base();
    var lhs = e448_mul(sig[57..], b);
    let ka = e448_mul(k, a);
    var rhs = e448_add(r, ka);
    for i in 2 {
        let l2 = e448_double(lhs);
        lhs = l2;
        let r2 = e448_double(rhs);
        rhs = r2;
    }
    return fe448_eq(fe448_mul(lhs.x, rhs.z), fe448_mul(rhs.x, lhs.z))
        && fe448_eq(fe448_mul(lhs.y, rhs.z), fe448_mul(rhs.y, lhs.z));
}

fn ed448_verify(pk: const u8[:], msg: const u8[:], sig: const u8[:], ctx: const u8[:] = "") -> bool {
    if ctx.len > 255 { return false; }
    let d = e448_dom4(false, ctx);
    return e448_verify_dom(pk, d, msg, sig);
}

fn ed448_verify_ph(pk: const u8[:], digest: const u8[:], sig: const u8[:], ctx: const u8[:] = "") -> bool {
    if digest.len != 64 || ctx.len > 255 { return false; }
    let d = e448_dom4(true, ctx);
    return e448_verify_dom(pk, d, digest, sig);
}
