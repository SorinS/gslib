// bignum.ed25519: Ed25519 signatures (RFC 8032 §5.1), and its Ed25519ctx
// and Ed25519ph variants, on the field arithmetic of bignum.x25519.
//
// Points are extended coordinates (X : Y : Z : T) on -x^2 + y^2 = 1 + d x^2 y^2,
// added by the RFC's formulas, which are complete on this curve, so
// doubling is an addition. Signing multiplies the base point by secret
// scalars with 4-bit windows over all 256 bits and a table read by
// scanning, and reduces its scalars mod L with bignum.mont, so it runs in
// constant time. Verification works on public data only.

namespace bignum;

import std;
import ct;
import mont;
import sha512;
import x25519;
import entropy;

struct EdPoint { x: Fe, y: Fe, z: Fe, t: Fe }

// d = -121665/121666 and sqrt(-1), little-endian.
let ED_D: u8[32] = [
    163, 120, 89, 19, 202, 77, 235, 117, 171, 216, 65, 65, 77, 10, 112, 0,
    152, 232, 121, 119, 121, 64, 199, 140, 115, 254, 111, 43, 238, 108, 3, 82,
];
let ED_SQRTM1: u8[32] = [
    176, 160, 14, 74, 39, 27, 238, 196, 120, 228, 47, 173, 6, 24, 67, 47,
    167, 215, 251, 61, 153, 0, 77, 43, 11, 223, 193, 79, 128, 36, 131, 43,
];

// 2d, and the base point (y = 4/5, x even) in extended coordinates, as
// field limbs.
let ED_D2: Fe = Fe { v: [45281625, 27714825, 36363642, 13898781, 229458, 15978800, 54557047, 27058993, 29715967, 9444199] };
let ED_BX: Fe = Fe { v: [52811034, 25909283, 16144682, 17082669, 27570973, 30858332, 40966398, 8378388, 20764389, 8758491] };
let ED_BY: Fe = Fe { v: [40265304, 26843545, 13421772, 20132659, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545] };
let ED_BT: Fe = Fe { v: [28827043, 27438313, 39759291, 244362, 8635006, 11264893, 19351346, 13413597, 16611511, 27139452] };

// The group order L = 2^252 + 27742317777372353535851937790883648493.
let ED_L: u32[8] = [0x5cf5d3ed, 0x5812631a, 0xa2f79cd6, 0x14def9de, 0, 0, 0, 0x10000000];

fn fe_neg(f: Fe) -> Fe { fe_sub(fe_zero(), f) }

// mask ? f : g, with mask 0 or -1.
fn fe_select(f: Fe, g: Fe, mask: i64) -> Fe {
    var r = g;
    for i in 10 { r.v[i] = g.v[i] ^ (mask & (f.v[i] ^ g.v[i])); }
    return r;
}

fn fe_eq(f: Fe, g: Fe) -> bool { fe_to_bytes(f) == fe_to_bytes(g) }

fn fe_is_odd(f: Fe) -> i64 { fe_to_bytes(f)[0] & 1 }

// z^((p - 5) / 8) = z^(2^252 - 3), by the inversion chain's first steps.
fn fe_pow22523(z: Fe) -> Fe {
    let z2 = fe_sq(z);
    let z9 = fe_mul(z, fe_sqn(z2, 2));
    let z11 = fe_mul(z2, z9);
    let z_5 = fe_mul(z9, fe_sq(z11));                    // 2^5 - 1
    let z_10 = fe_mul(fe_sqn(z_5, 5), z_5);
    let z_20 = fe_mul(fe_sqn(z_10, 10), z_10);
    let z_40 = fe_mul(fe_sqn(z_20, 20), z_20);
    let z_50 = fe_mul(fe_sqn(z_40, 10), z_10);
    let z_100 = fe_mul(fe_sqn(z_50, 50), z_50);
    let z_200 = fe_mul(fe_sqn(z_100, 100), z_100);
    let z_250 = fe_mul(fe_sqn(z_200, 50), z_50);         // 2^250 - 1
    return fe_mul(fe_sqn(z_250, 2), z);                  // 2^252 - 3
}

fn ed_identity() -> EdPoint { EdPoint { x: fe_zero(), y: fe_one(), z: fe_one(), t: fe_zero() } }

fn ed_add(p: const EdPoint&, q: const EdPoint&) -> EdPoint {
    let a = fe_mul(fe_sub(p.y, p.x), fe_sub(q.y, q.x));
    let b = fe_mul(fe_add(p.y, p.x), fe_add(q.y, q.x));
    let c = fe_mul(fe_mul(p.t, ED_D2), q.t);
    let zz = fe_mul(p.z, q.z);
    let d = fe_add(zz, zz);
    let e = fe_sub(b, a);
    let f = fe_sub(d, c);
    let g = fe_add(d, c);
    let h = fe_add(b, a);
    return EdPoint { x: fe_mul(e, f), y: fe_mul(g, h), z: fe_mul(f, g), t: fe_mul(e, h) };
}

fn ed_select(dst: EdPoint&, src: const EdPoint&, mask: i64) {
    dst.x = fe_select(src.x, dst.x, mask);
    dst.y = fe_select(src.y, dst.y, mask);
    dst.z = fe_select(src.z, dst.z, mask);
    dst.t = fe_select(src.t, dst.t, mask);
}

// k * p for a 32-byte little-endian scalar, in constant time.
fn ed_mul(k: const u8[:], p: const EdPoint&) -> EdPoint {
    assert(k.len == 32);
    var tab: EdPoint[16] = [ed_identity(); 16];
    tab[1] = p;
    for i in 2..16 { tab[i] = ed_add(tab[i - 1], p); }
    var acc = ed_identity();
    var w = 64;
    while w > 0 {
        w--;
        for s in 4 {
            let d = ed_add(acc, acc);
            acc = d;
        }
        let win: u32 = (k[w / 2] >> (4 * (w % 2))) & 15;
        var sel = ed_identity();
        for j in 16 { ed_select(sel, tab[j], 0 - (ct_eq_u32(win, j as! u32) as i64)); }
        let sum = ed_add(acc, sel);
        acc = sum;
    }
    return acc;
}

fn ed_encode(p: const EdPoint&) -> u8[32] {
    let zi = fe_invert(p.z);
    let x = fe_mul(p.x, zi);
    var s = fe_to_bytes(fe_mul(p.y, zi));
    s[31] = s[31] | ((fe_is_odd(x) as! u8) << 7);
    return s;
}

// RFC 8032 §5.1.3; false for a y that is not canonical or not on the curve.
fn ed_decode(s: const u8[:]) -> EdPoint, bool {
    var p = ed_identity();
    if s.len != 32 { return p, false; }
    var ys: u8[32] = [0; 32];
    for i in 32 { ys[i] = s[i]; }
    let xsign: i64 = s[31] >> 7;
    ys[31] = ys[31] & 127;
    let y = fe_from_bytes(ys);
    if fe_to_bytes(y) != ys { return p, false; }         // y >= p
    let y2 = fe_sq(y);
    let u = fe_sub(y2, fe_one());
    let v = fe_add(fe_mul(fe_from_bytes(ED_D), y2), fe_one());
    let v3 = fe_mul(fe_sq(v), v);
    let v7 = fe_mul(fe_sq(v3), v);
    var x = fe_mul(fe_mul(u, v3), fe_pow22523(fe_mul(u, v7)));
    let vx2 = fe_mul(v, fe_sq(x));
    if !fe_eq(vx2, u) {
        if !fe_eq(vx2, fe_neg(u)) { return p, false; }
        x = fe_mul(x, fe_from_bytes(ED_SQRTM1));
    }
    let zero: u8[32] = [0; 32];
    if fe_to_bytes(x) == zero && xsign == 1 { return p, false; }
    if fe_is_odd(x) != xsign { x = fe_neg(x); }
    p.x = x;
    p.y = y;
    p.t = fe_mul(x, y);
    return p, true;
}

fn ed_base() -> EdPoint { EdPoint { x: ED_BX, y: ED_BY, z: fe_one(), t: ED_BT } }

// x mod L for a little-endian byte string of any length, as 32 bytes.
fn ed_reduce(x: const u8[:]) -> u8[32] {
    var limbs: u32[>..] = [];
    limbs.resize((x.len + 3) / 4, 0);
    for i in x.len { limbs[i / 4] = limbs[i / 4] | (x[i] as u32) << (8 * (i % 4)); }
    var r: u32[8] = [0; 8];
    ct_reduce(r, limbs, ED_L);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = (r[i / 4] >> (8 * (i % 4))) as! u8; }
    return out;
}

fn le_limbs(b: const u8[:]) -> u32[8] {
    var r: u32[8] = [0; 8];
    for i in 32 { r[i / 4] = r[i / 4] | (b[i] as u32) << (8 * (i % 4)); }
    return r;
}

// (r + k a) mod L for r, k, a < L, as 32 little-endian bytes.
fn ed_muladd(r: const u8[:], k: const u8[:], a: const u8[:]) -> u8[32] {
    var r2: u32[8] = [0; 8];
    mont_r2(r2, ED_L);
    let m0i = mont_m0i(ED_L[0]);
    var t: u32[10] = [0; 10];
    var ka: u32[8] = [0; 8];
    var prod: u32[8] = [0; 8];
    mont_mul(ka, le_limbs(k), le_limbs(a), ED_L, m0i, t);
    mont_mul(prod, ka, r2, ED_L, m0i, t);
    var s: u32[8] = [0; 8];
    ct_mod_add(s, prod, le_limbs(r), ED_L);
    var out: u8[32] = [0; 32];
    for i in 32 { out[i] = (s[i / 4] >> (8 * (i % 4))) as! u8; }
    return out;
}

// The secret scalar (clamped) and the nonce prefix of a 32-byte seed.
fn ed_expand(seed: const u8[:]) -> u8[32], u8[32] {
    assert(seed.len == 32);
    let h = sha512(seed);
    var a: u8[32] = [0; 32];
    var prefix: u8[32] = [0; 32];
    for i in 32 { a[i] = h[i]; prefix[i] = h[32 + i]; }
    a[0] = a[0] & 248;
    a[31] = (a[31] & 127) | 64;
    return a, prefix;
}

// The public key of a 32-byte private key (the seed).
fn ed25519_public(seed: const u8[:]) -> u8[32] {
    let a, prefix = ed_expand(seed);
    let b = ed_base();
    let pa = ed_mul(a, b);
    return ed_encode(pa);
}

// A fresh key pair from the OS's entropy: private seed, public key.
fn ed25519_keypair() -> u8[32], u8[32] {
    var seed: u8[32] = [0; 32];
    random_bytes(seed);
    return seed, ed25519_public(seed);
}

// SHA-512(d || a || b || c) mod L; d is RFC 8032's dom2 prefix, or empty
// for plain Ed25519.
fn ed_hram(d: const u8[:], a: const u8[:], b: const u8[:], c: const u8[:]) -> u8[32] {
    var s = sha512_init();
    sha512_update(s, d);
    sha512_update(s, a);
    sha512_update(s, b);
    sha512_update(s, c);
    return ed_reduce(sha512_final(s));
}

// dom2(phflag, context) of RFC 8032 §5.1.
fn ed_dom2(ph: bool, ctx: const u8[:]) -> u8[>..] {
    assert(ctx.len <= 255);
    var d: u8[>..] = [];
    d.append("SigEd25519 no Ed25519 collisions");
    d.push(if ph { 1 } else { 0 });
    d.push(ctx.len as! u8);
    d.append(ctx);
    return d;
}

fn ed_sign_dom(seed: const u8[:], dom: const u8[:], msg: const u8[:]) -> u8[64] {
    let a, prefix = ed_expand(seed);
    let b = ed_base();
    let pa = ed_mul(a, b);
    let pk = ed_encode(pa);
    let r = ed_hram(dom, prefix, msg, "");
    let pr = ed_mul(r, b);
    let rs = ed_encode(pr);
    let k = ed_hram(dom, rs, pk, msg);
    let s = ed_muladd(r, k, ed_reduce(a));
    var sig: u8[64] = [0; 64];
    for i in 32 { sig[i] = rs[i]; sig[32 + i] = s[i]; }
    return sig;
}

// The 64-byte signature R || S of msg. Deterministic.
fn ed25519_sign(seed: const u8[:], msg: const u8[:]) -> u8[64] { ed_sign_dom(seed, "", msg) }

// Ed25519ctx: a signature bound to a context of 1 to 255 bytes, which
// verifies under that context only.
fn ed25519_sign_ctx(seed: const u8[:], msg: const u8[:], ctx: const u8[:]) -> u8[64] {
    assert(ctx.len >= 1);
    let d = ed_dom2(false, ctx);
    return ed_sign_dom(seed, d, msg);
}

// Ed25519ph: a signature of the message's SHA-512 digest (64 bytes, as
// Go's Options{Hash: crypto.SHA512} takes it), with a context of up to
// 255 bytes.
fn ed25519_sign_ph(seed: const u8[:], digest: const u8[:], ctx: const u8[:] = "") -> u8[64] {
    assert(digest.len == 64);
    let d = ed_dom2(true, ctx);
    return ed_sign_dom(seed, d, digest);
}

// [8][S]B == [8]R + [8][k]A, with A and R decoded strictly and S < L.
fn ed_verify_dom(pk: const u8[:], dom: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool {
    if pk.len != 32 || sig.len != 64 { return false; }
    let a, oka = ed_decode(pk);
    let r, okr = ed_decode(sig[..32]);
    if !oka || !okr { return false; }
    let s = le_limbs(sig[32..]);
    if ct_lt(s, ED_L) == 0 { return false; }
    let k = ed_hram(dom, sig[..32], pk, msg);
    let b = ed_base();
    var lhs = ed_mul(sig[32..], b);
    let ka = ed_mul(k, a);
    var rhs = ed_add(r, ka);
    for i in 3 {
        let l2 = ed_add(lhs, lhs);
        lhs = l2;
        let r2 = ed_add(rhs, rhs);
        rhs = r2;
    }
    return fe_eq(fe_mul(lhs.x, rhs.z), fe_mul(rhs.x, lhs.z))
        && fe_eq(fe_mul(lhs.y, rhs.z), fe_mul(rhs.y, lhs.z));
}

fn ed25519_verify(pk: const u8[:], msg: const u8[:], sig: const u8[:]) -> bool {
    ed_verify_dom(pk, "", msg, sig)
}

fn ed25519_verify_ctx(pk: const u8[:], msg: const u8[:], sig: const u8[:], ctx: const u8[:]) -> bool {
    if ctx.len < 1 || ctx.len > 255 { return false; }
    let d = ed_dom2(false, ctx);
    return ed_verify_dom(pk, d, msg, sig);
}

fn ed25519_verify_ph(pk: const u8[:], digest: const u8[:], sig: const u8[:], ctx: const u8[:] = "") -> bool {
    if digest.len != 64 || ctx.len > 255 { return false; }
    let d = ed_dom2(true, ctx);
    return ed_verify_dom(pk, d, digest, sig);
}
