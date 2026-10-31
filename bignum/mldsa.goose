// bignum.mldsa: ML-DSA (FIPS 204), the module-lattice signature scheme:
// ML-DSA-44, ML-DSA-65 and ML-DSA-87, chosen by that number. As in Go's
// crypto/mldsa the private key is the 32-byte seed; mldsa_expand_key
// gives the FIPS 204 encoding of the expanded key for formats that carry
// it. Signing is hedged (fresh randomness mixed in) unless asked to be
// deterministic, and takes a context string of up to 255 bytes. The
// external-mu forms sign and verify a precomputed message representative.
//
// Coefficients are u32s mod q = 8380417. Products go through Montgomery
// reduction (R = 2^32) with masked corrections, and Decompose is the
// reference implementation's multiply-and-shift, so nothing secret meets a
// division or a branch. The NTT-domain products carry a factor 1/R, which
// the inverse NTT's final scaling takes off.

namespace bignum;

import std;
import ct;
import sha3;
import entropy;

let MLDSA_Q: u32 = 8380417;
let MLDSA_QINV_NEG: u32 = 4236238847;          // -q^-1 mod 2^32
let MLDSA_F: u32 = 41978;                      // 256^-1 R^2 mod q

// zeta^BitRev8(i) R mod q, for zeta = 1753 (FIPS 204 Appendix B).
let MLDSA_ZETAS: u32[256] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166, 6288512,
    3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005, 2706023, 95776, 3077325, 3530437,
    6718724, 4788269, 5842901, 3915439, 4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043,
    3900724, 5823537, 2071892, 5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896, 2715295,
    5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618, 4656075, 8371839, 1653064, 5130689,
    2389356, 8169440, 759969, 7063561, 189548, 4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976,
    5037939, 2244091, 5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748, 3207046,
    4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145,
    5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464,
    5796124, 4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531, 7173032,
    5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501, 3523897, 3866901, 269760,
    2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443, 7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208,
    3937738, 1400424, 7534263, 1976782
];

// A parameter set (FIPS 204 Table 1).
struct MldsaParams {
    k: i64, l: i64, eta: i64, tau: i64, beta: i64, gamma1: i64, gamma2: i64, omega: i64, lambda: i64,
}

fn mldsa_params(set: i64) -> MldsaParams {
    assert(set == 44 || set == 65 || set == 87);
    if set == 44 {
        return MldsaParams { k: 4, l: 4, eta: 2, tau: 39, beta: 78, gamma1: 1 << 17, gamma2: 95232, omega: 80, lambda: 128 };
    }
    if set == 65 {
        return MldsaParams { k: 6, l: 5, eta: 4, tau: 49, beta: 196, gamma1: 1 << 19, gamma2: 261888, omega: 55, lambda: 192 };
    }
    return MldsaParams { k: 8, l: 7, eta: 2, tau: 60, beta: 120, gamma1: 1 << 19, gamma2: 261888, omega: 75, lambda: 256 };
}

fn mldsa_eta_bits(p: const MldsaParams&) -> i64 { if p.eta == 2 { 3 } else { 4 } }
fn mldsa_z_bits(p: const MldsaParams&) -> i64 { if p.gamma1 == 1 << 17 { 18 } else { 20 } }
fn mldsa_w1_bits(p: const MldsaParams&) -> i64 { if p.gamma2 == 95232 { 6 } else { 4 } }

fn mldsa_pk_len(set: i64) -> i64 { 32 + 320 * mldsa_params(set).k }
fn mldsa_sk_len(set: i64) -> i64 {
    let p = mldsa_params(set);
    return 128 + 32 * ((p.k + p.l) * mldsa_eta_bits(p) + 13 * p.k);
}
fn mldsa_sig_len(set: i64) -> i64 {
    let p = mldsa_params(set);
    return p.lambda / 4 + p.l * 32 * mldsa_z_bits(p) + p.omega + p.k;
}

// --- Arithmetic mod q ---------------------------------------------------------

// r - q if r >= q, for r < 2q.
fn mldsa_csub(r: u32) -> u32 {
    let t = r - MLDSA_Q;
    return t + ((0 - (t >> 31)) & MLDSA_Q);
}

fn mldsa_add(a: u32, b: u32) -> u32 { mldsa_csub(a + b) }
fn mldsa_sub(a: u32, b: u32) -> u32 { mldsa_csub(a + MLDSA_Q - b) }

// a / R mod q, for a < q R.
fn mldsa_reduce(a: u64) -> u32 {
    let t: u64 = (a as! u32) * MLDSA_QINV_NEG;
    let q: u64 = MLDSA_Q;
    return mldsa_csub(((a + t * q) >> 32) as! u32);
}

fn mldsa_mul(a: u32, b: u32) -> u32 {
    let x: u64 = a;
    let y: u64 = b;
    return mldsa_reduce(x * y);
}

// x as a signed value in (-(q-1)/2, (q-1)/2].
fn mldsa_centered(x: u32) -> i64 {
    let v: i64 = x;
    let q: i64 = MLDSA_Q;
    return v - (q & ((4190208 - v) >> 63));
}

// A small signed value mod q.
fn mldsa_from_signed(v: i64) -> u32 {
    let q: i64 = MLDSA_Q;
    return mldsa_csub((v + q) as! u32);
}

// Whether any coefficient of f has |x| >= bound, without branching on them.
fn mldsa_exceeds(f: const u32[:], bound: i64) -> bool {
    var bad: i64 = 0;
    for x in f {
        let v = mldsa_centered(x);
        let a = (v ^ (v >> 63)) - (v >> 63);
        bad = bad | ((bound - 1 - a) >> 63);
    }
    return bad != 0;
}

// NTT (Algorithm 41), in place.
fn mldsa_ntt(w: u32[:]) {
    var m = 0;
    var len = 128;
    while len >= 1 {
        var start = 0;
        while start < 256 {
            m++;
            let z = MLDSA_ZETAS[m];
            for j in start..start + len {
                let t = mldsa_mul(z, w[j + len]);
                w[j + len] = mldsa_sub(w[j], t);
                w[j] = mldsa_add(w[j], t);
            }
            start += 2 * len;
        }
        len = len / 2;
    }
}

// NTT^-1 (Algorithm 42) of a sum of NTT-domain products, whose factor 1/R
// the scaling by F takes off with the 1/256.
fn mldsa_ntt_inv(w: u32[:]) {
    var m = 256;
    var len = 1;
    while len < 256 {
        var start = 0;
        while start < 256 {
            m--;
            let z = MLDSA_ZETAS[m];
            for j in start..start + len {
                let t = w[j];
                w[j] = mldsa_add(t, w[j + len]);
                w[j + len] = mldsa_mul(z, mldsa_sub(w[j + len], t));
            }
            start += 2 * len;
        }
        len = 2 * len;
    }
    for j in 256 { w[j] = mldsa_mul(w[j], MLDSA_F); }
}

// h += f * g, coefficient by coefficient (NTT domain).
fn mldsa_mul_acc(h: u32[:], f: const u32[:], g: const u32[:]) {
    for i in 256 { h[i] = mldsa_add(h[i], mldsa_mul(f[i], g[i])); }
}

fn mldsa_poly(v: u32[:], i: i64) -> u32[:] { v[i * 256..(i + 1) * 256] }

fn mldsa_zeros(n: i64) -> u32[>..] {
    var r: u32[>..] = [];
    r.resize(n, 0);
    return r;
}

// t = A * s (all NTT domain, k rows of l), then back from the NTT domain.
fn mldsa_mat_mul(t: u32[:], a: const u32[:], s: const u32[:], k: i64, l: i64) {
    for i in k {
        let ti = t[i * 256..(i + 1) * 256];
        for x in 256 { ti[x] = 0; }
        for j in l { mldsa_mul_acc(ti, a[(i * l + j) * 256..(i * l + j + 1) * 256], s[j * 256..(j + 1) * 256]); }
        mldsa_ntt_inv(ti);
    }
}

// --- Rounding (§7.4) -----------------------------------------------------------

// Power2Round: r1 and r0 with r = r1 2^13 + r0, r0 in (-2^12, 2^12].
fn mldsa_power2round(r: u32) -> u32, i64 {
    let v: i64 = r;
    let r1 = (v + (1 << 12) - 1) >> 13;
    return r1 as! u32, v - (r1 << 13);
}

// Decompose: r1 and r0 with r = r1 2 gamma2 + r0 mod q (the reference
// implementation's branch-free form, which handles r - r0 = q - 1).
fn mldsa_decompose(r: u32, gamma2: i64) -> i64, i64 {
    let a: i64 = r;
    var a1 = (a + 127) >> 7;
    if gamma2 == 261888 {
        a1 = ((a1 * 1025 + (1 << 21)) >> 22) & 15;
    } else {
        a1 = (a1 * 11275 + (1 << 23)) >> 24;
        a1 = a1 ^ (((43 - a1) >> 63) & a1);
    }
    var a0 = a - a1 * 2 * gamma2;
    let q: i64 = MLDSA_Q;
    a0 = a0 - ((((q - 1) / 2) - a0) >> 63 & q);
    return a1, a0;
}

fn mldsa_high_bits(r: u32, gamma2: i64) -> i64 {
    let r1, r0 = mldsa_decompose(r, gamma2);
    return r1;
}

// UseHint (Algorithm 40).
fn mldsa_use_hint(h: bool, r: u32, gamma2: i64) -> i64 {
    let m = (8380417 - 1) / (2 * gamma2);
    let r1, r0 = mldsa_decompose(r, gamma2);
    if !h { return r1; }
    if r0 > 0 { return (r1 + 1) % m; }
    return (r1 - 1) % m;
}

// --- Encodings (§7.1, §7.2) ----------------------------------------------------

// d bits a value, little-endian.
fn mldsa_pack(out: u8[>..]&, vals: const u32[:], d: i64) {
    var acc: u64 = 0;
    var bits = 0;
    for x in vals {
        let v: u64 = x;
        acc = acc | v << bits;
        bits += d;
        while bits >= 8 {
            out.push(acc as! u8);
            acc = acc >> 8;
            bits -= 8;
        }
    }
}

fn mldsa_unpack(f: u32[:], b: const u8[:], d: i64) {
    var acc: u64 = 0;
    var bits = 0;
    var p = 0;
    let mask: u64 = (1 << d) - 1;
    for i in f.len {
        while bits < d {
            let v: u64 = b[p];
            acc = acc | v << bits;
            p++;
            bits += 8;
        }
        f[i] = (acc & mask) as! u32;
        acc = acc >> d;
        bits -= d;
    }
}

// BitPack(w, a, b) of signed coefficients: b - w in d bits.
fn mldsa_pack_signed(out: u8[>..]&, f: const u32[:], b: i64, d: i64) {
    var v = mldsa_zeros(f.len);
    for i in f.len { v[i] = (b - mldsa_centered(f[i])) as! u32; }
    mldsa_pack(out, v, d);
}

fn mldsa_unpack_signed(f: u32[:], bytes: const u8[:], b: i64, d: i64) {
    mldsa_unpack(f, bytes, d);
    for i in f.len {
        let v: i64 = f[i];
        f[i] = mldsa_from_signed(b - v);
    }
}

// HintBitPack (Algorithm 20): the positions of the set hints, then each
// polynomial's running count.
fn mldsa_pack_hints(out: u8[>..]&, h: const bool[:], k: i64, omega: i64) {
    var y: u8[>..] = [];
    y.resize(omega + k, 0);
    var index = 0;
    for i in k {
        for j in 256 {
            if h[i * 256 + j] { y[index] = j as! u8; index++; }
        }
        y[omega + i] = index as! u8;
    }
    out.append(y);
}

// HintBitUnpack (Algorithm 21): false for anything but the one encoding.
fn mldsa_unpack_hints(h: bool[:], y: const u8[:], k: i64, omega: i64) -> bool {
    var index: i64 = 0;
    for i in k {
        let end: i64 = y[omega + i];
        if end < index || end > omega { return false; }
        let first = index;
        while index < end {
            if index > first && y[index - 1] >= y[index] { return false; }
            let j: i64 = y[index];
            h[i * 256 + j] = true;
            index++;
        }
    }
    for i in index..omega { if y[i] != 0 { return false; } }
    return true;
}

// --- Sampling (§7.3) -------------------------------------------------------

// RejNTTPoly (Algorithm 30): A[r][s] from SHAKE128(rho || s || r).
fn mldsa_rej_ntt(f: u32[:], rho: const u8[:], s: u8, r: u8) {
    var x = shake_init(128);
    sha3_update(x, rho);
    let sr: u8[2] = [s, r];
    sha3_update(x, sr);
    var buf: u8[168] = [0; 168];
    var n = 0;
    while n < 256 {
        shake_read(x, buf);
        var p = 0;
        while p < 168 && n < 256 {
            let b0: u32 = buf[p]; let b1: u32 = buf[p + 1]; let b2: u32 = buf[p + 2];
            let v = b0 | b1 << 8 | (b2 & 0x7f) << 16;
            if v < MLDSA_Q { f[n] = v; n++; }
            p += 3;
        }
    }
}

// ExpandA (Algorithm 32): k * l polynomials, row by row.
fn mldsa_expand_a(a: u32[:], rho: const u8[:], k: i64, l: i64) {
    for r in k {
        for s in l { mldsa_rej_ntt(mldsa_poly(a, r * l + s), rho, s as! u8, r as! u8); }
    }
}

// RejBoundedPoly (Algorithm 31): coefficients in [-eta, eta] from
// SHAKE256(rho' || index), two candidates a byte.
fn mldsa_rej_bounded(f: u32[:], rhop: const u8[:], index: i64, eta: i64) {
    var x = shake_init(256);
    sha3_update(x, rhop);
    let ib: u8[2] = [index as! u8, (index >> 8) as! u8];
    sha3_update(x, ib);
    var buf: u8[136] = [0; 136];
    var n = 0;
    let eta_u: u32 = eta as! u32;
    while n < 256 {
        shake_read(x, buf);
        var p = 0;
        while p < 136 && n < 256 {
            let z: u32 = buf[p];
            let halves: u32[2] = [z & 15, z >> 4];
            for b in halves {
                if n < 256 {
                    // b mod 5 for b < 15 as a multiply and shift, not a
                    // division (which may take a time that depends on b).
                    if eta == 2 && b < 15 { f[n] = mldsa_csub(MLDSA_Q + 2 - (b - 5 * ((b * 205) >> 10))); n++; }
                    else if eta == 4 && b < 9 { f[n] = mldsa_csub(MLDSA_Q + eta_u - b); n++; }
                }
            }
            p++;
        }
    }
}

// ExpandMask (Algorithm 34): y from SHAKE256(rho'' || kappa + r).
fn mldsa_expand_mask(y: u32[:], rhopp: const u8[:], kappa: i64, p: const MldsaParams&) {
    let d = mldsa_z_bits(p);
    for r in p.l {
        var x = shake_init(256);
        sha3_update(x, rhopp);
        let n = kappa + r;
        let nb: u8[2] = [n as! u8, (n >> 8) as! u8];
        sha3_update(x, nb);
        var v: u8[>..] = [];
        v.resize(32 * d, 0);
        shake_read(x, v);
        mldsa_unpack_signed(mldsa_poly(y, r), v, p.gamma1, d);
    }
}

// SampleInBall (Algorithm 29): tau coefficients of +-1. The challenge is
// public (it is in the signature), so the rejection loop may branch.
fn mldsa_sample_in_ball(c: u32[:], seed: const u8[:], tau: i64) {
    var x = shake_init(256);
    sha3_update(x, seed);
    var s: u8[8] = [0; 8];
    shake_read(x, s);
    var signs: u64 = 0;
    for i in 8 { let b: u64 = s[i]; signs = signs | b << (8 * i); }
    for i in 256 { c[i] = 0; }
    var one: u8[1] = [0];
    for i in 256 - tau..256 {
        loop {
            shake_read(x, one);
            if one[0] as i64 <= i { break; }
        }
        let j: i64 = one[0];
        c[i] = c[j];
        c[j] = if (signs & 1) == 1 { MLDSA_Q - 1 } else { 1 };
        signs = signs >> 1;
    }
}

// --- Keys --------------------------------------------------------------------

// The pieces of a key, expanded from the seed (ML-DSA.KeyGen_internal,
// Algorithm 6): rho, K, tr, s1 and s2 (plain), t0, t1, and pk.
struct MldsaKey {
    rho: u8[32], kk: u8[32], tr: u8[64],
    s1: u32[..1792], s2: u32[..2048], t0: u32[..2048], pk: u8[>..],
}

fn mldsa_expand(set: i64, seed: const u8[:]) -> MldsaKey {
    assert(seed.len == 32);
    let p = mldsa_params(set);
    var hin: u8[>..] = [];
    hin.append(seed);
    hin.push(p.k as! u8);
    hin.push(p.l as! u8);
    let h = shake(256, hin, 128);
    var key = MldsaKey { rho: [0; 32], kk: [0; 32], tr: [0; 64], s1: [], s2: [], t0: [], pk: [] };
    key.s1.resize(p.l * 256, 0);
    key.s2.resize(p.k * 256, 0);
    key.t0.resize(p.k * 256, 0);
    for i in 32 { key.rho[i] = h[i]; key.kk[i] = h[96 + i]; }
    let rhop = h[32..96];
    for r in p.l { mldsa_rej_bounded(mldsa_poly(key.s1, r), rhop, r, p.eta); }
    for r in p.k { mldsa_rej_bounded(mldsa_poly(key.s2, r), rhop, r + p.l, p.eta); }
    var a = mldsa_zeros(p.k * p.l * 256);
    mldsa_expand_a(a, key.rho, p.k, p.l);
    var s1h = mldsa_zeros(p.l * 256);
    for i in s1h.len { s1h[i] = key.s1[i]; }
    for r in p.l { mldsa_ntt(mldsa_poly(s1h, r)); }
    var t = mldsa_zeros(p.k * 256);
    mldsa_mat_mul(t, a, s1h, p.k, p.l);
    var t1 = mldsa_zeros(p.k * 256);
    for i in t.len {
        let r1, r0 = mldsa_power2round(mldsa_add(t[i], key.s2[i]));
        t1[i] = r1;
        key.t0[i] = mldsa_from_signed(r0);
    }
    key.pk.append(key.rho);
    mldsa_pack(key.pk, t1, 10);
    let tr = shake(256, key.pk, 64);
    for i in 64 { key.tr[i] = tr[i]; }
    return key;
}

// The public key of a seed.
fn mldsa_public_key(set: i64, seed: const u8[:]) -> u8[>..] {
    let key = mldsa_expand(set, seed);
    var pk: u8[>..] = [];
    pk.append(key.pk);
    return pk;
}

// A fresh key pair from the OS's entropy: the seed (the private key) and
// the public key.
fn mldsa_keygen(set: i64) -> u8[>..], u8[>..] {
    var seed: u8[>..] = [];
    seed.resize(32, 0);
    random_bytes(seed);
    return seed, mldsa_public_key(set, seed);
}

// skEncode (Algorithm 24): the expanded private key of a seed.
fn mldsa_expand_key(set: i64, seed: const u8[:]) -> u8[>..] {
    let p = mldsa_params(set);
    let key = mldsa_expand(set, seed);
    var sk: u8[>..] = [];
    sk.append(key.rho);
    sk.append(key.kk);
    sk.append(key.tr);
    mldsa_pack_signed(sk, key.s1, p.eta, mldsa_eta_bits(p));
    mldsa_pack_signed(sk, key.s2, p.eta, mldsa_eta_bits(p));
    mldsa_pack_signed(sk, key.t0, 1 << 12, 13);
    return sk;
}

// --- Signing -----------------------------------------------------------------

// The message representative mu = H(H(pk) || 0 || |ctx| || ctx || msg);
// false for a context longer than 255 bytes.
fn mldsa_mu(pk: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[>..], bool {
    if ctx.len > 255 { var none: u8[>..] = []; return none, false; }
    var x = shake_init(256);
    sha3_update(x, shake(256, pk, 64));
    let pre: u8[2] = [0, ctx.len as! u8];
    sha3_update(x, pre);
    sha3_update(x, ctx);
    sha3_update(x, msg);
    var mu: u8[>..] = [];
    mu.resize(64, 0);
    shake_read(x, mu);
    return mu, true;
}

// w1Encode (Algorithm 28).
fn mldsa_w1_encode(out: u8[>..]&, w1: const u32[:], p: const MldsaParams&) { mldsa_pack(out, w1, mldsa_w1_bits(p)); }

// ML-DSA.Sign_internal (Algorithm 7) on mu, with the 32 bytes rnd.
fn mldsa_sign_internal(set: i64, seed: const u8[:], mu: const u8[:], rnd: const u8[:]) -> u8[>..] {
    assert(mu.len == 64 && rnd.len == 32);
    let p = mldsa_params(set);
    let key = mldsa_expand(set, seed);
    var s1h = mldsa_zeros(p.l * 256);
    var s2h = mldsa_zeros(p.k * 256);
    var t0h = mldsa_zeros(p.k * 256);
    for i in s1h.len { s1h[i] = key.s1[i]; }
    for i in s2h.len { s2h[i] = key.s2[i]; t0h[i] = key.t0[i]; }
    for r in p.l { mldsa_ntt(mldsa_poly(s1h, r)); }
    for r in p.k { mldsa_ntt(mldsa_poly(s2h, r)); mldsa_ntt(mldsa_poly(t0h, r)); }
    var a = mldsa_zeros(p.k * p.l * 256);
    mldsa_expand_a(a, key.rho, p.k, p.l);
    var hin: u8[>..] = [];
    hin.append(key.kk);
    hin.append(rnd);
    hin.append(mu);
    let rhopp = shake(256, hin, 64);
    let clen = p.lambda / 4;
    var y = mldsa_zeros(p.l * 256);
    var yh = mldsa_zeros(p.l * 256);
    var w = mldsa_zeros(p.k * 256);
    var w1 = mldsa_zeros(p.k * 256);
    var c = mldsa_zeros(256);
    var cs1 = mldsa_zeros(p.l * 256);
    var cs2 = mldsa_zeros(p.k * 256);
    var ct0 = mldsa_zeros(p.k * 256);
    var z = mldsa_zeros(p.l * 256);
    var r0 = mldsa_zeros(p.k * 256);
    var h: bool[>..] = [];
    h.resize(p.k * 256, false);
    var kappa = 0;
    loop {
        mldsa_expand_mask(y, rhopp, kappa, p);
        kappa += p.l;
        for i in y.len { yh[i] = y[i]; }
        for r in p.l { mldsa_ntt(mldsa_poly(yh, r)); }
        mldsa_mat_mul(w, a, yh, p.k, p.l);
        for i in w.len { w1[i] = mldsa_high_bits(w[i], p.gamma2) as! u32; }
        var cin: u8[>..] = [];
        cin.append(mu);
        mldsa_w1_encode(cin, w1, p);
        let ctilde = shake(256, cin, clen);
        mldsa_sample_in_ball(c, ctilde, p.tau);
        mldsa_ntt(c);
        for r in p.l {
            let o = mldsa_poly(cs1, r);
            for x in 256 { o[x] = 0; }
            mldsa_mul_acc(o, c, mldsa_poly(s1h, r));
            mldsa_ntt_inv(o);
        }
        for r in p.k {
            let o2 = mldsa_poly(cs2, r);
            let o3 = mldsa_poly(ct0, r);
            for x in 256 { o2[x] = 0; o3[x] = 0; }
            mldsa_mul_acc(o2, c, mldsa_poly(s2h, r));
            mldsa_mul_acc(o3, c, mldsa_poly(t0h, r));
            mldsa_ntt_inv(o2);
            mldsa_ntt_inv(o3);
        }
        for i in z.len { z[i] = mldsa_add(y[i], cs1[i]); }
        for i in r0.len {
            let hi, lo = mldsa_decompose(mldsa_sub(w[i], cs2[i]), p.gamma2);
            r0[i] = mldsa_from_signed(lo);
        }
        if mldsa_exceeds(z, p.gamma1 - p.beta) || mldsa_exceeds(r0, p.gamma2 - p.beta) { continue; }
        if mldsa_exceeds(ct0, p.gamma2) { continue; }
        // MakeHint(-ct0, w - cs2 + ct0): whether adding ct0 moves the high bits.
        var count = 0;
        for i in h.len {
            let v = mldsa_sub(w[i], cs2[i]);
            // Counted without a branch: the hints of a rejected attempt
            // stay secret.
            let a = mldsa_high_bits(mldsa_add(v, ct0[i]), p.gamma2);
            let b = mldsa_high_bits(v, p.gamma2);
            let moved = ct_eq_u32(a as! u32, b as! u32) ^ 1;
            h[i] = moved == 1;
            count += moved;
        }
        if count > p.omega { continue; }
        var sig: u8[>..] = [];
        sig.append(ctilde);
        mldsa_pack_signed(sig, z, p.gamma1, mldsa_z_bits(p));
        mldsa_pack_hints(sig, h, p.k, p.omega);
        return sig;
    }
}

// A hedged signature of msg under ctx.
fn mldsa_sign(set: i64, seed: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[>..] {
    var rnd: u8[32] = [0; 32];
    random_bytes(rnd);
    return mldsa_sign_with(set, seed, msg, ctx, rnd);
}

// The deterministic variant (rnd = 0).
fn mldsa_sign_deterministic(set: i64, seed: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[>..] {
    let rnd: u8[32] = [0; 32];
    return mldsa_sign_with(set, seed, msg, ctx, rnd);
}

// Signing with the given 32 bytes of randomness, for tests.
fn mldsa_sign_with(set: i64, seed: const u8[:], msg: const u8[:], ctx: const u8[:], rnd: const u8[:]) -> u8[>..] {
    let pk = mldsa_public_key(set, seed);
    let mu, ok = mldsa_mu(pk, msg, ctx);
    assert(ok);
    return mldsa_sign_internal(set, seed, mu, rnd);
}

// External mu: signs a 64-byte message representative from mldsa_mu.
fn mldsa_sign_mu(set: i64, seed: const u8[:], mu: const u8[:], deterministic: bool = false) -> u8[>..] {
    var rnd: u8[32] = [0; 32];
    if !deterministic { random_bytes(rnd); }
    return mldsa_sign_internal(set, seed, mu, rnd);
}

// --- Verification --------------------------------------------------------------

// ML-DSA.Verify_internal (Algorithm 8) on mu.
fn mldsa_verify_mu(set: i64, pk: const u8[:], mu: const u8[:], sig: const u8[:]) -> bool {
    let p = mldsa_params(set);
    if pk.len != mldsa_pk_len(set) || sig.len != mldsa_sig_len(set) || mu.len != 64 { return false; }
    let clen = p.lambda / 4;
    let zb = mldsa_z_bits(p);
    let ctilde = sig[..clen];
    var z = mldsa_zeros(p.l * 256);
    mldsa_unpack_signed(z, sig[clen..clen + p.l * 32 * zb], p.gamma1, zb);
    var h: bool[>..] = [];
    h.resize(p.k * 256, false);
    if !mldsa_unpack_hints(h, sig[clen + p.l * 32 * zb..], p.k, p.omega) { return false; }
    if mldsa_exceeds(z, p.gamma1 - p.beta) { return false; }
    var t1 = mldsa_zeros(p.k * 256);
    mldsa_unpack(t1, pk[32..], 10);
    var a = mldsa_zeros(p.k * p.l * 256);
    mldsa_expand_a(a, pk[..32], p.k, p.l);
    var c = mldsa_zeros(256);
    mldsa_sample_in_ball(c, ctilde, p.tau);
    mldsa_ntt(c);
    for r in p.l { mldsa_ntt(mldsa_poly(z, r)); }
    // w'approx = A z - c t1 2^d.
    var w = mldsa_zeros(p.k * 256);
    var ct1 = mldsa_zeros(256);
    var w1: u32[>..] = [];
    w1.resize(p.k * 256, 0);
    for i in p.k {
        let wi = mldsa_poly(w, i);
        for j in p.l { mldsa_mul_acc(wi, a[(i * p.l + j) * 256..(i * p.l + j + 1) * 256], mldsa_poly(z, j)); }
        let ti = mldsa_poly(t1, i);
        for x in 256 { ct1[x] = ti[x] << 13; }
        mldsa_ntt(ct1);
        for x in 256 { wi[x] = mldsa_sub(wi[x], mldsa_mul(c[x], ct1[x])); }
        mldsa_ntt_inv(wi);
        for x in 256 { w1[i * 256 + x] = mldsa_use_hint(h[i * 256 + x], wi[x], p.gamma2) as! u32; }
    }
    var cin: u8[>..] = [];
    cin.append(mu);
    mldsa_w1_encode(cin, w1, p);
    return shake(256, cin, clen) == ctilde;
}

// ML-DSA.Verify (Algorithm 3): whether sig signs msg under ctx for pk.
fn mldsa_verify(set: i64, pk: const u8[:], msg: const u8[:], sig: const u8[:], ctx: const u8[:] = "") -> bool {
    if pk.len != mldsa_pk_len(set) { return false; }
    let mu, ok = mldsa_mu(pk, msg, ctx);
    return ok && mldsa_verify_mu(set, pk, mu, sig);
}
