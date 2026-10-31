// bignum.mlkem: ML-KEM (FIPS 203), the module-lattice key encapsulation
// mechanism: ML-KEM-512, ML-KEM-768 and ML-KEM-1024 (k = 2, 3, 4), with
// the 64-byte seed as the private key, as Go's crypto/mlkem keeps it.
//
// Polynomials are 256 coefficients mod q = 3329 in u32s. Every reduction
// is a multiply and shift with a masked correction, never a division, so
// nothing depends on secret values in time (Compress included, the
// KyberSlash pitfall). Decapsulation re-encrypts and selects the implicit
// rejection key with a mask.

namespace bignum;

import std;
import ct;
import sha3;
import entropy;

let MLKEM_Q: u32 = 3329;

// zeta^BitRev7(i) and zeta^(2 BitRev7(i) + 1) for zeta = 17 (FIPS 203 §4.3).
let MLKEM_ZETAS: u32[128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154
];
let MLKEM_GAMMAS: u32[128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229,
    1409, 1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279,
    1703, 1626, 1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642,
    939, 2390, 2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688,
    1584, 1745, 2298, 1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684,
    1063, 2266, 319, 3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735,
    2804, 525, 1092, 2237, 403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443,
    1722, 1607, 1212, 2117, 1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175
];

// The parameter sets, by k.
fn mlkem_eta1(k: i64) -> i64 { if k == 2 { 3 } else { 2 } }
fn mlkem_du(k: i64) -> i64 { if k == 4 { 11 } else { 10 } }
fn mlkem_dv(k: i64) -> i64 { if k == 4 { 5 } else { 4 } }
fn mlkem_ek_len(k: i64) -> i64 { 384 * k + 32 }
fn mlkem_dk_len(k: i64) -> i64 { 768 * k + 96 }
fn mlkem_ct_len(k: i64) -> i64 { 32 * (mlkem_du(k) * k + mlkem_dv(k)) }

// x mod q for any u32, by Barrett: floor(2^32 / q) = 1290167 leaves at most
// one q too many.
fn mlkem_reduce(x: u32) -> u32 {
    let t: u32 = ((x as u64 * 1290167) >> 32) as! u32;
    return mlkem_csub(x - t * MLKEM_Q);
}

// r - q if r >= q, for r < 2q.
fn mlkem_csub(r: u32) -> u32 {
    let t = r - MLKEM_Q;
    return t + ((0 - (t >> 31)) & MLKEM_Q);
}

fn mlkem_mul(a: u32, b: u32) -> u32 { mlkem_reduce(a * b) }

fn mlkem_ntt(f: u32[:]) {
    var i = 1;
    var len = 128;
    while len >= 2 {
        var start = 0;
        while start < 256 {
            let zeta = MLKEM_ZETAS[i];
            i++;
            for j in start..start + len {
                let t = mlkem_mul(zeta, f[j + len]);
                f[j + len] = mlkem_csub(f[j] + MLKEM_Q - t);
                f[j] = mlkem_csub(f[j] + t);
            }
            start += 2 * len;
        }
        len = len / 2;
    }
}

fn mlkem_ntt_inv(f: u32[:]) {
    var i = 127;
    var len = 2;
    while len <= 128 {
        var start = 0;
        while start < 256 {
            let zeta = MLKEM_ZETAS[i];
            i--;
            for j in start..start + len {
                let t = f[j];
                f[j] = mlkem_csub(t + f[j + len]);
                f[j + len] = mlkem_mul(zeta, f[j + len] + MLKEM_Q - t);
            }
            start += 2 * len;
        }
        len = 2 * len;
    }
    for j in 256 { f[j] = mlkem_mul(f[j], 3303); }      // 128^-1 mod q
}

// h += f * g in the NTT domain (MultiplyNTTs, FIPS 203 Algorithm 11).
fn mlkem_mul_acc(h: u32[:], f: const u32[:], g: const u32[:]) {
    for i in 128 {
        let a0 = f[2 * i]; let a1 = f[2 * i + 1];
        let b0 = g[2 * i]; let b1 = g[2 * i + 1];
        let c0 = mlkem_reduce(a0 * b0 + mlkem_mul(mlkem_mul(a1, b1), MLKEM_GAMMAS[i]));
        let c1 = mlkem_reduce(a0 * b1 + a1 * b0);
        h[2 * i] = mlkem_csub(h[2 * i] + c0);
        h[2 * i + 1] = mlkem_csub(h[2 * i + 1] + c1);
    }
}

// ByteEncode_d / ByteDecode_d (Algorithms 5 and 6): d bits a coefficient,
// little-endian. Decoding with d = 12 does not reduce; the caller checks.
fn mlkem_encode(out: u8[>..]&, f: const u32[:], d: i64) {
    var acc: u64 = 0;
    var bits = 0;
    for x in f {
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

fn mlkem_decode(f: u32[:], b: const u8[:], d: i64) {
    var acc: u64 = 0;
    var bits = 0;
    var p = 0;
    let mask: u64 = (1 << d) - 1;
    for i in 256 {
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

// Compress_d(x) = round(2^d x / q) mod 2^d, its division by q done as a
// Barrett multiply and a masked fix.
fn mlkem_compress(x: u32, d: i64) -> u32 {
    let num: u32 = (x << (d as! u32)) + 1664;
    var t: u32 = ((num as u64 * 1290167) >> 32) as! u32;
    let r = num - t * MLKEM_Q;
    t += ((r - MLKEM_Q) >> 31) ^ 1;                    // r >= q: one more
    return t & ((1 << (d as! u32)) - 1);
}

fn mlkem_decompress(y: u32, d: i64) -> u32 {
    ((y * MLKEM_Q + (1 << ((d - 1) as! u32))) >> (d as! u32))
}

// SampleNTT (Algorithm 7): a matrix entry from SHAKE128(rho || j || i).
fn mlkem_sample_ntt(f: u32[:], rho: const u8[:], j: u8, i: u8) {
    var s = shake_init(128);
    sha3_update(s, rho);
    let ji: u8[2] = [j, i];
    sha3_update(s, ji);
    var buf: u8[168] = [0; 168];
    var n = 0;
    while n < 256 {
        shake_read(s, buf);
        var p = 0;
        while p + 3 <= 168 && n < 256 {
            let b0: u32 = buf[p]; let b1: u32 = buf[p + 1]; let b2: u32 = buf[p + 2];
            let d1 = b0 | (b1 & 15) << 8;
            let d2 = b1 >> 4 | b2 << 4;
            if d1 < MLKEM_Q { f[n] = d1; n++; }
            if d2 < MLKEM_Q && n < 256 { f[n] = d2; n++; }
            p += 3;
        }
    }
}

// SamplePolyCBD_eta (Algorithm 8) of PRF_eta(s, b) = SHAKE256(s || b).
fn mlkem_cbd(f: u32[:], s: const u8[:], b: u8, eta: i64) {
    var m: u8[>..] = [];
    m.append(s);
    m.push(b);
    let bytes = shake(256, m, 64 * eta);
    for i in 256 {
        var x: u32 = 0;
        var y: u32 = 0;
        for j in eta {
            let p = 2 * i * eta + j;
            let q = 2 * i * eta + eta + j;
            x += (bytes[p / 8] >> (p % 8)) & 1;
            y += (bytes[q / 8] >> (q % 8)) & 1;
        }
        f[i] = mlkem_csub(x + MLKEM_Q - y);
    }
}

// The matrix A (or its transpose) in the NTT domain: k * k polynomials.
fn mlkem_matrix(a: u32[:], rho: const u8[:], k: i64, transpose: bool) {
    for i in k {
        for j in k {
            let row = if transpose { j } else { i };
            let col = if transpose { i } else { j };
            mlkem_sample_ntt(a[(i * k + j) * 256..(i * k + j + 1) * 256], rho, col as! u8, row as! u8);
        }
    }
}

fn zeros_u32(n: i64) -> u32[>..] {
    var r: u32[>..] = [];
    r.resize(n, 0);
    return r;
}

// K-PKE.KeyGen (Algorithm 13): the encryption key and the secret s in NTT form.
fn kpke_keygen(d: const u8[:], k: i64) -> u8[>..], u8[>..] {
    var seed: u8[>..] = [];
    seed.append(d);
    seed.push(k as! u8);
    let g = sha3(512, seed);
    let rho = g[..32];
    let sigma = g[32..];
    let eta = mlkem_eta1(k);
    var a = zeros_u32(k * k * 256);
    mlkem_matrix(a, rho, k, false);
    var s = zeros_u32(k * 256);
    var e = zeros_u32(k * 256);
    var nonce: u8 = 0;
    for i in k { mlkem_cbd(s[i * 256..(i + 1) * 256], sigma, nonce, eta); nonce++; }
    for i in k { mlkem_cbd(e[i * 256..(i + 1) * 256], sigma, nonce, eta); nonce++; }
    for i in k {
        mlkem_ntt(s[i * 256..(i + 1) * 256]);
        mlkem_ntt(e[i * 256..(i + 1) * 256]);
    }
    var ek: u8[>..] = [];
    var t = zeros_u32(256);
    for i in k {
        for x in 256 { t[x] = e[i * 256 + x]; }
        for j in k { mlkem_mul_acc(t, a[(i * k + j) * 256..(i * k + j + 1) * 256], s[j * 256..(j + 1) * 256]); }
        mlkem_encode(ek, t, 12);
    }
    ek.append(rho);
    var dk: u8[>..] = [];
    mlkem_encode(dk, s, 12);
    return ek, dk;
}

// K-PKE.Encrypt (Algorithm 14).
fn kpke_encrypt(ek: const u8[:], m: const u8[:], r: const u8[:], k: i64) -> u8[>..] {
    let rho = ek[384 * k..];
    var a = zeros_u32(k * k * 256);
    mlkem_matrix(a, rho, k, true);
    var t = zeros_u32(k * 256);
    for i in k { mlkem_decode(t[i * 256..(i + 1) * 256], ek[384 * i..384 * (i + 1)], 12); }
    let eta1 = mlkem_eta1(k);
    var y = zeros_u32(k * 256);
    var e1 = zeros_u32(k * 256);
    var e2 = zeros_u32(256);
    var nonce: u8 = 0;
    for i in k { mlkem_cbd(y[i * 256..(i + 1) * 256], r, nonce, eta1); nonce++; }
    for i in k { mlkem_cbd(e1[i * 256..(i + 1) * 256], r, nonce, 2); nonce++; }
    mlkem_cbd(e2, r, nonce, 2);
    for i in k { mlkem_ntt(y[i * 256..(i + 1) * 256]); }
    var c: u8[>..] = [];
    let du = mlkem_du(k);
    let dv = mlkem_dv(k);
    var u = zeros_u32(256);
    for i in k {
        for x in 256 { u[x] = 0; }
        for j in k { mlkem_mul_acc(u, a[(i * k + j) * 256..(i * k + j + 1) * 256], y[j * 256..(j + 1) * 256]); }
        mlkem_ntt_inv(u);
        for x in 256 { u[x] = mlkem_compress(mlkem_csub(u[x] + e1[i * 256 + x]), du); }
        mlkem_encode(c, u, du);
    }
    var v = zeros_u32(256);
    for j in k { mlkem_mul_acc(v, t[j * 256..(j + 1) * 256], y[j * 256..(j + 1) * 256]); }
    mlkem_ntt_inv(v);
    var mu = zeros_u32(256);
    mlkem_decode(mu, m, 1);
    for x in 256 {
        let w = mlkem_csub(mlkem_csub(v[x] + e2[x]) + mlkem_decompress(mu[x], 1));
        v[x] = mlkem_compress(w, dv);
    }
    mlkem_encode(c, v, dv);
    return c;
}

// K-PKE.Decrypt (Algorithm 15).
fn kpke_decrypt(dk: const u8[:], c: const u8[:], k: i64) -> u8[>..] {
    let du = mlkem_du(k);
    let dv = mlkem_dv(k);
    var w = zeros_u32(256);
    var u = zeros_u32(256);
    var s = zeros_u32(256);
    for i in k {
        mlkem_decode(u, c[32 * du * i..32 * du * (i + 1)], du);
        for x in 256 { u[x] = mlkem_decompress(u[x], du); }
        mlkem_ntt(u);
        mlkem_decode(s, dk[384 * i..384 * (i + 1)], 12);
        mlkem_mul_acc(w, s, u);
    }
    mlkem_ntt_inv(w);
    var v = zeros_u32(256);
    mlkem_decode(v, c[32 * du * k..], dv);
    for x in 256 {
        let vx = mlkem_decompress(v[x], dv);
        w[x] = mlkem_compress(mlkem_csub(vx + MLKEM_Q - w[x]), 1);
    }
    var m: u8[>..] = [];
    mlkem_encode(m, w, 1);
    return m;
}

// The keys of a 64-byte seed d || z (ML-KEM.KeyGen_internal, Algorithm
// 16): the encapsulation key, and the expanded decapsulation key.
fn mlkem_keys_from_seed(k: i64, seed: const u8[:]) -> u8[>..], u8[>..] {
    assert((k == 2 || k == 3 || k == 4) && seed.len == 64);
    let ek, dkp = kpke_keygen(seed[..32], k);
    var dk: u8[>..] = [];
    dk.append(dkp);
    dk.append(ek);
    dk.append(sha3(256, ek));
    dk.append(seed[32..]);
    return ek, dk;
}

// A fresh key pair from the OS's entropy: the seed (the private key) and
// the encapsulation key.
fn mlkem_keygen(k: i64) -> u8[>..], u8[>..] {
    var seed: u8[>..] = [];
    seed.resize(64, 0);
    random_bytes(seed);
    let ek, dk = mlkem_keys_from_seed(k, seed);
    return seed, ek;
}

// Whether ek is well formed: its length, and every coefficient below q
// (the modulus check of FIPS 203 §7.2).
fn mlkem_ek_ok(k: i64, ek: const u8[:]) -> bool {
    if ek.len != mlkem_ek_len(k) { return false; }
    var f = zeros_u32(256);
    for i in k {
        mlkem_decode(f, ek[384 * i..384 * (i + 1)], 12);
        for x in f { if x >= MLKEM_Q { return false; } }
    }
    return true;
}

// ML-KEM.Encaps_internal (Algorithm 17) with the message m: the 32-byte
// shared secret and the ciphertext; false for a malformed ek.
fn mlkem_encaps_with(k: i64, ek: const u8[:], m: const u8[:]) -> u8[>..], u8[>..], bool {
    var key: u8[>..] = [];
    if !mlkem_ek_ok(k, ek) || m.len != 32 { var nc: u8[>..] = []; return key, nc, false; }
    var g_in: u8[>..] = [];
    g_in.append(m);
    g_in.append(sha3(256, ek));
    let g = sha3(512, g_in);
    let c = kpke_encrypt(ek, m, g[32..], k);
    key.append(g[..32]);
    return key, c, true;
}

fn mlkem_encaps(k: i64, ek: const u8[:]) -> u8[>..], u8[>..], bool {
    var m: u8[32] = [0; 32];
    random_bytes(m);
    return mlkem_encaps_with(k, ek, m);
}

// ML-KEM.Decaps (Algorithm 18) from the expanded key dk: the shared
// secret, or for a ciphertext that does not re-encrypt to itself the
// implicit rejection key J(z || c), chosen in constant time. False only
// for malformed lengths or a dk whose hash of ek does not match.
fn mlkem_decaps_dk(k: i64, dk: const u8[:], c: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if dk.len != mlkem_dk_len(k) || c.len != mlkem_ct_len(k) { return out, false; }
    let dkp = dk[..384 * k];
    let ek = dk[384 * k..768 * k + 32];
    let h = dk[768 * k + 32..768 * k + 64];
    let z = dk[768 * k + 64..];
    if sha3(256, ek) != h { return out, false; }
    let m2 = kpke_decrypt(dkp, c, k);
    var g_in: u8[>..] = [];
    g_in.append(m2);
    g_in.append(h);
    let g = sha3(512, g_in);
    var jz: u8[>..] = [];
    jz.append(z);
    jz.append(c);
    let reject = shake(256, jz, 32);
    let c2 = kpke_encrypt(ek, m2, g[32..], k);
    let same = ct_eq_bytes(c, c2);
    let mask: u8 = (0 - same) as! u8;                  // 0xff when they match
    out.resize(32, 0);
    for i in 32 { out[i] = reject[i] ^ (mask & (reject[i] ^ g[i])); }
    return out, true;
}

// Decapsulation from the 64-byte seed, as the private key.
fn mlkem_decaps(k: i64, seed: const u8[:], c: const u8[:]) -> u8[>..], bool {
    let ek, dk = mlkem_keys_from_seed(k, seed);
    return mlkem_decaps_dk(k, dk, c);
}
