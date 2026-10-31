// bignum.dsa: DSA (FIPS 186-4), for legacy keys and signatures, as Go's
// crypto/dsa keeps it: parameter generation for (L, N) = (1024, 160),
// (2048, 224), (2048, 256) and (3072, 256), keys, signatures with a random
// nonce, deterministic ones (RFC 6979), and verification. The digest is
// cut to its leftmost N bits, as FIPS 186 and openssl do (Go's crypto/dsa
// leaves that to the caller).
//
// Everything that touches x or a nonce is constant time: the nonce and a
// new x are drawn below q without a branch on them, x is checked and the
// deterministic nonce tested against q likewise, and g^k mod p and the
// arithmetic mod q go through bignum.mont. Verification and parameter
// generation, which see only public values, use BigInt.

namespace bignum;

import std;
import bignum;
import ct;
import mont;
import hmac;
import rsa;
import ec;
import entropy;

// A key: the domain parameters p, q, g, the public y, and the private x
// (empty for a public key), big-endian, p g y as wide as p and x as q.
struct DsaKey { p: u8[..384], q: u8[..32], g: u8[..384], y: u8[..384], x: u8[..32] }

fn dsa_be(v, width: i64) -> u8[>..] { to_bytes_be(v, width) }

fn dsa_width(b: const u8[:]) -> i64 { (bit_len(from_bytes_be(b)) + 7) / 8 }

// A key from its parts; false unless p and q are odd, q has 160, 224 or
// 256 bits and p at most 3072, 1 < g < p, 0 < y < p and 0 < x < q.
fn dsa_key_from(p: const u8[:], q: const u8[:], g: const u8[:], y: const u8[:], x: const u8[:] = "") -> DsaKey, bool {
    var k = DsaKey { p: [], q: [], g: [], y: [], x: [] };
    let pb = from_bytes_be(p);
    let qb = from_bytes_be(q);
    let gb = from_bytes_be(g);
    let yb = from_bytes_be(y);
    let lp = bit_len(pb);
    let nq = bit_len(qb);
    if !is_odd(pb) || !is_odd(qb) || lp > 3072 || lp < 512 || (nq != 160 && nq != 224 && nq != 256) { return k, false; }
    if !gt(gb, one()) || !lt(gb, pb) || is_zero(yb) || !lt(yb, pb) { return k, false; }
    let pw = (lp + 7) / 8;
    let qw = nq / 8;
    k.p.append(dsa_be(pb, pw));
    k.q.append(dsa_be(qb, qw));
    k.g.append(dsa_be(gb, pw));
    k.y.append(dsa_be(yb, pw));
    // x is secret: checked and padded to q's width in constant time, in
    // one pass over all of it whatever its value; only its length (public)
    // decides which bytes land where. Those above q's width must be zero.
    if x.len > 0 {
        k.x.resize(qw, 0);
        var high: u32 = 0;
        for i in x.len {
            let j = i - (x.len - qw);
            if j >= 0 { k.x[j] = x[i]; } else { high |= x[i]; }
        }
        if (ct_is_zero_u32(high) & dsa_in_range(k.q, k.x)) == 0 { k.x.clear(); return k, false; }
    }
    return k, true;
}

// 1 if 0 < v < q for v as wide as q, in constant time, else 0.
fn dsa_in_range(q: const u8[:], v: const u8[:]) -> u32 {
    let n = (q.len + 3) / 4;
    var ql = zero_limbs(n);
    limbs_from_be(ql, q);
    var vl = zero_limbs(n);
    limbs_from_be(vl, v);
    return ct_lt(vl, ql) & (ct_is_zero(vl) ^ 1);
}

// A uniform random number in [1, q - 1], as wide as q, in constant time.
fn dsa_random_scalar(q: const u8[:]) -> u8[>..] {
    let n = (q.len + 3) / 4;
    var ql = zero_limbs(n);
    limbs_from_be(ql, q);
    var r = zero_limbs(n);
    random_below(r, ql);
    var out: u8[>..] = [];
    out.resize(q.len, 0);
    be_from_limbs(out, r);
    return out;
}

// The public half of a key.
fn dsa_public(k: const DsaKey&) -> DsaKey {
    var pub = DsaKey { p: [], q: [], g: [], y: [], x: [] };
    pub.p.append(k.p);
    pub.q.append(k.q);
    pub.g.append(k.g);
    pub.y.append(k.y);
    return pub;
}

// Domain parameters for (L, N), as Go's GenerateParameters makes them: a
// random N-bit prime q, then random L-bit p = 1 mod 2q until one is prime
// (64 Miller-Rabin rounds each), and g = h^((p-1)/q) for the first h from
// 2 that gives g > 1. Returns p, q, g.
fn dsa_generate_parameters(l: i64, n: i64) -> u8[>..], u8[>..], u8[>..] {
    assert(l == 1024 && n == 160 || l == 2048 && (n == 224 || n == 256) || l == 3072 && n == 256);
    let primes = small_primes();
    loop {
        let q = bit_or(random_bits_vartime(n), add(shl(one(), n - 1), one()));
        if !dsa_probably_prime(q, primes) { continue; }
        let q2 = shl(q, 1);
        for attempt in 4 * l {
            let c = bit_or(random_bits_vartime(l), add(shl(one(), l - 1), one()));
            let p = add(sub(c, rem(c, q2)), one());
            if bit_len(p) < l { continue; }
            if !dsa_probably_prime(p, primes) { continue; }
            let e = div(sub(p, one()), q);
            var h: i64 = 2;
            loop {
                let g = modpow(big(h), e, p);
                if !eq(g, one()) { return dsa_be(p, l / 8), dsa_be(q, n / 8), dsa_be(g, l / 8); }
                h++;
            }
        }
    }
}

// Whether v (a BigInt) is prime: trial division by `primes`
// (small_primes()), then 64 Miller-Rabin rounds. Variable time, for public
// candidates (DSA's parameters). Any v: negatives, 0 and 1 are not prime.
fn dsa_probably_prime(v, primes: const u32[:]) -> bool {
    // Small values first: below 2 none is prime, 2 is the even one, and a
    // small prime is not composite for dividing itself. Miller-Rabin then
    // gets only odd values above the small primes, as it needs.
    if v.neg || cmp_i64(v, 2) < 0 { return false; }
    if !is_odd(v) { return cmp_i64(v, 2) == 0; }
    for sp in primes {
        if v.mag.len == 1 && v.mag[0] == sp { return true; }
        if ct_mod_small(v.mag, sp) == 0 { return false; }
    }
    return miller_rabin_vartime(v, 64);
}

// A fresh key for the parameters: x uniform in [1, q - 1], y = g^x mod p.
fn dsa_generate_key(p: const u8[:], q: const u8[:], g: const u8[:]) -> DsaKey, bool {
    let xs = dsa_random_scalar(q);
    let y = dsa_powmod(g, xs, p);
    return dsa_key_from(p, q, g, y, xs);
}

// base^e mod m in constant time (m odd), as m's width in bytes.
fn dsa_powmod(base: const u8[:], e: const u8[:], m: const u8[:]) -> u8[>..] {
    let n = (m.len + 3) / 4;
    var ml = zero_limbs(n);
    limbs_from_be(ml, m);
    var bl = zero_limbs(n);
    var wide = zero_limbs((base.len + 3) / 4);
    limbs_from_be(wide, base);
    ct_reduce(bl, wide, ml);
    var el = zero_limbs((e.len + 3) / 4);
    limbs_from_be(el, e);
    var r2 = zero_limbs(n);
    mont_r2(r2, ml);
    var r = zero_limbs(n);
    mont_modexp(r, bl, el, ml, mont_m0i(ml[0]), r2);
    var out: u8[>..] = [];
    out.resize(m.len, 0);
    be_from_limbs(out, r);
    return out;
}

// bits2int (RFC 6979 §2.3.2) for an N multiple of 8: the digest's
// leftmost N bits, as q's width in bytes.
fn dsa_bits2int(q: const u8[:], h: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.resize(q.len, 0);
    if h.len >= q.len { for i in q.len { out[i] = h[i]; } }
    else { for i in h.len { out[q.len - h.len + i] = h[i]; } }
    return out;
}

// The mod-q arithmetic of signing, in Montgomery form over q's limbs.
struct DsaModQ { q: u32[..8], r2: u32[..8], m0i: u32 }

fn dsa_modq(q: const u8[:]) -> DsaModQ {
    let n = (q.len + 3) / 4;
    var m = DsaModQ { q: [], r2: [], m0i: 0 };
    m.q.resize(n, 0);
    m.r2.resize(n, 0);
    limbs_from_be(m.q, q);
    mont_r2(m.r2, m.q);
    m.m0i = mont_m0i(m.q[0]);
    return m;
}

// v mod q, from big-endian bytes of any width.
fn dsa_reduce(m: const DsaModQ&, v: const u8[:]) -> u32[>..] {
    var wide = zero_limbs((v.len + 3) / 4 + 1);
    limbs_from_be(wide, v);
    var r = zero_limbs(m.q.len);
    ct_reduce(r, wide, m.q);
    return r;
}

fn dsa_mulq(m: const DsaModQ&, a: const u32[:], b: const u32[:]) -> u32[>..] {
    let n = m.q.len;
    var t = zero_limbs(n + 2);
    var x = zero_limbs(n);
    var r = zero_limbs(n);
    mont_mul(x, a, b, m.q, m.m0i, t);            // a b / R
    mont_mul(r, x, m.r2, m.q, m.m0i, t);         // a b
    return r;
}

// s = k^-1 (z + x r) mod q and r = (g^k mod p) mod q for the nonce k in
// [1, q - 1]; false when r or s is 0, for a new nonce.
fn dsa_sign_with(k: const DsaKey&, z: const u8[:], nonce: const u8[:]) -> u8[>..], bool {
    let m = dsa_modq(k.q);
    let n = m.q.len;
    let gk = dsa_powmod(k.g, nonce, k.p);
    let r = dsa_reduce(m, gk);
    let zr = dsa_reduce(m, z);
    let xr = dsa_reduce(m, k.x);
    let kl = dsa_reduce(m, nonce);
    var qm2 = zero_limbs(n);
    var two = zero_limbs(n);
    two[0] = 2;
    let borrow = ct_sub(qm2, m.q, two);
    var kinv = zero_limbs(n);
    mont_modexp(kinv, kl, qm2, m.q, m.m0i, m.r2);   // k^(q-2) = 1/k
    var sum = zero_limbs(n);
    ct_mod_add(sum, zr, dsa_mulq(m, xr, r), m.q);
    let s = dsa_mulq(m, kinv, sum);
    var sig: u8[>..] = [];
    sig.resize(2 * k.q.len, 0);
    be_from_limbs(sig[..k.q.len], r);
    be_from_limbs(sig[k.q.len..], s);
    return sig, ct_is_zero(r) == 0 && ct_is_zero(s) == 0;
}

// A signature r || s (each as wide as q) of a digest, with a random nonce.
fn dsa_sign(k: const DsaKey&, digest: const u8[:]) -> u8[>..] {
    assert(k.x.len > 0);
    let z = dsa_bits2int(k.q, digest);
    loop {
        let nonce = dsa_random_scalar(k.q);
        let sig, ok = dsa_sign_with(k, z, nonce);
        if ok { return sig; }
    }
}

// A deterministic signature (RFC 6979 §3.2), the nonce drawn from
// HMAC-DRBG on the hash `hash_id` (a bignum.hmac id) that made the digest.
fn dsa_sign_deterministic(k: const DsaKey&, digest: const u8[:], hash_id: i64) -> u8[>..] {
    assert(k.x.len > 0);
    let z = dsa_bits2int(k.q, digest);
    let q = from_bytes_be(k.q);
    let h1 = dsa_be(rem(from_bytes_be(z), q), k.q.len);     // bits2octets
    let hl = hash_len(hash_id);
    var v: u8[>..] = [];
    v.resize(hl, 1);
    var kk: u8[>..] = [];
    kk.resize(hl, 0);
    var m: u8[>..] = [];
    for round in 2 {
        m.clear();
        m.append(v);
        m.push(round as! u8);
        m.append(k.x);
        m.append(h1);
        let nk = hmac(hash_id, kk, m);
        kk = copy(nk);
        let nv = hmac(hash_id, kk, v);
        v = copy(nv);
    }
    loop {
        var t: u8[>..] = [];
        while t.len < k.q.len {
            let nv = hmac(hash_id, kk, v);
            v = copy(nv);
            t.append(v);
        }
        let nonce = dsa_bits2int(k.q, t);
        if dsa_in_range(k.q, nonce) == 1 {
            let sig, ok = dsa_sign_with(k, z, nonce);
            if ok { return sig; }
        }
        m.clear();
        m.append(v);
        m.push(0);
        let nk = hmac(hash_id, kk, m);
        kk = copy(nk);
        let nv = hmac(hash_id, kk, v);
        v = copy(nv);
    }
}

// Whether r || s signs the digest: 0 < r, s < q, and
// ((g^(z/s) y^(r/s)) mod p) mod q == r.
fn dsa_verify(k: const DsaKey&, digest: const u8[:], sig: const u8[:]) -> bool {
    let w = k.q.len;
    if sig.len != 2 * w || w == 0 { return false; }
    let q = from_bytes_be(k.q);
    let p = from_bytes_be(k.p);
    let r = from_bytes_be(sig[..w]);
    let s = from_bytes_be(sig[w..]);
    if is_zero(r) || !lt(r, q) || is_zero(s) || !lt(s, q) { return false; }
    let sinv, ok = modinv(s, q);
    if !ok { return false; }
    let z = from_bytes_be(dsa_bits2int(k.q, digest));
    let u1 = rem(mul(z, sinv), q);
    let u2 = rem(mul(r, sinv), q);
    let v = rem(rem(mul(modpow(from_bytes_be(k.g), u1, p), modpow(from_bytes_be(k.y), u2, p)), p), q);
    return eq(v, r);
}

// DER (SEQUENCE of two INTEGERs, as X.509 and openssl carry DSA
// signatures) to and from r || s.
fn dsa_sig_to_der(raw: const u8[:]) -> u8[>..] { ecdsa_sig_to_der(raw) }

fn dsa_sig_from_der(k: const DsaKey&, der: const u8[:]) -> u8[>..], bool {
    let raw, ok = sig_from_der(k.q.len, der);
    return raw, ok;
}
