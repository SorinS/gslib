// bignum.rsa: RSA (RFC 8017): key generation, PKCS #1 v1.5 and PSS
// signatures and OAEP encryption with SHA-1, SHA-2 or SHA-3 (bignum.hmac's
// hash ids), and PKCS #1 v1.5 encryption. Keys up to 8192 bits, Go's
// limit for TLS peers' keys (crypto/tls defaultMaxRSAKeySize).
//
// Everything that touches a private key is constant time, on limbs of the
// key's width (bignum.ct and bignum.mont), with only the key's size public:
// - the private-key operation: CRT with Montgomery exponentiation, the
//   reductions done bit by bit, the input blinded by a random r^e (r and
//   1/r in constant time too), and the result checked against the public
//   key: a fault in one CRT half would give the key away with the result,
//   so a result that fails the check is never released, and the operation
//   fails instead (a signature returns false; a decryption folds it into
//   its other checks, so it fails the way a bad ciphertext does);
// - loading a key (rsa_key_from, rsa_key_from_bytes): dp, dq and qinv
//   derived and every check made without a branch on the numbers;
// - generating one: candidates p = 3 mod 4, trial division without a
//   division, Miller-Rabin on Montgomery exponentiation, and d = 1/e mod
//   (p - 1)(q - 1) by way of the public e. Only candidates that fail are
//   branched on, and they are thrown away.
// - encrypting (OAEP and PKCS #1 v1.5): the padded message is secret, so
//   m^e mod n is a Montgomery exponentiation too (rsa_public_op_ct).
// Verifying a signature uses BigInt, as nothing in it is secret.

namespace bignum;

import std;
import bignum;
import ct;
import mont;
import sha256;
import hmac;
import entropy;

// Little-endian limbs, normalized: n, p and q have no zero top limb, and
// each exponent and qinv is padded to its modulus' width (d to n's, dp and
// qinv to p's, dq to q's), so lengths say nothing more than the key size.
struct RsaPublicKey { n: u32[..256], e: u32[..256] }

struct RsaPrivateKey {
    n: u32[..256], e: u32[..256], d: u32[..256],
    p: u32[..128], q: u32[..128], dp: u32[..128], dq: u32[..128], qinv: u32[..128],
}

// dst = the limbs of v >= 0, exactly w of them.
fn set_limbs<A>(dst: A&, v, w: i64) {
    assert(v.mag.len <= w);
    dst.clear();
    for i in w { dst.push(if i < v.mag.len { v.mag[i] } else { 0 }); }
}

fn zero_limbs(n: i64) -> u32[>..] {
    var r: u32[>..] = [];
    r.resize(n, 0);
    return r;
}

// The modulus size in bits, and in bytes (the size of every signature
// and ciphertext).
fn rsa_bits(key) -> i64 { mag_bit_len(key.n) }
fn rsa_size(key) -> i64 { (rsa_bits(key) + 7) / 8 }

fn mag_bit_len(xs) -> i64 {
    if xs.len == 0 { return 0; }
    return 32 * xs.len - ::clz(xs[xs.len - 1] as u64) + 32;
}

fn rsa_public(key) -> RsaPublicKey {
    var r = RsaPublicKey { n: [], e: [] };
    for x in key.n { r.n.push(x); }
    for x in key.e { r.e.push(x); }
    return r;
}

// A public key from its numbers; false unless n is odd and 1024 to 8192
// bits, and e is odd, 3 <= e < 2^31 (as Go's crypto/rsa: smaller keys are
// broken, and a larger e only makes verifying slow).
fn rsa_public_from(n, e) -> RsaPublicKey, bool {
    var r = RsaPublicKey { n: [], e: [] };
    let bits = bit_len(n);
    if n.neg || e.neg || bits < 1024 || bits > 8192 || !is_odd(n) || !is_odd(e)
        || cmp_i64(e, 1) <= 0 || bit_len(e) > 31 {
        return r, false;
    }
    set_limbs(r.n, n, n.mag.len);
    set_limbs(r.e, e, e.mag.len);
    return r, true;
}

// A private key from n, e, d, p and q, with the CRT values derived and the
// whole checked for consistency (rsa_key_from_limbs).
fn rsa_key_from(n, e, d, p, q) -> RsaPrivateKey, bool {
    if n.neg || e.neg || d.neg || p.neg || q.neg {
        return RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] }, false;
    }
    return rsa_key_from_limbs(n.mag, e.mag, d.mag, p.mag, q.mag);
}

// The same from big-endian bytes, as PKCS #1 holds them.
fn rsa_key_from_bytes(n: const u8[:], e: const u8[:], d: const u8[:], p: const u8[:], q: const u8[:])
        -> RsaPrivateKey, bool {
    let nl = be_limbs(n);
    let el = be_limbs(e);
    let dl = be_limbs(d);
    let pl = be_limbs(p);
    let ql = be_limbs(q);
    return rsa_key_from_limbs(nl, el, dl, pl, ql);
}

// Big-endian bytes as limbs, every byte read: leading zero bytes (a DER
// INTEGER's sign byte) give zero top limbs.
fn be_limbs(b: const u8[:]) -> u32[>..] {
    var r = zero_limbs((b.len + 3) / 4);
    limbs_from_be(r, b);
    return r;
}

// The number of limbs below the zero top ones, every limb read. For the
// widths of p and q: the result is public, as in Go (each is half the
// key's size), but not the values that give it.
fn limb_len(xs: const u32[:]) -> i64 {
    var k: u32 = 0;
    for i in xs.len { k = ct_select_u32(ct_mask(ct_is_zero_u32(xs[i]) ^ 1), (i + 1) as! u32, k); }
    let r: i64 = k;
    return r;
}

// The bit length of xs, every limb read, without BigInt: the result is
// branched on (as Go does for |p - q| and d), but not the limbs.
fn ct_bit_len(xs: const u32[:]) -> i64 {
    var bits: u32 = 0;
    for i in xs.len {
        let x = xs[i];
        let b = (32 * i + 64 - ::clz(x | 1)) as! u32;    // x | 1: the same length, and never 0
        bits = ct_select_u32(ct_mask(ct_is_zero_u32(x) ^ 1), b, bits);
    }
    let r: i64 = bits;
    return r;
}

// 1 if every limb of xs from the from-th on is zero, else 0.
fn ct_zero_above(xs: const u32[:], from: i64) -> u32 {
    var acc: u32 = 0;
    for i in from..xs.len { acc = acc | xs[i]; }
    return ct_is_zero_u32(acc);
}

// dst = xs, padded with zero limbs or cut to dst's width.
fn put_limbs(dst: u32[:], xs: const u32[:]) {
    for i in dst.len { dst[i] = if i < xs.len { xs[i] } else { 0 }; }
}

// 1 if e x == 1 mod m, else 0.
fn ct_inverse_check(e: const u32[:], x: const u32[:], m: const u32[:]) -> u32 {
    var ex = zero_limbs(e.len + x.len);
    ct_mul(ex, e, x);
    var r = zero_limbs(m.len);
    ct_reduce(r, ex, m);
    return ct_is_one(r);
}

// A private key from little-endian limbs, in constant time: dp = d mod
// (p - 1) and dq = d mod (q - 1) by bitwise reduction, qinv = q^(p - 2)
// mod p (Fermat), and the checks (p and q odd and above 1, p q = n,
// d < n, e dp = 1 mod p - 1, e dq = 1 mod q - 1, qinv q = 1 mod p) made on
// every value whatever the earlier ones gave. Only their outcome is
// branched on, so a valid key takes the one path. The lengths (the key's
// size) are public, and n and e. Then Go's last two checks, which reveal
// only magnitudes, and not adaptively: |p - q| > 2^(nbits/2 - 100) (Fermat
// factors n when p and q are close) and d > 2^(nbits/2) (Wiener and
// Boneh-Durfee recover a small d). Last, one private operation is checked
// against the public key.
fn rsa_key_from_limbs(n: const u32[:], e: const u32[:], d: const u32[:], p: const u32[:], q: const u32[:])
        -> RsaPrivateKey, bool {
    var k = RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
    let pub, ok = rsa_public_from(big_of(n), big_of(e));
    let nl = pub.n.len;
    let pl = limb_len(p);
    let ql = limb_len(q);
    if !ok || pl == 0 || ql == 0 || pl > k.p.cap || ql > k.q.cap || pl + ql < nl {
        return k, false;
    }
    let pn = p[..pl];
    let qn = q[..ql];
    var good = pn[0] & qn[0] & 1 & (ct_is_one(pn) ^ 1) & (ct_is_one(qn) ^ 1);
    var pq = zero_limbs(pl + ql);
    ct_mul(pq, pn, qn);
    var nw = zero_limbs(pl + ql);
    put_limbs(nw, pub.n);
    good = good & ct_eq(pq, nw);
    var dn = zero_limbs(nl);
    put_limbs(dn, d);
    good = good & ct_zero_above(d, nl) & ct_lt(dn, pub.n);
    if good == 0 { return k, false; }

    let nbits = mag_bit_len(pub.n);
    let w = if pl > ql { pl } else { ql };
    var pw = zero_limbs(w);
    var qw = zero_limbs(w);
    put_limbs(pw, pn);
    put_limbs(qw, qn);
    var pmq = zero_limbs(w);
    var qmp = zero_limbs(w);
    let borrow = ct_sub(pmq, pw, qw);
    ct_sub(qmp, qw, pw);
    var pqdiff = zero_limbs(w);
    ct_select(pqdiff, ct_mask(borrow), qmp, pmq);
    if ct_bit_len(pqdiff) <= nbits / 2 - 100 || ct_bit_len(dn) <= nbits / 2 {
        return k, false;
    }

    // p and q are odd: p - 1 and q - 1 clear the low bit.
    var p1 = zero_limbs(pl);
    put_limbs(p1, pn);
    p1[0] = p1[0] & 0xfffffffe;
    var q1 = zero_limbs(ql);
    put_limbs(q1, qn);
    q1[0] = q1[0] & 0xfffffffe;
    var dp = zero_limbs(pl);
    ct_reduce(dp, dn, p1);
    var dq = zero_limbs(ql);
    ct_reduce(dq, dn, q1);

    let p0i = mont_m0i(pn[0]);
    var r2p = zero_limbs(pl);
    mont_r2(r2p, pn);
    var qp = zero_limbs(pl);
    ct_reduce(qp, qn, pn);
    var p2 = zero_limbs(pl);
    var two = zero_limbs(pl);
    two[0] = 2;
    ct_sub(p2, pn, two);                         // p >= 3: no borrow
    var qinv = zero_limbs(pl);
    mont_modexp(qinv, qp, p2, pn, p0i, r2p);

    var t = zero_limbs(pl + 2);
    var x = zero_limbs(pl);
    var y = zero_limbs(pl);
    mont_mul(x, qinv, qp, pn, p0i, t);           // qinv q / R
    mont_mul(y, x, r2p, pn, p0i, t);             // qinv q
    good = ct_is_one(y) & ct_inverse_check(pub.e, dp, p1) & ct_inverse_check(pub.e, dq, q1);
    if good == 0 { return k, false; }

    for v in pub.n { k.n.push(v); }
    for v in pub.e { k.e.push(v); }
    for v in dn { k.d.push(v); }
    for v in pn { k.p.push(v); }
    for v in qn { k.q.push(v); }
    for v in dp { k.dp.push(v); }
    for v in dq { k.dq.push(v); }
    for v in qinv { k.qinv.push(v); }

    // A pairwise consistency test: numbers that pass every check above
    // with a q (or p) that is not prime give a CRT that is wrong, which
    // every private operation's check would then catch and fail on. One
    // operation here refuses such a key instead.
    var c = zero_limbs(nl);
    c[0] = 2;
    var m = zero_limbs(nl);
    if rsa_private_checked(k, m, c) == 0 { return k, false; }
    return k, true;
}

// The odd primes below 2000, for trial division.
fn small_primes() -> u32[>..] {
    var sieve: bool[2000] = [true; 2000];
    var out: u32[>..] = [];
    for i in 3..2000 {
        if !sieve[i] { continue; }
        if i % 2 == 0 { continue; }
        out.push(i as! u32);
        var j = i * i;
        while j < 2000 { sieve[j] = false; j += i; }
    }
    return out;
}

// A uniform random integer in [0, 2^bits), and in [lo, hi) for lo < hi.
// Variable time: for public values (DSA's domain parameters).
fn random_bits_vartime(bits: i64) -> BigInt {
    var b: u8[>..] = [];
    b.resize((bits + 7) / 8, 0);
    random_bytes(b);
    let extra = 8 * b.len - bits;
    if extra > 0 { b[0] = b[0] & (255 >> extra) as! u8; }
    return from_bytes_be(b);
}

fn random_range_vartime(lo, hi) -> BigInt {
    let span = sub(hi, lo);
    let bits = bit_len(span);
    loop {
        let r = random_bits_vartime(bits);
        if lt(r, span) { return add(r, lo); }
    }
}

// r = a uniform random number in [1, m), at m's width (m > 1 with no zero
// top limb), in constant time: random bits up to m's length, drawn again
// until they fall in range. Only the rejected draws are branched on, and
// they are thrown away.
fn random_below(r: u32[:], m: const u32[:]) {
    assert(r.len == m.len && m[m.len - 1] != 0);
    let top = mag_bit_len(m) - 32 * (m.len - 1);  // m's length is public
    var b: u8[>..] = [];
    b.resize(4 * m.len, 0);
    loop {
        random_bytes(b);
        limbs_from_be(r, b);
        if top < 32 { r[m.len - 1] = r[m.len - 1] & ((1 << top) - 1) as! u32; }
        if (ct_lt(r, m) & (ct_is_zero(r) ^ 1)) == 1 { return; }
    }
}

// Miller-Rabin with `rounds` random bases, for odd p > 3. Variable time
// (s and d come from BigInt): for public candidates, as DSA's p and q.
fn miller_rabin_vartime(p, rounds: i64) -> bool {
    // An odd p of 5 or more: below, p - 1 has no odd part to find (p = 1
    // loops) or no base in [2, p - 1) to draw.
    assert(is_odd(p) && cmp_i64(p, 5) >= 0);
    let n = p.mag.len;
    let m = p.mag;
    let m0i = mont_m0i(m[0]);
    var r2 = zero_limbs(n);
    mont_r2(r2, m);
    let p1 = sub(p, one());
    var s = 0;
    while !test_bit(p1, s) { s++; }
    let dexp = shr(p1, s);
    var minus1 = zero_limbs(n);
    for i in p1.mag.len { minus1[i] = p1.mag[i]; }
    var one_l = zero_limbs(n);
    one_l[0] = 1;
    var x = zero_limbs(n);
    var a = zero_limbs(n);
    var t = zero_limbs(n + 2);
    var tmp = zero_limbs(n);
    for round in rounds {
        let base = random_range_vartime(big(2), p1);
        for i in n { a[i] = if i < base.mag.len { base.mag[i] } else { 0 }; }
        mont_modexp(x, a, dexp.mag, m, m0i, r2);
        if ct_eq(x, one_l) == 1 || ct_eq(x, minus1) == 1 { continue; }
        var witness = true;
        for i in s - 1 {
            mont_mul(tmp, x, x, m, m0i, t);              // x^2 / R
            mont_mul(x, tmp, r2, m, m0i, t);             // x^2
            if ct_eq(x, minus1) == 1 { witness = false; break; }
        }
        if witness { return false; }
    }
    return true;
}

// Miller-Rabin with `rounds` random bases for p = 3 mod 4 (p > 3), in
// constant time. Such a p has p - 1 = 2 d with d odd, so a base passes
// when a^d is 1 or -1, and every round is one exponentiation of p's
// length. Only a composite's failed round is branched on.
fn rsa_miller_rabin(p: const u32[:], rounds: i64) -> bool {
    let n = p.len;
    let m0i = mont_m0i(p[0]);
    var r2 = zero_limbs(n);
    mont_r2(r2, p);
    var minus1 = zero_limbs(n);                  // p - 1: p is odd
    put_limbs(minus1, p);
    minus1[0] = minus1[0] & 0xfffffffe;
    var dexp = zero_limbs(n);                    // (p - 1) / 2
    put_limbs(dexp, minus1);
    ct_shr1(dexp);
    var a = zero_limbs(n);
    var x = zero_limbs(n);
    for round in rounds {
        loop {                                   // a in [2, p - 2]
            random_below(a, minus1);
            if ct_is_one(a) == 0 { break; }
        }
        mont_modexp(x, a, dexp, p, m0i, r2);
        if (ct_is_one(x) | ct_eq(x, minus1)) == 0 { return false; }
    }
    return true;
}

// A random prime of `limbs` limbs with its top two bits set (so a product
// of two has twice the bits), p = 3 mod 4, and p - 1 prime to e, found in
// constant time: trial division without dividing, a gcd test with e by
// ct_mod_inv, then rsa_miller_rabin. Only a failed candidate is branched
// on, and it is thrown away.
fn rsa_random_prime(limbs: i64, e: const u32[:], primes: const u32[:]) -> u32[>..] {
    let bits = 32 * limbs;
    let rounds = if bits >= 1024 { 5 } else if bits >= 512 { 8 } else { 40 };
    var b: u8[>..] = [];
    b.resize(4 * limbs, 0);
    var p = zero_limbs(limbs);
    var p1 = zero_limbs(limbs);
    var t = zero_limbs(1);
    var inv = zero_limbs(1);
    loop {
        random_bytes(b);
        limbs_from_be(p, b);
        p[limbs - 1] = p[limbs - 1] | 0xc0000000;
        p[0] = p[0] | 3;
        var sieved = true;
        for sp in primes {
            if ct_mod_small(p, sp) == 0 { sieved = false; break; }
        }
        if !sieved { continue; }
        put_limbs(p1, p);
        p1[0] = p1[0] & 0xfffffffe;
        ct_reduce(t, p1, e);
        if ct_mod_inv(inv, t, e) == 0 { continue; }   // gcd(p - 1, e) != 1
        if rsa_miller_rabin(p, rounds) { return p; }
    }
}

// d = 1/e mod phi for phi = (p - 1)(q - 1) and a public odd e prime to
// it, in constant time: with k = -1/phi mod e, 1 + k phi is a multiple of
// e, and its exact quotient by e is d. This is the RSA paper's d, as Go's
// crypto/rsa had it before its FIPS module; FIPS 186-5 asks for 1/e mod
// lcm(p - 1, q - 1), a gcd of two secret even numbers away.
fn rsa_private_exponent(d: u32[:], phi: const u32[:], e: u32) {
    var em = zero_limbs(1);
    em[0] = e;
    var t = zero_limbs(1);
    ct_reduce(t, phi, em);
    var ti = zero_limbs(1);
    let ok = ct_mod_inv(ti, t, em);
    assert(ok == 1);                             // p - 1 and q - 1 are prime to e
    let k: u64 = e - ti[0];                      // -1/phi mod e, in [1, e - 1]
    var x = zero_limbs(phi.len + 1);
    var carry: u64 = 1;                          // 1 + k phi
    for i in phi.len {
        let v: u64 = phi[i];
        let s = v * k + carry;
        x[i] = s as! u32;
        carry = s >> 32;
    }
    x[phi.len] = carry as! u32;
    var qd = zero_limbs(phi.len + 1);
    ct_div_exact(qd, x, e);
    for i in d.len { d[i] = qd[i]; }             // d < phi: the top limb is 0
}

// A new key of `bits` bits (a multiple of 64, 1024 to 8192) with public
// exponent e (odd, 3 to 2^31 - 1, as rsa_public_from takes; 65537
// unless given), from the OS's
// entropy, in constant time.
fn rsa_generate(bits: i64, e: u64 = 65537) -> RsaPrivateKey {
    assert(bits % 64 == 0 && bits >= 1024 && bits <= 8192);
    assert(e >= 3 && e % 2 == 1 && e < 2147483648);         // as rsa_public_from takes
    let half = bits / 64;
    var el = zero_limbs(1);
    el[0] = e as! u32;
    let primes = small_primes();
    var n = zero_limbs(2 * half);
    var phi = zero_limbs(2 * half);
    var d = zero_limbs(2 * half);
    var p1 = zero_limbs(half);
    var q1 = zero_limbs(half);
    loop {
        var p = rsa_random_prime(half, el, primes);
        var q = rsa_random_prime(half, el, primes);
        if ct_eq(p, q) == 1 { continue; }
        ct_cswap(ct_mask(ct_lt(p, q)), p, q);    // p > q, the usual order: qinv = 1/q mod p
        ct_mul(n, p, q);
        put_limbs(p1, p);
        p1[0] = p1[0] & 0xfffffffe;
        put_limbs(q1, q);
        q1[0] = q1[0] & 0xfffffffe;
        ct_mul(phi, p1, q1);
        rsa_private_exponent(d, phi, el[0]);
        let k, ok = rsa_key_from_limbs(n, el, d, p, q);
        if ok { return k; }
    }
}

// out = c^d mod n for c < n, both at n's width, in constant time, and 1
// if out^e == c, else 0 (a fault: out is then not to be released).
fn rsa_private_checked(key, out: u32[:], c: const u32[:]) -> u32 {
    let nl = key.n.len;
    let pl = key.p.len;
    let ql = key.q.len;
    let n = key.n[..];
    let p = key.p[..];
    let q = key.q[..];
    let n0i = mont_m0i(n[0]);
    let p0i = mont_m0i(p[0]);
    let q0i = mont_m0i(q[0]);
    var r2n = zero_limbs(nl);
    var r2p = zero_limbs(pl);
    var r2q = zero_limbs(ql);
    mont_r2(r2n, n);
    mont_r2(r2p, p);
    mont_r2(r2q, q);
    var tn = zero_limbs(nl + 2);
    var tp = zero_limbs(pl + 2);

    // Blinding: cb = c * r^e mod n for a random r, undone with 1/r at the
    // end; r and 1/r in constant time. (An r with no inverse shares a
    // factor with n, and is drawn again.)
    var rl = zero_limbs(nl);
    var rinvl = zero_limbs(nl);
    loop {
        random_below(rl, n);
        if ct_mod_inv(rinvl, rl, n) == 1 { break; }
    }
    var re = zero_limbs(nl);
    mont_modexp(re, rl, key.e[..], n, n0i, r2n);
    var tmp = zero_limbs(nl);
    var cb = zero_limbs(nl);
    mont_mul(tmp, c, re, n, n0i, tn);
    mont_mul(cb, tmp, r2n, n, n0i, tn);

    // The two halves.
    var cp = zero_limbs(pl);
    var m1 = zero_limbs(pl);
    ct_reduce(cp, cb, p);
    mont_modexp(m1, cp, key.dp[..], p, p0i, r2p);
    var cq = zero_limbs(ql);
    var m2 = zero_limbs(ql);
    ct_reduce(cq, cb, q);
    mont_modexp(m2, cq, key.dq[..], q, q0i, r2q);

    // Garner: h = qinv (m1 - m2) mod p, m = m2 + h q.
    var m2p = zero_limbs(pl);
    ct_reduce(m2p, m2, p);
    var diff = zero_limbs(pl);
    ct_mod_sub(diff, m1, m2p, p);
    var tp1 = zero_limbs(pl);
    var h = zero_limbs(pl);
    mont_mul(tp1, key.qinv[..], diff, p, p0i, tp);
    mont_mul(h, tp1, r2p, p, p0i, tp);
    var prod = zero_limbs(pl + ql);
    ct_mul(prod, h, q);
    var carry: u64 = 0;
    for i in pl + ql {
        let x: u64 = prod[i];
        let t = x + (if i < ql { m2[i] } else { 0 }) + carry;
        prod[i] = t as! u32;
        carry = t >> 32;
    }
    // prod < n, so it fits n's width.
    var mb = zero_limbs(nl);
    for i in nl { mb[i] = prod[i]; }

    // Unblind, then check m^e == c before letting m out.
    mont_mul(tmp, mb, rinvl, n, n0i, tn);
    mont_mul(out, tmp, r2n, n, n0i, tn);
    var check = zero_limbs(nl);
    mont_modexp(check, out, key.e[..], n, n0i, r2n);
    return ct_eq(check, c);
}

// The raw RSA functions on k-byte big-endian strings (k = rsa_size): x^e
// and x^d mod n. False when x is not k bytes or not below n.
fn rsa_public_op(key, x: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if x.len != rsa_size(key) { return out, false; }
    let xb = from_bytes_be(x);
    let nb = big_of(key.n);
    if ge(xb, nb) { return out, false; }
    let y = modpow(xb, big_of(key.e), nb);
    out = to_bytes_be(y, x.len);
    return out, true;
}

// x^e mod n in constant time in x, for a secret x (an encryption's padded
// message): the same checks as rsa_public_op, with only their outcome
// branched on, then Montgomery square-and-multiply. Only n and e, which
// are public, are branched on: R^2 mod n comes from BigInt, and the
// multiplies follow e's bits.
fn rsa_public_op_ct(key, x: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let nl = key.n.len;
    if x.len != rsa_size(key) { return out, false; }
    var c = zero_limbs(nl);
    limbs_from_be(c, x);
    let n = key.n[..];
    if ct_lt(c, n) == 0 { return out, false; }
    let n0i = mont_m0i(n[0]);
    var r2n = zero_limbs(nl);
    put_limbs(r2n, mod_floor(shl(one(), 64 * nl), big_of(key.n)).mag);
    var t = zero_limbs(nl + 2);
    var xm = zero_limbs(nl);
    mont_mul(xm, c, r2n, n, n0i, t);                     // x R
    var acc = zero_limbs(nl);
    var tmp = zero_limbs(nl);
    for i in nl { acc[i] = xm[i]; }
    let e = key.e[..];
    var b = mag_bit_len(e) - 1;
    while b > 0 {
        b--;
        mont_mul(tmp, acc, acc, n, n0i, t);
        if (e[b / 32] >> (b % 32)) & 1 == 1 { mont_mul(acc, tmp, xm, n, n0i, t); }
        else { for i in nl { acc[i] = tmp[i]; } }
    }
    var one_l = zero_limbs(nl);
    one_l[0] = 1;
    var m = zero_limbs(nl);
    mont_mul(m, acc, one_l, n, n0i, t);                  // out of Montgomery form
    out.resize(x.len, 0);
    be_from_limbs(out, m);
    return out, true;
}

// x^d mod n and true, or empty and false: for x not k bytes or not below
// n, or when the result fails its check against the public key (a fault).
fn rsa_private_op(key: const RsaPrivateKey&, x: const u8[:]) -> u8[>..], bool {
    var out, ok, good = rsa_private_raw(key, x);
    if !ok || good == 0 {
        for i in out.len { out[i] = 0; }
        var none: u8[>..] = [];
        return none, false;
    }
    return out, true;
}

// The same for decryption: false only for an x that is not k bytes or not
// below n (public, as x is the input); whether the result passed its check
// comes back as 1 or 0, for the caller to fold into its constant-time
// checks on the result.
fn rsa_private_raw(key: const RsaPrivateKey&, x: const u8[:]) -> u8[>..], bool, u32 {
    var out: u8[>..] = [];
    let nl = key.n.len;
    if x.len != rsa_size(key) { return out, false, 0; }
    var c = zero_limbs(nl);
    limbs_from_be(c, x);
    if ct_lt(c, key.n[..]) == 0 { return out, false, 0; }
    var m = zero_limbs(nl);
    let good = rsa_private_checked(key, m, c);
    out.resize(x.len, 0);
    be_from_limbs(out, m);
    return out, true, good;
}

// Signatures hash with SHA-256, SHA-384 or SHA-512: `hash` is 256, 384
// or 512, as in bignum.hmac.

// PKCS #1 v1.5 signatures (RSASSA-PKCS1-v1_5).

// The DER DigestInfo header for a hash (RFC 8017 §9.2): MD5's and SHA-1's
// own OIDs, or the NIST hash arc 2.16.840.1.101.3.4.2.n for SHA-2 and
// SHA-3. BLAKE2 has none, so it can't sign this way (as in Go).
fn has_digest_info(bits: i64) -> bool {
    bits == HASH_MD5 || bits == HASH_SHA1 || bits == 224 || bits == 256 || bits == 384 || bits == 512
        || bits == HASH_SHA512_224 || bits == HASH_SHA512_256 || (bits > 3000 && bits < 4000)
}

fn digest_info(bits: i64) -> u8[>..] {
    var di: u8[>..] = [];
    let hl = hash_len(bits);
    if bits == HASH_MD5 {
        let md5_di: u8[18] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05,
                              0x05, 0x00, 0x04, 0x10];
        di.append(md5_di);
        return di;
    }
    if bits == HASH_SHA1 {
        let sha1_di: u8[15] = [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14];
        di.append(sha1_di);
        return di;
    }
    let arc: u8 = if bits == 256 { 1 } else if bits == 384 { 2 } else if bits == 512 { 3 } else if bits == 224 { 4 }
                  else if bits == HASH_SHA512_224 { 5 } else if bits == HASH_SHA512_256 { 6 }
                  else if bits == HASH_SHA3_224 { 7 } else if bits == HASH_SHA3_256 { 8 }
                  else if bits == HASH_SHA3_384 { 9 } else { 10 };
    assert(has_digest_info(bits));
    let head: u8[17] = [0x30, (17 + hl) as! u8, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                        0x04, 0x02, arc, 0x05, 0x00];
    di.append(head);
    di.push(0x04);
    di.push(hl as! u8);
    return di;
}

fn pkcs1_encode(em: u8[:], bits: i64, digest: const u8[:]) {
    let di = digest_info(bits);
    assert(digest.len == hash_len(bits));
    let tlen = di.len + digest.len;
    assert(em.len >= tlen + 11);
    em[0] = 0;
    em[1] = 1;
    let ps = em.len - tlen - 3;
    for i in ps { em[2 + i] = 0xff; }
    em[2 + ps] = 0;
    for i in di.len { em[3 + ps + i] = di[i]; }
    for i in digest.len { em[3 + ps + di.len + i] = digest[i]; }
}

// The signature and true, or empty and false: for a hash with no
// DigestInfo, a key too small for it, or a fault (as Go's SignPKCS1v15
// returns an error).
fn rsa_sign_pkcs1(key: const RsaPrivateKey&, msg: const u8[:], hash: i64 = 256) -> u8[>..], bool {
    if !has_digest_info(hash) { var none: u8[>..] = []; return none, false; }
    let sig, ok = rsa_sign_pkcs1_digest(key, hash_bits(hash, msg), hash);
    return sig, ok;
}

// The same over a digest made by `hash`, as Go's SignPKCS1v15 takes one:
// also false for a digest of another length.
fn rsa_sign_pkcs1_digest(key: const RsaPrivateKey&, digest: const u8[:], hash: i64 = 256) -> u8[>..], bool {
    var em: u8[>..] = [];
    if !has_digest_info(hash) || digest.len != hash_len(hash) ||
       rsa_size(key) < digest_info(hash).len + hash_len(hash) + 11 { return em, false; }
    em.resize(rsa_size(key), 0);
    pkcs1_encode(em, hash, digest);
    let sig, ok = rsa_private_op(key, em);
    return sig, ok;
}

// The encoding is rebuilt and compared whole, rather than parsed.
fn rsa_verify_pkcs1(key, msg: const u8[:], sig: const u8[:], hash: i64 = 256) -> bool {
    if !has_digest_info(hash) { return false; }
    return rsa_verify_pkcs1_digest(key, hash_bits(hash, msg), sig, hash);
}

fn rsa_verify_pkcs1_digest(key, digest: const u8[:], sig: const u8[:], hash: i64 = 256) -> bool {
    if !has_digest_info(hash) || digest.len != hash_len(hash) { return false; }
    let m, ok = rsa_public_op(key, sig);
    if !ok || m.len < hash_len(hash) + 30 { return false; }
    var em: u8[>..] = [];
    em.resize(m.len, 0);
    pkcs1_encode(em, hash, digest);
    return ct_eq_bytes(em, m) == 1;
}

// PSS with MGF1 over the same hash (RSASSA-PSS). The salt is as long as
// the hash unless salt_len says otherwise; TLS 1.3 requires that length.

// H = Hash(0^8 || mhash || salt)
fn pss_hash(bits: i64, mhash: const u8[:], salt: const u8[:]) -> u8[>..] {
    let z: u8[8] = [0; 8];
    var m: u8[>..] = [];
    m.append(z);
    m.append(mhash);
    m.append(salt);
    return hash_bits(bits, m);
}

// The signature and true, or empty and false: for a key too small for the
// hash and salt, or a fault (as Go's SignPSS returns an error).
fn rsa_sign_pss_with_salt(key: const RsaPrivateKey&, msg: const u8[:], salt: const u8[:],
                          hash: i64 = 256) -> u8[>..], bool {
    let sig, ok = rsa_sign_pss_digest_with_salt(key, hash_bits(hash, msg), salt, hash);
    return sig, ok;
}

// The same over a digest made by `hash` (as Go's SignPSS takes one): also
// false for a digest of another length.
fn rsa_sign_pss_digest_with_salt(key: const RsaPrivateKey&, digest: const u8[:], salt: const u8[:],
                                 hash: i64 = 256) -> u8[>..], bool {
    let hl = hash_len(hash);
    let k = rsa_size(key);
    let embits = rsa_bits(key) - 1;
    let emlen = (embits + 7) / 8;
    var em: u8[>..] = [];
    if digest.len != hl || emlen < hl + salt.len + 2 { return em, false; }
    let h = pss_hash(hash, digest, salt);
    // em holds EM right-aligned: one leading zero byte when emlen < k.
    em.resize(k, 0);
    let off = k - emlen;
    let dblen = emlen - hl - 1;
    let db = em[off..off + dblen];
    db[dblen - salt.len - 1] = 1;
    for i in salt.len { db[dblen - salt.len + i] = salt[i]; }
    mgf1(hash, db, h);
    db[0] = db[0] & (255 >> (8 * emlen - embits)) as! u8;
    for i in hl { em[off + dblen + i] = h[i]; }
    em[k - 1] = 0xbc;
    let sig, ok = rsa_private_op(key, em);
    return sig, ok;
}

fn rsa_sign_pss(key: const RsaPrivateKey&, msg: const u8[:], salt_len: i64 = -1, hash: i64 = 256)
        -> u8[>..], bool {
    var salt: u8[>..] = [];
    salt.resize(if salt_len < 0 { hash_len(hash) } else { salt_len }, 0);
    random_bytes(salt);
    return rsa_sign_pss_with_salt(key, msg, salt, hash);
}

fn rsa_sign_pss_digest(key: const RsaPrivateKey&, digest: const u8[:], salt_len: i64 = -1, hash: i64 = 256)
        -> u8[>..], bool {
    var salt: u8[>..] = [];
    salt.resize(if salt_len < 0 { hash_len(hash) } else { salt_len }, 0);
    random_bytes(salt);
    return rsa_sign_pss_digest_with_salt(key, digest, salt, hash);
}

fn rsa_verify_pss(key, msg: const u8[:], sig: const u8[:], salt_len: i64 = -1, hash: i64 = 256) -> bool {
    return rsa_verify_pss_digest(key, hash_bits(hash, msg), sig, salt_len, hash);
}

fn rsa_verify_pss_digest(key, digest: const u8[:], sig: const u8[:], salt_len: i64 = -1, hash: i64 = 256) -> bool {
    let hl = hash_len(hash);
    if digest.len != hl { return false; }
    let slen = if salt_len < 0 { hl } else { salt_len };
    let m, ok = rsa_public_op(key, sig);
    if !ok { return false; }
    let k = m.len;
    let embits = rsa_bits(key) - 1;
    let emlen = (embits + 7) / 8;
    if emlen < hl + slen + 2 { return false; }
    let off = k - emlen;
    if off > 0 && m[0] != 0 { return false; }
    if m[k - 1] != 0xbc { return false; }
    let dblen = emlen - hl - 1;
    let zbits = 8 * emlen - embits;
    let top = (255 << (8 - zbits)) & 255;
    if m[off] & top != 0 { return false; }
    var db: u8[>..] = [];
    db.append(m[off..off + dblen]);
    let h = m[off + dblen..off + dblen + hl];
    mgf1(hash, db, h);
    db[0] = db[0] & (255 >> zbits) as! u8;
    let ps = dblen - slen - 1;
    for i in ps { if db[i] != 0 { return false; } }
    if db[ps] != 1 { return false; }
    let h2 = pss_hash(hash, digest, db[ps + 1..]);
    return ct_eq_bytes(h2, h) == 1;
}

// OAEP (RSAES-OAEP) with a hash and MGF1 over the same hash: SHA-256
// unless `hash` names another bignum.hmac id, as Go's EncryptOAEP takes
// one. A message takes at most rsa_oaep_max(key, hash) bytes, 2 hash
// lengths and 2 less than the modulus.
fn rsa_oaep_max(key, hash: i64 = 256) -> i64 { rsa_size(key) - 2 * hash_len(hash) - 2 }

fn rsa_encrypt_oaep_with_seed(key, msg: const u8[:], label: const u8[:], seed: const u8[:],
                              hash: i64 = 256) -> u8[>..] {
    let k = rsa_size(key);
    let hl = hash_len(hash);
    assert(msg.len <= k - 2 * hl - 2 && seed.len == hl);
    var em: u8[>..] = [];
    em.resize(k, 0);
    let lhash = hash_bits(hash, label);
    let dblen = k - hl - 1;
    let db = em[hl + 1..];
    for i in hl { db[i] = lhash[i]; }
    db[dblen - msg.len - 1] = 1;
    for i in msg.len { db[dblen - msg.len + i] = msg[i]; }
    let sd = em[1..hl + 1];
    for i in hl { sd[i] = seed[i]; }
    mgf1(hash, db, sd);
    mgf1(hash, sd, db);
    let c, ok = rsa_public_op_ct(key, em);
    assert(ok);
    return c;
}

fn rsa_encrypt_oaep(key, msg: const u8[:], label: const u8[:] = "", hash: i64 = 256) -> u8[>..] {
    var seed: u8[>..] = [];
    seed.resize(hash_len(hash), 0);
    random_bytes(seed);
    return rsa_encrypt_oaep_with_seed(key, msg, label, seed, hash);
}

// The message and true, or empty and false. Every check on the decoded
// block is made in constant time and folded into one flag, so a failure
// does not say which part was wrong (Manger's attack).
fn rsa_decrypt_oaep(key: const RsaPrivateKey&, ct: const u8[:], label: const u8[:] = "",
                    hash: i64 = 256) -> u8[>..], bool {
    var out: u8[>..] = [];
    let k = rsa_size(key);
    let hl = hash_len(hash);
    if k < 2 * hl + 2 { return out, false; }
    var em, ok, checked = rsa_private_raw(key, ct);
    if !ok { return out, false; }
    let dblen = k - hl - 1;
    let sd = em[1..hl + 1];
    let db = em[hl + 1..];
    mgf1(hash, sd, db);
    mgf1(hash, db, sd);
    let lhash = hash_bits(hash, label);
    var good = checked & ct_is_zero_u32(em[0]) & ct_eq_bytes(db[..hl], lhash);
    // Find the 0x01 after the zero padding, without branching on bytes.
    var found: u32 = 0;
    var bad: u32 = 0;
    var start: u32 = 0;
    for i in hl..dblen {
        let b: u32 = db[i];
        let is1 = ct_eq_u32(b, 1) & (found ^ 1);
        let is0 = ct_is_zero_u32(b);
        bad = bad | ((found ^ 1) & (is0 ^ 1) & (is1 ^ 1));
        start = ct_select_u32(ct_mask(is1), (i + 1) as! u32, start);
        found = found | is1;
    }
    good = good & found & (bad ^ 1);
    if good == 0 { return out, false; }
    let from: i64 = start;
    out.append(db[from..]);
    return out, true;
}

// PKCS #1 v1.5 encryption (RSAES-PKCS1-v1_5), for protocols that still
// use it; prefer OAEP. A message takes at most rsa_size(key) - 11 bytes.
fn rsa_encrypt_pkcs1(key, msg: const u8[:]) -> u8[>..] {
    let k = rsa_size(key);
    assert(msg.len <= k - 11);
    var em: u8[>..] = [];
    em.resize(k, 0);
    em[1] = 2;
    let ps = em[2..k - msg.len - 1];
    random_bytes(ps);
    // The padding bytes must not be zero: redraw any that are.
    var one: u8[1] = [0; 1];
    for i in ps.len {
        while ps[i] == 0 {
            random_bytes(one);
            ps[i] = one[0];
        }
    }
    for i in msg.len { em[k - msg.len + i] = msg[i]; }
    let c, ok = rsa_public_op_ct(key, em);
    assert(ok);
    return c;
}

// Decodes 00 02 PS 00 M in constant time: 1 when well formed (PS at least
// 8 bytes, all nonzero), and where M starts.
fn pkcs1_decode(em: const u8[:]) -> u32, i64 {
    let first = ct_is_zero_u32(em[0]);
    let second = ct_eq_u32(em[1], 2);
    var looking: u32 = 1;
    var index: u32 = 0;
    for i in 2..em.len {
        let is0 = ct_is_zero_u32(em[i]);
        index = ct_select_u32(ct_mask(looking & is0), i as! u32, index);
        looking = looking & (is0 ^ 1);
    }
    let valid = first & second & (looking ^ 1) & (ct_lt_u32(index, 10) ^ 1);
    let start: i64 = ct_select_u32(ct_mask(valid), index + 1, 0);
    return valid, start;
}

// The message and true, or empty and false. The padding is checked in
// constant time, but whether decryption failed is still visible to the
// caller and whoever it tells: a padding oracle (Bleichenbacher). For
// session keys, use rsa_decrypt_pkcs1_session_key.
fn rsa_decrypt_pkcs1(key: const RsaPrivateKey&, ct: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if rsa_size(key) < 11 { return out, false; }
    let em, ok, checked = rsa_private_raw(key, ct);
    if !ok { return out, false; }
    let valid, start = pkcs1_decode(em);
    if (valid & checked) == 0 { return out, false; }
    out.append(em[start..]);
    return out, true;
}

// Go's DecryptPKCS1v15SessionKey: decrypts a key of exactly key_out.len
// bytes into key_out, which the caller fills with random bytes first. A
// malformed ciphertext, one holding a key of another length, or a fault,
// leaves key_out as it was, and nothing about which happened takes a different
// time or path, so the protocol carries on with the random key and fails
// later, as TLS's RSA key exchange requires. False only when ct is not
// the size of the modulus, which is public.
fn rsa_decrypt_pkcs1_session_key(key: const RsaPrivateKey&, ct: const u8[:], key_out: u8[:]) -> bool {
    let k = rsa_size(key);
    if key_out.len > k - 11 { return false; }
    let em, ok, checked = rsa_private_raw(key, ct);
    if !ok { return false; }
    let valid, start = pkcs1_decode(em);
    let use = checked & valid & ct_eq_u32(start as! u32, (k - key_out.len) as! u32);
    let mask = ct_mask(use);
    for i in key_out.len {
        let b: u32 = key_out[i];
        let e: u32 = em[k - key_out.len + i];
        key_out[i] = ct_select_u32(mask, e, b) as! u8;
    }
    return true;
}
