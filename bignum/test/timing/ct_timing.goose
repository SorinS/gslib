// Timing tests of the constant-time code, after dudect (Reparaz, Balasch
// and Verbauwhede, "Dude, is my code constant time?", 2017). Each
// operation runs on one fixed input (class 0) and on random ones (class
// 1), the classes interleaved at random, and Welch's t-test compares the
// two classes' times: over all of them, and over those below the 50th to
// 99th percentile, which keeps a difference in the fast runs from being
// lost in the noise of the slow ones. A |t| above 10 says the classes
// differ (dudect's threshold for a leak). BigInt's modpow runs as a
// control, and must be caught.
//
//	python3 scripts/ct_timing.py [scale]
//
// Built natively at -O2 (the code as shipped); `scale` multiplies the
// number of runs (default 1). Not part of run_tests.py: it takes a minute
// and wants a quiet machine.

import std;
import os;
import math;
import bignum from "../..";
import bignum.ct;
import bignum.mont;
import bignum.rsa;
import bignum.x25519;
import bignum.ec;
import bignum.ed25519;

let LIMIT = 10.0;

var failures = 0;

// A test's runs, each its time in nanoseconds times 2 plus its class.
fn sample(s: i64[>..]&, class: u8, ns: i64) { s.push(2 * ns + class); }

// Welch's t for the runs that took `cut` nanoseconds or less.
fn welch(s: const i64[:], cut: i64) -> f64 {
    var n: f64[2] = [0.0, 0.0];
    var sum: f64[2] = [0.0, 0.0];
    for x in s {
        if x / 2 > cut { continue; }
        n[x & 1] += 1.0;
        sum[x & 1] += (x / 2) as f64;
    }
    if n[0] < 2.0 || n[1] < 2.0 { return 0.0; }
    let m0 = sum[0] / n[0];
    let m1 = sum[1] / n[1];
    var v: f64[2] = [0.0, 0.0];
    for x in s {
        if x / 2 > cut { continue; }
        let d = (x / 2) as f64 - (if (x & 1) == 0 { m0 } else { m1 });
        v[x & 1] += d * d;
    }
    let se = sqrt(v[0] / (n[0] - 1.0) / n[0] + v[1] / (n[1] - 1.0) / n[1]);
    if se == 0.0 { return 0.0; }
    return (m0 - m1) / se;
}

// The largest |t| over all the times and the percentile crops.
fn max_t(s: const i64[:]) -> f64 {
    var sorted: i64[>..] = [];
    sorted.append(s);
    sort(sorted);
    var worst = abs(welch(s, sorted[sorted.len - 1] / 2));
    for pct in [50, 60, 70, 80, 90, 95, 99] {
        worst = max(worst, abs(welch(s, sorted[sorted.len * pct / 100] / 2)));
    }
    return worst;
}

// Reports a test; a leak is a failure unless one is expected (the control).
fn report(name: const u8[:], s: const i64[:], leaky: bool) {
    let t = max_t(s);
    let leak = t > LIMIT;
    let ok = leak == leaky;
    if !ok { failures++; }
    let verdict = if leak { "differs" } else { "same" };
    print(if ok { "ok    " } else { "FAIL  " }, name, ": max |t| = ", t, " over ", s.len,
          " runs (", verdict, if leaky { ", a leak expected" } else { "" }, ")");
}

fn random_bytes_into(r: rng&, out: u8[:]) {
    for &b in out { b = r.rand_u64() as! u8; }
}

fn random_limbs(r: rng&, out: u32[:]) {
    for &x in out { x = r.rand_u64() as! u32; }
}

fn limbs(n: i64) -> u32[>..] {
    var v: u32[>..] = [];
    v.resize(n, 0);
    return v;
}

// An odd modulus of n limbs with its top bit set.
fn modulus(r: rng&, n: i64) -> u32[>..] {
    var m = limbs(n);
    random_limbs(r, m);
    m[0] = m[0] | 1;
    m[n - 1] = m[n - 1] | 0x80000000;
    return m;
}

fn main() {
    let args = args();
    var scale = 1;
    if args.len > 1 {
        let v, ok = parse_int(args[1]);
        if !ok || v < 1 { print("usage: ct_timing [scale]"); exit(2); }
        scale = v;
    }
    var r = rng { 2024 };

    // mont_modexp: exponent 0 against random ones, 512-bit modulus.
    block {
        let n = 16;
        let m = modulus(r, n);
        let m0i = bignum::mont_m0i(m[0]);
        var r2 = limbs(n);
        bignum::mont_r2(r2, m);
        var x = limbs(n);
        random_limbs(r, x);
        x[n - 1] = x[n - 1] & 0x7fffffff;
        var e = limbs(n);
        var out = limbs(n);
        var s: i64[>..] = [];
        for i in 3000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { for &v in e { v = 0; } } else { random_limbs(r, e); }
            let t0 = clock_ns();
            bignum::mont_modexp(out, x, e, m, m0i, r2);
            sample(s, c, clock_ns() - t0);
        }
        report("mont_modexp, exponent 0 or random", s, false);
    }

    // The control: BigInt's modpow, an exponent with one bit set against
    // random ones of the same length. It multiplies for every 1 bit.
    block {
        let m = bignum::big_of(modulus(r, 16));
        var xl = limbs(16);
        random_limbs(r, xl);
        let x = bignum::mod_floor(bignum::big_of(xl), m);
        var s: i64[>..] = [];
        var el = limbs(16);
        for i in 1500 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { for &v in el { v = 0; } } else { random_limbs(r, el); }
            el[15] = el[15] | 0x80000000;
            let e = bignum::big_of(el);
            let t0 = clock_ns();
            let y = bignum::modpow(x, e, m);
            sample(s, c, clock_ns() - t0);
        }
        report("BigInt modpow (the control)", s, true);
    }

    // ct_mod_inv: 1 against random values, 1024-bit modulus.
    block {
        let n = 32;
        let m = modulus(r, n);
        var a = limbs(n);
        var inv = limbs(n);
        var scratch = limbs(n);
        var s: i64[>..] = [];
        for i in 3000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            // Both classes do the same work before the timed call (drawing
            // random limbs, then a copy), so what came before can't differ.
            random_limbs(r, scratch);
            scratch[n - 1] = scratch[n - 1] & 0x7fffffff;
            for k in n { a[k] = if c == 0 { if k == 0 { 1 } else { 0 } } else { scratch[k] }; }
            let t0 = clock_ns();
            let ok = bignum::ct_mod_inv(inv, a, m);
            sample(s, c, clock_ns() - t0);
        }
        report("ct_mod_inv, 1 or random", s, false);
    }

    // ct_mod_small, 100 times a run: 0 against random 1024-bit values.
    // Every run's input is made before any is timed, as dudect does. Made
    // between the timed calls, behind a branch on the class, the inputs
    // left the core in a state that differed by class, and the time
    // differed with it: |t| 14 to 160 on an i7-8700, varying as the
    // program's stack layout changed, while the timed code was the same
    // instructions in every build.
    block {
        let runs = 5000 * scale;
        var inputs = limbs(32 * runs);
        var classes: u8[>..] = [];
        for i in runs {
            let c = (r.rand_u64() & 1) as! u8;
            classes.push(c);
            random_limbs(r, inputs[32 * i..32 * i + 32]);
            if c == 0 { for k in 32 { inputs[32 * i + k] = 0; } }
        }
        var s: i64[>..] = [];
        var acc: u32 = 0;
        for i in runs {
            let a = inputs[32 * i..32 * i + 32];
            let t0 = clock_ns();
            for k in 100 { acc = acc ^ bignum::ct_mod_small(a, 1999); }
            sample(s, classes[i], clock_ns() - t0);
        }
        report("ct_mod_small, 0 or random", s, false);
        if acc == 12345 { print(""); }           // keep the work
    }

    // The RSA private-key operation, 1024 bits: one ciphertext against
    // random ones.
    let key = bignum::rsa_generate(1024);
    block {
        let k = bignum::rsa_size(key);
        var fixed: u8[>..] = [];
        fixed.resize(k, 0);
        random_bytes_into(r, fixed);
        fixed[0] = 0;
        var x: u8[>..] = [];
        x.resize(k, 0);
        var s: i64[>..] = [];
        for i in 1000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { for j in k { x[j] = fixed[j]; } } else { random_bytes_into(r, x); x[0] = 0; }
            let t0 = clock_ns();
            let y, ok = bignum::rsa_private_op(key, x);
            sample(s, c, clock_ns() - t0);
        }
        report("rsa_private_op, 1024 bits, one input or random", s, false);
    }

    // RSA encryption's x^e mod n: one (secret) padded message against
    // random ones.
    block {
        let k = bignum::rsa_size(key);
        var fixed: u8[>..] = [];
        fixed.resize(k, 0);
        random_bytes_into(r, fixed);
        fixed[0] = 0;
        var x: u8[>..] = [];
        x.resize(k, 0);
        var s: i64[>..] = [];
        for i in 3000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { for j in k { x[j] = fixed[j]; } } else { random_bytes_into(r, x); x[0] = 0; }
            let t0 = clock_ns();
            let y, ok = bignum::rsa_public_op_ct(key, x);
            sample(s, c, clock_ns() - t0);
        }
        report("rsa_public_op_ct, 1024 bits, one input or random", s, false);
    }

    // Loading an RSA key: one key against seven others, 1024 bits each.
    block {
        var keys: bignum::RsaPrivateKey[8] = [key; 8];
        for i in 1..8 { keys[i] = bignum::rsa_generate(1024); }
        var s: i64[>..] = [];
        for i in 1000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            let which = if c == 0 { 0 } else { 1 + (r.rand_u64() % 7) as! i64 };
            let t0 = clock_ns();
            let k2, ok = bignum::rsa_key_from_limbs(keys[which].n, keys[which].e, keys[which].d, keys[which].p,
                                                    keys[which].q);
            sample(s, c, clock_ns() - t0);
            assert(ok);
        }
        report("rsa_key_from_limbs, one key or seven others", s, false);
    }

    // X25519: one scalar against random ones, on the base point.
    block {
        var fixed: u8[32] = [0; 32];
        random_bytes_into(r, fixed);
        var sk: u8[32] = [0; 32];
        var s: i64[>..] = [];
        for i in 3000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { sk = fixed; } else { random_bytes_into(r, sk); }
            let t0 = clock_ns();
            let pk = bignum::x25519_base(sk);
            sample(s, c, clock_ns() - t0);
        }
        report("x25519_base, one scalar or random", s, false);
    }

    // ECDSA on P-256: one private key against random ones, one message.
    block {
        let curve = bignum::p256();
        let fixed, fpub = bignum::ec_keypair(curve);
        var sk: u8[>..] = [];
        sk.append(fixed);
        var s: i64[>..] = [];
        for i in 1500 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { for j in sk.len { sk[j] = fixed[j]; } } else { random_bytes_into(r, sk); sk[0] = sk[0] & 0x7f; }
            let t0 = clock_ns();
            let sig = bignum::ecdsa_sign(curve, sk, "a message");
            sample(s, c, clock_ns() - t0);
        }
        report("ecdsa_sign P-256, one key or random", s, false);
    }

    // Ed25519: one seed against random ones, one message.
    block {
        var fixed: u8[32] = [0; 32];
        random_bytes_into(r, fixed);
        var seed: u8[32] = [0; 32];
        var s: i64[>..] = [];
        for i in 2000 * scale {
            let c = (r.rand_u64() & 1) as! u8;
            if c == 0 { seed = fixed; } else { random_bytes_into(r, seed); }
            let t0 = clock_ns();
            let sig = bignum::ed25519_sign(seed, "a message");
            sample(s, c, clock_ns() - t0);
        }
        report("ed25519_sign, one seed or random", s, false);
    }

    print(if failures == 0 { "ct timing: no leak found" } else { "ct timing: FAILED" });
    exit(if failures == 0 { 0 } else { 1 });
}
