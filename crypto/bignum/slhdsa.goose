// bignum.slhdsa: SLH-DSA (FIPS 205), the stateless hash-based signature
// scheme (SPHINCS+): all twelve parameter sets, SHA2 and SHAKE at 128, 192
// and 256 bits, small ("s") or fast ("f"), named by the SLHDSA_* numbers.
// A private key is SK.seed || SK.prf || PK.seed || PK.root (4n bytes), the
// public key PK.seed || PK.root (2n bytes). Keys come from the OS's entropy
// or from a 3n-byte seed (SK.seed || SK.prf || PK.seed, the form openssl's
// "seed" parameter and ACVP take). Signing is hedged (n fresh random bytes)
// unless asked to be deterministic, and takes a context string of up to 255
// bytes; HashSLH-DSA signs a digest of the message under the hash's OID.
// The _internal forms sign and verify a prepared message M', as ACVP's
// internal interface does.
//
// The "s" sets are slow by design: signing one builds 2^(h/d) WOTS+ keys in
// each of d layers. Every tweakable hash call takes one compression: SHA2's
// PK.seed block is hashed once per key (its midstate kept), and SHAKE's
// inputs are absorbed a lane at a time. Secrets (SK.seed, SK.prf) only ever
// enter hashes; what is branched on or indexed by (the tree and leaf
// indices, the FORS indices, the WOTS+ digits) is part of the signature.

namespace bignum;

import std;
import crypto.bignum.sha256;
import crypto.bignum.sha512;
import crypto.bignum.sha3;
import crypto.bignum.hmac;
import entropy;

// The parameter sets, in the order of their OIDs (2.16.840.1.101.3.4.3.20
// to .31: the set's number plus 19).
let SLHDSA_SHA2_128S:  i64 = 1;
let SLHDSA_SHA2_128F:  i64 = 2;
let SLHDSA_SHA2_192S:  i64 = 3;
let SLHDSA_SHA2_192F:  i64 = 4;
let SLHDSA_SHA2_256S:  i64 = 5;
let SLHDSA_SHA2_256F:  i64 = 6;
let SLHDSA_SHAKE_128S: i64 = 7;
let SLHDSA_SHAKE_128F: i64 = 8;
let SLHDSA_SHAKE_192S: i64 = 9;
let SLHDSA_SHAKE_192F: i64 = 10;
let SLHDSA_SHAKE_256S: i64 = 11;
let SLHDSA_SHAKE_256F: i64 = 12;

// HashSLH-DSA's pre-hashes beyond hmac's HASH_* numbers (SHA-224 to
// SHA-512, SHA-512/224, SHA-512/256 and SHA3-224 to SHA3-512 are those):
// SHAKE128 with a 256-bit and SHAKE256 with a 512-bit output.
let SLHDSA_PH_SHAKE128: i64 = 4128;
let SLHDSA_PH_SHAKE256: i64 = 4256;

// A parameter set (FIPS 205 Table 2): n, the hypertree's height h and
// layers d, each XMSS tree's height hp = h/d, FORS's a and k, the digest
// length m, WOTS+'s len = 2n + 3 (lg_w = 4).
struct SlhParams { set: i64, n: i64, h: i64, d: i64, hp: i64, a: i64, k: i64, m: i64, len: i64, shake: bool }

fn slhdsa_valid(set: i64) -> bool { set >= 1 && set <= 12 }

fn slhdsa_params(set: i64) -> SlhParams {
    assert(slhdsa_valid(set));
    let shake = set > 6;
    let s = (set - 1) % 6;
    var p = SlhParams { set: set, n: 16, h: 63, d: 7, hp: 9, a: 12, k: 14, m: 30, len: 35, shake: shake };
    if s == 1 { p.h = 66; p.d = 22; p.hp = 3; p.a = 6; p.k = 33; p.m = 34; }
    if s == 2 { p.n = 24; p.h = 63; p.d = 7; p.hp = 9; p.a = 14; p.k = 17; p.m = 39; }
    if s == 3 { p.n = 24; p.h = 66; p.d = 22; p.hp = 3; p.a = 8; p.k = 33; p.m = 42; }
    if s == 4 { p.n = 32; p.h = 64; p.d = 8; p.hp = 8; p.a = 14; p.k = 22; p.m = 47; }
    if s == 5 { p.n = 32; p.h = 68; p.d = 17; p.hp = 4; p.a = 9; p.k = 35; p.m = 49; }
    p.len = 2 * p.n + 3;
    return p;
}

// The set's name, "SLH-DSA-SHA2-128s" and so on.
fn slhdsa_name(set: i64) -> const u8[:] {
    assert(slhdsa_valid(set));
    let names = ["SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
                 "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
                 "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"];
    return names[set - 1];
}

// The set of a name (as slhdsa_name gives it), or 0.
fn slhdsa_set_of_name(name: const u8[:]) -> i64 {
    for s in 1..13 { if slhdsa_name(s) == name { return s; } }
    return 0;
}

fn slhdsa_n(set: i64) -> i64 { slhdsa_params(set).n }
fn slhdsa_pk_len(set: i64) -> i64 { 2 * slhdsa_n(set) }
fn slhdsa_sk_len(set: i64) -> i64 { 4 * slhdsa_n(set) }
fn slhdsa_seed_len(set: i64) -> i64 { 3 * slhdsa_n(set) }
fn slhdsa_sig_len(set: i64) -> i64 {
    let p = slhdsa_params(set);
    return (1 + p.k * (1 + p.a) + p.h + p.d * p.len) * p.n;
}

// --- Tweakable hashes (FIPS 205 §11) -----------------------------------------

// What every hash of one key shares: the parameters, PK.seed, SK.seed (zero
// when verifying), and SHA2's midstates after the block PK.seed ||
// toByte(0, 64 - n) (SHA-256) and PK.seed || toByte(0, 128 - n) (SHA-512).
struct SlhCtx { p: SlhParams, pk_seed: u8[32], sk_seed: u8[32], st256: u32[8], st512: u64[8] }

fn slh_ctx(set: i64, pk_seed: const u8[:], sk_seed: const u8[:]) -> SlhCtx {
    let p = slhdsa_params(set);
    var c = SlhCtx { p: p, pk_seed: [0; 32], sk_seed: [0; 32], st256: [0; 8], st512: [0; 8] };
    for i in p.n { c.pk_seed[i] = pk_seed[i]; }
    for i in sk_seed.len { c.sk_seed[i] = sk_seed[i]; }
    if !p.shake {
        var b: u8[128] = [0; 128];
        for i in p.n { b[i] = pk_seed[i]; }
        var s = sha256_init();
        sha256_block(s, b[..64]);
        c.st256 = s.h;
        if p.n > 16 {
            var t = sha512_init();
            sha512_block(t, b);
            c.st512 = t.h;
        }
    }
    return c;
}

// ADRS (§4.2) as eight big-endian words: layer, tree (three words, the top
// one zero), type, key pair, chain or tree height, hash or tree index.
let SLH_WOTS_HASH:  u32 = 0;
let SLH_WOTS_PK:    u32 = 1;
let SLH_TREE:       u32 = 2;
let SLH_FORS_TREE:  u32 = 3;
let SLH_FORS_ROOTS: u32 = 4;
let SLH_WOTS_PRF:   u32 = 5;
let SLH_FORS_PRF:   u32 = 6;

fn slh_adrs(layer: i64, tree: u64) -> u32[8] {
    var a: u32[8] = [0; 8];
    a[0] = layer as! u32;
    a[2] = (tree >> 32) as! u32;
    a[3] = tree as! u32;
    return a;
}

// setTypeAndClear: the type, with key pair, chain and hash cleared.
fn slh_set_type(a: u32[:], t: u32) { a[4] = t; a[5] = 0; a[6] = 0; a[7] = 0; }

// The 22-byte compressed ADRS of the SHA2 sets, into b.
fn slh_adrsc(b: u8[:], a: const u32[:]) {
    b[0] = a[0] as! u8;
    for i in 4 { b[1 + i] = (a[2] >> (24 - 8 * i)) as! u8; b[5 + i] = (a[3] >> (24 - 8 * i)) as! u8; }
    b[9] = a[4] as! u8;
    for w in 3 {
        for i in 4 { b[10 + 4 * w + i] = (a[5 + w] >> (24 - 8 * i)) as! u8; }
    }
}

fn slh_bswap32(x: u32) -> u64 {
    let v: u64 = (x >> 24) | ((x >> 8) & 0xff00) | ((x << 8) & 0xff0000) | (x << 24);
    return v;
}

// Eight bytes as a little-endian lane.
fn slh_lane(b: const u8[:], at: i64) -> u64 {
    var v: u64 = 0;
    var i = 8;
    while i > 0 { i--; v = (v << 8) | b[at + i]; }
    return v;
}

// SHAKE256(PK.seed || ADRS || m) to out (n bytes): every part is a whole
// number of lanes, so it is absorbed a lane at a time.
fn slh_shake(c: const SlhCtx&, a: const u32[:], m: const u8[:], out: u8[:]) {
    var st: u64[25] = [0; 25];
    let n = c.p.n;
    var pos = 0;                       // in lanes; the rate is 17
    for i in n / 8 { st[pos] ^= slh_lane(c.pk_seed, 8 * i); pos++; }
    for i in 4 { st[pos] ^= slh_bswap32(a[2 * i]) | (slh_bswap32(a[2 * i + 1]) << 32); pos++; }
    for i in m.len / 8 {
        if pos == 17 { slh_keccak_f(st); pos = 0; }
        st[pos] ^= slh_lane(m, 8 * i);
        pos++;
    }
    if pos == 17 { slh_keccak_f(st); pos = 0; }
    st[pos] ^= 0x1f;
    st[16] ^= 0x8000000000000000;
    slh_keccak_f(st);
    for i in out.len { out[i] = (st[i / 8] >> (8 * (i % 8))) as! u8; }
}

// ADRSc || m padded as SHA-2 pads it, after one bs of `bs` bytes
// (PK.seed's), into b: how many bytes that takes, a whole number of blocks.
fn slh_sha2_pad(b: u8[:], a: const u32[:], m: const u8[:], bs: i64) -> i64 {
    slh_adrsc(b, a);
    for i in m.len { b[22 + i] = m[i]; }
    b[22 + m.len] = 0x80;
    let ll = bs / 8;                // the length field's size
    let total = (22 + m.len + 1 + ll + bs - 1) / bs * bs;
    let bits = (bs + 22 + m.len) * 8;
    for i in 4 { b[total - 1 - i] = (bits >> (8 * i)) as! u8; }
    return total;
}

// The SHA-256 of b's blocks from c's midstate, cut to out's length.
fn slh_sha256_run(c: const SlhCtx&, b: const u8[:], out: u8[:]) {
    var st = c.st256;
    var w: u32[16] = [0; 16];
    for blk in b.len / 64 {
        for i in 16 {
            let o = 64 * blk + 4 * i;
            w[i] = (b[o] as u32) << 24 | (b[o + 1] as u32) << 16 | (b[o + 2] as u32) << 8 | b[o + 3];
        }
        slh_sha256_compress(st, w);
    }
    for i in out.len { out[i] = (st[i / 4] >> (24 - 8 * (i % 4))) as! u8; }
}

fn slh_sha512_run(c: const SlhCtx&, b: const u8[:], out: u8[:]) {
    var st = c.st512;
    var w: u64[16] = [0; 16];
    for blk in b.len / 128 {
        for i in 16 {
            var x: u64 = 0;
            for k in 8 { x = (x << 8) | b[128 * blk + 8 * i + k]; }
            w[i] = x;
        }
        slh_sha512_compress(st, w);
    }
    for i in out.len { out[i] = (st[i / 8] >> (56 - 8 * (i % 8))) as! u8; }
}

// Trunc_n(SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || m)), and the
// same with SHA-512 and 128 - n. F, PRF and H's inputs fit one bs,
// T_l's take up to 2304 bytes (67 * 32 and the rest).
fn slh_sha2(c: const SlhCtx&, a: const u32[:], m: const u8[:], out: u8[:], big: bool) {
    let bs = if big { 128 } else { 64 };
    if !big && m.len <= 33 {
        // One SHA-256 block, built as words: ADRSc's 22 bytes, m, the
        // padding and the length.
        var w: u32[16] = [0; 16];
        w[0] = a[0] << 24 | a[2] >> 8;
        w[1] = a[2] << 24 | a[3] >> 8;
        w[2] = a[3] << 24 | (a[4] & 0xff) << 16 | a[5] >> 16;
        w[3] = a[5] << 16 | a[6] >> 16;
        w[4] = a[6] << 16 | a[7] >> 16;
        w[5] = a[7] << 16;
        for i in m.len {
            let at = 22 + i;
            w[at / 4] |= (m[i] as u32) << (24 - 8 * (at % 4));
        }
        let end = 22 + m.len;
        w[end / 4] |= 0x80 << (24 - 8 * (end % 4));
        w[15] = ((86 + m.len) * 8) as! u32;
        var st = c.st256;
        slh_sha256_compress(st, w);
        for i in out.len { out[i] = (st[i / 4] >> (24 - 8 * (i % 4))) as! u8; }
        return;
    }
    if 22 + m.len + 1 + bs / 8 <= bs {
        var b: u8[128] = [0; 128];
        let len = slh_sha2_pad(b, a, m, bs);
        if big { slh_sha512_run(c, b[..len], out); } else { slh_sha256_run(c, b[..len], out); }
        return;
    }
    var b: u8[2304] = [0; 2304];
    let len = slh_sha2_pad(b, a, m, bs);
    if big { slh_sha512_run(c, b[..len], out); } else { slh_sha256_run(c, b[..len], out); }
}

// Keccak-f[1600] and the SHA-256 and SHA-512 compressions as sha3's,
// sha256's and sha512's, with the state in locals: Keccak's round and
// SHA-256 fully unrolled (its message schedule in locals too), SHA-512's
// rounds eight at a time. An SLH-DSA signature takes millions of them, and
// these run three to ten times faster than the general ones.
fn slh_keccak_f(st: u64[:]) {
    var a0 = st[0];
    var a1 = st[1];
    var a2 = st[2];
    var a3 = st[3];
    var a4 = st[4];
    var a5 = st[5];
    var a6 = st[6];
    var a7 = st[7];
    var a8 = st[8];
    var a9 = st[9];
    var a10 = st[10];
    var a11 = st[11];
    var a12 = st[12];
    var a13 = st[13];
    var a14 = st[14];
    var a15 = st[15];
    var a16 = st[16];
    var a17 = st[17];
    var a18 = st[18];
    var a19 = st[19];
    var a20 = st[20];
    var a21 = st[21];
    var a22 = st[22];
    var a23 = st[23];
    var a24 = st[24];
    for round in 24 {
        let c0 = a0 ^ a5 ^ a10 ^ a15 ^ a20;
        let c1 = a1 ^ a6 ^ a11 ^ a16 ^ a21;
        let c2 = a2 ^ a7 ^ a12 ^ a17 ^ a22;
        let c3 = a3 ^ a8 ^ a13 ^ a18 ^ a23;
        let c4 = a4 ^ a9 ^ a14 ^ a19 ^ a24;
        let d0 = c4 ^ ((c1 << 1) | (c1 >> 63));
        let d1 = c0 ^ ((c2 << 1) | (c2 >> 63));
        let d2 = c1 ^ ((c3 << 1) | (c3 >> 63));
        let d3 = c2 ^ ((c4 << 1) | (c4 >> 63));
        let d4 = c3 ^ ((c0 << 1) | (c0 >> 63));
        let b0 = (a0 ^ d0);
        let t5 = (a5 ^ d0); let b16 = (t5 << 36) | (t5 >> 28);
        let t10 = (a10 ^ d0); let b7 = (t10 << 3) | (t10 >> 61);
        let t15 = (a15 ^ d0); let b23 = (t15 << 41) | (t15 >> 23);
        let t20 = (a20 ^ d0); let b14 = (t20 << 18) | (t20 >> 46);
        let t1 = (a1 ^ d1); let b10 = (t1 << 1) | (t1 >> 63);
        let t6 = (a6 ^ d1); let b1 = (t6 << 44) | (t6 >> 20);
        let t11 = (a11 ^ d1); let b17 = (t11 << 10) | (t11 >> 54);
        let t16 = (a16 ^ d1); let b8 = (t16 << 45) | (t16 >> 19);
        let t21 = (a21 ^ d1); let b24 = (t21 << 2) | (t21 >> 62);
        let t2 = (a2 ^ d2); let b20 = (t2 << 62) | (t2 >> 2);
        let t7 = (a7 ^ d2); let b11 = (t7 << 6) | (t7 >> 58);
        let t12 = (a12 ^ d2); let b2 = (t12 << 43) | (t12 >> 21);
        let t17 = (a17 ^ d2); let b18 = (t17 << 15) | (t17 >> 49);
        let t22 = (a22 ^ d2); let b9 = (t22 << 61) | (t22 >> 3);
        let t3 = (a3 ^ d3); let b5 = (t3 << 28) | (t3 >> 36);
        let t8 = (a8 ^ d3); let b21 = (t8 << 55) | (t8 >> 9);
        let t13 = (a13 ^ d3); let b12 = (t13 << 25) | (t13 >> 39);
        let t18 = (a18 ^ d3); let b3 = (t18 << 21) | (t18 >> 43);
        let t23 = (a23 ^ d3); let b19 = (t23 << 56) | (t23 >> 8);
        let t4 = (a4 ^ d4); let b15 = (t4 << 27) | (t4 >> 37);
        let t9 = (a9 ^ d4); let b6 = (t9 << 20) | (t9 >> 44);
        let t14 = (a14 ^ d4); let b22 = (t14 << 39) | (t14 >> 25);
        let t19 = (a19 ^ d4); let b13 = (t19 << 8) | (t19 >> 56);
        let t24 = (a24 ^ d4); let b4 = (t24 << 14) | (t24 >> 50);
        a0 = b0 ^ (~b1 & b2);
        a1 = b1 ^ (~b2 & b3);
        a2 = b2 ^ (~b3 & b4);
        a3 = b3 ^ (~b4 & b0);
        a4 = b4 ^ (~b0 & b1);
        a5 = b5 ^ (~b6 & b7);
        a6 = b6 ^ (~b7 & b8);
        a7 = b7 ^ (~b8 & b9);
        a8 = b8 ^ (~b9 & b5);
        a9 = b9 ^ (~b5 & b6);
        a10 = b10 ^ (~b11 & b12);
        a11 = b11 ^ (~b12 & b13);
        a12 = b12 ^ (~b13 & b14);
        a13 = b13 ^ (~b14 & b10);
        a14 = b14 ^ (~b10 & b11);
        a15 = b15 ^ (~b16 & b17);
        a16 = b16 ^ (~b17 & b18);
        a17 = b17 ^ (~b18 & b19);
        a18 = b18 ^ (~b19 & b15);
        a19 = b19 ^ (~b15 & b16);
        a20 = b20 ^ (~b21 & b22);
        a21 = b21 ^ (~b22 & b23);
        a22 = b22 ^ (~b23 & b24);
        a23 = b23 ^ (~b24 & b20);
        a24 = b24 ^ (~b20 & b21);
        a0 ^= KECCAK_RC[round];
    }
    st[0] = a0;
    st[1] = a1;
    st[2] = a2;
    st[3] = a3;
    st[4] = a4;
    st[5] = a5;
    st[6] = a6;
    st[7] = a7;
    st[8] = a8;
    st[9] = a9;
    st[10] = a10;
    st[11] = a11;
    st[12] = a12;
    st[13] = a13;
    st[14] = a14;
    st[15] = a15;
    st[16] = a16;
    st[17] = a17;
    st[18] = a18;
    st[19] = a19;
    st[20] = a20;
    st[21] = a21;
    st[22] = a22;
    st[23] = a23;
    st[24] = a24;
}

fn slh_sha256_compress(st: u32[:], m: const u32[:]) {
    let w0 = m[0];
    let w1 = m[1];
    let w2 = m[2];
    let w3 = m[3];
    let w4 = m[4];
    let w5 = m[5];
    let w6 = m[6];
    let w7 = m[7];
    let w8 = m[8];
    let w9 = m[9];
    let w10 = m[10];
    let w11 = m[11];
    let w12 = m[12];
    let w13 = m[13];
    let w14 = m[14];
    let w15 = m[15];
    let w16 = w0 + (((w1 >> 7) | (w1 << 25)) ^ ((w1 >> 18) | (w1 << 14)) ^ (w1 >> 3)) + w9
        + (((w14 >> 17) | (w14 << 15)) ^ ((w14 >> 19) | (w14 << 13)) ^ (w14 >> 10));
    let w17 = w1 + (((w2 >> 7) | (w2 << 25)) ^ ((w2 >> 18) | (w2 << 14)) ^ (w2 >> 3)) + w10
        + (((w15 >> 17) | (w15 << 15)) ^ ((w15 >> 19) | (w15 << 13)) ^ (w15 >> 10));
    let w18 = w2 + (((w3 >> 7) | (w3 << 25)) ^ ((w3 >> 18) | (w3 << 14)) ^ (w3 >> 3)) + w11
        + (((w16 >> 17) | (w16 << 15)) ^ ((w16 >> 19) | (w16 << 13)) ^ (w16 >> 10));
    let w19 = w3 + (((w4 >> 7) | (w4 << 25)) ^ ((w4 >> 18) | (w4 << 14)) ^ (w4 >> 3)) + w12
        + (((w17 >> 17) | (w17 << 15)) ^ ((w17 >> 19) | (w17 << 13)) ^ (w17 >> 10));
    let w20 = w4 + (((w5 >> 7) | (w5 << 25)) ^ ((w5 >> 18) | (w5 << 14)) ^ (w5 >> 3)) + w13
        + (((w18 >> 17) | (w18 << 15)) ^ ((w18 >> 19) | (w18 << 13)) ^ (w18 >> 10));
    let w21 = w5 + (((w6 >> 7) | (w6 << 25)) ^ ((w6 >> 18) | (w6 << 14)) ^ (w6 >> 3)) + w14
        + (((w19 >> 17) | (w19 << 15)) ^ ((w19 >> 19) | (w19 << 13)) ^ (w19 >> 10));
    let w22 = w6 + (((w7 >> 7) | (w7 << 25)) ^ ((w7 >> 18) | (w7 << 14)) ^ (w7 >> 3)) + w15
        + (((w20 >> 17) | (w20 << 15)) ^ ((w20 >> 19) | (w20 << 13)) ^ (w20 >> 10));
    let w23 = w7 + (((w8 >> 7) | (w8 << 25)) ^ ((w8 >> 18) | (w8 << 14)) ^ (w8 >> 3)) + w16
        + (((w21 >> 17) | (w21 << 15)) ^ ((w21 >> 19) | (w21 << 13)) ^ (w21 >> 10));
    let w24 = w8 + (((w9 >> 7) | (w9 << 25)) ^ ((w9 >> 18) | (w9 << 14)) ^ (w9 >> 3)) + w17
        + (((w22 >> 17) | (w22 << 15)) ^ ((w22 >> 19) | (w22 << 13)) ^ (w22 >> 10));
    let w25 = w9 + (((w10 >> 7) | (w10 << 25)) ^ ((w10 >> 18) | (w10 << 14)) ^ (w10 >> 3)) + w18
        + (((w23 >> 17) | (w23 << 15)) ^ ((w23 >> 19) | (w23 << 13)) ^ (w23 >> 10));
    let w26 = w10 + (((w11 >> 7) | (w11 << 25)) ^ ((w11 >> 18) | (w11 << 14)) ^ (w11 >> 3)) + w19
        + (((w24 >> 17) | (w24 << 15)) ^ ((w24 >> 19) | (w24 << 13)) ^ (w24 >> 10));
    let w27 = w11 + (((w12 >> 7) | (w12 << 25)) ^ ((w12 >> 18) | (w12 << 14)) ^ (w12 >> 3)) + w20
        + (((w25 >> 17) | (w25 << 15)) ^ ((w25 >> 19) | (w25 << 13)) ^ (w25 >> 10));
    let w28 = w12 + (((w13 >> 7) | (w13 << 25)) ^ ((w13 >> 18) | (w13 << 14)) ^ (w13 >> 3)) + w21
        + (((w26 >> 17) | (w26 << 15)) ^ ((w26 >> 19) | (w26 << 13)) ^ (w26 >> 10));
    let w29 = w13 + (((w14 >> 7) | (w14 << 25)) ^ ((w14 >> 18) | (w14 << 14)) ^ (w14 >> 3)) + w22
        + (((w27 >> 17) | (w27 << 15)) ^ ((w27 >> 19) | (w27 << 13)) ^ (w27 >> 10));
    let w30 = w14 + (((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3)) + w23
        + (((w28 >> 17) | (w28 << 15)) ^ ((w28 >> 19) | (w28 << 13)) ^ (w28 >> 10));
    let w31 = w15 + (((w16 >> 7) | (w16 << 25)) ^ ((w16 >> 18) | (w16 << 14)) ^ (w16 >> 3)) + w24
        + (((w29 >> 17) | (w29 << 15)) ^ ((w29 >> 19) | (w29 << 13)) ^ (w29 >> 10));
    let w32 = w16 + (((w17 >> 7) | (w17 << 25)) ^ ((w17 >> 18) | (w17 << 14)) ^ (w17 >> 3)) + w25
        + (((w30 >> 17) | (w30 << 15)) ^ ((w30 >> 19) | (w30 << 13)) ^ (w30 >> 10));
    let w33 = w17 + (((w18 >> 7) | (w18 << 25)) ^ ((w18 >> 18) | (w18 << 14)) ^ (w18 >> 3)) + w26
        + (((w31 >> 17) | (w31 << 15)) ^ ((w31 >> 19) | (w31 << 13)) ^ (w31 >> 10));
    let w34 = w18 + (((w19 >> 7) | (w19 << 25)) ^ ((w19 >> 18) | (w19 << 14)) ^ (w19 >> 3)) + w27
        + (((w32 >> 17) | (w32 << 15)) ^ ((w32 >> 19) | (w32 << 13)) ^ (w32 >> 10));
    let w35 = w19 + (((w20 >> 7) | (w20 << 25)) ^ ((w20 >> 18) | (w20 << 14)) ^ (w20 >> 3)) + w28
        + (((w33 >> 17) | (w33 << 15)) ^ ((w33 >> 19) | (w33 << 13)) ^ (w33 >> 10));
    let w36 = w20 + (((w21 >> 7) | (w21 << 25)) ^ ((w21 >> 18) | (w21 << 14)) ^ (w21 >> 3)) + w29
        + (((w34 >> 17) | (w34 << 15)) ^ ((w34 >> 19) | (w34 << 13)) ^ (w34 >> 10));
    let w37 = w21 + (((w22 >> 7) | (w22 << 25)) ^ ((w22 >> 18) | (w22 << 14)) ^ (w22 >> 3)) + w30
        + (((w35 >> 17) | (w35 << 15)) ^ ((w35 >> 19) | (w35 << 13)) ^ (w35 >> 10));
    let w38 = w22 + (((w23 >> 7) | (w23 << 25)) ^ ((w23 >> 18) | (w23 << 14)) ^ (w23 >> 3)) + w31
        + (((w36 >> 17) | (w36 << 15)) ^ ((w36 >> 19) | (w36 << 13)) ^ (w36 >> 10));
    let w39 = w23 + (((w24 >> 7) | (w24 << 25)) ^ ((w24 >> 18) | (w24 << 14)) ^ (w24 >> 3)) + w32
        + (((w37 >> 17) | (w37 << 15)) ^ ((w37 >> 19) | (w37 << 13)) ^ (w37 >> 10));
    let w40 = w24 + (((w25 >> 7) | (w25 << 25)) ^ ((w25 >> 18) | (w25 << 14)) ^ (w25 >> 3)) + w33
        + (((w38 >> 17) | (w38 << 15)) ^ ((w38 >> 19) | (w38 << 13)) ^ (w38 >> 10));
    let w41 = w25 + (((w26 >> 7) | (w26 << 25)) ^ ((w26 >> 18) | (w26 << 14)) ^ (w26 >> 3)) + w34
        + (((w39 >> 17) | (w39 << 15)) ^ ((w39 >> 19) | (w39 << 13)) ^ (w39 >> 10));
    let w42 = w26 + (((w27 >> 7) | (w27 << 25)) ^ ((w27 >> 18) | (w27 << 14)) ^ (w27 >> 3)) + w35
        + (((w40 >> 17) | (w40 << 15)) ^ ((w40 >> 19) | (w40 << 13)) ^ (w40 >> 10));
    let w43 = w27 + (((w28 >> 7) | (w28 << 25)) ^ ((w28 >> 18) | (w28 << 14)) ^ (w28 >> 3)) + w36
        + (((w41 >> 17) | (w41 << 15)) ^ ((w41 >> 19) | (w41 << 13)) ^ (w41 >> 10));
    let w44 = w28 + (((w29 >> 7) | (w29 << 25)) ^ ((w29 >> 18) | (w29 << 14)) ^ (w29 >> 3)) + w37
        + (((w42 >> 17) | (w42 << 15)) ^ ((w42 >> 19) | (w42 << 13)) ^ (w42 >> 10));
    let w45 = w29 + (((w30 >> 7) | (w30 << 25)) ^ ((w30 >> 18) | (w30 << 14)) ^ (w30 >> 3)) + w38
        + (((w43 >> 17) | (w43 << 15)) ^ ((w43 >> 19) | (w43 << 13)) ^ (w43 >> 10));
    let w46 = w30 + (((w31 >> 7) | (w31 << 25)) ^ ((w31 >> 18) | (w31 << 14)) ^ (w31 >> 3)) + w39
        + (((w44 >> 17) | (w44 << 15)) ^ ((w44 >> 19) | (w44 << 13)) ^ (w44 >> 10));
    let w47 = w31 + (((w32 >> 7) | (w32 << 25)) ^ ((w32 >> 18) | (w32 << 14)) ^ (w32 >> 3)) + w40
        + (((w45 >> 17) | (w45 << 15)) ^ ((w45 >> 19) | (w45 << 13)) ^ (w45 >> 10));
    let w48 = w32 + (((w33 >> 7) | (w33 << 25)) ^ ((w33 >> 18) | (w33 << 14)) ^ (w33 >> 3)) + w41
        + (((w46 >> 17) | (w46 << 15)) ^ ((w46 >> 19) | (w46 << 13)) ^ (w46 >> 10));
    let w49 = w33 + (((w34 >> 7) | (w34 << 25)) ^ ((w34 >> 18) | (w34 << 14)) ^ (w34 >> 3)) + w42
        + (((w47 >> 17) | (w47 << 15)) ^ ((w47 >> 19) | (w47 << 13)) ^ (w47 >> 10));
    let w50 = w34 + (((w35 >> 7) | (w35 << 25)) ^ ((w35 >> 18) | (w35 << 14)) ^ (w35 >> 3)) + w43
        + (((w48 >> 17) | (w48 << 15)) ^ ((w48 >> 19) | (w48 << 13)) ^ (w48 >> 10));
    let w51 = w35 + (((w36 >> 7) | (w36 << 25)) ^ ((w36 >> 18) | (w36 << 14)) ^ (w36 >> 3)) + w44
        + (((w49 >> 17) | (w49 << 15)) ^ ((w49 >> 19) | (w49 << 13)) ^ (w49 >> 10));
    let w52 = w36 + (((w37 >> 7) | (w37 << 25)) ^ ((w37 >> 18) | (w37 << 14)) ^ (w37 >> 3)) + w45
        + (((w50 >> 17) | (w50 << 15)) ^ ((w50 >> 19) | (w50 << 13)) ^ (w50 >> 10));
    let w53 = w37 + (((w38 >> 7) | (w38 << 25)) ^ ((w38 >> 18) | (w38 << 14)) ^ (w38 >> 3)) + w46
        + (((w51 >> 17) | (w51 << 15)) ^ ((w51 >> 19) | (w51 << 13)) ^ (w51 >> 10));
    let w54 = w38 + (((w39 >> 7) | (w39 << 25)) ^ ((w39 >> 18) | (w39 << 14)) ^ (w39 >> 3)) + w47
        + (((w52 >> 17) | (w52 << 15)) ^ ((w52 >> 19) | (w52 << 13)) ^ (w52 >> 10));
    let w55 = w39 + (((w40 >> 7) | (w40 << 25)) ^ ((w40 >> 18) | (w40 << 14)) ^ (w40 >> 3)) + w48
        + (((w53 >> 17) | (w53 << 15)) ^ ((w53 >> 19) | (w53 << 13)) ^ (w53 >> 10));
    let w56 = w40 + (((w41 >> 7) | (w41 << 25)) ^ ((w41 >> 18) | (w41 << 14)) ^ (w41 >> 3)) + w49
        + (((w54 >> 17) | (w54 << 15)) ^ ((w54 >> 19) | (w54 << 13)) ^ (w54 >> 10));
    let w57 = w41 + (((w42 >> 7) | (w42 << 25)) ^ ((w42 >> 18) | (w42 << 14)) ^ (w42 >> 3)) + w50
        + (((w55 >> 17) | (w55 << 15)) ^ ((w55 >> 19) | (w55 << 13)) ^ (w55 >> 10));
    let w58 = w42 + (((w43 >> 7) | (w43 << 25)) ^ ((w43 >> 18) | (w43 << 14)) ^ (w43 >> 3)) + w51
        + (((w56 >> 17) | (w56 << 15)) ^ ((w56 >> 19) | (w56 << 13)) ^ (w56 >> 10));
    let w59 = w43 + (((w44 >> 7) | (w44 << 25)) ^ ((w44 >> 18) | (w44 << 14)) ^ (w44 >> 3)) + w52
        + (((w57 >> 17) | (w57 << 15)) ^ ((w57 >> 19) | (w57 << 13)) ^ (w57 >> 10));
    let w60 = w44 + (((w45 >> 7) | (w45 << 25)) ^ ((w45 >> 18) | (w45 << 14)) ^ (w45 >> 3)) + w53
        + (((w58 >> 17) | (w58 << 15)) ^ ((w58 >> 19) | (w58 << 13)) ^ (w58 >> 10));
    let w61 = w45 + (((w46 >> 7) | (w46 << 25)) ^ ((w46 >> 18) | (w46 << 14)) ^ (w46 >> 3)) + w54
        + (((w59 >> 17) | (w59 << 15)) ^ ((w59 >> 19) | (w59 << 13)) ^ (w59 >> 10));
    let w62 = w46 + (((w47 >> 7) | (w47 << 25)) ^ ((w47 >> 18) | (w47 << 14)) ^ (w47 >> 3)) + w55
        + (((w60 >> 17) | (w60 << 15)) ^ ((w60 >> 19) | (w60 << 13)) ^ (w60 >> 10));
    let w63 = w47 + (((w48 >> 7) | (w48 << 25)) ^ ((w48 >> 18) | (w48 << 14)) ^ (w48 >> 3)) + w56
        + (((w61 >> 17) | (w61 << 15)) ^ ((w61 >> 19) | (w61 << 13)) ^ (w61 >> 10));
    var a = st[0];
    var b = st[1];
    var c = st[2];
    var d = st[3];
    var e = st[4];
    var f = st[5];
    var g = st[6];
    var h = st[7];
    let t0 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[0] + w0;
    d += t0;
    h = t0 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t1 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[1] + w1;
    c += t1;
    g = t1 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t2 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[2] + w2;
    b += t2;
    f = t2 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t3 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[3] + w3;
    a += t3;
    e = t3 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t4 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[4] + w4;
    h += t4;
    d = t4 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t5 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[5] + w5;
    g += t5;
    c = t5 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t6 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[6] + w6;
    f += t6;
    b = t6 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t7 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[7] + w7;
    e += t7;
    a = t7 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t8 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[8] + w8;
    d += t8;
    h = t8 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t9 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[9] + w9;
    c += t9;
    g = t9 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t10 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[10] + w10;
    b += t10;
    f = t10 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t11 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[11] + w11;
    a += t11;
    e = t11 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t12 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[12] + w12;
    h += t12;
    d = t12 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t13 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[13] + w13;
    g += t13;
    c = t13 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t14 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[14] + w14;
    f += t14;
    b = t14 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t15 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[15] + w15;
    e += t15;
    a = t15 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t16 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[16] + w16;
    d += t16;
    h = t16 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t17 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[17] + w17;
    c += t17;
    g = t17 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t18 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[18] + w18;
    b += t18;
    f = t18 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t19 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[19] + w19;
    a += t19;
    e = t19 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t20 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[20] + w20;
    h += t20;
    d = t20 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t21 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[21] + w21;
    g += t21;
    c = t21 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t22 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[22] + w22;
    f += t22;
    b = t22 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t23 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[23] + w23;
    e += t23;
    a = t23 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t24 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[24] + w24;
    d += t24;
    h = t24 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t25 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[25] + w25;
    c += t25;
    g = t25 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t26 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[26] + w26;
    b += t26;
    f = t26 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t27 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[27] + w27;
    a += t27;
    e = t27 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t28 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[28] + w28;
    h += t28;
    d = t28 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t29 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[29] + w29;
    g += t29;
    c = t29 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t30 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[30] + w30;
    f += t30;
    b = t30 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t31 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[31] + w31;
    e += t31;
    a = t31 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t32 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[32] + w32;
    d += t32;
    h = t32 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t33 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[33] + w33;
    c += t33;
    g = t33 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t34 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[34] + w34;
    b += t34;
    f = t34 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t35 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[35] + w35;
    a += t35;
    e = t35 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t36 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[36] + w36;
    h += t36;
    d = t36 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t37 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[37] + w37;
    g += t37;
    c = t37 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t38 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[38] + w38;
    f += t38;
    b = t38 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t39 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[39] + w39;
    e += t39;
    a = t39 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t40 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[40] + w40;
    d += t40;
    h = t40 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t41 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[41] + w41;
    c += t41;
    g = t41 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t42 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[42] + w42;
    b += t42;
    f = t42 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t43 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[43] + w43;
    a += t43;
    e = t43 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t44 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[44] + w44;
    h += t44;
    d = t44 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t45 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[45] + w45;
    g += t45;
    c = t45 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t46 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[46] + w46;
    f += t46;
    b = t46 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t47 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[47] + w47;
    e += t47;
    a = t47 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t48 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[48] + w48;
    d += t48;
    h = t48 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t49 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[49] + w49;
    c += t49;
    g = t49 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t50 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[50] + w50;
    b += t50;
    f = t50 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t51 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[51] + w51;
    a += t51;
    e = t51 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t52 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[52] + w52;
    h += t52;
    d = t52 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t53 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[53] + w53;
    g += t53;
    c = t53 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t54 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[54] + w54;
    f += t54;
    b = t54 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t55 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[55] + w55;
    e += t55;
    a = t55 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    let t56 = h + (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) + ((e & f) ^ (~e & g)) + SHA256_K[56] + w56;
    d += t56;
    h = t56 + (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) + ((a & b) ^ (a & c) ^ (b & c));
    let t57 = g + (((d >> 6) | (d << 26)) ^ ((d >> 11) | (d << 21)) ^ ((d >> 25) | (d << 7))) + ((d & e) ^ (~d & f)) + SHA256_K[57] + w57;
    c += t57;
    g = t57 + (((h >> 2) | (h << 30)) ^ ((h >> 13) | (h << 19)) ^ ((h >> 22) | (h << 10))) + ((h & a) ^ (h & b) ^ (a & b));
    let t58 = f + (((c >> 6) | (c << 26)) ^ ((c >> 11) | (c << 21)) ^ ((c >> 25) | (c << 7))) + ((c & d) ^ (~c & e)) + SHA256_K[58] + w58;
    b += t58;
    f = t58 + (((g >> 2) | (g << 30)) ^ ((g >> 13) | (g << 19)) ^ ((g >> 22) | (g << 10))) + ((g & h) ^ (g & a) ^ (h & a));
    let t59 = e + (((b >> 6) | (b << 26)) ^ ((b >> 11) | (b << 21)) ^ ((b >> 25) | (b << 7))) + ((b & c) ^ (~b & d)) + SHA256_K[59] + w59;
    a += t59;
    e = t59 + (((f >> 2) | (f << 30)) ^ ((f >> 13) | (f << 19)) ^ ((f >> 22) | (f << 10))) + ((f & g) ^ (f & h) ^ (g & h));
    let t60 = d + (((a >> 6) | (a << 26)) ^ ((a >> 11) | (a << 21)) ^ ((a >> 25) | (a << 7))) + ((a & b) ^ (~a & c)) + SHA256_K[60] + w60;
    h += t60;
    d = t60 + (((e >> 2) | (e << 30)) ^ ((e >> 13) | (e << 19)) ^ ((e >> 22) | (e << 10))) + ((e & f) ^ (e & g) ^ (f & g));
    let t61 = c + (((h >> 6) | (h << 26)) ^ ((h >> 11) | (h << 21)) ^ ((h >> 25) | (h << 7))) + ((h & a) ^ (~h & b)) + SHA256_K[61] + w61;
    g += t61;
    c = t61 + (((d >> 2) | (d << 30)) ^ ((d >> 13) | (d << 19)) ^ ((d >> 22) | (d << 10))) + ((d & e) ^ (d & f) ^ (e & f));
    let t62 = b + (((g >> 6) | (g << 26)) ^ ((g >> 11) | (g << 21)) ^ ((g >> 25) | (g << 7))) + ((g & h) ^ (~g & a)) + SHA256_K[62] + w62;
    f += t62;
    b = t62 + (((c >> 2) | (c << 30)) ^ ((c >> 13) | (c << 19)) ^ ((c >> 22) | (c << 10))) + ((c & d) ^ (c & e) ^ (d & e));
    let t63 = a + (((f >> 6) | (f << 26)) ^ ((f >> 11) | (f << 21)) ^ ((f >> 25) | (f << 7))) + ((f & g) ^ (~f & h)) + SHA256_K[63] + w63;
    e += t63;
    a = t63 + (((b >> 2) | (b << 30)) ^ ((b >> 13) | (b << 19)) ^ ((b >> 22) | (b << 10))) + ((b & c) ^ (b & d) ^ (c & d));
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

fn slh_sha512_compress(st: u64[:], m: const u64[:]) {
    var w: u64[80] = [0; 80];
    for i in 16 { w[i] = m[i]; }
    for i in 16..80 {
        let x = w[i - 15];
        let y = w[i - 2];
        w[i] = w[i - 16] + (((x >> 1) | (x << 63)) ^ ((x >> 8) | (x << 56)) ^ (x >> 7)) + w[i - 7]
            + (((y >> 19) | (y << 45)) ^ ((y >> 61) | (y << 3)) ^ (y >> 6));
    }
    var a = st[0];
    var b = st[1];
    var c = st[2];
    var d = st[3];
    var e = st[4];
    var f = st[5];
    var g = st[6];
    var h = st[7];
    var i = 0;
    while i < 80 {
        let t0 = h + (((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23))) + ((e & f) ^ (~e & g)) + SHA512_K[i + 0] + w[i + 0];
        d += t0;
        h = t0 + (((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25))) + ((a & b) ^ (a & c) ^ (b & c));
        let t1 = g + (((d >> 14) | (d << 50)) ^ ((d >> 18) | (d << 46)) ^ ((d >> 41) | (d << 23))) + ((d & e) ^ (~d & f)) + SHA512_K[i + 1] + w[i + 1];
        c += t1;
        g = t1 + (((h >> 28) | (h << 36)) ^ ((h >> 34) | (h << 30)) ^ ((h >> 39) | (h << 25))) + ((h & a) ^ (h & b) ^ (a & b));
        let t2 = f + (((c >> 14) | (c << 50)) ^ ((c >> 18) | (c << 46)) ^ ((c >> 41) | (c << 23))) + ((c & d) ^ (~c & e)) + SHA512_K[i + 2] + w[i + 2];
        b += t2;
        f = t2 + (((g >> 28) | (g << 36)) ^ ((g >> 34) | (g << 30)) ^ ((g >> 39) | (g << 25))) + ((g & h) ^ (g & a) ^ (h & a));
        let t3 = e + (((b >> 14) | (b << 50)) ^ ((b >> 18) | (b << 46)) ^ ((b >> 41) | (b << 23))) + ((b & c) ^ (~b & d)) + SHA512_K[i + 3] + w[i + 3];
        a += t3;
        e = t3 + (((f >> 28) | (f << 36)) ^ ((f >> 34) | (f << 30)) ^ ((f >> 39) | (f << 25))) + ((f & g) ^ (f & h) ^ (g & h));
        let t4 = d + (((a >> 14) | (a << 50)) ^ ((a >> 18) | (a << 46)) ^ ((a >> 41) | (a << 23))) + ((a & b) ^ (~a & c)) + SHA512_K[i + 4] + w[i + 4];
        h += t4;
        d = t4 + (((e >> 28) | (e << 36)) ^ ((e >> 34) | (e << 30)) ^ ((e >> 39) | (e << 25))) + ((e & f) ^ (e & g) ^ (f & g));
        let t5 = c + (((h >> 14) | (h << 50)) ^ ((h >> 18) | (h << 46)) ^ ((h >> 41) | (h << 23))) + ((h & a) ^ (~h & b)) + SHA512_K[i + 5] + w[i + 5];
        g += t5;
        c = t5 + (((d >> 28) | (d << 36)) ^ ((d >> 34) | (d << 30)) ^ ((d >> 39) | (d << 25))) + ((d & e) ^ (d & f) ^ (e & f));
        let t6 = b + (((g >> 14) | (g << 50)) ^ ((g >> 18) | (g << 46)) ^ ((g >> 41) | (g << 23))) + ((g & h) ^ (~g & a)) + SHA512_K[i + 6] + w[i + 6];
        f += t6;
        b = t6 + (((c >> 28) | (c << 36)) ^ ((c >> 34) | (c << 30)) ^ ((c >> 39) | (c << 25))) + ((c & d) ^ (c & e) ^ (d & e));
        let t7 = a + (((f >> 14) | (f << 50)) ^ ((f >> 18) | (f << 46)) ^ ((f >> 41) | (f << 23))) + ((f & g) ^ (~f & h)) + SHA512_K[i + 7] + w[i + 7];
        e += t7;
        a = t7 + (((b >> 28) | (b << 36)) ^ ((b >> 34) | (b << 30)) ^ ((b >> 39) | (b << 25))) + ((b & c) ^ (b & d) ^ (c & d));
        i += 8;
    }
    st[0] += a;
    st[1] += b;
    st[2] += c;
    st[3] += d;
    st[4] += e;
    st[5] += f;
    st[6] += g;
    st[7] += h;
}

// F, H and T_l (and PRF, with m = SK.seed): out gets n bytes. The SHA2
// sets at 192 and 256 bits take SHA-512 for H and T_l, SHA-256 for F and
// PRF (§11.2.2).
fn slh_hash(c: const SlhCtx&, a: const u32[:], m: const u8[:], out: u8[:]) {
    if c.p.shake { slh_shake(c, a, m, out); }
    else { slh_sha2(c, a, m, out, c.p.n > 16 && m.len > c.p.n); }
}

// PRF(PK.seed, SK.seed, ADRS).
fn slh_prf(c: const SlhCtx&, a: const u32[:], out: u8[:]) { slh_hash(c, a, c.sk_seed[..c.p.n], out); }

// PRF_msg(SK.prf, opt_rand, M) (n bytes).
fn slh_prf_msg(p: const SlhParams&, sk_prf: const u8[:], opt_rand: const u8[:], msg: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if p.shake {
        var s = shake_init(256);
        sha3_update(s, sk_prf);
        sha3_update(s, opt_rand);
        sha3_update(s, msg);
        out.resize(p.n, 0);
        shake_read(s, out);
        return out;
    }
    var x: u8[>..] = [];
    x.append(opt_rand);
    x.append(msg);
    let mac = hmac(if p.n == 16 { 256 } else { 512 }, sk_prf, x);
    out.append(mac[..p.n]);
    return out;
}

// H_msg(R, PK.seed, PK.root, M) (m bytes).
fn slh_h_msg(p: const SlhParams&, r: const u8[:], pk: const u8[:], msg: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.resize(p.m, 0);
    if p.shake {
        var s = shake_init(256);
        sha3_update(s, r);
        sha3_update(s, pk);
        sha3_update(s, msg);
        shake_read(s, out);
        return out;
    }
    let bits = if p.n == 16 { 256 } else { 512 };
    var x: u8[>..] = [];
    x.append(r);
    x.append(pk);
    let inner = hash2(bits, x, msg);
    var seed: u8[>..] = [];
    seed.append(r);
    seed.append(pk[..p.n]);
    seed.append(inner);
    mgf1(bits, out, seed);
    return out;
}

// --- WOTS+ (§5) ----------------------------------------------------------------

// The len base-16 digits of an n-byte message and its checksum (Algorithm
// 7's first steps).
fn slh_wots_digits(p: const SlhParams&, msg: const u8[:], digits: u8[:]) {
    var csum = 0;
    for i in p.n {
        digits[2 * i] = msg[i] >> 4;
        digits[2 * i + 1] = msg[i] & 15;
        csum += 30 - (msg[i] >> 4) - (msg[i] & 15);
    }
    // csum << 4 as two bytes, read as three digits: its top 12 bits.
    digits[2 * p.n] = ((csum >> 8) & 15) as! u8;
    digits[2 * p.n + 1] = ((csum >> 4) & 15) as! u8;
    digits[2 * p.n + 2] = (csum & 15) as! u8;
}

// chain (Algorithm 5): s steps of F from step i, in place on x (n bytes).
fn slh_chain(c: const SlhCtx&, a: u32[:], x: u8[:], i: i64, s: i64) {
    var t: u8[32] = [0; 32];
    let n = c.p.n;
    for j in i..i + s {
        a[7] = j as! u32;
        slh_hash(c, a, x, t[..n]);
        for b in n { x[b] = t[b]; }
    }
}

// wots_pkGen (Algorithm 6) for key pair `kp` of the tree at `a` (layer and
// tree set), into out. With digits, also the WOTS+ signature of them
// (Algorithm 7) into sig, from the same chains.
fn slh_wots_leaf(c: const SlhCtx&, a: const u32[:], kp: i64, out: u8[:], digits: const u8[:], sig: u8[:]) {
    let n = c.p.n;
    var tmp: u8[2144] = [0; 2144];        // len * n, at most 67 * 32
    var ha:  u32[8]   = [0; 8];
    var pa:  u32[8]   = [0; 8];
    for i in 8 { ha[i] = a[i]; pa[i] = a[i]; }
    slh_set_type(ha, SLH_WOTS_HASH);
    ha[5] = kp as! u32;
    slh_set_type(pa, SLH_WOTS_PRF);
    pa[5] = kp as! u32;
    for i in c.p.len {
        pa[6] = i as! u32;
        let x = tmp[i * n..(i + 1) * n];
        slh_prf(c, pa, x);
        ha[6] = i as! u32;
        if digits.len > 0 {
            let d: i64 = digits[i];
            slh_chain(c, ha, x, 0, d);
            for b in n { sig[i * n + b] = x[b]; }
            slh_chain(c, ha, x, d, 15 - d);
        } else {
            slh_chain(c, ha, x, 0, 15);
        }
    }
    var ka: u32[8] = [0; 8];
    for i in 8 { ka[i] = a[i]; }
    slh_set_type(ka, SLH_WOTS_PK);
    ka[5] = kp as! u32;
    slh_hash(c, ka, tmp[..c.p.len * n], out);
}

// wots_pkFromSig (Algorithm 8).
fn slh_wots_pk_from_sig(c: const SlhCtx&, a: const u32[:], kp: i64, sig: const u8[:], msg: const u8[:], out: u8[:]) {
    let n = c.p.n;
    var digits: u8[67] = [0; 67];
    slh_wots_digits(c.p, msg, digits);
    var tmp: u8[2144] = [0; 2144];
    var ha:  u32[8]   = [0; 8];
    for i in 8 { ha[i] = a[i]; }
    slh_set_type(ha, SLH_WOTS_HASH);
    ha[5] = kp as! u32;
    for i in c.p.len {
        let x = tmp[i * n..(i + 1) * n];
        for b in n { x[b] = sig[i * n + b]; }
        ha[6] = i as! u32;
        let d: i64 = digits[i];
        slh_chain(c, ha, x, d, 15 - d);
    }
    var ka: u32[8] = [0; 8];
    for i in 8 { ka[i] = a[i]; }
    slh_set_type(ka, SLH_WOTS_PK);
    ka[5] = kp as! u32;
    slh_hash(c, ka, tmp[..c.p.len * n], out);
}

// --- XMSS and the hypertree (§6, §7) ---------------------------------------------

// One XMSS tree (layer and tree in a) whole: its root, and with idx >= 0
// the authentication path of leaf idx and the WOTS+ signature of msg by
// it (Algorithm 10), appended to sig as the signature lays them out. buf
// holds the 2^hp leaves.
fn slh_xmss(c: const SlhCtx&, a: const u32[:], idx: i64, msg: const u8[:], buf: u8[:], sig: u8[>..]&, root: u8[:]) {
    let n = c.p.n;
    let leaves = 1 << c.p.hp;
    var digits: u8[67] = [0; 67];
    let at = sig.len;
    if idx >= 0 {
        slh_wots_digits(c.p, msg, digits);
        sig.resize(at + (c.p.len + c.p.hp) * n, 0);
    }
    for i in leaves {
        let leaf = buf[i * n..(i + 1) * n];
        if i == idx { slh_wots_leaf(c, a, i, leaf, digits[..c.p.len], sig[at..at + c.p.len * n]); }
        else { slh_wots_leaf(c, a, i, leaf, "", sig[..0]); }
    }
    var ta: u32[8] = [0; 8];
    for i in 8 { ta[i] = a[i]; }
    slh_set_type(ta, SLH_TREE);
    var t: u8[32] = [0; 32];
    var width = leaves;
    for z in 1..c.p.hp + 1 {
        if idx >= 0 {
            let sib = (idx >> (z - 1)) ^ 1;
            let ap = at + (c.p.len + z - 1) * n;
            for b in n { sig[ap + b] = buf[sib * n + b]; }
        }
        width = width / 2;
        ta[6] = z as! u32;
        for j in width {
            ta[7] = j as! u32;
            slh_hash(c, ta, buf[2 * j * n..(2 * j + 2) * n], t[..n]);
            for b in n { buf[j * n + b] = t[b]; }
        }
    }
    for b in n { root[b] = buf[b]; }
}

// xmss_pkFromSig (Algorithm 11).
fn slh_xmss_pk_from_sig(c: const SlhCtx&, a: const u32[:], idx: i64, sig: const u8[:], msg: const u8[:], out: u8[:]) {
    let n = c.p.n;
    var node: u8[64] = [0; 64];
    slh_wots_pk_from_sig(c, a, idx, sig[..c.p.len * n], msg, node[..n]);
    var ta: u32[8] = [0; 8];
    for i in 8 { ta[i] = a[i]; }
    slh_set_type(ta, SLH_TREE);
    var ti = idx;
    var t: u8[32] = [0; 32];
    for k in c.p.hp {
        let auth = sig[(c.p.len + k) * n..(c.p.len + k + 1) * n];
        ta[6] = (k + 1) as! u32;
        if ((idx >> k) & 1) == 0 {
            for b in n { node[n + b] = auth[b]; }
        } else {
            for b in n { node[n + b] = node[b]; node[b] = auth[b]; }
        }
        ti = ti >> 1;
        ta[7] = ti as! u32;
        slh_hash(c, ta, node[..2 * n], t[..n]);
        for b in n { node[b] = t[b]; }
    }
    for b in n { out[b] = node[b]; }
}

// --- FORS (§8) ---------------------------------------------------------------------

// The k a-bit FORS indices of md (base_2b, Algorithm 4).
fn slh_fors_indices(p: const SlhParams&, md: const u8[:], idx: i64[:]) {
    var at = 0;
    var bits = 0;
    var total: u64 = 0;
    for i in p.k {
        while bits < p.a {
            total = (total << 8) | md[at];
            at++;
            bits += 8;
        }
        bits -= p.a;
        idx[i] = ((total >> bits) & ((1 << p.a) - 1)) as! i64;
        total = total & ((1 << bits) - 1);
    }
}

// fors_sign (Algorithm 16) with the roots of the k trees, which
// fors_pkFromSig would rebuild, hashed to the FORS public key. buf holds
// one tree's 2^a leaves.
fn slh_fors_sign(c: const SlhCtx&, a: const u32[:], md: const u8[:], buf: u8[:], sig: u8[>..]&, pk: u8[:]) {
    let n = c.p.n;
    let p = c.p;
    var idx: i64[35] = [0; 35];
    slh_fors_indices(p, md, idx);
    var roots: u8[1120] = [0; 1120];      // k * n, at most 35 * 32
    var fa:    u32[8]   = [0; 8];
    var sa:    u32[8]   = [0; 8];
    for i in 8 { fa[i] = a[i]; sa[i] = a[i]; }
    slh_set_type(fa, SLH_FORS_TREE);
    fa[5] = a[5];
    slh_set_type(sa, SLH_FORS_PRF);
    sa[5] = a[5];
    let leaves = 1 << p.a;
    var t: u8[32] = [0; 32];
    for i in p.k {
        let base = i * leaves;
        let at = sig.len;
        sig.resize(at + (1 + p.a) * n, 0);
        // The leaves: F of each PRF secret; the signed one's secret goes out.
        fa[6] = 0;
        for j in leaves {
            sa[7] = (base + j) as! u32;
            slh_prf(c, sa, t[..n]);
            if j == idx[i] { for b in n { sig[at + b] = t[b]; } }
            fa[7] = (base + j) as! u32;
            slh_hash(c, fa, t[..n], buf[j * n..(j + 1) * n]);
        }
        var width = leaves;
        for z in 1..p.a + 1 {
            let sib = (idx[i] >> (z - 1)) ^ 1;
            for b in n { sig[at + z * n + b] = buf[sib * n + b]; }
            width = width / 2;
            fa[6] = z as! u32;
            for j in width {
                fa[7] = ((base >> z) + j) as! u32;
                slh_hash(c, fa, buf[2 * j * n..(2 * j + 2) * n], t[..n]);
                for b in n { buf[j * n + b] = t[b]; }
            }
        }
        for b in n { roots[i * n + b] = buf[b]; }
    }
    var ra: u32[8] = [0; 8];
    for i in 8 { ra[i] = a[i]; }
    slh_set_type(ra, SLH_FORS_ROOTS);
    ra[5] = a[5];
    slh_hash(c, ra, roots[..p.k * n], pk);
}

// fors_pkFromSig (Algorithm 17).
fn slh_fors_pk_from_sig(c: const SlhCtx&, a: const u32[:], md: const u8[:], sig: const u8[:], pk: u8[:]) {
    let n = c.p.n;
    let p = c.p;
    var idx: i64[35] = [0; 35];
    slh_fors_indices(p, md, idx);
    var roots: u8[1120] = [0; 1120];
    var fa:    u32[8]   = [0; 8];
    for i in 8 { fa[i] = a[i]; }
    slh_set_type(fa, SLH_FORS_TREE);
    fa[5] = a[5];
    var node: u8[64] = [0; 64];
    var t:    u8[32] = [0; 32];
    for i in p.k {
        let s = sig[i * (1 + p.a) * n..(i + 1) * (1 + p.a) * n];
        var ti = (i << p.a) + idx[i];
        fa[6] = 0;
        fa[7] = ti as! u32;
        slh_hash(c, fa, s[..n], node[..n]);
        for j in p.a {
            let auth = s[(1 + j) * n..(2 + j) * n];
            fa[6] = (j + 1) as! u32;
            if ((idx[i] >> j) & 1) == 0 {
                for b in n { node[n + b] = auth[b]; }
            } else {
                for b in n { node[n + b] = node[b]; node[b] = auth[b]; }
            }
            ti = ti >> 1;
            fa[7] = ti as! u32;
            slh_hash(c, fa, node[..2 * n], t[..n]);
            for b in n { node[b] = t[b]; }
        }
        for b in n { roots[i * n + b] = node[b]; }
    }
    var ra: u32[8] = [0; 8];
    for i in 8 { ra[i] = a[i]; }
    slh_set_type(ra, SLH_FORS_ROOTS);
    ra[5] = a[5];
    slh_hash(c, ra, roots[..p.k * n], pk);
}

// The tree and leaf indices of a digest (Algorithm 19, steps 7 to 10).
fn slh_indices(p: const SlhParams&, digest: const u8[:]) -> u64, i64 {
    let mdb = (p.k * p.a + 7) / 8;
    let tb = (p.h - p.hp + 7) / 8;
    let lb = (p.hp + 7) / 8;
    var tree: u64 = 0;
    for i in tb { tree = (tree << 8) | digest[mdb + i]; }
    let tbits = p.h - p.hp;
    if tbits < 64 { tree = tree & ((1 << tbits) - 1); }
    var leaf = 0;
    for i in lb { leaf = (leaf << 8) | digest[mdb + tb + i]; }
    leaf = leaf & ((1 << p.hp) - 1);
    return tree, leaf;
}

// --- Keys ------------------------------------------------------------------------

// slh_keygen_internal (Algorithm 18): the private and public keys of
// SK.seed, SK.prf and PK.seed.
fn slhdsa_keygen_internal(set: i64, sk_seed: const u8[:], sk_prf: const u8[:], pk_seed: const u8[:]) -> u8[>..], u8[>..] {
    let p = slhdsa_params(set);
    assert(sk_seed.len == p.n && sk_prf.len == p.n && pk_seed.len == p.n);
    let c = slh_ctx(set, pk_seed, sk_seed);
    var buf: u8[>..] = [];
    buf.resize((1 << p.hp) * p.n, 0);
    var none: u8[>..] = [];
    var root: u8[32]  = [0; 32];
    let a = slh_adrs(p.d - 1, 0);
    slh_xmss(c, a, -1, "", buf, none, root[..p.n]);
    var sk: u8[>..] = [];
    sk.append(sk_seed);
    sk.append(sk_prf);
    sk.append(pk_seed);
    sk.append(root[..p.n]);
    var pk: u8[>..] = [];
    pk.append(sk[2 * p.n..]);
    return sk, pk;
}

// The key pair of a 3n-byte seed SK.seed || SK.prf || PK.seed.
fn slhdsa_key_from_seed(set: i64, seed: const u8[:]) -> u8[>..], u8[>..] {
    let n = slhdsa_n(set);
    assert(seed.len == 3 * n);
    let sk, pk = slhdsa_keygen_internal(set, seed[..n], seed[n..2 * n], seed[2 * n..]);
    return sk, pk;
}

// A fresh key pair from the OS's entropy: the private and the public key.
fn slhdsa_keygen(set: i64) -> u8[>..], u8[>..] {
    var seed: u8[>..] = [];
    seed.resize(slhdsa_seed_len(set), 0);
    entropy::random_bytes(seed);
    let sk, pk = slhdsa_key_from_seed(set, seed);
    return sk, pk;
}

// The public key in a private key (its last 2n bytes).
fn slhdsa_public_key(set: i64, sk: const u8[:]) -> u8[>..] {
    assert(sk.len == slhdsa_sk_len(set));
    var pk: u8[>..] = [];
    pk.append(sk[2 * slhdsa_n(set)..]);
    return pk;
}

// Whether a private key's PK.root is its seeds' (as costly as a key
// generation).
fn slhdsa_check_key(set: i64, sk: const u8[:]) -> bool {
    if !slhdsa_valid(set) || sk.len != slhdsa_sk_len(set) { return false; }
    let n = slhdsa_n(set);
    let sk2, pk2 = slhdsa_keygen_internal(set, sk[..n], sk[n..2 * n], sk[2 * n..3 * n]);
    return sk2 == sk;
}

// --- Signing and verifying -----------------------------------------------------------

// slh_sign_internal (Algorithm 19): a signature of the prepared message
// mp, with opt_rand = addrnd (n bytes; PK.seed for the deterministic
// variant).
fn slhdsa_sign_internal(set: i64, sk: const u8[:], mp: const u8[:], addrnd: const u8[:]) -> u8[>..] {
    let p = slhdsa_params(set);
    let n = p.n;
    assert(sk.len == 4 * n && addrnd.len == n);
    let c = slh_ctx(set, sk[2 * n..3 * n], sk[..n]);
    var sig: u8[>..] = [];
    let r = slh_prf_msg(p, sk[n..2 * n], addrnd, mp);
    sig.append(r);
    let digest = slh_h_msg(p, r, sk[2 * n..], mp);
    var tree, leaf = slh_indices(p, digest);
    var buf: u8[>..] = [];
    buf.resize((1 << ::max(p.a, p.hp)) * n, 0);
    var a = slh_adrs(0, tree);
    a[5] = leaf as! u32;
    var root: u8[32] = [0; 32];
    slh_fors_sign(c, a, digest[..(p.k * p.a + 7) / 8], buf, sig, root[..n]);
    var msg: u8[32] = [0; 32];
    for j in p.d {
        for b in n { msg[b] = root[b]; }
        let la = slh_adrs(j, tree);
        slh_xmss(c, la, leaf, msg[..n], buf, sig, root[..n]);
        leaf = (tree & ((1 << p.hp) - 1)) as! i64;
        tree = tree >> p.hp;
    }
    return sig;
}

// slh_verify_internal (Algorithm 20).
fn slhdsa_verify_internal(set: i64, pk: const u8[:], mp: const u8[:], sig: const u8[:]) -> bool {
    if !slhdsa_valid(set) || pk.len != slhdsa_pk_len(set) || sig.len != slhdsa_sig_len(set) { return false; }
    let p = slhdsa_params(set);
    let n = p.n;
    let c = slh_ctx(set, pk[..n], "");
    let r = sig[..n];
    let digest = slh_h_msg(p, r, pk, mp);
    var tree, leaf = slh_indices(p, digest);
    var a = slh_adrs(0, tree);
    a[5] = leaf as! u32;
    let fl = p.k * (1 + p.a) * n;
    var node: u8[32] = [0; 32];
    slh_fors_pk_from_sig(c, a, digest[..(p.k * p.a + 7) / 8], sig[n..n + fl], node[..n]);
    var at = n + fl;
    let xl = (p.len + p.hp) * n;
    var msg: u8[32] = [0; 32];
    for j in p.d {
        for b in n { msg[b] = node[b]; }
        let la = slh_adrs(j, tree);
        slh_xmss_pk_from_sig(c, la, leaf, sig[at..at + xl], msg[..n], node[..n]);
        at += xl;
        leaf = (tree & ((1 << p.hp) - 1)) as! i64;
        tree = tree >> p.hp;
    }
    var diff: u8 = 0;
    for b in n { diff |= node[b] ^ pk[n + b]; }
    return diff == 0;
}

// M' = toByte(0, 1) || toByte(|ctx|, 1) || ctx || M; false for a context
// past 255 bytes.
fn slh_pure_msg(msg: const u8[:], ctx: const u8[:]) -> u8[>..], bool {
    var mp: u8[>..] = [];
    if ctx.len > 255 { return mp, false; }
    mp.push(0);
    mp.push(ctx.len as! u8);
    mp.append(ctx);
    mp.append(msg);
    return mp, true;
}

// A hedged signature of msg under ctx (slh_sign, Algorithm 22).
fn slhdsa_sign(set: i64, sk: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[>..] {
    var rnd: u8[>..] = [];
    rnd.resize(slhdsa_n(set), 0);
    entropy::random_bytes(rnd);
    return slhdsa_sign_with(set, sk, msg, ctx, rnd);
}

// The deterministic variant (opt_rand = PK.seed).
fn slhdsa_sign_deterministic(set: i64, sk: const u8[:], msg: const u8[:], ctx: const u8[:] = "") -> u8[>..] {
    let n = slhdsa_n(set);
    assert(sk.len == 4 * n);
    return slhdsa_sign_with(set, sk, msg, ctx, sk[2 * n..3 * n]);
}

// Signing with the given n bytes of randomness, for tests.
fn slhdsa_sign_with(set: i64, sk: const u8[:], msg: const u8[:], ctx: const u8[:], addrnd: const u8[:]) -> u8[>..] {
    let mp, ok = slh_pure_msg(msg, ctx);
    assert(ok);
    return slhdsa_sign_internal(set, sk, mp, addrnd);
}

// slh_verify (Algorithm 24): whether sig signs msg under ctx for pk.
fn slhdsa_verify(set: i64, pk: const u8[:], msg: const u8[:], sig: const u8[:], ctx: const u8[:] = "") -> bool {
    if !slhdsa_valid(set) { return false; }
    let mp, ok = slh_pure_msg(msg, ctx);
    return ok && slhdsa_verify_internal(set, pk, mp, sig);
}

// --- HashSLH-DSA (Algorithms 23 and 25) ------------------------------------------------

// The DER OID of a pre-hash (2.16.840.1.101.3.4.2.x) and the digest of
// msg; false for a hash HashSLH-DSA does not take.
fn slh_prehash(ph: i64, msg: const u8[:]) -> u8[>..], u8[>..], bool {
    var oid:  u8[>..] = [];
    var d:    u8[>..] = [];
    var last: u8      = 0;
    if ph == HASH_SHA256 { last = 1; } else if ph == HASH_SHA384 { last = 2; } else if ph == HASH_SHA512 { last = 3; }
    else if ph == HASH_SHA224 { last = 4; } else if ph == HASH_SHA512_224 { last = 5; } else if ph == HASH_SHA512_256 { last = 6; }
    else if ph == HASH_SHA3_224 { last = 7; } else if ph == HASH_SHA3_256 { last = 8; } else if ph == HASH_SHA3_384 { last = 9; }
    else if ph == HASH_SHA3_512 { last = 10; } else if ph == SLHDSA_PH_SHAKE128 { last = 11; } else if ph == SLHDSA_PH_SHAKE256 { last = 12; }
    if last == 0 { return oid, d, false; }
    let prefix: u8[10] = [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];
    oid.append(prefix);
    oid.push(last);
    if ph == SLHDSA_PH_SHAKE128 { d = shake(128, msg, 32); }
    else if ph == SLHDSA_PH_SHAKE256 { d = shake(256, msg, 64); }
    else { d = hash_bits(ph, msg); }
    return oid, d, true;
}

// M' = toByte(1, 1) || toByte(|ctx|, 1) || ctx || OID || PH(M).
fn slh_hash_msg(msg: const u8[:], ph: i64, ctx: const u8[:]) -> u8[>..], bool {
    var mp: u8[>..] = [];
    let oid, d, ok = slh_prehash(ph, msg);
    if !ok || ctx.len > 255 { return mp, false; }
    mp.push(1);
    mp.push(ctx.len as! u8);
    mp.append(ctx);
    mp.append(oid);
    mp.append(d);
    return mp, true;
}

// hash_slh_sign with the given n bytes of randomness.
fn slhdsa_hash_sign_with(set: i64, sk: const u8[:], msg: const u8[:], ph: i64, ctx: const u8[:], addrnd: const u8[:]) -> u8[>..] {
    let mp, ok = slh_hash_msg(msg, ph, ctx);
    assert(ok);
    return slhdsa_sign_internal(set, sk, mp, addrnd);
}

// A hedged HashSLH-DSA signature of msg, pre-hashed with ph.
fn slhdsa_hash_sign(set: i64, sk: const u8[:], msg: const u8[:], ph: i64, ctx: const u8[:] = "") -> u8[>..] {
    var rnd: u8[>..] = [];
    rnd.resize(slhdsa_n(set), 0);
    entropy::random_bytes(rnd);
    return slhdsa_hash_sign_with(set, sk, msg, ph, ctx, rnd);
}

fn slhdsa_hash_sign_deterministic(set: i64, sk: const u8[:], msg: const u8[:], ph: i64, ctx: const u8[:] = "") -> u8[>..] {
    let n = slhdsa_n(set);
    assert(sk.len == 4 * n);
    return slhdsa_hash_sign_with(set, sk, msg, ph, ctx, sk[2 * n..3 * n]);
}

// hash_slh_verify (Algorithm 25).
fn slhdsa_hash_verify(set: i64, pk: const u8[:], msg: const u8[:], sig: const u8[:], ph: i64, ctx: const u8[:] = "") -> bool {
    if !slhdsa_valid(set) { return false; }
    let mp, ok = slh_hash_msg(msg, ph, ctx);
    return ok && slhdsa_verify_internal(set, pk, mp, sig);
}
