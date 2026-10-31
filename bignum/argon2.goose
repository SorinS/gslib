// bignum.argon2: Argon2 (RFC 9106, version 0x13): Argon2id, the one to
// use for password hashing, and Argon2i and Argon2d. argon2id_key and
// argon2i_key take Go's x/crypto/argon2 parameters (IDKey and Key);
// argon2 takes every parameter, the secret key and associated data too.
//
// Memory is m KiB (at least 8 per lane), filled t times over by p lanes.
// The lanes are filled one after another here, which gives the same
// output as filling them in parallel. Argon2i, and Argon2id in the first
// half of its first pass, choose the blocks they read independently of
// the password; Argon2d, and Argon2id after that, read blocks at
// password-dependent positions, as the algorithm intends.

namespace bignum;

import std;
import blake2;

let ARGON2D: i64 = 0;
let ARGON2I: i64 = 1;
let ARGON2ID: i64 = 2;

fn le32_bytes(out: u8[>..]&, x: i64) {
    for k in 4 { out.push((x >> (8 * k)) as! u8); }
}

// H' (RFC 9106 §3.3): a variable-length hash of x, len bytes.
fn argon2_hash(x: const u8[:], len: i64) -> u8[>..] {
    var pre: u8[>..] = [];
    le32_bytes(pre, len);
    var s = blake2b_init(::min(len, 64));
    blake2b_update(s, pre);
    blake2b_update(s, x);
    var out: u8[>..] = [];
    if len <= 64 {
        out = blake2b_final(s);
        return out;
    }
    var v = blake2b_final(s);
    let r = (len + 31) / 32 - 2;
    out.append(v[..32]);
    for i in 1..r {
        let nv = blake2b(v);
        v = copy(nv);
        out.append(v[..32]);
    }
    let last = blake2b(v, len - 32 * r);
    out.append(last);
    return out;
}

fn fbla(a: u64, b: u64) -> u64 { a + b + 2 * (a & 0xffffffff) * (b & 0xffffffff) }

// BLAKE2b's G with the multiplications Argon2 adds.
fn argon2_gb(v: u64[:], a: i64, b: i64, c: i64, d: i64) {
    v[a] = fbla(v[a], v[b]); v[d] = b2_rotr64(v[d] ^ v[a], 32);
    v[c] = fbla(v[c], v[d]); v[b] = b2_rotr64(v[b] ^ v[c], 24);
    v[a] = fbla(v[a], v[b]); v[d] = b2_rotr64(v[d] ^ v[a], 16);
    v[c] = fbla(v[c], v[d]); v[b] = b2_rotr64(v[b] ^ v[c], 63);
}

// The permutation P on the 16 words of q, at positions idx.
fn argon2_p(q: u64[:], idx: const i64[:]) {
    var v: u64[16] = [0; 16];
    for i in 16 { v[i] = q[idx[i]]; }
    argon2_gb(v, 0, 4, 8, 12); argon2_gb(v, 1, 5, 9, 13);
    argon2_gb(v, 2, 6, 10, 14); argon2_gb(v, 3, 7, 11, 15);
    argon2_gb(v, 0, 5, 10, 15); argon2_gb(v, 1, 6, 11, 12);
    argon2_gb(v, 2, 7, 8, 13); argon2_gb(v, 3, 4, 9, 14);
    for i in 16 { q[idx[i]] = v[i]; }
}

// out = G(x, y), or out ^= G(x, y) when xor (passes after the first). out
// may be y (address blocks), not x.
fn argon2_g(x: const u64[:], y: const u64[:], out: u64[:], xor: bool) {
    var r: u64[128] = [0; 128];
    var q: u64[128] = [0; 128];
    for i in 128 { r[i] = x[i] ^ y[i]; q[i] = r[i]; }
    var idx: i64[16] = [0; 16];
    for row in 8 {
        for k in 16 { idx[k] = 16 * row + k; }
        argon2_p(q, idx);
    }
    for col in 8 {
        for k in 8 { idx[2 * k] = 2 * col + 16 * k; idx[2 * k + 1] = 2 * col + 16 * k + 1; }
        argon2_p(q, idx);
    }
    if xor {
        for i in 128 { out[i] ^= q[i] ^ r[i]; }
    } else {
        for i in 128 { out[i] = q[i] ^ r[i]; }
    }
}

fn argon2_block_from(mem: u64[:], at: i64, b: const u8[:]) {
    for i in 128 {
        var w: u64 = 0;
        for k in 8 { w = w | (b[8 * i + k] as u64) << (8 * k); }
        mem[at + i] = w;
    }
}

// Argon2 of the given kind: len >= 4 bytes from the password and salt
// (at least 8 bytes), an optional secret key and associated data, t >= 1
// passes over m KiB with p lanes (1..2^24 - 1, m >= 8p).
fn argon2(kind: i64, password: const u8[:], salt: const u8[:], secret: const u8[:], ad: const u8[:],
          t: i64, m: i64, p: i64, len: i64) -> u8[>..] {
    assert(kind == ARGON2D || kind == ARGON2I || kind == ARGON2ID);
    assert(t >= 1 && p >= 1 && p < 1 << 24 && m >= 8 * p && len >= 4);
    var h0in: u8[>..] = [];
    le32_bytes(h0in, p);
    le32_bytes(h0in, len);
    le32_bytes(h0in, m);
    le32_bytes(h0in, t);
    le32_bytes(h0in, 0x13);
    le32_bytes(h0in, kind);
    le32_bytes(h0in, password.len);
    h0in.append(password);
    le32_bytes(h0in, salt.len);
    h0in.append(salt);
    le32_bytes(h0in, secret.len);
    h0in.append(secret);
    le32_bytes(h0in, ad.len);
    h0in.append(ad);
    var h0 = blake2b(h0in);
    h0.resize(72, 0);
    let blocks = 4 * p * (m / (4 * p));          // m', a whole number of segments
    let lane_len = blocks / p;
    let seg = lane_len / 4;
    var mem: u64[>..] = [];
    mem.resize(128 * blocks, 0);
    for l in p {
        for j in 2 {
            for k in 4 { h0[64 + k] = (j >> (8 * k)) as! u8; h0[68 + k] = (l >> (8 * k)) as! u8; }
            let b = argon2_hash(h0, 1024);
            argon2_block_from(mem, 128 * (l * lane_len + j), b);
        }
    }
    var zero: u64[128] = [0; 128];
    var input: u64[128] = [0; 128];
    var addr: u64[128] = [0; 128];
    for pass in t {
        for slice in 4 {
            let indep = kind == ARGON2I || (kind == ARGON2ID && pass == 0 && slice < 2);
            for l in p {
                if indep {
                    for i in 128 { input[i] = 0; }
                    input[0] = pass as! u64; input[1] = l as! u64; input[2] = slice as! u64;
                    input[3] = blocks as! u64; input[4] = t as! u64; input[5] = kind as! u64;
                }
                var start = 0;
                if pass == 0 && slice == 0 {
                    start = 2;
                    if indep {
                        input[6] += 1;
                        argon2_g(zero, input, addr, false);
                        argon2_g(zero, addr, addr, false);
                    }
                }
                for i in start..seg {
                    let cur = l * lane_len + slice * seg + i;
                    let prev = if cur % lane_len == 0 { cur + lane_len - 1 } else { cur - 1 };
                    var rnd: u64 = 0;
                    if indep {
                        if i % 128 == 0 {
                            input[6] += 1;
                            argon2_g(zero, input, addr, false);
                            argon2_g(zero, addr, addr, false);
                        }
                        rnd = addr[i % 128];
                    } else {
                        rnd = mem[128 * prev];
                    }
                    var ref_lane: i64 = ((rnd >> 32) % (p as! u64)) as! i64;
                    if pass == 0 && slice == 0 { ref_lane = l; }
                    let same = ref_lane == l;
                    // The blocks this one may refer to (RFC 9106 §3.4.1.2).
                    var area = 0;
                    if pass == 0 {
                        if slice == 0 { area = i - 1; }
                        else if same { area = slice * seg + i - 1; }
                        else { area = slice * seg - (if i == 0 { 1 } else { 0 }); }
                    } else {
                        if same { area = lane_len - seg + i - 1; }
                        else { area = lane_len - seg - (if i == 0 { 1 } else { 0 }); }
                    }
                    let j1: u64 = rnd & 0xffffffff;
                    let x = (j1 * j1) >> 32;
                    let rel = (area as! u64) - 1 - (((area as! u64) * x) >> 32);
                    let startpos = if pass == 0 || slice == 3 { 0 } else { (slice + 1) * seg };
                    let refidx = ((startpos as! u64) + rel) % (lane_len as! u64);
                    let refb: i64 = ref_lane * lane_len + (refidx as! i64);
                    argon2_g(mem[128 * prev..128 * prev + 128], mem[128 * refb..128 * refb + 128],
                             mem[128 * cur..128 * cur + 128], pass > 0);
                }
            }
        }
    }
    var c: u64[128] = [0; 128];
    for l in p {
        let last = 128 * (l * lane_len + lane_len - 1);
        for i in 128 { c[i] ^= mem[last + i]; }
    }
    var cb: u8[1024] = [0; 1024];
    for i in 1024 { cb[i] = (c[i / 8] >> (8 * (i % 8))) as! u8; }
    return argon2_hash(cb, len);
}

// Go's argon2.IDKey: Argon2id with time t, memory m KiB and p threads.
fn argon2id_key(password: const u8[:], salt: const u8[:], t: i64, m: i64, p: i64, len: i64) -> u8[>..] {
    argon2(ARGON2ID, password, salt, "", "", t, m, p, len)
}

// Go's argon2.Key: Argon2i.
fn argon2i_key(password: const u8[:], salt: const u8[:], t: i64, m: i64, p: i64, len: i64) -> u8[>..] {
    argon2(ARGON2I, password, salt, "", "", t, m, p, len)
}
