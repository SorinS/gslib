// bignum.blake2: BLAKE2b and BLAKE2s (RFC 7693), as in Go's
// x/crypto/blake2b and blake2s: digests of 1 to 64 (BLAKE2b) or 1 to 32
// (BLAKE2s) bytes, optionally keyed as a MAC with a key up to that long.
// Streaming: blake2b_init, blake2b_update any number of times, then
// blake2b_final; or blake2b(data). Argon2 (bignum.argon2) is built on
// BLAKE2b. Constant time.
//
// BLAKE2Xb and BLAKE2Xs (blake2.net/blake2x.pdf) are the extendable-output
// forms, as Go's blake2b.NewXOF and blake2s.NewXOF: the output length is
// fixed up front (up to 2^32 - 2 or 2^16 - 2 bytes) and is part of the
// hash, or left unknown with 0, which allows up to 256 GiB or 128 GiB.
// blake2xb_init, blake2xb_update, then blake2xb_read for as many pieces of
// output as wanted; or blake2xb(data, n).
//
// As hashes for HMAC, HKDF, PBKDF2 and signatures, bignum.hmac names
// BLAKE2b-256, -384, -512 and BLAKE2s-256 (Go's crypto.BLAKE2b_256 and so
// on), unkeyed.

namespace bignum;

import std;

// The last block is held back until final, which compresses it with the
// finalization flag.
struct Blake2b { h: u64[8], buf: u8[128], used: i64, t: u64, outlen: i64 }
struct Blake2s { h: u32[8], buf: u8[64], used: i64, t: u64, outlen: i64 }

// SHA-512's and SHA-256's initial values.
let BLAKE2B_IV: u64[8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
];
let BLAKE2S_IV: u32[8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
];

// The message word permutation of each round.
let BLAKE2_SIGMA: u8[160] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3,
    11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4,
    7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8,
    9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13,
    2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9,
    12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11,
    13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10,
    6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5,
    10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0
];

fn b2_rotr64(x: u64, n: u32) -> u64 { (x >> n) | (x << (64 - n)) }
fn b2_rotr32(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

fn b2b_g(v: u64[:], a: i64, b: i64, c: i64, d: i64, x: u64, y: u64) {
    v[a] = v[a] + v[b] + x; v[d] = b2_rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];     v[b] = b2_rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y; v[d] = b2_rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];     v[b] = b2_rotr64(v[b] ^ v[c], 63);
}

fn b2s_g(v: u32[:], a: i64, b: i64, c: i64, d: i64, x: u32, y: u32) {
    v[a] = v[a] + v[b] + x; v[d] = b2_rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];     v[b] = b2_rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] + v[b] + y; v[d] = b2_rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] + v[d];     v[b] = b2_rotr32(v[b] ^ v[c], 7);
}

fn blake2b_compress(s: Blake2b&, p: const u8[:], last: bool) {
    var m: u64[16] = [0; 16];
    for i in 16 {
        var w: u64 = 0;
        for k in 8 { w = w | (p[8 * i + k] as u64) << (8 * k); }
        m[i] = w;
    }
    var v: u64[16] = [0; 16];
    for i in 8 { v[i] = s.h[i]; v[8 + i] = BLAKE2B_IV[i]; }
    v[12] ^= s.t;
    if last { v[14] = ~v[14]; }
    for r in 12 {
        let sg = BLAKE2_SIGMA[16 * (r % 10)..16 * (r % 10) + 16];
        b2b_g(v, 0, 4, 8, 12, m[sg[0]], m[sg[1]]);
        b2b_g(v, 1, 5, 9, 13, m[sg[2]], m[sg[3]]);
        b2b_g(v, 2, 6, 10, 14, m[sg[4]], m[sg[5]]);
        b2b_g(v, 3, 7, 11, 15, m[sg[6]], m[sg[7]]);
        b2b_g(v, 0, 5, 10, 15, m[sg[8]], m[sg[9]]);
        b2b_g(v, 1, 6, 11, 12, m[sg[10]], m[sg[11]]);
        b2b_g(v, 2, 7, 8, 13, m[sg[12]], m[sg[13]]);
        b2b_g(v, 3, 4, 9, 14, m[sg[14]], m[sg[15]]);
    }
    for i in 8 { s.h[i] ^= v[i] ^ v[8 + i]; }
}

fn blake2s_compress(s: Blake2s&, p: const u8[:], last: bool) {
    var m: u32[16] = [0; 16];
    for i in 16 {
        let b0: u32 = p[4 * i];
        m[i] = b0 | (p[4 * i + 1] as u32) << 8 | (p[4 * i + 2] as u32) << 16 | (p[4 * i + 3] as u32) << 24;
    }
    var v: u32[16] = [0; 16];
    for i in 8 { v[i] = s.h[i]; v[8 + i] = BLAKE2S_IV[i]; }
    v[12] ^= s.t as! u32;
    v[13] ^= (s.t >> 32) as! u32;
    if last { v[14] = ~v[14]; }
    for r in 10 {
        let sg = BLAKE2_SIGMA[16 * r..16 * r + 16];
        b2s_g(v, 0, 4, 8, 12, m[sg[0]], m[sg[1]]);
        b2s_g(v, 1, 5, 9, 13, m[sg[2]], m[sg[3]]);
        b2s_g(v, 2, 6, 10, 14, m[sg[4]], m[sg[5]]);
        b2s_g(v, 3, 7, 11, 15, m[sg[6]], m[sg[7]]);
        b2s_g(v, 0, 5, 10, 15, m[sg[8]], m[sg[9]]);
        b2s_g(v, 1, 6, 11, 12, m[sg[10]], m[sg[11]]);
        b2s_g(v, 2, 7, 8, 13, m[sg[12]], m[sg[13]]);
        b2s_g(v, 3, 4, 9, 14, m[sg[14]], m[sg[15]]);
    }
    for i in 8 { s.h[i] ^= v[i] ^ v[8 + i]; }
}

// A digest of outlen bytes (1..64), keyed when key is not empty (at most
// 64 bytes).
fn blake2b_init(outlen: i64 = 64, key: const u8[:] = "") -> Blake2b {
    assert(outlen >= 1 && outlen <= 64 && key.len <= 64);
    var s = Blake2b { h: BLAKE2B_IV, buf: [0; 128], used: 0, t: 0, outlen: outlen };
    s.h[0] ^= 0x01010000 ^ ((key.len as u64) << 8) ^ (outlen as u64);
    if key.len > 0 {
        for i in key.len { s.buf[i] = key[i]; }
        s.used = 128;                            // the key fills one block, zero padded
    }
    return s;
}

fn blake2b_update(s: Blake2b&, data: const u8[:]) {
    var i = 0;
    while i < data.len {
        if s.used == 128 {
            s.t += 128;
            let blk = s.buf;
            blake2b_compress(s, blk, false);
            s.used = 0;
        }
        let n = ::min(128 - s.used, data.len - i);
        for k in n { s.buf[s.used + k] = data[i + k]; }
        s.used += n;
        i += n;
    }
}

fn blake2b_final(s: Blake2b&) -> u8[>..] {
    s.t += s.used as u64;
    for k in s.used..128 { s.buf[k] = 0; }
    let blk = s.buf;
    blake2b_compress(s, blk, true);
    var out: u8[>..] = [];
    for i in s.outlen { out.push((s.h[i / 8] >> (8 * (i % 8))) as! u8); }
    return out;
}

fn blake2b(data: const u8[:], outlen: i64 = 64, key: const u8[:] = "") -> u8[>..] {
    var s = blake2b_init(outlen, key);
    blake2b_update(s, data);
    return blake2b_final(s);
}

// A state from a whole parameter block (64 bytes), unkeyed.
fn blake2b_init_cfg(cfg: const u8[:]) -> Blake2b {
    var s = Blake2b { h: BLAKE2B_IV, buf: [0; 128], used: 0, t: 0, outlen: cfg[0] };
    for i in 8 {
        var w: u64 = 0;
        for k in 8 { w = w | (cfg[8 * i + k] as u64) << (8 * k); }
        s.h[i] ^= w;
    }
    return s;
}

// A digest of outlen bytes (1..32), keyed when key is not empty (at most
// 32 bytes).
fn blake2s_init(outlen: i64 = 32, key: const u8[:] = "") -> Blake2s {
    assert(outlen >= 1 && outlen <= 32 && key.len <= 32);
    var s = Blake2s { h: BLAKE2S_IV, buf: [0; 64], used: 0, t: 0, outlen: outlen };
    s.h[0] ^= 0x01010000 ^ ((key.len as! u32) << 8) ^ (outlen as! u32);
    if key.len > 0 {
        for i in key.len { s.buf[i] = key[i]; }
        s.used = 64;
    }
    return s;
}

fn blake2s_update(s: Blake2s&, data: const u8[:]) {
    var i = 0;
    while i < data.len {
        if s.used == 64 {
            s.t += 64;
            let blk = s.buf;
            blake2s_compress(s, blk, false);
            s.used = 0;
        }
        let n = ::min(64 - s.used, data.len - i);
        for k in n { s.buf[s.used + k] = data[i + k]; }
        s.used += n;
        i += n;
    }
}

fn blake2s_final(s: Blake2s&) -> u8[>..] {
    s.t += s.used as u64;
    for k in s.used..64 { s.buf[k] = 0; }
    let blk = s.buf;
    blake2s_compress(s, blk, true);
    var out: u8[>..] = [];
    for i in s.outlen { out.push((s.h[i / 4] >> (8 * (i % 4))) as! u8); }
    return out;
}

fn blake2s(data: const u8[:], outlen: i64 = 32, key: const u8[:] = "") -> u8[>..] {
    var s = blake2s_init(outlen, key);
    blake2s_update(s, data);
    return blake2s_final(s);
}

// A state from a whole parameter block (32 bytes), unkeyed.
fn blake2s_init_cfg(cfg: const u8[:]) -> Blake2s {
    var s = Blake2s { h: BLAKE2S_IV, buf: [0; 64], used: 0, t: 0, outlen: cfg[0] };
    for i in 8 {
        let b0: u32 = cfg[4 * i];
        s.h[i] ^= b0 | (cfg[4 * i + 1] as u32) << 8 | (cfg[4 * i + 2] as u32) << 16 | (cfg[4 * i + 3] as u32) << 24;
    }
    return s;
}

// BLAKE2X: the root hash absorbs the input (its parameter block carries
// the output length); output block i is then the hash of the root under a
// parameter block with node offset i, and the last block's digest length
// cut to what is left. `left` counts the output still to give, `off` the
// next unread byte of blk (a whole block when blk is used up).
struct Blake2xb { d: Blake2b, cfg: u8[64], root: u8[64], blk: u8[64], left: u64, off: i64, node: u32, reading: bool }
struct Blake2xs { d: Blake2s, cfg: u8[32], root: u8[32], blk: u8[32], left: u64, off: i64, node: u32, reading: bool }

let BLAKE2XB_UNKNOWN: u64 = 0xffffffff;
let BLAKE2XS_UNKNOWN: u64 = 0xffff;

// An XOF of n bytes, or of unknown length when n is 0, keyed when key is
// not empty (at most 64 bytes).
fn blake2xb_init(n: i64 = 0, key: const u8[:] = "") -> Blake2xb {
    assert(n >= 0 && (n as! u64) < BLAKE2XB_UNKNOWN);
    let len: u64 = if n == 0 { BLAKE2XB_UNKNOWN } else { n as! u64 };
    var x = Blake2xb { d: blake2b_init(64, key), cfg: [0; 64], root: [0; 64], blk: [0; 64],
                       left: if n == 0 { 64 << 32 } else { len }, off: 64, node: 0, reading: false };
    x.d.h[1] ^= len << 32;
    x.cfg[0] = 64;                               // digest length
    x.cfg[4] = 64;                               // leaf length
    for k in 4 { x.cfg[12 + k] = (len >> (8 * k)) as! u8; }
    x.cfg[17] = 64;                              // inner hash length
    return x;
}

fn blake2xb_update(x: Blake2xb&, data: const u8[:]) {
    assert(!x.reading);
    blake2b_update(x.d, data);
}

// Fills out with the next output; fewer bytes (the count is returned)
// once the output runs out.
fn blake2xb_read(x: Blake2xb&, out: u8[:]) -> i64 {
    if !x.reading {
        let r = blake2b_final(x.d);
        for i in 64 { x.root[i] = r[i]; }
        x.reading = true;
    }
    let n: i64 = if (out.len as! u64) > x.left { x.left as! i64 } else { out.len };
    for i in n {
        if x.off == 64 {
            x.cfg[0] = if x.left < 64 { x.left as! u8 } else { 64 };
            for k in 4 { x.cfg[8 + k] = (x.node >> (8 * k)) as! u8; }
            x.node++;
            var s = blake2b_init_cfg(x.cfg);
            blake2b_update(s, x.root);
            let b = blake2b_final(s);
            for k in b.len { x.blk[k] = b[k]; }
            x.off = 0;
        }
        out[i] = x.blk[x.off];
        x.off++;
        x.left--;
    }
    return n;
}

// n bytes (1..2^32 - 2) of BLAKE2Xb of data.
fn blake2xb(data: const u8[:], n: i64, key: const u8[:] = "") -> u8[>..] {
    assert(n >= 1);
    var x = blake2xb_init(n, key);
    blake2xb_update(x, data);
    var out: u8[>..] = [];
    out.resize(n, 0);
    blake2xb_read(x, out);
    return out;
}

// An XOF of n bytes, or of unknown length when n is 0, keyed when key is
// not empty (at most 32 bytes).
fn blake2xs_init(n: i64 = 0, key: const u8[:] = "") -> Blake2xs {
    assert(n >= 0 && (n as! u64) < BLAKE2XS_UNKNOWN);
    let len: u64 = if n == 0 { BLAKE2XS_UNKNOWN } else { n as! u64 };
    var x = Blake2xs { d: blake2s_init(32, key), cfg: [0; 32], root: [0; 32], blk: [0; 32],
                       left: if n == 0 { 32 << 32 } else { len }, off: 32, node: 0, reading: false };
    x.d.h[3] ^= len as! u32;
    x.cfg[0] = 32;                               // digest length
    x.cfg[4] = 32;                               // leaf length
    x.cfg[12] = len as! u8;
    x.cfg[13] = (len >> 8) as! u8;
    x.cfg[15] = 32;                              // inner hash length
    return x;
}

fn blake2xs_update(x: Blake2xs&, data: const u8[:]) {
    assert(!x.reading);
    blake2s_update(x.d, data);
}

fn blake2xs_read(x: Blake2xs&, out: u8[:]) -> i64 {
    if !x.reading {
        let r = blake2s_final(x.d);
        for i in 32 { x.root[i] = r[i]; }
        x.reading = true;
    }
    let n: i64 = if (out.len as! u64) > x.left { x.left as! i64 } else { out.len };
    for i in n {
        if x.off == 32 {
            x.cfg[0] = if x.left < 32 { x.left as! u8 } else { 32 };
            for k in 4 { x.cfg[8 + k] = (x.node >> (8 * k)) as! u8; }
            x.node++;
            var s = blake2s_init_cfg(x.cfg);
            blake2s_update(s, x.root);
            let b = blake2s_final(s);
            for k in b.len { x.blk[k] = b[k]; }
            x.off = 0;
        }
        out[i] = x.blk[x.off];
        x.off++;
        x.left--;
    }
    return n;
}

// n bytes (1..65534) of BLAKE2Xs of data.
fn blake2xs(data: const u8[:], n: i64, key: const u8[:] = "") -> u8[>..] {
    assert(n >= 1);
    var x = blake2xs_init(n, key);
    blake2xs_update(x, data);
    var out: u8[>..] = [];
    out.resize(n, 0);
    blake2xs_read(x, out);
    return out;
}
