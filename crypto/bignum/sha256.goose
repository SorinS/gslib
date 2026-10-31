// bignum.sha256: SHA-256 and SHA-224 (FIPS 180-4), and MGF1 (RFC 8017 §B.2.1), for
// RSA's padding schemes. Streaming: sha256_init, sha256_update any number
// of times, sha256_final; or sha256(data) in one call. Nothing branches on
// the data, only on lengths.

namespace bignum;

import std;

struct Sha256 { h: u32[8], buf: u8[64], used: i64, total: u64 }

let SHA256_K: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn rotr32(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

fn sha256_init() -> Sha256 {
    Sha256 {
        h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
        buf: [0; 64], used: 0, total: 0,
    }
}

fn sha256_block(s: Sha256&, p: const u8[:]) {
    var w: u32[64] = [0; 64];
    for i in 16 {
        let b0: u32 = p[4 * i];
        w[i] = b0 << 24 | (p[4 * i + 1] as u32) << 16 | (p[4 * i + 2] as u32) << 8 | p[4 * i + 3];
    }
    for i in 16..64 {
        let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3];
    var e = s.h[4]; var f = s.h[5]; var g = s.h[6]; var h = s.h[7];
    for i in 64 {
        let t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ (~e & g))
               + SHA256_K[i] + w[i];
        let t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
    s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}

fn sha256_update(s: Sha256&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(64 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 64 { return; }
        let blk = s.buf;
        sha256_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 64 {
        sha256_block(s, data[i..i + 64]);
        i += 64;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

fn sha256_final(s: Sha256&) -> u8[32] {
    let bits = s.total * 8;
    var tail: u8[72] = [0; 72];
    tail[0] = 0x80;
    let padlen = if s.used < 56 { 56 - s.used } else { 120 - s.used };
    for k in 8 { tail[padlen + k] = (bits >> (56 - 8 * k)) as! u8; }
    sha256_update(s, tail[..padlen + 8]);
    var out: u8[32] = [0; 32];
    for i in 8 {
        for k in 4 { out[4 * i + k] = (s.h[i] >> (24 - 8 * k)) as! u8; }
    }
    return out;
}

// SHA-224: SHA-256 from other initial values, cut to 28 bytes.
fn sha224_init() -> Sha256 {
    Sha256 {
        h: [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4],
        buf: [0; 64], used: 0, total: 0,
    }
}

fn sha224_final(s: Sha256&) -> u8[28] {
    let full = sha256_final(s);
    var out: u8[28] = [0; 28];
    for i in 28 { out[i] = full[i]; }
    return out;
}

fn sha224(data: const u8[:]) -> u8[28] {
    var s = sha224_init();
    sha256_update(s, data);
    return sha224_final(s);
}

fn sha256(data: const u8[:]) -> u8[32] {
    var s = sha256_init();
    sha256_update(s, data);
    return sha256_final(s);
}

// out ^= MGF1-SHA-256(seed), over out's whole length: the mask generation
// of OAEP and PSS.
fn mgf1_xor(out: u8[:], seed: const u8[:]) {
    var counter: u32 = 0;
    var off = 0;
    while off < out.len {
        var s = sha256_init();
        sha256_update(s, seed);
        let c: u8[4] = [(counter >> 24) as! u8, (counter >> 16) as! u8, (counter >> 8) as! u8, counter as! u8];
        sha256_update(s, c);
        let d = sha256_final(s);
        let n = ::min(32, out.len - off);
        for k in n { out[off + k] ^= d[k]; }
        off += n;
        counter++;
    }
}
