// bignum.sha1: SHA-1 (FIPS 180-4). Broken for collision resistance, so
// only for what still needs it: old signatures, HMAC-SHA-1, key
// identifiers, protocols that name it. Streaming like bignum.sha256.

namespace bignum;

import std;

struct Sha1 { h: u32[5], buf: u8[64], used: i64, total: u64 }

fn rotl32_1(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn sha1_init() -> Sha1 {
    Sha1 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0], buf: [0; 64], used: 0, total: 0 }
}

fn sha1_block(s: Sha1&, p: const u8[:]) {
    var w: u32[80] = [0; 80];
    for i in 16 {
        let b0: u32 = p[4 * i];
        w[i] = b0 << 24 | (p[4 * i + 1] as u32) << 16 | (p[4 * i + 2] as u32) << 8 | p[4 * i + 3];
    }
    for i in 16..80 { w[i] = rotl32_1(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1); }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3]; var e = s.h[4];
    for i in 80 {
        var f: u32 = 0;
        var k: u32 = 0;
        if i < 20 { f = (b & c) | (~b & d); k = 0x5a827999; }
        else if i < 40 { f = b ^ c ^ d; k = 0x6ed9eba1; }
        else if i < 60 { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
        else { f = b ^ c ^ d; k = 0xca62c1d6; }
        let t = rotl32_1(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32_1(b, 30); b = a; a = t;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d; s.h[4] += e;
}

fn sha1_update(s: Sha1&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(64 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 64 { return; }
        let blk = s.buf;
        sha1_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 64 {
        sha1_block(s, data[i..i + 64]);
        i += 64;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

fn sha1_final(s: Sha1&) -> u8[20] {
    let bits = s.total * 8;
    var tail: u8[72] = [0; 72];
    tail[0] = 0x80;
    let padlen = if s.used < 56 { 56 - s.used } else { 120 - s.used };
    for k in 8 { tail[padlen + k] = (bits >> (56 - 8 * k)) as! u8; }
    sha1_update(s, tail[..padlen + 8]);
    var out: u8[20] = [0; 20];
    for i in 5 {
        for k in 4 { out[4 * i + k] = (s.h[i] >> (24 - 8 * k)) as! u8; }
    }
    return out;
}

fn sha1(data: const u8[:]) -> u8[20] {
    var s = sha1_init();
    sha1_update(s, data);
    return sha1_final(s);
}
