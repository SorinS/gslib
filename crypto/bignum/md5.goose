// bignum.md5: MD5 (RFC 1321). Broken for collisions, so only for what
// still needs it (old protocols and file formats, HMAC-MD5). Streaming
// like bignum.sha1.

namespace bignum;

import std;

struct Md5 { h: u32[4], buf: u8[64], used: i64, total: u64 }

// floor(|sin(i + 1)| * 2^32).
let MD5_K: u32[64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
];

let MD5_R: u32[16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];

fn md5_init() -> Md5 {
    Md5 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: [0; 64], used: 0, total: 0 }
}

fn md5_block(s: Md5&, p: const u8[:]) {
    var m: u32[16] = [0; 16];
    for i in 16 {
        let b0: u32 = p[4 * i];
        m[i] = b0 | (p[4 * i + 1] as u32) << 8 | (p[4 * i + 2] as u32) << 16 | (p[4 * i + 3] as u32) << 24;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3];
    for i in 64 {
        var f: u32 = 0;
        var g = 0;
        if i < 16 { f = (b & c) | (~b & d); g = i; }
        else if i < 32 { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
        else if i < 48 { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
        else { f = c ^ (b | ~d); g = (7 * i) % 16; }
        let t = a + f + MD5_K[i] + m[g];
        let r = MD5_R[4 * (i / 16) + i % 4];
        a = d; d = c; c = b;
        b = b + ((t << r) | (t >> (32 - r)));
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
}

fn md5_update(s: Md5&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(64 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 64 { return; }
        let blk = s.buf;
        md5_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 64 {
        md5_block(s, data[i..i + 64]);
        i += 64;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

fn md5_final(s: Md5&) -> u8[16] {
    let bits = s.total * 8;
    var tail: u8[72] = [0; 72];
    tail[0] = 0x80;
    let padlen = if s.used < 56 { 56 - s.used } else { 120 - s.used };
    for k in 8 { tail[padlen + k] = (bits >> (8 * k)) as! u8; }
    md5_update(s, tail[..padlen + 8]);
    var out: u8[16] = [0; 16];
    for i in 4 {
        for k in 4 { out[4 * i + k] = (s.h[i] >> (8 * k)) as! u8; }
    }
    return out;
}

fn md5(data: const u8[:]) -> u8[16] {
    var s = md5_init();
    md5_update(s, data);
    return md5_final(s);
}
