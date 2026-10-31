// bignum.md4: MD4 (RFC 1320), as Go's x/crypto/md4 has it. Broken
// outright, so only for formats that still carry it (NTLM, old rsync and
// ed2k checksums). Streaming like bignum.md5.

namespace bignum;

import std;

struct Md4 { h: u32[4], buf: u8[64], used: i64, total: u64 }

// The word order and shifts of rounds 2 and 3.
let MD4_X2: u8[16] = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
let MD4_X3: u8[16] = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
let MD4_S: u32[12] = [3, 7, 11, 19, 3, 5, 9, 13, 3, 9, 11, 15];

fn md4_init() -> Md4 {
    Md4 { h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], buf: [0; 64], used: 0, total: 0 }
}

fn md4_block(s: Md4&, p: const u8[:]) {
    var m: u32[16] = [0; 16];
    for i in 16 {
        let b0: u32 = p[4 * i];
        m[i] = b0 | (p[4 * i + 1] as u32) << 8 | (p[4 * i + 2] as u32) << 16 | (p[4 * i + 3] as u32) << 24;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3];
    for i in 48 {
        let round = i / 16;
        let j = i % 16;
        var f: u32 = 0;
        var x: u32 = 0;
        if round == 0 { f = (b & c) | (~b & d); x = m[j]; }
        else if round == 1 { f = (b & c) | (b & d) | (c & d); x = m[MD4_X2[j]] + 0x5a827999; }
        else { f = b ^ c ^ d; x = m[MD4_X3[j]] + 0x6ed9eba1; }
        let t = a + f + x;
        let r = MD4_S[4 * round + j % 4];
        a = d; d = c; c = b;
        b = (t << r) | (t >> (32 - r));
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
}

fn md4_update(s: Md4&, data: const u8[:]) {
    s.total += data.len as u64;
    var i = 0;
    if s.used > 0 {
        let n = ::min(64 - s.used, data.len);
        for k in n { s.buf[s.used + k] = data[k]; }
        s.used += n;
        i = n;
        if s.used < 64 { return; }
        let blk = s.buf;
        md4_block(s, blk);
        s.used = 0;
    }
    while data.len - i >= 64 {
        md4_block(s, data[i..i + 64]);
        i += 64;
    }
    for k in data.len - i { s.buf[k] = data[i + k]; }
    s.used = data.len - i;
}

fn md4_final(s: Md4&) -> u8[16] {
    let bits = s.total * 8;
    var tail: u8[72] = [0; 72];
    tail[0] = 0x80;
    let padlen = if s.used < 56 { 56 - s.used } else { 120 - s.used };
    for k in 8 { tail[padlen + k] = (bits >> (8 * k)) as! u8; }
    md4_update(s, tail[..padlen + 8]);
    var out: u8[16] = [0; 16];
    for i in 4 {
        for k in 4 { out[4 * i + k] = (s.h[i] >> (8 * k)) as! u8; }
    }
    return out;
}

fn md4(data: const u8[:]) -> u8[16] {
    var s = md4_init();
    md4_update(s, data);
    return md4_final(s);
}
