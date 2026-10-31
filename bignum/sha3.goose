// bignum.sha3: SHA-3 and SHAKE (FIPS 202) and cSHAKE (SP 800-185), on
// Keccak-f[1600]. sha3_init(bits) for SHA3-224/256/384/512,
// shake_init(128 or 256) or cshake_init for the extendable-output
// functions; sha3_update any number of times, then sha3_final for a
// digest or shake_read as often as needed. Constant time by construction.

namespace bignum;

import std;

// The rate in bytes, the domain padding byte (0x06 for SHA-3, 0x1f for
// SHAKE), the output length (0 for SHAKE), and where absorbing or
// squeezing stands in the block.
struct Keccak { a: u64[25], rate: i64, dsbyte: u8, outlen: i64, pos: i64, squeezing: bool }

let KECCAK_RC: u64[24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
];

// The rotation of lane x + 5y.
let KECCAK_RHO: u32[25] = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];

fn rotl64(x: u64, n: u32) -> u64 { if n == 0 { x } else { (x << n) | (x >> (64 - n)) } }

fn keccak_f(a: u64[:]) {
    var c: u64[5] = [0; 5];
    var b: u64[25] = [0; 25];
    for round in 24 {
        // theta
        for x in 5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]; }
        for x in 5 {
            let d = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
            for y in 5 { a[x + 5 * y] ^= d; }
        }
        // rho and pi: B[y, 2x + 3y] = rot(A[x, y])
        for x in 5 {
            for y in 5 { b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(a[x + 5 * y], KECCAK_RHO[x + 5 * y]); }
        }
        // chi
        for y in 5 {
            for x in 5 { a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]); }
        }
        // iota
        a[0] ^= KECCAK_RC[round];
    }
}

fn sha3_init(bits: i64) -> Keccak {
    assert(bits == 224 || bits == 256 || bits == 384 || bits == 512);
    Keccak { a: [0; 25], rate: 200 - 2 * (bits / 8), dsbyte: 0x06, outlen: bits / 8, pos: 0, squeezing: false }
}

fn shake_init(bits: i64) -> Keccak {
    assert(bits == 128 || bits == 256);
    Keccak { a: [0; 25], rate: 200 - bits / 4, dsbyte: 0x1f, outlen: 0, pos: 0, squeezing: false }
}

fn xor_byte(s: Keccak&, i: i64, v: u8) {
    let lane: u64 = v;
    s.a[i / 8] ^= lane << (8 * (i % 8));
}

fn sha3_update(s: Keccak&, data: const u8[:]) {
    assert(!s.squeezing);
    for b in data {
        xor_byte(s, s.pos, b);
        s.pos++;
        if s.pos == s.rate {
            keccak_f(s.a);
            s.pos = 0;
        }
    }
}

fn keccak_pad(s: Keccak&) {
    xor_byte(s, s.pos, s.dsbyte);
    xor_byte(s, s.rate - 1, 0x80);
    keccak_f(s.a);
    s.pos = 0;
    s.squeezing = true;
}

// The next out.len bytes of a SHAKE stream.
fn shake_read(s: Keccak&, out: u8[:]) {
    if !s.squeezing { keccak_pad(s); }
    for i in out.len {
        if s.pos == s.rate {
            keccak_f(s.a);
            s.pos = 0;
        }
        out[i] = (s.a[s.pos / 8] >> (8 * (s.pos % 8))) as! u8;
        s.pos++;
    }
}

fn sha3_final(s: Keccak&) -> u8[>..] {
    assert(s.outlen > 0);
    var out: u8[>..] = [];
    out.resize(s.outlen, 0);
    shake_read(s, out);
    return out;
}

fn sha3(bits: i64, data: const u8[:]) -> u8[>..] {
    var s = sha3_init(bits);
    sha3_update(s, data);
    return sha3_final(s);
}

fn shake(bits: i64, data: const u8[:], n: i64) -> u8[>..] {
    var s = shake_init(bits);
    sha3_update(s, data);
    var out: u8[>..] = [];
    out.resize(n, 0);
    shake_read(s, out);
    return out;
}

// left_encode (SP 800-185 §2.3.1): x in as few big-endian bytes as it
// takes (at least one), after their count.
fn left_encode(out: u8[>..]&, x: u64) {
    var n = 1;
    while n < 8 && (x >> (8 * n)) != 0 { n++; }
    out.push(n as! u8);
    var i = n;
    while i > 0 {
        i--;
        out.push((x >> (8 * i)) as! u8);
    }
}

// cSHAKE128 or cSHAKE256 (SP 800-185 §3), as Go's sha3.NewCSHAKE128 and
// NewCSHAKE256: SHAKE separated by a function name and a customization
// string. With both empty it is SHAKE itself. Absorb with sha3_update and
// read with shake_read.
fn cshake_init(bits: i64, name: const u8[:], custom: const u8[:]) -> Keccak {
    var s = shake_init(bits);
    if name.len == 0 && custom.len == 0 { return s; }
    s.dsbyte = 0x04;
    var pre: u8[>..] = [];
    left_encode(pre, s.rate as! u64);
    left_encode(pre, 8 * name.len as! u64);
    pre.append(name);
    left_encode(pre, 8 * custom.len as! u64);
    pre.append(custom);
    while pre.len % s.rate != 0 { pre.push(0); }
    sha3_update(s, pre);
    return s;
}

fn cshake(bits: i64, name: const u8[:], custom: const u8[:], data: const u8[:], n: i64) -> u8[>..] {
    var s = cshake_init(bits, name, custom);
    sha3_update(s, data);
    var out: u8[>..] = [];
    out.resize(n, 0);
    shake_read(s, out);
    return out;
}
