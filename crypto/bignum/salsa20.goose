// bignum.salsa20: Salsa20/20 and XSalsa20 (Bernstein), with HSalsa20, as
// Go's x/crypto/salsa20 has them: an 8-byte nonce gives Salsa20, a
// 24-byte one XSalsa20. The keystream XORs in place and starts at block 0.

namespace bignum;

import std;

fn salsa_rotl(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn salsa_le32(p: const u8[:], i: i64) -> u32 {
    let b0: u32 = p[i];
    return b0 | (p[i + 1] as u32) << 8 | (p[i + 2] as u32) << 16 | (p[i + 3] as u32) << 24;
}

fn salsa_quarter(x: u32[:], a: i64, b: i64, c: i64, d: i64) {
    x[b] ^= salsa_rotl(x[a] + x[d], 7);
    x[c] ^= salsa_rotl(x[b] + x[a], 9);
    x[d] ^= salsa_rotl(x[c] + x[b], 13);
    x[a] ^= salsa_rotl(x[d] + x[c], 18);
}

// 20 rounds: ten column-and-row double rounds.
fn salsa_rounds(x: u32[:]) {
    for i in 10 {
        salsa_quarter(x, 0, 4, 8, 12);
        salsa_quarter(x, 5, 9, 13, 1);
        salsa_quarter(x, 10, 14, 2, 6);
        salsa_quarter(x, 15, 3, 7, 11);
        salsa_quarter(x, 0, 1, 2, 3);
        salsa_quarter(x, 5, 6, 7, 4);
        salsa_quarter(x, 10, 11, 8, 9);
        salsa_quarter(x, 15, 12, 13, 14);
    }
}

// The input words: "expand 32-byte k", the key, and 16 bytes of input
// (nonce and counter, or HSalsa20's 16 bytes).
fn salsa_state(key: const u8[:], input: const u8[:]) -> u32[16] {
    var x: u32[16] = [0; 16];
    x[0] = 0x61707865; x[5] = 0x3320646e; x[10] = 0x79622d32; x[15] = 0x6b206574;
    for i in 4 {
        x[1 + i] = salsa_le32(key, 4 * i);
        x[11 + i] = salsa_le32(key, 16 + 4 * i);
        x[6 + i] = salsa_le32(input, 4 * i);
    }
    return x;
}

// HSalsa20: a 32-byte subkey from a key and 16 bytes.
fn hsalsa20(key: const u8[:], input: const u8[:]) -> u8[32] {
    assert(key.len == 32 && input.len == 16);
    var x = salsa_state(key, input);
    salsa_rounds(x);
    let idx: i64[8] = [0, 5, 10, 15, 6, 7, 8, 9];
    var out: u8[32] = [0; 32];
    for i in 8 {
        for k in 4 { out[4 * i + k] = (x[idx[i]] >> (8 * k)) as! u8; }
    }
    return out;
}

// One 64-byte Salsa20 block of an 8-byte nonce at a counter.
fn salsa20_block(key: const u8[:], nonce: const u8[:], counter: u64) -> u8[64] {
    var input: u8[16] = [0; 16];
    for i in 8 { input[i] = nonce[i]; input[8 + i] = (counter >> (8 * i)) as! u8; }
    let s = salsa_state(key, input);
    var x = s;
    salsa_rounds(x);
    var out: u8[64] = [0; 64];
    for i in 16 {
        let v = x[i] + s[i];
        for k in 4 { out[4 * i + k] = (v >> (8 * k)) as! u8; }
    }
    return out;
}

// XORs the Salsa20 keystream from block `counter` into data.
fn salsa20_xor_at(key: const u8[:], nonce: const u8[:], counter: u64, data: u8[:]) {
    assert(key.len == 32 && nonce.len == 8);
    var ctr = counter;
    var off = 0;
    while off < data.len {
        let ks = salsa20_block(key, nonce, ctr);
        let n = ::min(64, data.len - off);
        for i in n { data[off + i] ^= ks[i]; }
        off += n;
        ctr++;
    }
}

// Salsa20 for an 8-byte nonce, XSalsa20 for a 24-byte one, in place.
fn salsa20_xor(key: const u8[:], nonce: const u8[:], data: u8[:]) {
    assert(key.len == 32 && (nonce.len == 8 || nonce.len == 24));
    if nonce.len == 8 { salsa20_xor_at(key, nonce, 0, data); return; }
    let sub = hsalsa20(key, nonce[..16]);
    salsa20_xor_at(sub, nonce[16..], 0, data);
}
