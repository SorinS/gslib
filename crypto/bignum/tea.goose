// bignum.tea: TEA and XTEA (Needham and Wheeler), with 16-byte keys and
// 64-bit blocks, as Go's x/crypto/tea and x/crypto/xtea have them. TEA
// takes an even round count (64 by default); XTEA runs 64 rounds. Legacy
// use only: related-key and short-block weaknesses.

namespace bignum;

import std;

let TEA_DELTA: u32 = 0x9e3779b9;

struct Tea { k: u32[4], rounds: i64 }
struct Xtea { table: u32[64] }

fn tea_be32(b: const u8[:], i: i64) -> u32 {
    let b0: u32 = b[i];
    return b0 << 24 | (b[i + 1] as u32) << 16 | (b[i + 2] as u32) << 8 | b[i + 3];
}

fn tea_put(v0: u32, v1: u32) -> u8[8] {
    var out: u8[8] = [0; 8];
    for k in 4 { out[k] = (v0 >> (24 - 8 * k)) as! u8; out[4 + k] = (v1 >> (24 - 8 * k)) as! u8; }
    return out;
}

fn tea_init(key: const u8[:], rounds: i64 = 64) -> Tea {
    assert(key.len == 16 && rounds > 0 && rounds % 2 == 0);
    var t = Tea { k: [0; 4], rounds: rounds };
    for i in 4 { t.k[i] = tea_be32(key, 4 * i); }
    return t;
}

fn tea_encrypt_block(t: const Tea&, b: const u8[:]) -> u8[8] {
    var v0 = tea_be32(b, 0);
    var v1 = tea_be32(b, 4);
    var sum: u32 = 0;
    for i in t.rounds / 2 {
        sum += TEA_DELTA;
        v0 += ((v1 << 4) + t.k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + t.k[1]);
        v1 += ((v0 << 4) + t.k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + t.k[3]);
    }
    return tea_put(v0, v1);
}

fn tea_decrypt_block(t: const Tea&, b: const u8[:]) -> u8[8] {
    var v0 = tea_be32(b, 0);
    var v1 = tea_be32(b, 4);
    var sum: u32 = TEA_DELTA * (t.rounds / 2) as! u32;
    for i in t.rounds / 2 {
        v1 -= ((v0 << 4) + t.k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + t.k[3]);
        v0 -= ((v1 << 4) + t.k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + t.k[1]);
        sum -= TEA_DELTA;
    }
    return tea_put(v0, v1);
}

// XTEA's round keys: sum + k[sum & 3] and, after the step, sum +
// k[(sum >> 11) & 3].
fn xtea_init(key: const u8[:]) -> Xtea {
    assert(key.len == 16);
    var k: u32[4] = [0; 4];
    for i in 4 { k[i] = tea_be32(key, 4 * i); }
    var x = Xtea { table: [0; 64] };
    var sum: u32 = 0;
    var i = 0;
    while i < 64 {
        x.table[i] = sum + k[sum & 3];
        sum += TEA_DELTA;
        x.table[i + 1] = sum + k[(sum >> 11) & 3];
        i += 2;
    }
    return x;
}

fn xtea_encrypt_block(x: const Xtea&, b: const u8[:]) -> u8[8] {
    var v0 = tea_be32(b, 0);
    var v1 = tea_be32(b, 4);
    var i = 0;
    while i < 64 {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ x.table[i];
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ x.table[i + 1];
        i += 2;
    }
    return tea_put(v0, v1);
}

fn xtea_decrypt_block(x: const Xtea&, b: const u8[:]) -> u8[8] {
    var v0 = tea_be32(b, 0);
    var v1 = tea_be32(b, 4);
    var i = 64;
    while i > 0 {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ x.table[i - 1];
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ x.table[i - 2];
        i -= 2;
    }
    return tea_put(v0, v1);
}

// For bignum.modes.
fn cipher_block_len(k: const Tea&) -> i64 { 8 }
fn cipher_encrypt(k: const Tea&, b: const u8[:]) -> u8[8] { tea_encrypt_block(k, b) }
fn cipher_decrypt(k: const Tea&, b: const u8[:]) -> u8[8] { tea_decrypt_block(k, b) }
fn cipher_block_len(k: const Xtea&) -> i64 { 8 }
fn cipher_encrypt(k: const Xtea&, b: const u8[:]) -> u8[8] { xtea_encrypt_block(k, b) }
fn cipher_decrypt(k: const Xtea&, b: const u8[:]) -> u8[8] { xtea_decrypt_block(k, b) }
