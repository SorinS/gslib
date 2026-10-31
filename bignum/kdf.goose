// bignum.kdf: password-based key derivation: PBKDF2 (RFC 8018 §5.2) over
// HMAC with any of bignum.hmac's hashes, and scrypt (RFC 7914), as Go's
// crypto/pbkdf2 and x/crypto/scrypt have them. For new password hashing,
// prefer Argon2id (bignum.argon2) or scrypt.
//
// scrypt reads its big table at positions that depend on the password,
// as the algorithm requires (and as every implementation does).

namespace bignum;

import std;
import hmac;
import sha256;
import sha512;
import sha1;
import sha3;
import md5;
import blake2;

// The hash states PBKDF2 runs, by type: absorb, and finish into out
// (hash_len bytes).
fn kdf_update(s: Sha256&, d: const u8[:]) { sha256_update(s, d); }
fn kdf_update(s: Sha512&, d: const u8[:]) { sha512_update(s, d); }
fn kdf_update(s: Sha1&, d: const u8[:]) { sha1_update(s, d); }
fn kdf_update(s: Md5&, d: const u8[:]) { md5_update(s, d); }
fn kdf_update(s: Keccak&, d: const u8[:]) { sha3_update(s, d); }
fn kdf_update(s: Blake2b&, d: const u8[:]) { blake2b_update(s, d); }
fn kdf_update(s: Blake2s&, d: const u8[:]) { blake2s_update(s, d); }

fn kdf_final(s: Sha256&, bits: i64, out: u8[:]) {
    if bits == 224 {
        let h = sha224_final(s);
        for i in 28 { out[i] = h[i]; }
    } else {
        let h = sha256_final(s);
        for i in 32 { out[i] = h[i]; }
    }
}
fn kdf_final(s: Sha512&, bits: i64, out: u8[:]) {
    let h = sha512_final(s);
    for i in h.len { out[i] = h[i]; }
}
fn kdf_final(s: Sha1&, bits: i64, out: u8[:]) {
    let h = sha1_final(s);
    for i in 20 { out[i] = h[i]; }
}
fn kdf_final(s: Md5&, bits: i64, out: u8[:]) {
    let h = md5_final(s);
    for i in 16 { out[i] = h[i]; }
}
fn kdf_final(s: Keccak&, bits: i64, out: u8[:]) {
    let h = sha3_final(s);
    for i in h.len { out[i] = h[i]; }
}
fn kdf_final(s: Blake2b&, bits: i64, out: u8[:]) {
    let h = blake2b_final(s);
    for i in h.len { out[i] = h[i]; }
}
fn kdf_final(s: Blake2s&, bits: i64, out: u8[:]) {
    let h = blake2s_final(s);
    for i in h.len { out[i] = h[i]; }
}

// PBKDF2 from a fresh state of the hash: HMAC's two keyed states are made
// once, and each iteration copies them rather than hashing the key again.
fn pbkdf2_with(s0, bits: i64, password: const u8[:], salt: const u8[:], iter: i64, len: i64) -> u8[>..] {
    let hl = hash_len(bits);
    let bl = hash_block(bits);
    var k: u8[144] = [0; 144];
    if password.len > bl {
        let hk = hash_bits(bits, password);
        for i in hk.len { k[i] = hk[i]; }
    } else {
        for i in password.len { k[i] = password[i]; }
    }
    var kpad: u8[144] = [0; 144];
    var inner = s0;
    for i in bl { kpad[i] = k[i] ^ 0x36; }
    kdf_update(inner, kpad[..bl]);
    var outer = s0;
    for i in bl { kpad[i] = k[i] ^ 0x5c; }
    kdf_update(outer, kpad[..bl]);
    var out: u8[>..] = [];
    var u: u8[64] = [0; 64];
    var t: u8[64] = [0; 64];
    var index: u32 = 1;
    while out.len < len {
        let be: u8[4] = [(index >> 24) as! u8, (index >> 16) as! u8, (index >> 8) as! u8, index as! u8];
        var s = inner;
        kdf_update(s, salt);
        kdf_update(s, be);
        kdf_final(s, bits, u);
        for it in iter {
            if it > 0 {
                s = inner;
                kdf_update(s, u[..hl]);
                kdf_final(s, bits, u);
            }
            s = outer;
            kdf_update(s, u[..hl]);
            kdf_final(s, bits, u);
            for i in hl { t[i] = if it == 0 { u[i] } else { t[i] ^ u[i] }; }
        }
        out.append(t[..::min(hl, len - out.len)]);
        index++;
    }
    return out;
}

// PBKDF2 with HMAC over the hash `bits` (a bignum.hmac id): len bytes from
// iter >= 1 iterations.
fn pbkdf2(bits: i64, password: const u8[:], salt: const u8[:], iter: i64, len: i64) -> u8[>..] {
    assert(iter >= 1 && len >= 0);
    if bits == 256 { return pbkdf2_with(sha256_init(), bits, password, salt, iter, len); }
    if bits == 224 { return pbkdf2_with(sha224_init(), bits, password, salt, iter, len); }
    if bits == 160 { return pbkdf2_with(sha1_init(), bits, password, salt, iter, len); }
    if bits == 128 { return pbkdf2_with(md5_init(), bits, password, salt, iter, len); }
    if bits > 3000 && bits < 4000 { return pbkdf2_with(sha3_init(bits - 3000), bits, password, salt, iter, len); }
    if is_blake2b(bits) { return pbkdf2_with(blake2b_init(hash_len(bits)), bits, password, salt, iter, len); }
    if bits == HASH_BLAKE2S_256 { return pbkdf2_with(blake2s_init(), bits, password, salt, iter, len); }
    let s0 = if bits == 384 { sha384_init() } else if bits == 512 { sha512_init() }
             else if bits == HASH_SHA512_224 { sha512_224_init() } else { sha512_256_init() };
    assert(bits == 384 || bits == 512 || bits == HASH_SHA512_224 || bits == HASH_SHA512_256);
    return pbkdf2_with(s0, bits, password, salt, iter, len);
}

fn rotl32_s(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

// b ^= x, then b = Salsa20/8(b) (RFC 7914 §3), on 16 words.
fn salsa8_xor(b: u32[:], x: const u32[:]) {
    var z: u32[16] = [0; 16];
    for i in 16 { b[i] ^= x[i]; z[i] = b[i]; }
    for r in 4 {
        z[4] ^= rotl32_s(z[0] + z[12], 7);   z[8] ^= rotl32_s(z[4] + z[0], 9);
        z[12] ^= rotl32_s(z[8] + z[4], 13);  z[0] ^= rotl32_s(z[12] + z[8], 18);
        z[9] ^= rotl32_s(z[5] + z[1], 7);    z[13] ^= rotl32_s(z[9] + z[5], 9);
        z[1] ^= rotl32_s(z[13] + z[9], 13);  z[5] ^= rotl32_s(z[1] + z[13], 18);
        z[14] ^= rotl32_s(z[10] + z[6], 7);  z[2] ^= rotl32_s(z[14] + z[10], 9);
        z[6] ^= rotl32_s(z[2] + z[14], 13);  z[10] ^= rotl32_s(z[6] + z[2], 18);
        z[3] ^= rotl32_s(z[15] + z[11], 7);  z[7] ^= rotl32_s(z[3] + z[15], 9);
        z[11] ^= rotl32_s(z[7] + z[3], 13);  z[15] ^= rotl32_s(z[11] + z[7], 18);
        z[1] ^= rotl32_s(z[0] + z[3], 7);    z[2] ^= rotl32_s(z[1] + z[0], 9);
        z[3] ^= rotl32_s(z[2] + z[1], 13);   z[0] ^= rotl32_s(z[3] + z[2], 18);
        z[6] ^= rotl32_s(z[5] + z[4], 7);    z[7] ^= rotl32_s(z[6] + z[5], 9);
        z[4] ^= rotl32_s(z[7] + z[6], 13);   z[5] ^= rotl32_s(z[4] + z[7], 18);
        z[11] ^= rotl32_s(z[10] + z[9], 7);  z[8] ^= rotl32_s(z[11] + z[10], 9);
        z[9] ^= rotl32_s(z[8] + z[11], 13);  z[10] ^= rotl32_s(z[9] + z[8], 18);
        z[12] ^= rotl32_s(z[15] + z[14], 7); z[13] ^= rotl32_s(z[12] + z[15], 9);
        z[14] ^= rotl32_s(z[13] + z[12], 13); z[15] ^= rotl32_s(z[14] + z[13], 18);
    }
    for i in 16 { b[i] += z[i]; }
}

// BlockMix (RFC 7914 §4) of the 32r words in b, into y.
fn scrypt_blockmix(b: const u32[:], y: u32[:], r: i64) {
    var x: u32[16] = [0; 16];
    for i in 16 { x[i] = b[(2 * r - 1) * 16 + i]; }
    for i in 2 * r {
        salsa8_xor(x, b[16 * i..16 * i + 16]);
        // Even blocks to the first half, odd ones to the second.
        let at = (i / 2 + (i % 2) * r) * 16;
        for k in 16 { y[at + k] = x[k]; }
    }
}

// ROMix (RFC 7914 §5) on one 128r-byte block, as little-endian words in
// x; v holds n of them and y is scratch of one.
fn scrypt_romix(x: u32[:], v: u32[:], y: u32[:], r: i64, n: i64) {
    let w = 32 * r;
    for i in n {
        for k in w { v[i * w + k] = x[k]; }
        scrypt_blockmix(x, y, r);
        for k in w { x[k] = y[k]; }
    }
    let mask: u32 = (n - 1) as! u32;
    for i in n {
        let j: i64 = x[(2 * r - 1) * 16] & mask;
        for k in w { x[k] ^= v[j * w + k]; }
        scrypt_blockmix(x, y, r);
        for k in w { x[k] = y[k]; }
    }
}

// scrypt: len bytes from the password and salt, with cost n (a power of
// two above 1), block size r and parallelism p. False, with nothing,
// when the parameters are out of range (n * r * 128 bytes of memory are
// needed, and r * p must stay below 2^30).
fn scrypt(password: const u8[:], salt: const u8[:], n: i64, r: i64, p: i64, len: i64) -> u8[>..], bool {
    var out: u8[>..] = [];
    if n <= 1 || (n & (n - 1)) != 0 || r < 1 || p < 1 || r * p >= 1 << 30 || len < 0 {
        return out, false;
    }
    if n > (1 << 40) / (128 * r) { return out, false; }      // a terabyte at most
    let w = 32 * r;
    var b = pbkdf2(HASH_SHA256, password, salt, 1, p * 128 * r);
    var x: u32[>..] = [];
    x.resize(w, 0);
    var y: u32[>..] = [];
    y.resize(w, 0);
    var v: u32[>..] = [];
    v.resize(n * w, 0);
    for i in p {
        let blk = b[i * 128 * r..(i + 1) * 128 * r];
        for k in w {
            x[k] = blk[4 * k] | (blk[4 * k + 1] as u32) << 8 | (blk[4 * k + 2] as u32) << 16 | (blk[4 * k + 3] as u32) << 24;
        }
        scrypt_romix(x, v, y, r, n);
        for k in w {
            for j in 4 { blk[4 * k + j] = (x[k] >> (8 * j)) as! u8; }
        }
    }
    out = pbkdf2(HASH_SHA256, password, b, 1, len);
    return out, true;
}
