// bignum.gcm: AES-GCM (NIST SP 800-38D), the AEAD of TLS 1.3, constant
// time.
//
// GHASH multiplies in GF(2^128) without tables: carry-less products come
// from ordinary integer multiplies with the operands spread into 4-bit
// lanes ("holes"), as in BearSSL's ghash_ctmul64, so the time does not
// depend on the hash key or the data.

namespace bignum;

import std;
import ct;
import aes;

struct AesGcm { aes: Aes, h1: u64, h0: u64 }

// The low 64 bits of the carry-less product x * y. Each lane keeps every
// fourth bit, so the carries of a lane's sums land in the holes and are
// masked off; the only sum that would reach the next lane's bit falls
// past bit 63.
fn bmul64(x: u64, y: u64) -> u64 {
    let m0: u64 = 0x1111111111111111;
    let m1: u64 = 0x2222222222222222;
    let m2: u64 = 0x4444444444444444;
    let m3: u64 = 0x8888888888888888;
    let x0 = x & m0; let x1 = x & m1; let x2 = x & m2; let x3 = x & m3;
    let y0 = y & m0; let y1 = y & m1; let y2 = y & m2; let y3 = y & m3;
    let z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    let z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    let z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    let z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    return (z0 & m0) | (z1 & m1) | (z2 & m2) | (z3 & m3);
}

fn rev64(v: u64) -> u64 {
    var x = v;
    x = ((x & 0x5555555555555555) << 1) | ((x >> 1) & 0x5555555555555555);
    x = ((x & 0x3333333333333333) << 2) | ((x >> 2) & 0x3333333333333333);
    x = ((x & 0x0f0f0f0f0f0f0f0f) << 4) | ((x >> 4) & 0x0f0f0f0f0f0f0f0f);
    x = ((x & 0x00ff00ff00ff00ff) << 8) | ((x >> 8) & 0x00ff00ff00ff00ff);
    x = ((x & 0x0000ffff0000ffff) << 16) | ((x >> 16) & 0x0000ffff0000ffff);
    return (x << 32) | (x >> 32);
}

fn be64(p: const u8[:]) -> u64 {
    var r: u64 = 0;
    for i in 8 { r = (r << 8) | p[i]; }
    return r;
}

fn put_be64(p: u8[:], x: u64) {
    for i in 8 { p[i] = (x >> (56 - 8 * i)) as! u8; }
}

// y = (y ^ block) * h in GF(2^128), GCM's bit order. y1:y0 and h1:h0 are
// the blocks read big-endian; bit-reflected operands give the reflected
// product, which is shifted by one and then reduced by x^128 = x^7 + x^2 + x + 1.
fn ghash_mul(y1: u64&, y0: u64&, h1: u64, h0: u64) {
    let h0r = rev64(h0);
    let h1r = rev64(h1);
    let h2 = h0 ^ h1;
    let h2r = h0r ^ h1r;
    let a0 = y0;
    let a1 = y1;
    let a0r = rev64(a0);
    let a1r = rev64(a1);
    let a2 = a0 ^ a1;
    let a2r = a0r ^ a1r;
    // Karatsuba over the 64-bit halves; the high halves of each product
    // come from the bit-reversed operands.
    let z0 = bmul64(a0, h0);
    let z1 = bmul64(a1, h1);
    var z2 = bmul64(a2, h2);
    var z0h = bmul64(a0r, h0r);
    var z1h = bmul64(a1r, h1r);
    var z2h = bmul64(a2r, h2r);
    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;
    var v0 = z0;
    var v1 = z0h ^ z2;
    var v2 = z1 ^ z2h;
    var v3 = z1h;
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 = v0 << 1;
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    y0 = v2;
    y1 = v3;
}

// Folds data into the GHASH state, zero-padded to whole blocks.
fn ghash_update(y1: u64&, y0: u64&, h1: u64, h0: u64, data: const u8[:]) {
    var blk: u8[16] = [0; 16];
    var off = 0;
    while off < data.len {
        let n = ::min(16, data.len - off);
        for i in 16 { blk[i] = if i < n { data[off + i] } else { 0 }; }
        y1 ^= be64(blk[..8]);
        y0 ^= be64(blk[8..]);
        ghash_mul(y1, y0, h1, h0);
        off += n;
    }
}

fn gcm_init(key: const u8[:]) -> AesGcm {
    let a = aes_init(key);
    let zero: u8[16] = [0; 16];
    let h = aes_encrypt_block(a, zero);
    return AesGcm { aes: a, h1: be64(h[..8]), h0: be64(h[8..]) };
}

// The pre-counter block J0: the nonce with a 32-bit 1 for the usual 12
// bytes, else the GHASH of the nonce and its length.
fn gcm_j0(g: const AesGcm&, nonce: const u8[:]) -> u8[16] {
    var j0: u8[16] = [0; 16];
    if nonce.len == 12 {
        for i in 12 { j0[i] = nonce[i]; }
        j0[15] = 1;
        return j0;
    }
    var y1: u64 = 0;
    var y0: u64 = 0;
    ghash_update(y1, y0, g.h1, g.h0, nonce);
    y0 ^= (nonce.len as u64) * 8;
    ghash_mul(y1, y0, g.h1, g.h0);
    put_be64(j0[..8], y1);
    put_be64(j0[8..], y0);
    return j0;
}

// The tag over aad and ciphertext ct for pre-counter block j0.
fn gcm_tag(g: const AesGcm&, j0: const u8[:], aad: const u8[:], ct: const u8[:]) -> u8[16] {
    var y1: u64 = 0;
    var y0: u64 = 0;
    ghash_update(y1, y0, g.h1, g.h0, aad);
    ghash_update(y1, y0, g.h1, g.h0, ct);
    y1 ^= (aad.len as u64) * 8;
    y0 ^= (ct.len as u64) * 8;
    ghash_mul(y1, y0, g.h1, g.h0);
    var s: u8[16] = [0; 16];
    put_be64(s[..8], y1);
    put_be64(s[8..], y0);
    let ek = aes_encrypt_block(g.aes, j0);
    for i in 16 { s[i] ^= ek[i]; }
    return s;
}

// The largest GCM plaintext, (2^32 - 2) * 16 bytes (SP 800-38D §5.2.1.1):
// more and the 32-bit counter would come back to J0, whose block masks
// the tag, and then repeat.
let GCM_MAX: i64 = 68719476704;

// Whether a GCM message of n bytes is within GCM_MAX: what every entry
// point below checks.
fn gcm_fits(n: i64) -> bool { n >= 0 && n <= GCM_MAX }

// Encrypts data in place and returns the 16-byte tag. A nonce must never
// repeat under one key; 12 bytes is the standard size. Data longer than
// GCM_MAX aborts, as in Go.
fn gcm_encrypt(g: const AesGcm&, nonce: const u8[:], aad: const u8[:], data: u8[:]) -> u8[16] {
    assert(nonce.len > 0 && gcm_fits(data.len));
    let j0 = gcm_j0(g, nonce);
    var cb = j0;
    ctr_increment(cb, true);
    aes_ctr_xor(g.aes, cb, data, true);
    return gcm_tag(g, j0, aad, data);
}

// Checks the tag, then decrypts data in place; returns false, with data
// zeroed, when the tag does not match (a tag of another length never
// does) or data is longer than GCM_MAX. The comparison is constant time.
fn gcm_decrypt(g: const AesGcm&, nonce: const u8[:], aad: const u8[:], data: u8[:],
               tag: const u8[:]) -> bool {
    assert(nonce.len > 0);
    if !gcm_fits(data.len) {
        for &x in data { x = 0; }
        return false;
    }
    let j0 = gcm_j0(g, nonce);
    let want = gcm_tag(g, j0, aad, data);
    if tag.len != 16 || ct_eq_bytes(want, tag) == 0 {
        for &x in data { x = 0; }
        return false;
    }
    var cb = j0;
    ctr_increment(cb, true);
    aes_ctr_xor(g.aes, cb, data, true);
    return true;
}

// One-shot forms: ciphertext followed by the tag, and back.
fn aes_gcm_seal(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                plaintext: const u8[:]) -> u8[>..] {
    assert(gcm_fits(plaintext.len));
    let g = gcm_init(key);
    var out: u8[>..] = [];
    out.append(plaintext);
    let tag = gcm_encrypt(g, nonce, aad, out);
    out.append(tag);
    return out;
}

fn aes_gcm_open(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                sealed: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if sealed.len < 16 || !gcm_fits(sealed.len - 16) { return out, false; }
    let g = gcm_init(key);
    let n = sealed.len - 16;
    out.append(sealed[..n]);
    let ok = gcm_decrypt(g, nonce, aad, out, sealed[n..]);
    if !ok { out.clear(); }
    return out, ok;
}
