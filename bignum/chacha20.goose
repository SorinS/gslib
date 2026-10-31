// bignum.chacha20: ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD
// (RFC 8439), the TLS 1.3 alternative to AES-GCM for machines without AES
// instructions, and XChaCha20-Poly1305, its 24-byte-nonce form. Additions, rotations and xors only: constant time by
// construction. Poly1305 keeps its accumulator in five 26-bit limbs (as
// poly1305-donna-32) so products fit in a u64.

namespace bignum;

import std;
import ct;

fn rotl32(x: u32, n: u32) -> u32 { (x << n) | (x >> (32 - n)) }

fn le32_at(p: const u8[:], i: i64) -> u32 {
    let b0: u32 = p[i];
    b0 | (p[i + 1] as u32) << 8 | (p[i + 2] as u32) << 16 | (p[i + 3] as u32) << 24
}

fn quarter(x: u32[:], a: i64, b: i64, c: i64, d: i64) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
}

// One 64-byte keystream block (RFC 8439 §2.3): 32-byte key, block counter,
// 12-byte nonce.
fn chacha20_block(key: const u8[:], counter: u32, nonce: const u8[:]) -> u8[64] {
    assert(key.len == 32 && nonce.len == 12);
    var s: u32[16] = [0; 16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for i in 8 { s[4 + i] = le32_at(key, 4 * i); }
    s[12] = counter;
    for i in 3 { s[13 + i] = le32_at(nonce, 4 * i); }
    var x = s;
    for i in 10 {
        quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13);
        quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12);
        quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
    }
    var out: u8[64] = [0; 64];
    for i in 16 {
        let v = x[i] + s[i];
        for k in 4 { out[4 * i + k] = (v >> (8 * k)) as! u8; }
    }
    return out;
}

// Whether n bytes of keystream from block `counter` stay below 2^32
// blocks, so that the 32-bit counter never wraps (as Go's chacha20).
fn chacha20_fits(counter: u32, n: i64) -> bool {
    if n < 0 { return false; }
    let blocks = n / 64 + (if n % 64 != 0 { 1 } else { 0 });
    return blocks <= 4294967296 - (counter as i64);
}

// The largest ChaCha20-Poly1305 plaintext, (2^32 - 1) * 64 bytes (RFC
// 8439 §2.8): block 0 makes the Poly1305 key, the data starts at block 1.
let CHACHA20_POLY1305_MAX: i64 = 274877906880;

// data ^= the keystream starting at block `counter` (RFC 8439 §2.4).
// Aborts, before touching data, if the counter would wrap.
fn chacha20_xor(key: const u8[:], counter: u32, nonce: const u8[:], data: u8[:]) {
    assert(chacha20_fits(counter, data.len));
    var ctr = counter;
    var off = 0;
    while off < data.len {
        let ks = chacha20_block(key, ctr, nonce);
        let n = ::min(64, data.len - off);
        for i in n { data[off + i] ^= ks[i]; }
        off += n;
        ctr++;
    }
}

struct Poly1305 { r: u32[5], h: u32[5], s: u32[4], buf: u8[16], used: i64 }

fn poly1305_init(key: const u8[:]) -> Poly1305 {
    assert(key.len == 32);
    var st = Poly1305 { r: [0; 5], h: [0; 5], s: [0; 4], buf: [0; 16], used: 0 };
    // r is clamped (RFC 8439 §2.5) as it is split into limbs.
    st.r[0] = le32_at(key, 0) & 0x3ffffff;
    st.r[1] = (le32_at(key, 3) >> 2) & 0x3ffff03;
    st.r[2] = (le32_at(key, 6) >> 4) & 0x3ffc0ff;
    st.r[3] = (le32_at(key, 9) >> 6) & 0x3f03fff;
    st.r[4] = (le32_at(key, 12) >> 8) & 0x00fffff;
    for i in 4 { st.s[i] = le32_at(key, 16 + 4 * i); }
    return st;
}

// h = (h + m + hibit * 2^128) * r mod 2^130 - 5, for one 16-byte block.
fn poly1305_block(st: Poly1305&, m: const u8[:], hibit: u32) {
    let mask: u32 = 0x3ffffff;
    let r0: u64 = st.r[0]; let r1: u64 = st.r[1]; let r2: u64 = st.r[2];
    let r3: u64 = st.r[3]; let r4: u64 = st.r[4];
    let s1 = r1 * 5; let s2 = r2 * 5; let s3 = r3 * 5; let s4 = r4 * 5;
    let h0: u64 = st.h[0] + (le32_at(m, 0) & mask);
    let h1: u64 = st.h[1] + ((le32_at(m, 3) >> 2) & mask);
    let h2: u64 = st.h[2] + ((le32_at(m, 6) >> 4) & mask);
    let h3: u64 = st.h[3] + ((le32_at(m, 9) >> 6) & mask);
    let h4: u64 = st.h[4] + ((le32_at(m, 12) >> 8) | hibit);
    let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
    var d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
    var d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
    var d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
    var d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
    d1 += d0 >> 26;
    d2 += d1 >> 26;
    d3 += d2 >> 26;
    d4 += d3 >> 26;
    var n0 = (d0 & 0x3ffffff) + (d4 >> 26) * 5;
    let n1 = (d1 & 0x3ffffff) + (n0 >> 26);
    n0 = n0 & 0x3ffffff;
    st.h[0] = n0 as! u32;
    st.h[1] = n1 as! u32;
    st.h[2] = (d2 & 0x3ffffff) as! u32;
    st.h[3] = (d3 & 0x3ffffff) as! u32;
    st.h[4] = (d4 & 0x3ffffff) as! u32;
}

fn poly1305_update(st: Poly1305&, data: const u8[:]) {
    var i = 0;
    if st.used > 0 {
        let n = ::min(16 - st.used, data.len);
        for k in n { st.buf[st.used + k] = data[k]; }
        st.used += n;
        i = n;
        if st.used < 16 { return; }
        let blk = st.buf;
        poly1305_block(st, blk, 1 << 24);
        st.used = 0;
    }
    while data.len - i >= 16 {
        poly1305_block(st, data[i..i + 16], 1 << 24);
        i += 16;
    }
    for k in data.len - i { st.buf[k] = data[i + k]; }
    st.used = data.len - i;
}

fn poly1305_final(st: Poly1305&) -> u8[16] {
    if st.used > 0 {
        // The last partial block gets a 1 byte after it, and no 2^128.
        var last: u8[16] = [0; 16];
        for k in st.used { last[k] = st.buf[k]; }
        last[st.used] = 1;
        poly1305_block(st, last, 0);
    }
    let mask: u32 = 0x3ffffff;
    var h0 = st.h[0]; var h1 = st.h[1]; var h2 = st.h[2]; var h3 = st.h[3]; var h4 = st.h[4];
    var c = h1 >> 26; h1 &= mask;
    h2 += c; c = h2 >> 26; h2 &= mask;
    h3 += c; c = h3 >> 26; h3 &= mask;
    h4 += c; c = h4 >> 26; h4 &= mask;
    h0 += c * 5; c = h0 >> 26; h0 &= mask;
    h1 += c;
    // g = h + 5 - 2^130; keep it when it did not go negative (h >= p).
    var g0 = h0 + 5; c = g0 >> 26; g0 &= mask;
    var g1 = h1 + c; c = g1 >> 26; g1 &= mask;
    var g2 = h2 + c; c = g2 >> 26; g2 &= mask;
    var g3 = h3 + c; c = g3 >> 26; g3 &= mask;
    let g4 = h4 + c - (1 << 26);
    let keep_g = (g4 >> 31) - 1;
    h0 = ct_select_u32(keep_g, g0, h0);
    h1 = ct_select_u32(keep_g, g1, h1);
    h2 = ct_select_u32(keep_g, g2, h2);
    h3 = ct_select_u32(keep_g, g3, h3);
    h4 = ct_select_u32(keep_g, g4 & mask, h4);
    // To 128 bits, plus s.
    let w0: u64 = h0 | (h1 << 26);
    let w1: u64 = (h1 >> 6) | (h2 << 20);
    let w2: u64 = (h2 >> 12) | (h3 << 14);
    let w3: u64 = (h3 >> 18) | (h4 << 8);
    var out: u8[16] = [0; 16];
    var f: u64 = 0;
    let ws: u64[4] = [w0 & 0xffffffff, w1 & 0xffffffff, w2 & 0xffffffff, w3 & 0xffffffff];
    for i in 4 {
        f = ws[i] + st.s[i] + (f >> 32);
        for k in 4 { out[4 * i + k] = (f >> (8 * k)) as! u8; }
    }
    return out;
}

// The one-shot MAC; a key must authenticate only one message.
fn poly1305(key: const u8[:], msg: const u8[:]) -> u8[16] {
    var st = poly1305_init(key);
    poly1305_update(st, msg);
    return poly1305_final(st);
}

fn aead_mac(otk: const u8[:], aad: const u8[:], ct: const u8[:]) -> u8[16] {
    var st = poly1305_init(otk);
    let zeros: u8[16] = [0; 16];
    poly1305_update(st, aad);
    poly1305_update(st, zeros[..(16 - aad.len % 16) % 16]);
    poly1305_update(st, ct);
    poly1305_update(st, zeros[..(16 - ct.len % 16) % 16]);
    var lens: u8[16] = [0; 16];
    for k in 8 {
        lens[k] = (aad.len >> (8 * k)) as! u8;
        lens[8 + k] = (ct.len >> (8 * k)) as! u8;
    }
    poly1305_update(st, lens);
    return poly1305_final(st);
}

// ChaCha20-Poly1305 (RFC 8439 §2.8): encrypts data in place, returns the
// tag. 32-byte key, 12-byte nonce that must never repeat under the key.
// Data longer than CHACHA20_POLY1305_MAX aborts, as in Go.
fn chacha20_poly1305_encrypt(key: const u8[:], nonce: const u8[:], aad: const u8[:], data: u8[:]) -> u8[16] {
    assert(data.len <= CHACHA20_POLY1305_MAX);
    let otk = chacha20_block(key, 0, nonce);
    chacha20_xor(key, 1, nonce, data);
    return aead_mac(otk[..32], aad, data);
}

// Checks the tag in constant time, then decrypts in place; false, with
// data zeroed, on a mismatch (a tag of another length never matches) or
// for data longer than CHACHA20_POLY1305_MAX.
fn chacha20_poly1305_decrypt(key: const u8[:], nonce: const u8[:], aad: const u8[:], data: u8[:],
                             tag: const u8[:]) -> bool {
    if data.len > CHACHA20_POLY1305_MAX {
        for &x in data { x = 0; }
        return false;
    }
    let otk = chacha20_block(key, 0, nonce);
    let want = aead_mac(otk[..32], aad, data);
    if tag.len != 16 || ct_eq_bytes(want, tag) == 0 {
        for &x in data { x = 0; }
        return false;
    }
    chacha20_xor(key, 1, nonce, data);
    return true;
}

// One-shot forms: ciphertext followed by the tag, and back.
fn chacha20_poly1305_seal(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                          plaintext: const u8[:]) -> u8[>..] {
    assert(plaintext.len <= CHACHA20_POLY1305_MAX);
    var out: u8[>..] = [];
    out.append(plaintext);
    let tag = chacha20_poly1305_encrypt(key, nonce, aad, out);
    out.append(tag);
    return out;
}

fn chacha20_poly1305_open(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                          sealed: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if sealed.len < 16 || sealed.len - 16 > CHACHA20_POLY1305_MAX { return out, false; }
    let n = sealed.len - 16;
    out.append(sealed[..n]);
    let ok = chacha20_poly1305_decrypt(key, nonce, aad, out, sealed[n..]);
    if !ok { out.clear(); }
    return out, ok;
}

// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): a 32-byte subkey from the key
// and a 16-byte nonce: the ChaCha20 rounds without the final addition,
// words 0-3 and 12-15.
fn hchacha20(key: const u8[:], nonce: const u8[:]) -> u8[32] {
    assert(key.len == 32 && nonce.len == 16);
    var x: u32[16] = [0; 16];
    x[0] = 0x61707865; x[1] = 0x3320646e; x[2] = 0x79622d32; x[3] = 0x6b206574;
    for i in 8 { x[4 + i] = le32_at(key, 4 * i); }
    for i in 4 { x[12 + i] = le32_at(nonce, 4 * i); }
    for i in 10 {
        quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13);
        quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
        quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12);
        quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
    }
    var out: u8[32] = [0; 32];
    for i in 4 {
        for k in 4 {
            out[4 * i + k] = (x[i] >> (8 * k)) as! u8;
            out[16 + 4 * i + k] = (x[12 + i] >> (8 * k)) as! u8;
        }
    }
    return out;
}

// XChaCha20's subkey and 12-byte nonce for a 24-byte nonce.
fn xchacha_keys(key: const u8[:], nonce: const u8[:]) -> u8[32], u8[12] {
    assert(nonce.len == 24);
    let sub = hchacha20(key, nonce[..16]);
    var n12: u8[12] = [0; 12];
    for i in 8 { n12[4 + i] = nonce[16 + i]; }
    return sub, n12;
}

// XChaCha20: ChaCha20 with a 24-byte nonce, long enough to choose at
// random.
fn xchacha20_xor(key: const u8[:], counter: u32, nonce: const u8[:], data: u8[:]) {
    let sub, n12 = xchacha_keys(key, nonce);
    chacha20_xor(sub, counter, n12, data);
}

// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha §2.3, Go's
// chacha20poly1305.NewX): ChaCha20-Poly1305 under the HChaCha20 subkey.
fn xchacha20_poly1305_encrypt(key: const u8[:], nonce: const u8[:], aad: const u8[:], data: u8[:]) -> u8[16] {
    let sub, n12 = xchacha_keys(key, nonce);
    return chacha20_poly1305_encrypt(sub, n12, aad, data);
}

fn xchacha20_poly1305_decrypt(key: const u8[:], nonce: const u8[:], aad: const u8[:], data: u8[:],
                              tag: const u8[:]) -> bool {
    let sub, n12 = xchacha_keys(key, nonce);
    return chacha20_poly1305_decrypt(sub, n12, aad, data, tag);
}

fn xchacha20_poly1305_seal(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                           plaintext: const u8[:]) -> u8[>..] {
    let sub, n12 = xchacha_keys(key, nonce);
    return chacha20_poly1305_seal(sub, n12, aad, plaintext);
}

fn xchacha20_poly1305_open(key: const u8[:], nonce: const u8[:], aad: const u8[:],
                           sealed: const u8[:]) -> u8[>..], bool {
    let sub, n12 = xchacha_keys(key, nonce);
    return chacha20_poly1305_open(sub, n12, aad, sealed);
}
