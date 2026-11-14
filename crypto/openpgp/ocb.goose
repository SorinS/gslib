// openpgp.ocb: OCB (RFC 7253) over AES with 128-bit tags, for the AEAD
// encrypted data that gpg writes (LibrePGP's OCB Encrypted Data packet)
// and RFC 9580's SEIPD v2. bignum has no OCB; this is the RFC's algorithm
// as written, checked against its Appendix A vectors.
//
//   let o = openpgp::ocb_init(key);                       // 16, 24 or 32 bytes
//   let tag = openpgp::ocb_encrypt(o, nonce, ad, data);   // data in place; nonce 1-15 bytes
//   let ok = openpgp::ocb_decrypt(o, nonce, ad, data, tag);

namespace openpgp;

import std;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.ct;

// The key schedule and the L values: L_* , L_$ and L_0 .. L_39 (enough for
// 2^40 blocks in one message).
struct Ocb { aes: bignum::Aes, lstar: u8[16], ldollar: u8[16], l: u8[640] }

fn ocb_double(s: const u8[:]) -> u8[16] {
    var r: u8[16] = [0; 16];
    for i in 15 { r[i] = (s[i] << 1) | (s[i + 1] >> 7); }
    r[15] = (s[15] << 1) ^ (if s[0] & 0x80 != 0 { 0x87 } else { 0 });
    return r;
}

fn ocb_init(key: const u8[:]) -> Ocb {
    assert(key.len == 16 || key.len == 24 || key.len == 32);
    var o = Ocb { aes: bignum::aes_init(key), lstar: [0; 16], ldollar: [0; 16], l: [0; 640] };
    let z: u8[16] = [0; 16];
    o.lstar = bignum::aes_encrypt_block(o.aes, z);
    o.ldollar = ocb_double(o.lstar);
    var prev = ocb_double(o.ldollar);
    for i in 40 {
        for j in 16 { o.l[16 * i + j] = prev[j]; }
        prev = ocb_double(prev);
    }
    return o;
}

fn ocb_xor_l(o: const Ocb&, x: u8[:], i: i64) {
    let k = ::ctz(i as u64);
    for j in 16 { x[j] ^= o.l[16 * k + j]; }
}

// HASH(K, A).
fn ocb_hash(o: const Ocb&, a: const u8[:]) -> u8[16] {
    var sum: u8[16] = [0; 16];
    var off: u8[16] = [0; 16];
    var t:   u8[16] = [0; 16];
    let m = a.len / 16;
    for i in m {
        ocb_xor_l(o, off, i + 1);
        for j in 16 { t[j] = a[16 * i + j] ^ off[j]; }
        let e = bignum::aes_encrypt_block(o.aes, t);
        for j in 16 { sum[j] ^= e[j]; }
    }
    let rest = a.len - 16 * m;
    if rest > 0 {
        for j in 16 { off[j] ^= o.lstar[j]; t[j] = 0; }
        for j in rest { t[j] = a[16 * m + j]; }
        t[rest] = 0x80;
        for j in 16 { t[j] ^= off[j]; }
        let e = bignum::aes_encrypt_block(o.aes, t);
        for j in 16 { sum[j] ^= e[j]; }
    }
    return sum;
}

// Offset_0 for a nonce of 1 to 15 bytes, with TAGLEN 128.
fn ocb_offset0(o: const Ocb&, nonce: const u8[:]) -> u8[16] {
    var n: u8[16] = [0; 16];
    for i in nonce.len { n[16 - nonce.len + i] = nonce[i]; }
    n[15 - nonce.len] |= 1;
    let bottom: i64 = n[15] & 63;
    n[15] &= 0xC0;
    let ktop = bignum::aes_encrypt_block(o.aes, n);
    var st: u8[25] = [0; 25];
    for i in 16 { st[i] = ktop[i]; }
    for i in 8 { st[16 + i] = ktop[i] ^ ktop[i + 1]; }
    let bs = bottom / 8;
    let sh = (bottom % 8) as u8;
    var off: u8[16] = [0; 16];
    for i in 16 {
        off[i] = if sh == 0 { st[i + bs] } else { (st[i + bs] << sh) | (st[i + bs + 1] >> (8 - sh)) };
    }
    return off;
}

fn ocb_crypt(o: const Ocb&, nonce: const u8[:], ad: const u8[:], data: u8[:], decrypt: bool) -> u8[16] {
    assert(nonce.len >= 1 && nonce.len <= 15);
    var off = ocb_offset0(o, nonce);
    var sum: u8[16] = [0; 16];
    var t:   u8[16] = [0; 16];
    let m = data.len / 16;
    for i in m {
        ocb_xor_l(o, off, i + 1);
        let b = 16 * i;
        for j in 16 { t[j] = data[b + j] ^ off[j]; }
        if !decrypt { for j in 16 { sum[j] ^= data[b + j]; } }
        let e = if decrypt { bignum::aes_decrypt_block(o.aes, t) } else { bignum::aes_encrypt_block(o.aes, t) };
        for j in 16 { data[b + j] = e[j] ^ off[j]; }
        if decrypt { for j in 16 { sum[j] ^= data[b + j]; } }
    }
    let rest = data.len - 16 * m;
    if rest > 0 {
        for j in 16 { off[j] ^= o.lstar[j]; }
        let ks = bignum::aes_encrypt_block(o.aes, off);
        let b = 16 * m;
        for j in 16 { t[j] = 0; }
        for j in rest {
            if !decrypt { t[j] = data[b + j]; }
            data[b + j] ^= ks[j];
            if decrypt { t[j] = data[b + j]; }
        }
        t[rest] = 0x80;
        for j in 16 { sum[j] ^= t[j]; }
    }
    for j in 16 { t[j] = sum[j] ^ off[j] ^ o.ldollar[j]; }
    var tag = bignum::aes_encrypt_block(o.aes, t);
    let h = ocb_hash(o, ad);
    for j in 16 { tag[j] ^= h[j]; }
    return tag;
}

// Encrypts data in place; the tag.
fn ocb_encrypt(o: const Ocb&, nonce: const u8[:], ad: const u8[:], data: u8[:]) -> u8[16] {
    return ocb_crypt(o, nonce, ad, data, false);
}

// Decrypts data in place and checks the tag in constant time. On a
// mismatch the data is zeroed, so nothing unauthenticated escapes.
fn ocb_decrypt(o: const Ocb&, nonce: const u8[:], ad: const u8[:], data: u8[:], tag: const u8[:]) -> bool {
    if tag.len != 16 { for j in data.len { data[j] = 0; } return false; }
    let t = ocb_crypt(o, nonce, ad, data, true);
    let ok = bignum::ct_eq_bytes(t, tag) == 1;
    if !ok { for j in data.len { data[j] = 0; } }
    return ok;
}
