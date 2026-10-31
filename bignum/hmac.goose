// bignum.hmac: one-shot hashing, HMAC (RFC 2104), HKDF (RFC 5869) and
// MGF1 over any of the package's hashes, named by an id: 128 for MD5, 160
// for SHA-1, 224, 256, 384 and 512 for SHA-2, HASH_SHA512_224 and
// HASH_SHA512_256, HASH_SHA3_224 through HASH_SHA3_512, and
// HASH_BLAKE2B_256, _384, _512 and HASH_BLAKE2S_256 (unkeyed). Most
// callers use 256 or 384, the key derivation of TLS 1.3.

namespace bignum;

import std;
import sha256;
import sha512;
import sha1;
import sha3;
import md5;
import blake2;
import ct;

let HASH_MD5: i64 = 128;
let HASH_SHA1: i64 = 160;
let HASH_SHA224: i64 = 224;
let HASH_SHA256: i64 = 256;
let HASH_SHA384: i64 = 384;
let HASH_SHA512: i64 = 512;
let HASH_SHA512_224: i64 = 5224;
let HASH_SHA512_256: i64 = 5256;
let HASH_SHA3_224: i64 = 3224;
let HASH_SHA3_256: i64 = 3256;
let HASH_SHA3_384: i64 = 3384;
let HASH_SHA3_512: i64 = 3512;
let HASH_BLAKE2B_256: i64 = 2256;
let HASH_BLAKE2B_384: i64 = 2384;
let HASH_BLAKE2B_512: i64 = 2512;
let HASH_BLAKE2S_256: i64 = 1256;

fn is_blake2b(bits: i64) -> bool { bits == HASH_BLAKE2B_256 || bits == HASH_BLAKE2B_384 || bits == HASH_BLAKE2B_512 }

fn hash_len(bits: i64) -> i64 {
    if bits == HASH_SHA512_224 || bits == HASH_SHA3_224 { return 28; }
    if bits == HASH_SHA512_256 || bits == HASH_SHA3_256 { return 32; }
    if bits == HASH_SHA3_384 { return 48; }
    if bits == HASH_SHA3_512 { return 64; }
    if is_blake2b(bits) { return (bits - 2000) / 8; }
    if bits == HASH_BLAKE2S_256 { return 32; }
    return bits / 8;
}

// The block size HMAC pads its key to.
fn hash_block(bits: i64) -> i64 {
    if bits == 128 || bits == 160 || bits == 224 || bits == 256 || bits == HASH_BLAKE2S_256 { return 64; }
    if bits > 3000 && bits < 4000 { return 200 - 2 * hash_len(bits); }
    return 128;
}

// One hash of a || b, by `bits`.
fn hash2(bits: i64, a: const u8[:], b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if bits == 256 || bits == 224 {
        var s = if bits == 256 { sha256_init() } else { sha224_init() };
        sha256_update(s, a);
        sha256_update(s, b);
        if bits == 256 { out.append(sha256_final(s)); } else { out.append(sha224_final(s)); }
    } else if bits == 128 {
        var s = md5_init();
        md5_update(s, a);
        md5_update(s, b);
        out.append(md5_final(s));
    } else if bits == 160 {
        var s = sha1_init();
        sha1_update(s, a);
        sha1_update(s, b);
        out.append(sha1_final(s));
    } else if bits > 3000 && bits < 4000 {
        var s = sha3_init(bits - 3000);
        sha3_update(s, a);
        sha3_update(s, b);
        out = sha3_final(s);
    } else if is_blake2b(bits) {
        var s = blake2b_init(hash_len(bits));
        blake2b_update(s, a);
        blake2b_update(s, b);
        out = blake2b_final(s);
    } else if bits == HASH_BLAKE2S_256 {
        var s = blake2s_init();
        blake2s_update(s, a);
        blake2s_update(s, b);
        out = blake2s_final(s);
    } else {
        var s = if bits == 384 { sha384_init() } else if bits == 512 { sha512_init() }
                else if bits == HASH_SHA512_224 { sha512_224_init() } else { sha512_256_init() };
        assert(bits == 384 || bits == 512 || bits == HASH_SHA512_224 || bits == HASH_SHA512_256);
        sha512_update(s, a);
        sha512_update(s, b);
        out = sha512_final(s);
    }
    return out;
}

fn hash_bits(bits: i64, data: const u8[:]) -> u8[>..] { hash2(bits, data, "") }

// HMAC-SHA-`bits`(key, msg).
fn hmac(bits: i64, key: const u8[:], msg: const u8[:]) -> u8[>..] {
    let bl = hash_block(bits);
    var k: u8[144] = [0; 144];
    if key.len > bl {
        let hk = hash_bits(bits, key);
        for i in hk.len { k[i] = hk[i]; }
    } else {
        for i in key.len { k[i] = key[i]; }
    }
    var kpad: u8[144] = [0; 144];
    for i in bl { kpad[i] = k[i] ^ 0x36; }
    let inner = hash2(bits, kpad[..bl], msg);
    for i in bl { kpad[i] = k[i] ^ 0x5c; }
    return hash2(bits, kpad[..bl], inner);
}

// The largest input hmac_prefix_ct takes, prefix and data together: its
// byte positions, padding blocks included, are compared as 32-bit numbers,
// so they must stay well below 2^32. Records are far smaller (TLS's are at
// most 16 KB and a little).
let HMAC_PREFIX_CT_MAX: i64 = 1 << 30;

// Whether hmac_prefix_ct takes a prefix and data of these (public) lengths.
fn hmac_prefix_ct_fits(prefix_len: i64, data_len: i64) -> bool {
    prefix_len >= 0 && data_len >= 0 && prefix_len <= HMAC_PREFIX_CT_MAX && data_len <= HMAC_PREFIX_CT_MAX - prefix_len
}

// HMAC-SHA-1 or HMAC-SHA-256 (bits 160 or 256) of prefix ‖ data[..len],
// in time that does not depend on len, nor on any byte's value: only on
// key.len, prefix.len, data.len and min_len, all public. For TLS's CBC
// records, whose MAC'd length comes out of the decrypted padding
// (Lucky13); the caller keeps min_len <= len <= data.len. As OpenSSL's
// ssl3_cbc_digest_record: the inner hash's blocks that lie wholly before
// min_len are hashed as usual; each block the message's end could fall in
// is built byte by byte with masks (the data, the 0x80, the length in the
// last), every one is compressed, and the state after the last is kept by
// a mask. The key is at most 64 bytes, and the input within
// hmac_prefix_ct_fits.
fn hmac_prefix_ct(bits: i64, key: const u8[:], prefix: const u8[:], data: const u8[:], len: i64,
                  min_len: i64) -> u8[>..] {
    assert((bits == 160 || bits == 256) && key.len <= 64 && min_len >= 0 && min_len <= data.len &&
           hmac_prefix_ct_fits(prefix.len, data.len));
    var kpad: u8[64] = [0; 64];
    for i in key.len { kpad[i] = key[i]; }
    // The inner hash's input: ipad, prefix, data; its message is the first
    // m bytes, m secret, m_min <= m <= m_max.
    var st: u8[>..] = [];
    for i in 64 { st.push(kpad[i] ^ 0x36); }
    st.append(prefix);
    st.append(data);
    let m = 64 + prefix.len + len;
    let m_min = 64 + prefix.len + min_len;
    let m_max = st.len;
    let bitlen = (m as! u64) * 8;
    let last = ((m + 8) / 64) as! u32;              // the block holding the length
    var s1 = sha1_init();
    var s2 = sha256_init();
    let nw = bits / 32;
    let k0 = m_min / 64;
    for j in k0 {
        if bits == 160 { sha1_block(s1, st[64 * j..64 * j + 64]); } else { sha256_block(s2, st[64 * j..64 * j + 64]); }
    }
    var h: u32[8] = [0; 8];
    var blk: u8[64] = [0; 64];
    for j in k0..(m_max + 8) / 64 + 1 {
        let mask_last = ct_mask(ct_eq_u32(j as! u32, last));
        for i in 64 {
            let p = 64 * j + i;
            let b: u32 = if p < st.len { st[p] } else { 0 };
            var v = (b & ct_mask(ct_lt_u32(p as! u32, m as! u32))) | (0x80 & ct_mask(ct_eq_u32(p as! u32, m as! u32)));
            if i >= 56 { v = ct_select_u32(mask_last, ((bitlen >> (8 * (63 - i))) as! u32) & 0xff, v); }
            blk[i] = v as! u8;
        }
        if bits == 160 {
            sha1_block(s1, blk);
            for w in 5 { h[w] = ct_select_u32(mask_last, s1.h[w], h[w]); }
        } else {
            sha256_block(s2, blk);
            for w in 8 { h[w] = ct_select_u32(mask_last, s2.h[w], h[w]); }
        }
    }
    var inner: u8[>..] = [];
    for w in nw {
        for k in 4 { inner.push((h[w] >> (24 - 8 * k)) as! u8); }
    }
    for i in 64 { kpad[i] = kpad[i] ^ 0x5c; }
    return hash2(bits, kpad, inner);
}

fn hmac_sha256(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(256, key, msg) }
fn hmac_sha384(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(384, key, msg) }
fn hmac_sha512(key: const u8[:], msg: const u8[:]) -> u8[>..] { hmac(512, key, msg) }

// HKDF-Extract: PRK = HMAC(salt, ikm); an empty salt means hash-length zeros.
fn hkdf_extract(bits: i64, salt: const u8[:], ikm: const u8[:]) -> u8[>..] {
    if salt.len == 0 {
        var z: u8[64] = [0; 64];
        return hmac(bits, z[..hash_len(bits)], ikm);
    }
    return hmac(bits, salt, ikm);
}

// HKDF-Expand: `len` bytes (at most 255 hash lengths) from prk and info.
fn hkdf_expand(bits: i64, prk: const u8[:], info: const u8[:], len: i64) -> u8[>..] {
    let hl = hash_len(bits);
    assert(len >= 0 && len <= 255 * hl);
    var out: u8[>..] = [];
    var t: u8[>..] = [];
    var msg: u8[>..] = [];
    var counter = 1;
    while out.len < len {
        msg.clear();
        msg.append(t);
        msg.append(info);
        msg.push(counter as! u8);
        t = hmac(bits, prk, msg);
        let n = ::min(hl, len - out.len);
        out.append(t[..n]);
        counter++;
    }
    return out;
}

// Extract then expand.
fn hkdf(bits: i64, salt: const u8[:], ikm: const u8[:], info: const u8[:], len: i64) -> u8[>..] {
    let prk = hkdf_extract(bits, salt, ikm);
    return hkdf_expand(bits, prk, info, len);
}

// out ^= MGF1 with SHA-`bits` (RFC 8017 §B.2.1), over out's whole length.
fn mgf1(bits: i64, out: u8[:], seed: const u8[:]) {
    var counter: u32 = 0;
    var off = 0;
    while off < out.len {
        let c: u8[4] = [(counter >> 24) as! u8, (counter >> 16) as! u8, (counter >> 8) as! u8, counter as! u8];
        let d = hash2(bits, seed, c);
        let n = ::min(d.len, out.len - off);
        for k in n { out[off + k] ^= d[k]; }
        off += n;
        counter++;
    }
}
