// bignum.keywrap: AES Key Wrap (RFC 3394, NIST SP 800-38F's KW) and AES
// Key Wrap with Padding (RFC 5649, KWP), as JOSE's A128KW/A192KW/A256KW
// (RFC 7518 §4.4), CMS and PKCS #11 use them. Constant time in the key and
// the wrapped key: the six rounds touch every block whatever its value, and
// unwrapping checks the integrity value with masks, so a bad ciphertext and a
// bad key fail alike. Only the lengths, which are public, pick a path.

namespace bignum;

import std;
import crypto.bignum.ct;
import crypto.bignum.aes;

// RFC 3394 §2.2.3.1's default initial value, and RFC 5649 §3's alternative
// one, whose low half is the message length.
let KW_IV: u64 = 0xA6A6A6A6A6A6A6A6;
let KWP_IV: u64 = 0xA65959A6;

fn kw_get64(p: const u8[:]) -> u64 {
    var v: u64 = 0;
    for i in 8 { v = v << 8 | p[i]; }
    return v;
}

fn kw_put64(p: u8[:], v: u64) {
    for i in 8 { p[i] = (v >> (56 - 8 * i as u64)) as! u8; }
}

fn kw_key_ok(kek: const u8[:]) -> bool { kek.len == 16 || kek.len == 24 || kek.len == 32 }

// W (RFC 3394 §2.2.1, index form): r holds the n 64-bit blocks, wrapped in
// place; the result's integrity block.
fn kw_wrap_blocks(k: const Aes&, a0: u64, r: u8[:]) -> u64 {
    let n = r.len / 8;
    var a = a0;
    var b: u8[16] = [0; 16];
    for j in 6 {
        for i in n {
            kw_put64(b[..8], a);
            for x in 8 { b[8 + x] = r[8 * i + x]; }
            let e = aes_encrypt_block(k, b);
            let t = (n * j + i + 1) as u64;
            a = kw_get64(e[..8]) ^ t;
            for x in 8 { r[8 * i + x] = e[8 + x]; }
        }
    }
    return a;
}

// W⁻¹: r holds the n blocks after the integrity block a0, unwrapped in
// place; the recovered integrity value.
fn kw_unwrap_blocks(k: const Aes&, a0: u64, r: u8[:]) -> u64 {
    let n = r.len / 8;
    var a = a0;
    var b: u8[16] = [0; 16];
    var j = 6;
    while j > 0 {
        j--;
        var i = n;
        while i > 0 {
            i--;
            let t = (n * j + i + 1) as u64;
            kw_put64(b[..8], a ^ t);
            for x in 8 { b[8 + x] = r[8 * i + x]; }
            let d = aes_decrypt_block(k, b);
            a = kw_get64(d[..8]);
            for x in 8 { r[8 * i + x] = d[8 + x]; }
        }
    }
    return a;
}

// 1 if the 64-bit values are equal, else 0, without a branch on them.
fn kw_eq64(a: u64, b: u64) -> u32 {
    let d = a ^ b;
    return ct_is_zero_u32((d >> 32) as! u32 | d as! u32);
}

// The key `key` (a multiple of 8 bytes, at least 16) wrapped under the AES
// key `kek` (16, 24 or 32 bytes): 8 bytes longer. False, and nothing, for
// lengths RFC 3394 does not take.
fn aes_key_wrap(kek: const u8[:], key: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !kw_key_ok(kek) || key.len < 16 || key.len % 8 != 0 { return out, false; }
    let k = aes_init(kek);
    out.resize(8, 0);
    out.append(key);
    let a = kw_wrap_blocks(k, KW_IV, out[8..]);
    kw_put64(out[..8], a);
    return out, true;
}

// The key wrapped in `wrapped` and true; or nothing and false when the
// integrity check fails or the lengths are wrong. Which of the two it was is
// not told apart by time.
fn aes_key_unwrap(kek: const u8[:], wrapped: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !kw_key_ok(kek) || wrapped.len < 24 || wrapped.len % 8 != 0 { return out, false; }
    let k = aes_init(kek);
    out.append(wrapped[8..]);
    let a = kw_unwrap_blocks(k, kw_get64(wrapped[..8]), out);
    if kw_eq64(a, KW_IV) == 0 {
        out.resize(0);
        return out, false;
    }
    return out, true;
}

// RFC 5649: a key of any length from 1 byte, padded with zeros to a multiple
// of 8; a single padded block is one AES encryption.
fn aes_key_wrap_pad(kek: const u8[:], key: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !kw_key_ok(kek) || key.len == 0 || key.len > 0xFFFFFFFF { return out, false; }
    let k = aes_init(kek);
    let aiv = KWP_IV << 32 | key.len as u64;
    let padded = (key.len + 7) / 8 * 8;
    if padded == 8 {
        var b: u8[16] = [0; 16];
        kw_put64(b[..8], aiv);
        for i in key.len { b[8 + i] = key[i]; }
        out.append(aes_encrypt_block(k, b));
        return out, true;
    }
    out.resize(8, 0);
    out.append(key);
    out.resize(8 + padded, 0);
    let a = kw_wrap_blocks(k, aiv, out[8..]);
    kw_put64(out[..8], a);
    return out, true;
}

// The key wrapped by aes_key_wrap_pad and true, or nothing and false. The
// integrity value, the length it carries and the zero padding are checked
// together, under one mask.
fn aes_key_unwrap_pad(kek: const u8[:], wrapped: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if !kw_key_ok(kek) || wrapped.len < 16 || wrapped.len % 8 != 0 { return out, false; }
    let k = aes_init(kek);
    var a: u64 = 0;
    if wrapped.len == 16 {
        let d = aes_decrypt_block(k, wrapped);
        a = kw_get64(d[..8]);
        out.append(d[8..]);
    } else {
        out.append(wrapped[8..]);
        a = kw_unwrap_blocks(k, kw_get64(wrapped[..8]), out);
    }
    let n = out.len;
    let mli = a & 0xFFFFFFFF;
    var ok = kw_eq64(a >> 32, KWP_IV);
    // 8(n/8 - 1) < MLI <= n: as unsigned compares on public bounds.
    ok = ok & ct_lt_u32((n - 8) as! u32, mli as! u32) & (ct_lt_u32(n as! u32, mli as! u32) ^ 1);
    // The bytes past MLI are zero. mli is secret until the check passes, so
    // every byte of the last block is looked at under a mask.
    var nonzero: u32 = 0;
    for i in n - 8..n {
        let past = ct_lt_u32(mli as! u32, (i + 1) as! u32);
        nonzero = nonzero | (ct_mask(past) & out[i]);
    }
    ok = ok & ct_is_zero_u32(nonzero);
    if ok == 0 {
        out.resize(0);
        return out, false;
    }
    out.resize(mli as i64);
    return out, true;
}
