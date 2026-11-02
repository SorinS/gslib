// krb5.crypto: Kerberos encryption and checksum types.
//
//   des3-cbc-sha1-kd              16  RFC 3961 §6.3 (deprecated, RFC 8429)
//   aes128-cts-hmac-sha1-96       17  RFC 3962
//   aes256-cts-hmac-sha1-96       18  RFC 3962
//   aes128-cts-hmac-sha256-128    19  RFC 8009
//   aes256-cts-hmac-sha384-192    20  RFC 8009
//   rc4-hmac (arcfour-hmac)       23  RFC 4757 (deprecated, RFC 8429)
//   camellia128-cts-cmac          25  RFC 6803
//   camellia256-cts-cmac          26  RFC 6803
//
// Every function takes a Key, which
// carries its type; encrypt and decrypt use a key usage number to derive
// the keys they use (RFC 3961 §3), and a checksum is of the type that
// goes with its key's encryption type unless one is named.
//
// MACs are compared in constant time, and AES, Camellia, CMAC and DES
// come from bignum, which is constant time itself.

namespace krb5;

import std;
import crypto.bignum;
import crypto.bignum.aes;
import crypto.bignum.des;
import crypto.bignum.camellia;
import crypto.bignum.cmac;
import crypto.bignum.rc4;
import crypto.bignum.md4;
import crypto.bignum.md5;
import crypto.bignum.sha1;
import crypto.bignum.hmac;
import crypto.bignum.kdf;
import crypto.bignum.ct;
import crypto.bignum.entropy;

// A key and its encryption type (RFC 4120 §5.2.9's EncryptionKey).
struct Key { etype: i32, value: u8[..32] }

fn make_key(etype: i32, value: const u8[:]) -> Key {
    var k = Key { etype: etype, value: [] };
    k.value.append(value);
    return k;
}

// --- The types' parameters ----------------------------------------------------

fn etype_supported(e: i32) -> bool {
    e == ETYPE_DES3_CBC_SHA1_KD || e == ETYPE_AES128_CTS_HMAC_SHA1_96 ||
    e == ETYPE_AES256_CTS_HMAC_SHA1_96 || e == ETYPE_AES128_CTS_HMAC_SHA256_128 ||
    e == ETYPE_AES256_CTS_HMAC_SHA384_192 || e == ETYPE_RC4_HMAC || is_camellia(e)
}

fn is_camellia(e: i32) -> bool { e == ETYPE_CAMELLIA128_CTS_CMAC || e == ETYPE_CAMELLIA256_CTS_CMAC }

// The protocol key's length in bytes.
fn key_len(e: i32) -> i64 {
    match e {
        ETYPE_DES3_CBC_SHA1_KD => 24,
        ETYPE_AES128_CTS_HMAC_SHA1_96 => 16,
        ETYPE_AES256_CTS_HMAC_SHA1_96 => 32,
        ETYPE_AES128_CTS_HMAC_SHA256_128 => 16,
        ETYPE_AES256_CTS_HMAC_SHA384_192 => 32,
        ETYPE_RC4_HMAC => 16,
        ETYPE_CAMELLIA128_CTS_CMAC => 16,
        ETYPE_CAMELLIA256_CTS_CMAC => 32,
        _ => 0,
    }
}

// The random-to-key input's length in bytes (DES3 drops its parity bits).
fn seed_len(e: i32) -> i64 { if e == ETYPE_DES3_CBC_SHA1_KD { 21 } else { key_len(e) } }

// The confounder's length, which is the cipher's block for the RFC 3961
// types.
fn confounder_len(e: i32) -> i64 { if e == ETYPE_DES3_CBC_SHA1_KD || e == ETYPE_RC4_HMAC { 8 } else { 16 } }

// The integrity tag's length in a ciphertext.
fn mac_len(e: i32) -> i64 {
    match e {
        ETYPE_DES3_CBC_SHA1_KD => 20,
        ETYPE_AES128_CTS_HMAC_SHA1_96 => 12,
        ETYPE_AES256_CTS_HMAC_SHA1_96 => 12,
        ETYPE_AES128_CTS_HMAC_SHA256_128 => 16,
        ETYPE_AES256_CTS_HMAC_SHA384_192 => 24,
        ETYPE_RC4_HMAC => 16,
        ETYPE_CAMELLIA128_CTS_CMAC => 16,
        ETYPE_CAMELLIA256_CTS_CMAC => 16,
        _ => 0,
    }
}

// How much longer a ciphertext is than its plaintext, at most (DES3 also
// pads to its block).
fn cipher_overhead(e: i32) -> i64 { confounder_len(e) + mac_len(e) + (if e == ETYPE_DES3_CBC_SHA1_KD { 7 } else { 0 }) }

// The checksum type that goes with an encryption type (RFC 3961 §4's
// "required checksum mechanism").
fn cksum_type_for(e: i32) -> i32 {
    match e {
        ETYPE_DES3_CBC_SHA1_KD => CKSUM_HMAC_SHA1_DES3_KD,
        ETYPE_AES128_CTS_HMAC_SHA1_96 => CKSUM_HMAC_SHA1_96_AES128,
        ETYPE_AES256_CTS_HMAC_SHA1_96 => CKSUM_HMAC_SHA1_96_AES256,
        ETYPE_AES128_CTS_HMAC_SHA256_128 => CKSUM_HMAC_SHA256_128_AES128,
        ETYPE_AES256_CTS_HMAC_SHA384_192 => CKSUM_HMAC_SHA384_192_AES256,
        ETYPE_RC4_HMAC => CKSUM_HMAC_MD5,
        ETYPE_CAMELLIA128_CTS_CMAC => CKSUM_CMAC_CAMELLIA128,
        ETYPE_CAMELLIA256_CTS_CMAC => CKSUM_CMAC_CAMELLIA256,
        _ => 0,
    }
}

// The encryption type whose keys a keyed checksum type takes, or 0 for the
// unkeyed ones.
fn cksum_etype(c: i32) -> i32 {
    match c {
        CKSUM_HMAC_SHA1_DES3_KD => ETYPE_DES3_CBC_SHA1_KD,
        CKSUM_HMAC_SHA1_96_AES128 => ETYPE_AES128_CTS_HMAC_SHA1_96,
        CKSUM_HMAC_SHA1_96_AES256 => ETYPE_AES256_CTS_HMAC_SHA1_96,
        CKSUM_HMAC_SHA256_128_AES128 => ETYPE_AES128_CTS_HMAC_SHA256_128,
        CKSUM_HMAC_SHA384_192_AES256 => ETYPE_AES256_CTS_HMAC_SHA384_192,
        CKSUM_HMAC_MD5 => ETYPE_RC4_HMAC,
        CKSUM_CMAC_CAMELLIA128 => ETYPE_CAMELLIA128_CTS_CMAC,
        CKSUM_CMAC_CAMELLIA256 => ETYPE_CAMELLIA256_CTS_CMAC,
        _ => 0,
    }
}

fn cksum_len(c: i32) -> i64 {
    match c {
        CKSUM_RSA_MD5 => 16,
        CKSUM_SHA1 => 20,
        CKSUM_HMAC_SHA1_DES3_KD => 20,
        CKSUM_HMAC_SHA1_96_AES128 => 12,
        CKSUM_HMAC_SHA1_96_AES256 => 12,
        CKSUM_HMAC_SHA256_128_AES128 => 16,
        CKSUM_HMAC_SHA384_192_AES256 => 24,
        CKSUM_HMAC_MD5 => 16,
        CKSUM_CMAC_CAMELLIA128 => 16,
        CKSUM_CMAC_CAMELLIA256 => 16,
        _ => 0,
    }
}

fn cksum_supported(c: i32) -> bool { cksum_len(c) > 0 }

// The names krb5.conf uses (MIT's), first the canonical one.
fn etype_name(e: i32) -> const u8[:] {
    match e {
        ETYPE_DES3_CBC_SHA1_KD => "des3-cbc-sha1",
        ETYPE_AES128_CTS_HMAC_SHA1_96 => "aes128-cts-hmac-sha1-96",
        ETYPE_AES256_CTS_HMAC_SHA1_96 => "aes256-cts-hmac-sha1-96",
        ETYPE_AES128_CTS_HMAC_SHA256_128 => "aes128-cts-hmac-sha256-128",
        ETYPE_AES256_CTS_HMAC_SHA384_192 => "aes256-cts-hmac-sha384-192",
        ETYPE_RC4_HMAC => "arcfour-hmac",
        ETYPE_CAMELLIA128_CTS_CMAC => "camellia128-cts-cmac",
        ETYPE_CAMELLIA256_CTS_CMAC => "camellia256-cts-cmac",
        _ => "",
    }
}

// An encryption type by any of MIT's names for it (case-insensitive), or
// by number; 0 if unknown. The family names (aes, des3, rc4, camellia)
// are left to the caller, as they name several types.
fn etype_by_name(name: const u8[:]) -> i32 {
    var s: u8[>..] = [];
    for c in name { s.push(if c >= 'A' && c <= 'Z' { c + 32 } else { c }); }
    if s == "des3-cbc-sha1" || s == "des3-hmac-sha1" || s == "des3-cbc-sha1-kd" { return ETYPE_DES3_CBC_SHA1_KD; }
    if s == "aes128-cts-hmac-sha1-96" || s == "aes128-cts" || s == "aes128-sha1" { return ETYPE_AES128_CTS_HMAC_SHA1_96; }
    if s == "aes256-cts-hmac-sha1-96" || s == "aes256-cts" || s == "aes256-sha1" { return ETYPE_AES256_CTS_HMAC_SHA1_96; }
    if s == "aes128-cts-hmac-sha256-128" || s == "aes128-sha2" { return ETYPE_AES128_CTS_HMAC_SHA256_128; }
    if s == "aes256-cts-hmac-sha384-192" || s == "aes256-sha2" { return ETYPE_AES256_CTS_HMAC_SHA384_192; }
    if s == "arcfour-hmac" || s == "rc4-hmac" || s == "arcfour-hmac-md5" { return ETYPE_RC4_HMAC; }
    if s == "camellia128-cts-cmac" || s == "camellia128-cts" { return ETYPE_CAMELLIA128_CTS_CMAC; }
    if s == "camellia256-cts-cmac" || s == "camellia256-cts" { return ETYPE_CAMELLIA256_CTS_CMAC; }
    var v: i64 = 0;
    if s.len == 0 || s.len > 6 { return 0; }
    for c in s {
        if c < '0' || c > '9' { return 0; }
        v = v * 10 + (c - '0');
    }
    return v as! i32;
}

// --- n-fold (RFC 3961 §5.1) ----------------------------------------------------

// The input folded (or stretched) to `nbits` bits, a multiple of 8: copies
// rotated right by 13 bits each, added with end-around carry. This is
// MIT's byte-at-a-time form.
fn nfold(input: const u8[:], nbits: i64) -> u8[>..] {
    let inb = input.len;
    let outb = nbits / 8;
    var out: u8[>..] = [];
    out.resize(outb, 0);
    assert(inb > 0 && outb > 0);
    var a = outb;
    var b = inb;
    while b != 0 { let c = b; b = a % b; a = c; }
    let lcm = outb * inb / a;
    var acc: i64 = 0;
    var i = lcm - 1;
    while i >= 0 {
        let msbit = ((inb << 3) - 1 + ((inb << 3) + 13) * (i / inb) + ((inb - i % inb) << 3)) % (inb << 3);
        let hi: i64 = input[((inb - 1) - (msbit >> 3)) % inb];
        let lo: i64 = input[(inb - (msbit >> 3)) % inb];
        acc += ((hi << 8 | lo) >> ((msbit & 7) + 1)) & 0xff;
        acc += out[i % outb];
        out[i % outb] = (acc & 0xff) as! u8;
        acc = acc >> 8;
        i--;
    }
    if acc != 0 {
        var j = outb - 1;
        while j >= 0 {
            acc += out[j];
            out[j] = (acc & 0xff) as! u8;
            acc = acc >> 8;
            j--;
        }
    }
    return out;
}

// --- Block ciphers ----------------------------------------------------------

// CBC mode with ciphertext stealing (RFC 3962 §5, and RFC 6803 for
// Camellia) over a 16-byte block cipher: the last two blocks are swapped
// always, the last one cut to the data's length. One block is plain CBC.
// data.len >= 16.
fn cts_encrypt<K>(k: const K&, iv: const u8[:], data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let n = data.len;
    assert(n >= 16 && iv.len == 16);
    var prev: u8[16] = [0; 16];
    for i in 16 { prev[i] = iv[i]; }
    if n == 16 {
        var b: u8[16] = [0; 16];
        for i in 16 { b[i] = data[i] ^ prev[i]; }
        out.append(bignum::cipher_encrypt(k, b));
        return out;
    }
    let nblocks = (n + 15) / 16;
    // Every block before the last two, as CBC.
    var blk: u8[16] = [0; 16];
    for j in nblocks - 2 {
        for i in 16 { blk[i] = data[j * 16 + i] ^ prev[i]; }
        prev = bignum::cipher_encrypt(k, blk);
        out.append(prev);
    }
    let p = (nblocks - 2) * 16;
    let tail = n - p - 16;
    for i in 16 { blk[i] = data[p + i] ^ prev[i]; }
    let cn1 = bignum::cipher_encrypt(k, blk);
    for i in 16 { blk[i] = (if i < tail { data[p + 16 + i] } else { 0 }) ^ cn1[i]; }
    let cn = bignum::cipher_encrypt(k, blk);
    out.append(cn);
    out.append(cn1[..tail]);
    return out;
}

fn cts_decrypt<K>(k: const K&, iv: const u8[:], data: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    let n = data.len;
    assert(n >= 16 && iv.len == 16);
    var prev: u8[16] = [0; 16];
    for i in 16 { prev[i] = iv[i]; }
    if n == 16 {
        let d = bignum::cipher_decrypt(k, data);
        for i in 16 { out.push(d[i] ^ prev[i]); }
        return out;
    }
    let nblocks = (n + 15) / 16;
    for j in nblocks - 2 {
        let c = data[j * 16..j * 16 + 16];
        let d = bignum::cipher_decrypt(k, c);
        for i in 16 { out.push(d[i] ^ prev[i]); prev[i] = c[i]; }
    }
    let p = (nblocks - 2) * 16;
    let tail = n - p - 16;
    // The block sent first is the last one, encrypted over the (cut)
    // second-to-last: decrypting it gives that block xor the padded tail.
    let d = bignum::cipher_decrypt(k, data[p..p + 16]);
    var cn1: u8[16] = [0; 16];
    for i in 16 { cn1[i] = if i < tail { data[p + 16 + i] } else { d[i] }; }
    let d1 = bignum::cipher_decrypt(k, cn1);
    for i in 16 { out.push(d1[i] ^ prev[i]); }
    for i in tail { out.push(d[i] ^ cn1[i]); }
    return out;
}

// CTS with the cipher of an encryption type: AES, or Camellia for RFC
// 6803's types.
fn etype_cts(e: i32, key: const u8[:], iv: const u8[:], data: const u8[:], decrypt: bool) -> u8[>..] {
    if is_camellia(e) {
        let k = bignum::camellia_init(key);
        return if decrypt { cts_decrypt(k, iv, data) } else { cts_encrypt(k, iv, data) };
    }
    let k = bignum::aes_init(key);
    return if decrypt { cts_decrypt(k, iv, data) } else { cts_encrypt(k, iv, data) };
}

fn aes_cts_encrypt(key: const u8[:], iv: const u8[:], data: const u8[:]) -> u8[>..] {
    let k = bignum::aes_init(key);
    return cts_encrypt(k, iv, data);
}

fn aes_cts_decrypt(key: const u8[:], iv: const u8[:], data: const u8[:]) -> u8[>..] {
    let k = bignum::aes_init(key);
    return cts_decrypt(k, iv, data);
}

// Triple DES in CBC mode; data.len is a multiple of 8.
fn des3_cbc(key: const u8[:], iv: const u8[:], data: const u8[:], decrypt: bool) -> u8[>..] {
    let k = bignum::des3_init(key);
    var out: u8[>..] = [];
    assert(data.len % 8 == 0 && iv.len == 8);
    var prev: u8[8] = [0; 8];
    for i in 8 { prev[i] = iv[i]; }
    var blk: u8[8] = [0; 8];
    for j in data.len / 8 {
        let c = data[j * 8..j * 8 + 8];
        if decrypt {
            let d = bignum::des3_decrypt_block(k, c);
            for i in 8 { out.push(d[i] ^ prev[i]); prev[i] = c[i]; }
        } else {
            for i in 8 { blk[i] = c[i] ^ prev[i]; }
            prev = bignum::des3_encrypt_block(k, blk);
            out.append(prev);
        }
    }
    return out;
}

// The basic encryption of the simplified profile (RFC 3961 §5.3) on whole
// blocks with a zero IV: one block of DR's chain.
fn block_encrypt(e: i32, key: const u8[:], data: const u8[:]) -> u8[>..] {
    if e == ETYPE_DES3_CBC_SHA1_KD {
        let z: u8[8] = [0; 8];
        return des3_cbc(key, z, data, false);
    }
    let z: u8[16] = [0; 16];
    return aes_cts_encrypt(key, z, data);
}

// --- Key derivation ---------------------------------------------------------

// DES's odd parity in each byte's low bit.
fn des_fix_parity(b: u8) -> u8 {
    var c = 0;
    for p in 1..8 { if (b >> (p as! u8)) & 1 != 0 { c++; } }
    return if c % 2 == 0 { b | 1 } else { b & 0xfe };
}

let DES_WEAK_KEYS: u8[128] = [
    0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
    0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
    0xe0, 0xe0, 0xe0, 0xe0, 0xf1, 0xf1, 0xf1, 0xf1,
    0x1f, 0x1f, 0x1f, 0x1f, 0x0e, 0x0e, 0x0e, 0x0e,
    0x01, 0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e,
    0x1f, 0x01, 0x1f, 0x01, 0x0e, 0x01, 0x0e, 0x01,
    0x01, 0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1,
    0xe0, 0x01, 0xe0, 0x01, 0xf1, 0x01, 0xf1, 0x01,
    0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe,
    0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01, 0xfe, 0x01,
    0x1f, 0xe0, 0x1f, 0xe0, 0x0e, 0xf1, 0x0e, 0xf1,
    0xe0, 0x1f, 0xe0, 0x1f, 0xf1, 0x0e, 0xf1, 0x0e,
    0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e, 0xfe,
    0xfe, 0x1f, 0xfe, 0x1f, 0xfe, 0x0e, 0xfe, 0x0e,
    0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1, 0xfe,
    0xfe, 0xe0, 0xfe, 0xe0, 0xfe, 0xf1, 0xfe, 0xf1,
];

fn des_is_weak(k: const u8[:]) -> bool {
    for w in 16 {
        var same = true;
        for i in 8 { if DES_WEAK_KEYS[w * 8 + i] != k[i] { same = false; } }
        if same { return true; }
    }
    return false;
}

// random-to-key (RFC 3961 §6.3.1 for DES3: each 7 bytes become 8, the
// eighth gathering the low bits, all with odd parity; a weak key has its
// last byte xored with 0xf0). Identity for the other types.
fn random_to_key(e: i32, r: const u8[:]) -> Key {
    var k = Key { etype: e, value: [] };
    if e != ETYPE_DES3_CBC_SHA1_KD {
        k.value.append(r[..key_len(e)]);
        return k;
    }
    for j in 3 {
        var d: u8[8] = [0; 8];
        var lb: u8 = 0;
        for i in 7 {
            let v = r[j * 7 + i];
            if v & 1 != 0 { lb = lb | ((1 as u8) << ((i + 1) as! u8)); }
            d[i] = des_fix_parity(v);
        }
        d[7] = des_fix_parity(lb);
        if des_is_weak(d) { d[7] = d[7] ^ 0xf0; }
        k.value.append(d);
    }
    return k;
}

// DR(Key, Constant) (RFC 3961 §5.1): the constant n-folded to a block,
// encrypted again and again, the outputs strung together.
fn derive_random(base: Key, constant: const u8[:]) -> u8[>..] {
    let bs = if base.etype == ETYPE_DES3_CBC_SHA1_KD { 8 } else { 16 };
    var out: u8[>..] = [];
    var blk = nfold(constant, bs * 8);
    let want = seed_len(base.etype);
    while out.len < want {
        let c = block_encrypt(base.etype, base.value, blk);
        let take = if want - out.len < c.len { want - out.len } else { c.len };
        out.append(c[..take]);
        blk.resize(0);
        blk.append(c);
    }
    return out;
}

// KDF-HMAC-SHA2(key, label, k) (RFC 8009 §3): k bits of
// HMAC(key, 00000001 | label | 00 | k).
fn kdf_hmac_sha2(e: i32, key: const u8[:], label: const u8[:], kbits: i64) -> u8[>..] {
    var msg: u8[>..] = [0, 0, 0, 1];
    msg.append(label);
    msg.push(0);
    msg.push((kbits >> 24) as! u8);
    msg.push((kbits >> 16) as! u8);
    msg.push((kbits >> 8) as! u8);
    msg.push(kbits as! u8);
    let h = bignum::hmac(if e == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 }, key, msg);
    var out: u8[>..] = [];
    out.append(h[..kbits / 8]);
    return out;
}

// KDF-FEEDBACK-CMAC(key, constant) (RFC 6803 §3, SP 800-108 §5.2 with
// Camellia's CMAC): K(i) = CMAC(key, K(i-1) | i | constant | 00 | k), from
// K(0) zero, i and k (the key's bits) 4 bytes big-endian; the K(i) strung
// together and cut to k bits.
fn kdf_feedback_cmac(key: const u8[:], constant: const u8[:], kbits: i64) -> u8[>..] {
    let c = bignum::camellia_init(key);
    var out: u8[>..] = [];
    var prev: u8[>..] = [];
    prev.resize(16, 0);
    var i: i64 = 1;
    while out.len * 8 < kbits {
        var msg: u8[>..] = [];
        msg.append(prev);
        msg.push((i >> 24) as! u8);
        msg.push((i >> 16) as! u8);
        msg.push((i >> 8) as! u8);
        msg.push(i as! u8);
        msg.append(constant);
        msg.push(0);
        msg.push((kbits >> 24) as! u8);
        msg.push((kbits >> 16) as! u8);
        msg.push((kbits >> 8) as! u8);
        msg.push(kbits as! u8);
        let t = bignum::cmac(c, msg);
        out.append(t);
        prev.clear();
        prev.append(t);
        i++;
    }
    out.resize(kbits / 8, 0);
    return out;
}

fn is_sha2_etype(e: i32) -> bool { e == ETYPE_AES128_CTS_HMAC_SHA256_128 || e == ETYPE_AES256_CTS_HMAC_SHA384_192 }

// The constant usage | kind (0x99 checksum, 0xaa encryption, 0x55
// integrity), RFC 3961 §5.3.
fn usage_constant(usage: i64, kind: u8) -> u8[5] {
    let u = usage as! u32;
    return [(u >> 24) as! u8, (u >> 16) as! u8, (u >> 8) as! u8, u as! u8, kind];
}

// DK(base, usage | kind) for the RFC 3961 and RFC 3962 types, KDF-HMAC-SHA2
// for RFC 8009's, KDF-FEEDBACK-CMAC for RFC 6803's: the key for one
// purpose. For RFC 8009 the integrity and checksum keys are as long as the
// MAC; the encryption key, as the base. RFC 6803's are all as the base.
fn derive_key(base: Key, usage: i64, kind: u8) -> u8[>..] {
    let c = usage_constant(usage, kind);
    if is_camellia(base.etype) { return kdf_feedback_cmac(base.value, c, key_len(base.etype) * 8); }
    if is_sha2_etype(base.etype) {
        let bits = if kind == 0xaa { key_len(base.etype) * 8 } else { mac_len(base.etype) * 8 };
        return kdf_hmac_sha2(base.etype, base.value, c, bits);
    }
    let r = derive_random(base, c);
    let k = random_to_key(base.etype, r);
    var out: u8[>..] = [];
    out.append(k.value);
    return out;
}

// --- String to key ----------------------------------------------------------

// The default string-to-key parameters (RFC 3962 §4, RFC 8009 §4, RFC
// 6803 §4): the iteration count, big-endian.
fn default_iterations(e: i32) -> i64 { if is_sha2_etype(e) || is_camellia(e) { 32768 } else { 4096 } }

// The UTF-16LE form of a UTF-8 password, as Windows hashes it; ok false
// for bytes that are not UTF-8.
fn utf16le(s: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let c = s[i] as u32;
        var cp: u32 = 0;
        var n = 0;
        if c < 0x80 { cp = c; n = 1; }
        else if c & 0xe0 == 0xc0 { cp = c & 0x1f; n = 2; }
        else if c & 0xf0 == 0xe0 { cp = c & 0x0f; n = 3; }
        else if c & 0xf8 == 0xf0 { cp = c & 0x07; n = 4; }
        else { return out, false; }
        if i + n > s.len { return out, false; }
        for j in 1..n {
            let b = s[i + j] as u32;
            if b & 0xc0 != 0x80 { return out, false; }
            cp = cp << 6 | (b & 0x3f);
        }
        let min: u32 = if n == 1 { 0 } else if n == 2 { 0x80 } else if n == 3 { 0x800 } else { 0x10000 };
        if cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp < 0xe000) { return out, false; }
        if cp >= 0x10000 {
            let v = cp - 0x10000;
            let hi = 0xd800 | (v >> 10);
            let lo = 0xdc00 | (v & 0x3ff);
            out.push(hi as! u8); out.push((hi >> 8) as! u8);
            out.push(lo as! u8); out.push((lo >> 8) as! u8);
        } else {
            out.push(cp as! u8); out.push((cp >> 8) as! u8);
        }
        i += n;
    }
    return out, true;
}

// The key of a password (RFC 3961 §3's string-to-key): salt is the
// principal's (realm then name components, or what the KDC gave in
// ETYPE-INFO2), params the KDC's s2kparams or empty for the default.
fn string_to_key(e: i32, password: const u8[:], salt: const u8[:], params: const u8[:] = "") -> Key, i64 {
    var k = Key { etype: e, value: [] };
    if !etype_supported(e) { return k, ERR_ETYPE; }
    if e == ETYPE_RC4_HMAC {
        // MD4 of the UTF-16LE password; no salt (RFC 4757 §5).
        let u, ok = utf16le(password);
        if !ok { return k, ERR_S2K_PARAMS; }
        k.value.append(bignum::md4(u));
        return k, OK;
    }
    if e == ETYPE_DES3_CBC_SHA1_KD {
        if params.len != 0 { return k, ERR_S2K_PARAMS; }
        var s: u8[>..] = [];
        s.append(password);
        s.append(salt);
        if s.len == 0 { return k, ERR_S2K_PARAMS; }
        let t = random_to_key(e, nfold(s, 168));
        return make_key(e, derive_key_const(t, "kerberos")), OK;
    }
    var iter = default_iterations(e);
    if params.len != 0 {
        if params.len != 4 { return k, ERR_S2K_PARAMS; }
        let p0: i64 = params[0];
        let p1: i64 = params[1];
        let p2: i64 = params[2];
        let p3: i64 = params[3];
        iter = p0 << 24 | p1 << 16 | p2 << 8 | p3;
        // RFC 3962 §4: zero would be 2^32; MIT, like us, refuses counts
        // above 2^24 as a denial of service.
        if iter == 0 || iter > 1 << 24 { return k, ERR_S2K_PARAMS; }
    }
    if is_sha2_etype(e) {
        var saltp: u8[>..] = [];
        saltp.append(etype_name(e));
        saltp.push(0);
        saltp.append(salt);
        let bits = if e == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 };
        let t = bignum::pbkdf2(bits, password, saltp, iter, key_len(e));
        return make_key(e, kdf_hmac_sha2(e, t, "kerberos", key_len(e) * 8)), OK;
    }
    if is_camellia(e) {
        // RFC 6803 §4: the enctype's name and a zero before the salt,
        // PBKDF2-HMAC-SHA1, then KDF-FEEDBACK-CMAC(tkey, "kerberos").
        var saltp: u8[>..] = [];
        saltp.append(etype_name(e));
        saltp.push(0);
        saltp.append(salt);
        let t = bignum::pbkdf2(160, password, saltp, iter, key_len(e));
        return make_key(e, kdf_feedback_cmac(t, "kerberos", key_len(e) * 8)), OK;
    }
    let t = make_key(e, bignum::pbkdf2(160, password, salt, iter, key_len(e)));
    return make_key(e, derive_key_const(t, "kerberos")), OK;
}

// DK(base, constant) for a constant that is not a usage (string-to-key's
// "kerberos").
fn derive_key_const(base: Key, constant: const u8[:]) -> u8[>..] {
    let r = derive_random(base, constant);
    let k = random_to_key(base.etype, r);
    var out: u8[>..] = [];
    out.append(k.value);
    return out;
}

// The default salt of a principal (RFC 4120 §4): the realm, then each name
// component, with nothing between.
fn default_salt(realm: const u8[:], components: const u8[][:]) -> u8[>..] {
    var s: u8[>..] = [];
    s.append(realm);
    for c in components { s.append(c); }
    return s;
}

// --- RC4-HMAC (RFC 4757) ------------------------------------------------------

// The message type T for a key usage (RFC 4757 §3).
fn rc4_usage(usage: i64) -> u8[4] {
    let u: u32 = match usage { 3 => 8, 9 => 8, 23 => 13, _ => usage as! u32 };
    return [u as! u8, (u >> 8) as! u8, (u >> 16) as! u8, (u >> 24) as! u8];
}

fn rc4_encrypt(key: Key, usage: i64, confounder: const u8[:], plain: const u8[:]) -> u8[>..] {
    let k1 = bignum::hmac(128, key.value, rc4_usage(usage));
    var data: u8[>..] = [];
    data.append(confounder);
    data.append(plain);
    let cksum = bignum::hmac(128, k1, data);
    let k3 = bignum::hmac(128, k1, cksum);
    var r = bignum::rc4_init(k3);
    bignum::rc4_xor(r, data);
    var out: u8[>..] = [];
    out.append(cksum);
    out.append(data);
    return out;
}

fn rc4_decrypt(key: Key, usage: i64, cipher: const u8[:], out: u8[>..]&) -> i64 {
    if cipher.len < 24 { return ERR_CIPHERTEXT; }
    let k1 = bignum::hmac(128, key.value, rc4_usage(usage));
    let cksum = cipher[..16];
    let k3 = bignum::hmac(128, k1, cksum);
    var data: u8[>..] = [];
    data.append(cipher[16..]);
    var r = bignum::rc4_init(k3);
    bignum::rc4_xor(r, data);
    let want = bignum::hmac(128, k1, data);
    if bignum::ct_eq_bytes(want, cksum) != 1 { return ERR_INTEGRITY; }
    out.append(data[8..]);
    return OK;
}

// --- Encryption ---------------------------------------------------------------

// The ciphertext of `plain` under `key` for `usage` (RFC 3961 §3's encrypt
// with the default cipher state), with a fresh random confounder.
fn encrypt(key: Key, usage: i64, plain: const u8[:], out: u8[>..]&) -> i64 {
    var conf: u8[16] = [0; 16];
    bignum::random_bytes(conf);
    return encrypt_with(key, usage, conf[..confounder_len(key.etype)], plain, out);
}

// encrypt with a given confounder, for test vectors.
fn encrypt_with(key: Key, usage: i64, confounder: const u8[:], plain: const u8[:], out: u8[>..]&) -> i64 {
    let e = key.etype;
    if !etype_supported(e) { return ERR_ETYPE; }
    if key.value.len != key_len(e) { return ERR_KEY_SIZE; }
    if confounder.len != confounder_len(e) { return ERR_CIPHERTEXT; }
    if e == ETYPE_RC4_HMAC {
        out.append(rc4_encrypt(key, usage, confounder, plain));
        return OK;
    }
    let ke = derive_key(key, usage, 0xaa);
    let ki = derive_key(key, usage, 0x55);
    var p: u8[>..] = [];
    p.append(confounder);
    p.append(plain);
    if e == ETYPE_DES3_CBC_SHA1_KD {
        while p.len % 8 != 0 { p.push(0); }
        let z: u8[8] = [0; 8];
        out.append(des3_cbc(ke, z, p, false));
        out.append(bignum::hmac(160, ki, p));
        return OK;
    }
    let z: u8[16] = [0; 16];
    let c = etype_cts(e, ke, z, p, false);
    out.append(c);
    if is_camellia(e) {
        // RFC 6803 §6: the MAC is CMAC over the plaintext.
        let ck = bignum::camellia_init(ki);
        out.append(bignum::cmac(ck, p));
    } else if is_sha2_etype(e) {
        // RFC 8009 §5: the MAC is over the IV and the ciphertext.
        var m: u8[>..] = [];
        m.append(z);
        m.append(c);
        let h = bignum::hmac(if e == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 }, ki, m);
        out.append(h[..mac_len(e)]);
    } else {
        let h = bignum::hmac(160, ki, p);
        out.append(h[..12]);
    }
    return OK;
}

// The plaintext of `cipher`, its confounder removed, appended to out.
// DES3's plaintext keeps the zeros that padded it to its block, as MIT's
// does; the ASN.1 inside says where it ends.
fn decrypt(key: Key, usage: i64, cipher: const u8[:], out: u8[>..]&) -> i64 {
    let e = key.etype;
    if !etype_supported(e) { return ERR_ETYPE; }
    if key.value.len != key_len(e) { return ERR_KEY_SIZE; }
    if e == ETYPE_RC4_HMAC { return rc4_decrypt(key, usage, cipher, out); }
    let cl = confounder_len(e);
    let ml = mac_len(e);
    if cipher.len < cl + ml { return ERR_CIPHERTEXT; }
    let c = cipher[..cipher.len - ml];
    let tag = cipher[cipher.len - ml..];
    let ke = derive_key(key, usage, 0xaa);
    let ki = derive_key(key, usage, 0x55);
    if e == ETYPE_DES3_CBC_SHA1_KD {
        if c.len % 8 != 0 { return ERR_CIPHERTEXT; }
        let z: u8[8] = [0; 8];
        let p = des3_cbc(ke, z, c, true);
        let h = bignum::hmac(160, ki, p);
        if bignum::ct_eq_bytes(h, tag) != 1 { return ERR_INTEGRITY; }
        out.append(p[cl..]);
        return OK;
    }
    let z: u8[16] = [0; 16];
    if is_sha2_etype(e) {
        // Check before decrypting (RFC 8009 §5).
        var m: u8[>..] = [];
        m.append(z);
        m.append(c);
        let h = bignum::hmac(if e == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 }, ki, m);
        if bignum::ct_eq_bytes(h[..ml], tag) != 1 { return ERR_INTEGRITY; }
        let p = aes_cts_decrypt(ke, z, c);
        out.append(p[cl..]);
        return OK;
    }
    let p = etype_cts(e, ke, z, c, true);
    if is_camellia(e) {
        let ck = bignum::camellia_init(ki);
        if !bignum::cmac_verify(ck, p, tag) { return ERR_INTEGRITY; }
        out.append(p[cl..]);
        return OK;
    }
    let h = bignum::hmac(160, ki, p);
    if bignum::ct_eq_bytes(h[..12], tag) != 1 { return ERR_INTEGRITY; }
    out.append(p[cl..]);
    return OK;
}

// --- Checksums ----------------------------------------------------------------

// A checksum of `data` of type `ctype` (0 for the key's own type), keyed
// with `key` for `usage` when the type is keyed.
fn checksum(key: Key, ctype0: i32, usage: i64, data: const u8[:], out: u8[>..]&) -> i64 {
    let ctype = if ctype0 == 0 { cksum_type_for(key.etype) } else { ctype0 };
    if ctype == CKSUM_RSA_MD5 { out.append(bignum::md5(data)); return OK; }
    if ctype == CKSUM_SHA1 { out.append(bignum::sha1(data)); return OK; }
    let ce = cksum_etype(ctype);
    if ce == 0 { return ERR_CKSUMTYPE; }
    // A keyed checksum takes a key of its own encryption type, except that
    // HMAC-MD5 is also used with AES keys by MS's PAC and S4U, and AES's
    // types interchange: we follow MIT in requiring the key's type to
    // agree with the checksum's, but for HMAC-MD5, which takes any key.
    if ctype != CKSUM_HMAC_MD5 && ce != key.etype { return ERR_CKSUMTYPE; }
    if key.value.len != key_len(key.etype) { return ERR_KEY_SIZE; }
    if ctype == CKSUM_HMAC_MD5 {
        // RFC 4757 §4.
        let ksign = bignum::hmac(128, key.value, "signaturekey\x00");
        var s = bignum::md5_init();
        bignum::md5_update(s, rc4_usage(usage));
        bignum::md5_update(s, data);
        let tmp = bignum::md5_final(s);
        out.append(bignum::hmac(128, ksign, tmp));
        return OK;
    }
    let kc = derive_key(key, usage, 0x99);
    if is_camellia(ce) {
        // RFC 6803 §7: CMAC(Kc, message).
        let ck = bignum::camellia_init(kc);
        out.append(bignum::cmac(ck, data));
    } else if is_sha2_etype(ce) {
        let h = bignum::hmac(if ce == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 }, kc, data);
        out.append(h[..cksum_len(ctype)]);
    } else {
        let h = bignum::hmac(160, kc, data);
        out.append(h[..cksum_len(ctype)]);
    }
    return OK;
}

// OK if `sum` is the checksum of type `ctype` of data, else
// KRB_AP_ERR_MODIFIED (or the error that kept it from being computed).
fn verify_checksum(key: Key, ctype: i32, usage: i64, data: const u8[:], sum: const u8[:]) -> i64 {
    var want: u8[>..] = [];
    let err = checksum(key, ctype, usage, data, want);
    if err != OK { return err; }
    if want.len != sum.len || bignum::ct_eq_bytes(want, sum) != 1 { return KRB_AP_ERR_MODIFIED; }
    return OK;
}

// --- Random keys ----------------------------------------------------------------

// A fresh random key of type e (a session key or subkey).
fn random_key(e: i32) -> Key {
    var r: u8[32] = [0; 32];
    bignum::random_bytes(r);
    if e == ETYPE_RC4_HMAC { return make_key(e, r[..16]); }
    return random_to_key(e, r[..seed_len(e)]);
}

// --- PRF (RFC 3961 §5.3, RFC 8009 §5) -------------------------------------------

// The pseudo-random function: for RFC 3962 and DES3, SHA-1 of the input
// cut to a multiple of the cipher's block and encrypted under
// DK(key, "prf"); for RFC 8009, KDF-HMAC-SHA2(key, "prf", input); for RFC
// 6803, CMAC(KDF-FEEDBACK-CMAC(key, "prf"), input); for RC4, which RFC
// 4757 leaves out, HMAC-SHA1(key, input) as MIT has it.
fn prf(key: Key, input: const u8[:], out: u8[>..]&) -> i64 {
    let e = key.etype;
    if !etype_supported(e) { return ERR_ETYPE; }
    if key.value.len != key_len(e) { return ERR_KEY_SIZE; }
    if is_camellia(e) {
        let kp = kdf_feedback_cmac(key.value, "prf", key_len(e) * 8);
        let c = bignum::camellia_init(kp);
        out.append(bignum::cmac(c, input));
        return OK;
    }
    if is_sha2_etype(e) {
        var label: u8[>..] = [];
        label.append("prf");
        label.push(0);
        label.append(input);
        let bits = if e == ETYPE_AES256_CTS_HMAC_SHA384_192 { 384 } else { 256 };
        var msg: u8[>..] = [0, 0, 0, 1];
        msg.append(label);
        msg.push(0); msg.push(0); msg.push((bits >> 8) as! u8); msg.push(bits as! u8);
        let h = bignum::hmac(bits, key.value, msg);
        out.append(h);
        return OK;
    }
    if e == ETYPE_RC4_HMAC {
        out.append(bignum::hmac(160, key.value, input));
        return OK;
    }
    let bs = if e == ETYPE_DES3_CBC_SHA1_KD { 8 } else { 16 };
    let h = bignum::sha1(input);
    let k = make_key(e, derive_key_const(key, "prf"));
    out.append(block_encrypt(e, k.value, h[..20 / bs * bs]));
    return OK;
}
