// bignum.bcrypt: bcrypt password hashing (Provos and Mazieres, 1999), as
// Go's x/crypto/bcrypt has it: "$2a$" hashes with a cost of 4 to 31 and a
// 16-byte salt, passwords up to 72 bytes, and comparison that accepts the
// $2b$ and $2y$ spellings too. And bcrypt_pbkdf, OpenBSD's key derivation
// on it, which OpenSSH uses for passphrase-protected keys.

namespace bignum;

import std;
import ct;
import blowfish;
import sha512;
import entropy;

let BCRYPT_MIN_COST: i64 = 4;
let BCRYPT_MAX_COST: i64 = 31;
let BCRYPT_DEFAULT_COST: i64 = 10;

let BCRYPT_ALPHABET: const u8[:] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// bcrypt's base64: its own alphabet, no padding.
fn bcrypt_b64_encode(src: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < src.len {
        let b0: u32 = src[i];
        let b1: u32 = if i + 1 < src.len { src[i + 1] } else { 0 };
        let b2: u32 = if i + 2 < src.len { src[i + 2] } else { 0 };
        let v = b0 << 16 | b1 << 8 | b2;
        let n = ::min(3, src.len - i) + 1;
        for k in n { out.push(BCRYPT_ALPHABET[(v >> (18 - 6 * k)) & 63]); }
        i += 3;
    }
    return out;
}

fn bcrypt_b64_value(c: u8) -> i64 {
    for i in 64 { if BCRYPT_ALPHABET[i] == c { return i; } }
    return -1;
}

// Decodes, ignoring the unused low bits of the last character as Go does;
// false for a character outside the alphabet or a length of 1 mod 4.
fn bcrypt_b64_decode(src: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    if src.len % 4 == 1 { return out, false; }
    var acc: u32 = 0;
    var bits = 0;
    for c in src {
        let v = bcrypt_b64_value(c);
        if v < 0 { return out, false; }
        acc = (acc << 6) | (v as! u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as! u8);
        }
    }
    return out, true;
}

// The 23 bytes of hash for a password, cost and 16-byte salt:
// EksBlowfishSetup, then "OrpheanBeholderScryDoubt" encrypted 64 times.
fn bcrypt_raw(password: const u8[:], cost: i64, salt: const u8[:]) -> u8[>..] {
    var key: u8[>..] = [];
    key.append(password);
    key.push(0);
    var c = blowfish_init_salted(key, salt);
    let rounds: u64 = 1 << cost;
    var i: u64 = 0;
    while i < rounds {
        blowfish_expand(c, key);
        blowfish_expand(c, salt);
        i++;
    }
    var data: u8[>..] = [];
    data.append("OrpheanBeholderScryDoubt");
    for b in 3 {
        for j in 64 {
            let e = blowfish_encrypt_block(c, data[8 * b..8 * b + 8]);
            for k in 8 { data[8 * b + k] = e[k]; }
        }
    }
    data.resize(23, 0);
    return data;
}

fn bcrypt_format(minor: u8, cost: i64, salt: const u8[:], hash: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("$2");
    if minor != 0 { out.push(minor); }
    out.push('$');
    format_int(out, cost, 10, 2, '0');
    out.push('$');
    out.append(bcrypt_b64_encode(salt));
    out.append(bcrypt_b64_encode(hash));
    return out;
}

// GenerateFromPassword with the salt given, for tests; false for a
// password over 72 bytes or a cost out of range. A cost below 4 means 10.
fn bcrypt_hash_with(password: const u8[:], cost: i64, salt: const u8[:]) -> u8[>..], bool {
    let c = if cost < BCRYPT_MIN_COST { BCRYPT_DEFAULT_COST } else { cost };
    if password.len > 72 || c > BCRYPT_MAX_COST || salt.len != 16 { var none: u8[>..] = []; return none, false; }
    return bcrypt_format('a', c, salt, bcrypt_raw(password, c, salt)), true;
}

fn bcrypt_hash(password: const u8[:], cost: i64 = BCRYPT_DEFAULT_COST) -> u8[>..], bool {
    var salt: u8[16] = [0; 16];
    random_bytes(salt);
    return bcrypt_hash_with(password, cost, salt);
}

// A hash's version byte after "$2" (0 for none), cost, salt and the
// position of its hash part; false for anything malformed.
fn bcrypt_parse(h: const u8[:]) -> u8, i64, u8[>..], i64, bool {
    var salt: u8[>..] = [];
    if h.len < 59 || h[0] != '$' || h[1] != '2' { return 0, 0, salt, 0, false; }
    var n = 3;
    var minor: u8 = 0;
    if h[2] != '$' { minor = h[2]; n = 4; if h[3] != '$' { return 0, 0, salt, 0, false; } }
    if h.len < n + 3 + 22 + 31 || h[n] < '0' || h[n] > '9' || h[n + 1] < '0' || h[n + 1] > '9' || h[n + 2] != '$' {
        return 0, 0, salt, 0, false;
    }
    let cost = (h[n] - '0') as i64 * 10 + (h[n + 1] - '0') as i64;
    if cost < BCRYPT_MIN_COST || cost > BCRYPT_MAX_COST { return 0, 0, salt, 0, false; }
    let s, ok = bcrypt_b64_decode(h[n + 3..n + 25]);
    if !ok || s.len != 16 { return 0, 0, salt, 0, false; }
    return minor, cost, s, n + 25, true;
}

// CompareHashAndPassword: whether password hashes to h, compared in
// constant time.
fn bcrypt_verify(h: const u8[:], password: const u8[:]) -> bool {
    let minor, cost, salt, at, ok = bcrypt_parse(h);
    if !ok { return false; }
    let again = bcrypt_format(minor, cost, salt, bcrypt_raw(password, cost, salt));
    return again.len == h.len && ct_eq_bytes(again, h) == 1;
}

// Cost: the cost a hash was made with, or -1.
fn bcrypt_cost(h: const u8[:]) -> i64 {
    let minor, cost, salt, at, ok = bcrypt_parse(h);
    return if ok { cost } else { -1 };
}

// bcrypt_pbkdf's hash of a SHA-512'd password and salt: the cipher
// expanded with both 64 times, then "OxychromaticBlowfishSwatDynamite"
// encrypted 64 times, its words written little-endian.
fn bcrypt_pbkdf_hash(shapass: const u8[:], shasalt: const u8[:]) -> u8[32] {
    var c = blowfish_init_salted(shapass, shasalt);
    for i in 64 {
        blowfish_expand(c, shasalt);
        blowfish_expand(c, shapass);
    }
    let magic: const u8[:] = "OxychromaticBlowfishSwatDynamite";
    var out: u8[32] = [0; 32];
    for b in 4 {
        var l = bf_load(magic, 8 * b);
        var r = bf_load(magic, 8 * b + 4);
        for j in 64 {
            let nl, nr = bf_encrypt_words(c, l, r);
            l = nl;
            r = nr;
        }
        for k in 4 {
            out[8 * b + k] = (l >> (8 * k)) as! u8;
            out[8 * b + 4 + k] = (r >> (8 * k)) as! u8;
        }
    }
    return out;
}

// bcrypt_pbkdf(3): key_len bytes (at most 1024) from a password and salt
// (neither empty) and a number of rounds (at least 1). The 32-byte blocks
// are interleaved, byte i of block b going to i * blocks + b. False for
// arguments out of range.
fn bcrypt_pbkdf(password: const u8[:], salt: const u8[:], rounds: i64, key_len: i64) -> u8[>..], bool {
    var key: u8[>..] = [];
    if rounds < 1 || password.len == 0 || salt.len == 0 || salt.len > 1 << 20 || key_len < 0 || key_len > 1024 {
        return key, false;
    }
    let blocks = (key_len + 31) / 32;
    key.resize(blocks * 32, 0);
    let shapass = sha512(password);
    for n in 1..blocks + 1 {
        var counted: u8[>..] = [];
        counted.append(salt);
        for k in 4 { counted.push((n >> (24 - 8 * k)) as! u8); }
        var tmp = bcrypt_pbkdf_hash(shapass, sha512(counted));
        var out = tmp;
        for i in 1..rounds {
            tmp = bcrypt_pbkdf_hash(shapass, sha512(tmp));
            for j in 32 { out[j] ^= tmp[j]; }
        }
        for j in 32 { key[j * blocks + n - 1] = out[j]; }
    }
    key.resize(key_len, 0);
    return key, true;
}
