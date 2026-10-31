// bignum.des: DES and triple DES (FIPS 46-3, SP 800-67), for what still
// needs them; neither is fit for new designs (DES's key is 56 bits, and
// both have 64-bit blocks). Blocks go through bignum.modes like AES's.
//
// The bit permutations follow the standard's tables, which hold public
// positions. The S-boxes are not looked up in memory: each box is four
// 64-bit masks, one per output bit, and the secret 6-bit input selects a
// bit of each by a shift, which takes the same time for every amount on
// the processors Goose targets. So nothing here indexes memory by a
// secret.

namespace bignum;

import std;

// The 16 round keys, 48 bits each.
struct Des { sk: u64[16] }

// Encrypt with k1, decrypt with k2, encrypt with k3.
struct Des3 { k1: Des, k2: Des, k3: Des }

// The standard's tables, positions numbered 1..n from the most significant
// bit; DES_FP is IP's inverse.
let DES_IP: u8[64] = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
];
let DES_FP: u8[64] = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25
];
let DES_E: u8[48] = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1
];
let DES_P: u8[32] = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25
];
let DES_PC1: u8[56] = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
];
let DES_PC2: u8[48] = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
];
let DES_SHIFTS: u8[16] = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
];

// S-box i as masks: bit x of DES_S[4 * i + j] is bit j of S_i(x), with x
// the box's six input bits as they leave the expansion (row from the
// outer two, column from the inner four).
let DES_S: u64[32] = [
    0x917be9066f81b478, 0x27e9d492609f1f29, 0xb0c7871b497826bd, 0x869d497a86e67619,
    0xcd235ad2b865168f, 0x746a8b7462949fc3, 0x68f93c169346c3e9, 0xe196196e69c3a659,
    0x4b8d9c63a965569a, 0x76b9960c39c2b749, 0xd96a863526f4794a, 0x96692d696b9c90d3,
    0x09b77c1ac34998e7, 0xacd1168f692cce71, 0xcb69718c74ca0e97, 0x92c3e719ed90583e,
    0xa4cd96d24b76b948, 0xc70b39c692f05d2b, 0x695b9ca191666b96, 0x429dcd6a79e1348e,
    0x95a36a597c3ca34c, 0x52cbe13c6d9216da, 0xc69938d615e69a69, 0xb44ab695c9a4695b,
    0x348e9679497969a6, 0x6a95f41a9e4b81f4, 0x869cd96699e643c3, 0x92c761f82c96d966,
    0x9f6281cd619c7c2b, 0xa71658a7c8f13f0c, 0x394e96b1596aa569, 0xc17abd2438c716b9
];

// The bits of x (width bits wide) at the table's positions, first entry
// highest.
fn des_perm(x: u64, t: const u8[:], width: u32) -> u64 {
    var out: u64 = 0;
    for i in t.len { out = (out << 1) | ((x >> (width - t[i])) & 1); }
    return out;
}

fn des_load(b: const u8[:]) -> u64 {
    var x: u64 = 0;
    for i in 8 { x = (x << 8) | b[i]; }
    return x;
}

fn des_store(x: u64) -> u8[8] {
    var out: u8[8] = [0; 8];
    for i in 8 { out[i] = (x >> (56 - 8 * i)) as! u8; }
    return out;
}

// The key schedule of an 8-byte key; the parity bits are ignored.
fn des_init(key: const u8[:]) -> Des {
    assert(key.len == 8);
    let k = des_perm(des_load(key), DES_PC1, 64);
    var c = k >> 28;
    var d = k & 0xfffffff;
    var r = Des { sk: [0; 16] };
    for i in 16 {
        let s: u32 = DES_SHIFTS[i];
        c = ((c << s) | (c >> (28 - s))) & 0xfffffff;
        d = ((d << s) | (d >> (28 - s))) & 0xfffffff;
        r.sk[i] = des_perm((c << 28) | d, DES_PC2, 56);
    }
    return r;
}

// The round function on the right half.
fn des_f(r: u64, k: u64) -> u64 {
    let x = des_perm(r, DES_E, 32) ^ k;
    var out: u64 = 0;
    for i in 8 {
        let six: u32 = ((x >> (42 - 6 * i)) & 63) as! u32;
        var v: u64 = 0;
        for j in 4 { v = v | ((DES_S[4 * i + j] >> six) & 1) << j; }
        out = (out << 4) | v;
    }
    return des_perm(out, DES_P, 32);
}

fn des_crypt(k: const Des&, x: u64, decrypt: bool) -> u64 {
    let y = des_perm(x, DES_IP, 64);
    var l = y >> 32;
    var r = y & 0xffffffff;
    for i in 16 {
        let t = r;
        r = l ^ des_f(r, k.sk[if decrypt { 15 - i } else { i }]);
        l = t;
    }
    return des_perm((r << 32) | l, DES_FP, 64);
}

fn des_encrypt_block(k: const Des&, blk: const u8[:]) -> u8[8] {
    assert(blk.len == 8);
    return des_store(des_crypt(k, des_load(blk), false));
}

fn des_decrypt_block(k: const Des&, blk: const u8[:]) -> u8[8] {
    assert(blk.len == 8);
    return des_store(des_crypt(k, des_load(blk), true));
}

// Triple DES from a 24-byte key k1 || k2 || k3 (keying option 1; repeat
// k1 as k3 for the two-key form).
fn des3_init(key: const u8[:]) -> Des3 {
    assert(key.len == 24);
    return Des3 { k1: des_init(key[..8]), k2: des_init(key[8..16]), k3: des_init(key[16..]) };
}

fn des3_encrypt_block(k: const Des3&, blk: const u8[:]) -> u8[8] {
    assert(blk.len == 8);
    let x = des_crypt(k.k1, des_load(blk), false);
    let y = des_crypt(k.k2, x, true);
    return des_store(des_crypt(k.k3, y, false));
}

fn des3_decrypt_block(k: const Des3&, blk: const u8[:]) -> u8[8] {
    assert(blk.len == 8);
    let x = des_crypt(k.k3, des_load(blk), true);
    let y = des_crypt(k.k2, x, false);
    return des_store(des_crypt(k.k1, y, true));
}
