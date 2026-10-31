// bignum.modes: the block cipher modes of SP 800-38A over any block
// cipher here (AES, DES, triple DES, and the legacy ciphers that add
// themselves): CBC, CFB, OFB and CTR, as Go's crypto/cipher has them,
// XTS (IEEE 1619) for 16-byte blocks as Go's x/crypto/xts has it, and
// PKCS #7 padding for CBC.
//
// Each mode works in place on the whole message, from an IV of one block.
// CBC takes whole blocks only; CFB (with full-block segments, CFB-128 for
// AES), OFB and CTR take any length. A cipher joins by giving overloads of
// cipher_block_len, cipher_encrypt and cipher_decrypt for its key type,
// as AES, DES and triple DES do below. None of this branches on the data;
// pkcs7_unpad checks the padding in constant time, but a CBC decryption
// that reports bad padding is still a padding oracle, so authenticate the
// ciphertext before decrypting it.

namespace bignum;

import std;
import ct;
import aes;
import des;

fn cipher_block_len(k: const Aes&) -> i64 { 16 }
fn cipher_encrypt(k: const Aes&, b: const u8[:]) -> u8[16] { aes_encrypt_block(k, b) }
fn cipher_decrypt(k: const Aes&, b: const u8[:]) -> u8[16] { aes_decrypt_block(k, b) }

fn cipher_block_len(k: const Des&) -> i64 { 8 }
fn cipher_encrypt(k: const Des&, b: const u8[:]) -> u8[8] { des_encrypt_block(k, b) }
fn cipher_decrypt(k: const Des&, b: const u8[:]) -> u8[8] { des_decrypt_block(k, b) }

fn cipher_block_len(k: const Des3&) -> i64 { 8 }
fn cipher_encrypt(k: const Des3&, b: const u8[:]) -> u8[8] { des3_encrypt_block(k, b) }
fn cipher_decrypt(k: const Des3&, b: const u8[:]) -> u8[8] { des3_decrypt_block(k, b) }

fn mode_check<K>(k: const K&, iv: const u8[:]) -> i64 {
    let bs = cipher_block_len(k);
    assert(iv.len == bs);
    return bs;
}

// CBC: each block is XORed with the previous ciphertext (the IV first),
// then encrypted. data.len must be a multiple of the block length.
fn cbc_encrypt<K>(k: const K&, iv: const u8[:], data: u8[:]) {
    let bs = mode_check(k, iv);
    assert(data.len % bs == 0);
    var x: u8[16] = [0; 16];
    for i in bs { x[i] = iv[i]; }
    var off = 0;
    while off < data.len {
        for i in bs { x[i] ^= data[off + i]; }
        let e = cipher_encrypt(k, x[..bs]);
        for i in bs { data[off + i] = e[i]; x[i] = e[i]; }
        off += bs;
    }
}

fn cbc_decrypt<K>(k: const K&, iv: const u8[:], data: u8[:]) {
    let bs = mode_check(k, iv);
    assert(data.len % bs == 0);
    var prev: u8[16] = [0; 16];
    var c: u8[16] = [0; 16];
    for i in bs { prev[i] = iv[i]; }
    var off = 0;
    while off < data.len {
        for i in bs { c[i] = data[off + i]; }
        let d = cipher_decrypt(k, c[..bs]);
        for i in bs { data[off + i] = d[i] ^ prev[i]; prev[i] = c[i]; }
        off += bs;
    }
}

// CFB with segments of a whole block: the keystream is the encryption of
// the previous ciphertext block (the IV first). A short last block takes
// as much keystream as it needs.
fn cfb_crypt<K>(k: const K&, iv: const u8[:], data: u8[:], decrypt: bool) {
    let bs = mode_check(k, iv);
    var x: u8[16] = [0; 16];
    for i in bs { x[i] = iv[i]; }
    var off = 0;
    while off < data.len {
        let ks = cipher_encrypt(k, x[..bs]);
        let n = ::min(bs, data.len - off);
        for i in n {
            let c = if decrypt { data[off + i] } else { data[off + i] ^ ks[i] };
            data[off + i] ^= ks[i];
            x[i] = c;
        }
        off += n;
    }
}

fn cfb_encrypt<K>(k: const K&, iv: const u8[:], data: u8[:]) { cfb_crypt(k, iv, data, false); }
fn cfb_decrypt<K>(k: const K&, iv: const u8[:], data: u8[:]) { cfb_crypt(k, iv, data, true); }

// OFB: the keystream is the IV encrypted again and again. Encryption and
// decryption are the same.
fn ofb_xor<K>(k: const K&, iv: const u8[:], data: u8[:]) {
    let bs = mode_check(k, iv);
    var x: u8[16] = [0; 16];
    for i in bs { x[i] = iv[i]; }
    var off = 0;
    while off < data.len {
        let ks = cipher_encrypt(k, x[..bs]);
        let n = ::min(bs, data.len - off);
        for i in bs { x[i] = ks[i]; }
        for i in n { data[off + i] ^= ks[i]; }
        off += n;
    }
}

// CTR: the keystream is the encryption of the IV, then of the IV plus one,
// and so on, the whole block counted as one big-endian number. For AES,
// aes_ctr gives the same bytes faster.
fn ctr_xor<K>(k: const K&, iv: const u8[:], data: u8[:]) {
    let bs = mode_check(k, iv);
    var x: u8[16] = [0; 16];
    for i in bs { x[i] = iv[i]; }
    var off = 0;
    while off < data.len {
        let ks = cipher_encrypt(k, x[..bs]);
        let n = ::min(bs, data.len - off);
        for i in n { data[off + i] ^= ks[i]; }
        var carry: u32 = 1;
        var i = bs;
        while i > 0 {
            i--;
            let t = x[i] + carry;
            x[i] = t as! u8;
            carry = t >> 8;
        }
        off += n;
    }
}

// XTS (IEEE 1619, SP 800-38E) for a 16-byte block cipher: k1 encrypts
// the data and k2 the tweak, which starts as the sector number in 16
// little-endian bytes and is multiplied by x in GF(2^128) each block.
// Whole blocks only, as in Go (no ciphertext stealing).
fn xts_crypt<K>(k1: const K&, k2: const K&, sector: u64, data: u8[:], decrypt: bool) {
    assert(cipher_block_len(k1) == 16 && data.len % 16 == 0);
    var t: u8[16] = [0; 16];
    for i in 8 { t[i] = (sector >> (8 * i)) as! u8; }
    var tw = cipher_encrypt(k2, t);
    var off = 0;
    var x: u8[16] = [0; 16];
    while off < data.len {
        for i in 16 { x[i] = data[off + i] ^ tw[i]; }
        let e = if decrypt { cipher_decrypt(k1, x) } else { cipher_encrypt(k1, x) };
        for i in 16 { data[off + i] = e[i] ^ tw[i]; }
        var carry: u8 = 0;
        for i in 16 {
            let c = tw[i] >> 7;
            tw[i] = (tw[i] << 1) | carry;
            carry = c;
        }
        tw[0] ^= 0x87 & (0 - carry);
        off += 16;
    }
}

fn xts_encrypt<K>(k1: const K&, k2: const K&, sector: u64, data: u8[:]) { xts_crypt(k1, k2, sector, data, false); }
fn xts_decrypt<K>(k1: const K&, k2: const K&, sector: u64, data: u8[:]) { xts_crypt(k1, k2, sector, data, true); }

// PKCS #7 padding (RFC 5652 §6.3): 1 to bs bytes, each holding the count.
fn pkcs7_pad(data: const u8[:], bs: i64 = 16) -> u8[>..] {
    assert(bs >= 1 && bs <= 255);
    let n = bs - data.len % bs;
    var out: u8[>..] = [];
    out.append(data);
    for i in n { out.push(n as! u8); }
    return out;
}

// The data without its padding, and true; or empty and false when the
// length is not a whole number of blocks or the padding is malformed. The
// padding is checked without branching on its bytes.
fn pkcs7_unpad(data: const u8[:], bs: i64 = 16) -> u8[>..], bool {
    var out: u8[>..] = [];
    if bs < 1 || bs > 255 || data.len == 0 || data.len % bs != 0 { return out, false; }
    let n: u32 = data[data.len - 1];
    // 1 <= n <= bs, and each of the last n bytes equals n.
    var good = ct_is_zero_u32(n) ^ 1;
    good = good & (ct_lt_u32(bs as! u32, n) ^ 1);
    for i in bs {
        let b: u32 = data[data.len - 1 - i];
        let inpad = ct_lt_u32(i as! u32, n);       // byte i from the end lies in the padding
        good = good & (ct_eq_u32(b, n) | (inpad ^ 1));
    }
    if good == 0 { return out, false; }
    let keep: i64 = data.len - n;
    out.append(data[..keep]);
    return out, true;
}
