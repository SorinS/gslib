// bignum's constant-time code as C functions, for dudect's own harness
// (github.com/oreparaz/dudect, tools/dudect/harness.c): each target takes
// one input, the class's bytes, and returns a byte of its result so that
// nothing is optimized away. scripts/dudect.py builds it (goose -o with
// --header) and runs every target.
//
// The fixed operands (an RSA key, the moduli, the base) are made once, in
// main, which goose_init runs.

import std;
import gslib from "../../../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.mont;
import gslib.crypto.bignum.rsa;
import gslib.crypto.bignum.x25519;
import gslib.crypto.bignum.ec;
import gslib.crypto.bignum.ed25519;
import gslib.crypto.bignum.camellia;
import gslib.crypto.bignum.cmac;
import gslib.crypto.bignum.shamir;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.gcm;
import gslib.crypto.bignum.ccm;
import gslib.crypto.bignum.chacha20;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.mlkem;
import gslib.crypto.bignum.x448;
import gslib.crypto.bignum.ed448;

var rsa_key = bignum::RsaPrivateKey { n: [], e: [], d: [], p: [], q: [], dp: [], dq: [], qinv: [] };
var m512: u32[..16] = [];           // an odd 512-bit modulus, with its R^2 and -1/m
var r2_512: u32[..16] = [];
var m0i_512: u32 = 0;
var x512: u32[..16] = [];
var m1024: u32[..32] = [];
var big_m: u8[..64] = [];           // the control's modulus, as bytes
var big_x: u8[..64] = [];
// For the targets whose class 0 is all zeros (FIXED_ZERO in harness.c):
// two ciphertexts or sealed messages that the input chooses between.
var gcm_sealed: u8[..80] = [];
var ccm_sealed: u8[..80] = [];
var chacha_sealed: u8[..80] = [];
var pkcs1_good: u8[..128] = [];        // 00 02 PS 00 and a 32-byte key
var pkcs1_bad: u8[..128] = [];         // 00 02 PS without the 00
var oaep_y1: u8[..128] = [];           // OAEP's first byte not zero
var oaep_hash: u8[..128] = [];         // first byte zero, label hash wrong
var mlkem_seed: u8[..64] = [];
var mlkem_ct: u8[..1088] = [];         // ML-KEM-768: a ciphertext that decapsulates
var mlkem_ct_bad: u8[..1088] = [];     // and one with a byte changed (implicit rejection)
var p256_peer: u8[..65] = [];

fn pseudo(seed: u32, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    var s = seed;
    for i in n {
        s = s * 1664525 + 1013904223;
        out.push((s >> 24) as! u8);
    }
    return out;
}

fn main() {
    rsa_key = bignum::rsa_generate(1024);
    var mb = pseudo(7, 64);
    mb[0] = mb[0] | 0x80;
    mb[63] = mb[63] | 1;
    m512.resize(16, 0);
    bignum::limbs_from_be(m512, mb);
    m0i_512 = bignum::mont_m0i(m512[0]);
    r2_512.resize(16, 0);
    bignum::mont_r2(r2_512, m512);
    var xb = pseudo(8, 64);
    xb[0] = xb[0] & 0x7f;
    x512.resize(16, 0);
    bignum::limbs_from_be(x512, xb);
    var mb2 = pseudo(9, 128);
    mb2[0] = mb2[0] | 0x80;
    mb2[127] = mb2[127] | 1;
    m1024.resize(32, 0);
    bignum::limbs_from_be(m1024, mb2);
    big_m.append(mb);
    big_x.append(xb);

    let msg = pseudo(10, 64);
    let nonce: u8[12] = [0; 12];
    let key16 = pseudo(11, 16);
    let key32 = pseudo(12, 32);
    gcm_sealed.append(bignum::aes_gcm_seal(key16, nonce, "", msg));
    ccm_sealed.append(bignum::aes_ccm_seal(key16, nonce, "", msg, 16));
    chacha_sealed.append(bignum::chacha20_poly1305_seal(key32, nonce, "", msg));

    // RSA blocks built by hand and encrypted with the raw public operation.
    var em = pseudo(13, 128);
    for i in 128 { if em[i] == 0 { em[i] = 1; } }
    em[0] = 0;
    em[1] = 2;
    em[128 - 33] = 0;
    let c1, ok1 = bignum::rsa_public_op_ct(rsa_key, em);
    pkcs1_good.append(c1);
    em[128 - 33] = 7;
    let c2, ok2 = bignum::rsa_public_op_ct(rsa_key, em);
    pkcs1_bad.append(c2);
    var em2 = pseudo(14, 128);
    em2[0] = 1;
    let c3, ok3 = bignum::rsa_public_op_ct(rsa_key, em2);
    oaep_y1.append(c3);
    em2[0] = 0;
    let c4, ok4 = bignum::rsa_public_op_ct(rsa_key, em2);
    oaep_hash.append(c4);

    mlkem_seed.append(pseudo(15, 64));
    let ek, dk = bignum::mlkem_keys_from_seed(3, mlkem_seed);
    let ss, ct, oke = bignum::mlkem_encaps_with(3, ek, pseudo(16, 32));
    mlkem_ct.append(ct);
    mlkem_ct_bad.append(ct);
    mlkem_ct_bad[500] = mlkem_ct_bad[500] ^ 1;

    var psk = pseudo(17, 32);
    psk[0] = psk[0] & 0x7f;
    let curve = bignum::p256();
    p256_peer.append(bignum::ec_public_key(curve, psk));
}

// a when the input's first byte is even, b when it is odd, chosen with a
// mask (the choice is the secret).
fn choose(out: u8[>..]&, a: const u8[:], b: const u8[:], data: const u8[:]) {
    let m: u8 = (0 - ((data[0] & 1) as u32)) as! u8;
    for i in a.len { out.push(a[i] ^ (m & (a[i] ^ b[i]))); }
}

// A sealed message whose tag is wrong: in its last byte only when the
// input is all zeros (class 0), from its first byte on, almost always,
// when it is random. The tag check must take the same time for both.
fn spoil_tag(out: u8[>..]&, sealed: const u8[:], data: const u8[:]) {
    let n = sealed.len - 16;
    out.append(sealed[..n]);
    for i in 15 { out.push(sealed[n + i] ^ data[i]); }
    out.push(sealed[n + 15] ^ (data[15] | 1));
}

// The control, which must be caught: BigInt's modpow, whose time follows
// the exponent's bits.
export fn dut_control_modpow(data: const u8[:]) -> u8 {
    let y = bignum::modpow(bignum::from_bytes_be(big_x), bignum::from_bytes_be(data), bignum::from_bytes_be(big_m));
    let b = bignum::to_bytes_be(y, 64);
    return b[63];
}

// x^e mod m, 512 bits, e the input (64 bytes).
export fn dut_mont_modexp(data: const u8[:]) -> u8 {
    var e: u32[16] = [0; 16];
    bignum::limbs_from_be(e, data[..64]);
    var out: u32[16] = [0; 16];
    bignum::mont_modexp(out, x512, e, m512, m0i_512, r2_512);
    return out[0] as! u8;
}

// 1/a mod m, 1024 bits, a the input (128 bytes, its top bit cleared).
export fn dut_ct_mod_inv(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    a[31] = a[31] & 0x7fffffff;
    var inv: u32[32] = [0; 32];
    let ok = bignum::ct_mod_inv(inv, a, m1024);
    return (inv[0] as! u8) ^ (ok as! u8);
}

// A negative control, constant time by construction: ct_mod_small's
// instruction mix (multiplies by constants, shifts, xors, no select)
// over the same input, to show what this machine's noise floor is at the
// same number of measurements.
export fn dut_plain_mix(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    var r: u64 = 0;
    var i = 32;
    while i > 0 {
        i--;
        let x = (r << 16) | (a[i] >> 16);
        r = (x - ((x * 2148557) >> 32) * 1999) & 0xffffffff;
        let y = (r << 16) | (a[i] & 0xffff);
        r = (y - ((y * 2148557) >> 32) * 1999) & 0xffffffff;
    }
    return r as! u8;
}

// a mod 1999, a the input as 32 limbs (128 bytes).
export fn dut_ct_mod_small(data: const u8[:]) -> u8 {
    var a: u32[32] = [0; 32];
    bignum::limbs_from_be(a, data[..128]);
    return bignum::ct_mod_small(a, 1999) as! u8;
}

// The RSA private operation, 1024 bits, on the input (128 bytes, first 0).
export fn dut_rsa_private_op(data: const u8[:]) -> u8 {
    var x: u8[128] = [0; 128];
    for i in 1..128 { x[i] = data[i]; }
    let y, ok = bignum::rsa_private_op(rsa_key, x);
    return if ok { y[127] } else { 0 };
}

// RSA's x^e mod n in constant time (encryption of a secret), on the input.
export fn dut_rsa_public_op_ct(data: const u8[:]) -> u8 {
    var x: u8[128] = [0; 128];
    for i in 1..128 { x[i] = data[i]; }
    let y, ok = bignum::rsa_public_op_ct(rsa_key, x);
    return if ok { y[127] } else { 0 };
}

// X25519 on the base point, the input the scalar (32 bytes).
export fn dut_x25519_base(data: const u8[:]) -> u8 {
    let pk = bignum::x25519_base(data[..32]);
    return pk[0];
}

// ECDSA P-256 signing of one message, the input the private key (32
// bytes, top bit cleared so that it is below n).
export fn dut_ecdsa_p256_sign(data: const u8[:]) -> u8 {
    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = data[i]; }
    sk[0] = sk[0] & 0x7f;
    let curve = bignum::p256();
    let sig = bignum::ecdsa_sign(curve, sk, "a message");
    return sig[0];
}

// ECDSA secp256k1 signing of one message, the input the private key (32
// bytes, top bit cleared so that it is below n).
export fn dut_ecdsa_secp256k1_sign(data: const u8[:]) -> u8 {
    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = data[i]; }
    sk[0] = sk[0] & 0x7f;
    let curve = bignum::secp256k1();
    let sig = bignum::ecdsa_sign(curve, sk, "a message");
    return sig[0];
}

// Shamir in GF(2^8): 5 parts, any 3, of a 32-byte secret (the input),
// under fixed coefficients; and the secret back from three parts (the
// input, 3 x 32 bytes, parts 1, 3 and 5).
let SHAMIR_RAND: u8[64] = [0x5a; 64];

export fn dut_shamir_gf8_split(data: const u8[:]) -> u8 {
    var out: u8[>..] = [];
    let ok = bignum::split_gf8_with(data[..32], 5, 3, SHAMIR_RAND, out);
    return out[0];
}

export fn dut_shamir_gf8_join(data: const u8[:]) -> u8 {
    let xs: i64[3] = [1, 3, 5];
    var out: u8[>..] = [];
    let ok = bignum::join_gf8(xs, data[..96], 32, out);
    return out[0];
}

// Shamir in the prime field of 2^255 - 19: 5 parts, any 3, of a 32-byte
// secret (the input, top bits cleared so that it is below the prime).
let P25519: u8[32] = [0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed];
let SHAMIR_RAND_P: u8[80] = [0x3c; 80];

export fn dut_shamir_prime_split(data: const u8[:]) -> u8 {
    var s: u8[32] = [0; 32];
    for i in 32 { s[i] = data[i]; }
    s[0] = s[0] & 0x3f;
    var out: u8[>..] = [];
    let ok = bignum::split_prime_with(s, P25519, 5, 3, SHAMIR_RAND_P, out);
    return out[0];
}

// Ed25519 signing of one message, the input the seed (32 bytes).
export fn dut_ed25519_sign(data: const u8[:]) -> u8 {
    let sig = bignum::ed25519_sign(data[..32], "a message");
    return sig[0];
}

// Camellia-128 encryption of one block under a fixed key, the input the
// block (16 bytes).
export fn dut_camellia128_encrypt(data: const u8[:]) -> u8 {
    let key: u8[16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let k = bignum::camellia_init(key);
    let out = bignum::camellia_encrypt_block(k, data[..16]);
    return out[0];
}

// Camellia-256's key schedule and one block's decryption, the input the
// key (32 bytes).
export fn dut_camellia256_key(data: const u8[:]) -> u8 {
    let zero: u8[16] = [0; 16];
    let k = bignum::camellia_init(data[..32]);
    let out = bignum::camellia_decrypt_block(k, zero);
    return out[0];
}

// CMAC over Camellia-128 of one message, the input the key (16 bytes).
export fn dut_cmac_camellia(data: const u8[:]) -> u8 {
    let k = bignum::camellia_init(data[..16]);
    let t = bignum::cmac(k, "a message of forty bytes, give or take..");
    return t[0];
}

// AES-128 encryption of one block under a fixed key, the input the block
// (16 bytes).
export fn dut_aes128_encrypt(data: const u8[:]) -> u8 {
    let key: u8[16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
    let k = bignum::aes_init(key);
    let out = bignum::aes_encrypt_block(k, data[..16]);
    return out[0];
}

// AES-256's key schedule and one block's decryption, the input the key
// (32 bytes).
export fn dut_aes256_key(data: const u8[:]) -> u8 {
    let zero: u8[16] = [0; 16];
    let k = bignum::aes_init(data[..32]);
    let out = bignum::aes_decrypt_block(k, zero);
    return out[0];
}

// AES-128-GCM sealing of 64 bytes, the input the key (16 bytes): GHASH
// multiplies by H, which the key makes secret.
export fn dut_aes_gcm_seal(data: const u8[:]) -> u8 {
    let nonce: u8[12] = [0; 12];
    let sealed = bignum::aes_gcm_seal(data[..16], nonce, "", big_x);
    return sealed[79];
}

// AES-128-GCM opening with a wrong tag (spoil_tag; class 0 all zeros).
export fn dut_aes_gcm_open_tag(data: const u8[:]) -> u8 {
    let key16 = pseudo(11, 16);
    let nonce: u8[12] = [0; 12];
    var s: u8[>..] = [];
    spoil_tag(s, gcm_sealed, data);
    let out, ok = bignum::aes_gcm_open(key16, nonce, "", s);
    return if ok { 1 } else { 0 };
}

// AES-128-CCM opening with a wrong tag, as above.
export fn dut_aes_ccm_open_tag(data: const u8[:]) -> u8 {
    let key16 = pseudo(11, 16);
    let nonce: u8[12] = [0; 12];
    var s: u8[>..] = [];
    spoil_tag(s, ccm_sealed, data);
    let out, ok = bignum::aes_ccm_open(key16, nonce, "", s, 16);
    return if ok { 1 } else { 0 };
}

// ChaCha20-Poly1305 sealing of 64 bytes, the input the key (32 bytes).
export fn dut_chacha20_poly1305_seal(data: const u8[:]) -> u8 {
    let nonce: u8[12] = [0; 12];
    let sealed = bignum::chacha20_poly1305_seal(data[..32], nonce, "", big_x);
    return sealed[79];
}

// ChaCha20-Poly1305 opening with a wrong tag, as above.
export fn dut_chacha20_poly1305_open_tag(data: const u8[:]) -> u8 {
    let key32 = pseudo(12, 32);
    let nonce: u8[12] = [0; 12];
    var s: u8[>..] = [];
    spoil_tag(s, chacha_sealed, data);
    let out, ok = bignum::chacha20_poly1305_open(key32, nonce, "", s);
    return if ok { 1 } else { 0 };
}

// Poly1305 of 64 bytes, the input the one-time key (32 bytes).
export fn dut_poly1305(data: const u8[:]) -> u8 {
    let t = bignum::poly1305(data[..32], big_x);
    return t[0];
}

// HMAC-SHA-256 of 64 bytes, the input the key (32 bytes).
export fn dut_hmac_sha256(data: const u8[:]) -> u8 {
    let t = bignum::hmac_sha256(data[..32], big_x);
    return t[0];
}

// HMAC-SHA-256 over a TLS CBC record's 13-byte header and the first len
// of 64 bytes, len from 32 to 63 taken from the input's first byte (the
// padding's length, which is secret: Lucky13).
export fn dut_hmac_prefix_ct(data: const u8[:]) -> u8 {
    let key: u8[32] = [0x11; 32];
    let hdr: u8[13] = [0x17; 13];
    let len: i64 = 32 + ((data[0] & 31) as i64);
    let t = bignum::hmac_prefix_ct(256, key, hdr, big_x, len, 32);
    return t[0];
}

// The constant-time byte comparison: the input against zeros, so class 0
// is equal throughout and class 1 differs at the first byte (64 bytes).
export fn dut_ct_eq_bytes(data: const u8[:]) -> u8 {
    let zero: u8[64] = [0; 64];
    return bignum::ct_eq_bytes(zero, data[..64]) as! u8;
}

// A control for dut_ct_eq_bytes: the same loads and ORs of the same
// input, no comparison, so whatever it shows comes from the input's
// values (all zeros against random), not from ct_eq_bytes.
export fn dut_or_bytes(data: const u8[:]) -> u8 {
    var acc: u8 = 0;
    for i in 64 { acc = acc | data[i]; }
    return acc;
}

// X25519 with a fixed peer's point, the input the scalar (32 bytes).
export fn dut_x25519(data: const u8[:]) -> u8 {
    let u = pseudo(18, 32);
    let s = bignum::x25519(data[..32], u);
    return s[0];
}

// X448 on the base point, the input the scalar (56 bytes).
export fn dut_x448_base(data: const u8[:]) -> u8 {
    let pk = bignum::x448_base(data[..56]);
    return pk[0];
}

// ECDH on P-256 with a fixed peer, the input the private key (32 bytes,
// top bit cleared so that it is below n).
export fn dut_ecdh_p256(data: const u8[:]) -> u8 {
    var sk: u8[32] = [0; 32];
    for i in 32 { sk[i] = data[i]; }
    sk[0] = sk[0] & 0x7f;
    let curve = bignum::p256();
    let s, ok = bignum::ecdh_shared(curve, sk, p256_peer);
    return if ok { s[0] } else { 0 };
}

// Ed448 signing of one message, the input the seed (57 bytes).
export fn dut_ed448_sign(data: const u8[:]) -> u8 {
    let sig = bignum::ed448_sign(data[..57], "a message");
    return sig[0];
}

// ML-KEM-768 decapsulation under a fixed key, the input the ciphertext
// (1088 bytes): its decompression divides by q (KyberSlash).
export fn dut_mlkem768_decaps(data: const u8[:]) -> u8 {
    let ss, ok = bignum::mlkem_decaps(3, mlkem_seed, data[..1088]);
    return if ok { ss[0] } else { 0 };
}

// ML-KEM-768 decapsulation of a good ciphertext or of one with a byte
// changed (choose; class 0 the good one): implicit rejection must not
// show.
export fn dut_mlkem768_reject(data: const u8[:]) -> u8 {
    var c: u8[>..] = [];
    choose(c, mlkem_ct, mlkem_ct_bad, data);
    let ss, ok = bignum::mlkem_decaps(3, mlkem_seed, c);
    return if ok { ss[0] } else { 0 };
}

// RSA PKCS #1 v1.5 decryption of a 32-byte session key, from a well
// formed block or from one with no 00 after the padding (choose; class 0
// the good one): Bleichenbacher's oracle, and Marvin's timing.
export fn dut_rsa_pkcs1_session_key(data: const u8[:]) -> u8 {
    var c: u8[>..] = [];
    choose(c, pkcs1_good, pkcs1_bad, data);
    var key: u8[32] = [0x42; 32];
    let ok = bignum::rsa_decrypt_pkcs1_session_key(rsa_key, c, key);
    return key[0];
}

// RSA-OAEP decryption of two bad blocks: one whose first byte is not
// zero, one whose label hash is wrong (choose; class 0 the first). Manger's
// attack tells them apart by time.
export fn dut_rsa_oaep_manger(data: const u8[:]) -> u8 {
    var c: u8[>..] = [];
    choose(c, oaep_y1, oaep_hash, data);
    let m, ok = bignum::rsa_decrypt_oaep(rsa_key, c);
    return if ok { 1 } else { 0 };
}
