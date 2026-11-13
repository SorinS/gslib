// Block cipher modes over AES: CBC with PKCS #7 padding, CTR, CFB and
// OFB, and XTS for disk sectors; then CBC over Camellia, the same mode
// code with another cipher. These modes give no integrity: prefer
// AES-GCM or ChaCha20-Poly1305, or add a MAC (encrypt, then MAC).
//
//   goose examples/bignum/block_modes.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.camellia;
import gslib.crypto.bignum.modes;
import gslib.crypto.bignum.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn fail(what: const u8[:]) { print("block_modes: ", what); exit(1); }

fn main() {
    let msg = "Attack at dawn; bring the blue folder and two pencils.";
    var key: u8[32] = [0; 32];
    bignum::random_bytes(key);
    var iv: u8[16] = [0; 16];
    bignum::random_bytes(iv);
    let k = bignum::aes_init(key);           // AES-256: the key size picks it

    // CBC takes whole blocks: pad, encrypt in place, decrypt, unpad.
    var cbc = bignum::pkcs7_pad(msg);
    bignum::cbc_encrypt(k, iv, cbc);
    print("aes-256-cbc ", msg.len, " bytes -> ", cbc.len, ": ", hex(cbc[..32]), "...");
    bignum::cbc_decrypt(k, iv, cbc);
    let plain, ok = bignum::pkcs7_unpad(cbc);
    guard ok && plain == msg else { fail("cbc round trip"); }

    // The stream modes take any length and need no padding.
    var ctr: u8[>..] = [];
    ctr.append(msg);
    bignum::ctr_xor(k, iv, ctr);
    guard ctr != msg else { fail("ctr did nothing"); }
    bignum::ctr_xor(k, iv, ctr);
    var cfb: u8[>..] = [];
    cfb.append(msg);
    bignum::cfb_encrypt(k, iv, cfb);
    bignum::cfb_decrypt(k, iv, cfb);
    var ofb: u8[>..] = [];
    ofb.append(msg);
    bignum::ofb_xor(k, iv, ofb);
    bignum::ofb_xor(k, iv, ofb);
    guard ctr == msg && cfb == msg && ofb == msg else { fail("a stream mode did not invert"); }
    print("ctr, cfb and ofb round trips ok");

    // XTS: two keys, a sector number as the tweak, whole 16-byte blocks.
    // The same data in two sectors encrypts differently.
    var k2b: u8[32] = [0; 32];
    bignum::random_bytes(k2b);
    let k2 = bignum::aes_init(k2b);
    var s7: u8[512] = [0x55; 512];
    var s8: u8[512] = [0x55; 512];
    bignum::xts_encrypt(k, k2, 7, s7);
    bignum::xts_encrypt(k, k2, 8, s8);
    guard s7[..] != s8[..] else { fail("xts sectors equal"); }
    bignum::xts_decrypt(k, k2, 7, s7);
    for b in s7 { guard b == 0x55 else { fail("xts round trip"); } }
    print("aes-xts sectors 7 and 8 differ, sector 7 decrypts");

    // Every mode is written once over any block cipher: Camellia here, and
    // DES, triple DES and the legacy ciphers likewise (legacy_ciphers.goose).
    let cam = bignum::camellia_init(key[..16]);
    var c2 = bignum::pkcs7_pad(msg);
    bignum::cbc_encrypt(cam, iv, c2);
    bignum::cbc_decrypt(cam, iv, c2);
    let p2, ok2 = bignum::pkcs7_unpad(c2);
    guard ok2 && p2 == msg else { fail("camellia-cbc round trip"); }
    print("camellia-128-cbc round trip ok");

    // Bad padding is reported (in constant time), but on its own that
    // report is a padding oracle: authenticate before decrypting.
    var junk: u8[16] = [0x20; 16];         // a pad byte above the block size
    let pj, okj = bignum::pkcs7_unpad(junk);
    guard !okj else { fail("bad padding accepted"); }
    print("all modes checked");
}
