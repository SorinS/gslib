// The legacy ciphers, for reading old data and talking to old protocols
// only: triple DES (and DES), Blowfish, CAST5, Twofish, XTEA and RC2 under
// CBC from bignum.modes, then the stream ciphers RC4 and Salsa20/XSalsa20.
// Each round trip is checked, and triple DES against a known answer.
// None of these is for new designs; most are not constant time.
//
//   goose examples/bignum/legacy_ciphers.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.modes;
import gslib.crypto.bignum.des;
import gslib.crypto.bignum.blowfish;
import gslib.crypto.bignum.cast5;
import gslib.crypto.bignum.twofish;
import gslib.crypto.bignum.tea;
import gslib.crypto.bignum.rc2;
import gslib.crypto.bignum.rc4;
import gslib.crypto.bignum.salsa20;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

let MSG: const u8[:] = "an old archive record";

// CBC with PKCS #7 under any block cipher: encrypt, show, decrypt, compare.
fn cbc_round_trip<K>(name: const u8[:], k: const K&) {
    let bs = bignum::cipher_block_len(k);
    var iv: u8[>..] = [];
    iv.resize(bs, 0x42);
    var buf = bignum::pkcs7_pad(MSG, bs);
    bignum::cbc_encrypt(k, iv, buf);
    print(name, ": ", hex(buf[..16]), "...");
    bignum::cbc_decrypt(k, iv, buf);
    let pt, ok = bignum::pkcs7_unpad(buf, bs);
    guard ok && pt == MSG else { print("legacy_ciphers: ", name, " round trip failed"); exit(1); }
}

fn main() {
    let key16 = "0123456789abcdef";
    let key24 = "0123456789abcdef01234567";

    // Triple DES (EDE) with three independent keys: one block, known answer
    // (as `openssl enc -des-ede3 -nopad` gives it).
    let d3 = bignum::des3_init(key24);
    let blk = bignum::des3_encrypt_block(d3, "Now is t");
    guard hex(blk) == "8813f246832d952b" && bignum::des3_decrypt_block(d3, blk)[..] == "Now is t" else {
        print("legacy_ciphers: 3des known answer");
        exit(1);
    }
    cbc_round_trip("des-ede3-cbc ", d3);
    let des = bignum::des_init(key16[..8]);
    let bf = bignum::blowfish_init(key16);
    let c5 = bignum::cast5_init(key16);
    let tf = bignum::twofish_init(key16);
    let xt = bignum::xtea_init(key16);
    let r2c = bignum::rc2_init(key16, 128);    // RC2's effective key bits
    cbc_round_trip("des-cbc      ", des);
    cbc_round_trip("blowfish-cbc ", bf);
    cbc_round_trip("cast5-cbc    ", c5);
    cbc_round_trip("twofish-cbc  ", tf);
    cbc_round_trip("xtea-cbc     ", xt);
    cbc_round_trip("rc2-cbc      ", r2c);

    // RC4: a keyed state that XORs a keystream; decrypt with a fresh state.
    var r = bignum::rc4_init("Key");
    var data: u8[>..] = [];
    data.append("Plaintext");
    bignum::rc4_xor(r, data);
    print("rc4          : ", hex(data));
    guard hex(data) == "bbf316e8d940af0ad3" else { print("legacy_ciphers: rc4 known answer"); exit(1); }
    var r2 = bignum::rc4_init("Key");
    bignum::rc4_xor(r2, data);
    guard data == "Plaintext" else { print("legacy_ciphers: rc4 round trip"); exit(1); }

    // Salsa20 with an 8-byte nonce; XSalsa20 (NaCl's) with a 24-byte one.
    let skey = "an example 32-byte salsa20 key!!";
    for nonce in ["8 bytes!", "a twenty-four byte nonce"] {
        var s: u8[>..] = [];
        s.append(MSG);
        bignum::salsa20_xor(skey, nonce, s);
        print(if nonce.len == 8 { "salsa20      : " } else { "xsalsa20     : " }, hex(s));
        bignum::salsa20_xor(skey, nonce, s);
        guard s == MSG else { print("legacy_ciphers: salsa20 round trip"); exit(1); }
    }
    print("all legacy ciphers round-tripped");
}
