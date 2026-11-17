// AES Key Wrap: a key-encryption key (KEK) wraps a data key for storage
// beside the data it protects (RFC 3394 KW, as JOSE's A256KW and CMS
// use it), checked against RFC 3394 §4.6; then RFC 5649's padded form for
// keys of any length; a wrong KEK or a changed byte fails to unwrap.
//
//   goose examples/bignum/key_wrap.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.keywrap;
import gslib.crypto.bignum.gcm;
import gslib.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn main() {
    // RFC 3394 §4.6: a 256-bit key under a 256-bit KEK.
    let kek0 = unhex("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    let key0 = unhex("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
    let w0, ok0 = bignum::aes_key_wrap(kek0, key0);
    guard ok0 && hex(w0) == "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21" else {
        print("key_wrap: RFC 3394 vector differs");
        exit(1);
    }

    // Envelope encryption: a fresh data key encrypts the data, and only
    // the wrapped data key is stored beside it.
    var kek: u8[32] = [0; 32];
    entropy::random_bytes(kek);
    var dek: u8[32] = [0; 32];
    entropy::random_bytes(dek);
    var nonce: u8[12] = [0; 12];
    entropy::random_bytes(nonce);
    let sealed = bignum::aes_gcm_seal(dek, nonce, "", "customer record #1001");
    let wrapped, okw = bignum::aes_key_wrap(kek, dek);
    guard okw && wrapped.len == 40 else { print("key_wrap: wrap failed"); exit(1); }
    print("wrapped data key ", hex(wrapped));

    // Later: unwrap with the KEK, then open the data.
    let dek2, oku = bignum::aes_key_unwrap(kek, wrapped);
    guard oku else { print("key_wrap: unwrap failed"); exit(1); }
    let data, okd = bignum::aes_gcm_open(dek2, nonce, "", sealed);
    guard okd && data == "customer record #1001" else { print("key_wrap: data did not open"); exit(1); }
    print("unwrapped and opened: ", data);

    // A wrong KEK and a changed byte both fail, alike and in the same time.
    var other: u8[32] = [0; 32];
    entropy::random_bytes(other);
    let k1, bad1 = bignum::aes_key_unwrap(other, wrapped);
    var changed = copy(wrapped);
    changed[20] ^= 0x80;
    let k2, bad2 = bignum::aes_key_unwrap(kek, changed);
    guard !bad1 && !bad2 && k1.len == 0 else { print("key_wrap: a bad unwrap succeeded"); exit(1); }

    // KW wants 16 bytes or more in multiples of 8; KWP (RFC 5649) takes
    // any length from one byte, such as a 20-byte HMAC key.
    let hkey = "twenty byte hmac key";
    let short, oks = bignum::aes_key_wrap(kek, hkey);
    let wp, okp = bignum::aes_key_wrap_pad(kek, hkey);
    let back, okb = bignum::aes_key_unwrap_pad(kek, wp);
    guard !oks && okp && okb && back == hkey else { print("key_wrap: padded wrap failed"); exit(1); }
    print("20-byte key wrapped with padding: ", wp.len, " bytes");
    print("all wraps checked");
}
