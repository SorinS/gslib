// Message authentication: HMAC over SHA-256 and SHA3-256, AES-CMAC and
// Camellia-CMAC with a truncated tag, and one-time Poly1305. Each tag is
// checked in constant time, and a changed message is refused.
//
//   goose examples/bignum/mac.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.ct;
import gslib.crypto.bignum.aes;
import gslib.crypto.bignum.camellia;
import gslib.crypto.bignum.cmac;
import gslib.crypto.bignum.chacha20;
import gslib.entropy;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    let msg = "transfer 100 to account 42";
    let forged = "transfer 900 to account 42";

    // HMAC: RFC 4231's test case 2, then any hash by id.
    let t = bignum::hmac_sha256("Jefe", "what do ya want for nothing?");
    guard hex(t) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" else {
        print("mac: hmac-sha256 is wrong");
        exit(1);
    }
    var key: u8[32] = [0; 32];
    entropy::random_bytes(key);
    let tag = bignum::hmac(256, key, msg);
    print("hmac-sha256     ", hex(tag));
    print("hmac-sha3-256   ", hex(bignum::hmac(bignum::HASH_SHA3_256, key, msg)));
    // Compare tags in constant time, never with ==, which stops early.
    guard bignum::ct_eq_bytes(bignum::hmac(256, key, msg), tag) == 1 &&
          bignum::ct_eq_bytes(bignum::hmac(256, key, forged), tag) == 0 else {
        print("mac: hmac check failed");
        exit(1);
    }

    // CMAC over a block cipher: the key is expanded once, and the tag may
    // be cut to its leading bytes (8 here).
    var k16: u8[16] = [0; 16];
    entropy::random_bytes(k16);
    let aes = bignum::aes_init(k16);
    let full = bignum::cmac(aes, msg);
    let short = full[..8];
    print("aes-cmac        ", hex(full), " (sent: ", hex(short), ")");
    guard bignum::cmac_verify(aes, msg, short) && !bignum::cmac_verify(aes, forged, short) else {
        print("mac: aes-cmac check failed");
        exit(1);
    }
    let cam = bignum::camellia_init(k16);
    let ctag = bignum::cmac(cam, msg);
    print("camellia-cmac   ", hex(ctag));
    guard bignum::cmac_verify(cam, msg, ctag) && !bignum::cmac_verify(cam, forged, ctag) else {
        print("mac: camellia-cmac check failed");
        exit(1);
    }

    // Poly1305 is a one-time MAC: a fresh 32-byte key for every message
    // (ChaCha20-Poly1305 derives one per nonce). It streams too.
    var otk: u8[32] = [0; 32];
    entropy::random_bytes(otk);
    let p = bignum::poly1305(otk, msg);
    var st = bignum::poly1305_init(otk);
    bignum::poly1305_update(st, msg[..9]);
    bignum::poly1305_update(st, msg[9..]);
    let p2 = bignum::poly1305_final(st);
    print("poly1305        ", hex(p));
    guard bignum::ct_eq_bytes(p, p2) == 1 && bignum::ct_eq_bytes(bignum::poly1305(otk, forged), p) == 0 else {
        print("mac: poly1305 check failed");
        exit(1);
    }
    print("every tag verified, every forgery refused");
}
