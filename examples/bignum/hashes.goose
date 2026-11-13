// Hashing: SHA-256 and SHA-512 one-shot and streaming, SHA3-256, SHAKE128
// read in pieces, cSHAKE, BLAKE2b (plain and keyed) and BLAKE2Xb, the
// generic hash_bits by id, and MD5, SHA-1, MD4 and RIPEMD-160 for the
// legacy formats that still carry them.
//
//   goose examples/bignum/hashes.goose
import std;
import os;
import gslib from "../..";
import gslib.crypto.bignum;
import gslib.crypto.bignum.sha256;
import gslib.crypto.bignum.sha512;
import gslib.crypto.bignum.sha3;
import gslib.crypto.bignum.blake2;
import gslib.crypto.bignum.hmac;
import gslib.crypto.bignum.md5;
import gslib.crypto.bignum.sha1;
import gslib.crypto.bignum.md4;
import gslib.crypto.bignum.ripemd160;

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_uint(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    let msg = "The quick brown fox jumps over the lazy dog";

    // SHA-256, with a known answer, then the same digest fed in pieces.
    let d = bignum::sha256(msg);
    print("sha256      ", hex(d));
    guard hex(d) == "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592" else {
        print("hashes: sha256 is wrong");
        exit(1);
    }
    var s = bignum::sha256_init();
    bignum::sha256_update(s, msg[..10]);
    bignum::sha256_update(s, msg[10..]);
    guard bignum::sha256_final(s)[..] == d[..] else { print("hashes: streaming sha256 differs"); exit(1); }

    // SHA-512 streams the same way (sha384_init and the /224, /256 forms too).
    var s5 = bignum::sha512_init();
    for w in split(msg, ' ') { bignum::sha512_update(s5, w); bignum::sha512_update(s5, " "); }
    var spaced: u8[>..] = [];
    for w in split(msg, ' ') { spaced.append(w); spaced.push(' '); }
    guard bignum::sha512_final(s5) == bignum::sha512(spaced) else { print("hashes: streaming sha512 differs"); exit(1); }
    print("sha384      ", hex(bignum::sha384(msg)));

    // SHA-3, and SHAKE128 as an extendable output: 32 bytes at once equal
    // 10 then 22 bytes squeezed from the same state.
    print("sha3-256    ", hex(bignum::sha3(256, msg)));
    let xof = bignum::shake(128, msg, 32);
    var k = bignum::shake_init(128);
    bignum::sha3_update(k, msg);
    var part: u8[32] = [0; 32];
    bignum::shake_read(k, part[..10]);
    bignum::shake_read(k, part[10..]);
    guard part[..] == xof[..] else { print("hashes: shake read in pieces differs"); exit(1); }
    print("shake128    ", hex(xof));
    print("cshake256   ", hex(bignum::cshake(256, "", "my app v1", msg, 32)));

    // BLAKE2: any output length, and keyed it is a MAC.
    print("blake2b-256 ", hex(bignum::blake2b(msg, 32)));
    print("blake2s     ", hex(bignum::blake2s(msg)));
    let mac = bignum::blake2b(msg, 32, "a secret key");
    guard mac != bignum::blake2b(msg, 32) else { print("hashes: keyed blake2b ignored its key"); exit(1); }
    print("blake2xb    ", hex(bignum::blake2xb(msg, 48)));

    // The generic form names a hash by id, as HMAC, HKDF and RSA do.
    guard bignum::hash_bits(256, msg)[..] == d[..] &&
          bignum::hash_bits(bignum::HASH_SHA3_256, msg) == bignum::sha3(256, msg) else {
        print("hashes: hash_bits disagrees");
        exit(1);
    }

    // Legacy: for checksums and old formats only, never for new security.
    print("md5         ", hex(bignum::md5(msg)));
    print("sha1        ", hex(bignum::sha1(msg)));
    print("md4         ", hex(bignum::md4(msg)));
    print("ripemd160   ", hex(bignum::ripemd160(msg)));
    guard hex(bignum::md5(msg)) == "9e107d9d372bb6826bd81d3542a419d6" else { print("hashes: md5 is wrong"); exit(1); }
    print("all digests checked");
}
