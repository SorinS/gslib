// tour: random bytes shown in hex (the mistake of printing a u8 array
// raw avoided), a SHA-256 digest compared against its published hex, a key
// read back from hex text, refused input, and a dump of some bytes, or of
// FILE when one is given.
//
//   goose examples/hex/tour.goose [-- FILE]

import std;
import os;
import gslib from "../..";
import gslib.encoding.hex;
import gslib.crypto.bignum.sha256;
import gslib.entropy;

fn main() {
    let a = args();
    if a.len > 1 {
        var b: u8[>..] = [];
        guard read_file(a[1], b) else { print("tour: cannot read ", a[1]); exit(1); }
        var d: u8[>..] = [];
        hex::dump(d, b);
        write_stdout(d);
        return;
    }

    // print writes a u8 array as its bytes; hex makes them readable.
    var nonce: u8[12] = [0; 12];
    entropy::random_bytes(nonce);
    let shown = hex::to_str(nonce);
    print("nonce: ", shown);
    assert(shown.len == 24);

    // FIPS 180-2's example: SHA-256("abc"), compared as text.
    let digest = bignum::sha256("abc");
    var up: u8[>..] = [];
    hex::encode_upper(up, digest);
    print("sha256(\"abc\"): ", up);
    assert(hex::to_str(digest) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // A key from a configuration file, in either case.
    var key: u8[>..] = [];
    assert(hex::decode(key, "000102030405060708090A0B0C0D0E0F"));
    print("key: ", key.len, " bytes, last ", key[15]);

    // Anything but pairs of digits is refused, and out is left as it was.
    var bad: u8[>..] = [];
    assert(!hex::decode(bad, "de:ad:be:ef"));
    assert(!hex::decode(bad, "abc"));
    assert(bad.len == 0);
    print("refused: \"de:ad:be:ef\", \"abc\"");

    var d: u8[>..] = [];
    hex::dump(d, "Goose\x00\x01\x02 hex dump, as hexdump -C shows it\n");
    write_stdout(d);
}
