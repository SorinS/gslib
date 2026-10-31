// compress: CRC-32, Adler-32 and CRC-64 against known values (zlib's,
// Python's binascii and xz's), in one piece and in pieces of every split.

import std;
import gslib from "../..";
import gslib.compress;

var failures = 0;

fn check(name: const u8[:], got: u64, want: u64) {
    if got != want {
        print("FAIL ", name, ": got ", got, ", want ", want);
        failures++;
    }
}

fn main() {
    let fox = "The quick brown fox jumps over the lazy dog";
    check("crc32 empty", compress::crc32(""), 0);
    check("crc32 fox", compress::crc32(fox), 0x414fa339);
    check("crc32 123456789", compress::crc32("123456789"), 0xcbf43926);
    check("adler32 empty", compress::adler32(""), 1);
    check("adler32 wikipedia", compress::adler32("Wikipedia"), 0x11e60398);
    check("crc64 123456789", compress::crc64("123456789"), 0x995dc9bbdf1939fa);
    check("crc64 empty", compress::crc64(""), 0);
    // Values from Python's zlib over a long run of bytes (i * 7 + i / 256).
    var buf: u8[>..] = [];
    for i in 100000 { buf.push(((i * 7 + i / 256) & 0xff) as! u8); }
    check("crc32 long", compress::crc32(buf), 0xe72bddc1);
    check("adler32 long", compress::adler32(buf), 0xd43b9aef);
    // Any split gives the same result.
    for cut in [0, 1, 7, 8, 9, 5551, 5552, 5553, 65536, 99999, 100000] {
        check("crc32 split", compress::crc32_update(compress::crc32(buf[..cut]), buf[cut..]), 0xe72bddc1);
        check("adler32 split", compress::adler32_update(compress::adler32(buf[..cut]), buf[cut..]), 0xd43b9aef);
        check("crc64 split", compress::crc64_update(compress::crc64(buf[..cut]), buf[cut..]), compress::crc64(buf));
    }
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("checksum: all passed");
}
