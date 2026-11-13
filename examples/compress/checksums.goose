// checksums: the CRC-32 of gzip, zip and PNG, the Adler-32 of zlib and
// the CRC-64 of xz, over a whole buffer and over pieces as they come; and
// the CRC-32 found again in a gzip file's trailer.
//
//   goose examples/compress/checksums.goose

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.gzip;

fn hex(v: u64, digits: i64) -> u8[>..] {
    var out: u8[>..] = [];
    format_uint(out, v, 16, digits, '0');
    return out;
}

fn main() {
    // The standard check value of each: the checksum of "123456789".
    let s = "123456789";
    let c32 = compress::crc32(s);
    let a32 = compress::adler32(s);
    let c64 = compress::crc64(s);
    print("crc32   ", hex(c32, 8));
    print("adler32 ", hex(a32, 8));
    print("crc64   ", hex(c64, 16));
    guard c32 == 0xcbf43926 && a32 == 0x091e01de && c64 == 0x995dc9bbdf1939fa else {
        print("checksums: wrong check values");
        exit(1);
    }

    // Data that comes in pieces: start from 0 (CRCs) or 1 (Adler-32) and
    // update with each piece; the result is the whole buffer's.
    var data: u8[>..] = [];
    for i in 100000 { data.push(((i * 31 + i / 7) & 0xff) as! u8); }
    var crc:   u32 = 0;
    var adler: u32 = 1;
    var crc64: u64 = 0;
    var p:     i64 = 0;
    while p < data.len {
        let n = min(4093, data.len - p);
        crc = compress::crc32_update(crc, data[p..p + n]);
        adler = compress::adler32_update(adler, data[p..p + n]);
        crc64 = compress::crc64_update(crc64, data[p..p + n]);
        p += n;
    }
    guard crc == compress::crc32(data) && adler == compress::adler32(data) && crc64 == compress::crc64(data) else {
        print("checksums: the pieces do not add up to the whole");
        exit(1);
    }
    print("100000 bytes in pieces: crc32 ", hex(crc, 8), ", adler32 ", hex(adler, 8), ", crc64 ", hex(crc64, 16));

    // A gzip file ends with the CRC-32 of its data and its size, both
    // little-endian.
    var gz: u8[>..] = [];
    guard compress::gzip_encode(data, gz, 6) == 0 else { print("checksums: gzip_encode"); exit(1); }
    let t = gz.len - 8;
    guard compress::get_le32(gz, t) == crc && compress::get_le32(gz, t + 4) == data.len as! u32 else {
        print("checksums: the gzip trailer differs");
        exit(1);
    }
    print("the gzip trailer holds crc32 ", hex(compress::get_le32(gz, t), 8), " and size ", compress::get_le32(gz, t + 4));
}
