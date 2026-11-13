// deflate_zlib_gzip: compresses a buffer in one call with each of the
// three DEFLATE formats (raw DEFLATE, zlib and gzip) and decompresses it
// back, then shows zlib with a preset dictionary and a capped output
// stopping a decompression bomb.
//
//   goose examples/compress/deflate_zlib_gzip.goose

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.deflate;
import gslib.compress.zlib;
import gslib.compress.gzip;

fn check(ok: bool, what: const u8[:]) {
    guard ok else { print("deflate_zlib_gzip: ", what); exit(1); }
}

fn main() {
    var data: u8[>..] = [];
    for i in 200 { data.append(str("line ", i, ": the quick brown fox jumps over the lazy dog\n")); }

    // Raw DEFLATE (RFC 1951): what zip and PNG carry, with no header.
    var raw: u8[>..] = [];
    check(compress::deflate_encode(data, raw, 6) == 0, "deflate_encode");
    var back: u8[>..] = [];
    var e = compress::inflate_decode(raw, back, 1 << 20);
    check(e == 0 && back[..] == data[..], str("inflate_decode: ", compress::error_text(e)));
    print("deflate: ", data.len, " -> ", raw.len, " bytes");

    // zlib (RFC 1950): two bytes of header, DEFLATE, the Adler-32.
    var z: u8[>..] = [];
    check(compress::zlib_encode(data, z, 9) == 0, "zlib_encode");
    back.clear();
    e = compress::zlib_decode(z, back, 1 << 20);
    check(e == 0 && back[..] == data[..], str("zlib_decode: ", compress::error_text(e)));
    print("zlib:    ", data.len, " -> ", z.len, " bytes");

    // gzip (RFC 1952): what .gz files and HTTP's Content-Encoding hold.
    var gz: u8[>..] = [];
    check(compress::gzip_encode(data, gz, 6) == 0, "gzip_encode");
    check(gz[0] == 0x1f && gz[1] == 0x8b, "gzip magic");
    back.clear();
    e = compress::gzip_decode(gz, back, 1 << 20);
    check(e == 0 && back[..] == data[..], str("gzip_decode: ", compress::error_text(e)));
    print("gzip:    ", data.len, " -> ", gz.len, " bytes");

    // A preset dictionary helps short messages that share words with it.
    // The reader must be given the same dictionary.
    let dict = "the quick brown fox jumps over the lazy dog";
    let msg = "a quick brown fox and a lazy dog";
    var w = compress::zlib_writer_dict(9, dict);
    var zd: u8[>..] = [];
    check(compress::zlib_write(w, msg, zd) == 0 && compress::zlib_close(w, zd) == 0, "zlib with a dictionary");
    back.clear();
    e = compress::zlib_decode(zd, back, -1);
    check(e == compress::ERR_DICTIONARY, "a dictionary stream read without it");
    back.clear();
    e = compress::zlib_decode_dict(zd, dict, back, -1);
    check(e == 0 && back[..] == msg, str("zlib_decode_dict: ", compress::error_text(e)));
    print("zlib with a dictionary: ", msg.len, " -> ", zd.len, " bytes");

    // A limit caps the output: 10 MB of zeros are refused past 64 KiB,
    // having cost no more than that.
    var zeros: u8[>..] = [];
    zeros.resize(10 << 20, 0);
    var bomb: u8[>..] = [];
    check(compress::gzip_encode(zeros, bomb, 9) == 0, "gzip_encode zeros");
    back.clear();
    e = compress::gzip_decode(bomb, back, 65536);
    check(e == compress::ERR_LIMIT, "the limit");
    print("a ", bomb.len, "-byte gzip of 10 MB: ", compress::error_text(e), " at 64 KiB");
}
