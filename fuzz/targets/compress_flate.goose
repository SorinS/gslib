// Fuzz target: compress_flate. The DEFLATE family's decoders, picked by
// the first byte: raw inflate, gzip (every member), zlib, zlib with a
// preset dictionary, and inflate and gzip fed in small pieces into small
// output buffers (the streaming paths). Output capped at 1 MiB.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.zlib;
import gslib.compress.gzip;

let LIMIT: i64 = 1 << 20;

// Streams `src` into the inflater `step` bytes at a time, into an output
// buffer of `room` bytes, until it ends, fails, stops moving or makes LIMIT.
fn inflate_pieces(src: const u8[:], step: i64, room: i64) {
    var d = compress::inflate_reader();
    var buf: u8[256] = [0; 256];
    var p = 0;
    var total = 0;
    var idle = 0;
    while total <= LIMIT && idle < 4 {
        let end = min(src.len, p + step);
        let used, made, st = compress::inflate_read(d, src[p..end], buf[..room]);
        p += used;
        total += made;
        if st != 0 { break; }
        if used == 0 && made == 0 { idle++; } else { idle = 0; }
    }
    let _ = compress::inflate_done(d);
}

fn gzip_pieces(src: const u8[:], step: i64, room: i64) {
    var r = compress::gzip_reader();
    compress::gzip_set_multistream(r, true);
    var buf: u8[256] = [0; 256];
    var p = 0;
    var total = 0;
    var idle = 0;
    while total <= LIMIT && idle < 4 {
        let end = min(src.len, p + step);
        let used, made, st = compress::gzip_read(r, src[p..end], buf[..room]);
        p += used;
        total += made;
        if st < 0 { break; }
        if st == compress::STREAM_END && p >= src.len { break; }
        if used == 0 && made == 0 { idle++; } else { idle = 0; }
    }
    let _ = compress::gzip_finish(r);
    var name: u8[>..] = [];
    compress::gzip_latin1_to_utf8(r.name[..], name);
    var comment: u8[>..] = [];
    compress::gzip_latin1_to_utf8(r.comment[..], comment);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let sel = data[0] % 6;
    let src = data[1..];
    var out: u8[>..] = [];
    if sel == 0 {
        let _ = compress::inflate_decode(src, out, LIMIT);
    } else if sel == 1 {
        let _ = compress::gzip_decode(src, out, LIMIT);
    } else if sel == 2 {
        let _ = compress::zlib_decode(src, out, LIMIT);
    } else if sel == 3 {
        // A dictionary: the first byte says how many of the next bytes.
        if src.len < 1 { return 0; }
        let n = min(src[0] as i64, src.len - 1);
        let _ = compress::zlib_decode_dict(src[1 + n..], src[1..1 + n], out, LIMIT);
    } else if sel == 4 {
        if src.len < 1 { return 0; }
        inflate_pieces(src[1..], 1 + (src[0] & 15) as i64, 1 + ((src[0] >> 4) as i64) * 16);
    } else {
        if src.len < 1 { return 0; }
        gzip_pieces(src[1..], 1 + (src[0] & 15) as i64, 1 + ((src[0] >> 4) as i64) * 16);
    }
    return 0;
}

fn main() {}
