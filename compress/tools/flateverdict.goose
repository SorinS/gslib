// flateverdict: decodes each case of a cases file with compress.flate,
// compress.zlib or compress.gzip, fed in the chunk sizes the case gives
// and written into an output buffer of the size it gives, for
// scripts/flate_differential.py. A case is a line
//
//   FORMAT CHUNK ROOM HEX [DICTHEX]
//
// (FORMAT raw, zlib, gzip, or gzip1 for one member; "-" for no bytes); the
// result a line: "ok SIZE CRC32" of what decoded, or "err CLASS SIZE
// CRC32" (header, data, checksum, dictionary, truncated, ...) with what
// decoded before the error, as gooracle prints Go's.
//
//	goose tools/flateverdict.goose -- cases.txt

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.zlib;
import gslib.compress.gzip;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn unhex(h: const u8[:], out: u8[>..]&) {
    if h == "-" { return; }
    var i = 0;
    while i + 1 < h.len {
        out.push((hexval(h[i]) * 16 + hexval(h[i + 1])) as! u8);
        i += 2;
    }
}

fn class(e: i64) -> const u8[:] {
    match e {
        compress::ERR_HEADER => "header",
        compress::ERR_DATA => "data",
        compress::ERR_CHECKSUM => "checksum",
        compress::ERR_TRAILING => "trailing",
        compress::ERR_DICTIONARY => "dictionary",
        compress::ERR_TRUNCATED => "truncated",
        _ => "other",
    }
}

// Runs one reader over bin in chunks, output in rooms of `room`: the
// last step's result (< 0 for an error), the size and CRC-32 of the
// output. R(input, out) is the format's read step.
struct Step { used: i64, made: i64, st: i64 }

fn drive<R>(bin: const u8[:], chunk: i64, room: i64, buf: u8[:]) -> i64, i64, u32 {
    var p: i64 = 0;
    var size: i64 = 0;
    var crc: u32 = 0;
    loop {
        let n = min(chunk, bin.len - p);
        let r = R(bin[p..p + n], buf[..room]);
        let used = r.used;
        let made = r.made;
        let st = r.st;
        crc = compress::crc32_update(crc, buf[..made]);
        size += made;
        p += used;
        if st < 0 { return st, size, crc; }
        if st == compress::STREAM_END && p >= bin.len { break; }
        if used == 0 && made == 0 {
            // No progress: the input is all taken (or the stream ended
            // and the rest is not its).
            if p >= bin.len || st == compress::STREAM_END { break; }
        }
    }
    return 0, size, crc;
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: flateverdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("flateverdict: cannot read ", a[1]); exit(1); }
    var out: u8[>..] = [];
    var buf: u8[>..] = [];
    buf.resize(1 << 20, 0);
    each_split(data, '\n') {
        let f = split(trim(it), ' ');
        if f.len >= 4 {
            let chunk, ok1 = parse_int(f[1]);
            let room, ok2 = parse_int(f[2]);
            var bin: u8[>..] = [];
            unhex(f[3], bin);
            var dict: u8[>..] = [];
            if f.len > 4 { unhex(f[4], dict); }
            var e: i64 = 0;
            var size: i64 = 0;
            var crc: u32 = 0;
            if f[0] == "raw" {
                var d = compress::inflate_reader();
                compress::inflate_set_dictionary(d, dict);
                e, size, crc = drive(bin, chunk, room, buf) { i, o => let u, m, t = compress::inflate_read(d, i, o); Step { u, m, t } };
                if e == 0 && !compress::inflate_done(d) { e = compress::ERR_TRUNCATED; }
            } else if f[0] == "zlib" {
                var z = if f.len > 4 { compress::zlib_reader_dict(dict) } else { compress::zlib_reader() };
                e, size, crc = drive(bin, chunk, room, buf) { i, o => let u, m, t = compress::zlib_read(z, i, o); Step { u, m, t } };
                if e == 0 { e = compress::zlib_finish(z); }
            } else {
                var g = compress::gzip_reader();
                if f[0] == "gzip1" { compress::gzip_set_multistream(g, false); }
                e, size, crc = drive(bin, chunk, room, buf) { i, o => let u, m, t = compress::gzip_read(g, i, o); Step { u, m, t } };
                if e == 0 { e = compress::gzip_finish(g); }
            }
            if e != 0 {
                out.append("err ");
                out.append(class(e));
            } else {
                out.append("ok");
            }
            out.push(' ');
            format(out, size);
            out.push(' ');
            format_uint(out, crc, 16, 8, '0');
            out.push('\n');
        }
    };
    write_stdout(out);
    flush_stdout();
}
