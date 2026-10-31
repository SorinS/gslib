// zipmake: writes a zip archive with compress.zip from a spec, for
// scripts/zip_differential.py (`gooracle zipmake` writes the same spec
// with Go's archive/zip). A spec is lines of
//
//   comment HEX                       the archive's comment
//   offset N                          zip_set_offset
//   create NAME_HEX DATAFILE CHUNK    zip_create (Go's Create): Deflate
//   file NAME_HEX METHOD MODSECS MODOFF MODE CMT_HEX EXTRA_HEX NONUTF8 DATAFILE CHUNK
//                                     zip_create_header: MODSECS "-" for no
//                                     time (else the time at zone offset
//                                     MODOFF), MODE "-" or Go's FileMode in hex,
//                                     DATAFILE "-" for no data, written CHUNK
//                                     bytes at a time
//   raw NAME_HEX METHOD FLAGS CRC_HEX CSIZE USIZE CREATOR READER DATAFILE
//                                     zip_create_raw, DATAFILE written as it is
//   copy ARCHIVE                      zip_copy of every file of ARCHIVE
//
// ("-" for an empty HEX).
//
//	goose tools/zipmake.goose -- spec.txt out.zip

import std;
import os;
import compress from "..";
import compress.zip;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn unhex(h: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if h == "-" { return out; }
    var i = 0;
    while i + 1 < h.len {
        out.push((hexval(h[i]) * 16 + hexval(h[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s);
    if !ok { print("zipmake: bad number ", s); exit(2); }
    return v;
}

fn write_data(w: compress::ZipWriter&, path: const u8[:], chunk: i64, out: u8[>..]&) {
    if path == "-" { return; }
    var data: u8[>..] = [];
    if !read_file(path, data) { print("zipmake: cannot read ", path); exit(1); }
    var p: i64 = 0;
    while p < data.len {
        let n = min(chunk, data.len - p);
        let e = compress::zip_write(w, data[p..p + n], out);
        if e != 0 { print("zipmake: write: ", e); exit(1); }
        p += n;
    }
    if data.len == 0 {
        let e = compress::zip_write(w, "", out);
        if e != 0 { print("zipmake: write: ", e); exit(1); }
    }
}

fn main() {
    let a = args();
    if a.len != 3 { print("usage: zipmake spec.txt out.zip"); exit(2); }
    var spec: u8[>..] = [];
    if !read_file(a[1], spec) { print("zipmake: cannot read ", a[1]); exit(1); }
    var w = compress::zip_writer();
    var out: u8[>..] = [];
    each_split(spec, '\n') {
        let f = split(trim(it), ' ');
        if f.len >= 2 {
            if f[0] == "comment" {
                if compress::zip_set_comment(w, unhex(f[1])) != 0 { print("zipmake: comment"); exit(1); }
            } else if f[0] == "offset" {
                if compress::zip_set_offset(w, num(f[1])) != 0 { print("zipmake: offset"); exit(1); }
            } else if f[0] == "create" {
                let e = compress::zip_create(w, unhex(f[1]), out);
                if e != 0 { print("zipmake: create: ", e); exit(1); }
                write_data(w, f[2], num(f[3]), out);
            } else if f[0] == "raw" {
                let crc, ok = parse_int(f[4], 16);
                var h = compress::ZipHeader { name: unhex(f[1]), creator_version: num(f[7]) as! u16,
                                              reader_version: num(f[8]) as! u16, flags: num(f[3]) as! u16,
                                              method: num(f[2]) as! u16, crc32: crc as! u32,
                                              compressed_size64: num(f[5]) as! u64,
                                              uncompressed_size64: num(f[6]) as! u64, .. };
                let e = compress::zip_create_raw(w, h, out);
                if e != 0 { print("zipmake: create_raw: ", e); exit(1); }
                write_data(w, f[9], 1 << 30, out);
            } else if f[0] == "copy" {
                var src: u8[>..] = [];
                if !read_file(f[1], src) { print("zipmake: cannot read ", f[1]); exit(1); }
                let r = compress::zip_open(src);
                if r.err != 0 { print("zipmake: open: ", r.err); exit(1); }
                for e in r.entries {
                    let c = compress::zip_copy(w, r, src, e, out);
                    if c != 0 { print("zipmake: copy: ", c); exit(1); }
                }
            } else if f[0] == "file" {
                var h = compress::ZipHeader { name: unhex(f[1]), comment: unhex(f[6]), extra: unhex(f[7]),
                                              non_utf8: f[8] == "1", method: num(f[2]) as! u16, .. };
                if f[3] != "-" { h.modified = compress::zip_time(num(f[3]), 0, num(f[4])); }
                if f[5] != "-" {
                    let m, ok = parse_int(f[5], 16);
                    compress::zip_header_set_mode(h, m as! u32);
                }
                let e = compress::zip_create_header(w, h, out);
                if e != 0 { print("zipmake: create_header: ", e); exit(1); }
                write_data(w, f[9], num(f[10]), out);
            }
        }
    };
    let e = compress::zip_close(w, out);
    if e != 0 { print("zipmake: close: ", e); exit(1); }
    if !write_file(a[2], out) { print("zipmake: cannot write ", a[2]); exit(1); }
}
