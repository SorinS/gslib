// bzip2verdict: compress.bzip2 for scripts/bzip2_differential.py. A cases
// file holds one case a line:
//
//   d CHUNK ROOM HEX     decode HEX ("-" for no bytes) fed CHUNK bytes at a
//                        time, with ROOM bytes of output a call; prints
//                        "ok SIZE CRC32", "err N", or "short" when the
//                        input ended inside a stream
//   c LEVEL CHUNK HEX    compress HEX at LEVEL, written CHUNK bytes at a
//                        time; prints the stream in hex
//
//	goose tools/bzip2verdict.goose -- cases.txt

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.bzip2;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn unhex(h: const u8[:], bin: u8[>..]&) {
    if h == "-" { return; }
    var i = 0;
    while i + 1 < h.len {
        bin.push((hexval(h[i]) * 16 + hexval(h[i + 1])) as! u8);
        i += 2;
    }
}

let HEX = "0123456789abcdef";

fn decode_case(chunk: i64, room: i64, bin: const u8[:], out: u8[>..]&) {
    var d = compress::bzip2_reader();
    var buf: u8[65536] = [0; 65536];
    let r = if room < 65536 { room } else { 65536 };
    var size: i64 = 0;
    var crc: u32 = 0;
    var e: i64 = 0;
    var p = 0;
    loop {
        let n = if bin.len - p < chunk { bin.len - p } else { chunk };
        let used, made, st = compress::bzip2_read(d, bin[p..p + n], buf[..r]);
        crc = compress::crc32_update(crc, buf[..made]);
        size += made;
        p += used;
        if st < 0 { e = st; break; }
        if used == 0 && made == 0 { break; }
    }
    if e != 0 { out.append("err "); format(out, e); }
    else if !compress::bzip2_done(d) { out.append("short"); }
    else {
        out.append("ok ");
        format(out, size);
        out.push(' ');
        format_uint(out, crc, 16, 8, '0');
    }
}

fn encode_case(level: i64, chunk: i64, bin: const u8[:], out: u8[>..]&) {
    var w = compress::bzip2_writer(level);
    var z: u8[>..] = [];
    var p = 0;
    var e: i64 = 0;
    while p < bin.len && e == 0 {
        let n = if bin.len - p < chunk { bin.len - p } else { chunk };
        e = compress::bzip2_write(w, bin[p..p + n], z);
        p += n;
    }
    if e == 0 { e = compress::bzip2_close(w, z); }
    if e != 0 { out.append("err "); format(out, e); return; }
    for b in z {
        out.push(HEX[b >> 4]);
        out.push(HEX[b & 15]);
    }
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: bzip2verdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("bzip2verdict: cannot read ", a[1]); exit(1); }
    each_split(data, '\n') {
        let f = split(trim(it), ' ');
        if f.len == 4 {
            var out: u8[>..] = [];
            var bin: u8[>..] = [];
            unhex(f[3], bin);
            let x, ok1 = parse_int(f[1]);
            let y, ok2 = parse_int(f[2]);
            if f[0] == "d" { decode_case(x, y, bin, out); } else { encode_case(x, y, bin, out); }
            out.push('\n');
            write_stdout(out);
        }
    };
    flush_stdout();
}
