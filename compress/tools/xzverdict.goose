// xzverdict: decodes the files a cases file names with compress.xz, fed
// in pieces, for scripts/xz_differential.py. A case is a line
// "MODE CHUNK ROOM PATH": MODE xz, xz1 (single stream), lzma, or lzma2:N
// (raw LZMA2 with an N-byte dictionary); CHUNK the bytes of input a call;
// ROOM the bytes of output a call. Each case gives a line: "ok SIZE CRC32"
// of what decoded, "trailing SIZE CRC32 USED" when the stream ended
// before the input did, "err N", or "short" when the input ended first.
//
//	goose tools/xzverdict.goose -- cases.txt

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;

fn run_case(mode: const u8[:], chunk: i64, room: i64, data: const u8[:], out: u8[>..]&) {
    var d = compress::xz_reader();
    if mode == "lzma" { d = compress::lzma_reader(); }
    else if mode == "xz1" { compress::xz_set_single_stream(d, true); }
    else if starts_with(mode, "lzma2:") {
        let n, ok = parse_int(mode[6..]);
        d = compress::lzma2_reader(n);
    }
    var buf: u8[>..] = [];
    for k in room { buf.push(0); }
    var size = 0;
    var crc: u32 = 0;
    var p = 0;
    var err: i64 = 0;
    while true {
        var hi = p + chunk;
        if hi > data.len { hi = data.len; }
        let used, made, st = compress::xz_read(d, data[p..hi], buf[..room]);
        crc = compress::crc32_update(crc, buf[..made]);
        size += made;
        p += used;
        if st < 0 { err = st; break; }
        if used == 0 && made == 0 { break; }
    }
    if err < 0 { out.append("err "); format(out, err); }
    else if !compress::xz_done(d) { out.append("short"); }
    else if p < data.len {
        out.append("trailing "); format(out, size); out.push(' ');
        format_uint(out, crc, 16, 8, '0'); out.push(' '); format(out, p);
    } else {
        out.append("ok "); format(out, size); out.push(' ');
        format_uint(out, crc, 16, 8, '0');
    }
    out.push('\n');
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: xzverdict cases.txt"); exit(2); }
    var cases: u8[>..] = [];
    if !read_file(a[1], cases) { print("xzverdict: cannot read ", a[1]); exit(1); }
    var out: u8[>..] = [];
    each_split(cases, '\n') {
        let f = split(trim(it), ' ');
        if f.len == 4 {
            let chunk, ok1 = parse_int(f[1]);
            let room, ok2 = parse_int(f[2]);
            var data: u8[>..] = [];
            if !read_file(f[3], data) { out.append("err cannot-read\n"); }
            else { run_case(f[0], chunk, room, data, out); }
        }
    };
    write_stdout(out);
    flush_stdout();
}
