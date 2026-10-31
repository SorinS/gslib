// deflateverdict: compresses each case of a cases file with
// compress.deflate (raw), compress.zlib or compress.gzip, for
// scripts/deflate_differential.py. A case is a line
//
//   FORMAT LEVEL CHUNK FLUSH HEX [DICTHEX]
//
// (FORMAT raw, zlib or gzip; the data written CHUNK bytes a call, with a
// Flush after every FLUSH bytes, 0 for none; "-" for no bytes). The result
// a line: the stream in hex ("-" for none), then the stream's length after
// each flush, then the input's length at each flush, comma-separated ("-"
// for none); or "err CODE".
//
//	goose tools/deflateverdict.goose -- cases.txt

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.deflate;
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

let HEX = "0123456789abcdef";

fn main() {
    let a = args();
    if a.len != 2 { print("usage: deflateverdict cases.txt"); exit(2); }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { print("deflateverdict: cannot read ", a[1]); exit(1); }
    var res: u8[>..] = [];
    each_split(data, '\n') {
        let f = split(trim(it), ' ');
        if f.len >= 5 {
            let level, ok1 = parse_int(f[1]);
            let chunk, ok2 = parse_int(f[2]);
            let flush, ok3 = parse_int(f[3]);
            var bin: u8[>..] = [];
            unhex(f[4], bin);
            var dict: u8[>..] = [];
            let has_dict = f.len > 5;
            if has_dict { unhex(f[5], dict); }
            var out: u8[>..] = [];
            var marks: i64[>..] = [];
            var inmarks: i64[>..] = [];
            var e: i64 = 0;
            var d = if has_dict { compress::deflate_writer_dict(level, dict) } else { compress::deflate_writer(level) };
            var z = if has_dict { compress::zlib_writer_dict(level, dict) } else { compress::zlib_writer(level) };
            var g = compress::gzip_writer(level);
            var p: i64 = 0;
            var since: i64 = 0;
            while p < bin.len && e == 0 {
                var n = min(chunk, bin.len - p);
                if flush > 0 { n = min(n, flush - since); }
                let part = bin[p..p + n];
                if f[0] == "raw" { e = compress::deflate_write(d, part, out); }
                else if f[0] == "zlib" { e = compress::zlib_write(z, part, out); }
                else { e = compress::gzip_write(g, part, out); }
                p += n;
                since += n;
                if flush > 0 && since == flush && e == 0 {
                    if f[0] == "raw" { e = compress::deflate_flush(d, out); }
                    else if f[0] == "zlib" { e = compress::zlib_flush(z, out); }
                    else { e = compress::gzip_flush(g, out); }
                    marks.push(out.len);
                    inmarks.push(p);
                    since = 0;
                }
            }
            if e == 0 {
                if f[0] == "raw" { e = compress::deflate_close(d, out); }
                else if f[0] == "zlib" { e = compress::zlib_close(z, out); }
                else { e = compress::gzip_close(g, out); }
            }
            if e != 0 {
                res.append("err ");
                format(res, e);
            } else {
                if out.len == 0 { res.push('-'); }
                for b in out {
                    res.push(HEX[b >> 4]);
                    res.push(HEX[b & 15]);
                }
                res.push(' ');
                if marks.len == 0 { res.append("- -"); }
                else {
                    for m, i in marks {
                        if i > 0 { res.push(','); }
                        format(res, m);
                    }
                    res.push(' ');
                    for m, i in inmarks {
                        if i > 0 { res.push(','); }
                        format(res, m);
                    }
                }
            }
            res.push('\n');
        }
    };
    write_stdout(res);
    flush_stdout();
}
