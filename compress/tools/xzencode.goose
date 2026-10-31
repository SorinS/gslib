// xzencode: compresses the files a cases file names with compress.lzma,
// for scripts/xz_differential.py --encode. A case is a line
// "MODE LEVEL CHECK BLOCK FILTER OPT CHUNK FLUSH IN OUT": MODE xz, lzma
// (size in the header), lzma-1 (end marker) or raw (LZMA2); CHECK, BLOCK
// (block size), FILTER and OPT as xz_writer_opts takes them; the input is
// written CHUNK bytes a call, with a flush every FLUSH bytes (0: none).
// Each case gives a line: "ok SIZE" (for raw: "ok SIZE DICT"), or "err N".
//
//	goose tools/xzencode.goose -- cases.txt

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;
import gslib.compress.lzma;

fn num(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s);
    return v;
}

fn main() {
    let a = args();
    if a.len != 2 { print("usage: xzencode cases.txt"); exit(2); }
    var cases: u8[>..] = [];
    if !read_file(a[1], cases) { print("xzencode: cannot read ", a[1]); exit(1); }
    var report: u8[>..] = [];
    each_split(cases, '\n') {
        let f = split(trim(it), ' ');
        if f.len == 10 {
            var data: u8[>..] = [];
            read_file(f[8], data);
            let level = num(f[1]);
            let chunk = num(f[6]);
            let flush = num(f[7]);
            var w = compress::xz_writer_opts(level, num(f[2]), num(f[3]), num(f[4]) as! u64, num(f[5]));
            if f[0] == "lzma" { w = compress::lzma_writer(level, data.len); }
            else if f[0] == "lzma-1" { w = compress::lzma_writer(level, -1); }
            else if f[0] == "raw" { w = compress::lzma2_writer(level); }
            var out: u8[>..] = [];
            var e: i64 = 0;
            var p = 0;
            var since = 0;
            while p < data.len && e == 0 {
                var n = data.len - p;
                if n > chunk { n = chunk; }
                e = compress::xz_write(w, data[p..p + n], out);
                p += n;
                since += n;
                if flush > 0 && since >= flush && e == 0 && f[0] != "lzma" && f[0] != "lzma-1" {
                    e = compress::xz_flush(w, out);
                    since = 0;
                }
            }
            if e == 0 { e = compress::xz_close(w, out); }
            if e != 0 { format(report, "err ", e, "\n"); }
            else {
                write_file(f[9], out);
                format(report, "ok ", out.len);
                if f[0] == "raw" { format(report, " ", compress::xz_writer_dict_size(w)); }
                report.push('\n');
            }
        }
    };
    write_stdout(report);
    flush_stdout();
}
