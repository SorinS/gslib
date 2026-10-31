// lzwverdict: runs compress.lzw over a cases file in the format of
// `gooracle lzw` and prints the same lines, for scripts/lzw_differential.py.
// A case is "enc|dec ORDER LITWIDTH HEX" a line (ORDER lsb or msb, HEX "-"
// for none); the output is that of `gooracle lzw`. Decoding is fed IN bytes of input at a time into OUT bytes of
// room at a time.
//
//	goose tools/lzwverdict.goose -- cases.txt [IN [OUT]]

import std;
import os;
import compress from "..";
import compress.lzw;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn put_hex(out: u8[>..]&, b: const u8[:]) {
    if b.len == 0 { out.push('-'); return; }
    let digits = "0123456789abcdef";
    for x in b {
        out.push(digits[x >> 4]);
        out.push(digits[x & 15]);
    }
}

fn put_len_crc(out: u8[>..]&, b: const u8[:]) {
    format(out, b.len);
    out.push(' ');
    format_uint(out, compress::crc32(b), 16, 8, '0');
}

fn main() {
    let a = args();
    if a.len < 2 { write_stderr("usage: lzwverdict cases.txt [IN [OUT]]\n"); exit(2); }
    var inchunk = 1 << 40;
    var outroom = 4096;
    if a.len > 2 { let v, ok = parse_int(a[2]); inchunk = v; }
    if a.len > 3 { let v, ok = parse_int(a[3]); outroom = v; }
    var data: u8[>..] = [];
    if !read_file(a[1], data) { write_stderr("lzwverdict: cannot read the cases\n"); exit(1); }
    var out: u8[>..] = [];
    var room: u8[>..] = [];
    room.resize(outroom, 0);
    each_split(data, '\n') {
        let f = split(trim(it), ' ');
        if f.len == 4 {
            let order = if f[1] == "msb" { compress::LZW_MSB } else { compress::LZW_LSB };
            let lw, ok = parse_int(f[2]);
            var bin: u8[>..] = [];
            let h = if f[3] == "-" { "" } else { f[3] };
            var i = 0;
            while i + 1 < h.len { bin.push((hexval(h[i]) * 16 + hexval(h[i + 1])) as! u8); i += 2; }
            if f[0] == "enc" {
                var enc: u8[>..] = [];
                var w = compress::lzw_writer(order, lw);
                // Written in pieces as the input chunk says, to test that too.
                var e: i64 = 0;
                var p = 0;
                while p < bin.len && e == 0 {
                    let n = if bin.len - p < inchunk { bin.len - p } else { inchunk };
                    e = compress::lzw_write(w, bin[p..p + n], enc);
                    p += n;
                }
                if e == 0 { e = compress::lzw_close(w, enc); }
                if e != 0 { out.append("err litwidth"); }
                else { out.append("ok "); put_hex(out, enc); }
            } else {
                var dec: u8[>..] = [];
                var d = compress::lzw_reader(order, lw);
                var p = 0;
                var st: i64 = 0;
                loop {
                    let n = if bin.len - p < inchunk { bin.len - p } else { inchunk };
                    let used, made, s = compress::lzw_read(d, bin[p..p + n], room);
                    p += used;
                    dec.append(room[..made]);
                    st = s;
                    if st != 0 { break; }
                    if made == 0 && used == 0 && p >= bin.len { break; }
                }
                if st == compress::STREAM_END { out.append("ok "); put_len_crc(out, dec); }
                else if st == compress::ERR_DATA { out.append("err invalid-code "); put_len_crc(out, dec); }
                else if st == 0 { out.append("err unexpected-eof "); put_len_crc(out, dec); }
                else { out.append("err other "); format(out, st); }
            }
            out.push('\n');
        }
    };
    write_stdout(out);
    flush_stdout();
}
