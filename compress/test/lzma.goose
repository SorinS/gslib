// compress.lzma: .xz, .lzma and raw LZMA2 written at every level (fast
// and normal modes), with every check, block sizes, filters, flushes and
// input written in pieces, and read back with compress.xz. scripts/xz_differential.py --encode
// has xz and Python's lzma read thousands more.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;
import gslib.compress.lzma;

var failures = 0;

fn fail(a: const u8[:], b: const u8[:]) {
    print("FAIL ", a, ": ", b);
    failures++;
}

fn sample(kind: i64, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    var r = rng { 12345 + kind as! u64 };
    let words = ["alpha ", "beta ", "gamma ", "delta\n", "goose ", "xz ", "compress "];
    while out.len < n {
        if kind == 0 { out.push((r.rand_u64() & 0xff) as! u8); }
        else if kind == 1 { out.append(words[r.rand_int(7)]); }
        else if kind == 2 { out.push(((out.len * 7 + out.len / 256) & 0xff) as! u8); }
        else {
            // Executable-like: calls with nearby targets among random bytes.
            if r.rand_int(6) == 0 {
                out.push(0xe8);
                let t = (r.rand_int(4000) - 2000) as! u32;
                for k in 4 { out.push(((t >> ((8 * k) as! u32)) & 0xff) as! u8); }
            } else {
                out.push((r.rand_u64() & 0xff) as! u8);
            }
        }
    }
    out.resize(n);
    return out;
}

fn decode_xz(s: const u8[:], want: const u8[:], what: const u8[:]) {
    var back: u8[>..] = [];
    let e = compress::xz_decode(s, back, -1);
    if e != 0 || back[..] != want { fail(what, str("read back: ", e, ", ", back.len, " bytes of ", want.len)); }
}

fn whole() {
    for kind in 4 {
        for n in [0, 1, 300, 20000] {
            let data = sample(kind, n);
            for level in 10 {
                var x: u8[>..] = [];
                if compress::xz_encode(data, x, level) != 0 { fail("xz_encode", "error"); }
                decode_xz(x, data, str("xz level ", level, " kind ", kind, " n ", n));
                var l: u8[>..] = [];
                if compress::lzma_encode(data, l, level) != 0 { fail("lzma_encode", "error"); }
                var lb: u8[>..] = [];
                let e = compress::lzma_decode(l, lb, -1);
                if e != 0 || lb[..] != data[..] { fail(str("lzma level ", level, " kind ", kind, " n ", n), str(e)); }
            }
            var raw: u8[>..] = [];
            let dict = compress::lzma2_encode(data, raw, 3);
            var d = compress::lzma2_reader(dict);
            var o: u8[>..] = [];
            o.resize(n + 10, 0);
            let used, made, st = compress::xz_read(d, raw, o);
            if st != compress::STREAM_END || used != raw.len || o[..made] != data[..] { fail("raw lzma2", str(st)); }
        }
    }
    // Incompressible data is stored in uncompressed chunks: it grows little.
    let rnd = sample(0, 200000);
    var x: u8[>..] = [];
    compress::xz_encode(rnd, x, 6);
    if x.len > rnd.len + 200 { fail("random data", str(x.len, " bytes")); }
    decode_xz(x, rnd, "random 200000");
}

fn streaming() {
    let data = sample(1, 150000);
    let exe = sample(3, 60000);
    var cases = 0;
    for check in [0, 1, 4, 10] {
        for bsize in [0, 1, 777, 65536] {
            for chunk in [1, 1000, 1 << 20] {
                if chunk == 1 && bsize != 777 { continue; }
                let src = if bsize == 1 { data[..3000] } else { data[..] };
                var w = compress::xz_writer_opts(if check == 4 && chunk == 1000 { 6 } else { 2 }, check, bsize, 0, 0);
                var out: u8[>..] = [];
                var p = 0;
                var k = 0;
                while p < src.len {
                    var n = src.len - p;
                    if n > chunk { n = chunk; }
                    compress::xz_write(w, src[p..p + n], out);
                    p += n;
                    k++;
                    if k % 7 == 0 { compress::xz_flush(w, out); }
                }
                compress::xz_close(w, out);
                // The stream header names the check.
                if out[7] != check as! u8 { fail("check flag", str(out[7])); }
                decode_xz(out, src, str("check ", check, " block ", bsize, " chunk ", chunk));
                cases++;
            }
        }
    }
    // Filters.
    for f in [3, 4, 5, 6, 7, 8, 9, 10] {
        for opt in [0, 1, 4] {
            let o = if f == 3 { opt + 1 } else { opt * 16 };
            var w = compress::xz_writer_opts(1, 4, 0, f as! u64, o);
            var out: u8[>..] = [];
            compress::xz_write(w, exe[..33333], out);
            compress::xz_write(w, exe[33333..], out);
            compress::xz_close(w, out);
            decode_xz(out, exe, str("filter ", f, " opt ", o));
        }
    }
    // A known .lzma size is kept to.
    var lw = compress::lzma_writer(1, 10);
    var lo: u8[>..] = [];
    if compress::xz_write(lw, "0123456789x", lo) != compress::ERR_ARGUMENT { fail("lzma size", "more taken"); }
    var lw2 = compress::lzma_writer(1, 10);
    compress::xz_write(lw2, "012345678", lo);
    if compress::xz_close(lw2, lo) != compress::ERR_ARGUMENT { fail("lzma size", "less taken"); }
    var lw3 = compress::lzma_writer(1, -1);
    var lo3: u8[>..] = [];
    compress::xz_write(lw3, data[..5000], lo3);
    compress::xz_close(lw3, lo3);
    var lb: u8[>..] = [];
    if compress::lzma_decode(lo3, lb, -1) != 0 || lb[..] != data[..5000] { fail("lzma end marker", "read back"); }
    if compress::xz_writer_opts(1, 2, 0, 0, 0).err != compress::ERR_ARGUMENT { fail("check 2", "taken"); }
    var bad: u8[>..] = [];
    if compress::xz_encode("x", bad, 10) != compress::ERR_ARGUMENT { fail("level 10", "taken"); }
}

fn main() {
    whole();
    streaming();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("lzma: all passed");
}
