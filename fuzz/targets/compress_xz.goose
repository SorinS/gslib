// Fuzz target: compress_xz. The xz, legacy .lzma and raw LZMA2 readers,
// picked by the first byte: .xz (several streams), .xz one stream only,
// .lzma, raw LZMA2 (the dictionary size from the next byte), and .xz fed
// in pieces into a small buffer. The dictionary is held to 16 MiB (the
// default memory limit is 256 MiB) and output to 1 MiB.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;

let LIMIT:    i64 = 1 << 20;
let MEMLIMIT: i64 = 16 << 20;

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let sel = data[0] % 5;
    let src = data[1..];
    var out: u8[>..] = [];
    if sel == 0 || sel == 1 {
        var d = compress::xz_reader();
        compress::xz_set_memlimit(d, MEMLIMIT);
        compress::xz_set_single_stream(d, sel == 1);
        let _ = compress::xz_decode_with(d, src, out, LIMIT);
        let _ = compress::xz_check_unverified(d);
        let _ = compress::xz_check_type(d);
        let _ = compress::xz_finish(d);
    } else if sel == 2 {
        var d = compress::lzma_reader();
        compress::xz_set_memlimit(d, MEMLIMIT);
        let _ = compress::xz_decode_with(d, src, out, LIMIT);
    } else if sel == 3 {
        if src.len < 1 { return 0; }
        var d = compress::lzma2_reader(4096 << (src[0] % 13));
        compress::xz_set_memlimit(d, MEMLIMIT);
        let _ = compress::xz_decode_with(d, src[1..], out, LIMIT);
        let _ = compress::xz_done(d);
    } else {
        if src.len < 1 { return 0; }
        let step = 1 + (src[0] & 15) as i64;
        let room = 1 + ((src[0] >> 4) as i64) * 16;
        let s = src[1..];
        var d = compress::xz_reader();
        compress::xz_set_memlimit(d, MEMLIMIT);
        var buf: u8[256] = [0; 256];
        var p = 0;
        var total = 0;
        var idle = 0;
        while total <= LIMIT && idle < 4 {
            let end = min(s.len, p + step);
            let used, made, st = compress::xz_read(d, s[p..end], buf[..room]);
            p += used;
            total += made;
            if st < 0 { break; }
            if st == compress::STREAM_END && p >= s.len { break; }
            if used == 0 && made == 0 { idle++; } else { idle = 0; }
        }
        let _ = compress::xz_finish(d);
    }
    return 0;
}

fn main() {}
