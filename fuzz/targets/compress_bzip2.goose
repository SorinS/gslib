// Fuzz target: compress_bzip2. bzip2_decode on the whole input, and the
// reader fed in pieces into a small output buffer; output capped at 1 MiB.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.bzip2;

let LIMIT: i64 = 1 << 20;

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let src = data[1..];
    if data[0] & 1 == 0 {
        var out: u8[>..] = [];
        let _ = compress::bzip2_decode(src, out, LIMIT);
        return 0;
    }
    let step = 1 + ((data[0] >> 1) as i64) * 8;
    var d = compress::bzip2_reader();
    var buf: u8[4096] = [0; 4096];
    var p = 0;
    var total = 0;
    var idle = 0;
    while total <= LIMIT && idle < 4 {
        let end = min(src.len, p + step);
        let used, made, st = compress::bzip2_read(d, src[p..end], buf[..]);
        p += used;
        total += made;
        if st < 0 { break; }
        if used == 0 && made == 0 { idle++; } else { idle = 0; }
    }
    let _ = compress::bzip2_done(d);
    let _ = compress::bzip2_streams(d);
    return 0;
}

fn main() {}
