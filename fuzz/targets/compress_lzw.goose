// Fuzz target: compress_lzw. lzw_decode with the bit order (LSB, MSB) and
// the literal width (2 to 8, and a bad one now and then) from the first
// byte, output capped at 1 MiB; and the reader fed in pieces.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.lzw;

let LIMIT: i64 = 1 << 20;

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let b = data[0];
    let order = if b & 1 == 0 { compress::LZW_LSB } else { compress::LZW_MSB };
    let lit_width = 1 + ((b >> 1) & 7) as i64;     // 1..8; 1 is refused
    let src = data[1..];
    if b & 0x80 == 0 {
        var out: u8[>..] = [];
        // A positive limit: lzw_decode's limit < 0 is a known abort.
        let _ = compress::lzw_decode(src, order, lit_width, out, LIMIT);
        return 0;
    }
    var d = compress::lzw_reader(order, lit_width);
    var buf: u8[64] = [0; 64];
    let step = 1 + ((b >> 4) & 7) as i64;
    var p = 0;
    var total = 0;
    var idle = 0;
    while total <= LIMIT && idle < 4 {
        let end = min(src.len, p + step);
        let used, made, st = compress::lzw_read(d, src[p..end], buf[..]);
        p += used;
        total += made;
        if st != 0 { break; }
        if used == 0 && made == 0 { idle++; } else { idle = 0; }
    }
    let _ = compress::lzw_done(d);
    return 0;
}

fn main() {}
