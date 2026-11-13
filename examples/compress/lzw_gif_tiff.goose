// lzw_gif_tiff: LZW as GIF uses it (least significant bit first, here
// with 4-bit pixels) and as TIFF and PDF use it (most significant bit
// first, bytes), each in one call and back; then the TIFF order read as a
// stream.
//
//   goose examples/compress/lzw_gif_tiff.goose

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.lzw;

fn main() {
    // A 64 x 64 image of 16 colours: stripes, so it compresses well.
    var pixels: u8[>..] = [];
    for y in 64 { for x in 64 { pixels.push((((x + y) / 8) % 16) as! u8); } }

    // GIF: the literal width is the colour depth (2-8 bits).
    var gif: u8[>..] = [];
    var e = compress::lzw_encode(pixels, compress::LZW_LSB, 4, gif);
    guard e == 0 else { print("lzw_gif_tiff: lzw_encode: ", compress::error_text(e)); exit(1); }
    var back: u8[>..] = [];
    e = compress::lzw_decode(gif, compress::LZW_LSB, 4, back);
    guard e == 0 && back[..] == pixels[..] else { print("lzw_gif_tiff: lzw_decode: ", compress::error_text(e)); exit(1); }
    print("GIF order, 4-bit pixels: ", pixels.len, " -> ", gif.len, " bytes");

    // A pixel wider than the literal width is refused.
    var bad: u8[>..] = [];
    guard compress::lzw_encode("\x10", compress::LZW_LSB, 4, bad) == compress::ERR_ARGUMENT else {
        print("lzw_gif_tiff: a 5-bit pixel was taken");
        exit(1);
    }

    // TIFF and PDF: bytes, most significant bit first.
    var text: u8[>..] = [];
    for i in 500 { text.append("TOBEORNOTTOBEORTOBEORNOT "); }
    var tiff: u8[>..] = [];
    e = compress::lzw_encode(text, compress::LZW_MSB, 8, tiff);
    guard e == 0 else { print("lzw_gif_tiff: lzw_encode: ", compress::error_text(e)); exit(1); }
    print("TIFF order, bytes: ", text.len, " -> ", tiff.len, " bytes");

    // The same read as a stream: 100 bytes at a time into 256 bytes of
    // room, until the end code.
    var d = compress::lzw_reader(compress::LZW_MSB, 8);
    var room: u8[256] = [0; 256];
    back.clear();
    var q: i64 = 0;
    loop {
        let n = min(100, tiff.len - q);
        let used, made, st = compress::lzw_read(d, tiff[q..q + n], room);
        back.append(room[..made]);
        q += used;
        guard st >= 0 else { print("lzw_gif_tiff: lzw_read: ", compress::error_text(st)); exit(1); }
        if st == compress::STREAM_END || (q == tiff.len && made == 0) { break; }
    }
    guard compress::lzw_done(d) && back[..] == text[..] else { print("lzw_gif_tiff: the stream did not read back"); exit(1); }
    print("read back as a stream: ", back.len, " bytes");
}
