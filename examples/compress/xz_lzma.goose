// xz_lzma: compresses a buffer as .xz and as the older .lzma in one call
// and reads both back; then writes an .xz stream in pieces with a SHA-256
// check and a Delta filter (good for samples and tables of numbers), and
// reads it a piece at a time.
//
//   goose examples/compress/xz_lzma.goose

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;
import gslib.compress.lzma;

fn main() {
    var data: u8[>..] = [];
    for i in 3000 { data.append(str("record ", i, " goose ", i * i % 977, "\n")); }

    // .xz: levels 0-9 are xz's presets; xz_encode sizes the dictionary to
    // the input, so level 9 costs little here.
    var x: u8[>..] = [];
    var e = compress::xz_encode(data, x, 9);
    guard e == 0 else { print("xz_lzma: xz_encode: ", compress::error_text(e)); exit(1); }
    var back: u8[>..] = [];
    e = compress::xz_decode(x, back, 1 << 24);
    guard e == 0 && back[..] == data[..] else { print("xz_lzma: xz_decode: ", compress::error_text(e)); exit(1); }
    print(".xz:   ", data.len, " -> ", x.len, " bytes");

    // .lzma (LZMA_Alone): a 13-byte header with the size, then LZMA.
    var l: u8[>..] = [];
    e = compress::lzma_encode(data, l, 6);
    guard e == 0 else { print("xz_lzma: lzma_encode: ", compress::error_text(e)); exit(1); }
    back.clear();
    e = compress::lzma_decode(l, back, 1 << 24);
    guard e == 0 && back[..] == data[..] else { print("xz_lzma: lzma_decode: ", compress::error_text(e)); exit(1); }
    print(".lzma: ", data.len, " -> ", l.len, " bytes");

    // 16-bit samples of a sawtooth wave: a Delta filter of distance 2 turns
    // them into small differences, which LZMA2 then packs well.
    var pcm: u8[>..] = [];
    for i in 50000 {
        let v = ((i % 400) - 200) * 100;
        pcm.push((v & 0xff) as! u8);
        pcm.push(((v >> 8) & 0xff) as! u8);
    }
    // A low level: xz_writer's dictionary is fixed by the level (64 MiB
    // at 9), unlike xz_encode's.
    var w = compress::xz_writer_opts(2, compress::XZ_CHECK_SHA256, 0, compress::XZ_FILTER_DELTA, 2);
    var s: u8[>..] = [];
    var p: i64     = 0;
    while p < pcm.len && e == 0 {
        let n = min(8192, pcm.len - p);
        e = compress::xz_write(w, pcm[p..p + n], s);
        p += n;
    }
    if e == 0 { e = compress::xz_close(w, s); }
    guard e == 0 else { print("xz_lzma: xz writer: ", compress::error_text(e)); exit(1); }
    var plain: u8[>..] = [];
    e = compress::xz_encode(pcm, plain, 2);
    guard e == 0 else { print("xz_lzma: xz_encode: ", compress::error_text(e)); exit(1); }

    // Read it 1000 bytes at a time into 4 KiB of room.
    var d = compress::xz_reader();
    var room: u8[4096] = [0; 4096];
    back.clear();
    var q: i64 = 0;
    loop {
        let n = min(1000, s.len - q);
        let used, made, st = compress::xz_read(d, s[q..q + n], room);
        back.append(room[..made]);
        q += used;
        guard st >= 0 else { print("xz_lzma: xz_read: ", compress::error_text(st)); exit(1); }
        if q == s.len && made == 0 { break; }
    }
    guard compress::xz_done(d) && back[..] == pcm[..] else { print("xz_lzma: the stream did not read back"); exit(1); }
    print("samples: ", pcm.len, " -> ", s.len, " bytes with Delta and SHA-256 (", plain.len, " without the filter)");
}
