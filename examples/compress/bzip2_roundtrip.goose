// bzip2_roundtrip: compresses text with bzip2 in one call, then again as
// a stream written in pieces, and reads both back; the second is read
// through a small output buffer, as a program writing to a file would.
//
//   goose examples/compress/bzip2_roundtrip.goose

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.bzip2;

fn main() {
    var data: u8[>..] = [];
    let words = ["goose ", "gander ", "gosling ", "flock ", "pond ", "feather\n"];
    var r = rng { 2026 };
    while data.len < 200000 { data.append(words[r.rand_int(words.len)]); }

    // Whole buffers: the block size 1-9 (x 100 000 bytes) is the level.
    var bz: u8[>..] = [];
    var e = compress::bzip2_encode(data, bz, 9);
    guard e == 0 else { print("bzip2_roundtrip: bzip2_encode: ", compress::error_text(e)); exit(1); }
    guard bz[..3] == "BZh" else { print("bzip2_roundtrip: no BZh magic"); exit(1); }
    var back: u8[>..] = [];
    e = compress::bzip2_decode(bz, back, 1 << 24);
    guard e == 0 && back[..] == data[..] else { print("bzip2_roundtrip: bzip2_decode: ", compress::error_text(e)); exit(1); }
    print("bzip2 -9: ", data.len, " -> ", bz.len, " bytes");

    // A stream: written 10 000 bytes at a time with small blocks (-1),
    // so it holds two blocks.
    var w = compress::bzip2_writer(1);
    var s: u8[>..] = [];
    var p: i64     = 0;
    while p < data.len && e == 0 {
        let n = min(10000, data.len - p);
        e = compress::bzip2_write(w, data[p..p + n], s);
        p += n;
    }
    if e == 0 { e = compress::bzip2_close(w, s); }
    guard e == 0 else { print("bzip2_roundtrip: writer: ", compress::error_text(e)); exit(1); }

    // Read it back 4 KiB of input at a time into 1 KiB of room.
    var d = compress::bzip2_reader();
    var room: u8[1024] = [0; 1024];
    back.clear();
    var q: i64 = 0;
    loop {
        let n = min(4096, s.len - q);
        let used, made, st = compress::bzip2_read(d, s[q..q + n], room);
        back.append(room[..made]);
        q += used;
        guard st >= 0 else { print("bzip2_roundtrip: bzip2_read: ", compress::error_text(st)); exit(1); }
        if q == s.len && made == 0 { break; }
    }
    guard compress::bzip2_done(d) && back[..] == data[..] else { print("bzip2_roundtrip: the stream did not read back"); exit(1); }
    print("bzip2 -1 as a stream: ", data.len, " -> ", s.len, " bytes, read back whole");

    // A damaged stream is refused: a flipped byte breaks a block's CRC
    // or its Huffman codes.
    s[s.len / 2] ^= 0x55;
    back.clear();
    e = compress::bzip2_decode(s, back, 1 << 24);
    guard e < 0 else { print("bzip2_roundtrip: a damaged stream was taken"); exit(1); }
    print("a damaged stream: ", compress::error_text(e));
}
