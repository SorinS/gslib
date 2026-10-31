// gzstream: compresses a file as gzip and reads it back, both as streams
// over small buffers: the writer is fed 4 KiB at a time, and the reader
// is fed 1000 bytes at a time into an output buffer of 512 bytes, as a
// program reading a socket or a pipe would.
//
//	goose examples/gzstream.goose -- FILE [LEVEL]

import std;
import os;
import compress from "..";
import compress.gzip;

fn main() {
    let a = args();
    guard a.len >= 2 else { print("usage: gzstream FILE [LEVEL]"); exit(2); }
    var level: i64 = 6;
    if a.len > 2 {
        let l, ok = parse_int(a[2]);
        guard ok else { print("gzstream: bad level ", a[2]); exit(2); }
        level = l;
    }
    var data: u8[>..] = [];
    guard read_file(a[1], data) else { print("gzstream: cannot read ", a[1]); exit(1); }

    // Write: the header with the file's name, then the data in pieces.
    var gz: u8[>..] = [];
    var w = compress::gzip_writer(level);
    var e = compress::gzip_write_header(w, gz, a[1], "", "", 0, 3);
    var p: i64 = 0;
    while p < data.len && e == 0 {
        let n = min(4096, data.len - p);
        e = compress::gzip_write(w, data[p..p + n], gz);
        p += n;
    }
    if e == 0 { e = compress::gzip_close(w, gz); }
    guard e == 0 else { print("gzstream: ", compress::error_text(e)); exit(1); }

    // Read: 1000 bytes of input at a time, 512 bytes of room.
    var r = compress::gzip_reader();
    var room: u8[512] = [0; 512];
    var back: u8[>..] = [];
    var q: i64 = 0;
    loop {
        let n = min(1000, gz.len - q);
        let used, made, st = compress::gzip_read(r, gz[q..q + n], room);
        back.append(room[..made]);
        q += used;
        guard st >= 0 else { print("gzstream: ", compress::error_text(st)); exit(1); }
        if q == gz.len && made == 0 { break; }
    }
    guard compress::gzip_done(r) && back[..] == data[..] else { print("gzstream: the round trip failed"); exit(1); }
    var name: u8[>..] = [];
    compress::gzip_latin1_to_utf8(r.name, name);
    print(name, ": ", data.len, " bytes, ", gz.len, " compressed at level ", level, ", read back whole");
}
