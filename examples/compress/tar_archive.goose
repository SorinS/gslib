// tar_archive: builds a .tar.gz in memory (a directory, two files and a
// symbolic link), then lists it with tar_each and extracts one file with
// the streaming reader, fed 700 bytes at a time as a pipe would give them.
// Given a path, it also writes the .tar.gz there, for `tar tzvf` to see.
//
//   goose examples/compress/tar_archive.goose [-- OUT.tar.gz]

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.gzip;
import gslib.compress.tar;

fn check(e: i64, what: const u8[:]) {
    guard e == 0 else { print("tar_archive: ", what, ": ", compress::error_text(e)); exit(1); }
}

// Adds a regular file: the header says its size, then the contents.
fn add_file(w: compress::TarWriter&, out: u8[>..]&, name: const u8[:], data: const u8[:], mtime: i64) {
    let h = compress::TarHeader {
        typeflag: compress::TAR_TYPE_REG,
        name:     name,
        size:     data.len,
        mode:     0x1a4,  // 0644
        uname:    "goose",
        gname:    "staff",
        mtime:    compress::tar_time(mtime),
        ..
    };
    check(compress::tar_write_header(w, h, out), name);
    let n, e = compress::tar_write(w, data, out);
    check(e, name);
}

fn main() {
    let t: i64 = 1794562200;     // 2026-11-13 09:30 UTC
    var log: u8[>..] = [];
    for i in 400 { log.append(str("2026-11-13 event ", i, " ok\n")); }

    var w = compress::tar_writer();
    var tar: u8[>..] = [];
    let dir = compress::TarHeader { typeflag: compress::TAR_TYPE_DIR, name: "site/", mode: 0x1ed, mtime: compress::tar_time(t), .. };
    check(compress::tar_write_header(w, dir, tar), "site/");
    add_file(w, tar, "site/index.html", "<h1>Hello</h1>\n", t);
    add_file(w, tar, "site/logs/access.log", log, t);
    let link = compress::TarHeader {
        typeflag: compress::TAR_TYPE_SYMLINK,
        name:     "site/latest.log",
        linkname: "logs/access.log",
        mode:     0x1ff,
        mtime:    compress::tar_time(t),
        ..
    };
    check(compress::tar_write_header(w, link, tar), "the link");
    check(compress::tar_close(w, tar), "close");
    var tgz: u8[>..] = [];
    check(compress::gzip_encode(tar, tgz, 9), "gzip");
    print("tar ", tar.len, " bytes, .tar.gz ", tgz.len, " bytes");
    let a = args();
    if a.len > 1 {
        guard write_file(a[1], tgz) else { print("tar_archive: cannot write ", a[1]); exit(1); }
        print("saved as ", a[1]);
    }

    // Listing a whole archive in memory: tar_each calls the block with
    // each header and its contents, and returns STREAM_END at the end.
    var plain: u8[>..] = [];
    check(compress::gzip_decode(tgz, plain, 1 << 24), "gunzip");
    var count = 0;
    let st = compress::tar_each(plain) { h, data =>
        var line: u8[>..] = [];
        line.push(h.typeflag);
        line.append(str("  ", h.size, "  ", h.name));
        if h.typeflag == compress::TAR_TYPE_SYMLINK { line.append(str(" -> ", h.linkname)); }
        print(line);
        count++;
    };
    guard st == compress::STREAM_END && count == 4 else { print("tar_archive: listed ", count, ", ", compress::error_text(st)); exit(1); }

    // Extracting one entry while the archive streams in: tar_read says
    // TAR_HEADER at each entry; then its contents come into `room` until
    // tar_in_entry turns false. Others are passed over with tar_skip.
    var r = compress::tar_reader(true);       // true: flag names like ../x
    var room: u8[512] = [0; 512];
    var got:  u8[>..] = [];
    var want = false;
    var q: i64 = 0;
    loop {
        let n = min(700, plain.len - q);
        let used, made, s = compress::tar_read(r, plain[q..q + n], room);
        q += used;
        if want { got.append(room[..made]); }
        guard s >= 0 else { print("tar_archive: tar_read: ", compress::error_text(s)); exit(1); }
        if s == compress::STREAM_END { break; }
        if s == compress::TAR_HEADER {
            let h = compress::tar_header(r);
            guard !compress::tar_insecure_path(r) else { print("tar_archive: unsafe name ", h.name); exit(1); }
            want = h.name == "site/logs/access.log";
            if !want { compress::tar_skip(r); }
        }
        if q == plain.len && used == 0 && made == 0 { break; }
    }
    guard compress::tar_finish(r) == compress::STREAM_END && got[..] == log[..] else {
        print("tar_archive: access.log did not come back");
        exit(1);
    }
    print("extracted site/logs/access.log: ", got.len, " bytes");
}
