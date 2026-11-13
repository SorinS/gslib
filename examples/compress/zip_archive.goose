// zip_archive: builds a zip archive in memory (a directory, a deflated
// text file, a stored file with a time and Unix mode, an archive
// comment), then opens it, lists its entries and extracts one by name.
// Given a path, it also writes the archive there, for `unzip -l` to see.
//
//   goose examples/compress/zip_archive.goose [-- OUT.zip]

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.zip;

fn check(e: i64, what: const u8[:]) {
    guard e == 0 else { print("zip_archive: ", what, ": ", compress::error_text(e)); exit(1); }
}

fn main() {
    var readme: u8[>..] = [];
    for i in 50 { readme.append(str("Line ", i, " of the read-me file.\n")); }
    let script = "#!/bin/sh\necho hello\n";

    // Writing: each zip_create* starts a file, zip_write gives its data
    // (in as many pieces as it comes), zip_close writes the directory.
    var w = compress::zip_writer();
    var zip: u8[>..] = [];
    check(compress::zip_create_header(w, compress::ZipHeader { name: "docs/", .. }, zip), "docs/");
    check(compress::zip_create(w, "docs/README.txt", zip), "create README");     // Deflate, as Go's Create
    check(compress::zip_write(w, readme[..1000], zip), "write README");
    check(compress::zip_write(w, readme[1000..], zip), "write README");
    var h = compress::ZipHeader { name: "bin/hello.sh", method: compress::ZIP_STORE, .. };
    compress::zip_header_set_mod_time(h, compress::zip_date(2026, 11, 13, 9, 30, 0));
    compress::zip_header_set_mode(h, 0x1ed);     // 0755, rwxr-xr-x
    check(compress::zip_create_header(w, h, zip), "create hello.sh");
    check(compress::zip_write(w, script, zip), "write hello.sh");
    check(compress::zip_set_comment(w, "an example archive"), "comment");
    check(compress::zip_close(w, zip), "close");
    print("wrote ", zip.len, " bytes");

    let a = args();
    if a.len > 1 {
        guard write_file(a[1], zip) else { print("zip_archive: cannot write ", a[1]); exit(1); }
        print("saved as ", a[1]);
    }

    // Reading: zip_open reads the directory; names and comments are
    // positions into the archive's own bytes.
    let r = compress::zip_open(zip);
    check(r.err, "open");
    print("comment: ", compress::zip_comment(r, zip));
    guard r.entries.len == 3 else { print("zip_archive: ", r.entries.len, " entries"); exit(1); }
    for e in r.entries {
        let name = compress::zip_name(r, zip, e);
        let mode = compress::zip_mode(r, zip, e);
        let how = if e.method == compress::ZIP_DEFLATE { "deflate" } else { "stored " };
        var line: u8[>..] = [];
        format_uint(line, mode & 0x1ff, 8, 4, '0');
        line.append(str("  ", how, "  ", e.uncompressed_size64, " -> ", e.compressed_size64, "  ", name));
        if (mode & compress::ZIP_MODE_DIR) != 0 { line.append("  (directory)"); }
        print(line);
    }

    // Extracting one file by name; its CRC-32 and size are checked as it
    // is read. The limit refuses a file that inflates past it.
    var found = false;
    for e in r.entries {
        if compress::zip_name(r, zip, e) == "docs/README.txt" {
            var data: u8[>..] = [];
            check(compress::zip_extract(r, zip, e, data, 1 << 20), "extract");
            guard data[..] == readme[..] else { print("zip_archive: README differs"); exit(1); }
            var crc: u8[>..] = [];
            format_uint(crc, e.crc32, 16, 8, '0');
            print("extracted docs/README.txt: ", data.len, " bytes, crc32 ", crc);
            found = true;
        }
    }
    guard found else { print("zip_archive: no docs/README.txt"); exit(1); }

    // The stored file keeps its time and mode.
    let e = r.entries[2];
    guard e.modified.secs == compress::zip_date(2026, 11, 13, 9, 30, 0).secs && (compress::zip_mode(r, zip, e) & 0x1ff) == 0x1ed else {
        print("zip_archive: hello.sh lost its time or mode");
        exit(1);
    }
}
