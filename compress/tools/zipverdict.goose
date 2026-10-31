// zipverdict: prints what compress.zip makes of archives, in the text
// `gooracle zip` prints for Go's archive/zip, for scripts/zip_differential.py
// and scripts/zip_testdata.py to compare line by line.
//
//	goose tools/zipverdict.goose -- [-check] [-room N] list.txt
//
// list.txt names an archive a line. A path ending in .zsparse is one of
// Go's sparse ZIP64 test archives (gzipped: a size, then spans of
// non-zero bytes): it is opened from its tail (zip_open_tail), local
// headers read where the spans have them, and no data is read. -check is
// GODEBUG=zipinsecurepath=0; -room is the output buffer files are read
// through (default 65536).

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.gzip;
import gslib.compress.zip;

fn hex(out: u8[>..]&, s: const u8[:]) {
    for c in s { format_uint(out, c, 16, 2, '0'); }
}

fn class(e: i64) -> const u8[:] {
    match e {
        0 => "ok",
        compress::ERR_INSECURE_PATH => "insecure",
        compress::ERR_FORMAT => "format",
        compress::ERR_CHECKSUM => "checksum",
        compress::ERR_UNSUPPORTED => "algorithm",
        compress::ERR_TRUNCATED => "truncated",
        compress::ZIP_ERR_EOF => "eof",
        compress::ERR_DATA => "data",
        compress::ZIP_ERR_NEG_OFFSET => "other:bytes.Reader.ReadAt:_negative_offset",
        _ => "other",
    }
}

fn dump(out: u8[>..]&, buf: const u8[:], check: bool, room: i64, rbuf: u8[:]) {
    let r = compress::zip_open(buf, check);
    if r.err != 0 && r.err != compress::ERR_INSECURE_PATH {
        format(out, "archive ", class(r.err), "\n");
        return;
    }
    format(out, "archive ", class(r.err), " comment=");
    hex(out, compress::zip_comment(r, buf));
    format(out, " files=", r.entries.len, "\n");
    var i: i64 = 0;
    for e in r.entries {
        // The file line, then its offset and data.
        var line: u8[>..] = [];
        dump_one(line, r, buf, e, i);
        out.append(line);
        let off, oerr = compress::zip_data_offset(r, buf, e);
        if oerr != 0 { format(out, "offset ", i, " err ", class(oerr), "\n"); }
        else { format(out, "offset ", i, " ", off, "\n"); }
        var f = compress::zip_file_open(r, buf, e);
        if f.err != 0 {
            format(out, "data ", i, " err ", class(f.err), "\n");
        } else {
            var size: i64 = 0;
            var crc: u32 = 0;
            var adler: u32 = 1;
            var st: i64 = 0;
            loop {
                let made, s = compress::zip_file_read_mem(f, buf, r, rbuf[..room]);
                crc = compress::crc32_update(crc, rbuf[..made]);
                adler = compress::adler32_update(adler, rbuf[..made]);
                size += made;
                st = s;
                if s != 0 { break; }
            }
            if st < 0 { format(out, "data ", i, " err ", class(st), "\n"); }
            else {
                format(out, "data ", i, " ok ", size, " ");
                format_uint(out, crc, 16, 8, '0');
                out.push(' ');
                format_uint(out, adler, 16, 8, '0');
                out.push('\n');
            }
        }
        i++;
    }
}

fn dump_one(out: u8[>..]&, r: const compress::ZipReader&, buf: const u8[:], e: const compress::ZipEntry&, i: i64) {
    format(out, "file ", i, " name=");
    hex(out, compress::zip_name(r, buf, e));
    out.append(" comment=");
    hex(out, compress::zip_entry_comment(r, buf, e));
    format(out, " nonutf8=", e.non_utf8, " creator=", e.creator_version, " reader=", e.reader_version,
           " flags=", e.flags, " method=", e.method, " mtime=", e.mod_time, " mdate=", e.mod_date,
           " modified=", e.modified.secs, ".");
    format_int(out, e.modified.nsec, 10, 9, '0');
    format(out, "@", e.modified.offset, " crc=");
    format_uint(out, e.crc32, 16, 8, '0');
    format(out, " csize=", e.compressed_size, " usize=", e.uncompressed_size, " csize64=", e.compressed_size64,
           " usize64=", e.uncompressed_size64, " extra=");
    hex(out, compress::zip_extra(r, buf, e));
    format(out, " attrs=", e.external_attrs, " mode=");
    format_uint(out, compress::zip_mode(r, buf, e), 16, 8, '0');
    out.push('\n');
}

// A sparse archive: its size and spans (offset, bytes) as in the file.
fn sparse_read(sp: const u8[:], off: i64, n: i64, out: u8[>..]&) {
    let start = out.len;
    out.resize(start + n, 0);
    let count = compress::get_le32(sp, 8) as i64;
    var p: i64 = 12;
    for k in count {
        let so = compress::get_le64(sp, p) as! i64;
        let l = compress::get_le32(sp, p + 8) as i64;
        let data = sp[p + 12..p + 12 + l];
        p += 12 + l;
        let from = max(so, off);
        let to = min(so + l, off + n);
        if from < to { out[start + from - off..start + to - off].move_from(data[from - so..to - so]); }
    }
}

fn dump_sparse(out: u8[>..]&, gz: const u8[:], check: bool) {
    var sp: u8[>..] = [];
    if compress::gzip_decode(gz, sp) != 0 {
        out.append("bad zsparse\n");
        return;
    }
    let size = compress::get_le64(sp, 0) as! i64;
    var keep = min(size, 70000);
    loop {
        var tail: u8[>..] = [];
        sparse_read(sp, size - keep, keep, tail);
        let r = compress::zip_open_tail(tail, size, check);
        if r.err == compress::ERR_TRUNCATED && r.need >= 0 && r.need < size - keep {
            keep = size - r.need;
            continue;
        }
        if r.err != 0 && r.err != compress::ERR_INSECURE_PATH {
            format(out, "archive ", class(r.err), "\n");
            return;
        }
        format(out, "archive ", class(r.err), " comment=");
        hex(out, compress::zip_comment(r, tail));
        format(out, " files=", r.entries.len, "\n");
        var i: i64 = 0;
        for e in r.entries {
            dump_one(out, r, tail, e, i);
            if e.header_offset < 0 || e.header_offset > size - 30 {
                format(out, "offset ", i, " err ", class(if e.header_offset < 0 { compress::ZIP_ERR_NEG_OFFSET } else { compress::ZIP_ERR_EOF }), "\n");
            } else {
                var local: u8[>..] = [];
                sparse_read(sp, e.header_offset, 30, local);
                let f = compress::zip_file_start(e, local, compress::zip_name(r, tail, e));
                if !f.header_ok { format(out, "offset ", i, " err ", class(f.err), "\n"); }
                else { format(out, "offset ", i, " ", f.data_pos, "\n"); }
            }
            i++;
        }
        return;
    }
}

fn main() {
    let a = args();
    var check = false;
    var room: i64 = 65536;
    var list = "";
    var i = 1;
    while i < a.len {
        if a[i] == "-check" { check = true; }
        else if a[i] == "-room" {
            i++;
            let v, ok = parse_int(a[i]);
            room = v;
        } else { list = a[i]; }
        i++;
    }
    var text: u8[>..] = [];
    if !read_file(list, text) { print("zipverdict: cannot read ", list); exit(1); }
    var rbuf: u8[>..] = [];
    rbuf.resize(max(room, 1), 0);
    var out: u8[>..] = [];
    each_split(text, '\n') {
        let path = trim(it);
        if path.len > 0 {
            var data: u8[>..] = [];
            if !read_file(path, data) { print("zipverdict: cannot read ", path); exit(1); }
            if ends_with(path, ".zsparse") { dump_sparse(out, data, check); }
            else { dump(out, data, check, room, rbuf); }
            out.append("end\n");
            if out.len > (1 << 20) {
                write_stdout(out);
                out.clear();
            }
        }
    };
    write_stdout(out);
    flush_stdout();
}
