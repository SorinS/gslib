// compress.tar: reading and writing tar archives as Go's archive/tar does.
//
// * Go's own test archives (vectors/tar/*.tar, from
//   $GOROOT/src/archive/tar/testdata) read whole and fed in pieces of 1,
//   7 and 513 bytes; every header field, PAX record, content CRC-32 and the
//   error that ends each must be what Go's Reader gives (vectors/tar/
//   read*.expect, written by `gooracle tar read`).
// * Go's TestWriter cases: the same calls make the same archives, byte for
//   byte, and the same errors.
// * Go's strconv_test tables (vectors/tar/strconv.txt, printed from Go's
//   own tables): numbers, PAX times and PAX records.
// * The insecure-path check, the writer's errors, and memory that stays
//   bounded whatever an archive's special headers say.
//
// scripts/tar_differential.py compares thousands more archives with Go.

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.tar;

var failures = 0;

fn fail(what: const u8[:]) {
    print("FAIL ", what);
    failures++;
}

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len { out.push((hexval(s[i]) * 16 + hexval(s[i + 1])) as! u8); i += 2; }
    return out;
}

fn num(s: const u8[:]) -> i64 { let v, ok = parse_int(s); return v; }

// --- Go's results on its own archives ---------------------------------------

fn hex_into(out: u8[>..]&, s: const u8[:]) {
    if s.len == 0 { out.push('-'); return; }
    for b in s { format_uint(out, b, 16, 2, '0'); }
}

fn time_into(out: u8[>..]&, t: compress::TarTime) {
    if compress::tar_time_is_zero(t) { out.append("zero"); return; }
    format(out, t.sec);
    out.push('.');
    format_int(out, t.nsec, 10, 9, '0');
}

fn read_class(code: i64, why: i64) -> const u8[:] {
    if code == compress::STREAM_END { return "EOF"; }
    match why {
        compress::TAR_WHY_HEADER => "header",
        compress::TAR_WHY_TRUNCATED => "unexpected-eof",
        compress::TAR_WHY_FIELD_TOO_LONG => "field-too-long",
        compress::TAR_WHY_SPARSE_TOO_LONG => "sparse-too-long",
        compress::TAR_WHY_MISS_DATA => "miss-data",
        compress::TAR_WHY_UNREF_DATA => "unref-data",
        _ => "other",
    }
}

fn header_into(out: u8[>..]&, h: compress::TarHeader) {
    out.append("hdr type=");
    format(out, h.typeflag);
    out.append(" name=");
    hex_into(out, h.name);
    out.append(" link=");
    hex_into(out, h.linkname);
    format(out, " size=", h.size, " mode=", h.mode, " uid=", h.uid, " gid=", h.gid);
    out.append(" uname=");
    hex_into(out, h.uname);
    out.append(" gname=");
    hex_into(out, h.gname);
    out.append(" mtime=");
    time_into(out, h.mtime);
    out.append(" atime=");
    time_into(out, h.atime);
    out.append(" ctime=");
    time_into(out, h.ctime);
    format(out, " devmajor=", h.devmajor, " devminor=", h.devminor, " format=", h.format, "\n");
    compress::tar_pax_each(h.pax) { k, v =>
        out.append("pax ");
        hex_into(out, k);
        out.push(' ');
        hex_into(out, v);
        out.push('\n');
    };
}

fn data_line(out: u8[>..]&, n: i64, crc: u32) {
    format(out, "data ", n, " ");
    format_uint(out, crc, 16, 8, '0');
}

// What `gooracle tar read` prints for an archive, fed `chunk` bytes at a time.
fn read_archive(out: u8[>..]&, data: const u8[:], cap: i64, chunk: i64, check: bool) {
    var r = compress::tar_reader(check);
    var buf: u8[4096] = [0; 4096];
    var at = 0;
    var in_data = false;
    var n: i64 = 0;
    var crc: u32 = 0;
    while true {
        let end = min(data.len, at + chunk);
        let room = if in_data { min(4096, cap - n) } else { 0 };
        let used, made, st = compress::tar_read(r, data[at..end], buf[..room]);
        at += used;
        if made > 0 {
            crc = compress::crc32_update(crc, buf[..made]);
            n += made;
        }
        if st < 0 {
            if in_data { data_line(out, n, crc); format(out, " err ", read_class(st, compress::tar_why(r)), "\n"); }
            format(out, "end ", read_class(st, compress::tar_why(r)), "\n");
            return;
        }
        if st == compress::STREAM_END {
            if in_data { data_line(out, n, crc); out.push('\n'); }
            out.append("end EOF\n");
            return;
        }
        if in_data && (!compress::tar_in_entry(r) || n >= cap) {
            if compress::tar_in_entry(r) { compress::tar_skip(r); }
            data_line(out, n, crc);
            out.push('\n');
            in_data = false;
        }
        if st == compress::TAR_HEADER {
            header_into(out, compress::tar_header(r));
            if compress::tar_insecure_path(r) { out.append("insecure\n"); }
            in_data = true;
            n = 0;
            crc = 0;
            continue;
        }
        if used == 0 && made == 0 && at >= data.len {
            let e = compress::tar_finish(r);
            if in_data {
                data_line(out, n, crc);
                if e < 0 { format(out, " err ", read_class(e, compress::tar_why(r))); }
                out.push('\n');
            }
            format(out, "end ", read_class(e, compress::tar_why(r)), "\n");
            return;
        }
    }
}

fn go_archives(expect_file: const u8[:], cap: i64, check: bool, chunks: const i64[:]) {
    var expect: u8[>..] = [];
    if !read_file(expect_file, expect) { fail(str("cannot read ", expect_file)); return; }
    var names: u8[>..] = [];
    each_split(expect, '\n') { if starts_with(it, "archive ") { names.append(it[8..]); names.push('\n'); } };
    var count = 0;
    for chunk in chunks {
        var got: u8[>..] = [];
        each_split(names, '\n') {
            if it.len > 0 {
                var data: u8[>..] = [];
                if !read_file(str("vectors/tar/", it), data) { fail(str("cannot read ", it)); }
                format(got, "archive ", it, "\n");
                read_archive(got, data, cap, chunk, check);
                count++;
            }
        };
        if got[..] != expect[..] {
            // Find the first archive that differs.
            let a = split(got, "archive ");
            let b = split(expect, "archive ");
            for k in min(a.len, b.len) {
                if a[k] != b[k] {
                    fail(str(expect_file, " chunk ", chunk, ":\n  got  archive ", a[k], "\n  want archive ", b[k]));
                    break;
                }
            }
        }
    }
    print("tar: ", count, " readings of Go's archives against ", expect_file);
}

// --- Go's TestWriter --------------------------------------------------------

fn same_as(got: const u8[:], file: const u8[:]) {
    var want: u8[>..] = [];
    if !read_file(str("vectors/tar/", file), want) { fail(str("cannot read ", file)); return; }
    if got != want[..] {
        var k = 0;
        while k < got.len && k < want.len && got[k] == want[k] { k++; }
        fail(str("writer: ", file, ": ", got.len, " bytes, want ", want.len, "; first difference at ", k));
    }
}

fn wh(w: compress::TarWriter&, h: compress::TarHeader, out: u8[>..]&, want: i64) {
    let e = compress::tar_write_header(w, h, out);
    if e != want { fail(str("write_header ", h.name, ": ", e, ", want ", want)); }
}

fn wr(w: compress::TarWriter&, s: const u8[:], out: u8[>..]&, want_n: i64, want: i64) {
    let n, e = compress::tar_write(w, s, out);
    if n != want_n || e != want { fail(str("write '", s, "': ", n, " ", e, ", want ", want_n, " ", want)); }
}

fn close(w: compress::TarWriter&, out: u8[>..]&) {
    let e = compress::tar_close(w, out);
    if e != 0 { fail(str("close: ", e)); }
}

fn pax(kv: const u8[:][:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < kv.len { compress::tar_pax_append(out, kv[i], kv[i + 1]); i += 2; }
    return out;
}

fn t(s: i64) -> compress::TarTime { compress::tar_time(s) }

fn go_writer_cases() {

    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        wh(w, compress::TarHeader { typeflag: '0', name: "small.txt", size: 5, mode: 416, uid: 73025, gid: 5000,
                                    uname: "dsymonds", gname: "eng", mtime: t(1246508266), .. }, out, 0);
        wr(w, "Kilts", out, 5, 0);
        wh(w, compress::TarHeader { typeflag: '0', name: "small2.txt", size: 11, mode: 416, uid: 73025, gid: 5000,
                                    uname: "dsymonds", gname: "eng", mtime: t(1245217492), .. }, out, 0);
        wr(w, "Google.com\n", out, 11, 0);
        wh(w, compress::TarHeader { typeflag: '2', name: "link.txt", linkname: "small.txt", mode: 511, uid: 1000, gid: 1000,
                                    uname: "strings", gname: "strings", mtime: t(1314603082), .. }, out, 0);
        wr(w, "", out, 0, 0);
        close(w, out);
        same_as(out, "writer.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        wh(w, compress::TarHeader { typeflag: '0', name: "tmp/16gig.txt", size: 16 << 30, mode: 416, uid: 73025, gid: 5000,
                                    uname: "dsymonds", gname: "eng", mtime: t(1254699560), format: compress::TAR_FORMAT_GNU, .. }, out, 0);
        same_as(out, "writer-big.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        var name: u8[>..] = [];
        for i in 15 { name.append("longname/"); }
        name.append("16gig.txt");
        wh(w, compress::TarHeader { typeflag: '0', name: name, size: 16 << 30, mode: 420, uid: 1000, gid: 1000,
                                    uname: "guillaume", gname: "guillaume", mtime: t(1399583047), .. }, out, 0);
        same_as(out, "writer-big-long.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        var name: u8[>..] = [];
        for i in 15 { name.append("longname/"); }
        name.append("file.txt");
        wh(w, compress::TarHeader { typeflag: '0', name: name, size: 6, mode: 420, uid: 501, gid: 20,
                                    uname: "shane", gname: "staff", mtime: t(1360135598), .. }, out, 0);
        wr(w, "hello\n", out, 6, 0);
        close(w, out);
        same_as(out, "ustar.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        wh(w, compress::TarHeader { typeflag: '0', name: "file.txt", size: 15, mode: 420, uid: 1000, gid: 100,
                                    uname: "vbatts", gname: "users", mtime: t(1425484303), .. }, out, 0);
        wr(w, "Slartibartfast\n", out, 15, 0);
        wh(w, compress::TarHeader { typeflag: '1', name: "hard.txt", linkname: "file.txt", mode: 420, uid: 1000, gid: 100,
                                    uname: "vbatts", gname: "users", mtime: t(1425484303), .. }, out, 0);
        wr(w, "", out, 0, 0);
        close(w, out);
        same_as(out, "hardlink.tar");
    }
    {
        // A NUL in an xattr's key, or in a name: no format can hold it.
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        let p = pax(["SCHILY.xattr.null\x00null\x00", "fizzbuzz"]);
        wh(w, compress::TarHeader { typeflag: '0', name: "bad-null.txt", pax: p, .. }, out, compress::ERR_HEADER);
        wh(w, compress::TarHeader { typeflag: '0', name: "null\x00.txt", .. }, out, compress::ERR_HEADER);
        if out.len != 0 { fail("writer: headers that cannot be encoded wrote something"); }
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        var long: u8[>..] = [];
        for i in 10 { long.append("long"); }
        let p = pax(["path", "FILE", "GNU.sparse.map", "0,0", "comment", "Hello, 世界", "GOLANG.pkg", "tar"]);
        wh(w, compress::TarHeader { typeflag: '0', name: "file", uname: long, pax: p, .. }, out, 0);
        close(w, out);
        same_as(out, "pax-records.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        let p1 = pax(["path", "global1", "mtime", "1500000000.0"]);
        let p2 = pax(["path", "file2"]);
        let p3 = pax(["path", ""]);
        let p4 = pax(["mtime", "1400000000"]);
        wh(w, compress::TarHeader { typeflag: 'g', pax: p1, .. }, out, 0);
        wh(w, compress::TarHeader { typeflag: '0', name: "file1", .. }, out, 0);
        wh(w, compress::TarHeader { typeflag: '0', name: "file2", pax: p2, .. }, out, 0);
        wh(w, compress::TarHeader { typeflag: 'g', pax: p3, .. }, out, 0);
        wh(w, compress::TarHeader { typeflag: '0', name: "file3", .. }, out, 0);
        wh(w, compress::TarHeader { typeflag: '0', name: "file4", mtime: t(1400000000), pax: p4, .. }, out, 0);
        close(w, out);
        same_as(out, "pax-global-records.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        var name: u8[>..] = [];
        for i in 18 { name.append("☺☻☹"); }
        wh(w, compress::TarHeader { typeflag: '0', name: name, mode: 420, uid: 1000, gid: 1000, uname: "☺", gname: "⚹",
                                    mtime: t(0), format: compress::TAR_FORMAT_GNU, .. }, out, 0);
        close(w, out);
        same_as(out, "gnu-utf8.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        wh(w, compress::TarHeader { typeflag: '0', name: "hi\x80\x81\x82\x83bye", mode: 420, uid: 1000, gid: 1000,
                                    uname: "rawr", gname: "dsnet", mtime: t(0), format: compress::TAR_FORMAT_GNU, .. }, out, 0);
        close(w, out);
        same_as(out, "gnu-not-utf8.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        var name: u8[>..] = [];
        for i in 30 { name.append("123456789/"); }
        wh(w, compress::TarHeader { typeflag: 0, name: name, .. }, out, 0);
        close(w, out);
        same_as(out, "trailing-slash.tar");
    }
    {
        var out: u8[>..] = [];
        var w = compress::tar_writer();
        wh(w, compress::TarHeader { typeflag: 0, name: "small.txt", size: 5, .. }, out, 0);
        wr(w, "Kilts", out, 5, 0);
        wh(w, compress::TarHeader { typeflag: 0, name: "dir/", .. }, out, 0);
        close(w, out);
        same_as(out, "file-and-dir.tar");
    }
    print("tar: Go's writer cases");
}

// --- The writer's errors ----------------------------------------------------

fn writer_errors() {
    var out: u8[>..] = [];
    var w = compress::tar_writer();
    wh(w, compress::TarHeader { name: "a", size: 3, .. }, out, 0);
    // More than the header's size: ErrWriteTooLong, and the writer goes on.
    wr(w, "abcd", out, 3, compress::ERR_TOO_LARGE);
    if compress::tar_writer_why(w) != compress::TAR_WHY_WRITE_TOO_LONG { fail("why: write too long"); }
    wh(w, compress::TarHeader { name: "b", size: 2, .. }, out, 0);
    wr(w, "x", out, 1, 0);
    // The entry is not all written: "missed writing", and the writer goes on.
    wh(w, compress::TarHeader { name: "c", .. }, out, compress::ERR_ARGUMENT);
    if compress::tar_writer_why(w) != compress::TAR_WHY_MISSED_WRITING { fail("why: missed writing"); }
    wr(w, "y", out, 1, 0);
    // A file name may not end in a slash; a header-only type takes no data.
    wh(w, compress::TarHeader { name: "d/", .. }, out, compress::ERR_HEADER);
    wh(w, compress::TarHeader { typeflag: '5', name: "d/", size: 10, .. }, out, 0);
    wr(w, "z", out, 0, compress::ERR_TOO_LARGE);
    // The types a writer makes itself are refused.
    for typ in ['x', 'L', 'K'] { wh(w, compress::TarHeader { typeflag: typ as! u8, name: "e", .. }, out, compress::ERR_HEADER); }
    // A global header holds records only.
    wh(w, compress::TarHeader { typeflag: 'g', name: "g", size: 1, .. }, out, compress::ERR_HEADER);
    // USTAR asked for, and a name it cannot hold.
    var long: u8[>..] = [];
    for i in 120 { long.push('n'); }
    wh(w, compress::TarHeader { name: long, format: compress::TAR_FORMAT_USTAR, .. }, out, compress::ERR_HEADER);
    // Sub-second times: PAX, unless USTAR is asked for (the time rounded down).
    var mark = out.len;
    wh(w, compress::TarHeader { name: "t", mtime: compress::tar_time(5, 7), format: compress::TAR_FORMAT_PAX, .. }, out, 0);
    if find(out[mark..], "mtime=5.000000007") < 0 { fail("PAX keeps a sub-second mtime"); }
    mark = out.len;
    wh(w, compress::TarHeader { name: "t", mtime: compress::tar_time(5, 7), .. }, out, 0);
    if find(out[mark..], "mtime") >= 0 { fail("with no format asked for, a time is rounded to a second"); }
    let e = compress::tar_close(w, out);
    if e != 0 { fail(str("close: ", e)); }
    let n, e2 = compress::tar_write(w, "x", out);
    if e2 != compress::ERR_ARGUMENT || compress::tar_writer_why(w) != compress::TAR_WHY_WRITE_AFTER_CLOSE { fail("write after close"); }
    if compress::tar_close(w, out) != 0 { fail("a second close"); }
    // Everything written reads back.
    var names: u8[>..] = [];
    let st = compress::tar_each(out) { h, data => names.append(h.name); names.push(' '); };
    if st != compress::STREAM_END || names[..] != "a b d/ t t " { fail(str("writer errors: read back ", st, " '", names, "'")); }
    print("tar: writer errors");
}

// --- Insecure paths ---------------------------------------------------------

fn insecure_paths() {
    let names = ["ok", "a/b", "/etc/passwd", "../x", "a/../../b", "ok/../c", "./ok", "a/./b/..", "..", "/", "x/..",
                 "a//b", "..a", "a/.."];
    let local = [true, true, false, false, false, true, true, true, false, false, true, true, true, true];
    var out: u8[>..] = [];
    var w = compress::tar_writer();
    for n in names { wh(w, compress::TarHeader { typeflag: '5', name: n, .. }, out, 0); }
    compress::tar_close(w, out);
    for check in [false, true] {
        var r = compress::tar_reader(check);
        var at = 0;
        var k = 0;
        var buf: u8[16] = [0; 16];
        while true {
            let used, made, st = compress::tar_read(r, out[at..], buf);
            at += used;
            if st == compress::STREAM_END || st < 0 { break; }
            if st == compress::TAR_HEADER {
                let want = check && !local[k];
                if compress::tar_insecure_path(r) != want { fail(str("insecure path '", names[k], "' check ", check)); }
                k++;
            }
        }
        if k != names.len { fail("insecure paths: entries missing"); }
    }
    // tar_each hands insecure entries out too.
    var count = 0;
    let st = compress::tar_each(out, 1 << 20, true) { h, data => count++; };
    if count != names.len || st != compress::STREAM_END { fail("insecure paths: tar_each"); }
    print("tar: insecure paths");
}

// --- Bounded memory ---------------------------------------------------------

// A block of a PAX header with the checksum right.
fn raw_header(out: u8[>..]&, name: const u8[:], size: i64, typ: u8) {
    var b: u8[512] = [0; 512];
    b[..name.len].move_from(name);
    var s: u8[>..] = [];
    format_int(s, size, 8, 11, '0');
    b[124..135].move_from(s[..11]);
    b[156] = typ;
    b[257..263].move_from("ustar\x00");
    b[263..265].move_from("00");
    var sum = 0;
    for c, i in b { sum += if i >= 148 && i < 156 { 32 } else { c }; }
    s.clear();
    format_int(s, sum, 8, 6, '0');
    b[148..154].move_from(s[..6]);
    b[155] = ' ';
    out.append(b[..]);
}

fn bounded_memory() {
    // A hundred PAX headers of 200 KB each, then a file: the reader keeps
    // the last one's records only.
    var arc: u8[>..] = [];
    var value: u8[>..] = [];
    for i in 200000 { value.push('v'); }
    var rec: u8[>..] = [];
    compress::tar_pax_append(rec, "comment", value);
    for i in 100 {
        raw_header(arc, "PaxHeaders/x", rec.len, 'x');
        arc.append(rec);
        for k in (512 - rec.len % 512) % 512 { arc.push(0); }
    }
    raw_header(arc, "file", 0, '0');
    for i in 1024 { arc.push(0); }
    var r = compress::tar_reader();
    var at = 0;
    var most = 0;
    var headers = 0;
    var buf: u8[16] = [0; 16];
    while true {
        let used, made, st = compress::tar_read(r, arc[at..min(arc.len, at + 65536)], buf);
        at += used;
        most = max(most, r.buf.len);
        if st == compress::TAR_HEADER { headers++; }
        if st == compress::STREAM_END || st < 0 { break; }
    }
    if headers != 1 || most > 2 * rec.len + 4096 { fail(str("bounded memory: ", headers, " headers, ", most, " bytes kept")); }
    // A special file past 1 MiB: ErrFieldTooLong, having kept 1 MiB at most.
    var big: u8[>..] = [];
    raw_header(big, "PaxHeaders/x", 3 << 20, 'x');
    for i in 3 << 20 { big.push('a'); }
    var r2 = compress::tar_reader();
    let u2, m2, st2 = compress::tar_read(r2, big, buf);
    if st2 != compress::ERR_LIMIT || compress::tar_why(r2) != compress::TAR_WHY_FIELD_TOO_LONG || r2.buf.len > (1 << 20) + 4096 {
        fail(str("special file too long: ", st2, " kept ", r2.buf.len));
    }
    // GNU long names, one after another: only the last is kept.
    var arc3: u8[>..] = [];
    for i in 50 {
        raw_header(arc3, "././@LongLink", 100001, 'L');
        for k in 100000 { arc3.push('n'); }
        arc3.push(0);
        for k in (512 - 100001 % 512) % 512 { arc3.push(0); }
    }
    raw_header(arc3, "short", 0, '0');
    for i in 1024 { arc3.push(0); }
    var r3 = compress::tar_reader();
    var at3 = 0;
    var most3 = 0;
    var name_len = 0;
    while true {
        let used, made, st = compress::tar_read(r3, arc3[at3..min(arc3.len, at3 + 10000)], buf);
        at3 += used;
        most3 = max(most3, r3.buf.len);
        if st == compress::TAR_HEADER { name_len = compress::tar_header(r3).name.len; }
        if st == compress::STREAM_END || st < 0 { break; }
    }
    if name_len != 100000 || most3 > 2 * 100001 + 4096 { fail(str("long names: name ", name_len, ", ", most3, " bytes kept")); }
    print("tar: bounded memory");
}

// --- Where an archive may end ----------------------------------------------

// Go's Reader takes an end of input at a header, after one block of zeros,
// or anywhere in an entry's padding, and calls any other end unexpected.
fn archive_ends() {
    var arc: u8[>..] = [];
    var w = compress::tar_writer();
    wh(w, compress::TarHeader { name: "a", size: 3, .. }, arc, 0);
    wr(w, "abc", arc, 3, 0);
    compress::tar_close(w, arc);
    // 512 header, 3 data, 509 padding, 1024 zeros.
    for cut in [0, 1, 511, 512, 513, 514, 515, 516, 900, 1023, 1024, 1025, 1535, 1536, 1537, 2047, 2048] {
        var r = compress::tar_reader();
        var buf: u8[8] = [0; 8];
        var at = 0;
        var st: i64 = 0;
        while true {
            let used, made, s2 = compress::tar_read(r, arc[at..cut], buf);
            at += used;
            st = s2;
            if s2 < 0 || s2 == compress::STREAM_END || (used == 0 && made == 0 && s2 != compress::TAR_HEADER && !compress::tar_in_entry(r)) { break; }
            if used == 0 && made == 0 && s2 == 0 { break; }
        }
        let e = if st == compress::STREAM_END { st } else { compress::tar_finish(r) };
        let want = if (cut > 0 && cut < 515) || (cut > 1024 && cut < 1536) || (cut > 1536 && cut < 2048) { compress::ERR_TRUNCATED } else { compress::STREAM_END };
        if e != want { fail(str("an archive cut at ", cut, ": ", e, ", want ", want)); }
    }
    print("tar: where an archive may end");
}

// --- Go's strconv_test tables -----------------------------------------------

fn strconv_vectors() {
    var text: u8[>..] = [];
    if !read_file("vectors/tar/strconv.txt", text) { fail("cannot read strconv.txt"); return; }
    var count = 0;
    each_split(text, '\n') {
        let f = words(it);
        if f.len > 0 {
            count++;
            if f[0] == "numeric" {
                let input = unhex(f[1]);
                let v, ok = compress::tar_parse_numeric(input);
                let want_ok = f[3] == "true";
                if ok != want_ok || (ok && v != num(f[2])) { fail(str("parse_numeric ", f[1], ": ", v, " ", ok)); }
            } else if f[0] == "fits256" {
                if compress::tar_fits_base256(num(f[1]), num(f[2])) != (f[3] == "true") { fail(str("fits base 256 ", f[1], " ", f[2])); }
            } else if f[0] == "fitsoctal" {
                if compress::tar_fits_octal(num(f[1]), num(f[2])) != (f[3] == "true") { fail(str("fits octal ", f[1], " ", f[2])); }
            } else if f[0] == "formatnumeric" {
                let want = unhex(f[2]);
                var b: u8[>..] = [];
                b.resize(want.len, 0);
                let ok = compress::tar_put_numeric(b, num(f[1]));
                if ok != (f[3] == "true") || (ok && b[..] != want[..]) { fail(str("format_numeric ", f[1])); }
            } else if f[0] == "paxtime" {
                let input = unhex(f[1]);
                let t, ok = compress::tar_parse_pax_time(input);
                let want_ok = f[4] == "true";
                if ok != want_ok || (ok && (t.sec != num(f[2]) || t.nsec != num(f[3]))) {
                    fail(str("parse_pax_time ", f[1], ": ", t.sec, " ", t.nsec, " ", ok));
                }
            } else if f[0] == "formatpaxtime" {
                var s: u8[>..] = [];
                compress::tar_format_pax_time(s, compress::tar_time(num(f[1]), num(f[2])));
                if s[..] != unhex(f[3])[..] { fail(str("format_pax_time ", f[1], " ", f[2], ": ", s)); }
            } else if f[0] == "paxrecord" {
                let input = unhex(f[1]);
                let ko, kl, vo, vl, n, ok = compress::tar_pax_record(input);
                let want_ok = f[5] == "true";
                if ok != want_ok { fail(str("parse_pax_record ", f[1], ": ", ok)); }
                else if ok {
                    if input[ko..ko + kl] != unhex(f[3])[..] || input[vo..vo + vl] != unhex(f[4])[..] || input[n..] != unhex(f[2])[..] {
                        fail(str("parse_pax_record ", f[1]));
                    }
                }
            } else if f[0] == "formatpaxrecord" {
                let k = unhex(f[1]);
                let v = unhex(f[2]);
                let ok = compress::tar_valid_pax_record(k, v);
                if ok != (f[4] == "true") { fail(str("valid_pax_record ", f[1], " ", f[2])); }
                if ok {
                    var s: u8[>..] = [];
                    compress::tar_pax_append(s, k, v);
                    if s[..] != unhex(f[3])[..] { fail(str("format_pax_record ", f[1], " ", f[2])); }
                }
            }
        }
    };
    print("tar: ", count, " of Go's strconv vectors");
}

fn main() {
    strconv_vectors();
    go_archives("vectors/tar/read.expect", 1 << 20, false, [1 << 40, 1, 513]);
    go_archives("vectors/tar/read-cap100-check.expect", 100, true, [7]);
    go_writer_cases();
    writer_errors();
    insecure_paths();
    bounded_memory();
    archive_ends();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("tar: all passed");
}
