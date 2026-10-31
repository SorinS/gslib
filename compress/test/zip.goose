// compress.zip: Go's archive/zip testdata, its ZIP64 sparse goldens and
// the archives of its regression tests (reader_test.go's TestIssue10957,
// 10956, 11146, 12449, TestCVE202133196, 39293, TestCompressedDirectory,
// TestBaseOffsetPlusOverflow), each read and compared with what Go
// 1.27.1 reads (test/vectors/zip/go_dump.txt, made by gooracle zip, with
// GODEBUG=zipinsecurepath=0 too); and Go's writer tests: TestWriter,
// TestWriterComment, TestWriterUTF8, TestWriterTime (byte for byte),
// TestWriterOffset, TestWriterDir, TestWriterDirAttributes,
// TestWriterCopy, TestWriterCreateRaw, TestOver65kFiles,
// TestInsecurePaths, TestUnderSize, TestHeaderTooLongErr, and ZIP64
// records for sizes past 4 GiB. scripts/zip_differential.py compares
// thousands more archives with Go.

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.deflate;
import gslib.compress.gzip;
import gslib.compress.zip;

var failures = 0;

fn fail(what: const u8[:]) {
    print("FAIL ", what);
    failures++;
}

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

// --- What gooracle zip prints, for our reader -------------------------------

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

fn dump(out: u8[>..]&, buf: const u8[:], check: bool, room: i64) {
    var rbuf: u8[>..] = [];
    rbuf.resize(room, 0);
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
        dump_one(out, r, buf, e, i);
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
                let made, s = compress::zip_file_read_mem(f, buf, r, rbuf);
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

// A sparse 64-bit archive (testdata/zip64): opened from its tail, grown to
// where the reader says the directory starts.
fn dump_sparse(out: u8[>..]&, gz: const u8[:], check: bool) {
    var sp: u8[>..] = [];
    if compress::gzip_decode(gz, sp) != 0 {
        out.append("bad zsparse\n");
        return;
    }
    let size = compress::get_le64(sp, 0) as! i64;
    var keep = min(size, 1000);
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
            var local: u8[>..] = [];
            sparse_read(sp, e.header_offset, 30, local);
            let f = compress::zip_file_start(e, local, compress::zip_name(r, tail, e));
            if !f.header_ok { format(out, "offset ", i, " err ", class(f.err), "\n"); }
            else { format(out, "offset ", i, " ", f.data_pos, "\n"); }
            i++;
        }
        return;
    }
}

fn go_testdata(golden: const u8[:], check: bool, room: i64) {
    var list: u8[>..] = [];
    var want: u8[>..] = [];
    if !read_file("vectors/zip/list.txt", list) || !read_file(golden, want) { fail("cannot read the zip vectors"); return; }
    var got: u8[>..] = [];
    var n = 0;
    each_split(list, '\n') {
        if it.len > 0 {
            var data: u8[>..] = [];
            if !read_file(str("vectors/zip/", it), data) { fail(str("cannot read vectors/zip/", it)); }
            if ends_with(it, ".zsparse") { dump_sparse(got, data, check); } else { dump(got, data, check, room); }
            got.append("end\n");
            n++;
        }
    };
    if got[..] != want[..] {
        // The first line that differs.
        let gl = split(got, '\n');
        let wl = split(want, '\n');
        for k in min(gl.len, wl.len) {
            if gl[k] != wl[k] {
                print("FAIL ", golden, " line ", k + 1, ":\n  go:   ", wl[k], "\n  ours: ", gl[k]);
                break;
            }
        }
        failures++;
    }
    if n < 60 { fail("fewer zip vectors than expected"); }
}

// --- Go's reader and writer tests -------------------------------------------

fn extract(r: const compress::ZipReader&, a: const u8[:], e: const compress::ZipEntry&) -> u8[>..], i64 {
    var out: u8[>..] = [];
    let st = compress::zip_extract(r, a, e, out);
    return out, st;
}

fn pseudo_random(n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    var x: u64 = 0x9e3779b97f4a7c15;
    for k in n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push((x & 0xff) as! u8);
    }
    return out;
}

struct WriteTest { name: const u8[:], method: u16, mode: u32 }

let WRITE_TESTS: WriteTest[7] = [
    WriteTest { name: "foo", method: 0, mode: 0x1b6 },
    WriteTest { name: "bar", method: 8, mode: 0x1a4 },
    WriteTest { name: "setuid", method: 8, mode: 0x1ed | 0x00800000 },
    WriteTest { name: "setgid", method: 8, mode: 0x1ed | 0x00400000 },
    WriteTest { name: "symlink", method: 8, mode: 0x1ed | 0x08000000 },
    WriteTest { name: "device", method: 8, mode: 0x1ed | 0x04000000 },
    WriteTest { name: "chardevice", method: 8, mode: 0x1ed | 0x04000000 | 0x00200000 },
];

fn write_test_data(i: i64) -> u8[>..] {
    if i == 1 { return pseudo_random(1 << 17); }
    var out: u8[>..] = [];
    out.append(match i {
        0 => "Rabbits, guinea pigs, gophers, marsupial rats, and quolls.",
        2 => "setuid file",
        3 => "setgid file",
        4 => "../link/target",
        5 => "device file",
        _ => "char device file",
    });
    return out;
}

fn write_tests(w: compress::ZipWriter&, out: u8[>..]&) {
    for i in WRITE_TESTS.len {
        let t = WRITE_TESTS[i];
        var h = compress::ZipHeader { name: t.name, method: t.method, .. };
        compress::zip_header_set_mode(h, t.mode);
        if compress::zip_create_header(w, h, out) != 0 { fail("create_header"); }
        let data = write_test_data(i);
        // In pieces, as io.Copy might.
        var p: i64 = 0;
        while p < data.len {
            let n = min(1000, data.len - p);
            if compress::zip_write(w, data[p..p + n], out) != 0 { fail("write"); }
            p += n;
        }
    }
}

fn check_write_tests(name: const u8[:], a: const u8[:]) {
    let r = compress::zip_open(a);
    if r.err != 0 || r.entries.len != WRITE_TESTS.len { print("FAIL ", name, ": open ", r.err); failures++; return; }
    var i: i64 = 0;
    for e in r.entries {
        let t = WRITE_TESTS[i];
        let got, st = extract(r, a, e);
        if st != 0 || got[..] != write_test_data(i)[..] || compress::zip_name(r, a, e) != t.name ||
           compress::zip_mode(r, a, e) != t.mode || e.method != t.method {
            print("FAIL ", name, " file ", i, ": st ", st, " mode ", compress::zip_mode(r, a, e));
            failures++;
        }
        i++;
    }
}

fn writer_tests() {
    // TestWriter, then TestWriterCopy over its archive.
    var w = compress::zip_writer();
    var a: u8[>..] = [];
    write_tests(w, a);
    if compress::zip_close(w, a) != 0 { fail("close"); }
    check_write_tests("TestWriter", a);
    let src = compress::zip_open(a);
    var w2 = compress::zip_writer();
    var b: u8[>..] = [];
    for e in src.entries { if compress::zip_copy(w2, src, a, e, b) != 0 { fail("copy"); } }
    compress::zip_close(w2, b);
    check_write_tests("TestWriterCopy", b);
    if compress::zip_close(w2, b) != compress::ERR_ARGUMENT { fail("closed twice"); }

    // TestWriterOffset: after 9 bytes of something else.
    var w3 = compress::zip_writer();
    var c: u8[>..] = [1, 2, 3, 1, 2, 3, 1, 2, 3];
    compress::zip_set_offset(w3, 9);
    write_tests(w3, c);
    compress::zip_close(w3, c);
    check_write_tests("TestWriterOffset", c);
    if compress::zip_set_offset(w3, 1) != compress::ERR_ARGUMENT { fail("SetOffset after writing"); }

    // TestWriterComment.
    for n in [0, 1, 65535, 65536] {
        var wc = compress::zip_writer();
        var cmt: u8[>..] = [];
        for k in n { cmt.push(('a' + k % 26) as! u8); }
        let e = compress::zip_set_comment(wc, cmt);
        if n > 65535 {
            if e == 0 { fail("comment too long accepted"); }
            continue;
        }
        var o: u8[>..] = [];
        compress::zip_close(wc, o);
        let r = compress::zip_open(o);
        if r.err != 0 || compress::zip_comment(r, o) != cmt[..] { print("FAIL comment of ", n); failures++; }
    }

    // TestWriterUTF8.
    var wu = compress::zip_writer();
    var u: u8[>..] = [];
    let names: const u8[:][7] = ["hi, hello", "hi, こんにちわ", "hi, こんにちわ", "hi, hello", "hi, こんにちわ",
                                 "the replacement rune is \xef\xbf\xbd", "\x93\xfa\x96{\x8c\xea.txt"];
    let comments: const u8[:][7] = ["in the world", "in the world", "in the world", "in the 世界", "in the 世界",
                                    "the replacement rune is \xef\xbf\xbd", "in the 世界"];
    let flags: u16[7] = [0x8, 0x808, 0x8, 0x808, 0x808, 0x808, 0x008];
    for k in 7 {
        let h = compress::ZipHeader { name: names[k], comment: comments[k], non_utf8: k == 2, method: 8, .. };
        compress::zip_create_header(wu, h, u);
        compress::zip_write(wu, "", u);
    }
    compress::zip_close(wu, u);
    let ru = compress::zip_open(u);
    var k: i64 = 0;
    for e in ru.entries {
        if e.flags != flags[k] { print("FAIL utf8 flags of ", k, ": ", e.flags); failures++; }
        k++;
    }

    // TestWriterTime: byte for byte Go's time-go.zip.
    var wt = compress::zip_writer();
    var t: u8[>..] = [];
    let tm = compress::zip_date(2017, 10, 31, 21 + 7, 11, 57);   // 21:11:57 at -7h
    compress::zip_create_header(wt, compress::ZipHeader { name: "test.txt", modified: compress::zip_time(tm.secs, 0, -7 * 3600), .. }, t);
    compress::zip_close(wt, t);
    var want: u8[>..] = [];
    read_file("vectors/zip/time-go.zip", want);
    if t[..] != want[..] { fail("TestWriterTime: not time-go.zip"); }

    // TestWriterDir and TestWriterDirAttributes.
    var wd = compress::zip_writer();
    var d: u8[>..] = [];
    if compress::zip_create(wd, "dir/", d) != 0 { fail("create dir"); }
    if compress::zip_write(wd, "", d) != 0 { fail("empty write to a directory"); }
    if compress::zip_write(wd, "hello", d) == 0 { fail("write to a directory accepted"); }
    var wa = compress::zip_writer();
    var da: u8[>..] = [];
    compress::zip_create_header(wa, compress::ZipHeader { name: "dir/", method: 8, compressed_size64: 1234,
                                                          uncompressed_size64: 5678, .. }, da);
    compress::zip_close(wa, da);
    let z4: u8[4] = [0; 4];
    let z12: u8[12] = [0; 12];
    if da[6..10] != z4[..] || da[14..26] != z12[..] { fail("TestWriterDirAttributes: local header"); }
    if find(da[..], "PK\x07\x08") >= 0 { fail("TestWriterDirAttributes: a data descriptor"); }

    // TestWriterCreateRaw: stored with a descriptor, deflated without.
    var content2: u8[>..] = [];
    for k2 in 2048 { content2.append("abcdefg"); }
    var comp: u8[>..] = [];
    compress::deflate_encode(content2, comp, 1);
    var wr = compress::zip_writer();
    var ra: u8[>..] = [];
    compress::zip_create_raw(wr, compress::ZipHeader { name: "small store w desc", flags: 8, method: 0,
                             crc32: compress::crc32("gophers"), compressed_size64: 7, uncompressed_size64: 7, .. }, ra);
    compress::zip_write(wr, "gophers", ra);
    compress::zip_create_raw(wr, compress::ZipHeader { name: "small deflate wo desc", method: 8,
                             crc32: compress::crc32(content2), compressed_size64: comp.len as u64,
                             uncompressed_size64: content2.len as u64, .. }, ra);
    compress::zip_write(wr, comp, ra);
    compress::zip_close(wr, ra);
    let rr = compress::zip_open(ra);
    if rr.err != 0 || rr.entries.len != 2 { fail("CreateRaw archive"); }
    else {
        var i2: i64 = 0;
        for e in rr.entries {
            let got, st = extract(rr, ra, e);
            if st != 0 || (i2 == 0 && got[..] != "gophers") || (i2 == 1 && got[..] != content2[..]) {
                print("FAIL CreateRaw file ", i2, ": ", st);
                failures++;
            }
            i2++;
        }
    }

    // TestHeaderTooLongErr: a name or extra field past 65535 bytes.
    var wl = compress::zip_writer();
    var l: u8[>..] = [];
    var long: u8[>..] = [];
    long.resize(65536, 'x');
    if compress::zip_create_header(wl, compress::ZipHeader { name: copy(long), .. }, l) != compress::ERR_TOO_LARGE { fail("long name"); }
    if compress::zip_create_header(wl, compress::ZipHeader { name: "x", extra: copy(long), .. }, l) != compress::ERR_TOO_LARGE { fail("long extra"); }
}

// TestInsecurePaths, and the default (Go 1.27: zipinsecurepath not set).
fn insecure_paths() {
    for name in ["../foo", "/foo", "a/b/../../../c", "a\\b"] {
        var w = compress::zip_writer();
        var a: u8[>..] = [];
        compress::zip_create(w, name, a);
        compress::zip_close(w, a);
        let r = compress::zip_open(a, true);
        if r.err != compress::ERR_INSECURE_PATH || r.entries.len != 1 { print("FAIL insecure ", name, ": ", r.err); failures++; }
        let r2 = compress::zip_open(a);
        if r2.err != 0 || !r2.insecure || r2.entries.len != 1 { print("FAIL insecure, unchecked ", name); failures++; }
    }
    for name in ["foo", "a/b/../c", "./x", "a/./b", "..foo", "a/..b"] {
        if compress::zip_insecure_path(name) { print("FAIL local path called insecure: ", name); failures++; }
    }
}

// TestUnderSize: a file longer than its size says is ErrFormat.
fn under_size() {
    var a: u8[>..] = [];
    read_file("vectors/zip/readme.zip", a);
    let r = compress::zip_open(a);
    for e in r.entries {
        var e2 = e;
        e2.uncompressed_size64 = 1;
        var out: u8[>..] = [];
        let st = compress::zip_extract(r, a, e2, out);
        if st != compress::ERR_FORMAT { print("FAIL under size: ", st); failures++; }
    }
}

// More than 65,535 files: ZIP64's end records, written as Go writes them
// and read back (TestOver65kFiles).
fn over_65k() {
    var w = compress::zip_writer();
    var a: u8[>..] = [];
    let n = 65578;
    for i in n {
        compress::zip_create_header(w, compress::ZipHeader { name: str(i, ".dat"), .. }, a);
    }
    compress::zip_close(w, a);
    let r = compress::zip_open(a);
    if r.err != 0 || r.entries.len != n { print("FAIL over 65k: ", r.err, " ", r.entries.len); failures++; return; }
    var i: i64 = 0;
    for e in r.entries {
        if compress::zip_name(r, a, e) != str(i, ".dat")[..] { print("FAIL over 65k name ", i); failures++; return; }
        i++;
    }
}

// Sizes past 4 GiB (raw files, as Go's zip64 tests fake them): ZIP64 extra
// fields in the local header and the directory, read back.
fn zip64_sizes() {
    var w = compress::zip_writer();
    var a: u8[>..] = [];
    let big: u64 = 5 << 30;
    compress::zip_create_raw(w, compress::ZipHeader { name: "big", method: 0, crc32: 7,
                             compressed_size64: big, uncompressed_size64: big, .. }, a);
    compress::zip_create_raw(w, compress::ZipHeader { name: "edge", method: 0, crc32: 7,
                             compressed_size64: 0xffffffff, uncompressed_size64: 0xfffffffe, .. }, a);
    compress::zip_close(w, a);
    let r = compress::zip_open(a);
    if r.err != 0 || r.entries.len != 2 { fail("zip64 sizes archive"); return; }
    var i: i64 = 0;
    for e in r.entries {
        if i == 0 && (e.uncompressed_size64 != big || e.compressed_size64 != big || e.uncompressed_size != 0xffffffff ||
                      e.reader_version != 45) {
            fail("zip64 big sizes");
        }
        if i == 1 && (e.compressed_size64 != 0xffffffff || e.uncompressed_size64 != 0xfffffffe || e.reader_version != 45) {
            fail("zip64 edge sizes");
        }
        i++;
    }
    // The local header of "big" has its own ZIP64 extra field (no data descriptor).
    if compress::get_le32(a, 18) != 0xffffffff || compress::get_le16(a, 28) != 20 { fail("zip64 local header"); }
}

// The streaming file reader over a tail, and the tail growing as told.
fn tail_and_stream() {
    var a: u8[>..] = [];
    read_file("vectors/zip/readme.zip", a);
    let r0 = compress::zip_open_tail(a[a.len - 30..], a.len);
    if r0.err != compress::ERR_TRUNCATED || r0.need < 0 { print("FAIL short tail: ", r0.err, " ", r0.need); failures++; return; }
    var start = r0.need;
    var rounds = 0;
    loop {
        let rt = compress::zip_open_tail(a[start..], a.len);
        if rt.err != compress::ERR_TRUNCATED || rounds > 5 { break; }
        start = rt.need;
        rounds++;
    }
    let tail = a[start..];
    let r = compress::zip_open_tail(tail, a.len);
    if r.err != 0 || r.entries.len != 1 { print("FAIL tail: ", r.err); failures++; return; }
    for e in r.entries {
        let ho = e.header_offset;
        var f = compress::zip_file_start(e, a[ho..ho + 30], compress::zip_name(r, tail, e));
        compress::zip_file_set_descriptor(f, a[f.data_pos + (e.compressed_size64 as! i64)..]);
        // Fed a byte at a time, read into 3 bytes of room.
        var out: u8[>..] = [];
        var buf: u8[3] = [0; 3];
        var p = f.data_pos;
        var st: i64 = 0;
        loop {
            let n = min(1, a.len - p);
            let used, made, s = compress::zip_file_read(f, a[p..p + n], buf);
            out.append(buf[..made]);
            p += used;
            st = s;
            if s != 0 { break; }
        }
        let whole = compress::zip_open(a);
        let want, wst = extract(whole, a, whole.entries[0]);
        if st != compress::STREAM_END || out[..] != want[..] { print("FAIL streamed file: ", st, " ", out.len); failures++; }
    }
}

fn main() {
    go_testdata("vectors/zip/go_dump.txt", false, 65536);
    go_testdata("vectors/zip/go_dump_check.txt", true, 7);
    writer_tests();
    insecure_paths();
    under_size();
    over_65k();
    zip64_sizes();
    tail_and_stream();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("zip: all passed");
}
