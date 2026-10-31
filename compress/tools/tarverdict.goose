// tarverdict: the compress package's tar reader and writer on the inputs
// scripts/tar_differential.py gives it, printed as `gooracle tar` prints
// Go's (see tools/gooracle/tar.go for the format).
//
//	goose tools/tarverdict.goose -- read [-cap N] [-chunk N] [-check] archive...
//	goose tools/tarverdict.goose -- write spec out.tar
//
// -chunk feeds the reader that many bytes at a time (default: all);
// -check flags insecure paths, as GODEBUG=tarinsecurepath=0 does in Go.

import std;
import os;
import compress from "..";
import compress.tar;

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

fn write_class(code: i64, why: i64) -> const u8[:] {
    if code == 0 { return "ok"; }
    match why {
        compress::TAR_WHY_CANNOT_ENCODE => "cannot-encode",
        compress::TAR_WHY_WRITE_TOO_LONG => "write-too-long",
        compress::TAR_WHY_MISSED_WRITING => "missed-writing",
        compress::TAR_WHY_WRITE_AFTER_CLOSE => "after-close",
        compress::TAR_WHY_FIELD_TOO_LONG => "field-too-long",
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

fn read_archive(out: u8[>..]&, data: const u8[:], cap: i64, chunk: i64, check: bool) {
    var r = compress::tar_reader(check);
    var buf: u8[32768] = [0; 32768];
    var at = 0;
    var in_data = false;
    var n: i64 = 0;
    var crc: u32 = 0;
    while true {
        let end = min(data.len, at + chunk);
        let room = if in_data { min(32768, cap - n) } else { 0 };
        let used, made, st = compress::tar_read(r, data[at..end], buf[..room]);
        at += used;
        if made > 0 {
            crc = compress::crc32_update(crc, buf[..made]);
            n += made;
        }
        if st < 0 {
            if in_data { format(out, "data ", n, " "); format_uint(out, crc, 16, 8, '0'); format(out, " err ", read_class(st, compress::tar_why(r)), "\n"); }
            format(out, "end ", read_class(st, compress::tar_why(r)), "\n");
            return;
        }
        if st == compress::STREAM_END {
            if in_data { format(out, "data ", n, " "); format_uint(out, crc, 16, 8, '0'); out.push('\n'); }
            out.append("end EOF\n");
            return;
        }
        if in_data && (!compress::tar_in_entry(r) || n >= cap) {
            if compress::tar_in_entry(r) { compress::tar_skip(r); }
            // This entry's contents are read (as far as -cap allows).
            format(out, "data ", n, " ");
            format_uint(out, crc, 16, 8, '0');
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
            if in_data && e < 0 { format(out, "data ", n, " "); format_uint(out, crc, 16, 8, '0'); format(out, " err ", read_class(e, compress::tar_why(r)), "\n"); }
            else if in_data { format(out, "data ", n, " "); format_uint(out, crc, 16, 8, '0'); out.push('\n'); }
            format(out, "end ", read_class(e, compress::tar_why(r)), "\n");
            return;
        }
    }
}

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

fn unhex_into(out: u8[>..]&, s: const u8[:]) -> compress::TarSpan {
    let off = out.len;
    if s != "-" {
        var i = 0;
        while i + 1 < s.len { out.push((hexval(s[i]) * 16 + hexval(s[i + 1])) as! u8); i += 2; }
    }
    return compress::TarSpan { off: off, len: out.len - off };
}

fn spec_time(s: const u8[:]) -> compress::TarTime {
    if s == "zero" { return compress::TarTime { .. }; }
    let dot = position(s, '.');
    if dot < 0 { let v, ok = parse_int(s); return compress::tar_time(v); }
    let a, ok1 = parse_int(s[..dot]);
    let b, ok2 = parse_int(s[dot + 1..]);
    return compress::tar_time(a, b);
}

fn num(s: const u8[:]) -> i64 { let v, ok = parse_int(s); return v; }

fn write_spec(out: u8[>..]&, spec: const u8[:], path: const u8[:]) -> bool {
    var w = compress::tar_writer();
    var tar: u8[>..] = [];
    each_split(spec, '\n') {
        let f = words(it);
        if f.len == 18 {
            var store: u8[>..] = [];
            let sn = unhex_into(store, f[1]);
            let sl = unhex_into(store, f[2]);
            let su = unhex_into(store, f[7]);
            let sg = unhex_into(store, f[8]);
            let sp = unhex_into(store, f[15]);
            let h = compress::TarHeader {
                typeflag: num(f[0]) as! u8,
                name: store[sn.off..sn.off + sn.len],
                linkname: store[sl.off..sl.off + sl.len],
                size: num(f[3]), mode: num(f[4]), uid: num(f[5]), gid: num(f[6]),
                uname: store[su.off..su.off + su.len],
                gname: store[sg.off..sg.off + sg.len],
                mtime: spec_time(f[9]), atime: spec_time(f[10]), ctime: spec_time(f[11]),
                devmajor: num(f[12]), devminor: num(f[13]),
                pax: store[sp.off..sp.off + sp.len], format: num(f[14]),
            };
            let e = compress::tar_write_header(w, h, tar);
            format(out, "wh ", write_class(e, compress::tar_writer_why(w)), "\n");
            var data: u8[>..] = [];
            var x = num(f[17]) as! u32;
            for i in num(f[16]) {
                x = x * 1103515245 + 12345;
                data.push(((x >> 16) & 0xff) as! u8);
            }
            let n, e2 = compress::tar_write(w, data, tar);
            format(out, "w ", n, " ", write_class(e2, compress::tar_writer_why(w)), "\n");
        }
    };
    let e = compress::tar_close(w, tar);
    format(out, "close ", write_class(e, compress::tar_writer_why(w)), "\n");
    return write_file(path, tar);
}

fn main() {
    let a = args();
    if a.len < 2 { print("usage: tarverdict read [-cap N] [-chunk N] [-check] archive... | write spec out.tar"); exit(2); }
    var out: u8[>..] = [];
    if a[1] == "write" {
        if a.len != 4 { print("usage: tarverdict write spec out.tar"); exit(2); }
        var spec: u8[>..] = [];
        if !read_file(a[2], spec) { print("tarverdict: cannot read ", a[2]); exit(1); }
        if !write_spec(out, spec, a[3]) { print("tarverdict: cannot write ", a[3]); exit(1); }
        write_stdout(out);
        flush_stdout();
        return;
    }
    var cap: i64 = 16 << 20;
    var chunk: i64 = 1 << 62;
    var check = false;
    var i = 2;
    while i < a.len {
        if a[i] == "-cap" { cap = num(a[i + 1]); i += 2; continue; }
        if a[i] == "-chunk" { chunk = num(a[i + 1]); i += 2; continue; }
        if a[i] == "-check" { check = true; i++; continue; }
        var data: u8[>..] = [];
        if !read_file(a[i], data) { print("tarverdict: cannot read ", a[i]); exit(1); }
        format(out, "archive ", a[i], "\n");
        read_archive(out, data, cap, chunk, check);
        write_stdout(out);
        out.clear();
        i++;
    }
    flush_stdout();
}
