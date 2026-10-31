// compress.xz: xz Utils' own test files (tests/files, public domain: good,
// bad and unsupported .xz files), .lzma and raw LZMA2 files made with
// liblzma, each decoded whole and fed a byte at a time with little room
// for output, against what xz (or liblzma through Python) makes of it
// (vectors/xz/expect.txt); SHA-256 against FIPS 180-2's examples; the
// memory limit; single-stream mode. scripts/xz_differential.py compares
// thousands more with xz.

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.xz;

var failures = 0;

fn fail(a: const u8[:], b: const u8[:]) {
    print("FAIL ", a, ": ", b);
    failures++;
}

fn reader(mode: const u8[:]) -> compress::XzReader {
    if mode == "lzma" { return compress::lzma_reader(); }
    if starts_with(mode, "lzma2:") {
        let n, ok = parse_int(mode[6..]);
        return compress::lzma2_reader(n);
    }
    return compress::xz_reader();
}

// The verdict line for data fed `chunk` bytes at a time with `room` bytes
// of output a call, as expect.txt has it.
fn verdict(mode: const u8[:], data: const u8[:], chunk: i64, room: i64) -> u8[>..] {
    var d = reader(mode);
    var buf: u8[>..] = [];
    for k in room { buf.push(0); }
    var size = 0;
    var crc: u32 = 0;
    var p = 0;
    var err: i64 = 0;
    while true {
        var hi = p + chunk;
        if hi > data.len { hi = data.len; }
        let used, made, st = compress::xz_read(d, data[p..hi], buf[..room]);
        crc = compress::crc32_update(crc, buf[..made]);
        size += made;
        p += used;
        if st < 0 { err = st; break; }
        if used == 0 && made == 0 { break; }
    }
    var out: u8[>..] = [];
    if err < 0 { format(out, "err ", err); }
    else if !compress::xz_done(d) { out.append("short"); }
    else if p < data.len { format(out, "trailing ", size); }
    else {
        format(out, "ok ", size, " ");
        format_uint(out, crc, 16, 8, '0');
    }
    return out;
}

fn files() {
    var manifest: u8[>..] = [];
    if !read_file("vectors/xz/expect.txt", manifest) { fail("expect.txt", "cannot read"); return; }
    var n = 0;
    each_split(manifest, '\n') {
        let line = trim(it);
        if line.len > 0 && line[0] != '#' {
            let f = words(line);
            let want = trim(line[f[0].len + 1 + f[1].len + 1..]);
            var data: u8[>..] = [];
            if !read_file(str("vectors/xz/", f[1]), data) {
                fail(f[1], "cannot read");
            } else {
                n++;
                // Whole, then a byte (or a few) at a time.
                let big = verdict(f[0], data, 1 << 20, 1 << 20);
                if big[..] != want { fail(f[1], str("whole: got '", big, "', want '", want, "'")); }
                let small = verdict(f[0], data, 1, 7);
                if small[..] != want { fail(f[1], str("a byte at a time: got '", small, "', want '", want, "'")); }
                if data.len < 4000 {
                    let tiny = verdict(f[0], data, 3, 1);
                    if tiny[..] != want { fail(f[1], str("3 bytes in, 1 out: got '", tiny, "', want '", want, "'")); }
                }
            }
        }
    };
    if n < 70 { fail("expect.txt", str("only ", n, " files")); }
}

fn hex(p: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for b in p { format_uint(out, b, 16, 2, '0'); }
    return out;
}

fn sha() {
    let a = compress::sha256("abc");
    if hex(a)[..] != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" { fail("sha256 abc", hex(a)); }
    let e = compress::sha256("");
    if hex(e)[..] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" { fail("sha256 empty", hex(e)); }
    let m = compress::sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    if hex(m)[..] != "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" { fail("sha256 448 bits", hex(m)); }
    // A million 'a's, fed in uneven pieces.
    var s = compress::sha256_new();
    var piece: u8[>..] = [];
    for k in 997 { piece.push('a'); }
    var left = 1000000;
    while left > 0 {
        let n = if left < 997 { left } else { 997 };
        compress::sha256_update(s, piece[..n]);
        left -= n;
    }
    let mil = compress::sha256_final(s);
    if hex(mil)[..] != "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0" { fail("sha256 million", hex(mil)); }
}

fn limits() {
    var data: u8[>..] = [];
    if !read_file("vectors/xz/good-1-lzma2-1.xz", data) { fail("limits", "cannot read"); return; }
    // The file's dictionary is 8 MiB... a limit below it refuses the block.
    var d = compress::xz_reader();
    compress::xz_set_memlimit(d, 4096);
    var out: u8[>..] = [];
    for k in 1000 { out.push(0); }
    let used, made, st = compress::xz_read(d, data, out);
    if st != compress::ERR_LIMIT { fail("memlimit", str("got ", st)); }
    // Whole-buffer helpers, with an output limit.
    var whole: u8[>..] = [];
    if compress::xz_decode(data, whole, -1) != 0 || whole.len != 457 { fail("xz_decode", str(whole.len)); }
    var lim: u8[>..] = [];
    if compress::xz_decode(data, lim, 100) != compress::ERR_LIMIT { fail("xz_decode limit", "not refused"); }
    var lz: u8[>..] = [];
    if !read_file("vectors/xz/alone-eopm.lzma", lz) { fail("lzma", "cannot read"); return; }
    var lo: u8[>..] = [];
    if compress::lzma_decode(lz, lo, -1) != 0 || lo.len != 1206 { fail("lzma_decode", str(lo.len)); }
    lz.append("junk");
    var lo2: u8[>..] = [];
    if compress::lzma_decode(lz, lo2, -1) != compress::ERR_TRAILING { fail("lzma_decode trailing", "not refused"); }
    var tr: u8[>..] = [];
    if compress::xz_decode(data[..data.len - 1], tr, -1) != compress::ERR_TRUNCATED { fail("xz_decode truncated", "not refused"); }
}

fn streams() {
    // Two streams with padding: whole as a file; single-stream mode stops
    // after the first and takes nothing of the rest.
    var a: u8[>..] = [];
    var b: u8[>..] = [];
    if !read_file("vectors/xz/good-1-check-crc64.xz", a) || !read_file("vectors/xz/good-1-check-sha256.xz", b) {
        fail("streams", "cannot read");
        return;
    }
    var both: u8[>..] = [];
    both.append(a);
    both.append([0, 0, 0, 0]);
    both.append(b);
    var out: u8[>..] = [];
    if compress::xz_decode(both, out, -1) != 0 || out.len != 26 { fail("two streams", str(out.len)); }
    var d = compress::xz_reader();
    compress::xz_set_single_stream(d, true);
    var o: u8[100] = [0; 100];
    let used, made, st = compress::xz_read(d, both, o);
    if st != compress::STREAM_END || used != a.len || made != 13 || !compress::xz_done(d) {
        fail("single stream", str(st, " ", used, " ", made));
    }
    let used2, made2, st2 = compress::xz_read(d, both[used..], o);
    if used2 != 0 || made2 != 0 || st2 != compress::STREAM_END { fail("single stream after", str(st2, " ", used2)); }
    // The unverifiable check is decoded and said so.
    var u: u8[>..] = [];
    if !read_file("vectors/xz/unsupported-check.xz", u) { fail("unsupported-check", "cannot read"); return; }
    var d2 = compress::xz_reader();
    let used3, made3, st3 = compress::xz_read(d2, u, o);
    if st3 != compress::STREAM_END || !compress::xz_check_unverified(d2) { fail("unsupported check", str(st3)); }
    // Padding that is not a multiple of four is not whole.
    var d3 = compress::xz_reader();
    both.resize(a.len + 2);
    let used4, made4, st4 = compress::xz_read(d3, both, o);
    if compress::xz_done(d3) { fail("padding of 2", "taken as whole"); }
}

fn main() {
    sha();
    files();
    limits();
    streams();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("xz: all passed");
}
