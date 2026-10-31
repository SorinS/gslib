// compress.flate, compress.zlib and compress.gzip decoding: Go's own
// vectors (flate_test.go's TestStreams, TestTruncatedStreams, the Huffman
// code tests, the .golden streams of compress/flate/testdata), streams made
// by Python's zlib, gzip header fields, preset dictionaries and errors,
// each fed whole, a byte at a time and in odd pieces, into output buffers
// of 1 byte upward. scripts/flate_differential.py compares thousands more
// with Go.

import std;
import os;
import gslib from "../..";
import gslib.compress;
import gslib.compress.flate;
import gslib.compress.zlib;
import gslib.compress.gzip;

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
    var i = 0;
    while i + 1 < s.len {
        out.push((hexval(s[i]) * 16 + hexval(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

let RAW: u8 = 0;
let ZLIB: u8 = 1;
let GZIP: u8 = 2;

// Decodes s fed `chunk` bytes at a time into a buffer of `room`: the
// output, and 0 or the error (ERR_TRUNCATED when the input ends early).
fn decode(format: u8, s: const u8[:], chunk: i64, room: i64, dict: const u8[:] = "") -> u8[>..], i64 {
    var out: u8[>..] = [];
    var buf: u8[>..] = [];
    buf.resize(room, 0);
    var d = compress::inflate_reader();
    compress::inflate_set_dictionary(d, dict);
    var z = compress::zlib_reader_dict(dict);
    var g = compress::gzip_reader();
    var p: i64 = 0;
    var e: i64 = 0;
    loop {
        let n = min(chunk, s.len - p);
        var used: i64 = 0;
        var made: i64 = 0;
        var st: i64 = 0;
        if format == RAW {
            used, made, st = compress::inflate_read(d, s[p..p + n], buf);
        } else if format == ZLIB {
            used, made, st = compress::zlib_read(z, s[p..p + n], buf);
        } else {
            used, made, st = compress::gzip_read(g, s[p..p + n], buf);
        }
        out.append(buf[..made]);
        p += used;
        if st < 0 { return out, st; }
        if st == compress::STREAM_END && (p >= s.len || format != GZIP) { break; }
        if used == 0 && made == 0 && p >= s.len { break; }
    }
    if format == RAW { e = if compress::inflate_done(d) { 0 } else { compress::ERR_TRUNCATED }; }
    else if format == ZLIB { e = compress::zlib_finish(z); }
    else { e = compress::gzip_finish(g); }
    return out, e;
}

// Every way of feeding s gives `want` and the error `want_err`.
fn expect(name: const u8[:], format: u8, s: const u8[:], want: const u8[:], want_err: i64, dict: const u8[:] = "") {
    for chunk in [1, 3, 1 << 30] {
        for room in [1, 7, 65536] {
            if chunk == 1 && room == 1 && s.len > 5000 { continue; }
            let out, e = decode(format, s, chunk, room, dict);
            if e != want_err || out[..] != want {
                print("FAIL ", name, " chunk ", chunk, " room ", room, ": err ", e, " (want ", want_err, "), ",
                      out.len, " bytes (want ", want.len, ")");
                failures++;
                return;
            }
        }
    }
}

// Go's TestStreams: raw streams that decode to `want` or fail.
fn go_streams() {
    var text: u8[>..] = [];
    if !read_file("vectors/flate/go_streams.txt", text) { fail("cannot read vectors/flate/go_streams.txt"); return; }
    var n = 0;
    each_split(text, '\n') {
        if it.len > 0 && it[0] != '#' {
            let f = split(it, ' ');
            let s = unhex(f[1]);
            if f[0] == "fail" {
                // Go refuses each; so must we, fed any way.
                for chunk in [1, 1 << 30] {
                    let out, e = decode(RAW, s, chunk, 65536);
                    if e == 0 { print("FAIL go stream accepted: ", it); failures++; }
                }
            } else {
                let want = if f[0] == "-" { unhex("") } else { unhex(f[0]) };
                expect(it[f[0].len + f[1].len + 2..], RAW, s, want, 0);
            }
            n++;
        }
    };
    if n != 28 { fail("go_streams.txt: not 28 cases"); }
}

fn verdict_code(v: const u8[:]) -> i64 {
    if v == "ok" { return 0; }
    if v == "truncated" { return compress::ERR_TRUNCATED; }
    if v == "checksum" { return compress::ERR_CHECKSUM; }
    if v == "header" { return compress::ERR_HEADER; }
    if v == "dictionary" { return compress::ERR_DICTIONARY; }
    if v == "data" { return compress::ERR_DATA; }
    return 99;
}

// Go's gunzipTests (gunzip_test.go): the verdict, the output (also before
// an error, as Go's test checks it) and the first member's name.
fn go_gunzip_tests() {
    var text: u8[>..] = [];
    if !read_file("vectors/flate/go_gunzip_tests.txt", text) { fail("cannot read go_gunzip_tests.txt"); return; }
    var n = 0;
    each_split(text, '\n') {
        if it.len > 0 && it[0] != '#' {
            let f = split(it, ' ');
            let s = unhex(f[2]);
            let want = if f[3] == "-" { unhex("") } else { unhex(f[3]) };
            let want_name = if f[1] == "-" { unhex("") } else { unhex(f[1]) };
            expect(it[f[0].len + f[1].len + f[2].len + f[3].len + 4..], GZIP, s, want, verdict_code(f[0]));
            var r = compress::gzip_reader();
            var out: u8[>..] = [];
            compress::gzip_decode_with(r, s, out, -1);
            var name: u8[>..] = [];
            compress::gzip_latin1_to_utf8(r.name, name);
            if name[..] != want_name { print("FAIL gunzip test name: ", name, " want ", want_name); failures++; }
            n++;
        }
    };
    if n != 15 { fail("go_gunzip_tests.txt: not 15 cases"); }
}

// Go's zlibTests (reader_test.go): the verdict, and the output when there
// is no error (as Go's test checks it), with the dictionary given.
fn go_zlib_tests() {
    var text: u8[>..] = [];
    if !read_file("vectors/flate/go_zlib_tests.txt", text) { fail("cannot read go_zlib_tests.txt"); return; }
    var n = 0;
    each_split(text, '\n') {
        if it.len > 0 && it[0] != '#' {
            let f = split(it, ' ');
            let dict = if f[1] == "-" { unhex("") } else { unhex(f[1]) };
            let s = if f[2] == "-" { unhex("") } else { unhex(f[2]) };
            let want = if f[3] == "-" { unhex("") } else { unhex(f[3]) };
            let code = verdict_code(f[0]);
            for chunk in [1, 1 << 30] {
                let out, e = decode(ZLIB, s, chunk, 7, dict);
                if e != code || (code == 0 && out[..] != want) {
                    print("FAIL zlib test ", it, ": err ", e, ", ", out.len, " bytes");
                    failures++;
                }
            }
            n++;
        }
    };
    if n != 14 { fail("go_zlib_tests.txt: not 14 cases"); }
}

// compress/flate/testdata's .golden files are Go's Huffman-only encodings
// of the .in files, without a final block: they decode to the .in file and
// then end too soon, in Go and here.
fn go_golden() {
    for name in ["huffman-null-max", "huffman-pi", "huffman-rand-1k", "huffman-rand-limit", "huffman-rand-max",
                 "huffman-shifts", "huffman-text-shift", "huffman-text", "huffman-zero"] {
        var s: u8[>..] = [];
        var want: u8[>..] = [];
        if !read_file(str("vectors/flate/", name, ".golden"), s) || !read_file(str("vectors/flate/", name, ".in"), want) {
            fail(str("cannot read vectors/flate/", name));
            continue;
        }
        expect(name, RAW, s, want, compress::ERR_TRUNCATED);
    }
}

fn huffman_codes() {
    // Go's TestIssue5915, TestIssue5962, TestIssue6255, TestInvalidBits.
    var h = compress::huff_code();
    let bad1: u8[63] = [4, 0, 0, 6, 4, 3, 2, 3, 3, 4, 4, 5, 0, 0, 0, 0, 5, 5, 6,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7, 8, 6, 0, 11, 0, 8, 0, 6, 6, 10, 8];
    if compress::huff_build(h, bad1) { fail("issue 5915 lengths accepted"); }
    let bad2: u8[30] = [4, 0, 0, 6, 4, 3, 2, 3, 3, 4, 4, 5, 0, 0, 0, 0, 5, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11];
    if compress::huff_build(h, bad2) { fail("issue 5962 lengths accepted"); }
    let good: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 11];
    if !compress::huff_build(h, good) { fail("issue 6255 good lengths refused"); }
    let bad3: u8[2] = [11, 13];
    if compress::huff_build(h, bad3) { fail("issue 6255 bad lengths accepted"); }
    let over: u8[6] = [1, 2, 3, 4, 4, 5];
    if compress::huff_build(h, over) { fail("oversubscribed lengths accepted"); }
    let incomplete: u8[4] = [1, 2, 4, 4];
    if compress::huff_build(h, incomplete) { fail("incomplete lengths accepted"); }
    let single: u8[1] = [1];
    if !compress::huff_build(h, single) { fail("a single one-bit code refused"); }
    let none: u8[3] = [0, 0, 0];
    if !compress::huff_build(h, none) { fail("no codes refused"); }
}

// Go's TestTruncatedStreams: every proper prefix of a stream ends too soon.
fn truncated() {
    let data = "\x00\x0c\x00\xf3\xffhello, world\x01\x00\x00\xff\xff";
    for i in data.len - 1 {
        let out, e = decode(RAW, data[..i], 1 << 30, 65536);
        if e != compress::ERR_TRUNCATED { print("FAIL truncated stream ", i, ": err ", e); failures++; }
    }
    let out, e = decode(RAW, data, 1, 1);
    if e != 0 || out[..] != "hello, world" { fail("the whole truncated-test stream"); }
    // Go's TestNlitOutOfRange: refused, no crash.
    let bogus = unhex("fcfe36e75e1cefb3555877b656b543f46ff2d2e63d99a0858c48ebf8da83042a75c4f80f1211b9b44b09a0be8b914c");
    let o2, e2 = decode(RAW, bogus, 1, 1);
    if e2 == 0 { fail("nlit out of range accepted"); }
}

fn python_streams() {
    expect("gzip with a name", GZIP,
           unhex("1f8b080800000000000368656c6c6f2e74787400cb48cdc9c9d75128cf2fca49e10200537424f40d000000"), "hello, world\n", 0);
    expect("gzip empty", GZIP, unhex("1f8b080000000000000303000000000000000000"), "", 0);
    expect("gzip two members", GZIP,
           unhex("1f8b0800000000000003cbcf4b5500004961ac23040000001f8b08000000000000032b29cf0700668aca1103000000"), "one two", 0);
    expect("zlib", ZLIB, unhex("78da4b494dcb492c4955c8cc53f008090950c82c56a8cac94c0200610f07fa"), "deflate in HTTP is zlib", 0);
    expect("raw deflate", RAW, unhex("2b4a2c5748494dcb492c49d551482c5628cecf4d55284e2d2a4b2d027252f35200"),
           "raw deflate, as some servers send", 0);
    var all: u8[>..] = [];
    for r in 2 { for b in 256 { all.push(b as! u8); } }
    expect("gzip dynamic", GZIP, unhex("1f8b08000000000000036360646266616563e7e0e4e2e6e1e5e3171014121611151397909492969195935750545256515553d7d0d4d2d6d1d5d33730343236313533b7b0b4b2b6b1b5b37770747276717573f7f0f4f2f6f1f5f30f080c0a0e090d0b8f888c8a8e898d8b4f484c4a4e494d4bcfc8cccacec9cdcb2f282c2a2e292d2bafa8acaaaea9adab6f686c6a6e696d6befe8eceaeee9edeb9f3071d2e42953a74d9f3173d6ec3973e7cd5fb070d1e2254b972d5fb172d5ea356bd7addfb071d3e62d5bb76ddfb173d7ee3d7bf7ed3f70f0d0e123478f1d3f71f2d4e93367cf9dbf70f1d2e52b57af5dbf71f3d6ed3b77efdd7ff0f0d1e3274f9f3d7ff1f2d5eb376fdfbdfff0f1d3e72f5fbf7dfff1f3d7ef3f7ffffd6718e1fe07007635611c00020000"), all, 0);
    expect("stored", RAW, unhex("010500faff68656c6c6f"), "hello", 0);
    // A zlib stream with a preset dictionary (Python: compressobj(zdict=b"hello, hello")).
    let zd = unhex("78f91cda0475031300062c0215");
    expect("zlib with its dictionary", ZLIB, zd, "hello", 0, "hello, hello");
    expect("zlib without its dictionary", ZLIB, zd, "", compress::ERR_DICTIONARY);
    expect("zlib with another dictionary", ZLIB, zd, "", compress::ERR_DICTIONARY, "hello, hellO");
    // Raw DEFLATE against a dictionary.
    expect("raw with a dictionary", RAW, unhex("031300"), "hello", 0, "hello, hello");
}

fn errors() {
    expect("not gzip", GZIP, unhex("1f8c0800000000000003"), "", compress::ERR_HEADER);
    expect("bad crc", GZIP, unhex("1f8b080000000000000303000000000100000000"), "", compress::ERR_CHECKSUM);
    expect("bad length", GZIP, unhex("1f8b080000000000000303000000000000000001"), "", compress::ERR_CHECKSUM);
    expect("bad adler", ZLIB, unhex("78da4b494dcb492c4955c8cc53f008090950c82c56a8cac94c0200610f07fb"),
           "deflate in HTTP is zlib", compress::ERR_CHECKSUM);
    expect("zlib bad check bits", ZLIB, unhex("78db4b494dcb"), "", compress::ERR_HEADER);
    expect("zlib method 7", ZLIB, unhex("77"), "", compress::ERR_TRUNCATED);
    expect("cut short", GZIP, unhex("1f8b08000000000000030300000000"), "", compress::ERR_TRUNCATED);
    // After a member: ten bytes that are not a header are a bad header;
    // fewer are a header cut short (Go reads ten first).
    expect("trailing junk", GZIP, unhex("1f8b0800000000000003030000000000000000006a756e6b"), "", compress::ERR_TRUNCATED);
    expect("trailing junk, 10 bytes", GZIP, unhex("1f8b08000000000000030300000000000000000030313233343536373839"), "",
           compress::ERR_HEADER);
    expect("block type 3", RAW, unhex("0700"), "", compress::ERR_DATA);
    expect("stored nlen", RAW, unhex("010500fbff68656c6c6f"), "", compress::ERR_DATA);
    expect("distance too far", RAW, unhex("030200"), "", compress::ERR_DATA);
    expect("no input", RAW, "", "", compress::ERR_TRUNCATED);
    // zlib and raw streams stop at their end; what follows is not theirs.
    expect("zlib then junk", ZLIB, unhex("78da4b494dcb492c4955c8cc53f008090950c82c56a8cac94c0200610f07fa6a756e6b"),
           "deflate in HTTP is zlib", 0);
}

fn gzip_member(name_len: i64, comment_len: i64, extra_len: i64, hcrc: bool) -> u8[>..] {
    var m: u8[>..] = [];
    var flags: u8 = 0;
    if extra_len >= 0 { flags |= compress::GZIP_FEXTRA; }
    if name_len >= 0 { flags |= compress::GZIP_FNAME; }
    if comment_len >= 0 { flags |= compress::GZIP_FCOMMENT; }
    if hcrc { flags |= compress::GZIP_FHCRC; }
    m.append([0x1f, 0x8b, 8, flags, 0x78, 0x56, 0x34, 0x12, 2, 3]);
    if extra_len >= 0 {
        compress::put_le16(m, extra_len as! u64);
        for k in extra_len { m.push(((k * 13) % 256) as! u8); }
    }
    if name_len >= 0 {
        for k in name_len { m.push(if k % 7 == 0 { 0xe9 } else { 'n' }); }
        m.push(0);
    }
    if comment_len >= 0 {
        for k in comment_len { m.push('c'); }
        m.push(0);
    }
    if hcrc { compress::put_le16(m, (compress::crc32(m) & 0xffff)); }
    // "hi" as a fixed-Huffman block, and its trailer.
    m.append([0xcb, 0xc8, 0x04, 0x00]);
    compress::put_le32(m, compress::crc32("hi"));
    compress::put_le32(m, 2);
    return m;
}

// gzip's header fields: kept from the first member, read as they come,
// and Go's limit of 511 bytes for a name or comment.
fn gzip_headers() {
    let m = gzip_member(511, 511, 65535, true);
    expect("long header fields", GZIP, m, "hi", 0);
    var g = compress::gzip_reader();
    var buf: u8[>..] = [];
    buf.resize(100, 0);
    let used, made, st = compress::gzip_read(g, m, buf);
    if st != compress::STREAM_END || made != 2 { fail("gzip header member"); }
    if g.name.len != 511 || g.comment.len != 511 || g.extra.len != 65535 || g.mtime != 0x12345678 || g.os != 3 || g.xfl != 2 {
        print("FAIL header fields: name ", g.name.len, " comment ", g.comment.len, " extra ", g.extra.len,
              " mtime ", g.mtime, " os ", g.os);
        failures++;
    }
    if g.extra[1000] != 200 { fail("FEXTRA bytes"); }
    var u: u8[>..] = [];
    compress::gzip_latin1_to_utf8(g.name[..8], u);
    if u[..] != "\xc3\xa9nnnnnn\xc3\xa9" { print("FAIL latin1 name: ", u); failures++; }
    expect("name of 512", GZIP, gzip_member(512, -1, -1, false), "", compress::ERR_HEADER);
    expect("comment of 512", GZIP, gzip_member(-1, 512, -1, true), "", compress::ERR_HEADER);
    // A wrong FHCRC.
    var bad = gzip_member(10, 10, 10, true);
    bad[10 + 2 + 10 + 11 + 11] ^= 1;
    expect("wrong FHCRC", GZIP, bad, "", compress::ERR_HEADER);
    // Reserved flag bits are ignored, as Go ignores them.
    var res = gzip_member(-1, -1, -1, false);
    res[3] = 0xe0;
    expect("reserved flags", GZIP, res, "hi", 0);
    // Several members, the second's header fields not kept.
    var two = gzip_member(3, -1, -1, false);
    two.append(gzip_member(5, 5, 5, true));
    expect("two members", GZIP, two, "hihi", 0);
    // Multistream off: one member, the rest left.
    var g1 = compress::gzip_reader();
    compress::gzip_set_multistream(g1, false);
    let u1, m1, s1 = compress::gzip_read(g1, two, buf);
    if s1 != compress::STREAM_END || m1 != 2 || u1 != gzip_member(3, -1, -1, false).len {
        print("FAIL multistream off: used ", u1, " made ", m1, " st ", s1);
        failures++;
    }
}

// The decoder's memory is fixed: a stream that expands a thousandfold is
// handed out through a small buffer.
fn bomb() {
    // 10 MB of zeros as raw DEFLATE (Python, level 9): about 10 KB.
    var zeros: u8[>..] = [];
    // A stored-free stream built by hand: fixed block, literal 0, then
    // matches of 258 at distance 1, repeated, and the end of block.
    // Each 258-byte match is 7 + 5 bits (length 258 is code 285: 8 bits; distance 1: 5 bits).
    var w = compress::bit_writer();
    compress::bw_bits(w, zeros, 1, 1);                // BFINAL
    compress::bw_bits(w, zeros, 1, 2);                // BTYPE 01
    compress::bw_bits(w, zeros, 0x0c, 8);             // literal 0: 00110000 reversed
    for k in 40000 {
        compress::bw_bits(w, zeros, 0xa3, 8);         // 285: 11000101 reversed
        compress::bw_bits(w, zeros, 0, 5);            // distance code 0
    }
    compress::bw_bits(w, zeros, 0, 7);                // end of block
    compress::bw_flush(w, zeros);
    var d = compress::inflate_reader();
    var buf: u8[4096] = [0; 4096];
    var total: i64 = 0;
    var p: i64 = 0;
    loop {
        let used, made, st = compress::inflate_read(d, zeros[p..], buf);
        p += used;
        total += made;
        for k in made { if buf[k] != 0 { fail("bomb output not zero"); return; } }
        if st != 0 { break; }
    }
    if total != 1 + 40000 * 258 || p != zeros.len { print("FAIL bomb: ", total, " bytes, ", p, " used"); failures++; }
}

// A match that ends exactly at the end of the window, from the fast
// loop: 1 + 125 * 258 + 3 + 256 = 32510 bytes, then a match of 258 fills
// the window to 32768, then a literal and more.
fn window_edge() {
    var s: u8[>..] = [];
    var w = compress::bit_writer();
    compress::bw_bits(w, s, 3, 3);                    // BFINAL, fixed
    compress::bw_bits(w, s, 0x0c, 8);                 // literal 0
    for k in 125 {
        compress::bw_bits(w, s, 0xa3, 8);             // length 258
        compress::bw_bits(w, s, 0, 5);                // distance 1
    }
    compress::bw_bits(w, s, 0x40, 7);                 // length 3
    compress::bw_bits(w, s, 0, 5);
    compress::bw_bits(w, s, 0x23, 8);                 // length 227 + 29 = 256
    compress::bw_bits(w, s, 29, 5);
    compress::bw_bits(w, s, 0, 5);
    compress::bw_bits(w, s, 0xa3, 8);                 // length 258
    compress::bw_bits(w, s, 0, 5);
    compress::bw_bits(w, s, 0x0c, 8);                 // literal 0
    for k in 100 {                                    // more input after it
        compress::bw_bits(w, s, 0xa3, 8);
        compress::bw_bits(w, s, 0, 5);
    }
    compress::bw_bits(w, s, 0, 7);                    // end of block
    compress::bw_flush(w, s);
    var want: u8[>..] = [];
    want.resize(32769 + 25800, 0);
    expect("a match to the window's end", RAW, s, want, 0);
}

fn main() {
    window_edge();
    go_streams();
    go_golden();
    go_gunzip_tests();
    go_zlib_tests();
    huffman_codes();
    truncated();
    python_streams();
    errors();
    gzip_headers();
    bomb();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("flate: all passed");
}
