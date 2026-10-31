// compress.deflate, and the gzip and zlib writers: round trips at every
// level through our own readers, written in pieces with flushes, preset
// dictionaries, the headers Go writes, and the errors. Every stream is
// also checked to end where its reader says it does.
// scripts/deflate_differential.py has Go and zlib read thousands more.

import std;
import compress from "..";
import compress.flate;
import compress.deflate;
import compress.zlib;
import compress.gzip;

var failures = 0;

fn fail(what: const u8[:]) {
    print("FAIL ", what);
    failures++;
}

fn inputs() -> u8[][>..] {
    var xs: u8[][>..] = [];
    xs.push("");
    xs.push("a");
    xs.push("hello, hello, hello, hello");
    var r = rng { 12345 };
    var random: u8[>..] = [];
    for k in 70000 { random.push((r.rand_u64() & 0xff) as! u8); }
    xs.push(copy(random));
    var zeros: u8[>..] = [];
    zeros.resize(200000, 0);
    xs.push(copy(zeros));
    var text: u8[>..] = [];
    let words = ["the ", "quick ", "brown ", "fox ", "jumps ", "over ", "lazy ", "dog\n", "{\"key\": 12}, "];
    while text.len < 150000 { text.append(words[r.rand_int(words.len)]); }
    xs.push(copy(text));
    var runs: u8[>..] = [];
    while runs.len < 100000 {
        let c = (r.rand_u64() & 3) as! u8;
        for k in r.rand_int(600) { runs.push(c); }
    }
    xs.push(copy(runs));
    return xs;
}

// Writes data at `level` `chunk` bytes a call, flushing every `flush`
// bytes (0: never), as raw DEFLATE; checks that it decodes to data, and
// that each flush point decodes to everything before it.
fn round_trip(data: const u8[:], level: i64, chunk: i64, flush: i64) {
    var w = compress::deflate_writer(level);
    var out: u8[>..] = [];
    var p: i64 = 0;
    var since: i64 = 0;
    while p < data.len {
        var n = min(chunk, data.len - p);
        if flush > 0 { n = min(n, flush - since); }
        if compress::deflate_write(w, data[p..p + n], out) != 0 { fail("deflate_write"); return; }
        p += n;
        since += n;
        if flush > 0 && since == flush {
            compress::deflate_flush(w, out);
            since = 0;
            // Everything so far decodes, the stream not yet ended.
            var part: u8[>..] = [];
            let e = compress::inflate_decode(out, part);
            if e != compress::ERR_TRUNCATED || part[..] != data[..p] {
                print("FAIL level ", level, ": after a flush at ", p, " the stream gives ", part.len, " bytes, err ", e);
                failures++;
                return;
            }
        }
    }
    if compress::deflate_close(w, out) != 0 { fail("deflate_close"); return; }
    if compress::deflate_close(w, out) != 0 { fail("a second close"); }
    if compress::deflate_write(w, "x", out) != compress::ERR_ARGUMENT { fail("write after close"); }
    var back: u8[>..] = [];
    var d = compress::inflate_reader();
    // Decode with junk after the stream: the decoder must stop at its end.
    var s = copy(out);
    s.append("JUNK");
    let e = compress::inflate_decode_with(d, s, back, -1);
    if e != 0 || back[..] != data || d.total_in != out.len {
        print("FAIL level ", level, " chunk ", chunk, " flush ", flush, " len ", data.len, ": err ", e, ", ",
              back.len, " bytes back, ", d.total_in, " of ", out.len, " taken");
        failures++;
    }
}

fn levels(xs: const u8[][>..]&) {
    for x in xs {
        for level in [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9] {
            round_trip(x, level, 1 << 30, 0);
        }
        for level in [0, 1, 6, 9, -2] {
            round_trip(x, level, 1000, 0);
            if x.len < 100000 { round_trip(x, level, 7, 7777); }
            round_trip(x, level, 65536, 30000);
        }
    }
    // A byte at a time, with a flush after each byte, at a few levels.
    for level in [0, 1, 6, -2] {
        round_trip("abracadabra, abracadabra", level, 1, 1);
    }
}

// Compression actually compresses, and level 0 is stored only.
fn sizes(xs: const u8[][>..]&) {
    for x, i in xs {
        var o0: u8[>..] = [];
        var o1: u8[>..] = [];
        var o9: u8[>..] = [];
        compress::deflate_encode(x, o0, 0);
        compress::deflate_encode(x, o1, 1);
        compress::deflate_encode(x, o9, 9);
        // Stored: 5 bytes of header per 65535 bytes.
        if o0.len != x.len + 5 * max(1, (x.len + 65534) / 65535) {
            print("FAIL level 0 size ", o0.len, " for ", x.len);
            failures++;
        }
        if x.len >= 100000 && i != 3 && o9.len * 5 > x.len { print("FAIL level 9 compresses ", x.len, " to ", o9.len); failures++; }
        if i == 3 && o9.len > x.len + x.len / 100 { print("FAIL random data grows to ", o9.len); failures++; }
    }
}

fn dictionaries() {
    let dict = "the quick brown fox jumps over the lazy dog";
    let data = "the lazy dog jumps over the quick brown fox";
    for level in [1, 6, 9] {
        var out: u8[>..] = [];
        var w = compress::deflate_writer_dict(level, dict);
        compress::deflate_write(w, data, out);
        compress::deflate_close(w, out);
        var plain: u8[>..] = [];
        compress::deflate_encode(data, plain, level);
        if out.len >= plain.len { print("FAIL the dictionary does not help at level ", level); failures++; }
        var d = compress::inflate_reader();
        compress::inflate_set_dictionary(d, dict);
        var back: u8[>..] = [];
        if compress::inflate_decode_with(d, out, back, -1) != 0 || back[..] != data { fail("raw stream with a dictionary"); }
        // zlib: FDICT and the dictionary's Adler-32.
        var z: u8[>..] = [];
        var zw = compress::zlib_writer_dict(level, dict);
        compress::zlib_write(zw, data, z);
        compress::zlib_close(zw, z);
        if (z[1] & 0x20) == 0 || compress::get_be32(z, 2) != compress::adler32(dict) { fail("zlib FDICT header"); }
        var zb: u8[>..] = [];
        if compress::zlib_decode_dict(z, dict, zb) != 0 || zb[..] != data { fail("zlib with a dictionary"); }
        var zn: u8[>..] = [];
        if compress::zlib_decode(z, zn) != compress::ERR_DICTIONARY { fail("zlib without the dictionary"); }
    }
}

// The zlib header Go writes for each level, and the gzip header.
fn headers() {
    let want: u8[12] = [0x01, 0x9c, 0x01, 0x01, 0x5e, 0x5e, 0x5e, 0x5e, 0x9c, 0xda, 0xda, 0xda];
    for level, i in [-2, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9] {
        var z: u8[>..] = [];
        compress::zlib_encode("x", z, level);
        if z[0] != 0x78 || z[1] != want[i] {
            print("FAIL zlib header at level ", level, ": ", z[1]);
            failures++;
        }
        var back: u8[>..] = [];
        if compress::zlib_decode(z, back) != 0 || back[..] != "x" { fail("zlib round trip"); }
    }
    var g: u8[>..] = [];
    var w = compress::gzip_writer(9);
    if compress::gzip_write_header(w, g, "caf\xc3\xa9.txt", "a comment", "XY", 1700000000, 3) != 0 { fail("gzip header"); }
    if compress::gzip_write_header(w, g, "again", "", "") != compress::ERR_ARGUMENT { fail("a second header"); }
    compress::gzip_write(w, "hello", g);
    compress::gzip_close(w, g);
    // Magic, CM, FEXTRA|FNAME|FCOMMENT, MTIME, XFL 2 (level 9), OS 3.
    let gh: u8[10] = [0x1f, 0x8b, 8, 0x1c, 0x00, 0xf1, 0x53, 0x65, 2, 3];
    if g[..10] != gh[..] { print("FAIL gzip header bytes ", g[..10]); failures++; }
    var r = compress::gzip_reader();
    var back: u8[>..] = [];
    if compress::gzip_decode_with(r, g, back, -1) != 0 || back[..] != "hello" { fail("gzip round trip"); }
    if r.name[..] != "caf\xe9.txt" || r.comment[..] != "a comment" || r.extra[..] != "XY" || r.mtime != 1700000000 || r.os != 3 {
        fail("gzip header fields read back");
    }
    // Strings that are not Latin-1, or hold a NUL, are refused, as Go refuses them.
    var w2 = compress::gzip_writer();
    var g2: u8[>..] = [];
    if compress::gzip_write_header(w2, g2, "\xe2\x82\xac", "", "") != compress::ERR_ARGUMENT || g2.len != 0 { fail("a euro sign in a name"); }
    if compress::gzip_write_header(w2, g2, "", "a\x00b", "") != compress::ERR_ARGUMENT { fail("a NUL in a comment"); }
    // No header given: Go's (OS 255, nothing else); XFL 4 at level 1.
    var g3: u8[>..] = [];
    compress::gzip_encode("", g3, 1);
    let dh: u8[10] = [0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 4, 255];
    if g3[..10] != dh[..] { print("FAIL default gzip header ", g3[..10]); failures++; }
    // Several members in a row read as one.
    var two: u8[>..] = [];
    compress::gzip_encode("one ", two, 6);
    compress::gzip_encode("two", two, 1);
    var both: u8[>..] = [];
    if compress::gzip_decode(two, both) != 0 || both[..] != "one two" { fail("two members"); }
}

fn errors() {
    for level in [-3, 10, 100] {
        var w = compress::deflate_writer(level);
        var out: u8[>..] = [];
        if compress::deflate_write(w, "x", out) != compress::ERR_ARGUMENT { print("FAIL level ", level, " accepted"); failures++; }
        if compress::deflate_encode("x", out, level) != compress::ERR_ARGUMENT { fail("deflate_encode bad level"); }
        if compress::gzip_encode("x", out, level) != compress::ERR_ARGUMENT { fail("gzip_encode bad level"); }
        if compress::zlib_encode("x", out, level) != compress::ERR_ARGUMENT { fail("zlib_encode bad level"); }
    }
    // Reset starts a new stream.
    var w = compress::deflate_writer(6);
    var a: u8[>..] = [];
    compress::deflate_write(w, "first stream", a);
    compress::deflate_close(w, a);
    compress::deflate_reset(w);
    var b: u8[>..] = [];
    compress::deflate_write(w, "second", b);
    compress::deflate_close(w, b);
    var back: u8[>..] = [];
    if compress::inflate_decode(b, back) != 0 || back[..] != "second" { fail("reset"); }
}

fn main() {
    let xs = inputs();
    levels(xs);
    sizes(xs);
    dictionaries();
    headers();
    errors();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("deflate: all passed");
}
