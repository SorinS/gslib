// compress.bzip2: Go's compress/bzip2 tests (TestReader's vectors, its
// testdata decoded and checked against Go's results, TestZeroRead), fed in
// pieces from a byte up and taken out in pieces from a byte up; streams cut
// short, trailing bytes, corrupted CRCs; and the writer's output read back
// at every block size. scripts/bzip2_differential.py compares thousands
// more with Go, Python's bz2 and the bzip2 program.

import std;
import os;
import compress from "..";
import compress.bzip2;

var failures = 0;

fn hexval(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    return c - 'a' + 10;
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

// Decodes s fed `chunk` bytes at a time with `room` bytes of output a call:
// the output, the error (0 for none) and whether it ended whole.
fn decode(s: const u8[:], chunk: i64, room: i64) -> u8[>..], i64, bool {
    var d = compress::bzip2_reader();
    var out: u8[>..] = [];
    var buf: u8[4096] = [0; 4096];
    var p = 0;
    var e: i64 = 0;
    loop {
        let n = if s.len - p < chunk { s.len - p } else { chunk };
        let used, made, st = compress::bzip2_read(d, s[p..p + n], buf[..room]);
        out.append(buf[..made]);
        p += used;
        if st < 0 { e = st; break; }
        if used == 0 && made == 0 {
            if p >= s.len { break; }
            print("FAIL no progress at ", p);
            failures++;
            break;
        }
    }
    return out, e, compress::bzip2_done(d);
}

fn want_ok(name: const u8[:], s: const u8[:], want: const u8[:]) {
    for chunk in [1, 3, 64, 1 << 30] {
        for room in [1, 5, 4096] {
            if chunk == 1 && room == 1 && want.len > 200000 { continue; }      // keep the JIT run short
            let out, e, done = decode(s, chunk, room);
            if e != 0 || !done || out[..] != want {
                print("FAIL ", name, " chunk ", chunk, " room ", room, ": err ", e, " done ", done, " got ", out.len, " bytes");
                failures++;
                return;
            }
        }
    }
}

fn want_fail(name: const u8[:], s: const u8[:]) {
    for chunk in [1, 1 << 30] {
        let out, e, done = decode(s, chunk, 4096);
        if e == 0 && done {
            print("FAIL ", name, " chunk ", chunk, ": decoded ", out.len, " bytes");
            failures++;
        }
    }
    var whole: u8[>..] = [];
    if compress::bzip2_decode(s, whole) == 0 { print("FAIL ", name, ": bzip2_decode took it"); failures++; }
}

fn want_err(name: const u8[:], s: const u8[:], err: i64) {
    let out, e, done = decode(s, 1, 4096);
    if e != err { print("FAIL ", name, ": err ", e, ", want ", err); failures++; }
}

let HELLO = "425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb9431f8bb9229c28482776741b0";

fn go_reader_vectors() {
    want_ok("hello world", unhex(HELLO), "hello world\n");
    want_ok("concatenated files", unhex(str(HELLO, HELLO)), "hello world\nhello world\n");
    var z32: u8[32] = [0; 32];
    want_ok("32B zeros", unhex("425a6839314159265359b5aa5098000000600040000004200021008283177245385090b5aa5098"), z32);
    var z1m: u8[>..] = [];
    z1m.resize(1 << 20, 0);
    want_ok("1MiB zeros", unhex("425a683931415926535938571ce50008084000c0040008200030cc0529a60806c4201e2ee48a70a12070ae39ca"), z1m);
    want_ok("random data - uses RLE1 stage",
        unhex("425a6839314159265359d992d0f60000137dfe84020310091c1e280e100e042801099210094806c0110002e70806402000546034000034000000f2830000032000d3403264049270eb7a9280d308ca06ad28f6981bee1bf8160727c7364510d73a1e123083421b63f031f63993a0f40051fbf177245385090d992d0f60"),
        unhex("92d5652616ac444a4a04af1a8a3964aca0450d43d6cf233bd03233f4ba92f8719e6c2a2bd4f5f88db07ecd0da3a33b263483db9b2c158786ad6363be35d17335ba"));
    want_fail("out-of-range selector - issue 8363",
        unhex("425a68393141592653594eece83600000251800010400006449080200031064c4101a7a9a580bb943117724538509000000000"));
    want_fail("bad block size - issue 13941",
        unhex("425a683131415926535936dc55330063ffc0006000200020a40830008b0008b8bb9229c28481b6e2a998"));
    want_fail("bad huffman delta",
        unhex("425a6836314159265359b1f7404b000000400040002000217d184682ee48a70a12163ee80960"));
}

fn read_vector(name: const u8[:]) -> u8[>..] {
    var data: u8[>..] = [];
    if !read_file(str("vectors/bzip2/", name), data) { print("FAIL cannot read vectors/bzip2/", name); failures++; }
    return data;
}

// Go's testdata, with what Go decodes from each (size and CRC-32, from
// tools/gooracle; Go fails on fail-issue5747 with "repeats past end of block").
fn go_testdata() {
    want_ok("pass-random1", read_vector("pass-random1.bz2"), read_vector("pass-random1.bin"));
    want_ok("pass-random2", read_vector("pass-random2.bz2"), read_vector("pass-random2.bin"));
    var saw: u8[>..] = [];
    for i in 1 << 20 { saw.push((i & 0xff) as! u8); }
    want_ok("pass-sawtooth", read_vector("pass-sawtooth.bz2"), saw);
    want_fail("fail-issue5747", read_vector("fail-issue5747.bz2"));
    want_err("fail-issue5747 error", read_vector("fail-issue5747.bz2"), compress::ERR_DATA);
    let files = ["e.txt.bz2", "Isaac.Newton-Opticks.txt.bz2", "random.data.bz2"];
    let sizes = [100003, 567198, 16384];
    let crcs: u32[3] = [0x8dc3bbcb, 0xde1864c0, 0xf2e49a4a];
    for f, i in files {
        var out: u8[>..] = [];
        let e = compress::bzip2_decode(read_vector(f), out);
        if e != 0 || out.len != sizes[i] || compress::crc32(out) != crcs[i] {
            print("FAIL ", f, ": err ", e, " size ", out.len);
            failures++;
        }
    }
    // A limit on the output.
    var lim: u8[>..] = [];
    if compress::bzip2_decode(read_vector("e.txt.bz2"), lim, 100002) != compress::ERR_LIMIT { print("FAIL limit"); failures++; }
}

fn malformed() {
    let hello = unhex(HELLO);
    // TestZeroRead: no room, no input: nothing, no error.
    var d = compress::bzip2_reader();
    var none: u8[0] = [];
    let u0, m0, s0 = compress::bzip2_read(d, hello[..0], none[..]);
    if u0 != 0 || m0 != 0 || s0 != 0 { print("FAIL zero read"); failures++; }
    // Every prefix is unfinished, never an error and never whole.
    for n in hello.len {
        let out, e, done = decode(hello[..n], 1, 4096);
        if e != 0 || done { print("FAIL prefix ", n, ": err ", e, " done ", done); failures++; }
    }
    // Empty input: not a stream (Go: unexpected EOF).
    var empty: u8[>..] = [];
    if compress::bzip2_decode(hello[..0], empty) != compress::ERR_TRUNCATED { print("FAIL empty input"); failures++; }
    // After a stream: another, or nothing.
    var junk = copy(hello);
    junk.append("XY");
    want_err("trailing junk", junk, compress::ERR_TRAILING);
    var b1 = copy(hello);
    b1.push('B');
    want_fail("a trailing B", b1);
    var zeros = copy(hello);
    zeros.append([0, 0, 0, 0]);
    want_err("trailing zeros", zeros, compress::ERR_TRAILING);
    // Headers.
    want_err("bad magic", unhex("425b68"), compress::ERR_HEADER);
    want_err("not h", unhex("425a6739"), compress::ERR_HEADER);
    want_err("level 0", unhex("425a6830"), compress::ERR_HEADER);
    // The block CRC (bytes 10-13) and the stream CRC (the last four).
    var bc = copy(hello);
    bc[12] ^= 0x10;
    want_err("block crc", bc, compress::ERR_CHECKSUM);
    var fc = copy(hello);
    fc[fc.len - 2] ^= 1;
    want_err("stream crc", fc, compress::ERR_CHECKSUM);
    // A randomised block (the bit after the block CRC): Go refuses them.
    var rnd = copy(hello);
    rnd[14] |= 0x80;
    want_err("randomised", rnd, compress::ERR_UNSUPPORTED);
    // The CRC tables.
    if compress::bzip2_crc_update(0, "hello world\n") != 0x4eece836 { print("FAIL bzip2 crc"); failures++; }
}

fn round_trip(name: const u8[:], data: const u8[:], level: i64) {
    var z: u8[>..] = [];
    let e = compress::bzip2_encode(data, z, level);
    var back: u8[>..] = [];
    let e2 = compress::bzip2_decode(z, back);
    if e != 0 || e2 != 0 || back[..] != data {
        print("FAIL round trip ", name, " level ", level, ": ", e, " ", e2, " ", back.len, " of ", data.len);
        failures++;
    }
}

fn writer() {
    // bzip2 1.0's own output, byte for byte: Go's hello world vector, the
    // empty stream, and Go's testdata (made by bzip2 -9).
    var hz: u8[>..] = [];
    compress::bzip2_encode("hello world\n", hz);
    if hz[..] != unhex(HELLO) { print("FAIL hello world is not bzip2's"); failures++; }
    var ez: u8[>..] = [];
    compress::bzip2_encode("", ez);
    if ez[..] != unhex("425a683917724538509000000000") { print("FAIL empty stream"); failures++; }
    var newton: u8[>..] = [];
    let nz = read_vector("Isaac.Newton-Opticks.txt.bz2");
    compress::bzip2_decode(nz, newton);
    var nz2: u8[>..] = [];
    compress::bzip2_encode(newton, nz2, 9);
    if nz2[..] != nz[..] { print("FAIL Newton's Opticks is not bzip2 -9's: ", nz2.len, " bytes"); failures++; }
    // Every level, over inputs that cross blocks, long runs (the initial
    // run-length coding and its 255 limit), one symbol, all 256 symbols,
    // and periodic data (equal rotations).
    var mixed: u8[>..] = [];
    var r = rng { 7 };
    for i in 250000 {
        let k = r.rand_int(10);
        if k < 3 { mixed.push(r.rand_int(256) as! u8); }
        else if k < 6 { for j in r.rand_int(600) { mixed.push('z'); } }
        else { mixed.append("the quick brown fox "); }
        if mixed.len > 250000 { break; }
    }
    for level in 1..10 { round_trip("mixed", mixed[..if level < 3 { 250000 } else { 30000 }], level); }
    var one: u8[>..] = [];
    one.resize(300000, 'a');
    round_trip("one byte", one, 1);
    round_trip("a single byte", "x", 9);
    var all: u8[>..] = [];
    for k in 3 { for b in 256 { all.push(b as! u8); } }
    round_trip("all bytes", all, 9);
    var per: u8[>..] = [];
    for k in 30000 { per.append("abc"); }
    round_trip("periodic", per, 2);
    for n in [4, 5, 254, 255, 256, 258, 259, 260, 263, 264, 518, 1000] {
        var run: u8[>..] = [];
        run.resize(n, 7);
        run.push(8);
        run.resize(run.len + n, 7);
        round_trip("runs", run, 9);
    }
    // Written in pieces with flushes between: each flush ends a block.
    var w = compress::bzip2_writer(1);
    var z: u8[>..] = [];
    var pos = 0;
    var step = 1;
    while pos < mixed.len {
        let n = if mixed.len - pos < step { mixed.len - pos } else { step };
        compress::bzip2_write(w, mixed[pos..pos + n], z);
        pos += n;
        if step % 3 == 0 { compress::bzip2_flush(w, z); }
        step = step * 2 + 1;
    }
    compress::bzip2_close(w, z);
    var back: u8[>..] = [];
    if compress::bzip2_decode(z, back) != 0 || back[..] != mixed[..] { print("FAIL pieces and flushes"); failures++; }
    if compress::bzip2_write(w, "more", z) != compress::ERR_ARGUMENT { print("FAIL write after close"); failures++; }
    var bad = compress::bzip2_writer(10);
    if compress::bzip2_write(bad, "x", z) != compress::ERR_ARGUMENT { print("FAIL level 10"); failures++; }
}

fn main() {
    writer();
    go_reader_vectors();
    go_testdata();
    malformed();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("bzip2: all passed");
}
