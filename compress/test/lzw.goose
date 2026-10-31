// compress.lzw: Go's compress/lzw tests (reader_test.go, writer_test.go)
// ported, long inputs whose encodings must match Go's (their CRC-32 and
// length, from Go 1.27's Writer), round trips at every order and literal
// width, and decoding fed a byte at a time into a byte of room.
// scripts/lzw_differential.py compares thousands more with Go.

import std;
import gslib from "../..";
import gslib.compress;
import gslib.compress.lzw;

var failures = 0;

fn fail(msg: const u8[:]) { print("FAIL ", msg); failures++; }

// Decodes `data` fed `inchunk` bytes at a time into `room` bytes of room:
// the output and the final status (0 when the input ran out first).
fn decode(data: const u8[:], order: i64, lw: i64, inchunk: i64, room: i64) -> u8[>..], i64 {
    var d = compress::lzw_reader(order, lw);
    var out: u8[>..] = [];
    var buf: u8[>..] = [];
    buf.resize(room, 0);
    var p = 0;
    loop {
        let n = if data.len - p < inchunk { data.len - p } else { inchunk };
        let used, made, st = compress::lzw_read(d, data[p..p + n], buf);
        p += used;
        out.append(buf[..made]);
        if st != 0 { return out, st; }
        if used == 0 && made == 0 && p >= data.len { return out, 0; }
    }
    return out, 0;
}

fn encode(data: const u8[:], order: i64, lw: i64, chunk: i64) -> u8[>..], i64 {
    var w = compress::lzw_writer(order, lw);
    var out: u8[>..] = [];
    var p = 0;
    while p < data.len {
        let n = if data.len - p < chunk { data.len - p } else { chunk };
        let e = compress::lzw_write(w, data[p..p + n], out);
        if e != 0 { return out, e; }
        p += n;
    }
    let e = compress::lzw_close(w, out);
    return out, e;
}

// Go's lzwTests: raw, compressed, and whether the stream is cut short.
fn go_case(desc: const u8[:], order: i64, lw: i64, raw: const u8[:], comp: const u8[:], truncated: bool) {
    for inchunk in [1, 2, 3, 1 << 20] {
        for room in [1, 5, 4096] {
            let out, st = decode(comp, order, lw, inchunk, room);
            if truncated {
                if st != 0 || out.len == 0 || !starts_with(raw, out[..]) {
                    print("FAIL ", desc, " in ", inchunk, " room ", room, ": status ", st, " out '", out, "'");
                    failures++;
                }
            } else if st != compress::STREAM_END || out[..] != raw {
                print("FAIL ", desc, " in ", inchunk, " room ", room, ": status ", st, " out '", out, "'");
                failures++;
            }
        }
    }
    if truncated {
        var whole: u8[>..] = [];
        if compress::lzw_decode(comp, order, lw, whole) != compress::ERR_TRUNCATED { fail(str(desc, ": lzw_decode not ERR_TRUNCATED")); }
    }
}

fn go_reader_tests() {
    let L = compress::LZW_LSB;
    let M = compress::LZW_MSB;
    let tobe = "TOBEORNOTTOBEORTOBEORNOT";
    go_case("empty;LSB;8", L, 8, "", [0x01, 0x01], false);
    go_case("empty;MSB;8", M, 8, "", [0x80, 0x80], false);
    go_case("tobe;LSB;7", L, 7, tobe, [0x54, 0x4f, 0x42, 0x45, 0x4f, 0x52, 0x4e, 0x4f, 0x54, 0x82, 0x84, 0x86, 0x8b, 0x85, 0x87, 0x89, 0x81], false);
    go_case("tobe;LSB;8", L, 8, tobe, [0x54, 0x9e, 0x08, 0x29, 0xf2, 0x44, 0x8a, 0x93, 0x27, 0x54, 0x04, 0x12, 0x34, 0xb8, 0xb0, 0xe0, 0xc1, 0x84, 0x01, 0x01], false);
    go_case("tobe;MSB;7", M, 7, tobe, [0x54, 0x4f, 0x42, 0x45, 0x4f, 0x52, 0x4e, 0x4f, 0x54, 0x82, 0x84, 0x86, 0x8b, 0x85, 0x87, 0x89, 0x81], false);
    go_case("tobe;MSB;8", M, 8, tobe, [0x2a, 0x13, 0xc8, 0x44, 0x52, 0x79, 0x48, 0x9c, 0x4f, 0x2a, 0x40, 0xa0, 0x90, 0x68, 0x5c, 0x16, 0x0f, 0x09, 0x80, 0x80], false);
    go_case("tobe-truncated;LSB;8", L, 8, tobe, [0x54, 0x9e, 0x08, 0x29, 0xf2, 0x44, 0x8a, 0x93, 0x27, 0x54, 0x04], true);
    go_case("gif;LSB;8", L, 8, [0x28, 0xff, 0xff, 0xff, 0x28, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            [0x00, 0x51, 0xfc, 0x1b, 0x28, 0x70, 0xa0, 0xc1, 0x83, 0x01, 0x01], false);
    go_case("pdf;MSB;8", M, 8, "-----A---B", [0x80, 0x0b, 0x60, 0x50, 0x22, 0x0c, 0x0c, 0x85, 0x01], false);
}

// TestHiCodeDoesNotOverflow: zeros forever; the table fills and stays full.
fn hi_code_does_not_overflow() {
    var d = compress::lzw_reader(compress::LZW_LSB, 8);
    var zeros: u8[1024] = [0; 1024];
    var buf: u8[1024] = [0; 1024];
    var old_hi: i64 = 0;
    var total = 0;
    for i in 200 {
        let used, made, st = compress::lzw_read(d, zeros, buf);
        total += made;
        if st != 0 { fail("hi code: an error on zeros"); return; }
        if d.hi < old_hi || d.hi > 4095 { fail("hi code decreased or overflowed"); return; }
        old_hi = d.hi;
    }
    if old_hi != 4095 || d.width != 12 { fail(str("hi code: hi ", old_hi, " width ", d.width)); }
}

// TestNoLongerSavingPriorExpansions: 43255 zero bits, then 4095 and the end code.
fn no_longer_saving_prior_expansions() {
    var input: u8[>..] = [];
    input.resize(5406, 0);
    input.append([0x80, 0xff, 0x0f, 0x08]);
    for inchunk in [1, 7, 1 << 20] {
        let out, st = decode(input, compress::LZW_LSB, 8, inchunk, 333);
        if st != compress::STREAM_END || out.len != 3841 { fail(str("no longer saving: status ", st, " decoded ", out.len)); }
    }
}

// A full table, then its highest code three times, another, a literal and
// the highest again: Go decodes 3850 bytes (CRC-32 d49889b8), adding
// nothing to the table (the literal does not redefine code 4095).
fn full_table_codes() {
    var input: u8[>..] = [];
    var bits: u64 = 0;
    var n: u64 = 7;                    // 43255 zero bits = 5406 bytes and 7 bits
    input.resize(5406, 0);
    let codes: u64[7] = [4095, 4095, 4095, 300, 5, 4095, 257];
    for c in codes {
        bits |= c << n;
        n += 12;
        while n >= 8 { input.push((bits & 0xff) as! u8); bits >>= 8; n -= 8; }
    }
    if n > 0 { input.push((bits & 0xff) as! u8); }
    for inchunk in [1, 1 << 20] {
        let out, st = decode(input, compress::LZW_LSB, 8, inchunk, 100);
        if st != compress::STREAM_END || out.len != 3850 || compress::crc32(out) != 0xd49889b8 {
            fail(str("full table: status ", st, " decoded ", out.len));
        }
    }
}

fn go_writer_tests() {
    // TestStartsWithClearCode
    let a, e1 = encode("Hi", compress::LZW_LSB, 7, 100);
    let want_hi: u8[4] = [0x80, 'H', 'i', 0x81];
    if e1 != 0 || a[..] != want_hi[..] { fail(str("starts with clear: ", a)); }
    let b, e2 = encode("", compress::LZW_LSB, 7, 100);
    let want_e: u8[2] = [0x80, 0x81];
    if e2 != 0 || b[..] != want_e[..] { fail(str("empty starts with clear: ", b)); }
    // TestSmallLitWidth: a byte < 1<<2 is fine, one >= 1<<2 is an error that sticks.
    var w = compress::lzw_writer(compress::LZW_LSB, 2);
    var out: u8[>..] = [];
    if compress::lzw_write(w, [3], out) != 0 { fail("small lit width: 3 refused"); }
    if compress::lzw_write(w, [4], out) != compress::ERR_ARGUMENT { fail("small lit width: 4 taken"); }
    if compress::lzw_write(w, [1], out) != compress::ERR_ARGUMENT { fail("small lit width: error did not stick"); }
    if compress::lzw_close(w, out) != compress::ERR_ARGUMENT { fail("small lit width: close after error"); }
    // Writing after close fails; closing again is fine.
    var w2 = compress::lzw_writer(compress::LZW_MSB, 8);
    var o2: u8[>..] = [];
    compress::lzw_write(w2, "asdf", o2);
    if compress::lzw_close(w2, o2) != 0 || compress::lzw_close(w2, o2) != 0 { fail("close twice"); }
    if compress::lzw_write(w2, "x", o2) != compress::ERR_ARGUMENT { fail("write after close"); }
    // Bad orders and widths, both ways.
    for lw in [0, 1, 9, 12] {
        var bw = compress::lzw_writer(compress::LZW_LSB, lw);
        var o3: u8[>..] = [];
        if compress::lzw_write(bw, "a", o3) != compress::ERR_ARGUMENT { fail(str("lit width ", lw, " taken by the writer")); }
        let r, st = decode([1, 1], compress::LZW_LSB, lw, 1, 10);
        if st != compress::ERR_ARGUMENT { fail(str("lit width ", lw, " taken by the reader")); }
    }
    let r2, st2 = decode([1, 1], 2, 8, 1, 10);
    if st2 != compress::ERR_ARGUMENT { fail("order 2 taken"); }
}

// An invalid code: past hi. LSB, width 9: clear (256), 'a', then 300.
fn invalid_code() {
    var w: u8[>..] = [];
    var bits: u64 = 0;
    var n: u64 = 0;
    let codes: u64[4] = [256, 97, 300, 257];
    for c in codes { bits |= c << n; n += 9; }
    while n > 0 { w.push((bits & 0xff) as! u8); bits >>= 8; n = if n >= 8 { n - 8 } else { 0 }; }
    let out, st = decode(w, compress::LZW_LSB, 8, 1, 1);
    if st != compress::ERR_DATA || out[..] != "a" { fail(str("invalid code: status ", st, " out '", out, "'")); }
    // The code being defined (hi) is valid: 'a', then 258 = "aa".
    var w2: u8[>..] = [];
    bits = 0;
    n = 0;
    let codes2: u64[3] = [97, 258, 257];
    for c in codes2 { bits |= c << n; n += 9; }
    while n > 0 { w2.push((bits & 0xff) as! u8); bits >>= 8; n = if n >= 8 { n - 8 } else { 0 }; }
    let out2, st2 = decode(w2, compress::LZW_LSB, 8, 1, 2);
    if st2 != compress::STREAM_END || out2[..] != "aaa" { fail(str("KwKwK: status ", st2, " out '", out2, "'")); }
}

fn lcg_data(lw: i64) -> u8[>..] {
    var data: u8[>..] = [];
    var s: u64 = 1;
    for i in 200000 {
        s = s * 6364136223846793005 + 1442695040888963407;
        var b = ((s >> 56) & ((1 << (lw as! u64)) - 1)) as! u8;
        if i % 3 == 0 && lw == 8 { b = 'a'; }
        data.push(b);
    }
    return data;
}

// Long inputs: Go's encodings (length and CRC-32), table clears included.
fn go_golden(lw: i64, order: i64, want_len: i64, want_crc: u32, in_crc: u32) {
    let data = lcg_data(lw);
    if compress::crc32(data) != in_crc { fail(str("golden input lw ", lw)); return; }
    for chunk in [1, 4096, 1 << 30] {
        if chunk == 1 && lw != 8 { continue; }
        let enc, e = encode(data, order, lw, chunk);
        if e != 0 || enc.len != want_len || compress::crc32(enc) != want_crc {
            print("FAIL golden lw ", lw, " order ", order, " chunk ", chunk, ": ", enc.len, " bytes, crc ", compress::crc32(enc));
            failures++;
        }
        if chunk == 4096 {
            for room in [1, 4097] {
                let dec, st = decode(enc, order, lw, if room == 1 { 3 } else { 1 << 30 }, room);
                if st != compress::STREAM_END || dec[..] != data[..] { fail(str("golden round trip lw ", lw, " order ", order)); }
            }
        }
    }
}

fn round_trips() {
    for order in [compress::LZW_LSB, compress::LZW_MSB] {
        for lw in 2..9 {
            var data: u8[>..] = [];
            for i in 30000 { data.push((((i * i) / 7 + i / 300) % (1 << lw)) as! u8); }
            for n in [0, 1, 2, 3, 100, 30000] {
                var enc: u8[>..] = [];
                if compress::lzw_encode(data[..n], order, lw, enc) != 0 { fail("round trip encode"); continue; }
                var dec: u8[>..] = [];
                let st = compress::lzw_decode(enc, order, lw, dec);
                if st != 0 || dec[..] != data[..n] { fail(str("round trip order ", order, " lw ", lw, " n ", n, ": ", st)); }
                // A limit cuts it short.
                if n >= 100 {
                    var lim: u8[>..] = [];
                    if compress::lzw_decode(enc, order, lw, lim, 50) != compress::ERR_LIMIT || lim.len != 50 { fail("limit"); }
                }
            }
        }
    }
}

fn main() {
    go_reader_tests();
    hi_code_does_not_overflow();
    no_longer_saving_prior_expansions();
    full_table_codes();
    go_writer_tests();
    invalid_code();
    go_golden(8, compress::LZW_LSB, 193913, 0xd8694237, 0x28684dbf);
    go_golden(8, compress::LZW_MSB, 193913, 0x1fd4a032, 0x28684dbf);
    go_golden(4, compress::LZW_LSB, 121512, 0xed4ef0af, 0x312dfec4);
    go_golden(4, compress::LZW_MSB, 121512, 0xb9fac5d1, 0x312dfec4);
    go_golden(2, compress::LZW_LSB, 57617, 0xf8795118, 0x86be7605);
    go_golden(2, compress::LZW_MSB, 57617, 0x74d9dc29, 0x86be7605);
    round_trips();
    if failures > 0 { print(failures, " failures"); exit(1); }
    print("lzw: all passed");
}
