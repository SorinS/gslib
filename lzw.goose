// compress.lzw: the Lempel-Ziv-Welch coding of Go's compress/lzw, as GIF
// (LSB first) and PDF and TIFF's "compatible" variant (MSB first) use it.
// Codes start at litWidth + 1 bits and grow to 12; the first code past the
// literals clears the table and the next ends the stream. As Go's, this is
// not TIFF's "early change" variant: the width grows when the table's next
// code no longer fits, not one code before.
//
// Decoding follows Go's Reader exactly: the same codes are taken as
// invalid, a full table (4096 codes) keeps its width and adds nothing
// until a clear code, and input that ends before the end code is an
// unexpected end. Encoding writes the same bytes as Go's Writer.
//
//   var d = compress::lzw_reader(compress::LZW_LSB, 8);
//   let used, made, st = compress::lzw_read(d, input, out);   // st: 0, STREAM_END or an error
//   // at the end of the input: compress::lzw_done(d) says whether the end code came
//
//   var w = compress::lzw_writer(compress::LZW_MSB, 8);
//   compress::lzw_write(w, data, out);        // appends to out
//   compress::lzw_close(w, out);              // the last code, the end code, the last bits
//
// Both states are of fixed size: the reader some 21 KB, the writer 64 KB.

namespace compress;

import std;

let LZW_LSB: i64 = 0;   // least significant bits first (GIF)
let LZW_MSB: i64 = 1;   // most significant bits first (TIFF, PDF)

let LZW_MAX_WIDTH: i64 = 12;
let LZW_INVALID: i64 = 0xffff;          // the reader's "no previous code"
let LZW_TABLE_SIZE: i64 = 16384;        // the writer's hash table: 4 << 12
let LZW_MAX_CODE: u32 = 4095;
let LZW_NO_CODE: i64 = -1;              // the writer's "no saved code"

// --- Reader ----------------------------------------------------------------

struct LzwReader {
    order: i64,
    lit_width: i64,
    err: i64,                   // 0, STREAM_END once the end code came, or an error
    bits: u32,
    nbits: i64,
    width: i64,
    clear: i64, eof: i64, hi: i64, overflow: i64, last: i64,
    suffix: u8[4096],
    prefix: u16[4096],
    pend: u8[8192],             // decoded bytes not yet handed out: pend[ppos..8192]
    ppos: i64,
}

// A reader of the given order (LZW_LSB or LZW_MSB) and literal width
// (2 to 8). A bad order or width makes every read fail with ERR_ARGUMENT,
// as Go's NewReader gives a reader whose reads fail.
fn lzw_reader(order: i64, lit_width: i64) -> LzwReader {
    var d = LzwReader {
        order: order, lit_width: lit_width, err: 0, bits: 0, nbits: 0, width: 0,
        clear: 0, eof: 0, hi: 0, overflow: 0, last: LZW_INVALID,
        suffix: [0; 4096], prefix: [0; 4096], pend: [0; 8192], ppos: 8192,
    };
    if (order != LZW_LSB && order != LZW_MSB) || lit_width < 2 || lit_width > 8 {
        d.err = ERR_ARGUMENT;
        return d;
    }
    d.width = 1 + lit_width;
    d.clear = 1 << lit_width;
    d.eof = d.clear + 1;
    d.hi = d.clear + 1;
    d.overflow = 1 << d.width;
    return d;
}

// Reads one code from the bits kept and `input[at..]`: the code and the new
// position, or -1 when the input runs out first (what it had is kept).
fn lzw_read_code(d: LzwReader&, input: const u8[:], at: i64) -> i64, i64 {
    var p = at;
    while d.nbits < d.width {
        if p >= input.len { return -1, p; }
        let x = input[p] as u32;
        p++;
        if d.order == LZW_LSB { d.bits |= x << (d.nbits as! u32); }
        else { d.bits |= x << ((24 - d.nbits) as! u32); }
        d.nbits += 8;
    }
    var code: i64 = 0;
    let w = d.width as! u32;
    if d.order == LZW_LSB {
        code = d.bits & ((1 << w) - 1);
        d.bits >>= w;
    } else {
        code = d.bits >> (32 - w);
        d.bits <<= w;
    }
    d.nbits -= d.width;
    return code, p;
}

// Decodes what it can of `input` into `out`: how much of the input it
// took, how many bytes it wrote, and 0 (more input or more room needed),
// STREAM_END (the end code came; the input after it is not taken) or an
// error (ERR_DATA for a code that is not valid, ERR_ARGUMENT for a reader
// made with a bad order or width). The bytes decoded before an error are
// all handed out before the error is returned.
fn lzw_read(d: LzwReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    var used = 0;
    var made = 0;
    loop {
        // Hand out what is pending first.
        if d.ppos < 8192 {
            var n = 8192 - d.ppos;
            if n > out.len - made { n = out.len - made; }
            out[made..made + n].move_from(d.pend[d.ppos..d.ppos + n]);
            made += n;
            d.ppos += n;
            if d.ppos < 8192 { return used, made, 0; }
        }
        if d.err != 0 { return used, made, d.err; }
        if made == out.len { return used, made, 0; }
        let code, p = lzw_read_code(d, input, used);
        used = p;
        if code < 0 { return used, made, 0; }
        if code < d.clear {
            d.ppos = 8191;
            d.pend[8191] = code as! u8;
            if d.last != LZW_INVALID {
                d.suffix[d.hi] = code as! u8;
                d.prefix[d.hi] = d.last as! u16;
            }
        } else if code == d.clear {
            d.width = 1 + d.lit_width;
            d.hi = d.eof;
            d.overflow = 1 << d.width;
            d.last = LZW_INVALID;
            continue;
        } else if code == d.eof {
            d.err = STREAM_END;
            continue;
        } else if code <= d.hi {
            var c = code;
            var i = 8191;
            if code == d.hi && d.last != LZW_INVALID {
                // The code being defined: the previous string and its own first byte.
                c = d.last;
                while c >= d.clear { c = d.prefix[c]; }
                d.pend[i] = c as! u8;
                i--;
                c = d.last;
            }
            while c >= d.clear {
                d.pend[i] = d.suffix[c];
                i--;
                c = d.prefix[c];
            }
            d.pend[i] = c as! u8;
            d.ppos = i;
            if d.last != LZW_INVALID {
                d.suffix[d.hi] = c as! u8;
                d.prefix[d.hi] = d.last as! u16;
            }
        } else {
            d.err = ERR_DATA;
            continue;
        }
        d.last = code;
        d.hi++;
        if d.hi >= d.overflow {
            if d.width == LZW_MAX_WIDTH {
                // A full table: no more codes until a clear.
                d.last = LZW_INVALID;
                d.hi--;
            } else {
                d.width++;
                d.overflow = 1 << d.width;
            }
        }
    }
    return used, made, 0;
}

// Whether the stream ended whole: the end code came and everything before
// it was handed out.
fn lzw_done(d: const LzwReader&) -> bool { d.err == STREAM_END && d.ppos == 8192 }

// Decodes a whole stream, appending to `out`: 0, or an error
// (ERR_TRUNCATED when the data ends before the end code, ERR_LIMIT when
// the output would pass `limit` bytes; what was decoded is in out). The
// bytes after the end code are ignored, as Go's Reader ignores them.
fn lzw_decode(data: const u8[:], order: i64, lit_width: i64, out: u8[>..]&, limit: i64 = 1 << 62) -> i64 {
    var d = lzw_reader(order, lit_width);
    var at = 0;
    var buf: u8[4096] = [0; 4096];
    loop {
        let used, made, st = lzw_read(d, data[at..], buf);
        at += used;
        if out.len + made > limit {
            out.append(buf[..limit - out.len]);
            return ERR_LIMIT;
        }
        out.append(buf[..made]);
        if st == STREAM_END { return 0; }
        if st < 0 { return st; }
        if made == 0 && at >= data.len { return ERR_TRUNCATED; }
    }
    return 0;
}

// --- Writer ----------------------------------------------------------------

struct LzwWriter {
    order: i64,
    lit_width: i64,
    err: i64,                   // a sticky error; ERR_ARGUMENT after close
    closed: bool,
    bits: u32,
    nbits: i64,
    width: i64,
    hi: u32, overflow: u32,
    saved: i64,                 // the code of the string being matched, or LZW_NO_CODE
    table: u32[16384],          // (prefix code << 8 | byte) << 12 | code; 0 is empty
}

// A writer of the given order and literal width (2 to 8). A bad order or
// width makes every write fail with ERR_ARGUMENT.
fn lzw_writer(order: i64, lit_width: i64) -> LzwWriter {
    var w = LzwWriter {
        order: order, lit_width: lit_width, err: 0, closed: false, bits: 0, nbits: 0,
        width: 0, hi: 0, overflow: 0, saved: LZW_NO_CODE, table: [0; 16384],
    };
    if (order != LZW_LSB && order != LZW_MSB) || lit_width < 2 || lit_width > 8 {
        w.err = ERR_ARGUMENT;
        return w;
    }
    w.width = 1 + lit_width;
    w.hi = ((1 << lit_width) + 1) as! u32;
    w.overflow = (1 << (lit_width + 1)) as! u32;
    return w;
}

fn lzw_put(w: LzwWriter&, c: u32, out: u8[>..]&) {
    let width = w.width as! u32;
    if w.order == LZW_LSB {
        w.bits |= c << (w.nbits as! u32);
        w.nbits += w.width;
        while w.nbits >= 8 {
            out.push((w.bits & 0xff) as! u8);
            w.bits >>= 8;
            w.nbits -= 8;
        }
    } else {
        w.bits |= c << (32 - width - (w.nbits as! u32));
        w.nbits += w.width;
        while w.nbits >= 8 {
            out.push((w.bits >> 24) as! u8);
            w.bits <<= 8;
            w.nbits -= 8;
        }
    }
}

// The next code; true when the codes ran out and the table was cleared
// (a clear code written).
fn lzw_inc_hi(w: LzwWriter&, out: u8[>..]&) -> bool {
    w.hi++;
    if w.hi == w.overflow {
        w.width++;
        w.overflow <<= 1;
    }
    if w.hi == LZW_MAX_CODE {
        let clear = (1 << w.lit_width) as! u32;
        lzw_put(w, clear, out);
        w.width = w.lit_width + 1;
        w.hi = clear + 1;
        w.overflow = clear << 1;
        for k in LZW_TABLE_SIZE { w.table[k] = 0; }
        return true;
    }
    return false;
}

// Compresses `input`, appending the bytes it completes to `out`: 0, or an
// error. A byte that does not fit the literal width is an error
// (ERR_ARGUMENT, as Go's "input byte too large for the litWidth"), and
// nothing of that input is written; the error sticks, as Go's does.
// Writing after lzw_close is ERR_ARGUMENT.
fn lzw_write(w: LzwWriter&, input: const u8[:], out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if input.len == 0 { return 0; }
    let max_lit = ((1 << w.lit_width) - 1) as! u8;
    if max_lit != 0xff {
        for x in input {
            if x > max_lit { w.err = ERR_ARGUMENT; return w.err; }
        }
    }
    var code: u32 = 0;
    var start = 0;
    if w.saved == LZW_NO_CODE {
        lzw_put(w, (1 << w.lit_width) as! u32, out);
        code = input[0];
        start = 1;
    } else {
        code = w.saved as! u32;
    }
    var i = start;
    while i < input.len {
        let literal = input[i] as u32;
        i++;
        let key = code << 8 | literal;
        let hash = ((key >> 12) ^ key) & 16383;
        var h = hash;
        var t = w.table[h];
        var found = false;
        while t != 0 {
            if key == t >> 12 {
                code = t & LZW_MAX_CODE;
                found = true;
                break;
            }
            h = (h + 1) & 16383;
            t = w.table[h];
        }
        if found { continue; }
        lzw_put(w, code, out);
        code = literal;
        if lzw_inc_hi(w, out) { continue; }
        var hh = hash;
        loop {
            if w.table[hh] == 0 {
                w.table[hh] = (key << 12) | w.hi;
                break;
            }
            hh = (hh + 1) & 16383;
        }
    }
    w.saved = code;
    return 0;
}

// Ends the stream: the code being matched, the end code and the last
// partial byte go to `out`. 0, or the writer's sticky error (closing twice
// is 0, as in Go).
fn lzw_close(w: LzwWriter&, out: u8[>..]&) -> i64 {
    if w.closed { return 0; }
    if w.err != 0 { return w.err; }
    w.closed = true;
    w.err = ERR_ARGUMENT;
    if w.saved != LZW_NO_CODE {
        lzw_put(w, w.saved as! u32, out);
        lzw_inc_hi(w, out);
    } else {
        lzw_put(w, (1 << w.lit_width) as! u32, out);
    }
    lzw_put(w, ((1 << w.lit_width) + 1) as! u32, out);
    if w.nbits > 0 {
        if w.order == LZW_MSB { w.bits >>= 24; }
        out.push((w.bits & 0xff) as! u8);
    }
    return 0;
}

// Compresses a whole buffer, appending to `out`: 0 or an error.
fn lzw_encode(data: const u8[:], order: i64, lit_width: i64, out: u8[>..]&) -> i64 {
    var w = lzw_writer(order, lit_width);
    let e = lzw_write(w, data, out);
    if e != 0 { return e; }
    return lzw_close(w, out);
}
