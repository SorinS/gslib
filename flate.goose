// compress.flate: DEFLATE decompression (RFC 1951), as Go's compress/flate
// reader. (The compressor is compress.deflate; gzip and zlib framing are
// compress.gzip and compress.zlib.)
//
//   var d = compress::inflate_reader();             // raw DEFLATE
//   let used, made, st = compress::inflate_read(d, input, out);
//   // st: 0 = give more input (or more room), STREAM_END, or an error < 0
//
// A decoder is of fixed size (some 37 KB). It takes input as it comes, in
// pieces of any size down to a byte, and writes at most out.len bytes a
// call: what it has decoded and not yet handed out waits in its 32 KiB
// window, so the decoder's memory never depends on the input.
//
// Decoding is zlib's state machine: a 64-bit bit buffer that takes input a
// byte at a time only as a step needs it, so the decoder stops exactly at
// the end of the DEFLATE stream (at most the last partial byte is taken)
// and can stop anywhere inside one, keeping only the bits it took. Huffman
// codes are looked up in a 512-entry table for codes of up to 9 bits; the
// rarer longer codes are decoded canonically from the code's counts. A
// faster loop decodes whole symbol sequences while 8 bytes of input and
// 258 bytes of window room are at hand, and gives back the whole bytes it
// took ahead when it stops.
//
// What is refused is what Go's reader refuses: a reserved block type, a
// stored block's LEN that does not match NLEN, more than 286 length or 30
// distance codes, code lengths that do not form a complete prefix code
// (except a single code of one bit, which zlib and Go both allow), a repeat
// with nothing to repeat or past the end of the lengths, length symbols
// 286-287 and distance symbols 30-31, a distance before the start of the
// output (or of a preset dictionary). In addition, a block whose code
// lengths give the end-of-block symbol no code is refused when its header
// is read, as zlib does: such a block can never end, so Go refuses it too,
// but only when the input runs out.

namespace compress;

import std;

let INFLATE_WINDOW: i64 = 32768;

// Decoder states.
let IS_BLOCK: u8 = 0;        // at a block's 3-bit header
let IS_STORED_LEN: u8 = 1;   // at a stored block's LEN and NLEN
let IS_STORED: u8 = 2;       // copying a stored block
let IS_TABLE: u8 = 3;        // at a dynamic block's HLIT, HDIST, HCLEN
let IS_LENLENS: u8 = 4;      // reading the code length code's lengths
let IS_CODELENS: u8 = 5;     // reading the literal/length and distance code lengths
let IS_LEN: u8 = 6;          // at a literal/length symbol
let IS_LENEXT: u8 = 7;       // at a length's extra bits
let IS_DIST: u8 = 8;         // at a distance symbol
let IS_DISTEXT: u8 = 9;      // at a distance's extra bits
let IS_MATCH: u8 = 10;       // copying a match
let IS_DONE: u8 = 11;        // the last block ended
let IS_FAILED: u8 = 12;

// A table entry: (symbol << 4) | length for a code of 1-9 bits, HUFF_LONG
// for the first 9 bits of a longer code, 0 for bits that start no code.
let HUFF_LONG: u16 = 15;

// A canonical Huffman code: its counts per length and its symbols in code
// order (for the codes longer than 9 bits), and the lookup table.
struct HuffCode {
    count: i16[16],
    symbol: i16[288],
    table: u16[512],
    min: i64,                   // the bits a symbol is decoded from at least (see IS_LEN)
}

fn huff_code() -> HuffCode { HuffCode { count: [0; 16], symbol: [0; 288], table: [0; 512], min: 0 } }

struct Inflate {
    state: u8,
    last: bool,                  // the block being decoded is the last
    bitbuf: u64,                 // bits taken from the input and not used, LSB first
    bitcnt: i64,
    stored_left: i64,
    nlen: i64, ndist: i64, ncode: i64, have: i64,     // a dynamic block's header
    rep_sym: i64,                // a code length repeat waiting for its extra bits
    lengths: u8[320],
    lencode: HuffCode, distcode: HuffCode,
    fixed_dist: bool,            // a fixed block: distances are 5 plain bits
    length: i64, extra: i64,     // the match being decoded (length, then distance)
    dist: i64,
    // The window: decoded bytes are written at wpos and handed out from
    // rpos; full once the window has wrapped (all 32 KiB is history).
    wpos: i64, rpos: i64, full: bool,
    window: u8[32768],
    err: i64,
    total_in: i64,               // input bytes taken, over the stream
    total_out: i64,              // bytes handed out
}

fn inflate_reader() -> Inflate {
    Inflate {
        state: IS_BLOCK, last: false, bitbuf: 0, bitcnt: 0, stored_left: 0,
        nlen: 0, ndist: 0, ncode: 0, have: 0, rep_sym: 0, lengths: [0; 320],
        lencode: huff_code(), distcode: huff_code(), fixed_dist: false,
        length: 0, extra: 0, dist: 0,
        wpos: 0, rpos: 0, full: false, window: [0; 32768],
        err: 0, total_in: 0, total_out: 0,
    }
}

// Starts over, as a new decoder (keeps nothing of the previous stream).
fn inflate_reset(d: Inflate&) {
    d.state = IS_BLOCK;
    d.last = false;
    d.bitbuf = 0;
    d.bitcnt = 0;
    d.stored_left = 0;
    d.wpos = 0;
    d.rpos = 0;
    d.full = false;
    d.err = 0;
    d.total_in = 0;
    d.total_out = 0;
}

// A preset dictionary: the history the stream's first distances may reach
// into (its last 32 KiB). Before the first inflate_read only.
fn inflate_set_dictionary(d: Inflate&, dict: const u8[:]) {
    let n = if dict.len > INFLATE_WINDOW { INFLATE_WINDOW } else { dict.len };
    let src = dict[dict.len - n..];
    for k in n { d.window[k] = src[k]; }
    d.wpos = n;
    d.rpos = n;
    if n == INFLATE_WINDOW {
        d.wpos = 0;
        d.rpos = 0;
        d.full = true;
    }
}

// --- Huffman codes ---------------------------------------------------------

fn reverse_bits(code: i64, len: i64) -> i64 {
    var r: i64 = 0;
    var c = code;
    for k in len {
        r = (r << 1) | (c & 1);
        c >>= 1;
    }
    return r;
}

// Builds a code from code lengths; false if the lengths are not a complete
// prefix code (a single code of length 1, and no code at all, are allowed,
// as Go's huffmanDecoder.init allows them).
fn huff_build(h: HuffCode&, lengths: const u8[:]) -> bool {
    for k in 16 { h.count[k] = 0; }
    for l in lengths { h.count[l]++; }
    for k in 512 { h.table[k] = 0; }
    h.count[0] = 0;
    var maxlen: i64 = 0;
    h.min = 0;
    for len in 1..16 {
        if h.count[len] != 0 {
            maxlen = len;
            if h.min == 0 { h.min = len; }
        }
    }
    if maxlen == 0 { return true; }
    // Complete: the codes use up all 2^maxlen bit patterns.
    var code: i64 = 0;
    var next: i64[16] = [0; 16];
    for len in 1..16 {
        code = (code + h.count[len - 1]) << 1;
        next[len] = code;
    }
    var left: i64 = 1;
    for len in 1..16 {
        left <<= 1;
        left -= h.count[len];
        if left < 0 { return false; }
    }
    if left != 0 && !(maxlen == 1 && h.count[1] == 1) { return false; }
    // Symbols in code order (by length, then by symbol).
    var offs: i64[16] = [0; 16];
    for len in 1..15 { offs[len + 1] = offs[len] + h.count[len]; }
    for sym in lengths.len {
        let l = lengths[sym] as i64;
        if l != 0 {
            h.symbol[offs[l]] = sym as! i16;
            offs[l]++;
            let c = next[l];
            next[l]++;
            if l <= 9 {
                let r = reverse_bits(c, l);
                let entry = ((sym << 4) | l) as! u16;
                var k = r;
                while k < 512 {
                    h.table[k] = entry;
                    k += 1 << l;
                }
            } else {
                h.table[reverse_bits(c >> (l - 9), 9)] = HUFF_LONG;
            }
        }
    }
    return true;
}

// Decodes a code longer than 9 bits from bits (LSB first, n of them
// valid), canonically: the symbol and its length, -1 (and 0) when n bits
// are not enough, or -2 when the bits start no code.
fn huff_slow(h: const HuffCode&, bits: u64, n: i64) -> i64, i64 {
    var code: i64 = 0;
    var first: i64 = 0;
    var index: i64 = 0;
    for len in 1..16 {
        if len > n { return -1, 0; }
        code |= ((bits >> (len - 1)) & 1) as i64;
        let count = h.count[len] as i64;
        if code - count < first { return h.symbol[index + (code - first)], len; }
        index += count;
        first += count;
        first <<= 1;
        code <<= 1;
    }
    return -2, 0;
}

// --- Input -----------------------------------------------------------------

// The fixed codes (RFC 1951 §3.2.6), built once.
fn fixed_lit_code() -> HuffCode {
    var h = huff_code();
    var l: u8[288] = [0; 288];
    for k in 144 { l[k] = 8; }
    for k in 144..256 { l[k] = 9; }
    for k in 256..280 { l[k] = 7; }
    for k in 280..288 { l[k] = 8; }
    huff_build(h, l);
    return h;
}

let FIXED_LIT: HuffCode = fixed_lit_code();

let LEN_BASE: u16[29] = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
let LEN_EXTRA: u8[29] = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
let DIST_BASE: u16[30] = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
                          4097, 6145, 8193, 12289, 16385, 24577];
let DIST_EXTRA: u8[30] = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
let CODE_ORDER: u8[19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

// --- Decoding --------------------------------------------------------------

// The history a distance may reach back into.
fn inflate_history(d: const Inflate&) -> i64 { if d.full { INFLATE_WINDOW } else { d.wpos } }

// Decodes what of `input` it can, writing at most out.len bytes into out:
// the input bytes it took, the bytes it wrote, and 0 (needs more input or
// room), STREAM_END (the stream ended and everything is written), or an
// error. Input after the stream's end is not taken.
fn inflate_read(d: Inflate&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    var ip: i64 = 0;
    var op: i64 = 0;
    let n_in = input.len;
    var bitbuf = d.bitbuf;
    var bitcnt = d.bitcnt;
    var st: i64 = 0;
    // Hands out what the window holds, then makes room in it.
    fn drain() {
        let n = min(d.wpos - d.rpos, out.len - op);
        if n > 0 {
            out[op..op + n].move_from(d.window[d.rpos..d.rpos + n]);
            op += n;
            d.rpos += n;
        }
        if d.rpos == INFLATE_WINDOW {
            d.wpos = 0;
            d.rpos = 0;
            d.full = true;
        }
    }
    // Takes input bytes into the bit buffer until it holds n bits: false
    // when the input runs out first.
    fn need(n: i64) -> bool {
        while bitcnt < n {
            if ip >= n_in { return false; }
            bitbuf |= (input[ip] as u64) << bitcnt;
            ip++;
            bitcnt += 8;
        }
        return true;
    }
    fn take(n: i64) -> i64 {
        let v = (bitbuf & ((1 << n) - 1)) as! i64;
        bitbuf >>= n;
        bitcnt -= n;
        return v;
    }
    // A symbol of h: >= 0, -1 for more input, -2 for an invalid code.
    fn decode(h: const HuffCode&) -> i64 {
        loop {
            let e = h.table[bitbuf & 511];
            let len = (e & 15) as i64;
            if e == 0 {
                if bitcnt >= 1 { return -2; }
            } else if len != 15 {
                if len <= bitcnt {
                    bitbuf >>= len;
                    bitcnt -= len;
                    return (e >> 4);
                }
            } else if bitcnt >= 10 {
                let sym, slen = huff_slow(h, bitbuf, bitcnt);
                if sym >= 0 {
                    bitbuf >>= slen;
                    bitcnt -= slen;
                    return sym;
                }
                if sym == -2 || bitcnt >= 15 { return -2; }
            }
            if ip >= n_in { return -1; }
            bitbuf |= (input[ip] as u64) << bitcnt;
            ip++;
            bitcnt += 8;
        }
        return -1;
    }
    fn fail(e: i64) {
        d.err = e;
        d.state = IS_FAILED;
        st = e;
    }
    // The fast loop: while 8 bytes of input and 258 bytes of window room
    // are at hand, whole symbol sequences are decoded without stopping (a
    // length, a distance and their extra bits are at most 48 bits). At its
    // end the whole bytes left in the bit buffer go back to the input.
    // Near the end of the input the state machine takes over, so what is
    // decoded before a stop is the same either way.
    // Whole bytes taken ahead go back to the input.
    fn giveback() {
        while bitcnt >= 8 && ip > 0 {
            ip--;
            bitcnt -= 8;
        }
        bitbuf &= (1 << bitcnt) - 1;
    }
    fn fast(h: const HuffCode&) -> bool {
        let fixed = d.fixed_dist;
        while ip + 8 <= n_in && d.wpos <= INFLATE_WINDOW - 258 {
            while bitcnt <= 56 {
                bitbuf |= (input[ip] as u64) << bitcnt;
                ip++;
                bitcnt += 8;
            }
            var e = h.table[bitbuf & 511];
            var sym: i64 = 0;
            var len = (e & 15) as i64;
            if len == 15 {
                let s2, l2 = huff_slow(h, bitbuf, bitcnt);
                if s2 < 0 { giveback(); fail(ERR_DATA); return false; }
                sym = s2;
                len = l2;
            } else if e == 0 {
                giveback();
                fail(ERR_DATA);
                return false;
            } else {
                sym = (e >> 4);
            }
            bitbuf >>= len;
            bitcnt -= len;
            if sym < 256 {
                d.window[d.wpos] = sym as! u8;
                d.wpos++;
                continue;
            }
            if sym == 256 {
                d.state = IS_BLOCK;
                break;
            }
            if sym >= 286 { giveback(); fail(ERR_DATA); return false; }
            var length = LEN_BASE[sym - 257] as i64;
            let le = LEN_EXTRA[sym - 257] as i64;
            length += (bitbuf & ((1 << le) - 1)) as! i64;
            bitbuf >>= le;
            bitcnt -= le;
            var dsym: i64 = 0;
            if fixed {
                dsym = reverse_bits((bitbuf & 31) as! i64, 5);
                bitbuf >>= 5;
                bitcnt -= 5;
            } else {
                let de0 = d.distcode.table[bitbuf & 511];
                var dlen = (de0 & 15) as i64;
                if dlen == 15 {
                    let s3, l3 = huff_slow(d.distcode, bitbuf, bitcnt);
                    if s3 < 0 { giveback(); fail(ERR_DATA); return false; }
                    dsym = s3;
                    dlen = l3;
                } else if de0 == 0 {
                    giveback();
                    fail(ERR_DATA);
                    return false;
                } else {
                    dsym = (de0 >> 4);
                }
                bitbuf >>= dlen;
                bitcnt -= dlen;
            }
            if dsym >= 30 { giveback(); fail(ERR_DATA); return false; }
            let xe = DIST_EXTRA[dsym] as i64;
            let dist = DIST_BASE[dsym] + (bitbuf & ((1 << xe) - 1)) as! i64;
            bitbuf >>= xe;
            bitcnt -= xe;
            if dist > inflate_history(d) { giveback(); fail(ERR_DATA); return false; }
            let wpos = d.wpos;
            if dist >= length && wpos >= dist {
                d.window[wpos..wpos + length].move_from(d.window[wpos - dist..wpos - dist + length]);
            } else {
                var src = wpos - dist;
                if src < 0 { src += INFLATE_WINDOW; }
                for k in length {
                    d.window[wpos + k] = d.window[src];
                    src++;
                    if src == INFLATE_WINDOW { src = 0; }
                }
            }
            d.wpos = wpos + length;
        }
        giveback();
        return true;
    }

    // After an error, what was decoded before it is handed out first, as
    // Go's reader does; then the error.
    if d.err != 0 {
        drain();
        d.total_out += op;
        return 0, op, if d.rpos < d.wpos { 0 } else { d.err };
    }
    loop {
        let s = d.state;
        if s == IS_BLOCK {
            if d.last {
                d.state = IS_DONE;
                continue;
            }
            if !need(3) { break; }
            d.last = take(1) == 1;
            let typ = take(2);
            if typ == 0 {
                d.state = IS_STORED_LEN;
            } else if typ == 1 {
                d.fixed_dist = true;
                d.state = IS_LEN;
            } else if typ == 2 {
                d.fixed_dist = false;
                d.state = IS_TABLE;
            } else {
                fail(ERR_DATA);
                break;
            }
        } else if s == IS_STORED_LEN {
            // To a byte boundary, then LEN and NLEN.
            take(bitcnt & 7);
            if !need(32) { break; }
            let len = take(16);
            let nlen = take(16);
            if len != (nlen ^ 0xffff) { fail(ERR_DATA); break; }
            d.stored_left = len;
            d.state = IS_STORED;
        } else if s == IS_STORED {
            if d.stored_left == 0 {
                d.state = IS_BLOCK;
                continue;
            }
            if d.wpos == INFLATE_WINDOW {
                drain();
                if d.wpos == INFLATE_WINDOW { break; }
            }
            // Whole bytes still in the bit buffer come first.
            if bitcnt > 0 {
                d.window[d.wpos] = take(8) as! u8;
                d.wpos++;
                d.stored_left--;
                continue;
            }
            var n = min(d.stored_left, INFLATE_WINDOW - d.wpos);
            n = min(n, n_in - ip);
            if n == 0 { break; }
            d.window[d.wpos..d.wpos + n].move_from(input[ip..ip + n]);
            ip += n;
            d.wpos += n;
            d.stored_left -= n;
        } else if s == IS_TABLE {
            if !need(14) { break; }
            d.nlen = take(5) + 257;
            d.ndist = take(5) + 1;
            d.ncode = take(4) + 4;
            if d.nlen > 286 || d.ndist > 30 { fail(ERR_DATA); break; }
            d.have = 0;
            d.state = IS_LENLENS;
        } else if s == IS_LENLENS {
            while d.have < d.ncode {
                if !need(3) { break; }
                d.lengths[CODE_ORDER[d.have]] = take(3) as! u8;
                d.have++;
            }
            if d.have < d.ncode { break; }
            while d.have < 19 {
                d.lengths[CODE_ORDER[d.have]] = 0;
                d.have++;
            }
            // The code length code is built in lencode, which the
            // literal/length code replaces once the lengths are read.
            if !huff_build(d.lencode, d.lengths[..19]) { fail(ERR_DATA); break; }
            d.have = 0;
            d.rep_sym = 0;
            d.state = IS_CODELENS;
        } else if s == IS_CODELENS {
            let total = d.nlen + d.ndist;
            var bad = false;
            var more = false;
            while d.have < total {
                // A repeat's extra bits may come in a later call: rep_sym
                // keeps the repeat symbol meanwhile.
                var sym = d.rep_sym;
                if sym == 0 {
                    sym = decode(d.lencode);
                    if sym == -1 { more = true; break; }
                    if sym < 0 { bad = true; break; }
                    if sym < 16 {
                        d.lengths[d.have] = sym as! u8;
                        d.have++;
                        continue;
                    }
                    if sym == 16 && d.have == 0 { bad = true; break; }
                    d.rep_sym = sym;
                }
                let nb: i64 = if sym == 16 { 2 } else if sym == 17 { 3 } else { 7 };
                if !need(nb) { more = true; break; }
                d.rep_sym = 0;
                var rep: i64 = if sym == 18 { 11 } else { 3 };
                rep += take(nb);
                let len: u8 = if sym == 16 { d.lengths[d.have - 1] } else { 0 };
                if d.have + rep > total { bad = true; break; }
                for k in rep {
                    d.lengths[d.have] = len;
                    d.have++;
                }
            }
            if bad { fail(ERR_DATA); break; }
            if more { break; }
            // The end-of-block code must exist: without it the block never ends.
            if d.lengths[256] == 0 { fail(ERR_DATA); break; }
            if !huff_build(d.lencode, d.lengths[..d.nlen]) { fail(ERR_DATA); break; }
            // Go reads at least the end-of-block code's length before each
            // literal/length symbol (a valid stream always has that many
            // bits left), so a stream cut short gives the same output.
            d.lencode.min = max(d.lencode.min, d.lengths[256]);
            if !huff_build(d.distcode, d.lengths[d.nlen..d.nlen + d.ndist]) { fail(ERR_DATA); break; }
            d.state = IS_LEN;
        } else if s == IS_LEN {
            if d.wpos == INFLATE_WINDOW {
                drain();
                if d.wpos == INFLATE_WINDOW { break; }
            }
            if ip + 8 <= n_in && d.wpos <= INFLATE_WINDOW - 258 {
                let ok = if d.fixed_dist { fast(FIXED_LIT) } else { fast(d.lencode) };
                if !ok { break; }
                continue;
            }
            if !need(if d.fixed_dist { 7 } else { d.lencode.min }) { break; }
            let sym = if d.fixed_dist { decode(FIXED_LIT) } else { decode(d.lencode) };
            if sym == -1 { break; }
            if sym < 0 { fail(ERR_DATA); break; }
            if sym < 256 {
                d.window[d.wpos] = sym as! u8;
                d.wpos++;
                continue;
            }
            if sym == 256 {
                d.state = IS_BLOCK;
                continue;
            }
            if sym >= 286 { fail(ERR_DATA); break; }
            d.length = LEN_BASE[sym - 257];
            d.extra = LEN_EXTRA[sym - 257];
            d.state = IS_LENEXT;
        } else if s == IS_LENEXT {
            if !need(d.extra) { break; }
            d.length += take(d.extra);
            d.state = IS_DIST;
        } else if s == IS_DIST {
            var sym: i64 = 0;
            if d.fixed_dist {
                if !need(5) { break; }
                sym = reverse_bits(take(5), 5);
            } else {
                sym = decode(d.distcode);
                if sym == -1 { break; }
                if sym < 0 { fail(ERR_DATA); break; }
            }
            if sym >= 30 { fail(ERR_DATA); break; }
            d.dist = DIST_BASE[sym];
            d.extra = DIST_EXTRA[sym];
            d.state = IS_DISTEXT;
        } else if s == IS_DISTEXT {
            if !need(d.extra) { break; }
            d.dist += take(d.extra);
            if d.dist > inflate_history(d) { fail(ERR_DATA); break; }
            d.state = IS_MATCH;
        } else if s == IS_MATCH {
            if d.wpos == INFLATE_WINDOW {
                drain();
                if d.wpos == INFLATE_WINDOW { break; }
            }
            let n = min(d.length, INFLATE_WINDOW - d.wpos);
            var src = d.wpos - d.dist;
            if src < 0 { src += INFLATE_WINDOW; }
            for k in n {
                d.window[d.wpos] = d.window[src];
                d.wpos++;
                src++;
                if src == INFLATE_WINDOW { src = 0; }
            }
            d.length -= n;
            if d.length == 0 { d.state = IS_LEN; }
        } else if s == IS_DONE {
            drain();
            if d.rpos == d.wpos {
                // The rest of the last byte is padding.
                take(bitcnt & 7);
                st = STREAM_END;
            }
            break;
        } else {
            break;
        }
    }
    if st == 0 { drain(); }
    if st < 0 {
        drain();
        if d.rpos < d.wpos { st = 0; }
    }
    d.bitbuf = bitbuf;
    d.bitcnt = bitcnt;
    d.total_in += ip;
    d.total_out += op;
    return ip, op, st;
}

// Whether the stream ended and everything was handed out.
fn inflate_done(d: const Inflate&) -> bool { d.state == IS_DONE && d.rpos == d.wpos }

// Decodes a whole raw DEFLATE stream and appends it to out: 0 or an error
// (ERR_TRUNCATED if it ends early, ERR_LIMIT past `limit` bytes of output,
// < 0 for none). Bytes after the stream are ignored, as Go ignores them.
fn inflate_decode(data: const u8[:], out: u8[>..]&, limit: i64 = -1) -> i64 {
    var d = inflate_reader();
    return inflate_decode_with(d, data, out, limit);
}

fn inflate_decode_with(d: Inflate&, data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var p: i64 = 0;
    loop {
        let start = out.len;
        out.resize(start + 65536, 0);
        let used, made, st = inflate_read(d, data[p..], out[start..]);
        out.resize(start + made);
        p += used;
        if limit >= 0 && out.len > limit { return ERR_LIMIT; }
        if st < 0 { return st; }
        if st == STREAM_END { return 0; }
        if p >= data.len && made == 0 { return ERR_TRUNCATED; }
    }
    return 0;
}
