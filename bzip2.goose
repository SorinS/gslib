// compress.bzip2: bzip2 decompression, as Go's compress/bzip2 reads it,
// and compression (which Go does not have), as the bzip2 program writes it.
//
// Reading:
//
//   var d = compress::bzip2_reader();
//   let used, made, st = compress::bzip2_read(d, input, out);
//   // st: 0 (more input, or more room in out), STREAM_END, or an error
//   // at the input's end: compress::bzip2_done(d) says whether it ended whole
//
// The reader is fed the input in pieces of any size, down to a byte: it
// keeps what it has read as explicit state (a bit buffer, where it is in a
// block's header, the block decoded so far), never the input itself. A
// block is held as the inverse BWT needs it (900k entries of 4 bytes, the
// most a block may hold) and its bytes are produced as the caller makes
// room: a block whose run lengths expand it to 45 MB costs no more memory
// than one that does not. Concatenated streams are read one after another,
// as Go reads them; anything else after a stream is an error.
//
// What Go refuses, this reader refuses, at the same point: a bad magic
// value, a block size digit outside 1-9, a randomised block (deprecated;
// Go refuses them), no symbols, a number of Huffman tables outside 2-6, a
// selector past the tables, code lengths outside 1-20, a Huffman code with
// two equal codes, runs past the block size, an origPtr past the block, a
// block or stream CRC that does not match. Huffman codes are built Go's
// way, so incomplete codes decode as Go decodes them.
//
// Writing:
//
//   var w = compress::bzip2_writer(9);           // block size 1-9 (x 100k)
//   compress::bzip2_write(w, input, out);        // appends to the builder out
//   compress::bzip2_close(w, out);
//
// The writer does what bzip2 1.0 does: the initial run-length coding, a
// Burrows-Wheeler transform by suffix sorting (prefix doubling with
// radix-sorted buckets, O(n log n) whatever the input), move-to-front and
// the zero-run coding, and 2 to 6 Huffman tables chosen per 50 symbols and
// refined over four passes.

namespace compress;

import std;

// --- The CRC (CRC-32 with the bits taken most significant first) ----------

fn bzip2_make_crc_table() -> u32[256] {
    var t: u32[256] = [0; 256];
    for i in 256 {
        var c = (i as! u32) << 24;
        for k in 8 { c = if (c & 0x80000000) != 0 { (c << 1) ^ 0x04c11db7 } else { c << 1 }; }
        t[i] = c;
    }
    return t;
}

let BZIP2_CRC_TABLE: u32[256] = bzip2_make_crc_table();

// bzip2's CRC of crc's data followed by p. Start from 0.
fn bzip2_crc_update(crc: u32, p: const u8[:]) -> u32 {
    var c = crc ^ 0xffffffff;
    for b in p { c = BZIP2_CRC_TABLE[((c >> 24) ^ b) & 0xff] ^ (c << 8); }
    return c ^ 0xffffffff;
}

// --- Reader state ----------------------------------------------------------

let BZ_MAGIC: u8 = 0;           // "BZ" of the first stream
let BZ_H: u8 = 1;               // 'h'
let BZ_LEVEL: u8 = 2;           // '1'-'9'
let BZ_BLOCK: u8 = 3;           // a block's or the end's 48-bit magic
let BZ_BLOCK_HDR: u8 = 4;       // CRC, randomised, origPtr
let BZ_BITMAP: u8 = 5;          // the 16 ranges used
let BZ_RANGES: u8 = 6;          // each range's 16 symbols
let BZ_TREES: u8 = 7;           // the number of tables and of selectors
let BZ_SELECTORS: u8 = 8;
let BZ_LENGTHS: u8 = 9;         // the tables' code lengths
let BZ_SYMBOLS: u8 = 10;        // the block's symbols
let BZ_OUTPUT: u8 = 11;         // the block's bytes, as the caller takes them
let BZ_END_CRC: u8 = 12;        // the stream's CRC
let BZ_AFTER: u8 = 13;          // a stream ended: another may follow
let BZ_FAILED: u8 = 14;

let BZ_TABLE_BITS: i64 = 10;
let BZ_LEAF: u16 = 0xffff;
let BZ_MAX_ALPHA: i64 = 258;

// One Huffman table, as Go builds it: a binary tree whose nodes link to
// other nodes or name a symbol (BZ_LEAF), and a table over the first
// BZ_TABLE_BITS bits: (length << 16 | symbol) for a symbol reached by then,
// or (0x80000000 | node) to walk on from.
struct Bzip2Tree {
    left: u16[258], right: u16[258], left_value: u16[258], right_value: u16[258],
    fast: u32[1024],
}

struct Bzip2Reader {
    state: u8,
    err: i64,
    bb: u64, nb: i64,               // the bit buffer: its low nb bits, read from the top
    ip: i64,                        // where in this call's input
    block_size: i64,
    file_crc: u32, block_crc: u32, want_block_crc: u32,
    orig_ptr: i64,
    streams: i64,                   // streams that ended whole
    // A block's header.
    ranges: i64, range_i: i64,
    num_symbols: i64,               // symbols used (the MTF list's length)
    symbols: u8[256],
    num_trees: i64, num_selectors: i64, sel_i: i64, sel_c: i64,
    selectors: u8[32768],
    tree_i: i64, sym_j: i64, cur_len: i64, len_started: bool,
    lengths: u8[258],
    trees: Bzip2Tree[6],
    // The block's symbols.
    decoded: i64, sel_next: i64, cur_tree: i64,
    repeat: i64, repeat_power: i64, buf_index: i64,
    mtf: u8[256],
    c: i64[256],
    // The block's bytes.
    tpos: u32, pre_used: i64, last_byte: i64, byte_repeats: i64, repeats: i64,
    tt: u32[900000],
}

fn bzip2_reader() -> Bzip2Reader {
    Bzip2Reader { state: BZ_MAGIC, err: 0, last_byte: -1, .. }
}

// Whether the input so far was whole streams, one or more, and nothing else
// (bits short of a byte after a stream's end aside, which bzip2 pads with).
fn bzip2_done(d: const Bzip2Reader&) -> bool { d.state == BZ_AFTER && d.nb == 0 }

// The streams that ended whole so far.
fn bzip2_streams(d: const Bzip2Reader&) -> i64 { d.streams }

fn bz_fail(d: Bzip2Reader&, e: i64) -> i64 {
    d.state = BZ_FAILED;
    d.err = e;
    return e;
}

// At least n bits (n <= 57) in the bit buffer, taking input as needed.
fn bz_need(d: Bzip2Reader&, input: const u8[:], n: i64) -> bool {
    while d.nb < n {
        if d.ip >= input.len { return false; }
        d.bb = (d.bb << 8) | input[d.ip];
        d.nb += 8;
        d.ip++;
    }
    return true;
}

// n bits (n <= 57), which bz_need made sure are there.
fn bz_take(d: Bzip2Reader&, n: i64) -> u64 {
    d.nb -= n;
    return (d.bb >> (d.nb as! u64)) & ((1 << (n as! u64)) - 1);
}

// --- Huffman tables, Go's way ----------------------------------------------

struct BzCode { code: u32, value: u16 }
struct BzPair { length: u8, value: u16 }
struct BzFrame { lo: i64, hi: i64, level: i64, parent: i64, side: i64 }

// Builds table t from code lengths as Go's newHuffmanTree does: the codes
// assigned from the longest (largest symbol) up, packed at the top of 32
// bits, and a tree that splits them bit by bit, levels where they all
// agree skipped. false for a table Go refuses.
fn bz_build_tree(t: Bzip2Tree&, lengths: const u8[:]) -> bool {
    let n = lengths.len;
    var pairs: BzPair[258] = [BzPair { length: 0, value: 0 }; 258];
    for i in n { pairs[i] = BzPair { length: lengths[i], value: i as! u16 }; }
    sort(pairs[..n]) { a, b => a.length < b.length || (a.length == b.length && a.value < b.value) };
    var codes: BzCode[258] = [BzCode { code: 0, value: 0 }; 258];
    var code: u32 = 0;
    var length: u8 = 32;
    var i = n - 1;
    while i >= 0 {
        if length > pairs[i].length { length = pairs[i].length; }
        codes[i] = BzCode { code: code, value: pairs[i].value };
        code += (1 as u32) << (32 - length);
        i--;
    }
    sort(codes[..n]) { a, b => a.code < b.code };
    // The tree, built depth first with a stack of the ranges still to split.
    var stack: BzFrame[64] = [BzFrame { lo: 0, hi: 0, level: 0, parent: 0, side: 0 }; 64];
    var sp = 0;
    stack[0] = BzFrame { lo: 0, hi: n, level: 0, parent: -1, side: 0 };
    sp = 1;
    var next_node = 0;
    while sp > 0 {
        sp--;
        let f = stack[sp];
        var level = f.level;
        var split = f.hi;
        loop {
            let test = (1 as u32) << ((31 - level) as! u32);
            split = f.hi;
            for k in f.lo..f.hi {
                if (codes[k].code & test) != 0 { split = k; break; }
            }
            if split != f.lo && split != f.hi { break; }
            if f.hi - f.lo < 2 { return false; }       // an empty tree
            if level == 31 { return false; }            // two equal codes
            level++;
        }
        let node = next_node;
        next_node++;
        if f.parent >= 0 {
            if f.side == 0 { t.left[f.parent] = node as! u16; } else { t.right[f.parent] = node as! u16; }
        }
        if split - f.lo == 1 {
            t.left[node] = BZ_LEAF;
            t.left_value[node] = codes[f.lo].value;
        } else {
            stack[sp] = BzFrame { lo: f.lo, hi: split, level: level + 1, parent: node, side: 0 };
            sp++;
        }
        if f.hi - split == 1 {
            t.right[node] = BZ_LEAF;
            t.right_value[node] = codes[split].value;
        } else {
            stack[sp] = BzFrame { lo: split, hi: f.hi, level: level + 1, parent: node, side: 1 };
            sp++;
        }
    }
    // The table over the first BZ_TABLE_BITS bits. A 1 bit goes left, as
    // in Go (left holds the codes with a 0 there: Go's codes are the
    // complement of bzip2's canonical ones).
    for p in 1 << BZ_TABLE_BITS {
        var node: i64 = 0;
        var entry: u32 = 0;
        var found = false;
        for k in BZ_TABLE_BITS {
            let bit = (p >> (BZ_TABLE_BITS - 1 - k)) & 1;
            let next = if bit == 1 { t.left[node] } else { t.right[node] };
            if next == BZ_LEAF {
                let v = if bit == 1 { t.left_value[node] } else { t.right_value[node] };
                entry = ((k + 1) as! u32) << 16 | v;
                found = true;
                break;
            }
            node = next;
        }
        if !found { entry = 0x80000000 | (node as! u32); }
        t.fast[p] = entry;
    }
    return true;
}

// The next symbol of table t, or -1 when the bits buffered do not reach
// its end (nothing is taken then).
fn bz_decode(d: Bzip2Reader&, ti: i64) -> i64 {
    let t .= d.trees[ti];
    var used: i64 = 0;
    var node: i64 = 0;
    if d.nb >= BZ_TABLE_BITS {
        let e = t.fast[(d.bb >> ((d.nb - BZ_TABLE_BITS) as! u64)) & ((1 << BZ_TABLE_BITS) - 1)];
        if (e & 0x80000000) == 0 {
            d.nb -= (e >> 16);
            return (e & 0xffff);
        }
        used = BZ_TABLE_BITS;
        node = (e & 0xffff);
    }
    loop {
        if used >= d.nb { return -1; }
        let bit = (d.bb >> ((d.nb - 1 - used) as! u64)) & 1;
        used++;
        let next = if bit == 1 { t.left[node] } else { t.right[node] };
        if next == BZ_LEAF {
            d.nb -= used;
            return (if bit == 1 { t.left_value[node] } else { t.right_value[node] }) as i64;
        }
        node = next;
    }
    return -1;
}

// --- Reading ---------------------------------------------------------------

// Decodes what it can of input into out: the input used, the bytes made,
// and 0 (more input or more room needed), STREAM_END (a stream ended and
// all its bytes are out; another may still follow) or an error.
fn bzip2_read(d: Bzip2Reader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    if d.state == BZ_FAILED { return 0, 0, d.err; }
    d.ip = 0;
    var made: i64 = 0;
    while true {
        let st = d.state;
        if st == BZ_OUTPUT {
            let n = bz_output(d, out[made..]);
            d.block_crc = bzip2_crc_update(d.block_crc, out[made..made + n]);
            made += n;
            if d.repeats > 0 || d.pre_used < d.buf_index { return d.ip, made, 0; }
            if d.block_crc != d.want_block_crc { return d.ip, made, bz_fail(d, ERR_CHECKSUM); }
            d.state = BZ_BLOCK;
            continue;
        }
        if st == BZ_SYMBOLS {
            let r = bz_symbols(d, input);
            if r < 0 { return d.ip, made, bz_fail(d, r); }
            if r == 0 { return d.ip, made, 0; }
            continue;
        }
        if st == BZ_AFTER {
            if d.ip >= input.len { return d.ip, made, STREAM_END; }
            // Another stream may follow, its "BZ" from the next byte.
            if !bz_need(d, input, 16) { return d.ip, made, 0; }
            if bz_take(d, 16) != 0x425a { return d.ip, made, bz_fail(d, ERR_TRAILING); }
            d.state = BZ_H;
            continue;
        }
        let r = bz_header_step(d, input);
        if r < 0 { return d.ip, made, bz_fail(d, r); }
        if r == 0 { return d.ip, made, 0; }
        if d.state == BZ_AFTER && d.ip >= input.len { return d.ip, made, STREAM_END; }
    }
    return d.ip, made, 0;
}

// One step of the parts between blocks' symbols: 1 when it moved on, 0 for
// more input, or an error.
fn bz_header_step(d: Bzip2Reader&, input: const u8[:]) -> i64 {
    let st = d.state;
    if st == BZ_MAGIC {
        if !bz_need(d, input, 16) { return 0; }
        if bz_take(d, 16) != 0x425a { return ERR_HEADER; }
        d.state = BZ_H;
    } else if st == BZ_H {
        if !bz_need(d, input, 8) { return 0; }
        if bz_take(d, 8) != 'h' { return ERR_HEADER; }
        d.state = BZ_LEVEL;
    } else if st == BZ_LEVEL {
        if !bz_need(d, input, 8) { return 0; }
        let level = bz_take(d, 8) as i64;
        if level < '1' || level > '9' { return ERR_HEADER; }
        d.block_size = 100000 * (level - '0');
        d.file_crc = 0;
        d.state = BZ_BLOCK;
    } else if st == BZ_BLOCK {
        if !bz_need(d, input, 48) { return 0; }
        let m = bz_take(d, 48);
        if m == 0x314159265359 {
            d.state = BZ_BLOCK_HDR;
        } else if m == 0x177245385090 {
            d.state = BZ_END_CRC;
        } else {
            return ERR_DATA;
        }
    } else if st == BZ_END_CRC {
        if !bz_need(d, input, 32) { return 0; }
        if bz_take(d, 32) as! u32 != d.file_crc { return ERR_CHECKSUM; }
        d.nb -= d.nb % 8;           // to a byte boundary
        d.streams++;
        d.state = BZ_AFTER;
    } else if st == BZ_BLOCK_HDR {
        if !bz_need(d, input, 57) { return 0; }
        d.want_block_crc = bz_take(d, 32) as! u32;
        d.block_crc = 0;
        d.file_crc = ((d.file_crc << 1) | (d.file_crc >> 31)) ^ d.want_block_crc;
        if bz_take(d, 1) != 0 { return ERR_UNSUPPORTED; }     // randomised (Go: deprecated)
        d.orig_ptr = bz_take(d, 24) as i64;
        d.state = BZ_BITMAP;
    } else if st == BZ_BITMAP {
        if !bz_need(d, input, 16) { return 0; }
        d.ranges = bz_take(d, 16) as i64;
        d.range_i = 0;
        d.num_symbols = 0;
        d.state = BZ_RANGES;
    } else if st == BZ_RANGES {
        while d.range_i < 16 {
            let r = d.range_i;
            if (d.ranges & (1 << (15 - r))) != 0 {
                if !bz_need(d, input, 16) { return 0; }
                let bits = bz_take(d, 16) as i64;
                for s in 16 {
                    if (bits & (1 << (15 - s))) != 0 {
                        d.symbols[d.num_symbols] = (16 * r + s) as! u8;
                        d.num_symbols++;
                    }
                }
            }
            d.range_i++;
        }
        if d.num_symbols == 0 { return ERR_DATA; }
        d.state = BZ_TREES;
    } else if st == BZ_TREES {
        if !bz_need(d, input, 18) { return 0; }
        d.num_trees = bz_take(d, 3) as i64;
        d.num_selectors = bz_take(d, 15) as i64;
        if d.num_trees < 2 || d.num_trees > 6 { return ERR_DATA; }
        d.sel_i = 0;
        d.sel_c = 0;
        for k in 6 { d.mtf[k] = k as! u8; }
        d.state = BZ_SELECTORS;
    } else if st == BZ_SELECTORS {
        while d.sel_i < d.num_selectors {
            // A unary count, then the MTF list of tables.
            loop {
                if !bz_need(d, input, 1) { return 0; }
                if bz_take(d, 1) == 0 { break; }
                d.sel_c++;
                if d.sel_c >= d.num_trees { return ERR_DATA; }
            }
            let c = d.sel_c;
            let v = d.mtf[c];
            var k = c;
            while k > 0 { d.mtf[k] = d.mtf[k - 1]; k--; }
            d.mtf[0] = v;
            d.selectors[d.sel_i] = v;
            d.sel_i++;
            d.sel_c = 0;
        }
        d.tree_i = 0;
        d.sym_j = 0;
        d.len_started = false;
        d.state = BZ_LENGTHS;
    } else if st == BZ_LENGTHS {
        let alpha = d.num_symbols + 2;
        while d.tree_i < d.num_trees {
            if !d.len_started {
                if !bz_need(d, input, 5) { return 0; }
                d.cur_len = bz_take(d, 5) as i64;
                d.len_started = true;
                d.sym_j = 0;
            }
            while d.sym_j < alpha {
                loop {
                    if d.cur_len < 1 || d.cur_len > 20 { return ERR_DATA; }
                    if !bz_need(d, input, 1) { return 0; }
                    if ((d.bb >> ((d.nb - 1) as! u64)) & 1) == 0 { d.nb -= 1; break; }
                    if !bz_need(d, input, 2) { return 0; }
                    if bz_take(d, 2) == 3 { d.cur_len--; } else { d.cur_len++; }
                }
                d.lengths[d.sym_j] = d.cur_len as! u8;
                d.sym_j++;
            }
            if !bz_build_tree(d.trees[d.tree_i], d.lengths[..alpha]) { return ERR_DATA; }
            d.tree_i++;
            d.len_started = false;
        }
        if d.num_selectors == 0 { return ERR_DATA; }
        // The block's symbols start.
        for k in d.num_symbols { d.mtf[k] = d.symbols[k]; }
        for k in 256 { d.c[k] = 0; }
        d.cur_tree = d.selectors[0];
        d.sel_next = 1;
        d.decoded = 0;
        d.repeat = 0;
        d.repeat_power = 0;
        d.buf_index = 0;
        d.state = BZ_SYMBOLS;
    } else {
        return ERR_ARGUMENT;
    }
    return 1;
}

// The block's symbols, MTF and zero runs undone into tt: 1 at the block's
// end (inverse BWT done), 0 for more input, or an error.
fn bz_symbols(d: Bzip2Reader&, input: const u8[:]) -> i64 {
    let eob = d.num_symbols + 1;
    while true {
        if d.decoded == 50 {
            if d.sel_next >= d.num_selectors { return ERR_DATA; }
            d.cur_tree = d.selectors[d.sel_next];
            d.sel_next++;
            d.decoded = 0;
        }
        if d.nb < 20 { bz_need(d, input, 57); }
        let v = bz_decode(d, d.cur_tree);
        if v < 0 { return 0; }
        d.decoded++;
        if v < 2 {
            // RUNA or RUNB: a digit of a run's length, in bijective base 2.
            if d.repeat == 0 { d.repeat_power = 1; }
            d.repeat += d.repeat_power << v;
            d.repeat_power <<= 1;
            if d.repeat > 2 * 1024 * 1024 { return ERR_DATA; }
            continue;
        }
        if d.repeat > 0 {
            if d.repeat > d.block_size - d.buf_index { return ERR_DATA; }
            let b = d.mtf[0];
            for k in d.repeat { d.tt[d.buf_index + k] = b; }
            d.c[b] += d.repeat;
            d.buf_index += d.repeat;
            d.repeat = 0;
        }
        if v == eob { break; }
        // MTF index v - 1 (index 0 only ever comes as a run).
        let k0 = v - 1;
        let b = d.mtf[k0];
        var k = k0;
        while k > 0 { d.mtf[k] = d.mtf[k - 1]; k--; }
        d.mtf[0] = b;
        if d.buf_index >= d.block_size { return ERR_DATA; }
        d.tt[d.buf_index] = b;
        d.c[b]++;
        d.buf_index++;
    }
    if d.orig_ptr >= d.buf_index { return ERR_DATA; }
    // The inverse BWT, bzip2's single-array way: each entry keeps its byte
    // in the low 8 bits and the index of the next in the top 24.
    var sum: i64 = 0;
    for i in 256 {
        sum += d.c[i];
        d.c[i] = sum - d.c[i];
    }
    for i in d.buf_index {
        let b = d.tt[i] & 0xff;
        let at = d.c[b];
        d.tt[at] |= (i as! u32) << 8;
        d.c[b] = at + 1;
    }
    d.tpos = d.tt[d.orig_ptr] >> 8;
    d.pre_used = 0;
    d.last_byte = -1;
    d.byte_repeats = 0;
    d.repeats = 0;
    d.state = BZ_OUTPUT;
    return 1;
}

// The block's bytes into out, the initial run-length coding undone as Go
// undoes it: after four equal bytes, the next is a count of more.
fn bz_output(d: Bzip2Reader&, out: u8[:]) -> i64 {
    var n: i64 = 0;
    let room = out.len;
    var tpos = d.tpos;
    var pre_used = d.pre_used;
    var last = d.last_byte;
    var byte_repeats = d.byte_repeats;
    var repeats = d.repeats;
    let end = d.buf_index;
    while n < room && (repeats > 0 || pre_used < end) {
        if repeats > 0 {
            out[n] = last as! u8;
            n++;
            repeats--;
            if repeats == 0 { last = -1; }
            continue;
        }
        tpos = d.tt[tpos];
        let b = (tpos & 0xff) as i64;
        tpos >>= 8;
        pre_used++;
        if byte_repeats == 3 {
            repeats = b;
            byte_repeats = 0;
            continue;
        }
        if last == b { byte_repeats++; } else { byte_repeats = 0; }
        last = b;
        out[n] = b as! u8;
        n++;
    }
    d.tpos = tpos;
    d.pre_used = pre_used;
    d.last_byte = last;
    d.byte_repeats = byte_repeats;
    d.repeats = repeats;
    return n;
}

// Decodes a whole bzip2 input (one or more streams) and appends it to out:
// 0, or an error (ERR_TRUNCATED for input that ends inside a stream,
// ERR_LIMIT when the output would pass `limit` bytes; limit < 0: none).
fn bzip2_decode(data: const u8[:], out: u8[>..]&, limit: i64 = -1) -> i64 {
    var d = bzip2_reader();
    var buf: u8[65536] = [0; 65536];
    var at: i64 = 0;
    var total: i64 = 0;
    loop {
        let used, made, st = bzip2_read(d, data[at..], buf);
        at += used;
        total += made;
        if limit >= 0 && total > limit { return ERR_LIMIT; }
        out.append(buf[..made]);
        if st < 0 { return st; }
        if made == 0 && (at >= data.len || used == 0) { break; }
    }
    return if bzip2_done(d) { 0 } else { ERR_TRUNCATED };
}

// --- Writing ---------------------------------------------------------------

let BZ_N_GROUPS: i64 = 6;
let BZ_G_SIZE: i64 = 50;
let BZ_N_ITERS: i64 = 4;
let BZ_MAX_SELECTORS: i64 = 18002;
let BZ_RUNA: u16 = 0;
let BZ_RUNB: u16 = 1;

struct Bzip2Writer {
    level: i64,
    err: i64,
    header_done: bool,
    closed: bool,
    nblock_max: i64,
    // The initial run-length coding: the byte of the run being counted
    // (256 for none) and its length.
    run_ch: i64, run_len: i64,
    nblock: i64,
    block_crc: u32, combined_crc: u32,
    in_use: bool[256],
    bb: u64, nb: i64,               // the bit writer: the low nb bits are pending
    // A block's coding.
    len: u8[258][6],
    code: u32[258][6],
    rfreq: i32[258][6],
    mtf_freq: i32[258],
    selector: u8[18002],
    selector_mtf: u8[18002],
    blk: u8[900000],
    // Suffix sorting: the rotations in order, and two arrays of ranks.
    sa: i32[900000],
    ra: i32[900000],
    rb: i32[900000],
    cnt: i32[900000],
    mtfv: u16[900002],
}

// A writer with blocks of level x 100k bytes (1-9; 9 is bzip2's default).
// A level out of range makes a writer that fails with ERR_ARGUMENT.
fn bzip2_writer(level: i64 = 9) -> Bzip2Writer {
    let ok = level >= 1 && level <= 9;
    let l = if ok { level } else { 9 };
    Bzip2Writer { level: l, err: if ok { 0 } else { ERR_ARGUMENT }, nblock_max: 100000 * l - 19,
                  run_ch: 256, .. }
}

fn bzw_bits(w: Bzip2Writer&, out: u8[>..]&, n: i64, v: u64) {
    w.bb = (w.bb << (n as! u64)) | v;
    w.nb += n;
    while w.nb >= 8 {
        w.nb -= 8;
        out.push(((w.bb >> (w.nb as! u64)) & 0xff) as! u8);
    }
}

fn bzw_add_byte(w: Bzip2Writer&, ch: i64) {
    w.blk[w.nblock] = ch as! u8;
    w.nblock++;
    w.in_use[ch] = true;
}

// The run that was being counted goes into the block, with the CRC of the
// bytes it stands for.
fn bzw_add_run(w: Bzip2Writer&) {
    let ch = w.run_ch;
    let n = w.run_len;
    var crc = w.block_crc ^ 0xffffffff;
    for k in n { crc = BZIP2_CRC_TABLE[((crc >> 24) ^ (ch as! u32)) & 0xff] ^ (crc << 8); }
    w.block_crc = crc ^ 0xffffffff;
    if n < 4 {
        for k in n { bzw_add_byte(w, ch); }
    } else {
        for k in 4 { bzw_add_byte(w, ch); }
        bzw_add_byte(w, n - 4);
    }
}

// Compresses data into the writer, appending what it makes to out: 0 or
// an error (ERR_ARGUMENT after close, or for a bad level).
fn bzip2_write(w: Bzip2Writer&, data: const u8[:], out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    var i = 0;
    let n = data.len;
    while i < n {
        let ch = data[i] as i64;
        if ch == w.run_ch && w.run_len < 255 {
            w.run_len++;
        } else {
            if w.run_ch < 256 { bzw_add_run(w); }
            w.run_ch = ch;
            w.run_len = 1;
        }
        i++;
        // A run adds at most five bytes: the block is full when fewer
        // than that are left (bzip2's nblockMAX).
        if w.nblock >= w.nblock_max { bzw_block(w, out); }
    }
    return 0;
}

// Ends the block being filled, so a reader can produce everything written
// so far (bzip2's BZ_FLUSH).
fn bzip2_flush(w: Bzip2Writer&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    if w.run_ch < 256 { bzw_add_run(w); w.run_ch = 256; w.run_len = 0; }
    if w.nblock > 0 { bzw_block(w, out); }
    return 0;
}

// Ends the stream: the last block, the end marker and the stream's CRC.
fn bzip2_close(w: Bzip2Writer&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    bzip2_flush(w, out);
    bzw_header(w, out);
    bzw_bits(w, out, 24, 0x177245);
    bzw_bits(w, out, 24, 0x385090);
    bzw_bits(w, out, 32, w.combined_crc);
    if w.nb > 0 { bzw_bits(w, out, 8 - w.nb, 0); }
    w.closed = true;
    return 0;
}

// Compresses data whole (level 1-9) and appends the stream to out: 0, or
// ERR_ARGUMENT for a bad level.
fn bzip2_encode(data: const u8[:], out: u8[>..]&, level: i64 = 9) -> i64 {
    var w = bzip2_writer(level);
    let e = bzip2_write(w, data, out);
    if e != 0 { return e; }
    return bzip2_close(w, out);
}

fn bzw_header(w: Bzip2Writer&, out: u8[>..]&) {
    if w.header_done { return; }
    out.append("BZh");
    out.push(('0' + w.level) as! u8);
    w.header_done = true;
}

// --- The Burrows-Wheeler transform -----------------------------------------

// Sorts the block's rotations by prefix doubling: ranks by the first byte,
// then each round orders by (rank of the first h bytes, rank of the next
// h), with a counting sort, until every rank differs or h covers the
// block. O(n) a round and at most log2(n) + 1 rounds. Returns origPtr,
// where the rotation starting at 0 landed.
fn bzw_sort(w: Bzip2Writer&) -> i64 {
    let n = w.nblock;
    var sa = w.sa[..n];
    var cnt = w.cnt[..];
    var c = w.ra[..n];
    var t = w.rb[..n];
    // Round 0: by the first byte.
    for k in 256 { cnt[k] = 0; }
    let blk = w.blk[..n];
    for i in n { cnt[blk[i]]++; }
    var sum: i32 = 0;
    for k in 256 { let v = cnt[k]; cnt[k] = sum; sum += v; }
    for i in n {
        let b = blk[i];
        sa[cnt[b]] = i as! i32;
        cnt[b]++;
    }
    var classes: i64 = 1;
    c[sa[0]] = 0;
    for i in 1..n {
        if blk[sa[i]] != blk[sa[i - 1]] { classes++; }
        c[sa[i]] = (classes - 1) as! i32;
    }
    var h: i64 = 1;
    while classes < n && h < n {
        // The rotations by their second half are sa shifted back by h.
        for i in n {
            var p = sa[i] - h;
            if p < 0 { p += n; }
            t[i] = p as! i32;
        }
        // A stable counting sort of those by their first half's rank.
        for k in classes { cnt[k] = 0; }
        for i in n { cnt[c[t[i]]]++; }
        var s: i32 = 0;
        for k in classes { let v = cnt[k]; cnt[k] = s; s += v; }
        for i in n {
            let p = t[i];
            let r = c[p];
            sa[cnt[r]] = p;
            cnt[r]++;
        }
        // New ranks, into t.
        t[sa[0]] = 0;
        classes = 1;
        for i in 1..n {
            let a = sa[i] as i64;
            let b = sa[i - 1] as i64;
            var a2 = a + h;
            if a2 >= n { a2 -= n; }
            var b2 = b + h;
            if b2 >= n { b2 -= n; }
            if c[a] != c[b] || c[a2] != c[b2] { classes++; }
            t[a] = (classes - 1) as! i32;
        }
        let tmp = c;
        c = t;
        t = tmp;
        h *= 2;
    }
    for i in n { if sa[i] == 0 { return i; } }
    return 0;
}

// --- Huffman code lengths, bzip2's way -------------------------------------

// Code lengths at most max_len for the frequencies, as bzip2's
// BZ2_hbMakeCodeLengths makes them: Huffman's algorithm with ties going to
// the shallower tree, the frequencies halved until the longest code fits.
fn bzw_code_lengths(lens: u8[:], freq: const i32[:], alpha: i64, max_len: i64) {
    var weight: i64[516] = [0; 516];
    var parent: i64[516] = [0; 516];
    var heap: i64[260] = [0; 260];
    for i in alpha {
        let f = if freq[i] == 0 { 1 } else { freq[i] as i64 };
        weight[i + 1] = f << 8;
    }
    loop {
        var nnodes = alpha;
        var nheap: i64 = 0;
        heap[0] = 0;
        weight[0] = 0;
        parent[0] = -2;
        for i in 1..alpha + 1 {
            parent[i] = -1;
            nheap++;
            heap[nheap] = i;
            // Up the heap.
            var zz = nheap;
            let tmp = heap[zz];
            while weight[tmp] < weight[heap[zz >> 1]] {
                heap[zz] = heap[zz >> 1];
                zz >>= 1;
            }
            heap[zz] = tmp;
        }
        while nheap > 1 {
            let n1 = heap[1];
            heap[1] = heap[nheap];
            nheap--;
            bzw_down_heap(heap[..], weight[..], nheap);
            let n2 = heap[1];
            heap[1] = heap[nheap];
            nheap--;
            bzw_down_heap(heap[..], weight[..], nheap);
            nnodes++;
            parent[n1] = nnodes;
            parent[n2] = nnodes;
            let w1 = weight[n1];
            let w2 = weight[n2];
            let d1 = w1 & 0xff;
            let d2 = w2 & 0xff;
            weight[nnodes] = (((w1 >> 8) + (w2 >> 8)) << 8) | (1 + (if d1 > d2 { d1 } else { d2 }));
            parent[nnodes] = -1;
            nheap++;
            heap[nheap] = nnodes;
            var zz = nheap;
            let tmp = heap[zz];
            while weight[tmp] < weight[heap[zz >> 1]] {
                heap[zz] = heap[zz >> 1];
                zz >>= 1;
            }
            heap[zz] = tmp;
        }
        var too_long = false;
        for i in 1..alpha + 1 {
            var j: i64 = 0;
            var k = i;
            while parent[k] >= 0 { k = parent[k]; j++; }
            lens[i - 1] = j as! u8;
            if j > max_len { too_long = true; }
        }
        if !too_long { break; }
        for i in 1..alpha + 1 {
            let j = 1 + (weight[i] >> 8) / 2;
            weight[i] = j << 8;
        }
    }
}

fn bzw_down_heap(heap: i64[:], weight: const i64[:], nheap: i64) {
    var zz: i64 = 1;
    let tmp = heap[zz];
    loop {
        var yy = zz << 1;
        if yy > nheap { break; }
        if yy < nheap && weight[heap[yy + 1]] < weight[heap[yy]] { yy++; }
        if weight[tmp] < weight[heap[yy]] { break; }
        heap[zz] = heap[yy];
        zz = yy;
    }
    heap[zz] = tmp;
}

// --- A block ---------------------------------------------------------------

fn bzw_block(w: Bzip2Writer&, out: u8[>..]&) {
    bzw_header(w, out);
    let n = w.nblock;
    if n == 0 { return; }
    w.combined_crc = ((w.combined_crc << 1) | (w.combined_crc >> 31)) ^ w.block_crc;
    let orig_ptr = bzw_sort(w);
    bzw_bits(w, out, 24, 0x314159);
    bzw_bits(w, out, 24, 0x265359);
    bzw_bits(w, out, 32, w.block_crc);
    bzw_bits(w, out, 1, 0);
    bzw_bits(w, out, 24, orig_ptr as! u64);
    // The symbols used, and MTF with the zero runs.
    var unseq: u8[256] = [0; 256];
    var n_in_use: i64 = 0;
    for i in 256 {
        if w.in_use[i] { unseq[i] = n_in_use as! u8; n_in_use++; }
    }
    let alpha = n_in_use + 2;
    let eob = n_in_use + 1;
    for k in 258 { w.mtf_freq[k] = 0; }
    var yy: u8[256] = [0; 256];
    for k in n_in_use { yy[k] = k as! u8; }
    var wr: i64 = 0;
    var zpend: i64 = 0;
    for i in n {
        var j = w.sa[i] as i64 - 1;
        if j < 0 { j += n; }
        let ll = unseq[w.blk[j]];
        if yy[0] == ll {
            zpend++;
        } else {
            if zpend > 0 {
                wr = bzw_zero_run(w, wr, zpend);
                zpend = 0;
            }
            var k: i64 = 1;
            var prev = yy[0];
            while yy[k] != ll {
                let t = yy[k];
                yy[k] = prev;
                prev = t;
                k++;
            }
            yy[k] = prev;
            yy[0] = ll;
            w.mtfv[wr] = (k + 1) as! u16;
            w.mtf_freq[k + 1]++;
            wr++;
        }
    }
    if zpend > 0 { wr = bzw_zero_run(w, wr, zpend); }
    w.mtfv[wr] = eob as! u16;
    w.mtf_freq[eob]++;
    wr++;
    bzw_send(w, out, wr, alpha, n_in_use);
    // Ready for the next block.
    w.nblock = 0;
    w.block_crc = 0;
    for k in 256 { w.in_use[k] = false; }
}

// A run of z zeros of the MTF output, as RUNA and RUNB digits.
fn bzw_zero_run(w: Bzip2Writer&, at: i64, z: i64) -> i64 {
    var wr = at;
    var zp = z - 1;
    loop {
        if (zp & 1) != 0 {
            w.mtfv[wr] = BZ_RUNB;
            w.mtf_freq[1]++;
        } else {
            w.mtfv[wr] = BZ_RUNA;
            w.mtf_freq[0]++;
        }
        wr++;
        if zp < 2 { break; }
        zp = (zp - 2) / 2;
    }
    return wr;
}

// The tables, the selectors and the symbols, as bzip2's sendMTFValues.
fn bzw_send(w: Bzip2Writer&, out: u8[>..]&, nmtf: i64, alpha: i64, n_in_use: i64) {
    let ngroups: i64 = if nmtf < 200 { 2 } else if nmtf < 600 { 3 } else if nmtf < 1200 { 4 }
                       else if nmtf < 2400 { 5 } else { 6 };
    // Starting tables: each covers a range of symbols holding about an
    // equal share of the frequencies.
    var npart = ngroups;
    var rem_f: i64 = nmtf;
    var gs: i64 = 0;
    while npart > 0 {
        let t_freq = rem_f / npart;
        var ge = gs - 1;
        var a_freq: i64 = 0;
        while a_freq < t_freq && ge < alpha - 1 {
            ge++;
            a_freq += w.mtf_freq[ge];
        }
        if ge > gs && npart != ngroups && npart != 1 && ((ngroups - npart) % 2 == 1) {
            a_freq -= w.mtf_freq[ge];
            ge--;
        }
        for v in alpha {
            w.len[npart - 1][v] = if v >= gs && v <= ge { 0 } else { 15 };
        }
        npart--;
        gs = ge + 1;
        rem_f -= a_freq;
    }
    // Refine: give each group of 50 symbols the table that codes it in the
    // fewest bits, and make each table's lengths from what it was given.
    var nselectors: i64 = 0;
    for iter in BZ_N_ITERS {
        for t in ngroups { for v in alpha { w.rfreq[t][v] = 0; } }
        nselectors = 0;
        gs = 0;
        while gs < nmtf {
            var ge = gs + BZ_G_SIZE - 1;
            if ge >= nmtf { ge = nmtf - 1; }
            var cost: i64[6] = [0; 6];
            for i in gs..ge + 1 {
                let v = w.mtfv[i];
                for t in ngroups { cost[t] += w.len[t][v]; }
            }
            var bt: i64 = 0;
            var bc = cost[0];
            for t in 1..ngroups { if cost[t] < bc { bc = cost[t]; bt = t; } }
            w.selector[nselectors] = bt as! u8;
            nselectors++;
            for i in gs..ge + 1 { w.rfreq[bt][w.mtfv[i]]++; }
            gs = ge + 1;
        }
        for t in ngroups { bzw_code_lengths(w.len[t][..], w.rfreq[t][..], alpha, 17); }
    }
    // The selectors, move-to-front.
    var pos: u8[6] = [0, 1, 2, 3, 4, 5];
    for i in nselectors {
        let ll = w.selector[i];
        var j: i64 = 0;
        var tmp = pos[0];
        while ll != tmp {
            j++;
            let t2 = tmp;
            tmp = pos[j];
            pos[j] = t2;
        }
        pos[0] = tmp;
        w.selector_mtf[i] = j as! u8;
    }
    // Canonical codes: by length, then by symbol.
    for t in ngroups {
        var min_len: i64 = 32;
        var max_len: i64 = 0;
        for v in alpha {
            let l = w.len[t][v] as i64;
            if l > max_len { max_len = l; }
            if l < min_len { min_len = l; }
        }
        var vec: u32 = 0;
        for l in min_len..max_len + 1 {
            for v in alpha {
                if w.len[t][v] == l { w.code[t][v] = vec; vec++; }
            }
            vec <<= 1;
        }
    }
    // The symbols used: which 16-byte ranges, then each range's 16.
    var in_use16: u64 = 0;
    for r in 16 {
        for s in 16 { if w.in_use[r * 16 + s] { in_use16 |= (1 as u64) << ((15 - r) as! u64); break; } }
    }
    bzw_bits(w, out, 16, in_use16);
    for r in 16 {
        if (in_use16 & ((1 as u64) << ((15 - r) as! u64))) != 0 {
            var bits: u64 = 0;
            for s in 16 { if w.in_use[r * 16 + s] { bits |= (1 as u64) << ((15 - s) as! u64); } }
            bzw_bits(w, out, 16, bits);
        }
    }
    bzw_bits(w, out, 3, ngroups as! u64);
    bzw_bits(w, out, 15, nselectors as! u64);
    for i in nselectors {
        for j in w.selector_mtf[i] { bzw_bits(w, out, 1, 1); }
        bzw_bits(w, out, 1, 0);
    }
    // The code lengths, as deltas.
    for t in ngroups {
        var curr = w.len[t][0] as i64;
        bzw_bits(w, out, 5, curr as! u64);
        for v in alpha {
            let l = w.len[t][v] as i64;
            while curr < l { bzw_bits(w, out, 2, 2); curr++; }
            while curr > l { bzw_bits(w, out, 2, 3); curr--; }
            bzw_bits(w, out, 1, 0);
        }
    }
    // The symbols.
    var sel_ctr: i64 = 0;
    gs = 0;
    while gs < nmtf {
        var ge = gs + BZ_G_SIZE - 1;
        if ge >= nmtf { ge = nmtf - 1; }
        let t = w.selector[sel_ctr] as i64;
        for i in gs..ge + 1 {
            let v = w.mtfv[i];
            bzw_bits(w, out, w.len[t][v], w.code[t][v]);
        }
        gs = ge + 1;
        sel_ctr++;
    }
}
