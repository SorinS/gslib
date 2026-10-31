// compress.lzma: LZMA compression, written as .xz (LZMA2 in xz's
// container, with a CRC-32, CRC-64, SHA-256 or no check, and optionally
// a Delta or BCJ filter before LZMA2), as raw LZMA2, or as legacy .lzma.
//
//   var w = compress::xz_writer(6);                 // levels 0-9, as xz's presets' dictionaries
//   compress::xz_write(w, data, out);               // appends what is ready to out
//   compress::xz_flush(w, out);                     // all so far decodable (ends the LZMA2 chunk)
//   compress::xz_close(w, out);                     // the stream's end
//   compress::xz_encode(data, out, 6)               // a whole buffer
//   compress::lzma_encode(data, out, 6)             // .lzma, with the size in the header
//
// Levels follow xz's presets: 0-3 are liblzma's "fast" mode (a hash chain
// over 4-byte strings with direct 2- and 3-byte tables, as its HC4, and the
// heuristics of lzma_encoder_optimum_fast.c), 4-9 its "normal" mode (a
// binary tree, as BT4, and the price-driven optimal parse of
// lzma_encoder_optimum_normal.c), with xz's dictionary sizes (256 KiB to
// 64 MiB), match lengths that end a search (nice) and search depths.
// LZMA2 chunks end at 2 MiB of input or near 64 KiB of output, and a chunk
// that does not compress is written uncompressed, as liblzma does.
//
// Memory: the window (the dictionary, at least 2 MiB behind the encoder
// and 2 MiB of input ahead), 4 bytes per dictionary byte of chains (8 for
// the binary tree), hash heads of up to half that, and some 650 KB of
// fixed state; the whole-buffer helpers size the dictionary to the input.

namespace compress;

import std;
import compress;

let LZE_OBUF: i64 = 1 << 17;
let LZE_CHUNK_U: i64 = (1 << 21) - 300 - 4096; // input in an LZMA2 chunk (2 MiB, less a parse)
let LZE_CHUNK_C: i64 = (1 << 16) - 200;        // its compressed size (64 KiB, less a symbol and the flush)
let LZE_CHUNK_C_NORMAL: i64 = (1 << 16) - 24576;   // the same less what a parse can add
let LZE_AHEAD: i64 = 1 << 21;                  // input taken ahead of the encoder
let LZE_MAXMATCH: i64 = 273;

let XW_XZ: u8 = 0;
let XW_ALONE: u8 = 1;
let XW_RAW: u8 = 2;

struct LzMatch { len: i64, dist: u32 }

// A position of the optimal parse: the cheapest way found to reach it.
struct LzOpt {
    state: i64,
    prev1_lit: bool, prev2: bool,
    pos_prev2: i64, back_prev2: i64,
    price: u32,
    pos_prev: i64, back_prev: i64,
    backs: u32[4],
}

struct XzWriter {
    mode: u8,
    err: i64,
    closed: bool,
    level: i64,
    check: i64,
    block_size: i64,            // input per block (0: one block)
    // LZMA parameters.
    lc: i64, lp: i64, pb: i64,
    dict_size: i64, nice: i64, depth: i64,
    // Range encoder; finished bytes go to obuf.
    low: u64, range: u32, cache: u8, cache_size: i64,
    olen: i64,
    // Model.
    state: i64, reps: u32[4],
    p: u16[14134],
    // LZMA2 framing.
    need_props: bool, need_dict_reset: bool, need_state_reset: bool,
    chunk_start: i64,           // absolute position where the chunk began
    dstart: i64,                // where the dictionary began (a block's start)
    // xz framing.
    header_done: bool,
    block_open: bool,
    block_taken: i64,           // input taken into the block
    block_out: i64,             // its compressed size so far
    bh_len: i64,                // its header's size
    crc32: u32, crc64: u64, sha: Sha256,
    nrec: i64,
    // A filter before LZMA2.
    has_filter: bool,
    filter_start: u32,
    filter: XzStage,
    // .lzma
    alone_size: i64,            // the size written in the header, -1 unknown
    alone_header_done: bool,
    total_in: i64,
    // Match finder: positions are absolute (0 = the first input byte);
    // the tables hold position + off (0 for none).
    base: i64,                  // the absolute position of win[0]
    cur: i64,                   // the next position to encode
    mfpos: i64,                 // the next position to put in the tables
    wend: i64,                  // the absolute position after the last input byte
    off: u64,
    cyc: i64,                   // dict_size + 1
    keep: i64,                  // bytes kept behind cur when the window slides
    hmask: u32,
    nmatch: i64,                // matches found for the read-ahead position
    matches: LzMatch[300],
    longest: i64,
    // Normal mode: the optimal parse (liblzma's lzma_encoder_optimum_normal.c).
    normal: bool,
    flushing: bool,             // a flush: BT4 leaves out positions it cannot compare fully
    opt_cur: i64, opt_end: i64,
    opts: LzOpt[4096],
    len_prices: u32[8704],      // [rep?][pos_state][len - 2]: 2 x 16 x 272
    slot_prices: u32[256],      // [len_state][slot]
    dist_prices: u32[512],      // [len_state][dist < 128]
    align_prices: u32[16],
    price_count: i64,           // symbols since the prices were made
    head2: u32[65536], head3: u32[65536],
    obuf: u8[131072],
    win: u8[],
    head4: u32[],
    chain: u32[],
    index: u8[>..],             // the xz index's records so far
}

fn lzmae_zeros8(n: i64) -> u8[>..] { var v: u8[>..] = []; v.resize(n, 0); return v; }
fn lzmae_zeros32(n: i64) -> u32[>..] { var v: u32[>..] = []; v.resize(n, 0); return v; }

let LZE_DICT_POW2: i64[10] = [18, 20, 21, 22, 22, 23, 23, 24, 25, 26];
let LZE_DEPTH: i64[10] = [4, 8, 24, 48, 24, 32, 48, 48, 48, 48];       // BT4 for 4-9: liblzma's 16 + nice / 2
let LZE_NICE: i64[10] = [128, 128, 273, 273, 16, 32, 64, 64, 64, 64];

// A dictionary size for a level, made no larger than the input needs
// (size < 0: unknown).
fn lzmae_dict_for(level: i64, size: i64) -> i64 {
    var d: i64 = 1 << (LZE_DICT_POW2[level] as! u64);
    if size >= 0 {
        var s: i64 = 4096;
        while s < size && s < d { s *= 2; }
        if s < d { d = s; }
    }
    return d;
}

// The LZMA2 dictionary-size byte for at least d bytes.
fn lzma2_dict_byte(d: i64) -> u8 {
    for b: u8 in 0..40 {
        if (lzma2_dict_size(b) as i64) >= d { return b; }
    }
    return 40;
}

fn xz_writer_new(mode: u8, level: i64, size: i64) -> XzWriter {
    let lv = if level < 0 || level > 9 { 6 } else { level };
    var dsize = lzmae_dict_for(lv, size);
    if mode != XW_ALONE {
        // A size LZMA2's dictionary byte can say exactly.
        dsize = lzma2_dict_size(lzma2_dict_byte(dsize)) as! i64;
    }
    let cyc = dsize + 1;
    var keep = dsize;
    if keep < (1 << 21) + 600 { keep = (1 << 21) + 600; }
    var hs: u32 = (dsize - 1) as! u32;
    hs |= hs >> 1; hs |= hs >> 2; hs |= hs >> 4; hs |= hs >> 8; hs |= hs >> 16;
    hs >>= 1;
    hs |= 0xffff;
    if hs > (1 << 24) { hs >>= 1; }
    var w = XzWriter {
        mode: mode, err: if level < 0 || level > 9 { ERR_ARGUMENT } else { 0 }, closed: false, level: lv,
        check: XZ_CHECK_CRC64, block_size: 0,
        lc: 3, lp: 0, pb: 2, dict_size: dsize, nice: LZE_NICE[lv], depth: LZE_DEPTH[lv],
        low: 0, range: 0xffffffff, cache: 0, cache_size: 1, olen: 0,
        state: 0, reps: [0; 4], p: [1024; 14134],
        need_props: true, need_dict_reset: true, need_state_reset: false, chunk_start: 0, dstart: 0,
        header_done: false, block_open: false, block_taken: 0, block_out: 0, bh_len: 0,
        crc32: 0, crc64: 0, sha: sha256_new(), nrec: 0,
        has_filter: false, filter_start: 0, filter: xz_stage_new(),
        alone_size: -1, alone_header_done: false, total_in: 0,
        base: 0, cur: 0, mfpos: 0, wend: 0, off: (cyc + 1) as! u64, cyc: cyc, keep: keep,
        hmask: hs, nmatch: 0, matches: [LzMatch { len: 0, dist: 0 }; 300], longest: 0,
        normal: lv >= 4, flushing: false, opt_cur: 0, opt_end: 0,
        opts: [LzOpt { state: 0, prev1_lit: false, prev2: false, pos_prev2: 0, back_prev2: 0, price: 0,
                       pos_prev: 0, back_prev: 0, backs: [0; 4] }; 4096],
        len_prices: [0; 8704], slot_prices: [0; 256], dist_prices: [0; 512], align_prices: [0; 16],
        price_count: 1 << 30,
        head2: [0; 65536], head3: [0; 65536], obuf: [0; 131072],
        win: lzmae_zeros8(keep + LZE_AHEAD + 4096),
        head4: lzmae_zeros32((hs as i64) + 1),
        chain: lzmae_zeros32(if lv >= 4 { 2 * cyc } else { cyc }),
        index: [],
    };
    return w;
}

// A writer of .xz with a CRC-64 check, at a level from 0 to 9.
fn xz_writer(level: i64) -> XzWriter { xz_writer_new(XW_XZ, level, -1) }

// The same with options: the check (XZ_CHECK_NONE, _CRC32, _CRC64,
// _SHA256), a block size (the input of each block, as xz's --block-size;
// 0 for one block), and a filter before LZMA2 (0 for none, or
// XZ_FILTER_DELTA with its distance 1-256 as opt, or one of the BCJ
// filters with its start offset as opt).
fn xz_writer_opts(level: i64, check: i64, block_size: i64, filter: u64, opt: i64) -> XzWriter {
    var w = xz_writer_new(XW_XZ, level, -1);
    if check != XZ_CHECK_NONE && check != XZ_CHECK_CRC32 && check != XZ_CHECK_CRC64 && check != XZ_CHECK_SHA256 {
        w.err = ERR_ARGUMENT;
    }
    w.check = check;
    if block_size < 0 { w.err = ERR_ARGUMENT; }
    w.block_size = block_size;
    if filter != 0 {
        if filter == XZ_FILTER_DELTA {
            if opt < 1 || opt > 256 { w.err = ERR_ARGUMENT; }
            xz_stage_reset(w.filter, filter, 0, opt);
        } else if filter == XZ_FILTER_X86 || filter == XZ_FILTER_POWERPC || filter == XZ_FILTER_IA64
               || filter == XZ_FILTER_ARM || filter == XZ_FILTER_ARMTHUMB || filter == XZ_FILTER_SPARC
               || filter == XZ_FILTER_ARM64 {
            if opt < 0 || opt > 0xffffffff { w.err = ERR_ARGUMENT; }
            w.filter_start = (opt & 0xffffffff) as! u32;
            xz_stage_reset(w.filter, filter, w.filter_start, 1);
        } else {
            w.err = ERR_UNSUPPORTED;
        }
        w.has_filter = true;
    }
    return w;
}

// A writer of a raw LZMA2 stream (no container; the reader needs the
// dictionary size, xz_writer_dict_size(w)).
fn lzma2_writer(level: i64) -> XzWriter { xz_writer_new(XW_RAW, level, -1) }

// A writer of .lzma: size is the input's size if known (written in the
// header, no end marker), -1 for unknown (the end marker ends it).
fn lzma_writer(level: i64, size: i64) -> XzWriter {
    var w = xz_writer_new(XW_ALONE, level, size);
    w.alone_size = if size < 0 { -1 } else { size };
    return w;
}

fn xz_writer_dict_size(w: const XzWriter&) -> i64 { w.dict_size }

// --- Range encoder -----------------------------------------------------------

fn lze_shift_low(w: XzWriter&) {
    if w.low < 0xff000000 || w.low > 0xffffffff {
        let carry = (w.low >> 32) as! u8;
        var temp = w.cache;
        while true {
            w.obuf[w.olen] = temp + carry;
            w.olen++;
            temp = 0xff;
            w.cache_size--;
            if w.cache_size == 0 { break; }
        }
        w.cache = ((w.low >> 24) & 0xff) as! u8;
    }
    w.cache_size++;
    w.low = (w.low & 0x00ffffff) << 8;
}

fn lze_bit(w: XzWriter&, i: i64, bit: u32) {
    let p = w.p[i] as u32;
    let bound = (w.range >> 11) * p;
    if bit == 0 {
        w.range = bound;
        w.p[i] = (p + ((2048 - p) >> 5)) as! u16;
    } else {
        w.low += bound as u64;
        w.range -= bound;
        w.p[i] = (p - (p >> 5)) as! u16;
    }
    while w.range < 0x1000000 {
        w.range <<= 8;
        lze_shift_low(w);
    }
}

fn lze_tree(w: XzWriter&, base: i64, bits: i64, v: u32) {
    var m: u32 = 1;
    var k = bits - 1;
    while k >= 0 {
        let b = (v >> (k as! u32)) & 1;
        lze_bit(w, base + (m as i64), b);
        m = (m << 1) | b;
        k--;
    }
}

fn lze_tree_rev(w: XzWriter&, base: i64, bits: i64, v0: u32) {
    var m: u32 = 1;
    var v = v0;
    for k in bits {
        let b = v & 1;
        v >>= 1;
        lze_bit(w, base + (m as i64), b);
        m = (m << 1) | b;
    }
}

fn lze_direct(w: XzWriter&, v: u32, bits: i64) {
    var k = bits - 1;
    while k >= 0 {
        w.range >>= 1;
        if ((v >> (k as! u32)) & 1) != 0 { w.low += w.range as u64; }
        while w.range < 0x1000000 {
            w.range <<= 8;
            lze_shift_low(w);
        }
        k--;
    }
}

fn lze_flush_rc(w: XzWriter&) {
    for k in 5 { lze_shift_low(w); }
}

fn lze_rc_reset(w: XzWriter&) {
    w.low = 0;
    w.range = 0xffffffff;
    w.cache = 0;
    w.cache_size = 1;
}

// Bytes the range encoder will have written when flushed.
fn lze_pending(w: const XzWriter&) -> i64 { w.olen + w.cache_size + 5 }

// --- Model -------------------------------------------------------------------

fn lze_reset_state(w: XzWriter&) {
    w.price_count = 1 << 30;
    w.state = 0;
    for k in 4 { w.reps[k] = 0; }
    for k in 14134 { w.p[k] = 1024; }
}

fn lze_byte(w: const XzWriter&, abs: i64) -> u8 { w.win[abs - w.base] }

fn lze_len(w: XzWriter&, base: i64, len: i64, ps: i64) {
    let l = len - 2;
    if l < 8 {
        lze_bit(w, base + LZ_LEN_CHOICE, 0);
        lze_tree(w, base + LZ_LEN_LOW + ps * 8, 3, l as! u32);
    } else if l < 16 {
        lze_bit(w, base + LZ_LEN_CHOICE, 1);
        lze_bit(w, base + LZ_LEN_CHOICE2, 0);
        lze_tree(w, base + LZ_LEN_MID + ps * 8, 3, (l - 8) as! u32);
    } else {
        lze_bit(w, base + LZ_LEN_CHOICE, 1);
        lze_bit(w, base + LZ_LEN_CHOICE2, 1);
        lze_tree(w, base + LZ_LEN_HIGH, 8, (l - 16) as! u32);
    }
}

fn lze_dist_slot(dist: u32) -> u32 {
    if dist < 4 { return dist; }
    var n: u32 = 31;
    while (dist >> n) == 0 { n--; }
    return 2 * n + ((dist >> (n - 1)) & 1);
}

fn lze_pos_state(w: const XzWriter&, pos: i64) -> i64 { (pos - w.dstart) & ((1 << (w.pb as! u64)) - 1) }

fn lze_literal(w: XzWriter&, pos: i64) {
    let ps = lze_pos_state(w, pos);
    lze_bit(w, LZ_IS_MATCH + (w.state << 4) + ps, 0);
    let rel = pos - w.dstart;
    let prev: u32 = if rel > 0 { lze_byte(w, pos - 1) } else { 0 };
    let ls = ((rel & ((1 << (w.lp as! u64)) - 1)) << (w.lc as! u64)) + ((prev >> ((8 - w.lc) as! u32)) as i64);
    let base = LZ_LITERAL + 0x300 * ls;
    var sym = (lze_byte(w, pos) as u32) | 0x100;
    if w.state < 7 {
        while sym < 0x10000 {
            lze_bit(w, base + ((sym >> 8) as i64), (sym >> 7) & 1);
            sym <<= 1;
        }
    } else {
        var mb = lze_byte(w, pos - (w.reps[0] as i64) - 1) as u32;
        var offs: u32 = 0x100;
        while sym < 0x10000 {
            mb <<= 1;
            let mbit = mb & offs;
            lze_bit(w, base + ((offs + mbit + (sym >> 8)) as i64), (sym >> 7) & 1);
            sym <<= 1;
            offs &= ~(mb ^ sym);
        }
    }
    w.state = if w.state < 4 { 0 } else if w.state < 10 { w.state - 3 } else { w.state - 6 };
}

fn lze_match(w: XzWriter&, pos: i64, dist: u32, len: i64) {
    let ps = lze_pos_state(w, pos);
    lze_bit(w, LZ_IS_MATCH + (w.state << 4) + ps, 1);
    lze_bit(w, LZ_IS_REP + w.state, 0);
    lze_len(w, LZ_LEN_MATCH, len, ps);
    let ls = if len - 2 < 3 { len - 2 } else { 3 };
    let slot = lze_dist_slot(dist);
    lze_tree(w, LZ_DIST_SLOT + ls * 64, 6, slot);
    if slot >= 4 {
        let footer = (slot >> 1) - 1;
        let base = (2 | (slot & 1)) << footer;
        let reduced = dist - base;
        if slot < 14 {
            lze_tree_rev(w, LZ_DIST_SPECIAL + (base as i64) - (slot as i64) - 1, footer as i64, reduced);
        } else {
            lze_direct(w, reduced >> 4, (footer - 4) as i64);
            lze_tree_rev(w, LZ_DIST_ALIGN, 4, reduced & 15);
        }
    }
    w.reps[3] = w.reps[2]; w.reps[2] = w.reps[1]; w.reps[1] = w.reps[0]; w.reps[0] = dist;
    w.state = if w.state < 7 { 7 } else { 10 };
}

fn lze_rep(w: XzWriter&, pos: i64, rep: i64, len: i64) {
    let ps = lze_pos_state(w, pos);
    lze_bit(w, LZ_IS_MATCH + (w.state << 4) + ps, 1);
    lze_bit(w, LZ_IS_REP + w.state, 1);
    if rep == 0 {
        lze_bit(w, LZ_IS_REP0 + w.state, 0);
        lze_bit(w, LZ_IS_REP0_LONG + (w.state << 4) + ps, if len == 1 { 0 } else { 1 });
    } else {
        let d = w.reps[rep];
        lze_bit(w, LZ_IS_REP0 + w.state, 1);
        if rep == 1 {
            lze_bit(w, LZ_IS_REP1 + w.state, 0);
        } else {
            lze_bit(w, LZ_IS_REP1 + w.state, 1);
            lze_bit(w, LZ_IS_REP2 + w.state, if rep == 2 { 0 } else { 1 });
            if rep == 3 { w.reps[3] = w.reps[2]; }
            w.reps[2] = w.reps[1];
        }
        w.reps[1] = w.reps[0];
        w.reps[0] = d;
    }
    if len == 1 {
        w.state = if w.state < 7 { 9 } else { 11 };
    } else {
        lze_len(w, LZ_LEN_REP, len, ps);
        w.state = if w.state < 7 { 8 } else { 11 };
    }
}

// The end-of-payload marker (.lzma of unknown size).
fn lze_eopm(w: XzWriter&, pos: i64) {
    let ps = lze_pos_state(w, pos);
    lze_bit(w, LZ_IS_MATCH + (w.state << 4) + ps, 1);
    lze_bit(w, LZ_IS_REP + w.state, 0);
    lze_len(w, LZ_LEN_MATCH, 2, ps);
    lze_tree(w, LZ_DIST_SLOT, 6, 63);
    lze_direct(w, 0x3ffffff, 26);
    lze_tree_rev(w, LZ_DIST_ALIGN, 4, 15);
}


// --- Match finder (HC4) ------------------------------------------------------

// As liblzma's: given the first byte, the hash says the next two exactly,
// so a candidate need only be checked for its first byte.
fn lze_h3(a: u32, b: u32, c: u32) -> u32 { (CRC32_TABLE[a] ^ b ^ (c << 8)) & 0xffff }

fn lze_h4(w: const XzWriter&, a: u32, b: u32, c: u32, d: u32) -> u32 {
    ((a | b << 8 | c << 16 | d << 24) * 0x9e3779b1 >> 8) & w.hmask
}

fn lze_matchlen(w: const XzWriter&, a: i64, b: i64, from: i64, limit: i64) -> i64 {
    var n = from;
    let pa = a - w.base;
    let pb = b - w.base;
    while n < limit && w.win[pa + n] == w.win[pb + n] { n++; }
    return n;
}

// Puts mfpos in the tables and finds its matches (w.matches, w.nmatch;
// lengths increasing, at most `nice`, then extended to 273 for the longest).
fn lze_find(w: XzWriter&) {
    let pos = w.mfpos;
    w.mfpos++;
    w.nmatch = 0;
    let avail = w.wend - pos;
    if avail < 4 { return; }
    // More input may follow a flush, and a binary tree built on shorter
    // comparisons would no longer be ordered: those positions wait.
    if w.normal && w.flushing && avail < w.nice { return; }
    var limit = avail;
    if limit > w.nice { limit = w.nice; }
    let i = pos - w.base;
    let b0 = w.win[i] as u32;
    let b1 = w.win[i + 1] as u32;
    let b2 = w.win[i + 2] as u32;
    let b3 = w.win[i + 3] as u32;
    let h2 = (b0 | b1 << 8) as i64;
    let h3 = lze_h3(b0, b1, b2) as i64;
    let h4 = lze_h4(w, b0, b1, b2, b3) as i64;
    let me = ((pos as u64) + w.off) as! u32;
    let m2 = w.head2[h2];
    let m3 = w.head3[h3];
    var cm = w.head4[h4];
    w.head2[h2] = me;
    w.head3[h3] = me;
    w.head4[h4] = me;
    if !w.normal { w.chain[pos % w.cyc] = cm; }
    // Distances reach back to the dictionary's start only.
    var cyc = w.cyc as u32;
    if pos - w.dstart + 1 < w.cyc { cyc = (pos - w.dstart + 1) as! u32; }
    var best: i64 = 1;
    var d2 = me - m2;
    let d3 = me - m3;
    var n = 0;
    if m2 != 0 && d2 < cyc && w.win[i - (d2 as i64)] == b0 {
        best = 2;
        w.matches[0] = LzMatch { len: 2, dist: d2 - 1 };
        n = 1;
    }
    if m3 != 0 && d2 != d3 && d3 < cyc && w.win[i - (d3 as i64)] == b0 {
        best = 3;
        w.matches[n] = LzMatch { len: 3, dist: d3 - 1 };
        n++;
        d2 = d3;
    }
    if n > 0 {
        best = lze_matchlen(w, pos - (d2 as i64), pos, best, limit);
        w.matches[n - 1].len = best;
        if best >= limit {
            if w.normal { lze_bt(w, pos, me, cm, cyc, limit, best, n, false); }
            w.nmatch = n;
            lze_extend(w, pos, avail);
            return;
        }
    }
    if best < 3 { best = 3; }
    if w.normal {
        w.nmatch = lze_bt(w, pos, me, cm, cyc, limit, best, n, true);
        lze_extend(w, pos, avail);
        return;
    }
    var depth = w.depth;
    while depth > 0 && cm != 0 {
        let delta = me - cm;
        if delta >= cyc { break; }
        let c = pos - (delta as i64);
        let ci = c - w.base;
        if w.win[ci + best] == w.win[i + best] && w.win[ci] == w.win[i] {
            let len = lze_matchlen(w, c, pos, 1, limit);
            if len > best {
                best = len;
                w.matches[n] = LzMatch { len: len, dist: delta - 1 };
                n++;
                if len >= limit { break; }
            }
        }
        cm = w.chain[c % w.cyc];
        depth--;
    }
    w.nmatch = n;
    lze_extend(w, pos, avail);
}

// The longest match at nice length goes on as far as it can.
fn lze_extend(w: XzWriter&, pos: i64, avail: i64) {
    let n = w.nmatch;
    if n == 0 { return; }
    let m = w.matches[n - 1];
    if m.len < w.nice { return; }
    var lim = avail;
    if lim > LZE_MAXMATCH { lim = LZE_MAXMATCH; }
    w.matches[n - 1].len = lze_matchlen(w, pos - (m.dist as i64) - 1, pos, m.len, lim);
}

// Puts the next n positions in the tables without searching.
fn lze_skip(w: XzWriter&, n: i64) {
    for k in n {
        let pos = w.mfpos;
        w.mfpos++;
        if w.wend - pos >= 4 && !(w.normal && w.flushing && w.wend - pos < w.nice) {
            let i = pos - w.base;
            let b0 = w.win[i] as u32;
            let b1 = w.win[i + 1] as u32;
            let b2 = w.win[i + 2] as u32;
            let b3 = w.win[i + 3] as u32;
            let me = ((pos as u64) + w.off) as! u32;
            w.head2[(b0 | b1 << 8) as i64] = me;
            w.head3[lze_h3(b0, b1, b2) as i64] = me;
            let h4 = lze_h4(w, b0, b1, b2, b3) as i64;
            if w.normal {
                var cyc = w.cyc as u32;
                if pos - w.dstart + 1 < w.cyc { cyc = (pos - w.dstart + 1) as! u32; }
                var limit = w.wend - pos;
                if limit > w.nice { limit = w.nice; }
                lze_bt(w, pos, me, w.head4[h4], cyc, limit, 0, 0, false);
            } else {
                w.chain[pos % w.cyc] = w.head4[h4];
            }
            w.head4[h4] = me;
        }
    }
}

// The binary tree of BT4 (liblzma's bt_find_func and bt_skip_func): puts
// pos in the tree rooted at the hash head cm and, if `find`, records the
// matches longer than `best` from w.matches[n]; returns the count.
fn lze_bt(w: XzWriter&, pos: i64, me: u32, cm0: u32, cyc: u32, limit: i64, best0: i64, n0: i64, find: bool) -> i64 {
    var cm = cm0;
    var n = n0;
    var best = best0;
    let cpos = (pos % w.cyc) * 2;
    var ptr0 = cpos + 1;
    var ptr1 = cpos;
    var len0: i64 = 0;
    var len1: i64 = 0;
    let i = pos - w.base;
    var depth = w.depth;
    while true {
        let delta = me - cm;
        if depth == 0 || cm == 0 || delta >= cyc {
            w.chain[ptr0] = 0;
            w.chain[ptr1] = 0;
            return n;
        }
        depth--;
        let c = pos - (delta as i64);
        let pair = (c % w.cyc) * 2;
        let ci = c - w.base;
        var len = if len0 < len1 { len0 } else { len1 };
        if w.win[ci + len] == w.win[i + len] {
            len++;
            while len < limit && w.win[ci + len] == w.win[i + len] { len++; }
            if find && len > best {
                best = len;
                w.matches[n] = LzMatch { len: len, dist: delta - 1 };
                n++;
            }
            if len >= limit {
                w.chain[ptr1] = w.chain[pair];
                w.chain[ptr0] = w.chain[pair + 1];
                return n;
            }
        }
        if w.win[ci + len] < w.win[i + len] {
            w.chain[ptr1] = cm;
            ptr1 = pair + 1;
            cm = w.chain[ptr1];
            len1 = len;
        } else {
            w.chain[ptr0] = cm;
            ptr0 = pair;
            cm = w.chain[ptr0];
            len0 = len;
        }
    }
    return n;
}

// --- Choosing symbols: liblzma's fast mode -----------------------------------

fn lze_change_pair(small: u32, big: u32) -> bool { (big >> 7) > small }

// The next symbol at w.cur: (back, len), back -1 for a literal, 0-3 for a
// repeated distance, 4 + distance for a match.
fn lze_choose(w: XzWriter&) -> i64, i64 {
    var len_main: i64 = 0;
    var count: i64 = 0;
    if w.mfpos == w.cur {
        lze_find(w);
        len_main = if w.nmatch > 0 { w.matches[w.nmatch - 1].len } else { 0 };
        count = w.nmatch;
    } else {
        len_main = w.longest;
        count = w.nmatch;
    }
    let pos = w.cur;
    var avail = w.wend - pos;
    if avail > LZE_MAXMATCH { avail = LZE_MAXMATCH; }
    if avail < 2 { return -1, 1; }
    var rep_len: i64 = 0;
    var rep_index: i64 = 0;
    for r in 4 {
        let back = pos - (w.reps[r] as i64) - 1;
        if back < w.dstart { continue; }
        if lze_byte(w, back) != lze_byte(w, pos) || lze_byte(w, back + 1) != lze_byte(w, pos + 1) { continue; }
        let len = lze_matchlen(w, back, pos, 2, avail);
        if len >= w.nice {
            lze_skip(w, len - 1);
            return r, len;
        }
        if len > rep_len { rep_index = r; rep_len = len; }
    }
    if len_main >= w.nice {
        lze_skip(w, len_main - 1);
        return 4 + (w.matches[count - 1].dist as i64), len_main;
    }
    var back_main: u32 = 0;
    if len_main >= 2 {
        back_main = w.matches[count - 1].dist;
        while count > 1 && len_main == w.matches[count - 2].len + 1 {
            if !lze_change_pair(w.matches[count - 2].dist, back_main) { break; }
            count--;
            len_main = w.matches[count - 1].len;
            back_main = w.matches[count - 1].dist;
        }
        if len_main == 2 && back_main >= 0x80 { len_main = 1; }
    }
    if rep_len >= 2 {
        if rep_len + 1 >= len_main || (rep_len + 2 >= len_main && back_main > (1 << 9))
           || (rep_len + 3 >= len_main && back_main > (1 << 15)) {
            lze_skip(w, rep_len - 1);
            return rep_index, rep_len;
        }
    }
    if len_main < 2 || avail <= 2 { return -1, 1; }
    // The matches for the next byte.
    lze_find(w);
    w.longest = if w.nmatch > 0 { w.matches[w.nmatch - 1].len } else { 0 };
    if w.longest >= 2 {
        let nd = w.matches[w.nmatch - 1].dist;
        if (w.longest >= len_main && nd < back_main) || (w.longest == len_main + 1 && !lze_change_pair(back_main, nd))
           || w.longest > len_main + 1 || (w.longest + 1 >= len_main && len_main >= 3 && lze_change_pair(nd, back_main)) {
            return -1, 1;
        }
    }
    var limit = len_main - 1;
    if limit < 2 { limit = 2; }
    for r in 4 {
        let back = pos + 1 - (w.reps[r] as i64) - 1;
        if back < w.dstart { continue; }
        if lze_matchlen(w, back, pos + 1, 0, limit) == limit { return -1, 1; }
    }
    lze_skip(w, len_main - 2);
    return 4 + (back_main as i64), len_main;
}

// Encodes one symbol at w.cur.
fn lze_symbol(w: XzWriter&) {
    var back: i64 = 0;
    var len: i64 = 0;
    if w.normal { back, len = lze_optimum(w); w.price_count++; } else { back, len = lze_choose(w); }
    let pos = w.cur;
    if back < 0 {
        lze_literal(w, pos);
    } else if back < 4 {
        lze_rep(w, pos, back, len);
    } else {
        lze_match(w, pos, (back - 4) as! u32, len);
    }
    w.cur += len;
    // After a literal chosen past a look ahead, the matches found for the
    // next byte stay (w.mfpos == w.cur + 1); otherwise none are kept.
    if w.mfpos != w.cur + 1 { w.longest = 0; }
}

// --- Windows and tables --------------------------------------------------------

// Makes room in the window for more input: what is kept behind cur moves
// to the front.
fn lze_slide(w: XzWriter&) {
    let from = w.cur - w.keep;
    if from <= w.base { return; }
    let shift = from - w.base;
    let n = w.wend - from;
    w.win[..n].move_from(w.win[shift..shift + n]);
    w.base = from;
    // Keep the tables' values in u32.
    if (w.wend as u64) + w.off > 0xe0000000 { lze_normalize(w); }
}

fn lze_normalize(w: XzWriter&) {
    // New values: position + off', with off' = off - sub; entries older than
    // the dictionary go to 0.
    let lowest = w.cur - w.cyc - (1 << 22);
    if lowest <= 0 { return; }
    let sub = ((lowest as u64) + w.off - (w.cyc as u64) - 1) as! u32;
    for k in 65536 {
        w.head2[k] = if w.head2[k] > sub { w.head2[k] - sub } else { 0 };
        w.head3[k] = if w.head3[k] > sub { w.head3[k] - sub } else { 0 };
    }
    for k in w.head4.len { w.head4[k] = if w.head4[k] > sub { w.head4[k] - sub } else { 0 }; }
    for k in w.chain.len { w.chain[k] = if w.chain[k] > sub { w.chain[k] - sub } else { 0 }; }
    w.off -= sub as u64;
}

// --- LZMA2 framing --------------------------------------------------------------

// Ends the chunk: written as LZMA, or uncompressed if that is no larger.
fn lz2_end_chunk(w: XzWriter&, out: u8[>..]&) {
    let usize = w.cur - w.chunk_start;
    if usize == 0 { return; }
    lze_flush_rc(w);
    let csize = w.olen;
    let hdr = if w.need_props { 6 } else { 5 };
    let at0 = out.len;
    if csize + hdr < usize + (usize + 65535) / 65536 * 3 {
        var control: u8 = 0x80;
        if w.need_props { control = if w.need_dict_reset { 0xe0 } else { 0xc0 }; }
        else if w.need_state_reset { control = 0xa0; }
        let u = usize - 1;
        let c = csize - 1;
        out.push(control | ((u >> 16) & 0x1f) as! u8);
        out.push(((u >> 8) & 0xff) as! u8);
        out.push((u & 0xff) as! u8);
        out.push(((c >> 8) & 0xff) as! u8);
        out.push((c & 0xff) as! u8);
        if w.need_props { out.push(((w.pb * 5 + w.lp) * 9 + w.lc) as! u8); }
        out.append(w.obuf[..csize]);
        w.need_props = false;
        w.need_state_reset = false;
        w.need_dict_reset = false;
    } else {
        var p = w.chunk_start;
        while p < w.cur {
            var n = w.cur - p;
            if n > 65536 { n = 65536; }
            out.push(if w.need_dict_reset { 1 } else { 2 });
            out.push((((n - 1) >> 8) & 0xff) as! u8);
            out.push(((n - 1) & 0xff) as! u8);
            out.append(w.win[p - w.base..p - w.base + n]);
            w.need_dict_reset = false;
            p += n;
        }
        // The decoder's model did not see what this encoder's did.
        w.need_state_reset = true;
        lze_reset_state(w);
    }
    w.block_out += out.len - at0;
    w.olen = 0;
    lze_rc_reset(w);
    w.chunk_start = w.cur;
}

// Encodes while enough input is ahead (all of it if `all`).
fn lze_encode(w: XzWriter&, out: u8[>..]&, all: bool) {
    while w.cur < w.wend {
        if !all && w.wend - w.cur < (if w.normal { 4096 + LZE_MAXMATCH + 2 } else { LZE_MAXMATCH + 2 }) { return; }
        lze_symbol(w);
        if w.opt_cur != w.opt_end { continue; }       // a chunk ends between parses only
        if w.mode == XW_ALONE {
            if w.olen > LZE_OBUF - 4096 {
                out.append(w.obuf[..w.olen]);
                w.olen = 0;
            }
        } else if w.cur - w.chunk_start >= LZE_CHUNK_U || lze_pending(w) >= (if w.normal { LZE_CHUNK_C_NORMAL } else { LZE_CHUNK_C }) {
            lz2_end_chunk(w, out);
        }
    }
}

// --- Input -------------------------------------------------------------------------

// Puts bytes in the window, encoding and sliding to make room.
fn lze_take(w: XzWriter&, data: const u8[:], out: u8[>..]&) {
    var p = 0;
    while p < data.len {
        var room = w.win.len - (w.wend - w.base);
        if room < 4096 {
            lze_encode(w, out, false);
            lze_slide(w);
            room = w.win.len - (w.wend - w.base);
        }
        var n = data.len - p;
        if n > room { n = room; }
        let at = w.wend - w.base;
        w.win[at..at + n].move_from(data[p..p + n]);
        w.wend += n;
        p += n;
        lze_encode(w, out, false);
    }
}

// Input through the filter (if any) into the window. `end`: the filter's
// stream ends here (the block's end), so its tail passes unchanged.
fn xz_feed(w: XzWriter&, data: const u8[:], out: u8[>..]&, end: bool) {
    if !w.has_filter {
        lze_take(w, data, out);
        return;
    }
    var p = 0;
    while true {
        xz_stage_compact(w.filter);
        var n = data.len - p;
        if n > XZ_STAGE_BUF - w.filter.filled { n = XZ_STAGE_BUF - w.filter.filled; }
        let f = w.filter.filled;
        w.filter.buf[f..f + n].move_from(data[p..p + n]);
        w.filter.filled += n;
        p += n;
        if end && p == data.len { w.filter.upstream_end = true; }
        xz_stage_convert(w.filter, true);
        let rd = w.filter.rd;
        let conv = w.filter.conv;
        if conv > rd {
            var tmp: u8[16384] = [0; 16384];
            let k = conv - rd;
            tmp[..k].move_from(w.filter.buf[rd..conv]);
            w.filter.rd = conv;
            lze_take(w, tmp[..k], out);
        }
        if p == data.len { break; }
    }
}

// --- xz framing --------------------------------------------------------------------

fn xz_write_vli(out: u8[>..]&, v0: i64) {
    var v = v0 as! u64;
    while v >= 0x80 {
        out.push(((v & 0x7f) | 0x80) as! u8);
        v >>= 7;
    }
    out.push(v as! u8);
}

fn xz_index_vli(w: XzWriter&, v0: i64) {
    var v = v0 as! u64;
    while v >= 0x80 {
        w.index.push(((v & 0x7f) | 0x80) as! u8);
        v >>= 7;
    }
    w.index.push(v as! u8);
}

fn xz_write_stream_header(w: XzWriter&, out: u8[>..]&) {
    out.append(XZ_MAGIC);
    let flags: u8[2] = [0, (w.check & 15) as! u8];
    out.append(flags);
    put_le32(out, crc32(flags) as u64);
    w.header_done = true;
}

fn xz_start_block(w: XzWriter&, out: u8[>..]&) {
    var h: u8[>..] = [];
    h.push(0);
    h.push(if w.has_filter { 1 } else { 0 });
    if w.has_filter {
        let id = w.filter.id;
        h.push(id as! u8);
        if id == XZ_FILTER_DELTA {
            h.push(1);
            h.push((w.filter.delta_dist - 1) as! u8);
        } else if w.filter_start != 0 {
            h.push(4);
            put_le32(h, w.filter_start as u64);
        } else {
            h.push(0);
        }
        xz_stage_reset(w.filter, id, w.filter_start, w.filter.delta_dist);
    }
    h.push(0x21);
    h.push(1);
    h.push(lzma2_dict_byte(w.dict_size));
    while (h.len + 4) % 4 != 0 { h.push(0); }
    h[0] = ((h.len + 4) / 4 - 1) as! u8;
    let c = crc32(h);
    out.append(h);
    put_le32(out, c as u64);
    w.bh_len = h.len + 4;
    w.block_open = true;
    w.block_taken = 0;
    w.block_out = 0;
    w.crc32 = 0; w.crc64 = 0; w.sha = sha256_new();
    // Each block's LZMA2 starts afresh: nothing before it can be matched.
    w.need_props = true;
    w.need_dict_reset = true;
    w.need_state_reset = false;
    lze_reset_state(w);
    w.dstart = w.cur;
    w.chunk_start = w.cur;
}

fn xz_end_block(w: XzWriter&, out: u8[>..]&) {
    if w.has_filter { xz_feed(w, "", out, true); }
    lze_encode(w, out, true);
    lz2_end_chunk(w, out);
    out.push(0);
    w.block_out++;
    var padn = 0;
    while (w.block_out + padn) % 4 != 0 { out.push(0); padn++; }
    if w.check == XZ_CHECK_CRC32 { put_le32(out, w.crc32 as u64); }
    else if w.check == XZ_CHECK_CRC64 { put_le64(out, w.crc64); }
    else if w.check == XZ_CHECK_SHA256 { let h = sha256_final(w.sha); out.append(h); }
    xz_index_vli(w, w.bh_len + w.block_out + XZ_CHECK_SIZES[w.check]);
    xz_index_vli(w, w.block_taken);
    w.nrec++;
    w.block_open = false;
}

fn xz_check_input(w: XzWriter&, p: const u8[:]) {
    if w.check == XZ_CHECK_CRC32 { w.crc32 = crc32_update(w.crc32, p); }
    else if w.check == XZ_CHECK_CRC64 { w.crc64 = crc64_update(w.crc64, p); }
    else if w.check == XZ_CHECK_SHA256 { sha256_update(w.sha, p); }
}

fn alone_header(w: XzWriter&, out: u8[>..]&) {
    out.push(((w.pb * 5 + w.lp) * 9 + w.lc) as! u8);
    put_le32(out, w.dict_size as u64);
    put_le64(out, if w.alone_size < 0 { 0xffffffffffffffff } else { w.alone_size as! u64 });
    w.alone_header_done = true;
}

// Compresses data, appending what is ready to out: 0 or an error.
fn xz_write(w: XzWriter&, data: const u8[:], out: u8[>..]&) -> i64 {
    if w.err < 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    if w.mode == XW_ALONE {
        if !w.alone_header_done { alone_header(w, out); }
        w.total_in += data.len;
        if w.alone_size >= 0 && w.total_in > w.alone_size { w.err = ERR_ARGUMENT; return w.err; }
        lze_take(w, data, out);
        return 0;
    }
    if w.mode == XW_RAW {
        lze_take(w, data, out);
        return 0;
    }
    if !w.header_done { xz_write_stream_header(w, out); }
    var p = 0;
    while p < data.len {
        if !w.block_open { xz_start_block(w, out); }
        var n = data.len - p;
        if w.block_size > 0 && n > w.block_size - w.block_taken { n = w.block_size - w.block_taken; }
        let part = data[p..p + n];
        xz_check_input(w, part);
        w.block_taken += n;
        p += n;
        xz_feed(w, part, out, false);
        if w.block_size > 0 && w.block_taken == w.block_size { xz_end_block(w, out); }
    }
    return 0;
}

// Makes all input so far decodable from what is written (ends the
// current LZMA2 chunk; .xz and raw LZMA2 only, and a filter's few
// unconverted bytes wait for more input or the end).
fn xz_flush(w: XzWriter&, out: u8[>..]&) -> i64 {
    if w.err < 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    if w.mode == XW_ALONE { return ERR_UNSUPPORTED; }
    if w.mode == XW_XZ && !w.header_done { xz_write_stream_header(w, out); }
    w.flushing = true;
    lze_encode(w, out, true);
    w.flushing = false;
    lz2_end_chunk(w, out);
    return 0;
}

// Ends the stream: 0 or an error.
fn xz_close(w: XzWriter&, out: u8[>..]&) -> i64 {
    if w.err < 0 { return w.err; }
    if w.closed { return 0; }
    if w.mode == XW_ALONE {
        if !w.alone_header_done { alone_header(w, out); }
        if w.alone_size >= 0 && w.total_in != w.alone_size { w.err = ERR_ARGUMENT; return w.err; }
        lze_encode(w, out, true);
        if w.alone_size < 0 { lze_eopm(w, w.cur); }
        lze_flush_rc(w);
        out.append(w.obuf[..w.olen]);
        w.olen = 0;
        w.closed = true;
        return 0;
    }
    if w.mode == XW_RAW {
        lze_encode(w, out, true);
        lz2_end_chunk(w, out);
        out.push(0);
        w.closed = true;
        return 0;
    }
    if !w.header_done { xz_write_stream_header(w, out); }
    if w.block_open { xz_end_block(w, out); }
    // The index: indicator, count, records, padding, CRC-32.
    var ix: u8[>..] = [];
    ix.push(0);
    xz_write_vli(ix, w.nrec);
    for b in w.index { ix.push(b); }
    while ix.len % 4 != 0 { ix.push(0); }
    put_le32(ix, crc32(ix) as u64);
    out.append(ix);
    // The footer.
    var f: u8[>..] = [];
    put_le32(f, (ix.len / 4 - 1) as u64);
    f.push(0);
    f.push((w.check & 15) as! u8);
    put_le32(out, crc32(f) as u64);
    out.append(f);
    out.push('Y');
    out.push('Z');
    w.closed = true;
    return 0;
}

// Compresses a whole buffer as .xz (CRC-64), appending to out.
fn xz_encode(data: const u8[:], out: u8[>..]&, level: i64) -> i64 {
    var w = xz_writer_new(XW_XZ, level, data.len);
    let e = xz_write(w, data, out);
    if e < 0 { return e; }
    return xz_close(w, out);
}

// Compresses a whole buffer as .lzma (its size in the header).
fn lzma_encode(data: const u8[:], out: u8[>..]&, level: i64) -> i64 {
    var w = xz_writer_new(XW_ALONE, level, data.len);
    w.alone_size = data.len;
    let e = xz_write(w, data, out);
    if e < 0 { return e; }
    return xz_close(w, out);
}

// Compresses a whole buffer as raw LZMA2, appending to out; the
// dictionary size the reader needs is returned (or an error).
fn lzma2_encode(data: const u8[:], out: u8[>..]&, level: i64) -> i64 {
    var w = xz_writer_new(XW_RAW, level, data.len);
    let e = xz_write(w, data, out);
    if e < 0 { return e; }
    let c = xz_close(w, out);
    if c < 0 { return c; }
    return w.dict_size;
}

// --- Normal mode: prices and the optimal parse ----------------------------------

// liblzma's price of a bit, in 1/16 bits, by probability / 16.
fn lze_make_prices() -> u32[128] {
    var t: u32[128] = [0; 128];
    var i: u32 = 8;
    while i < 2048 {
        var w = i;
        var bits: u32 = 0;
        for j in 4 {
            w *= w;
            bits <<= 1;
            while w >= 65536 { w >>= 1; bits++; }
        }
        t[i >> 4] = (11 << 4) - 15 - bits;
        i += 16;
    }
    return t;
}

let LZE_PRICES: u32[128] = lze_make_prices();

let LZE_INFINITY: u32 = 1 << 30;

fn lze_p0(w: const XzWriter&, i: i64) -> u32 { LZE_PRICES[w.p[i] >> 4] }
fn lze_p1(w: const XzWriter&, i: i64) -> u32 { LZE_PRICES[(w.p[i] ^ 0x7ff) >> 4] }
fn lze_pb(w: const XzWriter&, i: i64, bit: u32) -> u32 { if bit == 0 { lze_p0(w, i) } else { lze_p1(w, i) } }

fn lze_tree_price(w: const XzWriter&, base: i64, bits: i64, v: u32) -> u32 {
    var price: u32 = 0;
    var m: u32 = 1;
    var k = bits - 1;
    while k >= 0 {
        let b = (v >> (k as! u32)) & 1;
        price += lze_pb(w, base + (m as i64), b);
        m = (m << 1) | b;
        k--;
    }
    return price;
}

fn lze_tree_rev_price(w: const XzWriter&, base: i64, bits: i64, v0: u32) -> u32 {
    var price: u32 = 0;
    var m: u32 = 1;
    var v = v0;
    for k in bits {
        let b = v & 1;
        v >>= 1;
        price += lze_pb(w, base + (m as i64), b);
        m = (m << 1) | b;
    }
    return price;
}

fn lze_lit_base(w: const XzWriter&, pos: i64) -> i64 {
    let rel = pos - w.dstart;
    let prev: u32 = if rel > 0 { lze_byte(w, pos - 1) } else { 0 };
    let ls = ((rel & ((1 << (w.lp as! u64)) - 1)) << (w.lc as! u64)) + ((prev >> ((8 - w.lc) as! u32)) as i64);
    return LZ_LITERAL + 0x300 * ls;
}

fn lze_lit_price(w: const XzWriter&, pos: i64, matched: bool, mbyte: u8) -> u32 {
    let base = lze_lit_base(w, pos);
    var sym = (lze_byte(w, pos) as u32) | 0x100;
    var price: u32 = 0;
    if !matched {
        while sym < 0x10000 {
            price += lze_pb(w, base + ((sym >> 8) as i64), (sym >> 7) & 1);
            sym <<= 1;
        }
    } else {
        var mb = mbyte as u32;
        var offs: u32 = 0x100;
        while sym < 0x10000 {
            mb <<= 1;
            price += lze_pb(w, base + ((offs + (mb & offs) + (sym >> 8)) as i64), (sym >> 7) & 1);
            sym <<= 1;
            offs &= ~(mb ^ sym);
        }
    }
    return price;
}

fn lze_len_price(w: const XzWriter&, rep: bool, ps: i64, len: i64) -> u32 {
    w.len_prices[(if rep { 4352 } else { 0 }) + ps * 272 + len - 2]
}

fn lze_fill_len_prices(w: XzWriter&) {
    for r in 2 {
        let base = if r == 0 { LZ_LEN_MATCH } else { LZ_LEN_REP };
        let c0 = lze_p0(w, base + LZ_LEN_CHOICE);
        let c1 = lze_p1(w, base + LZ_LEN_CHOICE);
        let c10 = c1 + lze_p0(w, base + LZ_LEN_CHOICE2);
        let c11 = c1 + lze_p1(w, base + LZ_LEN_CHOICE2);
        for ps in 1 << (w.pb as! u64) {
            let at = r * 4352 + ps * 272;
            for l in 272 {
                var price: u32 = 0;
                if l < 8 { price = c0 + lze_tree_price(w, base + LZ_LEN_LOW + ps * 8, 3, l as! u32); }
                else if l < 16 { price = c10 + lze_tree_price(w, base + LZ_LEN_MID + ps * 8, 3, (l - 8) as! u32); }
                else { price = c11 + lze_tree_price(w, base + LZ_LEN_HIGH, 8, (l - 16) as! u32); }
                w.len_prices[at + l] = price;
            }
        }
    }
}

fn lze_fill_dist_prices(w: XzWriter&) {
    for ls in 4 {
        for slot in 64 {
            var price = lze_tree_price(w, LZ_DIST_SLOT + ls * 64, 6, slot as! u32);
            if slot >= 14 { price += ((((slot >> 1) - 1 - 4) as! u32) << 4); }
            w.slot_prices[ls * 64 + slot] = price;
        }
        for d in 128 {
            var price: u32 = 0;
            if d < 4 {
                price = w.slot_prices[ls * 64 + d];
            } else {
                let slot = lze_dist_slot(d as! u32);
                let footer = (slot >> 1) - 1;
                let base = (2 | (slot & 1)) << footer;
                price = w.slot_prices[ls * 64 + (slot as i64)]
                      + lze_tree_rev_price(w, LZ_DIST_SPECIAL + (base as i64) - (slot as i64) - 1, footer as i64, (d as! u32) - base);
            }
            w.dist_prices[ls * 128 + d] = price;
        }
    }
    for k in 16 { w.align_prices[k] = lze_tree_rev_price(w, LZ_DIST_ALIGN, 4, k as! u32); }
}

fn lze_match_price(w: const XzWriter&, dist: u32, len: i64) -> u32 {
    let ls = if len - 2 < 3 { len - 2 } else { 3 };
    if dist < 128 { return w.dist_prices[ls * 128 + (dist as i64)]; }
    return w.slot_prices[ls * 64 + (lze_dist_slot(dist) as i64)] + w.align_prices[dist & 15];
}

fn lze_rep1_price(w: const XzWriter&, st: i64, ps: i64) -> u32 {
    lze_p0(w, LZ_IS_REP0 + st) + lze_p0(w, LZ_IS_REP0_LONG + (st << 4) + ps)
}

fn lze_pure_rep_price(w: const XzWriter&, rep: i64, st: i64, ps: i64) -> u32 {
    if rep == 0 { return lze_p0(w, LZ_IS_REP0 + st) + lze_p1(w, LZ_IS_REP0_LONG + (st << 4) + ps); }
    var price = lze_p1(w, LZ_IS_REP0 + st);
    if rep == 1 { price += lze_p0(w, LZ_IS_REP1 + st); }
    else { price += lze_p1(w, LZ_IS_REP1 + st) + lze_pb(w, LZ_IS_REP2 + st, (rep - 2) as! u32); }
    return price;
}

fn lze_rep_price(w: const XzWriter&, rep: i64, len: i64, st: i64, ps: i64) -> u32 {
    lze_len_price(w, true, ps, len) + lze_pure_rep_price(w, rep, st, ps)
}

fn lze_next_lit(s: i64) -> i64 { if s < 4 { 0 } else if s < 10 { s - 3 } else { s - 6 } }
fn lze_next_match(s: i64) -> i64 { if s < 7 { 7 } else { 10 } }
fn lze_next_rep(s: i64) -> i64 { if s < 7 { 8 } else { 11 } }
fn lze_next_short(s: i64) -> i64 { if s < 7 { 9 } else { 11 } }

fn lze_ps(w: const XzWriter&, pos: i64) -> i64 { (pos - w.dstart) & ((1 << (w.pb as! u64)) - 1) }

fn lze_set_lit(o: LzOpt&) { o.back_prev = -1; o.prev1_lit = false; }

fn lze_backward(w: XzWriter&, cur0: i64) -> i64, i64 {
    var cur = cur0;
    var pos_mem = w.opts[cur].pos_prev;
    var back_mem = w.opts[cur].back_prev;
    w.opt_end = cur;
    while true {
        if w.opts[cur].prev1_lit {
            lze_set_lit(w.opts[pos_mem]);
            w.opts[pos_mem].pos_prev = pos_mem - 1;
            if w.opts[cur].prev2 {
                w.opts[pos_mem - 1].prev1_lit = false;
                w.opts[pos_mem - 1].pos_prev = w.opts[cur].pos_prev2;
                w.opts[pos_mem - 1].back_prev = w.opts[cur].back_prev2;
            }
        }
        let pos_prev = pos_mem;
        let back_cur = back_mem;
        back_mem = w.opts[pos_prev].back_prev;
        pos_mem = w.opts[pos_prev].pos_prev;
        w.opts[pos_prev].back_prev = back_cur;
        w.opts[pos_prev].pos_prev = cur;
        cur = pos_prev;
        if cur == 0 { break; }
    }
    w.opt_cur = w.opts[0].pos_prev;
    return w.opts[0].back_prev, w.opt_cur;
}

// The matches of the read-ahead position as found (count, longest).
fn lze_read_matches(w: XzWriter&) -> i64 {
    lze_find(w);
    return if w.nmatch > 0 { w.matches[w.nmatch - 1].len } else { 0 };
}

fn lze_bytes_eq(w: const XzWriter&, a: i64, b: i64) -> bool { w.win[a - w.base] == w.win[b - w.base] }

// The next symbol at w.cur by the optimal parse: (back, len) as lze_choose.
fn lze_optimum(w: XzWriter&) -> i64, i64 {
    if w.opt_end != w.opt_cur {
        let i = w.opt_cur;
        let len = w.opts[i].pos_prev - i;
        let back = w.opts[i].back_prev;
        w.opt_cur = w.opts[i].pos_prev;
        return back, len;
    }
    w.opt_cur = 0;
    w.opt_end = 0;
    if w.price_count >= 128 {
        lze_fill_len_prices(w);
        lze_fill_dist_prices(w);
        w.price_count = 0;
    }
    let start = w.cur;
    let nice = w.nice;
    var main_len: i64 = 0;
    if w.mfpos == start { main_len = lze_read_matches(w); } else { main_len = w.longest; }
    var npairs = w.nmatch;
    var avail = w.wend - start;
    if avail < 2 { return -1, 1; }
    if avail > LZE_MAXMATCH { avail = LZE_MAXMATCH; }
    var reps: u32[4] = w.reps;
    var rep_lens: i64[4] = [0; 4];
    var rep_max = 0;
    for r in 4 {
        let back = start - (reps[r] as i64) - 1;
        if back < w.dstart || !lze_bytes_eq(w, back, start) || !lze_bytes_eq(w, back + 1, start + 1) { continue; }
        rep_lens[r] = lze_matchlen(w, back, start, 2, avail);
        if rep_lens[r] > rep_lens[rep_max] { rep_max = r; }
    }
    if rep_lens[rep_max] >= nice {
        lze_skip(w, rep_lens[rep_max] - 1);
        return rep_max, rep_lens[rep_max];
    }
    if main_len >= nice {
        lze_skip(w, main_len - 1);
        return 4 + (w.matches[npairs - 1].dist as i64), main_len;
    }
    let cur_byte = lze_byte(w, start);
    let mb_at = start - (reps[0] as i64) - 1;
    let match_byte: u8 = if mb_at >= w.dstart { lze_byte(w, mb_at) } else { 0 };
    if main_len < 2 && cur_byte != match_byte && rep_lens[rep_max] < 2 { return -1, 1; }
    let st0 = w.state;
    w.opts[0].state = st0;
    let ps0 = lze_ps(w, start);
    w.opts[1].price = lze_p0(w, LZ_IS_MATCH + (st0 << 4) + ps0) + lze_lit_price(w, start, st0 >= 7, match_byte);
    lze_set_lit(w.opts[1]);
    let match_price = lze_p1(w, LZ_IS_MATCH + (st0 << 4) + ps0);
    let rep_match_price = match_price + lze_p1(w, LZ_IS_REP + st0);
    if match_byte == cur_byte && mb_at >= w.dstart {
        let short_price = rep_match_price + lze_rep1_price(w, st0, ps0);
        if short_price < w.opts[1].price {
            w.opts[1].price = short_price;
            w.opts[1].back_prev = 0;
            w.opts[1].prev1_lit = false;
        }
    }
    var len_end = if main_len > rep_lens[rep_max] { main_len } else { rep_lens[rep_max] };
    if len_end < 2 { return w.opts[1].back_prev, 1; }
    w.opts[1].pos_prev = 0;
    w.opts[0].backs = reps;
    var l = len_end;
    while l >= 2 { w.opts[l].price = LZE_INFINITY; l--; }
    for r in 4 {
        var rl = rep_lens[r];
        if rl < 2 { continue; }
        let price = rep_match_price + lze_pure_rep_price(w, r, st0, ps0);
        while rl >= 2 {
            let p = price + lze_len_price(w, true, ps0, rl);
            if p < w.opts[rl].price {
                w.opts[rl].price = p;
                w.opts[rl].pos_prev = 0;
                w.opts[rl].back_prev = r;
                w.opts[rl].prev1_lit = false;
            }
            rl--;
        }
    }
    let normal_price = match_price + lze_p0(w, LZ_IS_REP + st0);
    l = if rep_lens[0] >= 2 { rep_lens[0] + 1 } else { 2 };
    if l <= main_len {
        var offs = 0;
        while l > w.matches[offs].len { offs++; }
        while true {
            let dist = w.matches[offs].dist;
            let p = normal_price + lze_len_price(w, false, ps0, l) + lze_match_price(w, dist, l);
            if p < w.opts[l].price {
                w.opts[l].price = p;
                w.opts[l].pos_prev = 0;
                w.opts[l].back_prev = (dist as i64) + 4;
                w.opts[l].prev1_lit = false;
            }
            if l == w.matches[offs].len {
                offs++;
                if offs == npairs { break; }
            }
            l++;
        }
    }
    var cur: i64 = 0;
    while true {
        cur++;
        if cur == len_end { return lze_backward(w, cur); }
        var new_len = lze_read_matches(w);
        npairs = w.nmatch;
        if new_len >= nice {
            w.longest = new_len;
            return lze_backward(w, cur);
        }
        let position = start + cur;
        var pos_prev = w.opts[cur].pos_prev;
        var state: i64 = 0;
        if w.opts[cur].prev1_lit {
            pos_prev--;
            if w.opts[cur].prev2 {
                state = w.opts[w.opts[cur].pos_prev2].state;
                state = if w.opts[cur].back_prev2 < 4 { lze_next_rep(state) } else { lze_next_match(state) };
            } else {
                state = w.opts[pos_prev].state;
            }
            state = lze_next_lit(state);
        } else {
            state = w.opts[pos_prev].state;
        }
        if pos_prev == cur - 1 {
            if w.opts[cur].back_prev == 0 && !w.opts[cur].prev1_lit { state = lze_next_short(state); }
            else { state = lze_next_lit(state); }
        } else {
            var pos: i64 = 0;
            if w.opts[cur].prev1_lit && w.opts[cur].prev2 {
                pos_prev = w.opts[cur].pos_prev2;
                pos = w.opts[cur].back_prev2;
                state = lze_next_rep(state);
            } else {
                pos = w.opts[cur].back_prev;
                state = if pos < 4 { lze_next_rep(state) } else { lze_next_match(state) };
            }
            let pb = w.opts[pos_prev].backs;
            if pos < 4 {
                reps[0] = pb[pos];
                var i = 1;
                while i <= pos { reps[i] = pb[i - 1]; i++; }
                while i < 4 { reps[i] = pb[i]; i++; }
            } else {
                reps[0] = (pos - 4) as! u32;
                for i in 1..4 { reps[i] = pb[i - 1]; }
            }
        }
        w.opts[cur].state = state;
        w.opts[cur].backs = reps;
        let cur_price = w.opts[cur].price;
        var next_is_lit = false;
        let cb = lze_byte(w, position);
        let mpos = position - (reps[0] as i64) - 1;
        let mbyte: u8 = if mpos >= w.dstart { lze_byte(w, mpos) } else { 0 };
        let ps = lze_ps(w, position);
        let cur_and1 = cur_price + lze_p0(w, LZ_IS_MATCH + (state << 4) + ps) + lze_lit_price(w, position, state >= 7, mbyte);
        if cur_and1 < w.opts[cur + 1].price {
            w.opts[cur + 1].price = cur_and1;
            w.opts[cur + 1].pos_prev = cur;
            lze_set_lit(w.opts[cur + 1]);
            next_is_lit = true;
        }
        let mprice = cur_price + lze_p1(w, LZ_IS_MATCH + (state << 4) + ps);
        let rmprice = mprice + lze_p1(w, LZ_IS_REP + state);
        if mbyte == cb && mpos >= w.dstart && !(w.opts[cur + 1].pos_prev < cur && w.opts[cur + 1].back_prev == 0) {
            let sp = rmprice + lze_rep1_price(w, state, ps);
            if sp <= w.opts[cur + 1].price {
                w.opts[cur + 1].price = sp;
                w.opts[cur + 1].pos_prev = cur;
                w.opts[cur + 1].back_prev = 0;
                w.opts[cur + 1].prev1_lit = false;
                next_is_lit = true;
            }
        }
        var avail_full = w.wend - position;
        if avail_full > 4095 - cur { avail_full = 4095 - cur; }
        if avail_full < 2 { continue; }
        let navail = if avail_full <= nice { avail_full } else { nice };
        if !next_is_lit && mbyte != cb && mpos >= w.dstart {
            // A literal, then rep0.
            var lim = nice + 1;
            if lim > avail_full { lim = avail_full; }
            var t = 1;
            while t < lim && lze_bytes_eq(w, position + t, mpos + t) { t++; }
            let lt2 = t - 1;
            if lt2 >= 2 {
                let st2 = lze_next_lit(state);
                let psn = lze_ps(w, position + 1);
                let nrp = cur_and1 + lze_p1(w, LZ_IS_MATCH + (st2 << 4) + psn) + lze_p1(w, LZ_IS_REP + st2);
                let offset = cur + 1 + lt2;
                while len_end < offset { len_end++; w.opts[len_end].price = LZE_INFINITY; }
                let p = nrp + lze_rep_price(w, 0, lt2, st2, psn);
                if p < w.opts[offset].price {
                    w.opts[offset].price = p;
                    w.opts[offset].pos_prev = cur + 1;
                    w.opts[offset].back_prev = 0;
                    w.opts[offset].prev1_lit = true;
                    w.opts[offset].prev2 = false;
                }
            }
        }
        var start_len: i64 = 2;
        for ri in 4 {
            let d2 = position - (reps[ri] as i64) - 1;
            if d2 < w.dstart { continue; }
            if !lze_bytes_eq(w, position, d2) || !lze_bytes_eq(w, position + 1, d2 + 1) { continue; }
            var lt = 2;
            while lt < navail && lze_bytes_eq(w, position + lt, d2 + lt) { lt++; }
            while len_end < cur + lt { len_end++; w.opts[len_end].price = LZE_INFINITY; }
            let lt_keep = lt;
            let price = rmprice + lze_pure_rep_price(w, ri, state, ps);
            while lt >= 2 {
                let p = price + lze_len_price(w, true, ps, lt);
                if p < w.opts[cur + lt].price {
                    w.opts[cur + lt].price = p;
                    w.opts[cur + lt].pos_prev = cur;
                    w.opts[cur + lt].back_prev = ri;
                    w.opts[cur + lt].prev1_lit = false;
                }
                lt--;
            }
            lt = lt_keep;
            if ri == 0 { start_len = lt + 1; }
            // rep, a literal, rep0.
            var lt2 = lt + 1;
            var lim = lt2 + nice;
            if lim > avail_full { lim = avail_full; }
            while lt2 < lim && lze_bytes_eq(w, position + lt2, d2 + lt2) { lt2++; }
            lt2 -= lt + 1;
            if lt2 >= 2 {
                var st2 = lze_next_rep(state);
                var psn = lze_ps(w, position + lt);
                let clp = price + lze_len_price(w, true, ps, lt) + lze_p0(w, LZ_IS_MATCH + (st2 << 4) + psn)
                        + lze_lit_price(w, position + lt, true, lze_byte(w, d2 + lt));
                st2 = lze_next_lit(st2);
                psn = lze_ps(w, position + lt + 1);
                let nrp = clp + lze_p1(w, LZ_IS_MATCH + (st2 << 4) + psn) + lze_p1(w, LZ_IS_REP + st2);
                let offset = cur + lt + 1 + lt2;
                while len_end < offset { len_end++; w.opts[len_end].price = LZE_INFINITY; }
                let p = nrp + lze_rep_price(w, 0, lt2, st2, psn);
                if p < w.opts[offset].price {
                    w.opts[offset].price = p;
                    w.opts[offset].pos_prev = cur + lt + 1;
                    w.opts[offset].back_prev = 0;
                    w.opts[offset].prev1_lit = true;
                    w.opts[offset].prev2 = true;
                    w.opts[offset].pos_prev2 = cur;
                    w.opts[offset].back_prev2 = ri;
                }
            }
        }
        if new_len > navail {
            new_len = navail;
            npairs = 0;
            while new_len > w.matches[npairs].len { npairs++; }
            w.matches[npairs].len = new_len;
            npairs++;
        }
        if new_len >= start_len {
            let nmp = mprice + lze_p0(w, LZ_IS_REP + state);
            while len_end < cur + new_len { len_end++; w.opts[len_end].price = LZE_INFINITY; }
            var offs = 0;
            while start_len > w.matches[offs].len { offs++; }
            var cur_back = w.matches[offs].dist;
            var lt = start_len;
            while true {
                var p = nmp + lze_len_price(w, false, ps, lt) + lze_match_price(w, cur_back, lt);
                if p < w.opts[cur + lt].price {
                    w.opts[cur + lt].price = p;
                    w.opts[cur + lt].pos_prev = cur;
                    w.opts[cur + lt].back_prev = (cur_back as i64) + 4;
                    w.opts[cur + lt].prev1_lit = false;
                }
                if lt == w.matches[offs].len {
                    // A match, a literal, rep0.
                    let d2 = position - (cur_back as i64) - 1;
                    var lt2 = lt + 1;
                    var lim = lt2 + nice;
                    if lim > avail_full { lim = avail_full; }
                    while lt2 < lim && lze_bytes_eq(w, position + lt2, d2 + lt2) { lt2++; }
                    lt2 -= lt + 1;
                    if lt2 >= 2 {
                        var st2 = lze_next_match(state);
                        var psn = lze_ps(w, position + lt);
                        let clp = p + lze_p0(w, LZ_IS_MATCH + (st2 << 4) + psn)
                                + lze_lit_price(w, position + lt, true, lze_byte(w, d2 + lt));
                        st2 = lze_next_lit(st2);
                        psn = lze_ps(w, position + lt + 1);
                        let nrp = clp + lze_p1(w, LZ_IS_MATCH + (st2 << 4) + psn) + lze_p1(w, LZ_IS_REP + st2);
                        let offset = cur + lt + 1 + lt2;
                        while len_end < offset { len_end++; w.opts[len_end].price = LZE_INFINITY; }
                        p = nrp + lze_rep_price(w, 0, lt2, st2, psn);
                        if p < w.opts[offset].price {
                            w.opts[offset].price = p;
                            w.opts[offset].pos_prev = cur + lt + 1;
                            w.opts[offset].back_prev = 0;
                            w.opts[offset].prev1_lit = true;
                            w.opts[offset].prev2 = true;
                            w.opts[offset].pos_prev2 = cur;
                            w.opts[offset].back_prev2 = (cur_back as i64) + 4;
                        }
                    }
                    offs++;
                    if offs == npairs { break; }
                    cur_back = w.matches[offs].dist;
                }
                lt++;
            }
        }
    }
    return -1, 1;
}
