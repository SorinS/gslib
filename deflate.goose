// compress.deflate: DEFLATE compression (RFC 1951), with the levels and
// calls of Go's compress/flate Writer.
//
//   var w = compress::deflate_writer(6);       // -2 HuffmanOnly, -1 default (6), 0 stored .. 9
//   compress::deflate_write(w, data, out);     // appends compressed bytes to out
//   compress::deflate_flush(w, out);           // Go's Flush: a sync point, 00 00 ff ff
//   compress::deflate_close(w, out);           // the last block
//
// A writer is of fixed size (about 450 KB) and appends to a builder the
// caller owns. The matcher is zlib's: a 64 KiB window over which 3-byte
// hash chains are searched, greedy for levels 1-3 and lazy for 4-9, with
// zlib's limits for each level (good, lazy, nice, chain); level 0 writes
// stored blocks and HuffmanOnly literals only. Tokens are gathered in
// blocks of up to 16383, and each block is written stored, with the fixed
// codes or with its own codes, whichever is smallest. Huffman codes are
// optimal (Moffat and Katajainen's in-place algorithm), then limited to 15
// bits (7 for the code length code) by moving codes down the lengths until
// the Kraft sum is one again, as miniz does; every code written is
// complete. The exact bytes are not Go's (Go makes no promise about them
// either): scripts/deflate_differential.py compares sizes with Go's level
// for level.

namespace compress;

import std;
import .flate;

// --- Bits ------------------------------------------------------------------

struct BitWriter { bits: u64, n: i64 }

fn bit_writer() -> BitWriter { BitWriter { bits: 0, n: 0 } }

// Writes the low n bits of v (n <= 32), least significant first.
fn bw_bits(w: BitWriter&, out: u8[>..]&, v: u64, n: i64) {
    w.bits |= v << w.n;
    w.n += n;
    while w.n >= 8 {
        out.push((w.bits & 0xff) as! u8);
        w.bits >>= 8;
        w.n -= 8;
    }
}

// Pads to a byte boundary with zero bits.
fn bw_flush(w: BitWriter&, out: u8[>..]&) {
    if w.n > 0 {
        out.push((w.bits & 0xff) as! u8);
        w.bits = 0;
        w.n = 0;
    }
}

// --- Parameters ------------------------------------------------------------

let HUFFMAN_ONLY: i64 = -2;
let DEFAULT_COMPRESSION: i64 = -1;
let NO_COMPRESSION: i64 = 0;
let BEST_SPEED: i64 = 1;
let BEST_COMPRESSION: i64 = 9;

let DF_WSIZE: i64 = 32768;
let DF_WINDOW: i64 = 65536;
let DF_MIN_MATCH: i64 = 3;
let DF_MAX_MATCH: i64 = 258;
let DF_MIN_LOOKAHEAD: i64 = 262;                // DF_MAX_MATCH + DF_MIN_MATCH + 1
let DF_MAX_DIST: i64 = 32506;                   // DF_WSIZE - DF_MIN_LOOKAHEAD
let DF_TOO_FAR: i64 = 4096;
let DF_HASH_BITS: i64 = 15;
let DF_HASH_SIZE: i64 = 32768;
let DF_TOKENS: i64 = 16383;                     // a block's tokens at most
let DF_NIL: i32 = -1;

// zlib's configuration table: good, lazy, nice, chain; levels 1-3 greedy.
let DF_GOOD: i64[10] = [0, 4, 4, 4, 4, 8, 8, 8, 32, 32];
let DF_LAZY: i64[10] = [0, 4, 5, 6, 4, 16, 16, 32, 128, 258];
let DF_NICE: i64[10] = [0, 8, 16, 32, 16, 32, 128, 128, 258, 258];
let DF_CHAIN: i64[10] = [0, 4, 8, 32, 16, 32, 128, 256, 1024, 4096];

// Writer states.
let DW_OPEN: u8 = 0;
let DW_CLOSED: u8 = 1;
let DW_FAILED: u8 = 2;

// The length code (0-28) of each match length - 3, and the distance code
// of each distance - 1 (the first 256), then of (distance - 1) >> 7.
fn df_make_len_code() -> u8[256] {
    var t: u8[256] = [0; 256];
    for code in 29 {
        let base = LEN_BASE[code] as i64 - 3;
        let n = 1 << (LEN_EXTRA[code]);
        for k in n {
            if base + k < 256 { t[base + k] = code as! u8; }
        }
    }
    t[255] = 28;
    return t;
}

fn df_make_dist_code() -> u8[512] {
    var t: u8[512] = [0; 512];
    for code in 30 {
        let base = DIST_BASE[code] as i64 - 1;
        let n = 1 << (DIST_EXTRA[code]);
        for k in n {
            let d = base + k;
            if d < 256 { t[d] = code as! u8; } else { t[256 + (d >> 7)] = code as! u8; }
        }
    }
    return t;
}

let DF_LEN_CODE: u8[256] = df_make_len_code();
let DF_DIST_CODE: u8[512] = df_make_dist_code();

fn df_dist_code(dist: i64) -> i64 {
    let d = dist - 1;
    if d < 256 { DF_DIST_CODE[d] } else { DF_DIST_CODE[256 + (d >> 7)] }
}

// --- The writer ------------------------------------------------------------

struct Deflate {
    level: i64,
    good: i64, lazy: i64, nice: i64, chain: i64,
    state: u8,
    err: i64,
    bw: BitWriter,
    // The window: [0, strstart) is history, [strstart, strstart +
    // lookahead) input not yet matched; block_start is where the block
    // being gathered starts (< 0 once it slid out: it cannot be stored).
    strstart: i64, lookahead: i64, block_start: i64, block_bytes: i64,
    match_length: i64, match_start: i64, prev_length: i64, prev_match: i64,
    match_available: bool,
    total_in: i64,
    ntok: i64,
    lit_freq: i64[286], dist_freq: i64[30],
    tokens: u32[16384],          // a literal, or 1 << 31 | (distance - 1) << 8 | (length - 3)
    head: i32[32768],
    prev: i32[32768],
    window: u8[65536],
}

// A writer at a level from -2 (HuffmanOnly) to 9, -1 the default (6). A
// level out of range gives a writer that refuses everything with
// ERR_ARGUMENT (Go's NewWriter returns an error).
fn deflate_writer(level: i64) -> Deflate {
    var w = Deflate {
        level: level, good: 0, lazy: 0, nice: 0, chain: 0, state: DW_OPEN, err: 0, bw: bit_writer(),
        strstart: 0, lookahead: 0, block_start: 0, block_bytes: 0,
        match_length: 2, match_start: 0, prev_length: 2, prev_match: 0, match_available: false,
        total_in: 0, ntok: 0, lit_freq: [0; 286], dist_freq: [0; 30], tokens: [0; 16384],
        head: [-1; 32768], prev: [-1; 32768], window: [0; 65536],
    };
    deflate_set_level(w, level);
    return w;
}

fn deflate_set_level(w: Deflate&, level: i64) {
    var l = level;
    if l == DEFAULT_COMPRESSION { l = 6; }
    if l < HUFFMAN_ONLY || l > 9 {
        w.err = ERR_ARGUMENT;
        w.state = DW_FAILED;
        return;
    }
    w.level = l;
    if l >= 1 {
        w.good = DF_GOOD[l];
        w.lazy = DF_LAZY[l];
        w.nice = DF_NICE[l];
        w.chain = DF_CHAIN[l];
    }
}

// A writer whose stream starts with a preset dictionary: matches may
// reach into its last 32 KiB, and none of it is written (Go's
// NewWriterDict).
fn deflate_writer_dict(level: i64, dict: const u8[:]) -> Deflate {
    var w = deflate_writer(level);
    deflate_set_dict(w, dict);
    return w;
}

fn deflate_set_dict(w: Deflate&, dict: const u8[:]) {
    if w.state != DW_OPEN || w.level <= 0 { return; }
    let n = min(dict.len, DF_WSIZE);
    let d = dict[dict.len - n..];
    w.window[..n].move_from(d);
    for k in n {
        if k + 3 <= n { df_insert(w, k); }
    }
    w.strstart = n;
    w.block_start = n;
}

// Starts a new stream at the same level, as Go's Writer.Reset.
fn deflate_reset(w: Deflate&) {
    let level = w.level;
    w.state = DW_OPEN;
    w.err = 0;
    w.bw = bit_writer();
    w.strstart = 0;
    w.lookahead = 0;
    w.block_start = 0;
    w.block_bytes = 0;
    w.match_length = 2;
    w.prev_length = 2;
    w.match_available = false;
    w.total_in = 0;
    w.ntok = 0;
    for k in 286 { w.lit_freq[k] = 0; }
    for k in 30 { w.dist_freq[k] = 0; }
    for k in DF_HASH_SIZE { w.head[k] = DF_NIL; }
    deflate_set_level(w, level);
}

// --- Matching --------------------------------------------------------------

fn df_hash(w: const Deflate&, p: i64) -> i64 {
    let v = (w.window[p] as u32) << 16 | (w.window[p + 1] as u32) << 8 | w.window[p + 2];
    return ((v * 2654435761) >> (32 - 15));
}

// Inserts the string at p into its hash chain: the previous head.
fn df_insert(w: Deflate&, p: i64) -> i64 {
    let h = df_hash(w, p);
    let old = w.head[h] as i64;
    w.prev[p & (DF_WSIZE - 1)] = old as! i32;
    w.head[h] = p as! i32;
    return old;
}

// The longest match at strstart along the chain from cur (zlib's
// longest_match): its length (at most lookahead), with match_start set.
fn df_longest_match(w: Deflate&, cur_match: i64) -> i64 {
    var chain = w.chain;
    let scan = w.strstart;
    var best_len = w.prev_length;
    var nice = w.nice;
    let limit = if w.strstart > DF_MAX_DIST { w.strstart - DF_MAX_DIST } else { 0 };
    let maxlen = min(DF_MAX_MATCH, w.lookahead);
    if w.prev_length >= w.good { chain >>= 2; }
    if nice > w.lookahead { nice = w.lookahead; }
    if best_len >= maxlen { return maxlen; }
    let win = w.window[..];
    let b = win[scan..scan + maxlen];
    var cur = cur_match;
    loop {
        // The candidate must at least beat best_len: its byte there
        // and its first two first.
        let a = win[cur..cur + maxlen];
        assert(a.len == b.len && best_len < a.len && a.len >= 2);
        if a[best_len] == b[best_len] && a[0] == b[0] && a[1] == b[1] {
            var len: i64 = 2;
            while len < a.len && a[len] == b[len] { len++; }
            if len > best_len {
                w.match_start = cur;
                best_len = len;
                if len >= nice { break; }
            }
        }
        let next = w.prev[cur & (DF_WSIZE - 1)] as i64;
        chain--;
        if next < limit || next < 0 || chain == 0 { break; }
        cur = next;
    }
    return min(best_len, w.lookahead);
}

// Moves the upper half of the window down when the lookahead runs into
// the end, and takes input into it: the bytes of input taken.
fn df_fill(w: Deflate&, input: const u8[:]) -> i64 {
    if w.strstart >= DF_WSIZE + DF_MAX_DIST {
        w.window[..DF_WSIZE].move_from(w.window[DF_WSIZE..]);
        w.match_start -= DF_WSIZE;
        w.strstart -= DF_WSIZE;
        w.block_start -= DF_WSIZE;
        for k in DF_HASH_SIZE {
            let v = w.head[k] - DF_WSIZE;
            w.head[k] = if v < 0 { DF_NIL } else { v as! i32 };
        }
        for k in DF_WSIZE {
            let v = w.prev[k] - DF_WSIZE;
            w.prev[k] = if v < 0 { DF_NIL } else { v as! i32 };
        }
    }
    let at = w.strstart + w.lookahead;
    let n = min(DF_WINDOW - at, input.len);
    if n > 0 {
        w.window[at..at + n].move_from(input[..n]);
        w.lookahead += n;
    }
    return n;
}

fn df_lit(w: Deflate&, c: u8) {
    w.tokens[w.ntok] = c;
    w.ntok++;
    w.lit_freq[c]++;
    w.block_bytes++;
}

fn df_match(w: Deflate&, dist: i64, len: i64) {
    w.tokens[w.ntok] = (1 << 31 | (dist - 1) << 8 | (len - 3)) as! u32;
    w.ntok++;
    w.lit_freq[257 + (DF_LEN_CODE[len - 3] as i64)]++;
    w.dist_freq[df_dist_code(dist)]++;
    w.block_bytes += len;
}

// Matches what the window holds: with `flush`, to the end of the input
// taken; otherwise while the lookahead is long enough for the longest
// match. Writes a block whenever the token buffer fills.
fn df_compress(w: Deflate&, out: u8[>..]&, flush: bool) {
    let lazy_mode = w.level >= 4;
    loop {
        if w.lookahead < DF_MIN_LOOKAHEAD && !flush { return; }
        if w.lookahead == 0 { break; }
        if w.level == HUFFMAN_ONLY {
            df_lit(w, w.window[w.strstart]);
            w.strstart++;
            w.lookahead--;
            if w.ntok >= DF_TOKENS { df_block(w, out, false); }
            continue;
        }
        var hash_head: i64 = -1;
        if w.lookahead >= DF_MIN_MATCH { hash_head = df_insert(w, w.strstart); }
        if !lazy_mode {
            w.match_length = 2;
            if hash_head >= 0 && w.strstart - hash_head <= DF_MAX_DIST {
                w.prev_length = 2;
                w.match_length = df_longest_match(w, hash_head);
            }
            if w.match_length >= DF_MIN_MATCH {
                df_match(w, w.strstart - w.match_start, w.match_length);
                w.lookahead -= w.match_length;
                if w.match_length <= w.lazy && w.lookahead >= DF_MIN_MATCH {
                    // Insert the strings the match covers.
                    for m in w.match_length - 1 {
                        w.strstart++;
                        df_insert(w, w.strstart);
                    }
                    w.strstart++;
                } else {
                    w.strstart += w.match_length;
                }
                w.match_length = 2;
            } else {
                df_lit(w, w.window[w.strstart]);
                w.lookahead--;
                w.strstart++;
            }
            if w.ntok >= DF_TOKENS { df_block(w, out, false); }
            continue;
        }
        // Lazy: a match is taken only if the next position has none longer.
        w.prev_length = w.match_length;
        w.prev_match = w.match_start;
        w.match_length = 2;
        if hash_head >= 0 && w.prev_length < w.lazy && w.strstart - hash_head <= DF_MAX_DIST {
            w.match_length = df_longest_match(w, hash_head);
            if w.match_length <= 5 && w.match_length == DF_MIN_MATCH && w.strstart - w.match_start > DF_TOO_FAR {
                w.match_length = 2;
            }
        }
        if w.prev_length >= DF_MIN_MATCH && w.match_length <= w.prev_length {
            let max_insert = w.strstart + w.lookahead - DF_MIN_MATCH;
            df_match(w, w.strstart - 1 - w.prev_match, w.prev_length);
            w.lookahead -= w.prev_length - 1;
            var m = w.prev_length - 2;
            while m > 0 {
                w.strstart++;
                if w.strstart <= max_insert { df_insert(w, w.strstart); }
                m--;
            }
            w.match_available = false;
            w.match_length = 2;
            w.strstart++;
            if w.ntok >= DF_TOKENS { df_block(w, out, false); }
        } else if w.match_available {
            df_lit(w, w.window[w.strstart - 1]);
            if w.ntok >= DF_TOKENS { df_block(w, out, false); }
            w.strstart++;
            w.lookahead--;
        } else {
            w.match_available = true;
            w.strstart++;
            w.lookahead--;
        }
    }
    if w.match_available {
        df_lit(w, w.window[w.strstart - 1]);
        w.match_available = false;
    }
    w.prev_length = 2;
    w.match_length = 2;
}

// --- Huffman codes ---------------------------------------------------------

struct SymFreq { freq: i64, sym: i64 }

// Code lengths for the frequencies, none longer than maxbits: an optimal
// code (Moffat and Katajainen's in-place algorithm over the frequencies in
// order), its longest codes then moved up the tree until it fits (miniz's
// method). A code with one symbol gets a second, so that every code is
// complete.
fn df_build_lengths(freq: const i64[:], maxbits: i64, lengths: u8[:]) {
    let n = freq.len;
    for k in n { lengths[k] = 0; }
    var a: SymFreq[288] = [SymFreq { freq: 0, sym: 0 }; 288];
    var used: i64 = 0;
    for k in n {
        if freq[k] > 0 {
            a[used] = SymFreq { freq: freq[k], sym: k };
            used++;
        }
    }
    if used == 0 { return; }
    if used == 1 {
        let s = a[0].sym;
        lengths[s] = 1;
        lengths[if s == 0 { 1 } else { 0 }] = 1;
        return;
    }
    sort(a[..used]) { x, y => x.freq < y.freq || (x.freq == y.freq && x.sym < y.sym) };
    // Moffat-Katajainen: a[i].freq becomes the depth of the i-th symbol.
    var key: i64[288] = [0; 288];
    for k in used { key[k] = a[k].freq; }
    key[0] += key[1];
    var root: i64 = 0;
    var leaf: i64 = 2;
    for next in 1..used - 1 {
        if leaf >= used || key[root] < key[leaf] {
            key[next] = key[root];
            key[root] = next;
            root++;
        } else {
            key[next] = key[leaf];
            leaf++;
        }
        if leaf >= used || (root < next && key[root] < key[leaf]) {
            key[next] += key[root];
            key[root] = next;
            root++;
        } else {
            key[next] += key[leaf];
            leaf++;
        }
    }
    key[used - 2] = 0;
    var i = used - 3;
    while i >= 0 {
        key[i] = key[key[i]] + 1;
        i--;
    }
    var avbl: i64 = 1;
    var u: i64 = 0;
    var depth: i64 = 0;
    var r = used - 2;
    var nx = used - 1;
    while avbl > 0 {
        while r >= 0 && key[r] == depth {
            u++;
            r--;
        }
        while avbl > u {
            key[nx] = depth;
            nx--;
            avbl--;
        }
        avbl = 2 * u;
        depth++;
        u = 0;
    }
    // key[i] is now the length of a[i]'s code (longest first). Count the
    // codes of each length, folding those past maxbits into maxbits.
    var count: i64[300] = [0; 300];
    for k in used { count[min(key[k], maxbits)]++; }
    var total: i64 = 0;
    for len in 1..maxbits + 1 { total += count[len] << (maxbits - len); }
    while total > (1 << maxbits) {
        count[maxbits]--;
        var l = maxbits - 1;
        while l > 0 {
            if count[l] > 0 {
                count[l]--;
                count[l + 1] += 2;
                break;
            }
            l--;
        }
        total--;
    }
    // The most frequent symbols get the shortest codes.
    var j = used;
    for len in 1..maxbits + 1 {
        for c in count[len] {
            j--;
            lengths[a[j].sym] = len as! u8;
        }
    }
}

// Canonical codes for lengths, bit-reversed for writing LSB first.
fn df_codes(lengths: const u8[:], codes: u16[:]) {
    var count: i64[16] = [0; 16];
    for l in lengths { count[l]++; }
    count[0] = 0;
    var next: i64[16] = [0; 16];
    var code: i64 = 0;
    for len in 1..16 {
        code = (code + count[len - 1]) << 1;
        next[len] = code;
    }
    for s in lengths.len {
        let l = lengths[s] as i64;
        if l != 0 {
            codes[s] = reverse_bits(next[l], l) as! u16;
            next[l]++;
        }
    }
}

let DF_FIXED_LIT_LEN: u8[288] = df_fixed_lit_lengths();

fn df_fixed_lit_lengths() -> u8[288] {
    var l: u8[288] = [0; 288];
    for k in 144 { l[k] = 8; }
    for k in 144..256 { l[k] = 9; }
    for k in 256..280 { l[k] = 7; }
    for k in 280..288 { l[k] = 8; }
    return l;
}

fn df_fixed_lit_codes() -> u16[288] {
    var c: u16[288] = [0; 288];
    df_codes(DF_FIXED_LIT_LEN, c);
    return c;
}

fn df_fixed_dist_codes() -> u16[30] {
    var c: u16[30] = [0; 30];
    let l: u8[30] = [5; 30];
    df_codes(l, c);
    return c;
}

let DF_FIXED_LIT_CODE: u16[288] = df_fixed_lit_codes();
let DF_FIXED_DIST_CODE: u16[30] = df_fixed_dist_codes();

// --- Blocks ----------------------------------------------------------------

// The code length code's symbols for a run of lengths (RFC 1951 §3.2.7):
// each entry symbol | extra << 8.
fn df_rle_lengths(lens: const u8[:], syms: u16[:]) -> i64 {
    var n: i64 = 0;
    var i: i64 = 0;
    while i < lens.len {
        let l = lens[i];
        var run: i64 = 1;
        while i + run < lens.len && lens[i + run] == l { run++; }
        i += run;
        if l == 0 {
            while run >= 11 {
                let r = min(run, 138);
                syms[n] = (18 | (r - 11) << 8) as! u16;
                n++;
                run -= r;
            }
            if run >= 3 {
                syms[n] = (17 | (run - 3) << 8) as! u16;
                n++;
                run = 0;
            }
        } else {
            syms[n] = l;
            n++;
            run--;
            while run >= 3 {
                let r = min(run, 6);
                syms[n] = (16 | (r - 3) << 8) as! u16;
                n++;
                run -= r;
            }
        }
        for k in run {
            syms[n] = l;
            n++;
        }
    }
    return n;
}

let DF_CL_EXTRA: i64[19] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7];

// The bits of the block's symbols with the given lengths (extra bits too).
fn df_data_bits(w: const Deflate&, ll: const u8[:], dl: const u8[:]) -> i64 {
    var bits: i64 = 0;
    for s in 286 { bits += w.lit_freq[s] * (ll[s]); }
    for s in 29 { bits += w.lit_freq[257 + s] * (LEN_EXTRA[s]); }
    for s in 30 { bits += w.dist_freq[s] * ((dl[s]) + (DIST_EXTRA[s])); }
    return bits;
}

// Writes the block's tokens with the given codes.
fn df_write_tokens(w: Deflate&, out: u8[>..]&, lc: const u16[:], ll: const u8[:], dc: const u16[:], dl: const u8[:]) {
    for k in w.ntok {
        let t = w.tokens[k];
        if (t >> 31) == 0 {
            bw_bits(w.bw, out, lc[t], ll[t]);
            continue;
        }
        let len3 = (t & 0xff) as i64;
        let dist = ((t >> 8) & 0x7fff) as i64 + 1;
        let code = DF_LEN_CODE[len3] as i64;
        bw_bits(w.bw, out, lc[257 + code], ll[257 + code]);
        let le = LEN_EXTRA[code] as i64;
        if le > 0 { bw_bits(w.bw, out, (len3 + 3 - (LEN_BASE[code])) as! u64, le); }
        let dcode = df_dist_code(dist);
        bw_bits(w.bw, out, dc[dcode], dl[dcode]);
        let de = DIST_EXTRA[dcode] as i64;
        if de > 0 { bw_bits(w.bw, out, (dist - (DIST_BASE[dcode])) as! u64, de); }
    }
    bw_bits(w.bw, out, lc[256], ll[256]);
}

// Writes stored blocks of window[from, from + n) (several when n is over
// 65535; one empty block when n is 0).
fn df_stored(w: Deflate&, out: u8[>..]&, from: i64, n: i64, last: bool) {
    var p = from;
    var left = n;
    loop {
        let k = min(left, 65535);
        let final = last && k == left;
        bw_bits(w.bw, out, if final { 1 } else { 0 }, 3);
        bw_flush(w.bw, out);
        put_le16(out, k as! u64);
        put_le16(out, (k ^ 0xffff) as! u64);
        out.append(w.window[p..p + k]);
        p += k;
        left -= k;
        if left == 0 { break; }
    }
}

// Writes the gathered tokens as one block (or several stored ones),
// whichever way is smallest.
fn df_block(w: Deflate&, out: u8[>..]&, last: bool) {
    w.lit_freq[256] = 1;
    var ll: u8[286] = [0; 286];
    var dl: u8[30] = [0; 30];
    df_build_lengths(w.lit_freq, 15, ll);
    df_build_lengths(w.dist_freq, 15, dl);
    // No distances: still two codes, as zlib writes (an empty distance code
    // is valid, but not every decoder takes it).
    if dl[0] == 0 && dl[1] == 0 {
        var any = false;
        for k in 30 { if dl[k] != 0 { any = true; } }
        if !any {
            dl[0] = 1;
            dl[1] = 1;
        }
    }
    var hlit: i64 = 286;
    while hlit > 257 && ll[hlit - 1] == 0 { hlit--; }
    var hdist: i64 = 30;
    while hdist > 1 && dl[hdist - 1] == 0 { hdist--; }
    // The code lengths, run-length coded, and the code length code.
    var lens: u8[316] = [0; 316];
    for k in hlit { lens[k] = ll[k]; }
    for k in hdist { lens[hlit + k] = dl[k]; }
    var syms: u16[316] = [0; 316];
    let nsyms = df_rle_lengths(lens[..hlit + hdist], syms);
    var clfreq: i64[19] = [0; 19];
    for k in nsyms { clfreq[syms[k] & 0xff]++; }
    var cll: u8[19] = [0; 19];
    df_build_lengths(clfreq, 7, cll);
    var hclen: i64 = 19;
    while hclen > 4 && cll[CODE_ORDER[hclen - 1]] == 0 { hclen--; }
    var dyn_bits: i64 = 3 + 5 + 5 + 4 + 3 * hclen;
    for s in 19 { dyn_bits += clfreq[s] * ((cll[s]) + DF_CL_EXTRA[s]); }
    dyn_bits += df_data_bits(w, ll, dl);
    let fixed_dl: u8[30] = [5; 30];
    let fixed_bits = 3 + df_data_bits(w, DF_FIXED_LIT_LEN, fixed_dl);
    // Stored: the bytes must still be in the window.
    var stored_bits: i64 = -1;
    if w.block_start >= 0 {
        let nblocks = max(1, (w.block_bytes + 65534) / 65535);
        stored_bits = 8 * w.block_bytes + nblocks * 40 + 7;
    }
    if stored_bits >= 0 && stored_bits <= fixed_bits && stored_bits <= dyn_bits {
        df_stored(w, out, w.block_start, w.block_bytes, last);
    } else if fixed_bits <= dyn_bits {
        bw_bits(w.bw, out, if last { 3 } else { 2 }, 3);
        df_write_tokens(w, out, DF_FIXED_LIT_CODE, DF_FIXED_LIT_LEN, DF_FIXED_DIST_CODE, fixed_dl);
    } else {
        bw_bits(w.bw, out, if last { 5 } else { 4 }, 3);
        bw_bits(w.bw, out, (hlit - 257) as! u64, 5);
        bw_bits(w.bw, out, (hdist - 1) as! u64, 5);
        bw_bits(w.bw, out, (hclen - 4) as! u64, 4);
        for k in hclen { bw_bits(w.bw, out, cll[CODE_ORDER[k]], 3); }
        var clc: u16[19] = [0; 19];
        df_codes(cll, clc);
        for k in nsyms {
            let s = (syms[k] & 0xff) as i64;
            bw_bits(w.bw, out, clc[s], cll[s]);
            if DF_CL_EXTRA[s] > 0 { bw_bits(w.bw, out, (syms[k] >> 8), DF_CL_EXTRA[s]); }
        }
        var lc: u16[286] = [0; 286];
        var dc: u16[30] = [0; 30];
        df_codes(ll, lc);
        df_codes(dl, dc);
        df_write_tokens(w, out, lc, ll, dc, dl);
    }
    w.block_start += w.block_bytes;
    w.block_bytes = 0;
    w.ntok = 0;
    for k in 286 { w.lit_freq[k] = 0; }
    for k in 30 { w.dist_freq[k] = 0; }
}

// --- Calls -----------------------------------------------------------------

// Compresses input, appending what is ready to out: 0 or an error
// (ERR_ARGUMENT after close or for a bad level).
fn deflate_write(w: Deflate&, input: const u8[:], out: u8[>..]&) -> i64 {
    if w.state != DW_OPEN { return if w.err != 0 { w.err } else { ERR_ARGUMENT }; }
    var p: i64 = 0;
    w.total_in += input.len;
    if w.level == 0 {
        // Stored blocks of 65535 bytes, the bytes gathered in the window.
        while p < input.len {
            let n = min(65535 - w.lookahead, input.len - p);
            w.window[w.lookahead..w.lookahead + n].move_from(input[p..p + n]);
            w.lookahead += n;
            p += n;
            if w.lookahead == 65535 {
                df_stored(w, out, 0, 65535, false);
                w.lookahead = 0;
            }
        }
        return 0;
    }
    while p < input.len {
        p += df_fill(w, input[p..]);
        df_compress(w, out, false);
    }
    return 0;
}

// Writes everything taken so far, then an empty stored block, so that a
// reader can decode all of it (Go's Flush; zlib's Z_SYNC_FLUSH). Matches
// may still reach back past it.
fn deflate_flush(w: Deflate&, out: u8[>..]&) -> i64 {
    if w.state != DW_OPEN { return if w.err != 0 { w.err } else { ERR_ARGUMENT }; }
    df_finish_blocks(w, out, false);
    df_stored(w, out, 0, 0, false);
    return 0;
}

fn df_finish_blocks(w: Deflate&, out: u8[>..]&, last: bool) {
    if w.level == 0 {
        if w.lookahead > 0 || last {
            df_stored(w, out, 0, w.lookahead, last);
            w.lookahead = 0;
        }
        return;
    }
    df_compress(w, out, true);
    if w.ntok > 0 || last { df_block(w, out, last); }
}

// Writes the rest and the last block: 0, or an error. A second close does
// nothing (as Go's).
fn deflate_close(w: Deflate&, out: u8[>..]&) -> i64 {
    if w.state == DW_CLOSED { return 0; }
    if w.state != DW_OPEN { return w.err; }
    df_finish_blocks(w, out, true);
    bw_flush(w.bw, out);
    w.state = DW_CLOSED;
    return 0;
}

// Compresses data as one raw DEFLATE stream, appended to out: 0 or
// ERR_ARGUMENT for a bad level.
fn deflate_encode(data: const u8[:], out: u8[>..]&, level: i64 = 6) -> i64 {
    var w = deflate_writer(level);
    let e = deflate_write(w, data, out);
    if e != 0 { return e; }
    return deflate_close(w, out);
}
