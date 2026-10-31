// compress.xz: decoding of xz (the .xz file format, version 1.2.1), of
// raw LZMA2, and of the legacy .lzma format (LZMA "alone"), as liblzma
// does it, with the same checks of the container.
//
//   var d = compress::xz_reader();               // or lzma_reader(), lzma2_reader(dict_size)
//   let used, made, st = compress::xz_read(d, input, out);
//   // st: 0 (more input or room wanted), STREAM_END, or an error
//   // at the end of the input: compress::xz_done(d)
//
// The decoder is fed any amount of input at a time, down to a byte, and
// writes at most out.len bytes a call. It keeps at most a little over a
// kilobyte of input of its own (a block header is up to 1024 bytes); the
// rest of what it is given stays the caller's: `used` counts only what it
// took. Bytes after the end of a .lzma stream, or of the first .xz stream
// in single-stream mode, are not taken.
//
// Memory: the probability model is of fixed size (liblzma's limit
// lc + lp <= 4 holds for .lzma too), and the dictionary grows as output
// is made, up to the size the stream declares (at least 4 KiB). A
// declared size above the reader's memory limit (XZ_DEFAULT_MEMLIMIT,
// 256 MiB, set with xz_set_memlimit) is refused with ERR_LIMIT before
// anything is allocated.
//
// Integrity checks: None, CRC-32, CRC-64 and SHA-256 are verified. The
// check IDs the format reserves (2-3, 5-9, 11-15) are decoded without
// being verified, as xz does (it warns): xz_check_unverified(d) says so.
//
// Filters: LZMA2, Delta and the branch converters (BCJ) for x86,
// PowerPC, IA-64, ARM, ARM-Thumb, SPARC and ARM64, up to four in a
// chain as the format allows. RISC-V is not done (ERR_UNSUPPORTED).

namespace compress;

import std;
import compress;

// --- SHA-256 (FIPS 180-4), for xz's check ----------------------------------

let SHA256_K: u32[64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 { h: u32[8], buf: u8[64], blen: i64, total: u64 }

fn sha256_new() -> Sha256 {
    Sha256 {
        h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
        buf: [0; 64], blen: 0, total: 0,
    }
}

fn rotr32(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }

fn sha256_block(s: Sha256&, p: const u8[:], at: i64) {
    var w: u32[64] = [0; 64];
    for i in 16 { w[i] = get_be32(p, at + i * 4); }
    for i in 16..64 {
        let s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    var a = s.h[0]; var b = s.h[1]; var c = s.h[2]; var d = s.h[3];
    var e = s.h[4]; var f = s.h[5]; var g = s.h[6]; var h = s.h[7];
    for i in 64 {
        let t1 = h + (rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)) + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
        let t2 = (rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    s.h[0] += a; s.h[1] += b; s.h[2] += c; s.h[3] += d;
    s.h[4] += e; s.h[5] += f; s.h[6] += g; s.h[7] += h;
}

fn sha256_update(s: Sha256&, p: const u8[:]) {
    s.total += p.len as! u64;
    var i = 0;
    if s.blen > 0 {
        while s.blen < 64 && i < p.len { s.buf[s.blen] = p[i]; s.blen++; i++; }
        if s.blen < 64 { return; }
        let blk = s.buf;
        sha256_block(s, blk, 0);
        s.blen = 0;
    }
    while i + 64 <= p.len {
        sha256_block(s, p, i);
        i += 64;
    }
    while i < p.len { s.buf[s.blen] = p[i]; s.blen++; i++; }
}

fn sha256_final(s: Sha256&) -> u8[32] {
    let bits = s.total * 8;
    var padb: u8[72] = [0; 72];
    padb[0] = 0x80;
    let padlen = if s.blen < 56 { 56 - s.blen } else { 120 - s.blen };
    for k in 8 { padb[padlen + k] = ((bits >> ((56 - k * 8) as! u64)) & 0xff) as! u8; }
    let total = s.total;
    sha256_update(s, padb[..padlen + 8]);
    s.total = total;
    var out: u8[32] = [0; 32];
    for i in 8 {
        for k in 4 { out[i * 4 + k] = ((s.h[i] >> ((24 - k * 8) as! u32)) & 0xff) as! u8; }
    }
    return out;
}

fn sha256(p: const u8[:]) -> u8[32] {
    var s = sha256_new();
    sha256_update(s, p);
    return sha256_final(s);
}

// --- Shared constants -------------------------------------------------------

let XZ_CHECK_NONE: i64 = 0;
let XZ_CHECK_CRC32: i64 = 1;
let XZ_CHECK_CRC64: i64 = 4;
let XZ_CHECK_SHA256: i64 = 10;

// The filter IDs of the .xz format.
let XZ_FILTER_DELTA: u64 = 0x03;
let XZ_FILTER_X86: u64 = 0x04;
let XZ_FILTER_POWERPC: u64 = 0x05;
let XZ_FILTER_IA64: u64 = 0x06;
let XZ_FILTER_ARM: u64 = 0x07;
let XZ_FILTER_ARMTHUMB: u64 = 0x08;
let XZ_FILTER_SPARC: u64 = 0x09;
let XZ_FILTER_ARM64: u64 = 0x0a;
let XZ_FILTER_RISCV: u64 = 0x0b;
let XZ_FILTER_LZMA2: u64 = 0x21;

let XZ_DEFAULT_MEMLIMIT: i64 = 1 << 28;

let XZ_CHECK_SIZES: i64[16] = [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64];

let XZ_MAGIC: u8[6] = [0xfd, '7', 'z', 'X', 'Z', 0];

// The size an LZMA2 dictionary-size byte (<= 40) stands for.
fn lzma2_dict_size(b: u8) -> u64 {
    if b >= 40 { return 0xffffffff; }
    return ((2 | (b & 1)) as u64) << ((b / 2 + 11) as! u64);
}

// --- LZMA probability model ------------------------------------------------

let LZ_IS_MATCH: i64 = 0;          // [state][pos_state], 12 x 16
let LZ_IS_REP: i64 = 192;
let LZ_IS_REP0: i64 = 204;
let LZ_IS_REP1: i64 = 216;
let LZ_IS_REP2: i64 = 228;
let LZ_IS_REP0_LONG: i64 = 240;    // [state][pos_state]
let LZ_DIST_SLOT: i64 = 432;       // [len_state][64]
let LZ_DIST_SPECIAL: i64 = 688;    // 114
let LZ_DIST_ALIGN: i64 = 802;      // 16
let LZ_LEN_MATCH: i64 = 818;       // a length coder: 514
let LZ_LEN_REP: i64 = 1332;
let LZ_LITERAL: i64 = 1846;        // 0x300 << (lc + lp), lc + lp <= 4
let LZ_PROBS: i64 = 1846 + 0x300 * 16;
let LZ_LEN_CHOICE: i64 = 0;
let LZ_LEN_CHOICE2: i64 = 1;
let LZ_LEN_LOW: i64 = 2;           // [pos_state][8]
let LZ_LEN_MID: i64 = 130;
let LZ_LEN_HIGH: i64 = 258;        // 256

let LZ_MATCH_LEN_MAX: i64 = 273;

// Symbols decoded, before they are applied.
let SYM_LITERAL: i64 = 0;
let SYM_MATCH: i64 = 1;
let SYM_REP: i64 = 2;
let SYM_SHORTREP: i64 = 3;
let SYM_EOPM: i64 = 4;

let LZ_LOGCAP: i64 = 64;

// The LZMA decoder's state, of fixed size. The dictionary is the
// reader's (its tail), shared by the chunks of an LZMA2 stream.
struct Lzma {
    lc: i64, lp: i64, pb: i64,
    state: i64,
    rep0: u32, rep1: u32, rep2: u32, rep3: u32,
    range: u32, code: u32,
    mlen: i64,                  // bytes of a match still to copy (at rep0)
    short: bool,                // the input ran out inside a symbol
    spec: bool,                 // log changes so that a symbol can be undone
    nlog: i64,
    logi: u16[64], logv: u16[64],
    // A decoded symbol, applied once whole.
    s_kind: i64, s_len: i64, s_byte: u8, s_state: i64,
    s_rep0: u32, s_rep1: u32, s_rep2: u32, s_rep3: u32,
    p: u16[14134],
}

fn lzma_new() -> Lzma {
    Lzma {
        lc: 3, lp: 0, pb: 2, state: 0, rep0: 0, rep1: 0, rep2: 0, rep3: 0,
        range: 0xffffffff, code: 0, mlen: 0, short: false, spec: false, nlog: 0,
        logi: [0; 64], logv: [0; 64],
        s_kind: 0, s_len: 0, s_byte: 0, s_state: 0, s_rep0: 0, s_rep1: 0, s_rep2: 0, s_rep3: 0,
        p: [1024; 14134],
    }
}

fn lzma_reset_state(z: Lzma&) {
    z.state = 0;
    z.rep0 = 0; z.rep1 = 0; z.rep2 = 0; z.rep3 = 0;
    z.mlen = 0;
    let n = LZ_LITERAL + (0x300 << ((z.lc + z.lp) as! u64));
    for i in n { z.p[i] = 1024; }
}

// lc/lp/pb from a properties byte: false when not valid (lc + lp > 4, as
// liblzma requires, or past 224).
fn lzma_set_props(z: Lzma&, b: u8) -> bool {
    if b > 224 { return false; }
    let v = b as i64;
    let lc = v % 9;
    let lp = (v / 9) % 5;
    let pb = v / 45;
    if lc + lp > 4 { return false; }
    z.lc = lc; z.lp = lp; z.pb = pb;
    return true;
}

// --- Filters after LZMA2 (decoding) ----------------------------------------

let XZ_STAGE_BUF: i64 = 16384;

struct XzStage {
    id: u64,
    pos: u32,                   // the stream position of buf[conv] (BCJ's now_pos)
    x86_mask: u32, x86_prev: u32,
    delta_dist: i64, delta_pos: i64, delta_hist: u8[256],
    rd: i64, conv: i64, filled: i64,    // buf[rd..conv] ready, buf[conv..filled] not yet converted
    upstream_end: bool,
    buf: u8[16384],
}

fn xz_stage_new() -> XzStage {
    XzStage {
        id: 0, pos: 0, x86_mask: 0, x86_prev: 0, delta_dist: 1, delta_pos: 0, delta_hist: [0; 256],
        rd: 0, conv: 0, filled: 0, upstream_end: false, buf: [0; 16384],
    }
}

fn xz_stage_reset(s: XzStage&, id: u64, start: u32, dist: i64) {
    s.id = id; s.pos = start; s.x86_mask = 0; s.x86_prev = 0xfffffffb;
    s.delta_dist = dist; s.delta_pos = 0;
    for i in 256 { s.delta_hist[i] = 0; }
    s.rd = 0; s.conv = 0; s.filled = 0; s.upstream_end = false;
}

fn x86_test_ms(b: u8) -> bool { ((b + 1) & 0xfe) == 0 }

let X86_ALLOWED: bool[8] = [true, true, true, false, true, false, false, false];
let X86_BITNUM: u32[8] = [0, 1, 2, 2, 3, 3, 3, 3];

// The branch converters, liblzma's simple/*.c: each converts what it can
// of buf (in place) and returns how many bytes are done; the rest waits
// for more input (or, at the end, is passed unchanged).
fn bcj_x86(s: XzStage&, buf: u8[:], enc: bool) -> i64 {
    let size = buf.len;
    if size < 5 { return 0; }
    let now = s.pos;
    var prev_mask = s.x86_mask;
    var prev_pos = s.x86_prev;
    if now - prev_pos > 5 { prev_pos = now - 5; }
    let limit = size - 5;
    var i = 0;
    while i <= limit {
        var b = buf[i];
        if b != 0xe8 && b != 0xe9 { i++; continue; }
        let offset = now + (i as! u32) - prev_pos;
        prev_pos = now + (i as! u32);
        if offset > 5 {
            prev_mask = 0;
        } else {
            for k in offset {
                prev_mask &= 0x77;
                prev_mask <<= 1;
            }
        }
        b = buf[i + 4];
        if x86_test_ms(b) && X86_ALLOWED[(prev_mask >> 1) & 7] && (prev_mask >> 1) < 0x10 {
            var src = (b as u32) << 24 | (buf[i + 3] as u32) << 16 | (buf[i + 2] as u32) << 8 | buf[i + 1];
            var dest: u32 = 0;
            while true {
                if enc { dest = src + (now + (i as! u32) + 5); }
                else { dest = src - (now + (i as! u32) + 5); }
                if prev_mask == 0 { break; }
                let k = X86_BITNUM[prev_mask >> 1];
                b = ((dest >> (24 - k * 8)) & 0xff) as! u8;
                if !x86_test_ms(b) { break; }
                src = dest ^ (((1 as u64) << ((32 - k * 8) as u64)) - 1) as! u32;
            }
            buf[i + 4] = if ((dest >> 24) & 1) != 0 { 0xff } else { 0 };
            buf[i + 3] = ((dest >> 16) & 0xff) as! u8;
            buf[i + 2] = ((dest >> 8) & 0xff) as! u8;
            buf[i + 1] = (dest & 0xff) as! u8;
            i += 5;
            prev_mask = 0;
        } else {
            i++;
            prev_mask |= 1;
            if x86_test_ms(b) { prev_mask |= 0x10; }
        }
    }
    s.x86_mask = prev_mask;
    s.x86_prev = prev_pos;
    return i;
}

fn bcj_powerpc(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 4 <= buf.len {
        if (buf[i] >> 2) == 0x12 && (buf[i + 3] & 3) == 1 {
            let src = ((buf[i] & 3) as u32) << 24 | (buf[i + 1] as u32) << 16 | (buf[i + 2] as u32) << 8 | (buf[i + 3] & 0xfc);
            let dest = if enc { now + (i as! u32) + src } else { src - (now + (i as! u32)) };
            buf[i] = 0x48 | ((dest >> 24) & 3) as! u8;
            buf[i + 1] = ((dest >> 16) & 0xff) as! u8;
            buf[i + 2] = ((dest >> 8) & 0xff) as! u8;
            buf[i + 3] = (buf[i + 3] & 3) | (dest & 0xfc) as! u8;
        }
        i += 4;
    }
    return i;
}

fn bcj_arm(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 4 <= buf.len {
        if buf[i + 3] == 0xeb {
            let src = ((buf[i + 2] as u32) << 16 | (buf[i + 1] as u32) << 8 | buf[i]) << 2;
            var dest = if enc { now + (i as! u32) + 8 + src } else { src - (now + (i as! u32) + 8) };
            dest >>= 2;
            buf[i + 2] = ((dest >> 16) & 0xff) as! u8;
            buf[i + 1] = ((dest >> 8) & 0xff) as! u8;
            buf[i] = (dest & 0xff) as! u8;
        }
        i += 4;
    }
    return i;
}

fn bcj_armthumb(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 4 <= buf.len {
        if (buf[i + 1] & 0xf8) == 0xf0 && (buf[i + 3] & 0xf8) == 0xf8 {
            var src = ((buf[i + 1] & 7) as u32) << 19 | (buf[i] as u32) << 11 | ((buf[i + 3] & 7) as u32) << 8 | buf[i + 2];
            src <<= 1;
            var dest = if enc { now + (i as! u32) + 4 + src } else { src - (now + (i as! u32) + 4) };
            dest >>= 1;
            buf[i + 1] = 0xf0 | ((dest >> 19) & 7) as! u8;
            buf[i] = ((dest >> 11) & 0xff) as! u8;
            buf[i + 3] = 0xf8 | ((dest >> 8) & 7) as! u8;
            buf[i + 2] = (dest & 0xff) as! u8;
            i += 2;
        }
        i += 2;
    }
    return i;
}

fn bcj_sparc(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 4 <= buf.len {
        if (buf[i] == 0x40 && (buf[i + 1] & 0xc0) == 0) || (buf[i] == 0x7f && (buf[i + 1] & 0xc0) == 0xc0) {
            var src = get_be32(buf, i);
            src <<= 2;
            var dest = if enc { now + (i as! u32) + src } else { src - (now + (i as! u32)) };
            dest >>= 2;
            dest = (((0 - ((dest >> 22) & 1)) << 22) & 0x3fffffff) | (dest & 0x3fffff) | 0x40000000;
            buf[i] = (dest >> 24) as! u8;
            buf[i + 1] = ((dest >> 16) & 0xff) as! u8;
            buf[i + 2] = ((dest >> 8) & 0xff) as! u8;
            buf[i + 3] = (dest & 0xff) as! u8;
        }
        i += 4;
    }
    return i;
}

let IA64_BRANCH: u32[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];

fn bcj_ia64(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 16 <= buf.len {
        let mask = IA64_BRANCH[buf[i] & 0x1f];
        var bit_pos: i64 = 5;
        for slot in 3 {
            if ((mask >> (slot as! u32)) & 1) != 0 {
                let byte_pos = bit_pos >> 3;
                let bit_res = (bit_pos & 7) as! u64;
                var instr: u64 = 0;
                for j in 6 { instr += (buf[i + j + byte_pos] as u64) << ((8 * j) as! u64); }
                var norm = instr >> bit_res;
                if ((norm >> 37) & 0xf) == 5 && ((norm >> 9) & 7) == 0 {
                    var src = ((norm >> 13) & 0xfffff) as! u32;
                    src |= (((norm >> 36) & 1) as! u32) << 20;
                    src <<= 4;
                    var dest = if enc { now + (i as! u32) + src } else { src - (now + (i as! u32)) };
                    dest >>= 4;
                    norm &= ~((0x8fffff as u64) << 13);
                    norm |= ((dest & 0xfffff) as u64) << 13;
                    norm |= ((dest & 0x100000) as u64) << (36 - 20);
                    instr &= ((1 as u64) << bit_res) - 1;
                    instr |= norm << bit_res;
                    for j in 6 { buf[i + j + byte_pos] = ((instr >> ((8 * j) as! u64)) & 0xff) as! u8; }
                }
            }
            bit_pos += 41;
        }
        i += 16;
    }
    return i;
}

fn bcj_arm64(now: u32, buf: u8[:], enc: bool) -> i64 {
    var i = 0;
    while i + 4 <= buf.len {
        var pc = now + (i as! u32);
        var instr = get_le32(buf, i);
        var write = false;
        if (instr >> 26) == 0x25 {
            let src = instr;
            instr = 0x94000000;
            pc >>= 2;
            if !enc { pc = 0 - pc; }
            instr |= (src + pc) & 0x03ffffff;
            write = true;
        } else if (instr & 0x9f000000) == 0x90000000 {
            let src = ((instr >> 29) & 3) | ((instr >> 3) & 0x001ffffc);
            if ((src + 0x00020000) & 0x001c0000) == 0 {
                instr &= 0x9000001f;
                pc >>= 12;
                if !enc { pc = 0 - pc; }
                let dest = src + pc;
                instr |= (dest & 3) << 29;
                instr |= (dest & 0x0003fffc) << 3;
                instr |= (0 - (dest & 0x00020000)) & 0x00e00000;
                write = true;
            }
        }
        if write {
            for k in 4 { buf[i + k] = ((instr >> ((k * 8) as! u32)) & 0xff) as! u8; }
        }
        i += 4;
    }
    return i;
}

// Converts what it can of s.buf[conv..filled].
fn xz_stage_convert(s: XzStage&, enc: bool) {
    let n = s.filled - s.conv;
    if n <= 0 { return; }
    var done: i64 = 0;
    if s.id == XZ_FILTER_DELTA {
        let dist = s.delta_dist;
        for k in n {
            let at = s.conv + k;
            let x = s.buf[at];
            let hist_at = (dist + s.delta_pos) & 0xff;
            if enc {
                let t = s.delta_hist[hist_at];
                s.delta_hist[s.delta_pos & 0xff] = x;
                s.buf[at] = x - t;
            } else {
                let y = x + s.delta_hist[hist_at];
                s.delta_hist[s.delta_pos & 0xff] = y;
                s.buf[at] = y;
            }
            s.delta_pos = (s.delta_pos - 1) & 0xff;
        }
        done = n;
    } else {
        let b = s.buf[s.conv..s.filled];
        if s.id == XZ_FILTER_X86 { done = bcj_x86(s, b, enc); }
        else if s.id == XZ_FILTER_POWERPC { done = bcj_powerpc(s.pos, b, enc); }
        else if s.id == XZ_FILTER_IA64 { done = bcj_ia64(s.pos, b, enc); }
        else if s.id == XZ_FILTER_ARM { done = bcj_arm(s.pos, b, enc); }
        else if s.id == XZ_FILTER_ARMTHUMB { done = bcj_armthumb(s.pos, b, enc); }
        else if s.id == XZ_FILTER_SPARC { done = bcj_sparc(s.pos, b, enc); }
        else if s.id == XZ_FILTER_ARM64 { done = bcj_arm64(s.pos, b, enc); }
    }
    s.pos += done as! u32;
    s.conv += done;
    if s.upstream_end { s.conv = s.filled; }   // the rest passes unchanged
}

// --- The reader -------------------------------------------------------------

let XZ_MODE_XZ: u8 = 0;
let XZ_MODE_ALONE: u8 = 1;
let XZ_MODE_LZMA2: u8 = 2;

// Stages.
let XS_STREAM_HEADER: u8 = 0;
let XS_BLOCK_HEADER: u8 = 1;
let XS_BLOCK_DATA: u8 = 2;
let XS_BLOCK_PADDING: u8 = 3;
let XS_CHECK: u8 = 4;
let XS_INDEX: u8 = 5;
let XS_FOOTER: u8 = 6;
let XS_PADDING: u8 = 7;              // after a stream: padding, another stream, or the end
let XS_ALONE_HEADER: u8 = 8;
let XS_DONE: u8 = 9;                 // the end of a .lzma stream (or single-stream .xz)
let XS_FAILED: u8 = 10;

// LZMA2 states.
let L2_CONTROL: u8 = 0;
let L2_LZMA: u8 = 1;
let L2_COPY: u8 = 2;
let L2_END: u8 = 3;

// What a run stops for.
let XR_INPUT: i64 = 0;
let XR_OUTPUT: i64 = 2;
let XR_END: i64 = 1;
let XR_CONTINUE: i64 = 3;

let XZ_TCAP: i64 = 1100;

struct XzReader {
    mode: u8,
    stage: u8,
    err: i64,
    single: bool,
    memlimit: i64,
    sp: i64,                        // position in the input of the current run
    op: i64,                        // bytes written to out by this call
    tlen: i64,                      // input kept between calls
    tbuf: u8[1100],
    // Stream.
    streams: i64,
    flags1: u8,
    check: i64, check_size: i64, unverified: bool,
    crc32: u32, crc64: u64, sha: Sha256,
    // Block.
    bh_size: i64, bh_csize: i64, bh_usize: i64,
    bcsize: i64, busize: i64, bpadn: i64,
    nstages: i64,
    stages: XzStage[3],
    // Records of the blocks, against the index (count, sums, a hash).
    nblocks: i64, sum_unpadded: i64, sum_uncomp: i64, rec_hash: u64,
    // Index.
    ix_part: u8, ix_left: i64, ix_count: i64, ix_unpadded: i64, ix_size: i64, ix_crc: u32,
    ix_sum_unpadded: i64, ix_sum_uncomp: i64, ix_hash: u64, ix_vli: u64, ix_vlen: i64,
    spad: i64,
    // LZMA2.
    l2: u8, l2_need_props: bool, l2_need_dict_reset: bool,
    l2_uleft: i64, l2_cleft: i64, l2_rc_init: bool,
    // .lzma
    alone_left: i64,                // -1: unknown, ended by the marker
    alone_eopm: bool,               // at the known end, looking for an end marker
    lz: Lzma,
    // Dictionary: a ring of dsize bytes, grown as written.
    dsize: i64, dpos: i64, dfull: bool, dtotal: i64,
    dict: u8[>..],
}

fn xz_new(mode: u8) -> XzReader {
    XzReader {
        mode: mode, stage: XS_STREAM_HEADER, err: 0, single: false, memlimit: XZ_DEFAULT_MEMLIMIT,
        sp: 0, op: 0, tlen: 0, tbuf: [0; 1100],
        streams: 0, flags1: 0, check: 0, check_size: 0, unverified: false,
        crc32: 0, crc64: 0, sha: sha256_new(),
        bh_size: 0, bh_csize: -1, bh_usize: -1, bcsize: 0, busize: 0, bpadn: 0,
        nstages: 0, stages: [xz_stage_new(), xz_stage_new(), xz_stage_new()],
        nblocks: 0, sum_unpadded: 0, sum_uncomp: 0, rec_hash: 0,
        ix_part: 0, ix_left: 0, ix_count: 0, ix_unpadded: 0, ix_size: 0, ix_crc: 0,
        ix_sum_unpadded: 0, ix_sum_uncomp: 0, ix_hash: 0, ix_vli: 0, ix_vlen: 0,
        spad: 0,
        l2: L2_CONTROL, l2_need_props: true, l2_need_dict_reset: true, l2_uleft: 0, l2_cleft: 0, l2_rc_init: false,
        alone_left: -1, alone_eopm: false,
        lz: lzma_new(),
        dsize: 4096, dpos: 0, dfull: false, dtotal: 0,
        dict: [],
    }
}

// A reader of .xz files: one stream, or several in a row with stream
// padding between them (as xz reads a file).
fn xz_reader() -> XzReader { xz_new(XZ_MODE_XZ) }

// A reader of the legacy .lzma format (13-byte header, then LZMA).
fn lzma_reader() -> XzReader {
    var d = xz_new(XZ_MODE_ALONE);
    d.stage = XS_ALONE_HEADER;
    return d;
}

// A reader of a raw LZMA2 stream (no container), with the given
// dictionary size.
fn lzma2_reader(dict_size: i64) -> XzReader {
    var d = xz_new(XZ_MODE_LZMA2);
    d.stage = XS_BLOCK_DATA;
    d.dsize = dict_size;
    if d.dsize < 4096 { d.dsize = 4096; }
    d.dsize = (d.dsize + 15) & ~15;
    if d.dsize > d.memlimit { d.err = ERR_LIMIT; d.stage = XS_FAILED; }
    return d;
}

// The largest dictionary the reader accepts, in bytes.
fn xz_set_memlimit(d: XzReader&, limit: i64) {
    d.memlimit = limit;
    if d.mode == XZ_MODE_LZMA2 && d.dsize > limit && d.err == 0 { d.err = ERR_LIMIT; d.stage = XS_FAILED; }
}

// Stop after the first .xz stream: what follows it is not taken.
fn xz_set_single_stream(d: XzReader&, single: bool) { d.single = single; }

// Whether the input so far is whole: complete streams (and padding a
// multiple of four bytes), or a complete .lzma or LZMA2 stream.
fn xz_done(d: const XzReader&) -> bool {
    if d.err < 0 || d.tlen > 0 { return false; }
    if d.stage == XS_DONE { return true; }
    return d.mode == XZ_MODE_XZ && d.stage == XS_PADDING && d.spad % 4 == 0;
}

// Whether a stream used a check this package cannot verify.
fn xz_check_unverified(d: const XzReader&) -> bool { d.unverified }

// The check type of the last stream header read (XZ_CHECK_*).
fn xz_check_type(d: const XzReader&) -> i64 { d.check }

// --- Dictionary ------------------------------------------------------------

fn dict_reset(d: XzReader&) {
    d.dpos = 0;
    d.dfull = false;
    d.dtotal = 0;
}

fn dict_grow(d: XzReader&) {
    if d.dict.len >= d.dsize { return; }
    var n = d.dict.len * 2;
    if n < 65536 { n = 65536; }
    if n > d.dsize { n = d.dsize; }
    let add = n - d.dict.len;
    for k in add { d.dict.push(0); }
}

// The byte dist + 1 back (0 if there is none).
fn dict_get(d: const XzReader&, dist: u32) -> u8 {
    var i = d.dpos - (dist as i64) - 1;
    if i < 0 { i += d.dsize; }
    if i < 0 || i >= d.dict.len { return 0; }
    return d.dict[i];
}

fn dict_put(d: XzReader&, b: u8) {
    if d.dpos >= d.dict.len { dict_grow(d); }
    d.dict[d.dpos] = b;
    d.dpos++;
    d.dtotal++;
    if d.dpos == d.dsize { d.dpos = 0; d.dfull = true; }
}

// Copies n bytes from dist + 1 back.
fn dict_repeat(d: XzReader&, dist: u32, n: i64) {
    var src = d.dpos - (dist as i64) - 1;
    if src < 0 { src += d.dsize; }
    var left = n;
    while left > 0 {
        if d.dpos >= d.dict.len { dict_grow(d); }
        // A run that neither wraps nor needs growth.
        var k = left;
        if k > d.dict.len - d.dpos { k = d.dict.len - d.dpos; }
        if k > d.dsize - d.dpos { k = d.dsize - d.dpos; }
        if k > d.dsize - src { k = d.dsize - src; }
        if src < d.dpos && k > d.dpos - src {
            // Overlapping forward copy: byte by byte.
            for j in k { d.dict[d.dpos + j] = d.dict[src + j]; }
        } else {
            d.dict[d.dpos..d.dpos + k].move_from(d.dict[src..src + k]);
        }
        d.dpos += k;
        d.dtotal += k;
        src += k;
        left -= k;
        if src == d.dsize { src = 0; }
        if d.dpos == d.dsize { d.dpos = 0; d.dfull = true; }
    }
}

fn dict_has(d: const XzReader&, dist: u32) -> bool {
    let full = if d.dtotal < d.dsize { d.dtotal } else { d.dsize };
    return (dist as i64) < full;
}

// The last n bytes written to the dictionary, to dst.
fn dict_copy_last(d: const XzReader&, n: i64, dst: u8[:]) {
    var start = d.dpos - n;
    if start >= 0 {
        dst.move_from(d.dict[start..d.dpos]);
    } else {
        start += d.dsize;
        let first = d.dsize - start;
        dst[..first].move_from(d.dict[start..d.dsize]);
        dst[first..].move_from(d.dict[..d.dpos]);
    }
}

// --- Range decoder -----------------------------------------------------------

fn rc_norm(d: XzReader&, src: const u8[:], end: i64) {
    if d.lz.range < 0x1000000 {
        d.lz.range <<= 8;
        var b: u32 = 0;
        if d.sp < end { b = src[d.sp]; d.sp++; } else { d.lz.short = true; }
        d.lz.code = (d.lz.code << 8) | b;
    }
}

fn rc_bit(d: XzReader&, src: const u8[:], end: i64, i: i64) -> u32 {
    let p = d.lz.p[i] as u32;
    if d.lz.spec && d.lz.nlog < LZ_LOGCAP {
        d.lz.logi[d.lz.nlog] = i as! u16;
        d.lz.logv[d.lz.nlog] = d.lz.p[i];
        d.lz.nlog++;
    }
    let bound = (d.lz.range >> 11) * p;
    var bit: u32 = 0;
    if d.lz.code < bound {
        d.lz.range = bound;
        d.lz.p[i] = (p + ((2048 - p) >> 5)) as! u16;
    } else {
        d.lz.range -= bound;
        d.lz.code -= bound;
        d.lz.p[i] = (p - (p >> 5)) as! u16;
        bit = 1;
    }
    rc_norm(d, src, end);
    return bit;
}

fn rc_tree(d: XzReader&, src: const u8[:], end: i64, base: i64, bits: i64) -> u32 {
    var m: u32 = 1;
    for k in bits { m = (m << 1) | rc_bit(d, src, end, base + (m as i64)); }
    return m - ((1 as u32) << (bits as! u32));
}

fn rc_tree_rev(d: XzReader&, src: const u8[:], end: i64, base: i64, bits: i64) -> u32 {
    var m: u32 = 1;
    var r: u32 = 0;
    for k in bits {
        let b = rc_bit(d, src, end, base + (m as i64));
        m = (m << 1) | b;
        r |= b << (k as! u32);
    }
    return r;
}

fn rc_direct(d: XzReader&, src: const u8[:], end: i64, bits: i64) -> u32 {
    var r: u32 = 0;
    for k in bits {
        d.lz.range >>= 1;
        var b: u32 = 0;
        if d.lz.code >= d.lz.range { d.lz.code -= d.lz.range; b = 1; }
        r = (r << 1) | b;
        rc_norm(d, src, end);
    }
    return r;
}

fn lzma_len(d: XzReader&, src: const u8[:], end: i64, base: i64, ps: i64) -> i64 {
    if rc_bit(d, src, end, base + LZ_LEN_CHOICE) == 0 {
        return 2 + rc_tree(d, src, end, base + LZ_LEN_LOW + ps * 8, 3) as i64;
    }
    if rc_bit(d, src, end, base + LZ_LEN_CHOICE2) == 0 {
        return 10 + rc_tree(d, src, end, base + LZ_LEN_MID + ps * 8, 3) as i64;
    }
    return 18 + rc_tree(d, src, end, base + LZ_LEN_HIGH, 8) as i64;
}

// Decodes one symbol into d.lz.s_*, changing nothing but the range
// decoder, the probabilities (logged when speculative) and d.sp.
fn lzma_symbol(d: XzReader&, src: const u8[:], end: i64) {
    let st = d.lz.state;
    let pos = d.dtotal;
    let ps = pos & ((1 << (d.lz.pb as! u64)) - 1);
    d.lz.s_rep0 = d.lz.rep0; d.lz.s_rep1 = d.lz.rep1; d.lz.s_rep2 = d.lz.rep2; d.lz.s_rep3 = d.lz.rep3;
    if rc_bit(d, src, end, LZ_IS_MATCH + (st << 4) + ps) == 0 {
        let prev: u8 = if d.dtotal > 0 { dict_get(d, 0) } else { 0 };
        let lit_state = ((pos & ((1 << (d.lz.lp as! u64)) - 1)) << (d.lz.lc as! u64)) + ((prev as i64) >> ((8 - d.lz.lc) as! u64));
        let base = LZ_LITERAL + 0x300 * lit_state;
        var sym: u32 = 1;
        if st < 7 {
            while sym < 0x100 { sym = (sym << 1) | rc_bit(d, src, end, base + (sym as i64)); }
        } else {
            var mb = dict_get(d, d.lz.rep0) as u32;
            var offs: u32 = 0x100;
            while sym < 0x100 {
                mb <<= 1;
                let mbit = mb & offs;
                let b = rc_bit(d, src, end, base + ((offs + mbit + sym) as i64));
                sym = (sym << 1) | b;
                if b == 0 { offs &= ~mbit; } else { offs &= mbit; }
            }
        }
        d.lz.s_kind = SYM_LITERAL;
        d.lz.s_byte = (sym & 0xff) as! u8;
        d.lz.s_len = 1;
        d.lz.s_state = if st < 4 { 0 } else if st < 10 { st - 3 } else { st - 6 };
        return;
    }
    if rc_bit(d, src, end, LZ_IS_REP + st) == 0 {
        let len = lzma_len(d, src, end, LZ_LEN_MATCH, ps);
        let ls = if len - 2 < 3 { len - 2 } else { 3 };
        let slot = rc_tree(d, src, end, LZ_DIST_SLOT + ls * 64, 6);
        var dist: u32 = slot;
        if slot >= 4 {
            let footer = (slot >> 1) - 1;
            dist = (2 | (slot & 1)) << footer;
            if slot < 14 {
                dist += rc_tree_rev(d, src, end, LZ_DIST_SPECIAL + (dist as i64) - (slot as i64) - 1, footer as i64);
            } else {
                dist += rc_direct(d, src, end, (footer - 4) as i64) << 4;
                dist += rc_tree_rev(d, src, end, LZ_DIST_ALIGN, 4);
            }
        }
        d.lz.s_len = len;
        d.lz.s_state = if st < 7 { 7 } else { 10 };
        if dist == 0xffffffff {
            d.lz.s_kind = SYM_EOPM;
            return;
        }
        d.lz.s_kind = SYM_MATCH;
        d.lz.s_rep3 = d.lz.rep2; d.lz.s_rep2 = d.lz.rep1; d.lz.s_rep1 = d.lz.rep0; d.lz.s_rep0 = dist;
        return;
    }
    if rc_bit(d, src, end, LZ_IS_REP0 + st) == 0 {
        if rc_bit(d, src, end, LZ_IS_REP0_LONG + (st << 4) + ps) == 0 {
            d.lz.s_kind = SYM_SHORTREP;
            d.lz.s_len = 1;
            d.lz.s_state = if st < 7 { 9 } else { 11 };
            return;
        }
    } else {
        if rc_bit(d, src, end, LZ_IS_REP1 + st) == 0 {
            d.lz.s_rep0 = d.lz.rep1; d.lz.s_rep1 = d.lz.rep0;
        } else {
            if rc_bit(d, src, end, LZ_IS_REP2 + st) == 0 {
                d.lz.s_rep0 = d.lz.rep2; d.lz.s_rep1 = d.lz.rep0; d.lz.s_rep2 = d.lz.rep1;
            } else {
                d.lz.s_rep0 = d.lz.rep3; d.lz.s_rep1 = d.lz.rep0; d.lz.s_rep2 = d.lz.rep1; d.lz.s_rep3 = d.lz.rep2;
            }
        }
    }
    d.lz.s_kind = SYM_REP;
    d.lz.s_len = lzma_len(d, src, end, LZ_LEN_REP, ps);
    d.lz.s_state = if st < 7 { 8 } else { 11 };
}

// Results of lzma_run.
let LR_INPUT: i64 = 0;          // more input needed
let LR_ROOM: i64 = 1;           // room or the limit reached
let LR_EOPM: i64 = 2;           // the end marker

// Decodes symbols from src[d.sp..end] into the dictionary, making at most
// `room` bytes (*made). `left` is what the chunk (or the .lzma stream)
// has left to make, -1 for unknown; a match may not run past it. With
// `exact`, end is where the compressed data ends, and running out of it
// is an error; otherwise a symbol the input does not hold whole is
// undone, to be decoded again with more input.
fn lzma_run(d: XzReader&, src: const u8[:], end: i64, exact: bool, room: i64, left: i64) -> i64, i64 {
    var made: i64 = 0;
    // A match left over from the last call.
    if d.lz.mlen > 0 {
        var n = d.lz.mlen;
        if n > room { n = room; }
        dict_repeat(d, d.lz.rep0, n);
        d.lz.mlen -= n;
        made += n;
        if d.lz.mlen > 0 { return LR_ROOM, made; }
    }
    while made < room {
        if left >= 0 && made >= left { return LR_ROOM, made; }
        let avail = end - d.sp;
        let spec = !exact && avail < 64;
        let sp0 = d.sp;
        let range0 = d.lz.range;
        let code0 = d.lz.code;
        d.lz.spec = spec;
        d.lz.nlog = 0;
        d.lz.short = false;
        lzma_symbol(d, src, end);
        if d.lz.short {
            if exact { return ERR_DATA, made; }
            // Undo the symbol.
            var k = d.lz.nlog - 1;
            while k >= 0 { d.lz.p[d.lz.logi[k]] = d.lz.logv[k]; k--; }
            d.sp = sp0;
            d.lz.range = range0;
            d.lz.code = code0;
            d.lz.short = false;
            return LR_INPUT, made;
        }
        let kind = d.lz.s_kind;
        if kind == SYM_EOPM { d.lz.state = d.lz.s_state; return LR_EOPM, made; }
        if kind == SYM_LITERAL {
            dict_put(d, d.lz.s_byte);
            made++;
        } else {
            if !dict_has(d, d.lz.s_rep0) { return ERR_DATA, made; }
            var n = d.lz.s_len;
            if left >= 0 && made + n > left { return ERR_DATA, made; }
            if n > room - made { n = room - made; }
            dict_repeat(d, d.lz.s_rep0, n);
            made += n;
            d.lz.mlen = d.lz.s_len - n;
            d.lz.rep0 = d.lz.s_rep0; d.lz.rep1 = d.lz.s_rep1; d.lz.rep2 = d.lz.s_rep2; d.lz.rep3 = d.lz.s_rep3;
        }
        d.lz.state = d.lz.s_state;
    }
    return LR_ROOM, made;
}

// The range decoder's first five bytes: 1 when read, 0 for more input.
fn rc_init(d: XzReader&, src: const u8[:]) -> i64 {
    if src.len - d.sp < 5 { return 0; }
    if src[d.sp] != 0 { return ERR_DATA; }
    d.lz.code = get_be32(src, d.sp + 1);
    d.lz.range = 0xffffffff;
    d.sp += 5;
    return 1;
}

// --- LZMA2 -----------------------------------------------------------------

// Decodes LZMA2 into the dictionary, at most `room` bytes (*made): XR_END
// at the end of the LZMA2 stream, XR_INPUT, XR_OUTPUT, or an error.
fn lzma2_run(d: XzReader&, src: const u8[:], room: i64) -> i64, i64 {
    var made: i64 = 0;
    while true {
        if d.l2 == L2_CONTROL {
            if d.sp >= src.len { return XR_INPUT, made; }
            let c = src[d.sp];
            if made > 0 { return XR_OUTPUT, made; }     // the caller takes what was made first
            if c == 0 {
                d.sp++;
                d.l2 = L2_END;
                return XR_END, made;
            }
            let hsize: i64 = if c >= 0xc0 { 6 } else if c >= 0x80 { 5 } else { 3 };
            if c >= 0xe0 || c == 1 {
                d.l2_need_props = true;
                d.l2_need_dict_reset = false;
                dict_reset(d);
            } else if d.l2_need_dict_reset {
                return ERR_DATA, made;
            }
            if c >= 0x80 {
                if c < 0xc0 && d.l2_need_props { return ERR_DATA, made; }
            } else if c > 2 {
                return ERR_DATA, made;
            }
            if src.len - d.sp < hsize {
                // Undo nothing: the resets above are idempotent, so the
                // control byte is simply read again.
                return XR_INPUT, made;
            }
            let p = d.sp;
            if c >= 0x80 {
                d.l2_uleft = (((c & 0x1f) as i64) << 16) + ((src[p + 1] as i64) << 8) + (src[p + 2] as i64) + 1;
                d.l2_cleft = ((src[p + 3] as i64) << 8) + (src[p + 4] as i64) + 1;
                if c >= 0xc0 {
                    if !lzma_set_props(d.lz, src[p + 5]) { return ERR_DATA, made; }
                    d.l2_need_props = false;
                    lzma_reset_state(d.lz);
                } else if c >= 0xa0 {
                    lzma_reset_state(d.lz);
                }
                d.l2_rc_init = false;
                d.l2 = L2_LZMA;
            } else {
                d.l2_uleft = ((src[p + 1] as i64) << 8) + (src[p + 2] as i64) + 1;
                d.l2 = L2_COPY;
            }
            d.sp += hsize;
        } else if d.l2 == L2_COPY {
            if made >= room { return XR_OUTPUT, made; }
            var n = d.l2_uleft;
            if n > room - made { n = room - made; }
            if n > src.len - d.sp { n = src.len - d.sp; }
            if n == 0 { return XR_INPUT, made; }
            for k in n { dict_put(d, src[d.sp + k]); }
            d.sp += n;
            made += n;
            d.l2_uleft -= n;
            if d.l2_uleft == 0 { d.l2 = L2_CONTROL; }
        } else if d.l2 == L2_LZMA {
            if !d.l2_rc_init {
                if d.l2_cleft < 5 { return ERR_DATA, made; }
                let r = rc_init(d, src);
                if r < 0 { return r, made; }
                if r == 0 { return XR_INPUT, made; }
                d.l2_cleft -= 5;
                d.l2_rc_init = true;
            }
            if made >= room && d.l2_uleft > 0 { return XR_OUTPUT, made; }
            let avail = src.len - d.sp;
            let exact = avail >= d.l2_cleft;
            let end = if exact { d.sp + d.l2_cleft } else { src.len };
            let sp0 = d.sp;
            let r, n = lzma_run(d, src, end, exact, room - made, d.l2_uleft);
            d.l2_cleft -= d.sp - sp0;
            d.l2_uleft -= n;
            made += n;
            if r < 0 { return r, made; }
            if r == LR_EOPM { return ERR_DATA, made; }
            if d.l2_uleft == 0 {
                if d.lz.mlen > 0 || d.l2_cleft != 0 || d.lz.code != 0 { return ERR_DATA, made; }
                d.l2 = L2_CONTROL;
            } else if r == LR_INPUT {
                return XR_INPUT, made;
            } else if exact && d.l2_cleft == 0 && made < room {
                return ERR_DATA, made;          // the data ended before the chunk did
            } else if made >= room {
                return XR_OUTPUT, made;
            }
        } else {
            return XR_END, made;
        }
    }
    return XR_INPUT, made;
}

// --- Block data through the filters ----------------------------------------

// Moves decoded bytes along: the first decoder (LZMA2, or LZMA for .lzma)
// into the last filter stage, each stage into the one before, stage 0 to
// out. XR_CONTINUE once the block's data has ended and all of it is out.
fn block_data(d: XzReader&, src: const u8[:], out: u8[:]) -> i64 {
    let ns = d.nstages;
    while true {
        var progress = false;
        // Stage 0 to out; stage k to stage k - 1.
        for k in ns {
            let from = k;
            let ready = d.stages[from].conv - d.stages[from].rd;
            if ready > 0 {
                var n = ready;
                if from == 0 {
                    if n > out.len - d.op { n = out.len - d.op; }
                    if n > 0 {
                        let rd = d.stages[0].rd;
                        out[d.op..d.op + n].move_from(d.stages[0].buf[rd..rd + n]);
                        xz_account(d, out[d.op..d.op + n]);
                        d.op += n;
                    }
                } else {
                    xz_stage_compact(d.stages[from - 1]);
                    let room = XZ_STAGE_BUF - d.stages[from - 1].filled;
                    if n > room { n = room; }
                    if n > 0 {
                        let rd = d.stages[from].rd;
                        let f = d.stages[from - 1].filled;
                        d.stages[from - 1].buf[f..f + n].move_from(d.stages[from].buf[rd..rd + n]);
                        d.stages[from - 1].filled += n;
                        xz_stage_convert(d.stages[from - 1], false);
                    }
                }
                if n > 0 { d.stages[from].rd += n; progress = true; }
            }
            // The end passes down once a stage is empty.
            if from > 0 && d.stages[from].upstream_end && d.stages[from].rd == d.stages[from].filled
               && !d.stages[from - 1].upstream_end {
                d.stages[from - 1].upstream_end = true;
                xz_stage_convert(d.stages[from - 1], false);
                progress = true;
            }
        }
        if ns > 0 && d.stages[0].upstream_end && d.stages[0].rd == d.stages[0].filled { return XR_CONTINUE; }
        // The decoder, into the last stage or out.
        let decoder_done = if ns > 0 { d.stages[ns - 1].upstream_end } else { false };
        if !decoder_done {
            var room: i64 = 0;
            if ns > 0 {
                xz_stage_compact(d.stages[ns - 1]);
                room = XZ_STAGE_BUF - d.stages[ns - 1].filled;
            } else {
                room = out.len - d.op;
            }
            if room > d.dsize { room = d.dsize; }
            var r: i64 = 0;
            var made: i64 = 0;
            if d.mode == XZ_MODE_ALONE {
                r, made = alone_run(d, src, room);
            } else {
                r, made = lzma2_run(d, src, room);
            }
            if made > 0 {
                progress = true;
                if ns > 0 {
                    let f = d.stages[ns - 1].filled;
                    dict_copy_last(d, made, d.stages[ns - 1].buf[f..f + made]);
                    d.stages[ns - 1].filled += made;
                    xz_stage_convert(d.stages[ns - 1], false);
                } else {
                    dict_copy_last(d, made, out[d.op..d.op + made]);
                    xz_account(d, out[d.op..d.op + made]);
                    d.op += made;
                }
            }
            if r < 0 { return r; }
            if r == XR_END {
                if ns == 0 { return XR_CONTINUE; }
                d.stages[ns - 1].upstream_end = true;
                xz_stage_convert(d.stages[ns - 1], false);
                progress = true;
            } else if !progress {
                return if r == XR_INPUT { XR_INPUT } else { XR_OUTPUT };
            }
        } else if !progress {
            return XR_OUTPUT;
        }
    }
    return XR_INPUT;
}

fn xz_stage_compact(s: XzStage&) {
    if s.rd == 0 { return; }
    let n = s.filled - s.rd;
    if n > 0 {
        for k in n { s.buf[k] = s.buf[s.rd + k]; }
    }
    s.conv -= s.rd;
    s.filled = n;
    s.rd = 0;
}

// Output of a block: its check, and its size.
fn xz_account(d: XzReader&, p: const u8[:]) {
    if d.mode != XZ_MODE_XZ { return; }
    d.busize += p.len;
    if d.check == XZ_CHECK_CRC32 { d.crc32 = crc32_update(d.crc32, p); }
    else if d.check == XZ_CHECK_CRC64 { d.crc64 = crc64_update(d.crc64, p); }
    else if d.check == XZ_CHECK_SHA256 { sha256_update(d.sha, p); }
}

// --- .lzma -----------------------------------------------------------------

fn alone_run(d: XzReader&, src: const u8[:], room: i64) -> i64, i64 {
    if !d.l2_rc_init {
        let r = rc_init(d, src);
        if r < 0 { return r, 0; }
        if r == 0 { return XR_INPUT, 0; }
        d.l2_rc_init = true;
    }
    if d.alone_left == 0 {
        // The known size is reached: done if the range decoder is, else
        // an end marker must follow.
        if d.lz.mlen > 0 { return ERR_DATA, 0; }
        if d.lz.code == 0 && !d.alone_eopm { return XR_END, 0; }
        d.alone_eopm = true;
        let r, n = lzma_run(d, src, src.len, false, 1, -1);
        if r < 0 { return r, 0; }
        if r == LR_INPUT { return XR_INPUT, 0; }
        if r != LR_EOPM || n > 0 { return ERR_DATA, 0; }
        if d.lz.code != 0 { return ERR_DATA, 0; }
        return XR_END, 0;
    }
    if room == 0 { return XR_OUTPUT, 0; }
    let r, made = lzma_run(d, src, src.len, false, room, d.alone_left);
    if d.alone_left > 0 { d.alone_left -= made; }
    if r < 0 { return r, made; }
    if r == LR_EOPM {
        // An end marker before a known size is reached is an error.
        if d.alone_left > 0 || d.lz.code != 0 { return ERR_DATA, made; }
        return XR_END, made;
    }
    if r == LR_INPUT { return XR_INPUT, made; }
    if d.alone_left == 0 { return XR_CONTINUE, made; }
    return XR_OUTPUT, made;
}

// --- The container ---------------------------------------------------------

// A VLI at src[p..]: value, length (0: incomplete within `end`, -1: not valid).
fn xz_vli(src: const u8[:], p: i64, end: i64) -> u64, i64 {
    var v: u64 = 0;
    for k in 9 {
        if p + k >= end { return 0, 0; }
        let b = src[p + k];
        v |= ((b & 0x7f) as u64) << ((7 * k) as! u64);
        if (b & 0x80) == 0 {
            if b == 0 && k > 0 { return 0, -1; }
            return v, k + 1;
        }
    }
    return 0, -1;
}

fn rec_mix(h: u64, a: i64, b: i64) -> u64 {
    var t: u8[16] = [0; 16];
    for k in 8 {
        t[k] = ((a >> ((k * 8) as! u64)) & 0xff) as! u8;
        t[8 + k] = ((b >> ((k * 8) as! u64)) & 0xff) as! u8;
    }
    return crc64_update(h ^ 0x9e3779b97f4a7c15, t) + h * 31;
}

fn xz_stream_header(d: XzReader&, src: const u8[:]) -> i64 {
    if src.len - d.sp < 12 { return XR_INPUT; }
    let p = d.sp;
    for k in 6 {
        if src[p + k] != XZ_MAGIC[k] { return if d.streams == 0 { ERR_HEADER } else { ERR_TRAILING }; }
    }
    if crc32(src[p + 6..p + 8]) != get_le32(src, p + 8) { return ERR_DATA; }
    if src[p + 6] != 0 || (src[p + 7] & 0xf0) != 0 { return ERR_UNSUPPORTED; }
    d.flags1 = src[p + 7];
    d.check = (src[p + 7] & 15) as i64;
    d.check_size = XZ_CHECK_SIZES[d.check];
    if d.check != XZ_CHECK_NONE && d.check != XZ_CHECK_CRC32 && d.check != XZ_CHECK_CRC64 && d.check != XZ_CHECK_SHA256 {
        d.unverified = true;
    }
    d.sp += 12;
    d.nblocks = 0; d.sum_unpadded = 0; d.sum_uncomp = 0; d.rec_hash = 0;
    d.stage = XS_BLOCK_HEADER;
    return XR_CONTINUE;
}

fn xz_block_header(d: XzReader&, src: const u8[:]) -> i64 {
    if d.sp >= src.len { return XR_INPUT; }
    let b0 = src[d.sp];
    if b0 == 0 {
        // The index.
        d.ix_crc = crc32_update(0, src[d.sp..d.sp + 1]);
        d.sp++;
        d.ix_size = 1;
        d.ix_part = 0;
        d.ix_sum_unpadded = 0; d.ix_sum_uncomp = 0; d.ix_hash = 0;
        d.stage = XS_INDEX;
        return XR_CONTINUE;
    }
    let hsize = ((b0 as i64) + 1) * 4;
    if src.len - d.sp < hsize { return XR_INPUT; }
    let h = src[d.sp..d.sp + hsize];
    let n = hsize - 4;
    if crc32(h[..n]) != get_le32(h, n) { return ERR_DATA; }
    let fl = h[1];
    if (fl & 0x3c) != 0 { return ERR_UNSUPPORTED; }
    var p: i64 = 2;
    d.bh_csize = -1;
    d.bh_usize = -1;
    if (fl & 0x40) != 0 {
        let v, l = xz_vli(h, p, n);
        if l <= 0 { return ERR_DATA; }
        p += l;
        // Not zero, and the block's unpadded size a valid VLI.
        if v == 0 || v > (0x7ffffffffffffffc - (hsize + d.check_size) as! u64) { return ERR_DATA; }
        d.bh_csize = v as! i64;
    }
    if (fl & 0x80) != 0 {
        let v, l = xz_vli(h, p, n);
        if l <= 0 { return ERR_DATA; }
        p += l;
        d.bh_usize = v as! i64;
    }
    let nf = ((fl & 3) as i64) + 1;
    var ids: u64[4] = [0; 4];
    var prop0: u8[4] = [0; 4];
    var starts: u32[4] = [0; 4];
    for k in nf {
        let id, l = xz_vli(h, p, n);
        if l <= 0 { return ERR_DATA; }
        p += l;
        if id >= ((1 as u64) << 62) { return ERR_DATA; }
        let ps, l2 = xz_vli(h, p, n);
        if l2 <= 0 { return ERR_DATA; }
        p += l2;
        if ps > (n - p) as! u64 { return ERR_DATA; }
        let psize = ps as! i64;
        ids[k] = id;
        if id == XZ_FILTER_LZMA2 || id == XZ_FILTER_DELTA {
            if psize != 1 { return ERR_UNSUPPORTED; }
            prop0[k] = h[p];
        } else if id == XZ_FILTER_X86 || id == XZ_FILTER_POWERPC || id == XZ_FILTER_IA64 || id == XZ_FILTER_ARM
               || id == XZ_FILTER_ARMTHUMB || id == XZ_FILTER_SPARC || id == XZ_FILTER_ARM64 {
            if psize == 4 { starts[k] = get_le32(h, p); }
            else if psize != 0 { return ERR_UNSUPPORTED; }
        } else {
            return ERR_UNSUPPORTED;
        }
        p += psize;
    }
    while p < n {
        if h[p] != 0 { return ERR_UNSUPPORTED; }
        p++;
    }
    // The chain: LZMA2 last, and only last.
    for k in nf {
        if (ids[k] == XZ_FILTER_LZMA2) != (k == nf - 1) { return ERR_UNSUPPORTED; }
    }
    if prop0[nf - 1] > 40 { return ERR_UNSUPPORTED; }
    for k in nf - 1 {
        // liblzma: Delta, then the stage's options; no LZMA2 props checks here.
        let dist = (prop0[k] as i64) + 1;
        xz_stage_reset(d.stages[k], ids[k], starts[k], dist);
    }
    d.nstages = nf - 1;
    let ds = lzma2_dict_size(prop0[nf - 1]);
    var dsize = ds as! i64;
    if dsize < 4096 { dsize = 4096; }
    dsize = (dsize + 15) & ~15;
    if dsize > d.memlimit { return ERR_LIMIT; }
    // A new block: a fresh LZMA2 decoder (the dictionary's storage is kept).
    d.dsize = dsize;
    dict_reset(d);
    d.l2 = L2_CONTROL;
    d.l2_need_props = true;
    d.l2_need_dict_reset = true;
    d.lz.mlen = 0;
    d.bh_size = hsize;
    d.bcsize = 0;
    d.busize = 0;
    d.bpadn = 0;
    d.crc32 = 0;
    d.crc64 = 0;
    d.sha = sha256_new();
    d.sp += hsize;
    d.stage = XS_BLOCK_DATA;
    return XR_CONTINUE;
}

fn xz_index(d: XzReader&, src: const u8[:]) -> i64 {
    while true {
        let start = d.sp;
        if d.ix_part <= 2 {
            // 0: the count, 1: a record's unpadded size, 2: its uncompressed size.
            if d.ix_part == 1 || d.ix_part == 2 {
                if d.ix_left == 0 && d.ix_part == 1 { d.ix_part = 3; continue; }
            }
            let v, l = xz_vli(src, d.sp, src.len);
            if l < 0 { return ERR_DATA; }
            if l == 0 {
                if src.len - d.sp >= 9 { return ERR_DATA; }
                return XR_INPUT;
            }
            d.sp += l;
            if d.ix_part == 0 {
                if v > 0x7fffffffffffffff { return ERR_DATA; }
                d.ix_count = v as! i64;
                d.ix_left = d.ix_count;
                if d.ix_count != d.nblocks { return ERR_DATA; }
                d.ix_part = 1;
            } else if d.ix_part == 1 {
                if v < 5 || v > 0x7ffffffffffffffc { return ERR_DATA; }
                d.ix_unpadded = v as! i64;
                d.ix_part = 2;
            } else {
                if v > 0x7fffffffffffffff { return ERR_DATA; }
                d.ix_sum_unpadded += d.ix_unpadded;
                d.ix_sum_uncomp += v as! i64;
                d.ix_hash = rec_mix(d.ix_hash, d.ix_unpadded, v as! i64);
                d.ix_left--;
                d.ix_part = 1;
            }
        } else if d.ix_part == 3 {
            // Padding to a multiple of four.
            if (d.ix_size + (d.sp - start)) % 4 != 0 {
                if d.sp >= src.len { return XR_INPUT; }
                if src[d.sp] != 0 { return ERR_DATA; }
                d.sp++;
            } else {
                d.ix_part = 4;
            }
        } else {
            if src.len - d.sp < 4 { return XR_INPUT; }
            if get_le32(src, d.sp) != d.ix_crc { return ERR_DATA; }
            if d.ix_sum_unpadded != d.sum_unpadded || d.ix_sum_uncomp != d.sum_uncomp || d.ix_hash != d.rec_hash {
                return ERR_DATA;
            }
            d.sp += 4;
            d.ix_size += 4;
            d.stage = XS_FOOTER;
            return XR_CONTINUE;
        }
        d.ix_crc = crc32_update(d.ix_crc, src[start..d.sp]);
        d.ix_size += d.sp - start;
    }
    return XR_INPUT;
}

fn xz_footer(d: XzReader&, src: const u8[:]) -> i64 {
    if src.len - d.sp < 12 { return XR_INPUT; }
    let p = d.sp;
    if src[p + 10] != 'Y' || src[p + 11] != 'Z' { return ERR_DATA; }
    if crc32(src[p + 4..p + 10]) != get_le32(src, p) { return ERR_DATA; }
    if src[p + 8] != 0 || (src[p + 9] & 0xf0) != 0 { return ERR_UNSUPPORTED; }
    let backward = ((get_le32(src, p + 4) as i64) + 1) * 4;
    if backward != d.ix_size { return ERR_DATA; }
    if src[p + 9] != d.flags1 { return ERR_DATA; }
    d.sp += 12;
    d.streams++;
    d.spad = 0;
    d.stage = if d.single { XS_DONE } else { XS_PADDING };
    return XR_CONTINUE;
}

// Runs the stages over src from d.sp, writing to out from d.op.
fn xz_run(d: XzReader&, src: const u8[:], out: u8[:]) -> i64 {
    while true {
        var r: i64 = XR_CONTINUE;
        let st = d.stage;
        if st == XS_STREAM_HEADER {
            r = xz_stream_header(d, src);
        } else if st == XS_BLOCK_HEADER {
            r = xz_block_header(d, src);
        } else if st == XS_BLOCK_DATA {
            let sp0 = d.sp;
            r = block_data(d, src, out);
            d.bcsize += d.sp - sp0;
            if d.mode == XZ_MODE_XZ {
                if (d.bh_csize >= 0 && d.bcsize > d.bh_csize) || (d.bh_usize >= 0 && d.busize > d.bh_usize) {
                    r = ERR_DATA;
                }
            }
            if r == XR_CONTINUE {
                if d.mode == XZ_MODE_LZMA2 || d.mode == XZ_MODE_ALONE {
                    d.stage = XS_DONE;
                } else {
                    if (d.bh_csize >= 0 && d.bcsize != d.bh_csize) || (d.bh_usize >= 0 && d.busize != d.bh_usize) {
                        r = ERR_DATA;
                    } else {
                        d.stage = XS_BLOCK_PADDING;
                    }
                }
            }
        } else if st == XS_BLOCK_PADDING {
            if (d.bcsize + d.bpadn) % 4 != 0 {
                if d.sp >= src.len { r = XR_INPUT; }
                else if src[d.sp] != 0 { r = ERR_DATA; }
                else { d.sp++; d.bpadn++; }
            } else {
                d.stage = XS_CHECK;
            }
        } else if st == XS_CHECK {
            let n = d.check_size;
            if src.len - d.sp < n {
                r = XR_INPUT;
            } else {
                let c = src[d.sp..d.sp + n];
                var ok = true;
                if d.check == XZ_CHECK_CRC32 { ok = get_le32(c, 0) == d.crc32; }
                else if d.check == XZ_CHECK_CRC64 { ok = get_le64(c, 0) == d.crc64; }
                else if d.check == XZ_CHECK_SHA256 {
                    let h = sha256_final(d.sha);
                    ok = h[..] == c;
                }
                if !ok {
                    r = ERR_CHECKSUM;
                } else {
                    d.sp += n;
                    // The block's record: unpadded size (without the padding).
                    let unpadded = d.bh_size + d.check_size + d.bcsize;
                    d.nblocks++;
                    d.sum_unpadded += unpadded;
                    d.sum_uncomp += d.busize;
                    d.rec_hash = rec_mix(d.rec_hash, unpadded, d.busize);
                    d.stage = XS_BLOCK_HEADER;
                }
            }
        } else if st == XS_INDEX {
            r = xz_index(d, src);
        } else if st == XS_FOOTER {
            r = xz_footer(d, src);
        } else if st == XS_PADDING {
            if d.sp >= src.len {
                r = XR_INPUT;
            } else if src[d.sp] == 0 {
                d.sp++;
                d.spad++;
            } else {
                if d.spad % 4 != 0 { r = ERR_DATA; }
                else { d.stage = XS_STREAM_HEADER; }
            }
        } else if st == XS_ALONE_HEADER {
            if src.len - d.sp < 13 {
                r = XR_INPUT;
            } else {
                let p = d.sp;
                if !lzma_set_props(d.lz, src[p]) {
                    r = ERR_HEADER;
                } else {
                    var ds = get_le32(src, p + 1) as i64;
                    if ds < 4096 { ds = 4096; }
                    ds = (ds + 15) & ~15;
                    if ds > d.memlimit {
                        r = ERR_LIMIT;
                    } else {
                        d.dsize = ds;
                        let size = get_le64(src, p + 5);
                        d.alone_left = if size == 0xffffffffffffffff { -1 } else { size as! i64 };
                        if d.alone_left < -1 { r = ERR_HEADER; }
                        lzma_reset_state(d.lz);
                        d.l2_rc_init = false;
                        d.sp += 13;
                        d.stage = XS_BLOCK_DATA;
                    }
                }
            }
        } else if st == XS_DONE {
            return XR_END;
        } else {
            return d.err;
        }
        if r != XR_CONTINUE { return r; }
    }
    return XR_INPUT;
}

// --- Feeding ---------------------------------------------------------------

fn xz_fail(d: XzReader&, e: i64) -> i64 {
    d.err = e;
    d.stage = XS_FAILED;
    return e;
}

fn xz_status(d: const XzReader&, r: i64) -> i64 {
    if r == XR_END { return STREAM_END; }
    if d.mode == XZ_MODE_XZ && d.stage == XS_PADDING && d.spad % 4 == 0 && d.tlen == 0 { return STREAM_END; }
    return 0;
}

// Decodes what it can of `input` into `out`: the bytes of input taken,
// the bytes written to out, and 0, STREAM_END or an error.
fn xz_read(d: XzReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    if d.err < 0 { return 0, 0, d.err; }
    d.op = 0;
    var taken: i64 = 0;
    while true {
        let before = taken;
        if d.tlen > 0 {
            // Input kept from before, with as much new input as fits.
            let old = d.tlen;
            var add = input.len - taken;
            if add > XZ_TCAP - old { add = XZ_TCAP - old; }
            d.tbuf[old..old + add].move_from(input[taken..taken + add]);
            d.tlen = old + add;
            d.sp = 0;
            let r = xz_run(d, d.tbuf[..d.tlen], out);
            if r < 0 { return taken, d.op, xz_fail(d, r); }
            let sp = d.sp;
            if sp >= old {
                // Past what was kept: what is left came from input.
                taken = before + (sp - old);
                d.tlen = 0;
                if r != XR_INPUT { return taken, d.op, xz_status(d, r); }
                if taken >= input.len { return taken, d.op, xz_status(d, r); }
                continue;
            }
            if r == XR_INPUT && before + add == input.len {
                // Keep all of it, the new input too.
                let n = d.tlen - sp;
                for k in n { d.tbuf[k] = d.tbuf[sp + k]; }
                d.tlen = n;
                return input.len, d.op, xz_status(d, r);
            }
            // Give back the new input; keep the old that is left.
            let n = old - sp;
            for k in n { d.tbuf[k] = d.tbuf[sp + k]; }
            d.tlen = n;
            taken = before;
            if r == XR_INPUT {
                if sp == 0 { return taken, d.op, xz_fail(d, ERR_DATA); }
                continue;
            }
            return taken, d.op, xz_status(d, r);
        }
        d.sp = 0;
        let rest = input[taken..];
        let r = xz_run(d, rest, out);
        if r < 0 { return taken + d.sp, d.op, xz_fail(d, r); }
        if r == XR_INPUT {
            let n = rest.len - d.sp;
            if n > XZ_TCAP { return taken, d.op, xz_fail(d, ERR_DATA); }
            d.tbuf[..n].move_from(rest[d.sp..]);
            d.tlen = n;
            return input.len, d.op, xz_status(d, r);
        }
        taken += d.sp;
        return taken, d.op, xz_status(d, r);
    }
    return taken, d.op, 0;
}

// Decodes a whole .xz file (any number of streams) into out, at most
// `limit` bytes (-1: no limit): 0, or an error (ERR_TRUNCATED when it ends
// early, ERR_LIMIT past the limit).
fn xz_decode(data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var d = xz_reader();
    return xz_decode_with(d, data, out, limit);
}

// The same for a .lzma file; bytes after its end are an error.
fn lzma_decode(data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var d = lzma_reader();
    return xz_decode_with(d, data, out, limit);
}

fn xz_decode_with(d: XzReader&, data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var p = 0;
    while true {
        let at = out.len;
        var room: i64 = 1 << 16;
        if limit >= 0 && at + room > limit + 1 { room = limit + 1 - at; }
        out.resize(at + room, 0);
        let used, made, st = xz_read(d, data[p..], out[at..]);
        out.resize(at + made);
        p += used;
        if st < 0 { return st; }
        if limit >= 0 && out.len > limit { return ERR_LIMIT; }
        if d.stage == XS_DONE {
            if p < data.len { return ERR_TRAILING; }
            return 0;
        }
        if p >= data.len && made < room {
            if xz_done(d) { return 0; }
            return ERR_TRUNCATED;
        }
    }
    return 0;
}

// At the end of the input: 0 when the input was whole (xz_done), else
// ERR_TRUNCATED, or the error the reader stopped at.
fn xz_finish(d: const XzReader&) -> i64 {
    if d.err < 0 { return d.err; }
    if xz_done(d) { return 0; }
    return ERR_TRUNCATED;
}
