// compress: compression formats and archives, after Go's compress/* and
// archive/* packages. This module holds what the formats share: the error
// codes every codec returns, and the checksums (CRC-32 of gzip, zip and
// bzip2's own CRC-32 lives with bzip2; Adler-32 of zlib; CRC-64 of xz).
//
// The codecs are in modules of their own, all in namespace `compress`:
//
//   compress.flate   DEFLATE (RFC 1951): inflate and deflate, levels 0-9
//   compress.gzip    gzip (RFC 1952) readers and writers
//   compress.zlib    zlib (RFC 1950) readers and writers
//   compress.lzw     LZW as Go's compress/lzw (LSB and MSB orders)
//   compress.bzip2   bzip2
//   compress.xz      xz, LZMA2 and .lzma
//   compress.zip     zip archives
//   compress.tar     tar archives
//
// Every streaming codec works on buffers the caller supplies: no codec
// reads or writes a file, and none grows memory of its own past a bound
// fixed when it is made.

namespace compress;

import std;

// --- Results ---------------------------------------------------------------

// A step of a codec returns 0 when it needs more input (or more room for
// its output), STREAM_END when the stream is complete, or one of the
// errors, all negative. After an error a codec takes nothing more and
// returns the same error again.
let STREAM_END: i64 = 1;

let ERR_HEADER: i64 = -1;       // not this format's header, or a header field that is not valid
let ERR_DATA: i64 = -2;         // the compressed data is not valid
let ERR_CHECKSUM: i64 = -3;     // a checksum or a length that does not match the data
let ERR_TRAILING: i64 = -4;     // bytes after the end that the format does not allow
let ERR_DICTIONARY: i64 = -5;   // a preset dictionary is needed (or the one given is not it)
let ERR_UNSUPPORTED: i64 = -6;  // valid, but a feature this package does not implement
let ERR_LIMIT: i64 = -7;        // past a limit the caller set (output size, memory)
let ERR_TRUNCATED: i64 = -8;    // the input ended inside the stream (unexpected EOF)
let ERR_ARGUMENT: i64 = -9;     // a bad argument: a level out of range, a call out of order
let ERR_INSECURE_PATH: i64 = -10;   // an archive entry's name is not a local path (zip, tar)
let ERR_FORMAT: i64 = -11;      // an archive's structure is not valid
let ERR_TOO_LARGE: i64 = -12;   // a value too large for the format (a writer's input)

// A short description of a result code.
fn error_text(code: i64) -> const u8[:] {
    match code {
        0 => "ok",
        1 => "end of stream",
        -1 => "invalid header",
        -2 => "invalid compressed data",
        -3 => "checksum mismatch",
        -4 => "trailing data after the stream",
        -5 => "preset dictionary needed or wrong",
        -6 => "unsupported feature",
        -7 => "limit exceeded",
        -8 => "unexpected end of input",
        -9 => "invalid argument",
        -10 => "insecure path in archive",
        -11 => "invalid archive format",
        -12 => "value too large for the format",
        _ => "unknown error",
    }
}

// --- CRC-32 (IEEE 802.3, reflected, as gzip, zip and PNG use it) -----------

fn crc32_make_table() -> u32[2048] {
    var t: u32[2048] = [0; 2048];
    for n in 256 {
        var c = n as! u32;
        for k in 8 { c = if (c & 1) != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 }; }
        t[n] = c;
    }
    for n in 256 {
        var c = t[n];
        for k in 1..8 {
            c = t[c & 0xff] ^ (c >> 8);
            t[k * 256 + n] = c;
        }
    }
    return t;
}

// Eight tables of 256 (slicing by 8).
let CRC32_TABLE: u32[2048] = crc32_make_table();

// The CRC-32 of crc's data followed by p: crc32_update(0, a ++ b) ==
// crc32_update(crc32_update(0, a), b). Start from 0.
fn crc32_update(crc: u32, p: const u8[:]) -> u32 {
    var c = crc ^ 0xffffffff;
    var i = 0;
    let n = p.len;
    while i + 8 <= n {
        let a = c ^ (p[i] | (p[i + 1] as u32) << 8 | (p[i + 2] as u32) << 16 | (p[i + 3] as u32) << 24);
        c = CRC32_TABLE[1792 + (a & 0xff)] ^ CRC32_TABLE[1536 + ((a >> 8) & 0xff)]
          ^ CRC32_TABLE[1280 + ((a >> 16) & 0xff)] ^ CRC32_TABLE[1024 + (a >> 24)]
          ^ CRC32_TABLE[768 + (p[i + 4] as i64)] ^ CRC32_TABLE[512 + (p[i + 5] as i64)]
          ^ CRC32_TABLE[256 + (p[i + 6] as i64)] ^ CRC32_TABLE[p[i + 7]];
        i += 8;
    }
    while i < n {
        c = CRC32_TABLE[(c ^ p[i]) & 0xff] ^ (c >> 8);
        i++;
    }
    return c ^ 0xffffffff;
}

fn crc32(p: const u8[:]) -> u32 { crc32_update(0, p) }

// --- Adler-32 (RFC 1950) ---------------------------------------------------

// The Adler-32 of adler's data followed by p. Start from 1.
fn adler32_update(adler: u32, p: const u8[:]) -> u32 {
    var s1: u64 = adler & 0xffff;
    var s2: u64 = adler >> 16;
    var i = 0;
    let n = p.len;
    while i < n {
        // 5552 bytes is the most that cannot overflow 32 bits before the
        // reduction (zlib's NMAX); 64-bit sums allow far more, but keep it.
        var end = i + 5552;
        if end > n { end = n; }
        while i < end {
            s1 += p[i];
            s2 += s1;
            i++;
        }
        s1 %= 65521;
        s2 %= 65521;
    }
    return ((s2 << 16) | s1) as! u32;
}

fn adler32(p: const u8[:]) -> u32 { adler32_update(1, p) }

// --- CRC-64 (ECMA-182, reflected, as xz uses it) ---------------------------

fn crc64_make_table() -> u64[256] {
    var t: u64[256] = [0; 256];
    for n in 256 {
        var c = n as! u64;
        for k in 8 { c = if (c & 1) != 0 { 0xc96c5795d7870f42 ^ (c >> 1) } else { c >> 1 }; }
        t[n] = c;
    }
    return t;
}

let CRC64_TABLE: u64[256] = crc64_make_table();

// The CRC-64 of crc's data followed by p. Start from 0.
fn crc64_update(crc: u64, p: const u8[:]) -> u64 {
    var c = crc ^ 0xffffffffffffffff;
    for b in p { c = CRC64_TABLE[(c ^ b) & 0xff] ^ (c >> 8); }
    return c ^ 0xffffffffffffffff;
}

fn crc64(p: const u8[:]) -> u64 { crc64_update(0, p) }

// --- Little helpers the formats share --------------------------------------

fn get_le16(m: const u8[:], p: i64) -> u32 { m[p] | (m[p + 1] as u32) << 8 }

fn get_le32(m: const u8[:], p: i64) -> u32 {
    m[p] | (m[p + 1] as u32) << 8 | (m[p + 2] as u32) << 16 | (m[p + 3] as u32) << 24
}

fn get_le64(m: const u8[:], p: i64) -> u64 { get_le32(m, p) | (get_le32(m, p + 4) as u64) << 32 }

fn get_be32(m: const u8[:], p: i64) -> u32 {
    (m[p] as u32) << 24 | (m[p + 1] as u32) << 16 | (m[p + 2] as u32) << 8 | m[p + 3]
}

fn put_le16(out: u8[>..]&, v: u64) {
    out.push((v & 0xff) as! u8);
    out.push(((v >> 8) & 0xff) as! u8);
}

fn put_le32(out: u8[>..]&, v: u64) {
    for k in 4 { out.push(((v >> ((k * 8) as! u64)) & 0xff) as! u8); }
}

fn put_le64(out: u8[>..]&, v: u64) {
    for k in 8 { out.push(((v >> ((k * 8) as! u64)) & 0xff) as! u8); }
}

fn put_be32(out: u8[>..]&, v: u64) {
    for k in 4 { out.push(((v >> (((3 - k) * 8) as! u64)) & 0xff) as! u8); }
}
