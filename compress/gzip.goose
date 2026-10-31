// compress.gzip: the gzip format (RFC 1952), as Go's compress/gzip: a
// reader of one member or of several in a row (multistream, the default),
// and a writer.
//
//   var r = compress::gzip_reader();
//   let used, made, st = compress::gzip_read(r, input, out);
//   // st: 0 = more input or room, STREAM_END = a member ended (complete
//   // if no more input comes), or an error < 0
//   compress::gzip_done(r)                     // at the end of the input
//
// The first member's header is kept: r.name, r.comment, r.extra (bytes as
// they are in the file: gzip's strings are Latin-1, and
// gzip_latin1_to_utf8 gives them as Go's Header does), r.mtime, r.os.
//
// What Go refuses, this refuses: a header whose magic, method or FHCRC is
// wrong (ERR_HEADER), a name or comment of 512 bytes or more with its NUL
// (Go's limit, ERR_HEADER), a CRC-32 or ISIZE that does not match
// (ERR_CHECKSUM), the input ending inside a member (ERR_TRUNCATED from
// gzip_finish), and after a member, anything but another member: ten or
// more bytes that are not a header are ERR_HEADER, fewer are ERR_TRUNCATED,
// exactly as Go reads them. Go ignores the reserved flag bits and XFL, and
// so does this.

namespace compress;

import std;
import .flate;
import .deflate;


let GZ_HEADER: u8 = 0;      // reading a member's header
let GZ_DATA: u8 = 1;        // inflating
let GZ_TRAILER: u8 = 2;     // CRC-32 and ISIZE
let GZ_END: u8 = 3;         // a member ended
let GZ_FAILED: u8 = 4;

// Header parts, read as they come.
let GH_FIXED: u8 = 0;
let GH_XLEN: u8 = 1;
let GH_EXTRA: u8 = 2;
let GH_NAME: u8 = 3;
let GH_COMMENT: u8 = 4;
let GH_HCRC: u8 = 5;

let GZIP_FTEXT: u8 = 1;
let GZIP_FHCRC: u8 = 2;
let GZIP_FEXTRA: u8 = 4;
let GZIP_FNAME: u8 = 8;
let GZIP_FCOMMENT: u8 = 16;

// The operating system byte Go writes: 255, unknown.
let GZIP_OS_UNKNOWN: u8 = 255;

struct GzipReader {
    state: u8,
    multistream: bool,
    members: i64,               // members ended
    gh: u8,                     // the header part being read
    flags: u8,
    hbuf: u8[..10],             // the fixed part, and XLEN and FHCRC
    xleft: i64,                 // FEXTRA bytes still to read
    slen: i64,                  // bytes of the name or comment so far
    hcrc: u32,                  // CRC-32 of the header so far
    crc: u32, size: u32,        // of the member's data so far
    err: i64,
    inf: Inflate,
    // The first member's header.
    has_header: bool,
    mtime: u32, xfl: u8, os: u8, hflags: u8,
    name: u8[..511], comment: u8[..511],
    extra: u8[..65535],
}

fn gzip_reader() -> GzipReader {
    GzipReader {
        state: GZ_HEADER, multistream: true, members: 0, gh: GH_FIXED, flags: 0, hbuf: [],
        xleft: 0, slen: 0, hcrc: 0, crc: 0, size: 0, err: 0, inf: inflate_reader(),
        has_header: false, mtime: 0, xfl: 0, os: 0, hflags: 0, name: [], comment: [], extra: [],
    }
}

// Multistream off: the reader stops after one member, taking none of
// what follows it (Go's Reader.Multistream(false)).
fn gzip_set_multistream(r: GzipReader&, on: bool) { r.multistream = on; }

// Reads the header from input[at..]: the bytes taken, and 1 when the
// header is complete, 0 when more input is needed, or an error.
fn gzip_header(r: GzipReader&, input: const u8[:]) -> i64, i64 {
    var p: i64 = 0;
    let n = input.len;
    let first = r.members == 0;
    loop {
        if r.gh == GH_FIXED {
            while r.hbuf.len < 10 && p < n {
                r.hbuf.push(input[p]);
                p++;
            }
            if r.hbuf.len < 10 { return p, 0; }
            let h = r.hbuf[..];
            if h[0] != 0x1f || h[1] != 0x8b || h[2] != 8 { return p, ERR_HEADER; }
            r.flags = h[3];
            if first {
                r.has_header = true;
                r.hflags = h[3];
                r.mtime = get_le32(h, 4);
                r.xfl = h[8];
                r.os = h[9];
            }
            r.hcrc = crc32_update(0, h);
            r.hbuf.clear();
            r.gh = GH_XLEN;
        } else if r.gh == GH_XLEN {
            if (r.flags & GZIP_FEXTRA) == 0 {
                r.gh = GH_NAME;
                continue;
            }
            while r.hbuf.len < 2 && p < n {
                r.hbuf.push(input[p]);
                p++;
            }
            if r.hbuf.len < 2 { return p, 0; }
            r.xleft = get_le16(r.hbuf, 0) as i64;
            r.hcrc = crc32_update(r.hcrc, r.hbuf);
            r.hbuf.clear();
            r.gh = GH_EXTRA;
        } else if r.gh == GH_EXTRA {
            let k = min(r.xleft, n - p);
            let part = input[p..p + k];
            if first { r.extra.append(part); }
            r.hcrc = crc32_update(r.hcrc, part);
            p += k;
            r.xleft -= k;
            if r.xleft > 0 { return p, 0; }
            r.gh = GH_NAME;
        } else if r.gh == GH_NAME || r.gh == GH_COMMENT {
            let is_name = r.gh == GH_NAME;
            let flag = if is_name { GZIP_FNAME } else { GZIP_FCOMMENT };
            if (r.flags & flag) == 0 {
                r.gh = if is_name { GH_COMMENT } else { GH_HCRC };
                r.slen = 0;
                continue;
            }
            var ended = false;
            let from = p;
            while p < n {
                let c = input[p];
                p++;
                if c == 0 {
                    ended = true;
                    break;
                }
                // Go keeps a string in 512 bytes with its NUL.
                if r.slen >= 511 { return p, ERR_HEADER; }
                if first {
                    if is_name { r.name.push(c); } else { r.comment.push(c); }
                }
                r.slen++;
            }
            r.hcrc = crc32_update(r.hcrc, input[from..p]);
            if !ended { return p, 0; }
            r.slen = 0;
            r.gh = if is_name { GH_COMMENT } else { GH_HCRC };
        } else {
            if (r.flags & GZIP_FHCRC) != 0 {
                while r.hbuf.len < 2 && p < n {
                    r.hbuf.push(input[p]);
                    p++;
                }
                if r.hbuf.len < 2 { return p, 0; }
                if get_le16(r.hbuf, 0) != (r.hcrc & 0xffff) { return p, ERR_HEADER; }
                r.hbuf.clear();
            }
            r.gh = GH_FIXED;
            return p, 1;
        }
    }
    return p, 0;
}

// Decodes what of `input` it can into out: the bytes taken, the bytes
// written, and 0, STREAM_END (a member ended: complete unless more input
// follows; with multistream on, further input is read as the next
// member), or an error.
fn gzip_read(r: GzipReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    if r.err != 0 { return 0, 0, r.err; }
    var ip: i64 = 0;
    var op: i64 = 0;
    loop {
        if r.state == GZ_HEADER {
            let used, st = gzip_header(r, input[ip..]);
            ip += used;
            if st < 0 {
                r.err = st;
                r.state = GZ_FAILED;
                return ip, op, st;
            }
            if st == 0 { return ip, op, 0; }
            inflate_reset(r.inf);
            r.crc = 0;
            r.size = 0;
            r.state = GZ_DATA;
        } else if r.state == GZ_DATA {
            let used, made, st = inflate_read(r.inf, input[ip..], out[op..]);
            r.crc = crc32_update(r.crc, out[op..op + made]);
            r.size += (made & 0xffffffff) as! u32;
            ip += used;
            op += made;
            if st < 0 {
                r.err = st;
                r.state = GZ_FAILED;
                return ip, op, st;
            }
            if st == 0 { return ip, op, 0; }
            r.state = GZ_TRAILER;
        } else if r.state == GZ_TRAILER {
            while r.hbuf.len < 8 && ip < input.len {
                r.hbuf.push(input[ip]);
                ip++;
            }
            if r.hbuf.len < 8 { return ip, op, 0; }
            if get_le32(r.hbuf, 0) != r.crc || get_le32(r.hbuf, 4) != r.size {
                r.err = ERR_CHECKSUM;
                r.state = GZ_FAILED;
                return ip, op, ERR_CHECKSUM;
            }
            r.hbuf.clear();
            r.members++;
            r.state = GZ_END;
        } else if r.state == GZ_END {
            if ip >= input.len || !r.multistream { return ip, op, STREAM_END; }
            r.state = GZ_HEADER;
        } else {
            return ip, op, r.err;
        }
    }
    return ip, op, 0;
}

// At the end of the input: 0 if the input was whole (one member or more,
// each complete), else the error Go gives there (ERR_TRUNCATED; or for
// no input at all, ERR_TRUNCATED too, where Go's NewReader says io.EOF).
fn gzip_finish(r: const GzipReader&) -> i64 {
    if r.err != 0 { return r.err; }
    if r.state == GZ_END { return 0; }
    // A next member's header begun and not finished.
    if r.state == GZ_HEADER && r.members > 0 && r.gh == GH_FIXED && r.hbuf.len == 0 { return 0; }
    return ERR_TRUNCATED;
}

fn gzip_done(r: const GzipReader&) -> bool { gzip_finish(r) == 0 }

// gzip's strings are Latin-1: appends s as UTF-8, as Go's Reader gives
// Header.Name and Header.Comment.
fn gzip_latin1_to_utf8(s: const u8[:], out: u8[>..]&) {
    for c in s {
        if c < 0x80 {
            out.push(c);
        } else {
            out.push((0xc0 | (c >> 6)) as! u8);
            out.push((0x80 | (c & 0x3f)) as! u8);
        }
    }
}

// Decodes a whole gzip file (every member) and appends it to out: 0, or
// an error; ERR_LIMIT if the output would pass `limit` bytes (< 0: no
// limit).
fn gzip_decode(data: const u8[:], out: u8[>..]&, limit: i64 = -1) -> i64 {
    var r = gzip_reader();
    return gzip_decode_with(r, data, out, limit);
}

fn gzip_decode_with(r: GzipReader&, data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var p: i64 = 0;
    loop {
        let start = out.len;
        out.resize(start + 65536, 0);
        let used, made, st = gzip_read(r, data[p..], out[start..]);
        out.resize(start + made);
        p += used;
        if limit >= 0 && out.len > limit { return ERR_LIMIT; }
        if st < 0 { return st; }
        if p >= data.len && made == 0 { break; }
        if st == STREAM_END && (p >= data.len || !r.multistream) { break; }
    }
    return gzip_finish(r);
}

// --- Writing ---------------------------------------------------------------

struct GzipWriter {
    level: i64,
    wrote_header: bool,
    closed: bool,
    err: i64,
    crc: u32, size: u32,
    z: Deflate,
}

// A writer at a deflate level (-2 to 9, -1 the default); a bad level makes
// a writer whose calls return ERR_ARGUMENT, as Go's NewWriterLevel errs.
fn gzip_writer(level: i64 = -1) -> GzipWriter {
    var w = GzipWriter { level: level, wrote_header: false, closed: false, err: 0, crc: 0, size: 0,
                         z: deflate_writer(level) };
    if w.z.err != 0 { w.err = w.z.err; }
    return w;
}

// Appends s, UTF-8, as Latin-1 (gzip's strings): false if s has a NUL or
// a character past U+00FF (Go's "non-Latin-1 header string").
fn gzip_latin1(s: const u8[:], out: u8[>..]&) -> bool {
    var ok = true;
    each_utf8(s) {
        if it == 0 || it > 0xff { ok = false; } else { out.push(it as! u8); }
    };
    return ok;
}

// Writes the header with these fields (Go's Header: Name and Comment as
// UTF-8, written as Latin-1; Extra; ModTime in Unix seconds, 0 or less for
// none; OS). Before the first gzip_write only; without it the first write
// writes a header with no fields and OS 255, as Go's does. ERR_ARGUMENT if
// a string cannot be Latin-1, or if a header was written already.
fn gzip_write_header(w: GzipWriter&, out: u8[>..]&, name: const u8[:], comment: const u8[:], extra: const u8[:],
                     mtime: i64 = 0, os: u8 = 255, has_extra: bool = false) -> i64 {
    if w.err != 0 { return w.err; }
    if w.wrote_header || w.closed { return ERR_ARGUMENT; }
    if extra.len > 65535 {
        w.err = ERR_ARGUMENT;
        return ERR_ARGUMENT;
    }
    let start = out.len;
    var flags: u8 = 0;
    if extra.len > 0 || has_extra { flags |= GZIP_FEXTRA; }
    if name.len > 0 { flags |= GZIP_FNAME; }
    if comment.len > 0 { flags |= GZIP_FCOMMENT; }
    out.append([0x1f, 0x8b, 8, flags]);
    put_le32(out, if mtime > 0 { (mtime & 0xffffffff) as! u64 } else { 0 });
    out.push(if w.level == 9 { 2 } else if w.level == 1 { 4 } else { 0 });
    out.push(os);
    if (flags & GZIP_FEXTRA) != 0 {
        put_le16(out, extra.len as! u64);
        out.append(extra);
    }
    var ok = true;
    if name.len > 0 {
        ok = ok && gzip_latin1(name, out);
        out.push(0);
    }
    if comment.len > 0 {
        ok = ok && gzip_latin1(comment, out);
        out.push(0);
    }
    if !ok {
        // As Go: the writer fails, and keeps failing.
        out.resize(start);
        w.err = ERR_ARGUMENT;
        return ERR_ARGUMENT;
    }
    w.wrote_header = true;
    return 0;
}

fn gzip_write(w: GzipWriter&, data: const u8[:], out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    if !w.wrote_header { gzip_write_header(w, out, "", "", ""); }
    w.crc = crc32_update(w.crc, data);
    w.size += (data.len & 0xffffffff) as! u32;
    let e = deflate_write(w.z, data, out);
    if e != 0 { w.err = e; }
    return e;
}

// Go's Flush: everything written so far can be decoded.
fn gzip_flush(w: GzipWriter&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return 0; }
    if !w.wrote_header { gzip_write_header(w, out, "", "", ""); }
    return deflate_flush(w.z, out);
}

// Ends the member: the last block, CRC-32 and ISIZE. A second close does
// nothing.
fn gzip_close(w: GzipWriter&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return 0; }
    if !w.wrote_header { gzip_write_header(w, out, "", "", ""); }
    w.closed = true;
    let e = deflate_close(w.z, out);
    if e != 0 {
        w.err = e;
        return e;
    }
    put_le32(out, w.crc as u64);
    put_le32(out, w.size as u64);
    return 0;
}

// Starts another member at the same level (Go's Reset).
fn gzip_writer_reset(w: GzipWriter&) {
    w.wrote_header = false;
    w.closed = false;
    w.crc = 0;
    w.size = 0;
    if w.err == 0 { deflate_reset(w.z); }
}

// Compresses data as one gzip member with no header fields, appended to
// out: 0 or ERR_ARGUMENT for a bad level.
fn gzip_encode(data: const u8[:], out: u8[>..]&, level: i64 = -1) -> i64 {
    var w = gzip_writer(level);
    let e = gzip_write(w, data, out);
    if e != 0 { return e; }
    return gzip_close(w, out);
}
