// compress.zlib: the zlib format (RFC 1950), as Go's compress/zlib: a
// two-byte header (and a preset dictionary's Adler-32), DEFLATE data, and
// the Adler-32 of the data.
//
//   var r = compress::zlib_reader();                 // or zlib_reader_dict(dict)
//   let used, made, st = compress::zlib_read(r, input, out);
//
// As Go's reader: a header whose method is not 8, whose window is over
// 32 KiB or whose check bits are wrong is ERR_HEADER; a stream that names
// a preset dictionary is ERR_DICTIONARY unless the dictionary given has
// that Adler-32 (with none given, Go compares with the Adler-32 of no
// bytes, 1, and so does this); a wrong Adler-32 is ERR_CHECKSUM. Bytes
// after the stream are not taken (Go leaves them unread too).

namespace compress;

import std;
import .flate;
import .deflate;

let ZL_HEADER: u8 = 0;
let ZL_DICTID: u8 = 1;
let ZL_DATA: u8 = 2;
let ZL_TRAILER: u8 = 3;
let ZL_END: u8 = 4;
let ZL_FAILED: u8 = 5;

struct ZlibReader {
    state: u8,
    hbuf: u8[..4],
    adler: u32,
    dict_adler: u32,            // of the dictionary given (1: none)
    dict_used: bool,            // the stream named the dictionary
    err: i64,
    inf: Inflate,
    dict: u8[..32768],          // the dictionary's last 32 KiB, until the header says
}

fn zlib_reader() -> ZlibReader {
    ZlibReader { state: ZL_HEADER, hbuf: [], adler: 1, dict_adler: 1, dict_used: false, err: 0,
                 inf: inflate_reader(), dict: [] }
}

// A reader with a preset dictionary, used if the stream names it (Go's
// NewReaderDict).
fn zlib_reader_dict(dict: const u8[:]) -> ZlibReader {
    var r = zlib_reader();
    r.dict_adler = adler32(dict);
    let n = min(dict.len, 32768);
    r.dict.append(dict[dict.len - n..]);
    return r;
}

fn zlib_read(r: ZlibReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    if r.err != 0 { return 0, 0, r.err; }
    var ip: i64 = 0;
    var op: i64 = 0;
    fn fail(e: i64) -> i64 {
        r.err = e;
        r.state = ZL_FAILED;
        return e;
    }
    loop {
        if r.state == ZL_HEADER {
            while r.hbuf.len < 2 && ip < input.len {
                r.hbuf.push(input[ip]);
                ip++;
            }
            if r.hbuf.len < 2 { return ip, op, 0; }
            let cmf = r.hbuf[0] as i64;
            let flg = r.hbuf[1] as i64;
            if (cmf & 15) != 8 || (cmf >> 4) > 7 || (cmf * 256 + flg) % 31 != 0 {
                return ip, op, fail(ERR_HEADER);
            }
            r.hbuf.clear();
            if (flg & 0x20) != 0 {
                r.state = ZL_DICTID;
            } else {
                r.state = ZL_DATA;
            }
        } else if r.state == ZL_DICTID {
            while r.hbuf.len < 4 && ip < input.len {
                r.hbuf.push(input[ip]);
                ip++;
            }
            if r.hbuf.len < 4 { return ip, op, 0; }
            if get_be32(r.hbuf, 0) != r.dict_adler { return ip, op, fail(ERR_DICTIONARY); }
            r.hbuf.clear();
            inflate_set_dictionary(r.inf, r.dict);
            r.dict_used = true;
            r.state = ZL_DATA;
        } else if r.state == ZL_DATA {
            let used, made, st = inflate_read(r.inf, input[ip..], out[op..]);
            r.adler = adler32_update(r.adler, out[op..op + made]);
            ip += used;
            op += made;
            if st < 0 { return ip, op, fail(st); }
            if st == 0 { return ip, op, 0; }
            r.state = ZL_TRAILER;
        } else if r.state == ZL_TRAILER {
            while r.hbuf.len < 4 && ip < input.len {
                r.hbuf.push(input[ip]);
                ip++;
            }
            if r.hbuf.len < 4 { return ip, op, 0; }
            if get_be32(r.hbuf, 0) != r.adler { return ip, op, fail(ERR_CHECKSUM); }
            r.state = ZL_END;
        } else if r.state == ZL_END {
            return ip, op, STREAM_END;
        } else {
            return ip, op, r.err;
        }
    }
    return ip, op, 0;
}

// At the end of the input: 0 if the stream was whole, else the error.
fn zlib_finish(r: const ZlibReader&) -> i64 {
    if r.err != 0 { return r.err; }
    if r.state == ZL_END { return 0; }
    return ERR_TRUNCATED;
}

fn zlib_done(r: const ZlibReader&) -> bool { r.state == ZL_END }

// Decodes a whole zlib stream and appends it to out: 0 or an error
// (ERR_LIMIT past `limit` bytes of output, < 0 for none). Bytes after the
// stream are ignored, as Go's reader ignores them.
fn zlib_decode(data: const u8[:], out: u8[>..]&, limit: i64 = -1) -> i64 {
    var r = zlib_reader();
    return zlib_decode_with(r, data, out, limit);
}

fn zlib_decode_dict(data: const u8[:], dict: const u8[:], out: u8[>..]&, limit: i64 = -1) -> i64 {
    var r = zlib_reader_dict(dict);
    return zlib_decode_with(r, data, out, limit);
}

fn zlib_decode_with(r: ZlibReader&, data: const u8[:], out: u8[>..]&, limit: i64) -> i64 {
    var p: i64 = 0;
    loop {
        let start = out.len;
        out.resize(start + 65536, 0);
        let used, made, st = zlib_read(r, data[p..], out[start..]);
        out.resize(start + made);
        p += used;
        if limit >= 0 && out.len > limit { return ERR_LIMIT; }
        if st != 0 { break; }
        if p >= data.len && made == 0 { break; }
    }
    return zlib_finish(r);
}

// --- Writing ---------------------------------------------------------------

struct ZlibWriter {
    level: i64,
    wrote_header: bool,
    closed: bool,
    has_dict: bool,
    dict_adler: u32,
    err: i64,
    adler: u32,
    z: Deflate,
}

// A writer at a deflate level (-2 to 9, -1 the default); a bad level makes
// a writer whose calls return ERR_ARGUMENT (Go's NewWriterLevel errs).
fn zlib_writer(level: i64 = -1) -> ZlibWriter {
    var w = ZlibWriter { level: level, wrote_header: false, closed: false, has_dict: false, dict_adler: 1, err: 0,
                         adler: 1, z: deflate_writer(level) };
    if w.z.err != 0 { w.err = w.z.err; }
    return w;
}

// A writer with a preset dictionary (Go's NewWriterLevelDict): the header
// names its Adler-32, and matches may reach into it.
fn zlib_writer_dict(level: i64, dict: const u8[:]) -> ZlibWriter {
    var w = zlib_writer(level);
    w.has_dict = true;
    w.dict_adler = adler32(dict);
    deflate_set_dict(w.z, dict);
    return w;
}

fn zlib_header(w: ZlibWriter&, out: u8[>..]&) {
    w.wrote_header = true;
    let l = if w.level == DEFAULT_COMPRESSION { 6 } else { w.level };
    let flevel: i64 = if l <= 1 { 0 } else if l <= 5 { 1 } else if l == 6 { 2 } else { 3 };
    var flg = flevel << 6;
    if w.has_dict { flg |= 0x20; }
    flg += 31 - (0x78 * 256 + flg) % 31;
    out.push(0x78);
    out.push(flg as! u8);
    if w.has_dict { put_be32(out, w.dict_adler); }
}

fn zlib_write(w: ZlibWriter&, data: const u8[:], out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return ERR_ARGUMENT; }
    if !w.wrote_header { zlib_header(w, out); }
    w.adler = adler32_update(w.adler, data);
    let e = deflate_write(w.z, data, out);
    if e != 0 { w.err = e; }
    return e;
}

fn zlib_flush(w: ZlibWriter&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return 0; }
    if !w.wrote_header { zlib_header(w, out); }
    return deflate_flush(w.z, out);
}

fn zlib_close(w: ZlibWriter&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return w.err; }
    if w.closed { return 0; }
    if !w.wrote_header { zlib_header(w, out); }
    w.closed = true;
    let e = deflate_close(w.z, out);
    if e != 0 {
        w.err = e;
        return e;
    }
    put_be32(out, w.adler);
    return 0;
}

// Compresses data as one zlib stream, appended to out.
fn zlib_encode(data: const u8[:], out: u8[>..]&, level: i64 = -1) -> i64 {
    var w = zlib_writer(level);
    let e = zlib_write(w, data, out);
    if e != 0 { return e; }
    return zlib_close(w, out);
}
