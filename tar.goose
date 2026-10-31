// compress.tar: tar archives, read and written as Go's archive/tar does.
//
// Reading takes V7, USTAR, PAX (local and global extended headers), GNU
// (long names and links, base-256 numbers, access and change times, old
// sparse files with their extension blocks) and star archives, and the
// GNU sparse formats 0.0, 0.1 and 1.0 inside PAX. A sparse file reads as
// Go reads it: its holes come out as zeros, and its map is checked as Go
// checks it. Every limit is Go's: a special file (PAX records, a long name
// or link, a 1.0 sparse map) of at most 1 MiB, a sparse map of at most
// 2^20 entries; so a reader holds a bounded amount of memory whatever the
// archive says.
//
// The reader is fed the archive as it comes (a tar.gz is read as a
// stream) and hands out headers and file contents:
//
//   var r = compress::tar_reader();
//   let used, made, st = compress::tar_read(r, input, out);
//     // st == compress::TAR_HEADER: compress::tar_header(r) is the next entry;
//     //   the calls after it write that entry's contents into `out`, the
//     //   last of them returning as they end (compress::tar_in_entry(r))
//     // st == 0: more input (or more room in `out`) is needed
//     // st == compress::STREAM_END: the archive's end (two zero blocks)
//   // at the end of the input: compress::tar_finish(r) is STREAM_END, or
//   //   ERR_TRUNCATED when the archive was cut short
//
// Writing appends to a builder the caller owns:
//
//   var w = compress::tar_writer();
//   compress::tar_write_header(w, compress::TarHeader { typeflag: '0', name: "a.txt", size: 5, .. }, out);
//   compress::tar_write(w, "hello", out);
//   compress::tar_close(w, out);
//
// The writer picks USTAR, then PAX, then GNU, the first that can hold the
// header, as Go's Writer does (or the format the header asks for), and
// writes PAX records for what USTAR cannot hold (long or non-ASCII names,
// large numbers, sub-second times).

namespace compress;

import std;

// --- Types and formats -----------------------------------------------------

let TAR_TYPE_REG: u8 = '0';
let TAR_TYPE_REGA: u8 = 0;          // an old regular file; read as TAR_TYPE_REG (or DIR, for a name ending in /)
let TAR_TYPE_LINK: u8 = '1';
let TAR_TYPE_SYMLINK: u8 = '2';
let TAR_TYPE_CHAR: u8 = '3';
let TAR_TYPE_BLOCK: u8 = '4';
let TAR_TYPE_DIR: u8 = '5';
let TAR_TYPE_FIFO: u8 = '6';
let TAR_TYPE_CONT: u8 = '7';
let TAR_TYPE_XHEADER: u8 = 'x';
let TAR_TYPE_XGLOBAL: u8 = 'g';
let TAR_TYPE_GNU_SPARSE: u8 = 'S';
let TAR_TYPE_GNU_LONGNAME: u8 = 'L';
let TAR_TYPE_GNU_LONGLINK: u8 = 'K';

// Formats, bits as Go's tar.Format.
let TAR_FORMAT_UNKNOWN: i64 = 0;
let TAR_FORMAT_V7: i64 = 1;
let TAR_FORMAT_USTAR: i64 = 2;
let TAR_FORMAT_PAX: i64 = 4;
let TAR_FORMAT_GNU: i64 = 8;
let TAR_FORMAT_STAR: i64 = 16;

// tar_read's result when a header is ready.
let TAR_HEADER: i64 = 2;

// Which of Go's errors an error is (tar_why), past the compress::ERR_* code.
let TAR_WHY_NONE: i64 = 0;
let TAR_WHY_HEADER: i64 = 1;            // ErrHeader                         (ERR_HEADER)
let TAR_WHY_TRUNCATED: i64 = 2;         // io.ErrUnexpectedEOF                (ERR_TRUNCATED)
let TAR_WHY_FIELD_TOO_LONG: i64 = 3;    // ErrFieldTooLong                    (ERR_LIMIT)
let TAR_WHY_SPARSE_TOO_LONG: i64 = 4;   // errSparseTooLong                   (ERR_LIMIT)
let TAR_WHY_MISS_DATA: i64 = 5;         // errMissData                        (ERR_DATA)
let TAR_WHY_UNREF_DATA: i64 = 6;        // errUnrefData                       (ERR_DATA)
let TAR_WHY_WRITE_TOO_LONG: i64 = 7;    // ErrWriteTooLong                    (ERR_TOO_LARGE)
let TAR_WHY_WRITE_AFTER_CLOSE: i64 = 8; // ErrWriteAfterClose                 (ERR_ARGUMENT)
let TAR_WHY_MISSED_WRITING: i64 = 9;    // "missed writing N bytes"           (ERR_ARGUMENT)
let TAR_WHY_CANNOT_ENCODE: i64 = 10;    // "cannot encode header" (headerError) (ERR_HEADER)

// The most a special file (PAX records, a GNU long name, a sparse map)
// may hold, and the most entries of a sparse map: Go's limits.
let TAR_MAX_SPECIAL: i64 = 1 << 20;
let TAR_MAX_SPARSE_ENTRIES: i64 = 1 << 20;

// A time: seconds since 1970 and nanoseconds (0 to 999999999); `valid`
// false is Go's zero time.Time (not set).
struct TarTime { sec: i64 = 0, nsec: i64 = 0, valid: bool = false }

fn tar_time(sec: i64, nsec: i64 = 0) -> TarTime { TarTime { sec: sec, nsec: nsec, valid: true } }

// Go's Time.IsZero: not set, or (as Go has it) January 1 of year 1.
fn tar_time_is_zero(t: TarTime) -> bool { !t.valid || (t.sec == -62135596800 && t.nsec == 0) }

// A header, as Go's tar.Header. Read, its strings are views into the
// reader (valid until the reader goes past the entry); to write, they are
// whatever the caller has. `pax` holds PAX records in PAX's own encoding
// ("LEN key=value\n" each; compress::tar_pax_append makes one), so Go's
// PAXRecords and its Xattrs (the SCHILY.xattr.* records) are both in it;
// read, the records are each key's last, sorted by key.
struct TarHeader {
    typeflag: u8 = '0',
    name: const u8[:] = "",
    linkname: const u8[:] = "",
    size: i64 = 0,
    mode: i64 = 0,
    uid: i64 = 0,
    gid: i64 = 0,
    uname: const u8[:] = "",
    gname: const u8[:] = "",
    mtime: TarTime = TarTime { .. },
    atime: TarTime = TarTime { .. },
    ctime: TarTime = TarTime { .. },
    devmajor: i64 = 0,
    devminor: i64 = 0,
    pax: const u8[:] = "",
    format: i64 = 0,
}

struct TarSpan { off: i64 = 0, len: i64 = 0 }

// The reader's spans into its buffer.
let TSP_NAME: i64 = 0;
let TSP_LINK: i64 = 1;
let TSP_UNAME: i64 = 2;
let TSP_GNAME: i64 = 3;
let TSP_PAX: i64 = 4;          // the records of the last PAX header
let TSP_LONGNAME: i64 = 5;
let TSP_LONGLINK: i64 = 6;
let TSP_RAW: i64 = 7;          // a special file being read
let TSP_SPD: i64 = 8;          // a sparse map's data fragments, 16 bytes each
let TSP_HOLES: i64 = 9;        // and its holes
let TSP_MAP: i64 = 10;         // a 1.0 sparse map's blocks
let TSP_COUNT: i64 = 11;

// Reader states.
let TRS_HEADER: u8 = 0;
let TRS_ZERO2: u8 = 1;        // after a block of zeros
let TRS_SPECIAL: u8 = 2;
let TRS_PAD: u8 = 3;
let TRS_GNU_EXT: u8 = 4;
let TRS_MAP: u8 = 5;
let TRS_DATA: u8 = 6;
let TRS_END: u8 = 7;
let TRS_FAILED: u8 = 8;

struct TarReader {
    state: u8,
    err: i64,
    why: i64,
    check_paths: bool,          // Go with GODEBUG=tarinsecurepath=0
    insecure: bool,             // the header handed out is not a local path (check_paths only)
    emitted: bool,              // a header was handed out: the next header starts afresh
    blk: u8[512],
    fill: i64,
    // The header being read.
    typeflag: u8,
    size: i64,
    mode: i64,
    uid: i64,
    gid: i64,
    mtime: TarTime,
    atime: TarTime,
    ctime: TarTime,
    devmajor: i64,
    devminor: i64,
    hformat: i64,
    facc: i64,                  // what the entry's headers allow it to be (Go's `format`)
    has_pax: bool,
    sp: TarSpan[11],
    // The entry's data.
    phys: i64,                  // bytes of it in the archive still to read
    padn: i64,                   // padding after it
    pad_left: i64,
    spec_need: i64,             // a special file: the bytes to read of it,
    spec_size: i64,             // and its size
    sparse: bool,
    logical: i64,               // a sparse file's size,
    pos: i64,                   // the position in it,
    hole: i64,                  // the hole at or after it
    nholes: i64,
    skip: bool,
    gnu_total: i64,             // old GNU sparse: the size of the map so far
    map_total: i64,             // 1.0 sparse: the map's size so far,
    map_lines: i64,             // the newlines in it,
    map_need: i64,              // the newlines wanted,
    map_n: i64,                 // its entries (-1 before they are known)
    map_used: i64,              // and the bytes of it parsed
    hstart: i64,                // a special header's strings, hstart..hend in buf
    hend: i64,
    buf: u8[>..],
}

// A reader. check_paths makes it flag names that are not local paths
// (absolute, or reaching out with ..), as Go does under
// GODEBUG=tarinsecurepath=0; Go's default, and this one, flags nothing.
fn tar_reader(check_paths: bool = false) -> TarReader {
    TarReader {
        state: TRS_HEADER, err: 0, why: 0, check_paths: check_paths, insecure: false, emitted: false,
        blk: [0; 512], fill: 0,
        typeflag: 0, size: 0, mode: 0, uid: 0, gid: 0,
        mtime: TarTime { .. }, atime: TarTime { .. }, ctime: TarTime { .. },
        devmajor: 0, devminor: 0, hformat: 0, facc: TAR_FORMAT_USTAR | TAR_FORMAT_PAX | TAR_FORMAT_GNU,
        has_pax: false, sp: [TarSpan { .. }; 11],
        phys: 0, padn: 0, pad_left: 0, spec_need: 0, spec_size: 0,
        sparse: false, logical: 0, pos: 0, hole: 0, nholes: 0, skip: false,
        gnu_total: 0, map_total: 0, map_lines: 0, map_need: 0, map_n: -1, map_used: 0, hstart: 0, hend: 0,
        buf: [],
    }
}

fn tar_span(r: const TarReader&, k: i64) -> const u8[:] { r.buf[r.sp[k].off..r.sp[k].off + r.sp[k].len] }

// The header tar_read handed out last.
fn tar_header(r: const TarReader&) -> TarHeader {
    TarHeader {
        typeflag: r.typeflag,
        name: tar_span(r, TSP_NAME),
        linkname: tar_span(r, TSP_LINK),
        size: r.size, mode: r.mode, uid: r.uid, gid: r.gid,
        uname: tar_span(r, TSP_UNAME),
        gname: tar_span(r, TSP_GNAME),
        mtime: r.mtime, atime: r.atime, ctime: r.ctime,
        devmajor: r.devmajor, devminor: r.devminor,
        pax: if r.has_pax { tar_span(r, TSP_PAX) } else { "" },
        format: r.hformat,
    }
}

// Whether the header handed out last has a name that is not a local path
// (only for a reader made with check_paths; Go's ErrInsecurePath, which
// Go returns together with the header).
fn tar_insecure_path(r: const TarReader&) -> bool { r.insecure }

// Which of Go's errors the reader's (or writer's) last error is.
fn tar_why(r: const TarReader&) -> i64 { r.why }

// Whether the reader is within an entry's contents (from the TAR_HEADER
// to the call that ends them).
fn tar_in_entry(r: const TarReader&) -> bool { r.state == TRS_DATA }

// What is left to read of the current entry's contents.
fn tar_remaining(r: const TarReader&) -> i64 {
    if r.state != TRS_DATA { return 0; }
    if r.sparse { r.logical - r.pos } else { r.phys }
}

// Skips the rest of the current entry: tar_read takes its bytes and
// writes nothing (and, as Go's Next, checks no sparse map against them).
fn tar_skip(r: TarReader&) { if r.state == TRS_DATA { r.skip = true; } }

fn tar_fail(r: TarReader&, code: i64, why: i64) -> i64 {
    r.state = TRS_FAILED;
    r.err = code;
    r.why = why;
    return code;
}

// Whether the input may end here: at a header, after a block of zeros,
// after the end, or anywhere after an entry's data (in its padding, which
// Go's Reader does not insist on), as Go's Reader takes such an end.
fn tar_done(r: const TarReader&) -> bool {
    if r.state == TRS_HEADER || r.state == TRS_ZERO2 { return r.fill == 0; }
    if r.state == TRS_END || r.state == TRS_PAD { return true; }
    if r.state == TRS_DATA { return r.phys == 0; }
    return false;
}

// At the end of the input: STREAM_END if the archive ended where it may,
// else ERR_TRUNCATED (or the error the reader stopped at).
fn tar_finish(r: TarReader&) -> i64 {
    if r.state == TRS_FAILED { return r.err; }
    if tar_done(r) { return STREAM_END; }
    return tar_fail(r, ERR_TRUNCATED, TAR_WHY_TRUNCATED);
}

// --- Numbers and strings as Go parses them ---------------------------------

// strconv.ParseInt(s, 10, 64).
fn tar_parse_int(s: const u8[:]) -> i64, bool {
    if s.len == 0 { return 0, false; }
    var i = 0;
    var neg = false;
    if s[0] == '+' || s[0] == '-' {
        neg = s[0] == '-';
        i = 1;
    }
    if i == s.len { return 0, false; }
    let limit: u64 = if neg { 0x8000000000000000 } else { 0x7fffffffffffffff };
    var x: u64 = 0;
    while i < s.len {
        let c = s[i];
        if c < '0' || c > '9' { return 0, false; }
        let d: u64 = c - '0';
        if x > (limit - d) / 10 { return 0, false; }
        x = x * 10 + d;
        i++;
    }
    if neg { return (0 - x) as! i64, true; }
    return x as! i64, true;
}

// The bytes before the first NUL.
fn tar_cstr(b: const u8[:]) -> const u8[:] {
    let z = position(b, 0);
    if z < 0 { return b; }
    return b[..z];
}

// Go's parser.parseOctal: trims spaces and NULs, then octal; false for an error.
fn tar_parse_octal(b: const u8[:]) -> i64, bool {
    var lo = 0;
    var hi = b.len;
    while lo < hi && (b[lo] == ' ' || b[lo] == 0) { lo++; }
    while hi > lo && (b[hi - 1] == ' ' || b[hi - 1] == 0) { hi--; }
    if lo == hi { return 0, true; }
    let s = tar_cstr(b[lo..hi]);
    if s.len == 0 { return 0, false; }
    var x: u64 = 0;
    for c in s {
        if c < '0' || c > '7' { return 0, false; }
        if (x >> 61) != 0 { return 0, false; }
        x = x * 8 + (c - '0');
    }
    return x as! i64, true;
}

// Go's parser.parseNumeric: base-256 (GNU) when the top bit is set, else octal.
fn tar_parse_numeric(b: const u8[:]) -> i64, bool {
    if b.len > 0 && (b[0] & 0x80) != 0 {
        let inv: u8 = if (b[0] & 0x40) != 0 { 0xff } else { 0 };
        var x: u64 = 0;
        for c0, i in b {
            var c = c0 ^ inv;
            if i == 0 { c &= 0x7f; }
            if (x >> 56) > 0 { return 0, false; }
            x = (x << 8) | c;
        }
        if (x >> 63) > 0 { return 0, false; }
        if inv == 0xff { return ~(x as! i64), true; }
        return x as! i64, true;
    }
    return tar_parse_octal(b);
}

// Go's parsePAXTime.
fn tar_parse_pax_time(s: const u8[:]) -> TarTime, bool {
    let dot = position(s, '.');
    let ss = if dot < 0 { s } else { s[..dot] };
    let sn = if dot < 0 { s[s.len..] } else { s[dot + 1..] };
    let secs, ok = tar_parse_int(ss);
    if !ok { return TarTime { .. }, false; }
    if sn.len == 0 { return tar_time(secs), true; }
    var nsecs: i64 = 0;
    for c, i in sn {
        if c < '0' || c > '9' { return TarTime { .. }, false; }
        if i < 9 { nsecs = nsecs * 10 + (c - '0'); }
    }
    for i in sn.len..9 { nsecs *= 10; }
    if ss.len > 0 && ss[0] == '-' && nsecs > 0 {
        // time.Unix(secs, -nsecs), which wraps as Go's int64 does.
        return tar_time(((secs as! u64) - 1) as! i64, 1000000000 - nsecs), true;
    }
    return tar_time(secs, nsecs), true;
}

// Go's validPAXRecord.
fn tar_valid_pax_record(k: const u8[:], v: const u8[:]) -> bool {
    if k.len == 0 || position(k, '=') >= 0 { return false; }
    if k == "path" || k == "linkpath" || k == "uname" || k == "gname" { return position(v, 0) < 0; }
    return position(k, 0) < 0;
}

// The framing of Go's parsePAXRecord over s ("LEN key=value\n"): the
// key's and value's offsets and lengths in s and the record's length, or
// ok false.
fn tar_pax_record_raw(s: const u8[:]) -> i64, i64, i64, i64, i64, bool {
    let sp = position(s, ' ');
    if sp < 0 { return 0, 0, 0, 0, 0, false; }
    let n0, ok = tar_parse_int(s[..sp]);
    if !ok || n0 < 5 || n0 > s.len { return 0, 0, 0, 0, 0, false; }
    let n = n0 - (sp + 1);
    if n <= 0 { return 0, 0, 0, 0, 0, false; }
    let rest = s[sp + 1..];
    if rest[n - 1] != '\n' { return 0, 0, 0, 0, 0, false; }
    let rec = rest[..n - 1];
    let eq = position(rec, '=');
    if eq < 0 { return 0, 0, 0, 0, 0, false; }
    return sp + 1, eq, sp + 2 + eq, rec.len - eq - 1, sp + 1 + n, true;
}

// Go's parsePAXRecord: the framing, and a key and value Go accepts.
fn tar_pax_record(s: const u8[:]) -> i64, i64, i64, i64, i64, bool {
    let ko, kl, vo, vl, n, ok = tar_pax_record_raw(s);
    if !ok || !tar_valid_pax_record(s[ko..ko + kl], s[vo..vo + vl]) { return 0, 0, 0, 0, 0, false; }
    return ko, kl, vo, vl, n, true;
}

// Appends the PAX record key=value, as Go's formatPAXRecord writes it.
fn tar_pax_append(out: u8[>..]&, key: const u8[:], value: const u8[:]) {
    var size = key.len + value.len + 3;
    var digits = 1;
    var t = size;
    while t >= 10 { t /= 10; digits++; }
    size += digits;
    // The length counts its own digits: one more digit can be needed.
    var d2 = 1;
    t = size;
    while t >= 10 { t /= 10; d2++; }
    if d2 != digits { size += d2 - digits; }
    format(out, size);
    out.push(' ');
    out.append(key);
    out.push('=');
    out.append(value);
    out.push('\n');
}

// Calls F(key, value) for each of a header's PAX records (stopping at one
// that is not well formed).
fn tar_pax_each<F>(pax: const u8[:]) {
    var p = 0;
    while p < pax.len {
        let ko, kl, vo, vl, n, ok = tar_pax_record_raw(pax[p..]);
        if !ok { return; }
        F(pax[p + ko..p + ko + kl], pax[p + vo..p + vo + vl]);
        p += n;
    }
}

// The value of a PAX record (the last with that key), and whether there is one.
fn tar_pax_get(pax: const u8[:], key: const u8[:]) -> const u8[:], bool {
    var p = 0;
    var found = false;
    var vo2 = 0;
    var vl2 = 0;
    while p < pax.len {
        let ko, kl, vo, vl, n, ok = tar_pax_record_raw(pax[p..]);
        if !ok { break; }
        if pax[p + ko..p + ko + kl] == key {
            found = true;
            vo2 = p + vo;
            vl2 = vl;
        }
        p += n;
    }
    return pax[vo2..vo2 + vl2], found;
}

// Go's path.Clean, appended to out.
fn tar_clean(path: const u8[:], out: u8[>..]&) {
    let base = out.len;
    if path.len == 0 { out.push('.'); return; }
    let rooted = path[0] == '/';
    let n = path.len;
    var r = 0;
    var dotdot = base;
    if rooted { out.push('/'); r = 1; dotdot = base + 1; }
    while r < n {
        if path[r] == '/' {
            r++;
        } else if path[r] == '.' && (r + 1 == n || path[r + 1] == '/') {
            r++;
        } else if path[r] == '.' && path[r + 1] == '.' && (r + 2 == n || path[r + 2] == '/') {
            r += 2;
            if out.len > dotdot {
                var w = out.len - 1;
                while w > dotdot && out[w] != '/' { w--; }
                out.resize(w);
            } else if !rooted {
                if out.len > base { out.push('/'); }
                out.push('.');
                out.push('.');
                dotdot = out.len;
            }
        } else {
            if (rooted && out.len != base + 1) || (!rooted && out.len != base) { out.push('/'); }
            while r < n && path[r] != '/' { out.push(path[r]); r++; }
        }
    }
    if out.len == base { out.push('.'); }
}

// Go's filepath.IsLocal, as on Unix.
fn tar_is_local(path: const u8[:]) -> bool {
    if path.len == 0 || path[0] == '/' { return false; }
    var has_dots = false;
    var start = 0;
    for i in 0..path.len + 1 {
        if i == path.len || path[i] == '/' {
            let part = path[start..i];
            if part == "." || part == ".." { has_dots = true; break; }
            start = i + 1;
        }
    }
    if !has_dots { return !(path == ".." || starts_with(path, "../")); }
    var c: u8[>..] = [];
    tar_clean(path, c);
    return !(c == ".." || starts_with(c, "../"));
}

fn tar_padding(n: i64) -> i64 { (512 - (n & 511)) & 511 }

fn tar_header_only(t: u8) -> bool {
    t == TAR_TYPE_LINK || t == TAR_TYPE_SYMLINK || t == TAR_TYPE_CHAR || t == TAR_TYPE_BLOCK
        || t == TAR_TYPE_DIR || t == TAR_TYPE_FIFO
}

fn tar_get_i64(m: const u8[:], p: i64) -> i64 { get_le64(m, p) as! i64 }

fn tar_put_i64(out: u8[>..]&, v: i64) { put_le64(out, v as! u64); }

// --- Blocks ----------------------------------------------------------------

// Go's block.computeChecksum: unsigned and signed sums, the checksum field as spaces.
fn tar_checksums(b: const u8[512]&) -> i64, i64 {
    var u: i64 = 0;
    var s: i64 = 0;
    for c0, i in b {
        let c = if i >= 148 && i < 156 { 32 as u8 } else { c0 };
        u += c;
        s += if c >= 128 { (c as i64) - 256 } else { c };
    }
    return u, s;
}

// Go's block.getFormat.
fn tar_block_format(b: const u8[512]&) -> i64 {
    let value, ok = tar_parse_octal(b[148..156]);
    let c1, c2 = tar_checksums(b);
    if !ok || (value != c1 && value != c2) { return TAR_FORMAT_UNKNOWN; }
    let magic = b[257..263];
    let version = b[263..265];
    if magic == "ustar\x00" && b[508..512] == "tar\x00" { return TAR_FORMAT_STAR; }
    if magic == "ustar\x00" { return TAR_FORMAT_USTAR | TAR_FORMAT_PAX; }
    if magic == "ustar " && version == " \x00" { return TAR_FORMAT_GNU; }
    return TAR_FORMAT_V7;
}

fn tar_is_zero_block(b: const u8[512]&) -> bool {
    for c in b { if c != 0 { return false; } }
    return true;
}

fn tar_set_span(r: TarReader&, k: i64, off: i64, len: i64) { r.sp[k] = TarSpan { off: off, len: len }; }

// Appends s to the buffer as span k.
fn tar_keep(r: TarReader&, k: i64, s: const u8[:]) {
    let off = r.buf.len;
    r.buf.append(s);
    tar_set_span(r, k, off, s.len);
}

// Removes n bytes of the buffer at off; the spans after them move down.
fn tar_cut(r: TarReader&, off: i64, n: i64) {
    if n <= 0 { return; }
    let end = r.buf.len;
    if off + n < end { r.buf[off..end - n].move_from(r.buf[off + n..end]); }
    r.buf.resize(end - n);
    for k in TSP_COUNT {
        if r.sp[k].off >= off + n { r.sp[k].off -= n; }
        else if r.sp[k].off >= off && r.sp[k].len > 0 { r.sp[k] = TarSpan { .. }; }
    }
}

fn tar_new_entry(r: TarReader&) {
    r.buf.clear();
    for k in TSP_COUNT { r.sp[k] = TarSpan { .. }; }
    r.has_pax = false;
    r.facc = TAR_FORMAT_USTAR | TAR_FORMAT_PAX | TAR_FORMAT_GNU;
    r.emitted = false;
    r.insecure = false;
    r.sparse = false;
    r.skip = false;
}

// Go's Reader.readHeader on the block in r.blk, after its zero-block
// checks: the fields, with the strings kept in the buffer. An error, or 0.
fn tar_read_header(r: TarReader&) -> i64 {
    let format = tar_block_format(r.blk);
    if format == TAR_FORMAT_UNKNOWN { return ERR_HEADER; }
    let b = r.blk[..];
    var perr = false;
    r.typeflag = b[156];
    r.hformat = TAR_FORMAT_UNKNOWN;
    var ok = true;
    r.size, ok = tar_parse_numeric(b[124..136]);
    if !ok { perr = true; }
    r.mode, ok = tar_parse_numeric(b[100..108]);
    if !ok { perr = true; }
    r.uid, ok = tar_parse_numeric(b[108..116]);
    if !ok { perr = true; }
    r.gid, ok = tar_parse_numeric(b[116..124]);
    if !ok { perr = true; }
    var mt: i64 = 0;
    mt, ok = tar_parse_numeric(b[136..148]);
    if !ok { perr = true; }
    r.mtime = tar_time(mt);
    r.atime = TarTime { .. };
    r.ctime = TarTime { .. };
    r.devmajor = 0;
    r.devminor = 0;
    let name = tar_cstr(b[0..100]);
    var prefix: const u8[:] = b[0..0];
    if format > TAR_FORMAT_V7 {
        tar_keep(r, TSP_UNAME, tar_cstr(b[265..297]));
        tar_keep(r, TSP_GNAME, tar_cstr(b[297..329]));
        r.devmajor, ok = tar_parse_numeric(b[329..337]);
        if !ok { perr = true; }
        r.devminor, ok = tar_parse_numeric(b[337..345]);
        if !ok { perr = true; }
        if (format & (TAR_FORMAT_USTAR | TAR_FORMAT_PAX)) != 0 {
            r.hformat = format;
            prefix = tar_cstr(b[345..500]);
            for c in b { if c >= 0x80 { r.hformat = TAR_FORMAT_UNKNOWN; break; } }
            if !(b[135] == 0 && b[107] == 0 && b[115] == 0 && b[123] == 0 && b[147] == 0 && b[336] == 0 && b[344] == 0) {
                r.hformat = TAR_FORMAT_UNKNOWN;
            }
        } else if (format & TAR_FORMAT_STAR) != 0 {
            prefix = tar_cstr(b[345..476]);
            var t: i64 = 0;
            t, ok = tar_parse_numeric(b[476..488]);
            if !ok { perr = true; }
            r.atime = tar_time(t);
            t, ok = tar_parse_numeric(b[488..500]);
            if !ok { perr = true; }
            r.ctime = tar_time(t);
        } else if (format & TAR_FORMAT_GNU) != 0 {
            r.hformat = format;
            var p2err = false;
            if b[345] != 0 {
                let t, ok2 = tar_parse_numeric(b[345..357]);
                if !ok2 { p2err = true; }
                r.atime = tar_time(t);
            }
            if b[357] != 0 {
                let t, ok2 = tar_parse_numeric(b[357..369]);
                if !ok2 { p2err = true; }
                r.ctime = tar_time(t);
            }
            if p2err {
                r.atime = TarTime { .. };
                r.ctime = TarTime { .. };
                let s = tar_cstr(b[345..500]);
                var ascii = true;
                for c in s { if c >= 0x80 { ascii = false; } }
                if ascii { prefix = s; }
                r.hformat = TAR_FORMAT_UNKNOWN;
            }
        }
    }
    let off = r.buf.len;
    if prefix.len > 0 {
        r.buf.append(prefix);
        r.buf.push('/');
    }
    r.buf.append(name);
    tar_set_span(r, TSP_NAME, off, r.buf.len - off);
    tar_keep(r, TSP_LINK, tar_cstr(b[157..257]));
    if perr { return ERR_HEADER; }
    return 0;
}

// Go's handleRegularFile: the data the header says follows it.
fn tar_regular(r: TarReader&) -> bool {
    let nb = if tar_header_only(r.typeflag) { 0 } else { r.size };
    if nb < 0 { return false; }
    r.phys = nb;
    r.padn = tar_padding(nb);
    r.pad_left = r.padn;
    return true;
}

struct TarKV { koff: i64, klen: i64, voff: i64, vlen: i64, idx: i64, synth: bool }

// Go's parsePAX over the special file just read (span TSP_RAW): its
// records, each key's last, sorted, appended to the buffer as span
// TSP_PAX (replacing the records before). false for ErrHeader.
fn tar_parse_pax(r: TarReader&) -> bool {
    let raw = r.sp[TSP_RAW];
    var ents: TarKV[>..] = [];
    var smap: u8[>..] = [];         // GNU.sparse.offset and numbytes values, joined with commas
    var nsmap = 0;
    var p = raw.off;
    let end = raw.off + raw.len;
    while p < end {
        let ko, kl, vo, vl, n, ok = tar_pax_record(r.buf[p..end]);
        if !ok { return false; }
        let k = r.buf[p + ko..p + ko + kl];
        let v = r.buf[p + vo..p + vo + vl];
        if k == "GNU.sparse.offset" || k == "GNU.sparse.numbytes" {
            if (nsmap % 2 == 0 && k != "GNU.sparse.offset") || (nsmap % 2 == 1 && k != "GNU.sparse.numbytes")
                || position(v, ',') >= 0 {
                return false;
            }
            if nsmap > 0 { smap.push(','); }
            smap.append(v);
            nsmap++;
        } else {
            ents.push(TarKV { koff: p + ko, klen: kl, voff: p + vo, vlen: vl, idx: ents.len, synth: false });
        }
        p += n;
    }
    if nsmap > 0 {
        ents.push(TarKV { koff: -1, klen: 14, voff: 0, vlen: smap.len, idx: ents.len, synth: true });
    }
    let buf = r.buf[..];
    stable_sort(ents) { a, b =>
        let ka = if a.synth { "GNU.sparse.map" } else { buf[a.koff..a.koff + a.klen] };
        let kb = if b.synth { "GNU.sparse.map" } else { buf[b.koff..b.koff + b.klen] };
        compare(ka, kb) < 0
    };
    let start = r.buf.len;
    for e, i in ents {
        if i + 1 < ents.len {
            let e2 = ents[i + 1];
            let k1 = if e.synth { "GNU.sparse.map" } else { r.buf[e.koff..e.koff + e.klen] };
            let k2 = if e2.synth { "GNU.sparse.map" } else { r.buf[e2.koff..e2.koff + e2.klen] };
            if k1 == k2 { continue; }          // a later record for the key follows
        }
        if e.synth {
            tar_pax_append(r.buf, "GNU.sparse.map", smap);
        } else {
            tar_pax_append(r.buf, r.buf[e.koff..e.koff + e.klen], r.buf[e.voff..e.voff + e.vlen]);
        }
    }
    let old = r.sp[TSP_PAX];
    tar_set_span(r, TSP_PAX, start, r.buf.len - start);
    if r.has_pax { tar_cut(r, old.off, old.len); }
    r.has_pax = true;
    return true;
}

fn tar_pax_value(r: const TarReader&, key: const u8[:]) -> const u8[:] {
    if !r.has_pax { return ""; }
    let v, found = tar_pax_get(tar_span(r, TSP_PAX), key);
    return v;
}

// Points span k at the PAX record key's value, if it has one that is not empty.
fn tar_span_from_pax(r: TarReader&, k: i64, key: const u8[:]) {
    let pax = r.sp[TSP_PAX];
    var p = pax.off;
    let end = pax.off + pax.len;
    while p < end {
        let ko, kl, vo, vl, n, ok = tar_pax_record(r.buf[p..end]);
        if !ok { return; }
        if r.buf[p + ko..p + ko + kl] == key && vl > 0 {
            tar_set_span(r, k, p + vo, vl);
            return;
        }
        p += n;
    }
}

// Go's mergePAX: the records over the header's fields. false for ErrHeader.
fn tar_merge_pax(r: TarReader&) -> bool {
    if !r.has_pax { return true; }
    let pax = r.sp[TSP_PAX];
    var p = pax.off;
    let end = pax.off + pax.len;
    var good = true;
    while p < end {
        let ko, kl, vo, vl, n, ok = tar_pax_record(r.buf[p..end]);
        if !ok { break; }
        let k = r.buf[p + ko..p + ko + kl];
        let v = r.buf[p + vo..p + vo + vl];
        p += n;
        if v.len == 0 { continue; }
        if k == "path" { tar_set_span(r, TSP_NAME, p - n + vo, vl); }
        else if k == "linkpath" { tar_set_span(r, TSP_LINK, p - n + vo, vl); }
        else if k == "uname" { tar_set_span(r, TSP_UNAME, p - n + vo, vl); }
        else if k == "gname" { tar_set_span(r, TSP_GNAME, p - n + vo, vl); }
        else if k == "uid" { let x, okx = tar_parse_int(v); r.uid = x; if !okx { good = false; } }
        else if k == "gid" { let x, okx = tar_parse_int(v); r.gid = x; if !okx { good = false; } }
        else if k == "atime" { let t, okt = tar_parse_pax_time(v); r.atime = t; if !okt { good = false; } }
        else if k == "mtime" { let t, okt = tar_parse_pax_time(v); r.mtime = t; if !okt { good = false; } }
        else if k == "ctime" { let t, okt = tar_parse_pax_time(v); r.ctime = t; if !okt { good = false; } }
        else if k == "size" { let x, okx = tar_parse_int(v); r.size = x; if !okx { good = false; } }
    }
    return good;
}

fn tar_add_spd(r: TarReader&, off: i64, len: i64) -> bool {
    if r.sp[TSP_SPD].len / 16 >= TAR_MAX_SPARSE_ENTRIES { return false; }
    if r.sp[TSP_SPD].len == 0 { r.sp[TSP_SPD].off = r.buf.len; }
    tar_put_i64(r.buf, off);
    tar_put_i64(r.buf, len);
    r.sp[TSP_SPD].len += 16;
    return true;
}

// The entries of an old GNU sparse map in blk[from..], n of them; 0, or an error.
fn tar_gnu_sparse_entries(r: TarReader&, from: i64, n: i64) -> i64 {
    for i in n {
        let at = from + i * 24;
        if r.blk[at] == 0 { break; }
        let off, ok1 = tar_parse_numeric(r.blk[at..at + 12]);
        let len, ok2 = tar_parse_numeric(r.blk[at + 12..at + 24]);
        if !ok1 || !ok2 { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        if !tar_add_spd(r, off, len) { return tar_fail(r, ERR_LIMIT, TAR_WHY_SPARSE_TOO_LONG); }
    }
    return 0;
}

// The header of a file (not a special one) was read: Go's next(), from
// mergePAX on. TAR_HEADER, 0 (more of a sparse map to read), or an error.
fn tar_file_header(r: TarReader&) -> i64 {
    if !tar_merge_pax(r) { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    if r.sp[TSP_LONGNAME].len > 0 { r.sp[TSP_NAME] = r.sp[TSP_LONGNAME]; }
    if r.sp[TSP_LONGLINK].len > 0 { r.sp[TSP_LINK] = r.sp[TSP_LONGLINK]; }
    if r.typeflag == TAR_TYPE_REGA {
        let n = tar_span(r, TSP_NAME);
        r.typeflag = if n.len > 0 && n[n.len - 1] == '/' { TAR_TYPE_DIR } else { TAR_TYPE_REG };
    }
    if !tar_regular(r) { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    // Go's handleSparseFile.
    if r.typeflag == TAR_TYPE_GNU_SPARSE {
        if tar_block_format(r.blk) != TAR_FORMAT_GNU { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        let rs, ok = tar_parse_numeric(r.blk[483..495]);
        if !ok { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        r.size = rs;
        r.sparse = true;
        tar_set_span(r, TSP_SPD, r.buf.len, 0);
        r.gnu_total = 97;
        let e = tar_gnu_sparse_entries(r, 386, 4);
        if e < 0 { return e; }
        if r.blk[482] > 0 {
            r.state = TRS_GNU_EXT;
            r.fill = 0;
            return 0;
        }
        return tar_sparse_ready(r);
    }
    let major = tar_pax_value(r, "GNU.sparse.major");
    let minor = tar_pax_value(r, "GNU.sparse.minor");
    var is1x0 = false;
    if major == "0" && (minor == "0" || minor == "1") {
        is1x0 = false;
    } else if major == "1" && minor == "0" {
        is1x0 = true;
    } else if major.len > 0 || minor.len > 0 {
        return tar_emit(r);
    } else if tar_pax_value(r, "GNU.sparse.map").len > 0 {
        is1x0 = false;
    } else {
        return tar_emit(r);
    }
    tar_span_from_pax(r, TSP_NAME, "GNU.sparse.name");
    var size = tar_pax_value(r, "GNU.sparse.size");
    if size.len == 0 { size = tar_pax_value(r, "GNU.sparse.realsize"); }
    if size.len > 0 {
        let n, ok = tar_parse_int(size);
        if !ok { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        r.size = n;
    }
    r.sparse = true;
    tar_set_span(r, TSP_SPD, r.buf.len, 0);
    if is1x0 {
        r.state = TRS_MAP;
        r.fill = 0;
        r.map_total = 0;
        r.map_lines = 0;
        r.map_need = 1;
        r.map_n = -1;
        r.map_used = 0;
        tar_set_span(r, TSP_MAP, r.buf.len, 0);
        return 0;
    }
    // 0.1 (and 0.0): the map is in the records.
    let nb, ok = tar_parse_int(tar_pax_value(r, "GNU.sparse.numblocks"));
    if !ok || nb < 0 || nb > 0x3fffffffffffffff { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    let m = tar_pax_value(r, "GNU.sparse.map");
    var count = 0;
    if m.len > 0 { count = 1; for c in m { if c == ',' { count++; } } }
    if count != 2 * nb { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    // Go splits the map at commas and parses it a pair at a time.
    var p = 0;
    while p < m.len {
        let c1 = position(m[p..], ',');
        let o_end = if c1 < 0 { m.len } else { p + c1 };
        let p2 = o_end + 1;
        let c2 = if p2 > m.len { -1 } else { position(m[p2..], ',') };
        let l_end = if c2 < 0 { m.len } else { p2 + c2 };
        let o, ok1 = tar_parse_int(m[p..o_end]);
        let l, ok2 = tar_parse_int(m[min(p2, m.len)..l_end]);
        if !ok1 || !ok2 { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        if !tar_add_spd(r, o, l) { return tar_fail(r, ERR_LIMIT, TAR_WHY_SPARSE_TOO_LONG); }
        p = l_end + 1;
    }
    return tar_sparse_ready(r);
}

// The sparse map is read: Go checks and inverts it; then the header is ready.
fn tar_sparse_ready(r: TarReader&) -> i64 {
    let spd = r.sp[TSP_SPD];
    let n = spd.len / 16;
    let size = r.size;
    if tar_header_only(r.typeflag) || size < 0 { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    var pre_end: i64 = 0;
    for i in n {
        let o = tar_get_i64(r.buf, spd.off + i * 16);
        let l = tar_get_i64(r.buf, spd.off + i * 16 + 8);
        if o < 0 || l < 0 || o > 0x7fffffffffffffff - l || o + l > size || pre_end > o {
            return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER);
        }
        pre_end = o + l;
    }
    // Go's invertSparseEntries: the holes, ending in one (perhaps empty) at the end.
    let start = r.buf.len;
    var pre_off: i64 = 0;
    for i in n {
        let o = tar_get_i64(r.buf, spd.off + i * 16);
        let l = tar_get_i64(r.buf, spd.off + i * 16 + 8);
        if l == 0 { continue; }
        if o - pre_off > 0 {
            tar_put_i64(r.buf, pre_off);
            tar_put_i64(r.buf, o - pre_off);
        }
        pre_off = o + l;
    }
    tar_put_i64(r.buf, pre_off);
    tar_put_i64(r.buf, size - pre_off);
    tar_set_span(r, TSP_HOLES, start, r.buf.len - start);
    r.nholes = (r.buf.len - start) / 16;
    r.logical = size;
    r.pos = 0;
    r.hole = 0;
    return tar_emit(r);
}

// The header is ready to hand out.
fn tar_emit(r: TarReader&) -> i64 {
    if (r.facc & TAR_FORMAT_USTAR) != 0 && (r.facc & TAR_FORMAT_PAX) != 0 { r.facc &= TAR_FORMAT_USTAR; }
    r.hformat = r.facc;
    r.insecure = r.check_paths && !tar_is_local(tar_span(r, TSP_NAME));
    r.emitted = true;
    r.skip = false;
    r.state = TRS_DATA;
    return TAR_HEADER;
}

// A whole header block is in r.blk.
fn tar_block(r: TarReader&) -> i64 {
    r.fill = 0;
    if r.state == TRS_ZERO2 {
        if tar_is_zero_block(r.blk) { r.state = TRS_END; return STREAM_END; }
        return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER);
    }
    if r.emitted { tar_new_entry(r); }
    if tar_is_zero_block(r.blk) { r.state = TRS_ZERO2; return 0; }
    let hstart = r.buf.len;
    let e = tar_read_header(r);
    if e < 0 { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    if !tar_regular(r) { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
    r.facc &= r.hformat;
    let t = r.typeflag;
    if t == TAR_TYPE_XHEADER || t == TAR_TYPE_XGLOBAL || t == TAR_TYPE_GNU_LONGNAME || t == TAR_TYPE_GNU_LONGLINK {
        r.facc &= if t == TAR_TYPE_XHEADER || t == TAR_TYPE_XGLOBAL { TAR_FORMAT_PAX } else { TAR_FORMAT_GNU };
        r.spec_size = r.phys;
        r.spec_need = if r.phys > TAR_MAX_SPECIAL { TAR_MAX_SPECIAL + 1 } else { r.phys };
        // The meta header's own strings are not needed, but a global
        // header's name is: keep them until the special file is read.
        tar_set_span(r, TSP_RAW, r.buf.len, 0);
        r.state = TRS_SPECIAL;
        r.hstart = hstart;
        r.hend = r.buf.len;
        return 0;
    }
    return tar_file_header(r);
}

// The special file (TSP_RAW) was read.
fn tar_special_done(r: TarReader&) -> i64 {
    if r.spec_size > TAR_MAX_SPECIAL { return tar_fail(r, ERR_LIMIT, TAR_WHY_FIELD_TOO_LONG); }
    r.phys = 0;
    let t = r.typeflag;
    if t != TAR_TYPE_XGLOBAL {
        // The meta header's own strings are not needed.
        tar_cut(r, r.hstart, r.hend - r.hstart);
        for k in [TSP_NAME, TSP_LINK, TSP_UNAME, TSP_GNAME] { r.sp[k] = TarSpan { .. }; }
    }
    if t == TAR_TYPE_XHEADER || t == TAR_TYPE_XGLOBAL {
        if !tar_parse_pax(r) { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
        let raw = r.sp[TSP_RAW];
        tar_cut(r, raw.off, raw.len);
        r.sp[TSP_RAW] = TarSpan { .. };
        if t == TAR_TYPE_XGLOBAL {
            // Go hands out a global header of its own, with its name,
            // records and format only.
            tar_span_from_pax(r, TSP_NAME, "path");
            r.sp[TSP_LINK] = TarSpan { .. };
            r.sp[TSP_UNAME] = TarSpan { .. };
            r.sp[TSP_GNAME] = TarSpan { .. };
            r.size = 0; r.mode = 0; r.uid = 0; r.gid = 0;
            r.mtime = TarTime { .. }; r.atime = TarTime { .. }; r.ctime = TarTime { .. };
            r.devmajor = 0; r.devminor = 0;
            r.hformat = r.facc;
            r.insecure = r.check_paths && !tar_is_local(tar_span(r, TSP_NAME));
            r.emitted = true;
            r.skip = false;
            r.sparse = false;
            r.state = TRS_DATA;
            return TAR_HEADER;
        }
    } else {
        let raw = r.sp[TSP_RAW];
        let s = tar_cstr(r.buf[raw.off..raw.off + raw.len]);
        let slen = s.len;
        let k = if t == TAR_TYPE_GNU_LONGNAME { TSP_LONGNAME } else { TSP_LONGLINK };
        let old = r.sp[k];
        tar_cut(r, raw.off + slen, raw.len - slen);
        tar_set_span(r, k, raw.off, slen);
        r.sp[TSP_RAW] = TarSpan { .. };
        if old.len > 0 { tar_cut(r, old.off, old.len); }
    }
    r.state = TRS_PAD;
    return 0;
}

// Takes up to want bytes of input for a block in r.blk.
fn tar_fill(r: TarReader&, input: const u8[:], at: i64) -> i64 {
    let n = min(512 - r.fill, input.len - at);
    r.blk[r.fill..r.fill + n].move_from(input[at..at + n]);
    r.fill += n;
    return n;
}

// Reads the archive in `input`, writing an entry's contents into `out`:
// the input used, the bytes written, and TAR_HEADER (a header is ready:
// tar_header), 0 (more input, or more room in out, is needed),
// STREAM_END (the end of the archive), or an error (tar_why says which
// of Go's). A call that hands out a header writes no contents, and the
// call that ends an entry's contents returns there (having perhaps used
// and written nothing): the header stays valid until the call after it.
// tar_skip passes over the rest of an entry without writing it.
fn tar_read(r: TarReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    var at = 0;
    var made = 0;
    while true {
        let st = r.state;
        if st == TRS_FAILED { return at, made, r.err; }
        if st == TRS_END { return at, made, STREAM_END; }
        if st == TRS_HEADER || st == TRS_ZERO2 {
            at += tar_fill(r, input, at);
            if r.fill < 512 { return at, made, 0; }
            let e = tar_block(r);
            if e != 0 { return at, made, e; }
        } else if st == TRS_SPECIAL {
            let raw = r.sp[TSP_RAW];
            let n = min(r.spec_need - raw.len, input.len - at);
            r.buf.append(input[at..at + n]);
            r.sp[TSP_RAW].len += n;
            at += n;
            if r.sp[TSP_RAW].len < r.spec_need { return at, made, 0; }
            let e = tar_special_done(r);
            if e != 0 { return at, made, e; }
        } else if st == TRS_PAD {
            let n = min(r.pad_left, input.len - at);
            at += n;
            r.pad_left -= n;
            if r.pad_left > 0 { return at, made, 0; }
            r.state = TRS_HEADER;
            r.fill = 0;
        } else if st == TRS_GNU_EXT {
            at += tar_fill(r, input, at);
            if r.fill < 512 { return at, made, 0; }
            r.fill = 0;
            r.gnu_total += 512;
            if r.gnu_total >= TAR_MAX_SPECIAL { tar_fail(r, ERR_LIMIT, TAR_WHY_SPARSE_TOO_LONG); continue; }
            let e = tar_gnu_sparse_entries(r, 0, 21);
            if e < 0 { return at, made, e; }
            if r.blk[504] == 0 {
                let e2 = tar_sparse_ready(r);
                if e2 != 0 { return at, made, e2; }
            }
        } else if st == TRS_MAP {
            let e = tar_map_step(r, input, at);
            at += r.spec_need;     // the bytes the step took
            if e != 0 { return at, made, e; }
            if r.state == TRS_MAP { return at, made, 0; }
        } else {
            // TRS_DATA. The call that ends an entry's contents returns
            // there (having perhaps used and written nothing), so the
            // header stays valid until the next call.
            let used, wrote, e = tar_data(r, input[at..], out[made..]);
            at += used;
            made += wrote;
            if e != 0 { return at, made, e; }
            return at, made, 0;
        }
    }
    return at, made, 0;
}

// A step of reading a 1.0 sparse map (Go's readGNUSparseMap1x0) from the
// entry's data; r.spec_need is set to the input it took.
fn tar_map_step(r: TarReader&, input: const u8[:], at: i64) -> i64 {
    r.spec_need = 0;
    while true {
        while r.map_lines < r.map_need {
            if r.fill == 0 {
                if r.map_total + 512 > TAR_MAX_SPECIAL { return tar_fail(r, ERR_LIMIT, TAR_WHY_SPARSE_TOO_LONG); }
                if r.phys < 512 { return tar_fail(r, ERR_TRUNCATED, TAR_WHY_TRUNCATED); }
            }
            let n = tar_fill(r, input, at + r.spec_need);
            r.spec_need += n;
            if r.fill < 512 { return 0; }
            r.fill = 0;
            r.map_total += 512;
            r.phys -= 512;
            r.buf.append(r.blk[..]);
            r.sp[TSP_MAP].len += 512;
            for c in r.blk { if c == '\n' { r.map_lines++; } }
        }
        let m = r.sp[TSP_MAP];
        if r.map_n < 0 {
            // The number of entries, the first line.
            let s = r.buf[m.off..m.off + m.len];
            let nl = position(s, '\n');
            let n, ok = tar_parse_int(s[..nl]);
            if !ok || n < 0 || n > 0x3fffffffffffffff { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
            r.map_n = n;
            r.map_used = nl + 1;
            r.map_need = 1 + 2 * n;
            continue;
        }
        var p = m.off + r.map_used;
        let end = m.off + m.len;
        for i in r.map_n {
            let nl1 = position(r.buf[p..end], '\n');
            let p2 = p + nl1 + 1;
            let nl2 = position(r.buf[p2..end], '\n');
            let o, ok1 = tar_parse_int(r.buf[p..p + nl1]);
            let l, ok2 = tar_parse_int(r.buf[p2..p2 + nl2]);
            if !ok1 || !ok2 { return tar_fail(r, ERR_HEADER, TAR_WHY_HEADER); }
            if !tar_add_spd(r, o, l) { return tar_fail(r, ERR_LIMIT, TAR_WHY_SPARSE_TOO_LONG); }
            p = p2 + nl2 + 1;
        }
        return tar_sparse_ready(r);
    }
    return 0;
}

// Writes zeros.
fn tar_zero(out: u8[:]) { for &b in out { b = 0; } }

// The entry's contents: input used, bytes written, and 0 or an error.
fn tar_data(r: TarReader&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    var at = 0;
    var made = 0;
    if r.skip || !r.sparse {
        while r.phys > 0 {
            let n = if r.skip { min(r.phys, input.len - at) } else { min(min(r.phys, input.len - at), out.len - made) };
            if n == 0 { return at, made, 0; }
            if !r.skip { out[made..made + n].move_from(input[at..at + n]); made += n; }
            at += n;
            r.phys -= n;
        }
        r.state = TRS_PAD;
        return at, made, 0;
    }
    let h = r.sp[TSP_HOLES];
    while r.pos < r.logical && made < out.len {
        let hs = tar_get_i64(r.buf, h.off + r.hole * 16);
        let he = hs + tar_get_i64(r.buf, h.off + r.hole * 16 + 8);
        var n: i64 = 0;
        if r.pos < hs {
            if r.phys == 0 { return at, made, tar_fail(r, ERR_DATA, TAR_WHY_MISS_DATA); }
            n = min(min(out.len - made, hs - r.pos), min(r.phys, input.len - at));
            if n == 0 { return at, made, 0; }
            out[made..made + n].move_from(input[at..at + n]);
            at += n;
            r.phys -= n;
        } else {
            n = min(out.len - made, he - r.pos);
            tar_zero(out[made..made + n]);
        }
        made += n;
        r.pos += n;
        if r.pos >= he && r.hole < r.nholes - 1 { r.hole++; }
    }
    if r.pos < r.logical { return at, made, 0; }
    if r.phys > 0 { return at, made, tar_fail(r, ERR_DATA, TAR_WHY_UNREF_DATA); }
    r.state = TRS_PAD;
    return at, made, 0;
}

// --- Whole archives ---------------------------------------------------------

// Reads a whole archive in memory, calling F(header, contents) for each
// entry (contents in a buffer that is reused; at most `limit` bytes an
// entry, else ERR_LIMIT). STREAM_END at the archive's end, or an error.
fn tar_each<F>(data: const u8[:], limit: i64 = 1 << 30, check_paths: bool = false) -> i64 {
    var r = tar_reader(check_paths);
    var content: u8[>..] = [];
    var at = 0;
    while true {
        let used, made, st = tar_read(r, data[at..], content[..0]);
        at += used;
        if st == STREAM_END { return STREAM_END; }
        if st < 0 { return st; }
        if st == TAR_HEADER {
            content.clear();
            let want = tar_remaining(r);
            if want > limit { return ERR_LIMIT; }
            content.resize(want, 0);
            var got = 0;
            while got < want {
                let u, m, s = tar_read(r, data[at..], content[got..]);
                at += u;
                got += m;
                if s < 0 { return s; }
                if u == 0 && m == 0 { return tar_finish(r); }
            }
            F(tar_header(r), content[..]);
            continue;
        }
        if at >= data.len { return tar_finish(r); }
    }
    return 0;
}

// --- Writing -----------------------------------------------------------------

struct TarWriter {
    err: i64,           // a lasting error (Go's tw.err)
    ewhy: i64,          // which one
    why: i64,           // which of Go's errors the last call's was
    nb: i64,            // bytes of the entry still to write
    padn: i64,
}

fn tar_writer() -> TarWriter { TarWriter { err: 0, ewhy: 0, why: 0, nb: 0, padn: 0 } }

fn tar_writer_why(w: const TarWriter&) -> i64 { w.why }

fn tar_wfail(w: TarWriter&, code: i64, why: i64) -> i64 {
    w.err = code;
    w.ewhy = why;
    w.why = why;
    return code;
}

fn tar_werr(w: TarWriter&) -> i64 {
    w.why = w.ewhy;
    return w.err;
}

fn tar_wnote(w: TarWriter&, code: i64, why: i64) -> i64 {
    w.why = why;
    return code;
}

// Go's Flush: the padding after an entry written whole. ERR_ARGUMENT
// (TAR_WHY_MISSED_WRITING) if the entry's contents are not all written.
fn tar_flush(w: TarWriter&, out: u8[>..]&) -> i64 {
    if w.err != 0 { return tar_werr(w); }
    if w.nb > 0 { return tar_wnote(w, ERR_ARGUMENT, TAR_WHY_MISSED_WRITING); }
    for i in w.padn { out.push(0); }
    w.padn = 0;
    return 0;
}

// Writes the next entry's contents: the bytes taken, and 0, or
// ERR_TOO_LARGE (TAR_WHY_WRITE_TOO_LONG) for more than the header's size
// (the rest is not written; the writer goes on), or a lasting error.
fn tar_write(w: TarWriter&, data: const u8[:], out: u8[>..]&) -> i64, i64 {
    if w.err != 0 { return 0, tar_werr(w); }
    let n = min(data.len, w.nb);
    out.append(data[..n]);
    w.nb -= n;
    if n < data.len { return n, tar_wnote(w, ERR_TOO_LARGE, TAR_WHY_WRITE_TOO_LONG); }
    return n, 0;
}

// Ends the archive: the last padding and two blocks of zeros. Later
// calls are refused (TAR_WHY_WRITE_AFTER_CLOSE) but a second close is 0.
fn tar_close(w: TarWriter&, out: u8[>..]&) -> i64 {
    if w.err == ERR_ARGUMENT && w.ewhy == TAR_WHY_WRITE_AFTER_CLOSE { return 0; }
    if w.err != 0 { return tar_werr(w); }
    let e = tar_flush(w, out);
    if e == 0 { for i in 1024 { out.push(0); } }
    // Go reports the flush's error, and refuses what comes after either way.
    w.err = ERR_ARGUMENT;
    w.ewhy = TAR_WHY_WRITE_AFTER_CLOSE;
    return e;
}

fn tar_is_ascii(s: const u8[:]) -> bool {
    for c in s { if c >= 0x80 || c == 0 { return false; } }
    return true;
}

fn tar_fits_octal(n: i64, x: i64) -> bool {
    let bits = (n - 1) * 3;
    return x >= 0 && (n >= 22 || x < (1 << bits));
}

fn tar_fits_base256(n: i64, x: i64) -> bool {
    if n >= 9 { return true; }
    let bits = (n - 1) * 8;
    return x >= -(1 << bits) && x < (1 << bits);
}

// Go's splitUSTARPath: the prefix's length (the name is after it and a
// slash), or -1.
fn tar_split_ustar(name: const u8[:]) -> i64 {
    var length = name.len;
    if length <= 100 || !tar_is_ascii(name) { return -1; }
    if length > 156 { length = 156; }
    else if name[length - 1] == '/' { length--; }
    let i = rfind(name[..length], "/");
    let nlen = name.len - i - 1;
    if i <= 0 || nlen > 100 || nlen == 0 || i > 155 { return -1; }
    return i;
}

// Go's formatPAXTime.
fn tar_format_pax_time(out: u8[>..]&, t: TarTime) {
    var secs = t.sec;
    var ns = t.nsec;
    if ns == 0 { format(out, secs); return; }
    if secs < 0 {
        out.push('-');
        secs = -(secs + 1);
        ns = 1000000000 - ns;
    }
    format(out, secs);
    out.push('.');
    var digits: u8[9] = [0; 9];
    var x = ns;
    for i in 9 { digits[8 - i] = ('0' + (x % 10)) as! u8; x /= 10; }
    var last = 9;
    while last > 0 && digits[last - 1] == '0' { last--; }
    out.append(digits[..last]);
}

fn tar_format_int(out: u8[>..]&, x: i64) { format(out, x); }

// The record set the writer builds: entries over a store.
struct TarRec { koff: i64, klen: i64, voff: i64, vlen: i64 }

// Go's formatter.formatString into b.
fn tar_put_string(b: u8[:], s: const u8[:]) {
    let n = min(s.len, b.len);
    b[..n].move_from(s[..n]);
    if s.len < b.len { b[s.len] = 0; }
    if s.len > b.len && b[b.len - 1] == '/' {
        var k = b.len - 1;
        while k > 0 && s[k - 1] == '/' { k--; }
        b[k] = 0;
    }
}

// Go's formatOctal (false when x does not fit, and 0 is written).
fn tar_put_octal(b: u8[:], x0: i64) -> bool {
    var x = x0;
    var ok = true;
    if !tar_fits_octal(b.len, x) { x = 0; ok = false; }
    var s: u8[..24] = [];
    format_int(s, x, 8, b.len - 1, '0');
    tar_put_string(b, s);
    return ok;
}

// Go's formatNumeric: octal, else base-256.
fn tar_put_numeric(b: u8[:], x: i64) -> bool {
    if tar_fits_octal(b.len, x) { return tar_put_octal(b, x); }
    if tar_fits_base256(b.len, x) {
        var v = x;
        var i = b.len - 1;
        while i >= 0 {
            b[i] = (v & 0xff) as! u8;
            v >>= 8;
            i--;
        }
        b[0] |= 0x80;
        return true;
    }
    tar_put_octal(b, 0);
    return false;
}

// Go's block.setFormat: the magic and the checksum.
fn tar_set_format(b: u8[512]&, format: i64) {
    if (format & TAR_FORMAT_V7) != 0 {
    } else if (format & TAR_FORMAT_GNU) != 0 {
        b[257..263].move_from("ustar ");
        b[263..265].move_from(" \x00");
    } else if (format & TAR_FORMAT_STAR) != 0 {
        b[257..263].move_from("ustar\x00");
        b[263..265].move_from("00");
        b[508..512].move_from("tar\x00");
    } else {
        b[257..263].move_from("ustar\x00");
        b[263..265].move_from("00");
    }
    let u, s = tar_checksums(b);
    tar_put_octal(b[148..155], u);
    b[155] = ' ';
}

// Go's toASCII.
fn tar_to_ascii(out: u8[>..]&, s: const u8[:]) {
    for c in s { if c < 0x80 && c != 0 { out.push(c); } }
}

// Go's templateV7Plus: the fields every format has. numeric says
// whether numbers may be base-256 (GNU); ascii whether strings are made
// ASCII first (PAX).
fn tar_template(b: u8[512]&, h: const TarHeader&, name: const u8[:], numeric: bool, ascii: bool) {
    for &c in b { c = 0; }
    b[156] = h.typeflag;
    var tmp: u8[>..] = [];
    tar_put_str(b[0..100], name, ascii, tmp);
    tar_put_str(b[157..257], h.linkname, ascii, tmp);
    tar_put_num(b[100..108], h.mode, numeric);
    tar_put_num(b[108..116], h.uid, numeric);
    tar_put_num(b[116..124], h.gid, numeric);
    tar_put_num(b[124..136], h.size, numeric);
    let mt = if tar_time_is_zero(h.mtime) { 0 } else { h.mtime.sec };
    tar_put_num(b[136..148], mt, numeric);
    tar_put_str(b[265..297], h.uname, ascii, tmp);
    tar_put_str(b[297..329], h.gname, ascii, tmp);
    tar_put_num(b[329..337], h.devmajor, numeric);
    tar_put_num(b[337..345], h.devminor, numeric);
}

fn tar_put_str(b: u8[:], s: const u8[:], ascii: bool, tmp: u8[>..]&) {
    if !ascii { tar_put_string(b, s); return; }
    tmp.clear();
    tar_to_ascii(tmp, s);
    tar_put_string(b, tmp);
}

fn tar_put_num(b: u8[:], x: i64, numeric: bool) {
    if numeric { tar_put_numeric(b, x); } else { tar_put_octal(b, x); }
}

// Go's writeRawHeader: the block, then the entry's data is due.
fn tar_raw_header(w: TarWriter&, b: const u8[512]&, size: i64, flag: u8, out: u8[>..]&) -> i64 {
    let e = tar_flush(w, out);
    if e != 0 { return e; }
    out.append(b[..]);
    let n = if tar_header_only(flag) { 0 } else { size };
    w.nb = n;
    w.padn = tar_padding(n);
    return 0;
}

// Go's writeRawFile: a special header and its data.
fn tar_raw_file(w: TarWriter&, name0: const u8[:], data: const u8[:], flag: u8, format: i64, out: u8[>..]&) -> i64 {
    var b: u8[512] = [0; 512];
    var name: u8[>..] = [];
    tar_to_ascii(name, name0);
    if name.len > 100 { name.resize(100); }
    while name.len > 0 && name[name.len - 1] == '/' { name.pop(); }
    b[156] = flag;
    tar_put_string(b[0..100], name);
    tar_put_octal(b[100..108], 0);
    tar_put_octal(b[108..116], 0);
    tar_put_octal(b[116..124], 0);
    let ok = tar_put_octal(b[124..136], data.len);
    tar_put_octal(b[136..148], 0);
    tar_set_format(b, format);
    if !ok { return tar_wfail(w, ERR_LIMIT, TAR_WHY_FIELD_TOO_LONG); }
    let e = tar_raw_header(w, b, data.len, flag, out);
    if e != 0 { return e; }
    let n, e2 = tar_write(w, data, out);
    return e2;
}

let TAR_BASIC_KEYS: const u8[:][10] = ["path", "linkpath", "size", "uid", "gid", "uname", "gname", "mtime", "atime", "ctime"];

fn tar_rec_key(store: const u8[:], e: TarRec) -> const u8[:] { store[e.koff..e.koff + e.klen] }
fn tar_rec_val(store: const u8[:], e: TarRec) -> const u8[:] { store[e.voff..e.voff + e.vlen] }

fn tar_rec_has(store: const u8[:], recs: const TarRec[:], k: const u8[:]) -> bool {
    for e in recs { if tar_rec_key(store, e) == k { return true; } }
    return false;
}

// paxHdrs[k] = v, for a key not set before (the values Go sets twice
// are the same).
fn tar_rec_set(store: u8[>..]&, recs: TarRec[>..]&, k: const u8[:], v: const u8[:]) {
    if tar_rec_has(store, recs, k) { return; }
    let ko = store.len;
    store.append(k);
    let vo = store.len;
    store.append(v);
    recs.push(TarRec { koff: ko, klen: k.len, voff: vo, vlen: v.len });
}

// Writes an entry's header (Go's WriteHeader), then its contents are due
// (tar_write, `size` bytes for a regular file). 0, ERR_HEADER
// (TAR_WHY_CANNOT_ENCODE: no format can hold the header; nothing is
// written and the writer goes on), ERR_ARGUMENT (TAR_WHY_MISSED_WRITING:
// the entry before is not all written), or a lasting error.
fn tar_write_header(w: TarWriter&, h0: TarHeader, out: u8[>..]&) -> i64 {
    let e0 = tar_flush(w, out);
    if e0 != 0 { return e0; }
    var h = h0;
    if h.typeflag == TAR_TYPE_REGA {
        h.typeflag = if h.name.len > 0 && h.name[h.name.len - 1] == '/' { TAR_TYPE_DIR } else { TAR_TYPE_REG };
    }
    if h.format == TAR_FORMAT_UNKNOWN {
        if h.mtime.valid && h.mtime.nsec >= 500000000 { h.mtime = tar_time(h.mtime.sec + 1); }
        else if h.mtime.valid { h.mtime = tar_time(h.mtime.sec); }
        h.atime = TarTime { .. };
        h.ctime = TarTime { .. };
    }
    // The user's records, each key's last (Go has a map).
    var urecs: TarRec[>..] = [];
    var bad_rec = false;
    {
        var p = 0;
        while p < h.pax.len {
            let ko, kl, vo, vl, n, ok = tar_pax_record_raw(h.pax[p..]);
            if !ok { bad_rec = true; break; }
            urecs.push(TarRec { koff: p + ko, klen: kl, voff: p + vo, vlen: vl });
            p += n;
        }
    }
    if bad_rec { return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE); }
    let upax = h.pax;
    stable_sort(urecs) { a, b => compare(tar_rec_key(upax, a), tar_rec_key(upax, b)) < 0 };
    var udedup: TarRec[>..] = [];
    for e, i in urecs {
        if i + 1 < urecs.len && tar_rec_key(upax, urecs[i + 1]) == tar_rec_key(upax, e) { continue; }
        udedup.push(e);
    }
    // Go's allowedFormats.
    var fmts = TAR_FORMAT_USTAR | TAR_FORMAT_PAX | TAR_FORMAT_GNU;
    var store: u8[>..] = [];
    var recs: TarRec[>..] = [];
    var prefer_pax = false;
    var num: u8[>..] = [];

    // verifyString
    for which in 4 {
        let s = match which { 0 => h.name, 1 => h.linkname, 2 => h.uname, _ => h.gname };
        let size = match which { 0 => 100, 1 => 100, _ => 32 };
        let key = match which { 0 => "path", 1 => "linkpath", 2 => "uname", _ => "gname" };
        let too_long = s.len > size;
        let allow_long_gnu = which < 2;
        if position(s, 0) >= 0 || (too_long && !allow_long_gnu) { fmts &= ~TAR_FORMAT_GNU; }
        if !tar_is_ascii(s) || too_long {
            if which != 0 || tar_split_ustar(s) < 0 { fmts &= ~TAR_FORMAT_USTAR; }
            tar_rec_set(store, recs, key, s);
        }
        let v, found = tar_pax_get(h.pax, key);
        if found && v == s { tar_rec_set(store, recs, key, v); }
    }
    // verifyNumeric
    for which in 6 {
        let x = match which { 0 => h.mode, 1 => h.uid, 2 => h.gid, 3 => h.size, 4 => h.devmajor, _ => h.devminor };
        let size = match which { 3 => 12, _ => 8 };
        let key = match which { 1 => "uid", 2 => "gid", 3 => "size", _ => "" };
        if !tar_fits_base256(size, x) { fmts &= ~TAR_FORMAT_GNU; }
        num.clear();
        format(num, x);
        if !tar_fits_octal(size, x) {
            fmts &= ~TAR_FORMAT_USTAR;
            if key.len == 0 { fmts &= ~TAR_FORMAT_PAX; }
            else { tar_rec_set(store, recs, key, num); }
        }
        let v, found = tar_pax_get(h.pax, key);
        if found && v == num[..] { tar_rec_set(store, recs, key, v); }
    }
    // verifyTime
    for which in 3 {
        let t = match which { 0 => h.mtime, 1 => h.atime, _ => h.ctime };
        let key = match which { 0 => "mtime", 1 => "atime", _ => "ctime" };
        if !tar_time_is_zero(t) {
            if !tar_fits_base256(12, t.sec) { fmts &= ~TAR_FORMAT_GNU; }
            let is_mtime = which == 0;
            let fits = tar_fits_octal(12, t.sec);
            if (is_mtime && !fits) || !is_mtime { fmts &= ~TAR_FORMAT_USTAR; }
            num.clear();
            tar_format_pax_time(num, t);
            if !is_mtime || !fits || t.nsec != 0 {
                prefer_pax = true;
                tar_rec_set(store, recs, key, num);
            }
            let v, found = tar_pax_get(h.pax, key);
            if found && v == num[..] { tar_rec_set(store, recs, key, v); }
        }
    }
    let t = h.typeflag;
    if t == TAR_TYPE_REG || t == TAR_TYPE_CHAR || t == TAR_TYPE_BLOCK || t == TAR_TYPE_FIFO || t == TAR_TYPE_GNU_SPARSE {
        if h.name.len > 0 && h.name[h.name.len - 1] == '/' { return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE); }
    } else if t == TAR_TYPE_XHEADER || t == TAR_TYPE_GNU_LONGNAME || t == TAR_TYPE_GNU_LONGLINK {
        return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE);
    } else if t == TAR_TYPE_XGLOBAL {
        if h.linkname.len != 0 || h.size != 0 || h.mode != 0 || h.uid != 0 || h.gid != 0 || h.uname.len != 0
            || h.gname.len != 0 || h.mtime.valid || h.atime.valid || h.ctime.valid || h.devmajor != 0 || h.devminor != 0 {
            return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE);
        }
        fmts &= TAR_FORMAT_PAX;
    }
    if !tar_header_only(t) && h.size < 0 { return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE); }
    if udedup.len > 0 {
        for e in udedup {
            let k = tar_rec_key(upax, e);
            if tar_rec_has(store, recs, k) { continue; }
            var basic = false;
            for bk in TAR_BASIC_KEYS { if k == bk { basic = true; } }
            if t == TAR_TYPE_XGLOBAL || (!basic && !starts_with(k, "GNU.sparse.")) {
                tar_rec_set(store, recs, k, tar_rec_val(upax, e));
            }
        }
        fmts &= TAR_FORMAT_PAX;
    }
    for e in recs {
        if !tar_valid_pax_record(tar_rec_key(store, e), tar_rec_val(store, e)) {
            return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE);
        }
    }
    if h.format != TAR_FORMAT_UNKNOWN {
        var want = h.format;
        if (want & TAR_FORMAT_PAX) != 0 && !prefer_pax { want |= TAR_FORMAT_USTAR; }
        fmts &= want;
    }
    if (fmts & TAR_FORMAT_USTAR) != 0 { return tar_write_ustar(w, h, out); }
    if (fmts & TAR_FORMAT_PAX) != 0 { return tar_write_pax(w, h, store, recs, out); }
    if (fmts & TAR_FORMAT_GNU) != 0 { return tar_write_gnu(w, h, out); }
    return tar_wnote(w, ERR_HEADER, TAR_WHY_CANNOT_ENCODE);
}

fn tar_write_ustar(w: TarWriter&, h: const TarHeader&, out: u8[>..]&) -> i64 {
    var b: u8[512] = [0; 512];
    let i = tar_split_ustar(h.name);
    let name = if i >= 0 { h.name[i + 1..] } else { h.name };
    let prefix = if i >= 0 { h.name[..i] } else { h.name[..0] };
    tar_template(b, h, name, false, false);
    tar_put_string(b[345..500], prefix);
    tar_set_format(b, TAR_FORMAT_USTAR);
    return tar_raw_header(w, b, h.size, h.typeflag, out);
}

// path.Join(dir, "PaxHeaders.0", file) for name's path.Split.
fn tar_pax_header_name(out: u8[>..]&, name: const u8[:]) {
    let slash = rfind(name, "/");
    let dir = name[..slash + 1];
    let file = name[slash + 1..];
    var joined: u8[>..] = [];
    if dir.len > 0 { joined.append(dir); joined.push('/'); }
    joined.append("PaxHeaders.0");
    if file.len > 0 { joined.push('/'); joined.append(file); }
    tar_clean(joined, out);
}

fn tar_write_pax(w: TarWriter&, h: const TarHeader&, store: const u8[:], recs: TarRec[>..]&, out: u8[>..]&) -> i64 {
    let global = h.typeflag == TAR_TYPE_XGLOBAL;
    if recs.len > 0 || global {
        stable_sort(recs) { a, b => compare(tar_rec_key(store, a), tar_rec_key(store, b)) < 0 };
        var data: u8[>..] = [];
        for e in recs { tar_pax_append(data, tar_rec_key(store, e), tar_rec_val(store, e)); }
        var name: u8[>..] = [];
        var flag = TAR_TYPE_XHEADER;
        if global {
            name.append(if h.name.len > 0 { h.name } else { "GlobalHead.0.0" });
            flag = TAR_TYPE_XGLOBAL;
        } else {
            tar_pax_header_name(name, h.name);
        }
        if data.len > TAR_MAX_SPECIAL { return tar_wfail(w, ERR_LIMIT, TAR_WHY_FIELD_TOO_LONG); }
        let e = tar_raw_file(w, name, data, flag, TAR_FORMAT_PAX, out);
        if e != 0 || global { return e; }
    }
    var b: u8[512] = [0; 512];
    tar_template(b, h, h.name, false, true);
    tar_set_format(b, TAR_FORMAT_PAX);
    return tar_raw_header(w, b, h.size, h.typeflag, out);
}

fn tar_write_gnu(w: TarWriter&, h: const TarHeader&, out: u8[>..]&) -> i64 {
    var tmp: u8[>..] = [];
    if h.name.len > 100 {
        tmp.append(h.name);
        tmp.push(0);
        let e = tar_raw_file(w, "././@LongLink", tmp, TAR_TYPE_GNU_LONGNAME, TAR_FORMAT_GNU, out);
        if e != 0 { return e; }
    }
    if h.linkname.len > 100 {
        tmp.clear();
        tmp.append(h.linkname);
        tmp.push(0);
        let e = tar_raw_file(w, "././@LongLink", tmp, TAR_TYPE_GNU_LONGLINK, TAR_FORMAT_GNU, out);
        if e != 0 { return e; }
    }
    var b: u8[512] = [0; 512];
    tar_template(b, h, h.name, true, false);
    if !tar_time_is_zero(h.atime) { tar_put_numeric(b[345..357], h.atime.sec); }
    if !tar_time_is_zero(h.ctime) { tar_put_numeric(b[357..369], h.ctime.sec); }
    tar_set_format(b, TAR_FORMAT_GNU);
    return tar_raw_header(w, b, h.size, h.typeflag, out);
}
