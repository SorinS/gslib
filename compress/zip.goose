// compress.zip: zip archives, as Go's archive/zip reads and writes them.
//
// Reading. The archive is in memory (zip_open), or only its end is: the
// central directory and the records after it (zip_open_tail, given the
// archive's size), for an archive too large to hold whole. The reader
// keeps one fixed-size record a file, its strings as positions into the
// caller's buffer; nothing is copied.
//
//   var r = compress::zip_open(archive);           // r.err: 0, or why not
//   for e in r.entries {
//       let name = compress::zip_name(r, archive, e);
//       var f = compress::zip_file_open(r, archive, e);
//       let made, st = compress::zip_file_read_mem(f, archive, out);   // STREAM_END: all checked
//   }
//   compress::zip_extract(r, archive, e, out, limit)     // a file's bytes, appended
//
// A file's data is inflated as it is read, into the caller's room, and
// checked at its end as Go checks it: the size against the directory's,
// then the CRC-32 (against the data descriptor's too, when there is one).
// The streaming form (zip_file_read: compressed bytes fed by the caller)
// serves an archive that is not in memory.
//
// Writing appends the archive to a builder the caller owns:
//
//   var w = compress::zip_writer();
//   compress::zip_create(w, "a.txt", out);          // Deflate, a data descriptor (Go's Create)
//   compress::zip_write(w, data, out);
//   compress::zip_create_header(w, compress::ZipHeader { name: "b/", .. }, out);
//   compress::zip_close(w, out);                     // the central directory
//
// Everything Go's reader and writer do is done here the same way:
// directory search, base-offset recovery for archives with a prefix,
// ZIP64 records and extra fields (read and written by Go's rules), the
// UTF-8 flag (Go's detectUTF8), modification times from the MS-DOS fields
// and the NTFS, Unix, Info-ZIP and extended-timestamp extra fields, with
// Go's time zone inference, Mode() from the external attributes, and the
// GODEBUG=zipinsecurepath check (off by default, as in Go 1.27: pass
// check_paths = true for zipinsecurepath=0). Where Go's errors are values,
// these are compress::ERR_* codes: ErrFormat ERR_FORMAT, ErrAlgorithm
// ERR_UNSUPPORTED, ErrChecksum ERR_CHECKSUM, ErrInsecurePath
// ERR_INSECURE_PATH, io.ErrUnexpectedEOF ERR_TRUNCATED, io.EOF from a read
// past the archive's end ZIP_ERR_EOF, flate's CorruptInputError ERR_DATA.

namespace compress;

import std;
import compress;
import compress.flate;
import compress.deflate;

let ZIP_STORE: u16 = 0;
let ZIP_DEFLATE: u16 = 8;

// io.EOF where Go returns it as an error (a record read entirely past the
// end of the archive).
let ZIP_ERR_EOF: i64 = -100;
// A local header at a negative offset (Go's bytes.Reader refuses the read).
let ZIP_ERR_NEG_OFFSET: i64 = -101;

let ZIP_FILE_SIG: u32 = 0x04034b50;
let ZIP_DIR_SIG: u32 = 0x02014b50;
let ZIP_END_SIG: u32 = 0x06054b50;
let ZIP_END64_LOC_SIG: u32 = 0x07064b50;
let ZIP_END64_SIG: u32 = 0x06064b50;
let ZIP_DESC_SIG: u32 = 0x08074b50;

let ZIP_CREATOR_FAT: u16 = 0;
let ZIP_CREATOR_UNIX: u16 = 3;
let ZIP_CREATOR_NTFS: u16 = 11;
let ZIP_CREATOR_VFAT: u16 = 14;
let ZIP_CREATOR_MACOSX: u16 = 19;

let ZIP_VERSION20: u16 = 20;
let ZIP_VERSION45: u16 = 45;
let ZIP_U16MAX: u64 = 0xffff;
let ZIP_U32MAX: u64 = 0xffffffff;

let ZIP_FLAG_DESCRIPTOR: u16 = 0x8;
let ZIP_FLAG_UTF8: u16 = 0x800;

// Go's fs.FileMode bits, as Mode() gives them.
let ZIP_MODE_DIR: u32 = 0x80000000;
let ZIP_MODE_SYMLINK: u32 = 0x08000000;
let ZIP_MODE_DEVICE: u32 = 0x04000000;
let ZIP_MODE_NAMED_PIPE: u32 = 0x02000000;
let ZIP_MODE_SOCKET: u32 = 0x01000000;
let ZIP_MODE_SETUID: u32 = 0x00800000;
let ZIP_MODE_SETGID: u32 = 0x00400000;
let ZIP_MODE_CHAR_DEVICE: u32 = 0x00200000;
let ZIP_MODE_STICKY: u32 = 0x00100000;
let ZIP_MODE_TYPE: u32 = 0x8f280000;     // dir, symlink, pipe, socket, device, char device, irregular

// --- Times -----------------------------------------------------------------

// A time as Go's time.Time keeps it: seconds since the Unix epoch, the
// nanoseconds within that second, and the offset in seconds of the zone
// it is shown in (which decides its calendar fields). `set` false is Go's
// zero Time.
struct ZipTime { set: bool = false, secs: i64 = 0, nsec: i64 = 0, offset: i64 = 0 }

fn zip_time(secs: i64, nsec: i64 = 0, offset: i64 = 0) -> ZipTime {
    // As time.Unix: the nanoseconds are brought into [0, 1e9).
    var s = secs;
    var n = nsec;
    if n < 0 || n >= 1000000000 {
        s += n / 1000000000;
        n = n % 1000000000;
        if n < 0 {
            n += 1000000000;
            s--;
        }
    }
    return ZipTime { set: true, secs: s, nsec: n, offset: offset };
}

// Days from 1970-01-01 to y-m-d (proleptic Gregorian; m 1-12).
fn zip_days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = div_euclid(y, 400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// The calendar date of a day number: year, month (1-12), day.
fn zip_civil_from_days(z0: i64) -> i64, i64, i64 {
    let z = z0 + 719468;
    let era = div_euclid(z, 146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (if m <= 2 { 1 } else { 0 });
    return y, m, d;
}

// time.Date(y, mon, d, h, mi, s, 0, UTC), with Go's normalization of
// fields out of range.
fn zip_date(y: i64, mon: i64, d: i64, h: i64, mi: i64, s: i64) -> ZipTime {
    let m0 = mon - 1;
    let yy = y + div_euclid(m0, 12);
    let mm = m0 % 12 + 1;
    let days = zip_days_from_civil(yy, mm, 1) + d - 1;
    return zip_time(days * 86400 + h * 3600 + mi * 60 + s);
}

// The MS-DOS date and time fields as Go reads them (in UTC).
fn zip_msdos_time(dos_date: u16, dos_time: u16) -> ZipTime {
    let dd = dos_date as i64;
    let dt = dos_time as i64;
    return zip_date((dd >> 9) + 1980, (dd >> 5) & 0xf, dd & 0x1f, dt >> 11, (dt >> 5) & 0x3f, (dt & 0x1f) * 2);
}

// The MS-DOS date and time of t in its own zone, as Go's
// timeToMsDosTime (wrapping as Go's uint16 conversions do).
fn zip_to_msdos(t: ZipTime) -> u16, u16 {
    let local = t.secs + t.offset;
    let days = div_euclid(local, 86400);
    let sod = local - days * 86400;
    let y, m, d = zip_civil_from_days(days);
    let fdate = (d + m * 32 + (y - 1980) * 512) as! u16;
    let ftime = (sod % 60 / 2 + (sod / 60 % 60) * 32 + (sod / 3600) * 2048) as! u16;
    return fdate, ftime;
}

// Go's timeZone(msdos.Sub(modified)): the offset rounded to 15 minutes,
// 0 outside -12h..+14h.
fn zip_infer_zone(msdos: ZipTime, modified: ZipTime) -> i64 {
    let ds = msdos.secs - modified.secs;
    // Far outside the range (Sub saturates there; the result is 0 either way).
    if ds > 200000 || ds < -200000 { return 0; }
    let d = ds * 1000000000 + (msdos.nsec - modified.nsec);
    let m: i64 = 15 * 60 * 1000000000;
    // Duration.Round: halves away from zero.
    var r = d % m;          // Euclidean: [0, m)
    var rounded: i64 = 0;
    if d < 0 {
        // Go's remainder for d < 0 is in (-m, 0]; work with its magnitude.
        let rr = if r == 0 { 0 } else { m - r };
        rounded = if rr + rr < m { d + rr } else { d - m + rr };
    } else {
        rounded = if r + r < m { d - r } else { d + m - r };
    }
    let lo: i64 = -12 * 3600 * 1000000000;
    let hi: i64 = 14 * 3600 * 1000000000;
    if rounded < lo || rounded > hi { return 0; }
    return rounded / 1000000000;
}

// --- UTF-8 and paths -------------------------------------------------------

// Go's utf8.DecodeRune: the rune and its size; (0xFFFD, 1) for anything
// that is not a valid encoding.
fn zip_decode_rune(s: const u8[:], i: i64) -> i64, i64 {
    let c0 = s[i] as i64;
    if c0 < 0x80 { return c0, 1; }
    let n = s.len - i;
    if c0 < 0xc2 || c0 > 0xf4 { return 0xfffd, 1; }
    if c0 < 0xe0 {
        if n < 2 { return 0xfffd, 1; }
        let c1 = s[i + 1] as i64;
        if c1 < 0x80 || c1 > 0xbf { return 0xfffd, 1; }
        return ((c0 & 0x1f) << 6) | (c1 & 0x3f), 2;
    }
    var lo: i64 = 0x80;
    var hi: i64 = 0xbf;
    if c0 == 0xe0 { lo = 0xa0; }
    if c0 == 0xed { hi = 0x9f; }
    if c0 == 0xf0 { lo = 0x90; }
    if c0 == 0xf4 { hi = 0x8f; }
    if n < 2 { return 0xfffd, 1; }
    let c1 = s[i + 1] as i64;
    if c1 < lo || c1 > hi { return 0xfffd, 1; }
    if n < 3 { return 0xfffd, 1; }
    let c2 = s[i + 2] as i64;
    if c2 < 0x80 || c2 > 0xbf { return 0xfffd, 1; }
    if c0 < 0xf0 { return ((c0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (c2 & 0x3f), 3; }
    if n < 4 { return 0xfffd, 1; }
    let c3 = s[i + 3] as i64;
    if c3 < 0x80 || c3 > 0xbf { return 0xfffd, 1; }
    return ((c0 & 0x07) << 18) | ((c1 & 0x3f) << 12) | ((c2 & 0x3f) << 6) | (c3 & 0x3f), 4;
}

// Go's detectUTF8: whether s is valid UTF-8 as far as the zip format
// cares, and whether it needs the UTF-8 flag (anything outside
// 0x20-0x7d, or a backslash, which CP-437 and Shift-JIS read differently).
fn zip_detect_utf8(s: const u8[:]) -> bool, bool {
    var require = false;
    var i: i64 = 0;
    while i < s.len {
        let r, size = zip_decode_rune(s, i);
        i += size;
        if r < 0x20 || r > 0x7d || r == 0x5c {
            if r == 0xfffd && size == 1 { return false, false; }
            require = true;
        }
    }
    return true, require;
}

// Go's path.Clean, appended to out.
fn zip_clean_path(p: const u8[:], out: u8[>..]&) {
    let start = out.len;
    if p.len == 0 {
        out.push('.');
        return;
    }
    let rooted = p[0] == '/';
    var r: i64 = 0;
    var dotdot: i64 = 0;     // where .. may no longer be removed (in out, relative to start)
    if rooted {
        out.push('/');
        r = 1;
        dotdot = 1;
    }
    let n = p.len;
    while r < n {
        if p[r] == '/' {
            r++;
        } else if p[r] == '.' && (r + 1 == n || p[r + 1] == '/') {
            r++;
        } else if p[r] == '.' && p[r + 1] == '.' && (r + 2 == n || p[r + 2] == '/') {
            r += 2;
            let w = out.len - start;
            if w > dotdot {
                var k = w - 1;
                while k > dotdot && out[start + k] != '/' { k--; }
                out.resize(start + k);
            } else if !rooted {
                if w > 0 { out.push('/'); }
                out.append("..");
                dotdot = out.len - start;
            }
        } else {
            let w = out.len - start;
            if (rooted && w != 1) || (!rooted && w != 0) { out.push('/'); }
            while r < n && p[r] != '/' {
                out.push(p[r]);
                r++;
            }
        }
    }
    if out.len == start { out.push('.'); }
}

// Go's filepath.IsLocal (as on Unix) of name, and no backslash: the test
// GODEBUG=zipinsecurepath=0 makes of every name.
fn zip_insecure_path(name: const u8[:]) -> bool {
    if position(name, '\\') >= 0 { return true; }
    if name.len == 0 || name[0] == '/' { return true; }
    var has_dots = false;
    var i: i64 = 0;
    while i <= name.len {
        var j = i;
        while j < name.len && name[j] != '/' { j++; }
        let part = name[i..j];
        if part == "." || part == ".." {
            has_dots = true;
            break;
        }
        i = j + 1;
    }
    if !has_dots { return false; }
    var c: u8[>..] = [];
    zip_clean_path(name, c);
    return c[..] == ".." || starts_with(c[..], "../");
}

// --- Reading ---------------------------------------------------------------

// A file of the central directory: Go's File, its strings as positions in
// the archive (zip_name, zip_comment, zip_extra give them).
struct ZipEntry {
    name_pos: i64, name_len: i64,
    extra_pos: i64, extra_len: i64,
    comment_pos: i64, comment_len: i64,
    non_utf8: bool,
    creator_version: u16, reader_version: u16, flags: u16, method: u16,
    mod_time: u16, mod_date: u16,
    modified: ZipTime,
    crc32: u32,
    compressed_size: u32, uncompressed_size: u32,
    compressed_size64: u64, uncompressed_size64: u64,
    external_attrs: u32,
    header_offset: i64,          // of the local header, base offset included
}

struct ZipReader {
    err: i64,                    // 0, the error opening it, or ERR_INSECURE_PATH (entries kept)
    need: i64,                   // with zip_open_tail and ERR_TRUNCATED: where the tail must start
    size: i64,                   // of the archive
    buf_start: i64,              // the archive offset of the buffer's first byte
    base_offset: i64,
    comment_pos: i64, comment_len: i64,
    records: u64, dir_size: u64, dir_offset: u64,
    insecure: bool,              // some name fails the zipinsecurepath test (whether checked or not)
    entries: ZipEntry[>..],
}

fn zip_entry_default() -> ZipEntry {
    ZipEntry {
        name_pos: 0, name_len: 0, extra_pos: 0, extra_len: 0, comment_pos: 0, comment_len: 0, non_utf8: false,
        creator_version: 0, reader_version: 0, flags: 0, method: 0, mod_time: 0, mod_date: 0, modified: ZipTime { .. },
        crc32: 0, compressed_size: 0, uncompressed_size: 0, compressed_size64: 0, uncompressed_size64: 0,
        external_attrs: 0, header_offset: 0,
    }
}

// The archive's bytes [off, off + n): the slice, and 0; ZIP_ERR_EOF when
// that is past the archive's end (Go's ReadAt fails), or ERR_TRUNCATED
// when it is before the tail the reader was given.
fn zip_at(r: ZipReader&, buf: const u8[:], off: i64, n: i64) -> const u8[:], i64 {
    if off < 0 || n < 0 || off > r.size || r.size - off < n { return buf[..0], ZIP_ERR_EOF; }
    if off < r.buf_start {
        if r.need < 0 || off < r.need { r.need = off; }
        return buf[..0], ERR_TRUNCATED;
    }
    let p = off - r.buf_start;
    return buf[p..p + n], 0;
}

fn zip_find_end_sig(b: const u8[:]) -> i64 {
    var i = b.len - 22;
    while i >= 0 {
        if b[i] == 'P' && b[i + 1] == 'K' && b[i + 2] == 5 && b[i + 3] == 6 {
            let n = b[i + 20] as i64 | (b[i + 21] as i64) << 8;
            if n + 22 + i > b.len { return -1; }
            return i;
        }
        i--;
    }
    return -1;
}

fn zip_u64_to_i64(v: u64) -> i64 { v as! i64 }

// Reads a directory header at archive offset off into e: its length and 0,
// or the error Go's readDirectoryHeader gives (ERR_FORMAT, ERR_TRUNCATED
// for a record cut short, ZIP_ERR_EOF for one entirely past the end).
fn zip_read_dir_header(r: ZipReader&, buf: const u8[:], off: i64, e: ZipEntry&) -> i64, i64 {
    let avail = r.size - off;
    if avail <= 0 { return 0, ZIP_ERR_EOF; }
    if avail < 46 {
        let s, err = zip_at(r, buf, off, avail);
        if err != 0 { return 0, err; }
        return 0, ERR_TRUNCATED;
    }
    let b, err = zip_at(r, buf, off, 46);
    if err != 0 { return 0, err; }
    if get_le32(b, 0) != ZIP_DIR_SIG { return 0, ERR_FORMAT; }
    e.creator_version = get_le16(b, 4) as! u16;
    e.reader_version = get_le16(b, 6) as! u16;
    e.flags = get_le16(b, 8) as! u16;
    e.method = get_le16(b, 10) as! u16;
    e.mod_time = get_le16(b, 12) as! u16;
    e.mod_date = get_le16(b, 14) as! u16;
    e.crc32 = get_le32(b, 16);
    e.compressed_size = get_le32(b, 20);
    e.uncompressed_size = get_le32(b, 24);
    e.compressed_size64 = e.compressed_size;
    e.uncompressed_size64 = e.uncompressed_size;
    let nlen = get_le16(b, 28) as i64;
    let xlen = get_le16(b, 30) as i64;
    let clen = get_le16(b, 32) as i64;
    e.external_attrs = get_le32(b, 38);
    e.header_offset = get_le32(b, 42) as i64;
    let total = nlen + xlen + clen;
    let rest = r.size - (off + 46);
    if total > 0 && rest <= 0 { return 0, ZIP_ERR_EOF; }
    if rest < total {
        let s2, err2 = zip_at(r, buf, off + 46, rest);
        if err2 != 0 { return 0, err2; }
        return 0, ERR_TRUNCATED;
    }
    let d, err3 = zip_at(r, buf, off + 46, total);
    if err3 != 0 { return 0, err3; }
    e.name_pos = off + 46;
    e.name_len = nlen;
    e.extra_pos = off + 46 + nlen;
    e.extra_len = xlen;
    e.comment_pos = off + 46 + nlen + xlen;
    e.comment_len = clen;
    let name = d[..nlen];
    let extra = d[nlen..nlen + xlen];
    let comment = d[nlen + xlen..];

    let v1, q1 = zip_detect_utf8(name);
    let v2, q2 = zip_detect_utf8(comment);
    if !v1 || !v2 {
        e.non_utf8 = true;
    } else if !q1 && !q2 {
        e.non_utf8 = false;
    } else {
        e.non_utf8 = (e.flags & ZIP_FLAG_UTF8) == 0;
    }

    var modified = ZipTime { .. };
    var x: i64 = 0;
    while extra.len - x >= 4 {
        let tag = get_le16(extra, x);
        let size = get_le16(extra, x + 2) as i64;
        x += 4;
        if extra.len - x < size { break; }
        let f = extra[x..x + size];
        x += size;
        if tag == 0x0001 {
            var p: i64 = 0;
            if e.uncompressed_size == 0xffffffff {
                if f.len - p < 8 { return 0, ERR_FORMAT; }
                e.uncompressed_size64 = get_le64(f, p);
                p += 8;
            }
            if e.compressed_size == 0xffffffff {
                if f.len - p < 8 { return 0, ERR_FORMAT; }
                e.compressed_size64 = get_le64(f, p);
                p += 8;
            }
            if e.header_offset == 0xffffffff {
                if f.len - p < 8 { return 0, ERR_FORMAT; }
                e.header_offset = get_le64(f, p) as! i64;
                p += 8;
            }
        } else if tag == 0x000a {
            if f.len < 4 { continue; }
            var p: i64 = 4;
            while f.len - p >= 4 {
                let atag = get_le16(f, p);
                let asize = get_le16(f, p + 2) as i64;
                p += 4;
                if f.len - p < asize { break; }
                let a = f[p..p + asize];
                p += asize;
                if atag != 1 || asize != 24 { continue; }
                let ts = get_le64(a, 0) as! i64;
                let secs = ts / 10000000;
                let nsecs = 100 * rem(ts, 10000000);
                modified = zip_time(-11644473600 + secs, nsecs);
            }
        } else if tag == 0x000d || tag == 0x5855 {
            if f.len < 8 { continue; }
            modified = zip_time(get_le32(f, 4) as i64);
        } else if tag == 0x5455 {
            if f.len < 5 || (f[0] & 1) == 0 { continue; }
            modified = zip_time(get_le32(f, 1) as i64);
        }
    }
    let msdos = zip_msdos_time(e.mod_date, e.mod_time);
    e.modified = msdos;
    if modified.set {
        e.modified = modified;
        if e.mod_time != 0 || e.mod_date != 0 {
            e.modified.offset = zip_infer_zone(msdos, modified);
        }
    }
    return 46 + total, 0;
}

// Opens an archive held whole in `archive`. With check_paths, a name
// that is not a local path is ERR_INSECURE_PATH (Go with
// GODEBUG=zipinsecurepath=0), the entries kept as Go keeps its Reader.
fn zip_open(archive: const u8[:], check_paths: bool = false) -> ZipReader {
    return zip_open_tail(archive, archive.len, check_paths);
}

// Opens an archive of `size` bytes of which `tail` is the end. When the
// directory starts before the tail, r.err is ERR_TRUNCATED and r.need the
// offset the tail must start at.
fn zip_open_tail(tail: const u8[:], size: i64, check_paths: bool = false) -> ZipReader {
    var r = ZipReader {
        err: 0, need: -1, size: size, buf_start: size - tail.len, base_offset: 0, comment_pos: 0, comment_len: 0,
        records: 0, dir_size: 0, dir_offset: 0, insecure: false, entries: [],
    };
    let e = zip_read_directory(r, tail, check_paths);
    if e != 0 && e != ERR_INSECURE_PATH { r.entries.clear(); }
    r.err = e;
    return r;
}

fn zip_read_directory(r: ZipReader&, buf: const u8[:], check_paths: bool) -> i64 {
    let size = r.size;
    if size < 0 || r.buf_start < 0 { return ERR_ARGUMENT; }
    // The end of central directory record, in the last 1 KiB, else 65 KiB.
    var end_off: i64 = -1;
    for i in 2 {
        let blen = min(if i == 0 { 1024 } else { 65 * 1024 }, size);
        let blk, err = zip_at(r, buf, size - blen, blen);
        if err != 0 { return err; }
        let p = zip_find_end_sig(blk);
        if p >= 0 {
            end_off = size - blen + p;
            break;
        }
        if i == 1 || blen == size { return ERR_FORMAT; }
    }
    let b, e0 = zip_at(r, buf, end_off, 22);
    if e0 != 0 { return e0; }
    r.records = get_le16(b, 10);
    r.dir_size = get_le32(b, 12);
    r.dir_offset = get_le32(b, 16);
    r.comment_len = get_le16(b, 20) as i64;
    r.comment_pos = end_off + 22;
    if r.records == 0xffff || r.dir_size == 0xffffffff || r.dir_offset == 0xffffffff {
        let loc_off = end_off - 20;
        if loc_off >= 0 {
            let l, e1 = zip_at(r, buf, loc_off, 20);
            if e1 != 0 { return e1; }
            if get_le32(l, 0) == ZIP_END64_LOC_SIG && get_le32(l, 4) == 0 && get_le32(l, 16) == 1 {
                let p = get_le64(l, 8) as! i64;
                if p >= 0 {
                    let d, e2 = zip_at(r, buf, p, 56);
                    if e2 != 0 { return e2; }
                    if get_le32(d, 0) != ZIP_END64_SIG { return ERR_FORMAT; }
                    end_off = p;
                    r.records = get_le64(d, 32);
                    r.dir_size = get_le64(d, 40);
                    r.dir_offset = get_le64(d, 48);
                }
            }
        }
    }
    let max_i64: u64 = 0x7fffffffffffffff;
    if r.dir_size > max_i64 || r.dir_offset > max_i64 { return ERR_FORMAT; }
    // Wrapping, as Go's int64 arithmetic.
    let base = ((end_off as! u64) - r.dir_size - r.dir_offset) as! i64;
    let o = ((base as! u64) + r.dir_offset) as! i64;
    if o < 0 || o >= size { return ERR_FORMAT; }
    var base_offset = base;
    if base_offset > 0 {
        // A directory that is where its offset says: the archive is not
        // prefixed after all.
        var probe = zip_entry_default();
        let n, perr = zip_read_dir_header(r, buf, r.dir_offset as! i64, probe);
        if perr == ERR_TRUNCATED && r.need >= 0 && r.dir_offset as! i64 >= 0 && (r.dir_offset as! i64) < r.buf_start {
            return ERR_TRUNCATED;
        }
        if perr == 0 { base_offset = 0; }
    }
    r.base_offset = base_offset;
    r.need = -1;
    var at = ((base_offset as! u64) + r.dir_offset) as! i64;
    var stop: i64 = 0;
    loop {
        var e = zip_entry_default();
        let n, err = zip_read_dir_header(r, buf, at, e);
        if err == ERR_TRUNCATED && r.need >= 0 { return ERR_TRUNCATED; }
        if err == ERR_FORMAT || err == ERR_TRUNCATED {
            stop = err;
            break;
        }
        if err != 0 { return err; }
        e.header_offset = ((e.header_offset as! u64) + (base_offset as! u64)) as! i64;
        r.entries.push(e);
        at += n;
    }
    if (r.entries.len & 0xffff) != ((r.records & 0xffff) as! i64) { return stop; }
    for e in r.entries {
        if e.name_len > 0 && zip_insecure_path(zip_name(r, buf, e)) { r.insecure = true; }
    }
    if check_paths && r.insecure { return ERR_INSECURE_PATH; }
    return 0;
}

// The bytes of an archive span, from the buffer the reader was opened on.
fn zip_span(r: const ZipReader&, buf: const u8[:], pos: i64, len: i64) -> const u8[:] {
    let p = pos - r.buf_start;
    return buf[p..p + len];
}

fn zip_name(r: const ZipReader&, buf: const u8[:], e: const ZipEntry&) -> const u8[:] { zip_span(r, buf, e.name_pos, e.name_len) }
fn zip_extra(r: const ZipReader&, buf: const u8[:], e: const ZipEntry&) -> const u8[:] { zip_span(r, buf, e.extra_pos, e.extra_len) }
fn zip_entry_comment(r: const ZipReader&, buf: const u8[:], e: const ZipEntry&) -> const u8[:] {
    zip_span(r, buf, e.comment_pos, e.comment_len)
}
fn zip_comment(r: const ZipReader&, buf: const u8[:]) -> const u8[:] { zip_span(r, buf, r.comment_pos, r.comment_len) }

fn zip_is_dir_name(name: const u8[:]) -> bool { name.len > 0 && name[name.len - 1] == '/' }

// Go's FileHeader.Mode().
fn zip_mode(r: const ZipReader&, buf: const u8[:], e: const ZipEntry&) -> u32 {
    return zip_mode_of(e.creator_version, e.external_attrs, zip_name(r, buf, e));
}

fn zip_mode_of(creator_version: u16, external_attrs: u32, name: const u8[:]) -> u32 {
    var mode: u32 = 0;
    let creator = creator_version >> 8;
    if creator == ZIP_CREATOR_UNIX || creator == ZIP_CREATOR_MACOSX {
        mode = zip_unix_to_mode(external_attrs >> 16);
    } else if creator == ZIP_CREATOR_NTFS || creator == ZIP_CREATOR_VFAT || creator == ZIP_CREATOR_FAT {
        if (external_attrs & 0x10) != 0 { mode = ZIP_MODE_DIR | 0x1ff; } else { mode = 0x1b6; }
        if (external_attrs & 0x01) != 0 { mode &= ~(0x92 as u32); }
    }
    if zip_is_dir_name(name) { mode |= ZIP_MODE_DIR; }
    return mode;
}

fn zip_unix_to_mode(m: u32) -> u32 {
    var mode = m & 0x1ff;
    let t = m & 0xf000;
    if t == 0x6000 { mode |= ZIP_MODE_DEVICE; }
    else if t == 0x2000 { mode |= ZIP_MODE_DEVICE | ZIP_MODE_CHAR_DEVICE; }
    else if t == 0x4000 { mode |= ZIP_MODE_DIR; }
    else if t == 0x1000 { mode |= ZIP_MODE_NAMED_PIPE; }
    else if t == 0xa000 { mode |= ZIP_MODE_SYMLINK; }
    else if t == 0xc000 { mode |= ZIP_MODE_SOCKET; }
    if (m & 0x400) != 0 { mode |= ZIP_MODE_SETGID; }
    if (m & 0x800) != 0 { mode |= ZIP_MODE_SETUID; }
    if (m & 0x200) != 0 { mode |= ZIP_MODE_STICKY; }
    return mode;
}

// Go's fileModeToUnixMode.
fn zip_mode_to_unix(mode: u32) -> u32 {
    var m: u32 = 0x8000;
    let t = mode & ZIP_MODE_TYPE;
    if t == ZIP_MODE_DIR { m = 0x4000; }
    else if t == ZIP_MODE_SYMLINK { m = 0xa000; }
    else if t == ZIP_MODE_NAMED_PIPE { m = 0x1000; }
    else if t == ZIP_MODE_SOCKET { m = 0xc000; }
    else if t == ZIP_MODE_DEVICE { m = 0x6000; }
    else if t == (ZIP_MODE_DEVICE | ZIP_MODE_CHAR_DEVICE) { m = 0x2000; }
    if (mode & ZIP_MODE_SETUID) != 0 { m |= 0x800; }
    if (mode & ZIP_MODE_SETGID) != 0 { m |= 0x400; }
    if (mode & ZIP_MODE_STICKY) != 0 { m |= 0x200; }
    return m | (mode & 0x1ff);
}

// --- A file's data ---------------------------------------------------------

let ZF_DATA: u8 = 0;
let ZF_DONE: u8 = 1;
let ZF_FAILED: u8 = 2;

// Reading one file: the compressed bytes fed in order, the data handed
// out into the caller's room, the checks made at the end.
struct ZipFile {
    state: u8,
    err: i64,
    is_dir: bool,
    method: u16,
    has_descriptor: bool,
    crc_want: u32,
    usize: u64,
    csize: u64,
    data_pos: i64,               // the archive offset of the compressed data
    data_len: i64,               // the compressed bytes there are (csize, or less where the archive ends)
    header_ok: bool,             // the local header was read (data_pos is known)
    used: i64,                   // compressed bytes taken
    nread: u64,
    crc: u32,
    desc: u8[..16],              // the bytes after the data (where a data descriptor is)
    inf: Inflate,
}

// Starts reading a file whose local header is `local` (at least its 30
// fixed bytes, at the entry's header offset); r and e as read. The
// returned reader's err is 0, or why it cannot be opened (Go's File.Open
// error).
fn zip_file_start(e: const ZipEntry&, local: const u8[:], name: const u8[:]) -> ZipFile {
    var f = ZipFile {
        state: ZF_DATA, err: 0, is_dir: zip_is_dir_name(name), method: e.method,
        has_descriptor: (e.flags & ZIP_FLAG_DESCRIPTOR) != 0, crc_want: e.crc32,
        usize: e.uncompressed_size64, csize: e.compressed_size64, data_pos: 0, data_len: 0, header_ok: false, used: 0,
        nread: 0, crc: 0, desc: [], inf: inflate_reader(),
    };
    if local.len < 30 {
        f.err = ZIP_ERR_EOF;
        return f;
    }
    if get_le32(local, 0) != ZIP_FILE_SIG {
        f.err = ERR_FORMAT;
        return f;
    }
    f.data_pos = e.header_offset + 30 + (get_le16(local, 26) as i64) + (get_le16(local, 28) as i64);
    f.header_ok = true;
    if f.is_dir {
        if f.usize != 0 { f.err = ERR_FORMAT; f.state = ZF_FAILED; } else { f.state = ZF_DONE; }
        return f;
    }
    if f.method != ZIP_STORE && f.method != ZIP_DEFLATE {
        f.err = ERR_UNSUPPORTED;
        return f;
    }
    f.data_len = min(f.csize, 0x7fffffffffffffff) as! i64;
    return f;
}

// Opens a file of an archive held in memory (r opened on archive).
fn zip_file_open(r: const ZipReader&, archive: const u8[:], e: const ZipEntry&) -> ZipFile {
    var local = archive[..0];
    var why: i64 = 0;
    // Go reads the 30 bytes at the header offset.
    if e.header_offset < 0 {
        why = ZIP_ERR_NEG_OFFSET;
    } else if e.header_offset > r.size - 30 {
        why = ZIP_ERR_EOF;
    } else if e.header_offset < r.buf_start {
        why = ERR_TRUNCATED;
    } else {
        let ho = e.header_offset - r.buf_start;
        local = archive[ho..ho + 30];
    }
    var f = zip_file_start(e, local, zip_name(r, archive, e));
    if why != 0 {
        f.err = why;
        f.state = ZF_FAILED;
        return f;
    }
    if f.err != 0 || f.is_dir { return f; }
    // The data where the archive has it; and the descriptor after it.
    let dp = f.data_pos;
    var avail: i64 = 0;
    if dp >= 0 && dp < r.size { avail = r.size - dp; }
    if f.csize < (avail as u64) { avail = f.csize as! i64; }
    f.data_len = avail;
    if f.has_descriptor && dp >= 0 && f.csize <= 0x7fffffffffffffff {
        let dd = dp + (f.csize as! i64);
        if dd >= 0 && dd < r.size {
            let n = min(16, r.size - dd);
            f.desc.append(archive[dd - r.buf_start..dd - r.buf_start + n]);
        }
    }
    return f;
}

// For a file read with zip_file_read: the bytes after its compressed data
// (up to 16; fewer where the archive ends), read as its data descriptor.
fn zip_file_set_descriptor(f: ZipFile&, bytes: const u8[:]) {
    f.desc.clear();
    f.desc.append(bytes[..min(16, bytes.len)]);
}

// For a file read with zip_file_read whose archive ends inside its data:
// the compressed bytes there are, from its start.
fn zip_file_set_available(f: ZipFile&, n: i64) { f.data_len = min(n, f.data_len); }

fn zip_file_fail(f: ZipFile&, e: i64) -> i64 {
    f.err = e;
    f.state = ZF_FAILED;
    return e;
}

// The checks at the data's end (Go's checksumReader at io.EOF).
fn zip_file_check(f: ZipFile&) -> i64 {
    if f.nread != f.usize { return zip_file_fail(f, ERR_TRUNCATED); }
    if f.has_descriptor {
        let d = f.desc[..];
        if d.len < 4 { return zip_file_fail(f, ERR_TRUNCATED); }
        var crc_at: i64 = 0;
        if get_le32(d, 0) == ZIP_DESC_SIG {
            if d.len < 16 { return zip_file_fail(f, ERR_TRUNCATED); }
            crc_at = 4;
        } else if d.len < 12 {
            return zip_file_fail(f, ERR_TRUNCATED);
        }
        if get_le32(d, crc_at) != f.crc_want { return zip_file_fail(f, ERR_CHECKSUM); }
        if f.crc != f.crc_want { return zip_file_fail(f, ERR_CHECKSUM); }
    } else if f.crc_want != 0 && f.crc != f.crc_want {
        return zip_file_fail(f, ERR_CHECKSUM);
    }
    f.state = ZF_DONE;
    return STREAM_END;
}

// Decodes the file's compressed bytes, fed in order from its start (what
// passes data_len is not taken), into out: the bytes taken, the bytes
// written, and 0, STREAM_END (the data ended and passed every check), or
// an error. The output before an error is handed out first.
fn zip_file_read(f: ZipFile&, input: const u8[:], out: u8[:]) -> i64, i64, i64 {
    if f.state == ZF_DONE { return 0, 0, STREAM_END; }
    if f.state == ZF_FAILED || f.err != 0 { return 0, 0, f.err; }
    let room = f.data_len - f.used;
    let inp = input[..min(input.len, room)];
    var used: i64 = 0;
    var made: i64 = 0;
    var st: i64 = 0;
    let at_end = f.used + inp.len == f.data_len;
    if f.method == ZIP_STORE {
        let n = min(inp.len, out.len);
        out[..n].move_from(inp[..n]);
        used = n;
        made = n;
        if at_end && n == inp.len { st = STREAM_END; }
    } else {
        used, made, st = inflate_read(f.inf, inp, out);
        if st == 0 && at_end && used == inp.len && made < out.len {
            // No more input will come: the stream was cut short.
            st = ERR_TRUNCATED;
        }
    }
    f.used += used;
    f.crc = crc32_update(f.crc, out[..made]);
    f.nread += made as u64;
    if f.nread > f.usize {
        // Go returns 0 bytes and ErrFormat for the read that passes the size.
        zip_file_fail(f, ERR_FORMAT);
        return used, 0, ERR_FORMAT;
    }
    if st < 0 {
        zip_file_fail(f, st);
        return used, made, st;
    }
    if st == STREAM_END { return used, made, zip_file_check(f); }
    return used, made, 0;
}

// zip_file_read on an archive held in memory.
fn zip_file_read_mem(f: ZipFile&, archive: const u8[:], r: const ZipReader&, out: u8[:]) -> i64, i64 {
    if f.state == ZF_DONE { return 0, STREAM_END; }
    if f.state == ZF_FAILED || f.err != 0 { return 0, f.err; }
    let p = f.data_pos + f.used - r.buf_start;
    let n = f.data_len - f.used;
    if n > 0 && (p < 0 || p + n > archive.len) { return 0, ERR_TRUNCATED; }
    let input = if n > 0 { archive[p..p + n] } else { archive[..0] };
    let used, made, st = zip_file_read(f, input, out);
    return made, st;
}

// Appends a file's data to out: 0, or the error (ERR_LIMIT past `limit`
// bytes, < 0 for none).
fn zip_extract(r: const ZipReader&, archive: const u8[:], e: const ZipEntry&, out: u8[>..]&, limit: i64 = -1) -> i64 {
    var f = zip_file_open(r, archive, e);
    if f.err != 0 { return f.err; }
    loop {
        let start = out.len;
        out.resize(start + 65536, 0);
        let made, st = zip_file_read_mem(f, archive, r, out[start..]);
        out.resize(start + made);
        if limit >= 0 && out.len > limit { return ERR_LIMIT; }
        if st == STREAM_END { return 0; }
        if st < 0 { return st; }
        if made == 0 { return ERR_TRUNCATED; }
    }
    return 0;
}

// The archive offset of a file's data, or an error (Go's DataOffset).
fn zip_data_offset(r: const ZipReader&, archive: const u8[:], e: const ZipEntry&) -> i64, i64 {
    let f = zip_file_open(r, archive, e);
    if !f.header_ok { return 0, f.err; }
    return f.data_pos, 0;
}

// --- Writing ---------------------------------------------------------------

// What a file is written with: Go's FileHeader. Only `name` is needed;
// method is Store unless set (as in Go).
struct ZipHeader {
    name: u8[],
    comment: u8[] = "",
    extra: u8[] = "",
    non_utf8: bool = false,
    creator_version: u16 = 0,
    reader_version: u16 = 0,
    flags: u16 = 0,
    method: u16 = 0,
    modified: ZipTime = ZipTime { .. },
    mod_time: u16 = 0,
    mod_date: u16 = 0,
    crc32: u32 = 0,
    compressed_size64: u64 = 0,
    uncompressed_size64: u64 = 0,
    external_attrs: u32 = 0,
}

// Go's FileHeader.SetMode.
fn zip_header_set_mode(h: ZipHeader&, mode: u32) {
    h.creator_version = (h.creator_version & 0xff) | (ZIP_CREATOR_UNIX << 8);
    h.external_attrs = zip_mode_to_unix(mode) << 16;
    if (mode & ZIP_MODE_DIR) != 0 { h.external_attrs |= 0x10; }
    if (mode & 0x80) == 0 { h.external_attrs |= 0x01; }
}

// Go's FileHeader.SetModTime: the time in UTC and its MS-DOS fields.
fn zip_header_set_mod_time(h: ZipHeader&, t: ZipTime) {
    h.modified = t;
    h.modified.offset = 0;
    h.mod_date, h.mod_time = zip_to_msdos(h.modified);
}

let ZW_NONE: u8 = 0;         // no file open
let ZW_FILE: u8 = 1;         // a file being written
let ZW_DIR: u8 = 2;          // a directory (nothing may be written)
let ZW_RAW: u8 = 3;          // a file written raw

struct ZipWriter {
    count: i64,                  // bytes written (and the offset SetOffset gave)
    wrote: bool,
    closed: bool,
    state: u8,
    // The file being written.
    method: u16,
    flags: u16,
    reader_version: u16,
    creator_version: u16,
    crc: u32,
    crc_given: u32,
    raw_count: i64,              // bytes written to it
    comp_start: i64,             // count where its compressed data starts
    csize: u64, usize: u64,      // sizes given to zip_create_raw
    offset: i64,
    rec: i64,                    // where its directory record starts in cd
    extra_end: i64,              // where its comment starts in cd
    records: u64,
    used_zip64: bool,
    comment: u8[..65535],
    def: Deflate,
    // The central directory as it is built: each file's 46-byte record,
    // filled when the file ends, its name, extra and comment.
    cd: u8[>..],
}

fn zip_writer() -> ZipWriter {
    ZipWriter {
        count: 0, wrote: false, closed: false, state: ZW_NONE, method: 0, flags: 0, reader_version: 0,
        creator_version: 0, crc: 0, crc_given: 0, raw_count: 0, comp_start: 0, csize: 0, usize: 0, offset: 0,
        rec: 0, extra_end: 0, records: 0, used_zip64: false, comment: [], def: deflate_writer(5), cd: [],
    }
}

// The offset of the archive's start within what it is written into (Go's
// SetOffset): only before anything is written.
fn zip_set_offset(w: ZipWriter&, n: i64) -> i64 {
    if w.wrote || w.count != 0 { return ERR_ARGUMENT; }
    w.count = n;
    return 0;
}

fn zip_set_comment(w: ZipWriter&, comment: const u8[:]) -> i64 {
    if comment.len > 65535 { return ERR_TOO_LARGE; }
    w.comment.clear();
    w.comment.append(comment);
    return 0;
}

fn zw_emit(w: ZipWriter&, out: u8[>..]&, b: const u8[:]) {
    out.append(b);
    w.count += b.len;
    if b.len > 0 { w.wrote = true; }
}

fn zw_put16(b: u8[>..]&, v: u64) { put_le16(b, v); }
fn zw_put32(b: u8[>..]&, v: u64) { put_le32(b, v); }

fn zw_set16(b: u8[:], at: i64, v: u64) {
    b[at] = (v & 0xff) as! u8;
    b[at + 1] = ((v >> 8) & 0xff) as! u8;
}

fn zw_set32(b: u8[:], at: i64, v: u64) {
    for k in 4 { b[at + k] = ((v >> ((k * 8) as! u64)) & 0xff) as! u8; }
}

// Ends the file being written: its data descriptor, its directory record.
fn zw_end_file(w: ZipWriter&, out: u8[>..]&) -> i64 {
    let st = w.state;
    if st == ZW_NONE { return 0; }
    w.state = ZW_NONE;
    var csize: u64 = 0;
    var usize: u64 = 0;
    var crc: u32 = 0;
    if st == ZW_FILE {
        if w.method == ZIP_DEFLATE {
            var buf: u8[>..] = [];
            let e = deflate_close(w.def, buf);
            if e != 0 { return e; }
            zw_emit(w, out, buf);
        }
        csize = (w.count - w.comp_start) as u64;
        usize = w.raw_count as u64;
        crc = w.crc;
        if csize > ZIP_U32MAX || usize > ZIP_U32MAX { w.reader_version = ZIP_VERSION45; }
    } else if st == ZW_RAW {
        csize = w.csize;
        usize = w.usize;
        crc = w.crc_given;
    } else {
        // A directory: no data; a raw one keeps the sizes it was given (Go).
        csize = w.csize;
        usize = w.usize;
        crc = w.crc_given;
    }
    // The data descriptor (Go writes one with its signature).
    if (st == ZW_FILE || st == ZW_RAW) && (w.flags & ZIP_FLAG_DESCRIPTOR) != 0 {
        var d: u8[>..] = [];
        zw_put32(d, ZIP_DESC_SIG);
        zw_put32(d, crc);
        if csize > ZIP_U32MAX || usize > ZIP_U32MAX {
            put_le64(d, csize);
            put_le64(d, usize);
        } else if st == ZW_RAW {
            zw_put32(d, min(csize, ZIP_U32MAX));
            zw_put32(d, min(usize, ZIP_U32MAX));
        } else {
            zw_put32(d, csize);
            zw_put32(d, usize);
        }
        zw_emit(w, out, d);
    }
    // The directory record (Go's Close), ZIP64 where a size or the offset needs it.
    var rv = w.reader_version;
    let off = w.offset as u64;
    if csize >= ZIP_U32MAX || usize >= ZIP_U32MAX || off >= ZIP_U32MAX {
        w.used_zip64 = true;
        rv = max(rv, ZIP_VERSION45);
        var x: u8[>..] = [];
        zw_put16(x, 0x0001);
        zw_put16(x, 0);
        if usize >= ZIP_U32MAX { put_le64(x, usize); }
        if csize >= ZIP_U32MAX { put_le64(x, csize); }
        if off >= ZIP_U32MAX { put_le64(x, off); }
        zw_set16(x, 2, (x.len - 4) as u64);
        // Into the record between the extra field and the comment.
        let at = w.extra_end;
        w.cd.append(x);
        reverse(w.cd[at..]);
        reverse(w.cd[at..at + x.len]);
        reverse(w.cd[at + x.len..]);
        let rec = w.rec;
        let old = get_le16(w.cd, rec + 30) as u64;
        if old + (x.len as u64) > 0xffff { return ERR_TOO_LARGE; }
        zw_set16(w.cd, rec + 30, old + x.len as u64);
    }
    let rec = w.rec;
    zw_set32(w.cd, rec, ZIP_DIR_SIG);
    zw_set16(w.cd, rec + 4, w.creator_version);
    zw_set16(w.cd, rec + 6, rv);
    zw_set16(w.cd, rec + 8, w.flags);
    zw_set16(w.cd, rec + 10, w.method);
    zw_set32(w.cd, rec + 16, crc);
    zw_set32(w.cd, rec + 20, min(csize, ZIP_U32MAX));
    zw_set32(w.cd, rec + 24, min(usize, ZIP_U32MAX));
    zw_set32(w.cd, rec + 42, min(off, ZIP_U32MAX));
    return 0;
}

// Starts a file's directory record in cd (filled when the file ends), and
// writes its local header.
fn zw_begin(w: ZipWriter&, h: const ZipHeader&, flags: u16, method: u16, creator: u16, reader: u16,
            mtime: u16, mdate: u16, ext_time: bool, mt: u32, raw: bool, out: u8[>..]&) -> i64 {
    let xlen = h.extra.len + (if ext_time { 9 } else { 0 });
    if h.name.len > 65535 { return ERR_TOO_LARGE; }
    if xlen > 65535 { return ERR_TOO_LARGE; }
    w.offset = w.count;
    w.flags = flags;
    w.method = method;
    w.creator_version = creator;
    w.reader_version = reader;
    w.records++;
    w.rec = w.cd.len;
    w.cd.resize(w.rec + 46, 0);
    let rec = w.rec;
    zw_set16(w.cd, rec + 12, mtime);
    zw_set16(w.cd, rec + 14, mdate);
    zw_set16(w.cd, rec + 28, h.name.len as u64);
    zw_set16(w.cd, rec + 30, xlen as u64);
    zw_set16(w.cd, rec + 32, h.comment.len as u64);
    zw_set32(w.cd, rec + 38, h.external_attrs);
    w.cd.append(h.name);
    w.cd.append(h.extra);
    var et: u8[>..] = [];
    if ext_time {
        zw_put16(et, 0x5455);
        zw_put16(et, 5);
        et.push(1);
        zw_put32(et, mt);
        w.cd.append(et);
    }
    w.extra_end = w.cd.len;
    w.cd.append(h.comment);
    // The local header.
    var b: u8[>..] = [];
    var rv = reader;
    let no_desc = raw && (flags & ZIP_FLAG_DESCRIPTOR) == 0;
    let big = no_desc && (h.compressed_size64 > ZIP_U32MAX || h.uncompressed_size64 > ZIP_U32MAX);
    if big { rv = max(rv, ZIP_VERSION45); }
    zw_put32(b, ZIP_FILE_SIG);
    zw_put16(b, rv);
    zw_put16(b, flags);
    zw_put16(b, method);
    zw_put16(b, mtime);
    zw_put16(b, mdate);
    if no_desc {
        zw_put32(b, h.crc32);
        if big {
            zw_put32(b, ZIP_U32MAX);
            zw_put32(b, ZIP_U32MAX);
        } else {
            zw_put32(b, h.compressed_size64 & 0xffffffff);
            zw_put32(b, h.uncompressed_size64 & 0xffffffff);
        }
    } else {
        zw_put32(b, 0);
        zw_put32(b, 0);
        zw_put32(b, 0);
    }
    zw_put16(b, h.name.len as u64);
    zw_put16(b, (xlen + (if big { 20 } else { 0 })) as u64);
    b.append(h.name);
    b.append(h.extra);
    b.append(et);
    if big {
        zw_put16(b, 0x0001);
        zw_put16(b, 16);
        put_le64(b, h.uncompressed_size64);
        put_le64(b, h.compressed_size64);
    }
    zw_emit(w, out, b);
    return 0;
}

// Go's CreateHeader: a file (or, for a name ending in '/', a directory)
// whose data follows with zip_write. Store or Deflate (level 5, as Go's
// zip writer), a data descriptor after the data, the UTF-8 flag by Go's
// detectUTF8, an extended timestamp when h.modified is set.
fn zip_create_header(w: ZipWriter&, h, out: u8[>..]&) -> i64 {
    if w.closed { return ERR_ARGUMENT; }
    let e = zw_end_file(w, out);
    if e != 0 { return e; }
    var flags = h.flags;
    let v1, q1 = zip_detect_utf8(h.name);
    let v2, q2 = zip_detect_utf8(h.comment);
    if h.non_utf8 {
        flags &= ~ZIP_FLAG_UTF8;
    } else if (q1 || q2) && v1 && v2 {
        flags |= ZIP_FLAG_UTF8;
    }
    let creator = (h.creator_version & 0xff00) | ZIP_VERSION20;
    var mtime = h.mod_time;
    var mdate = h.mod_date;
    var mt: u32 = 0;
    if h.modified.set {
        mdate, mtime = zip_to_msdos(h.modified);
        mt = h.modified.secs as! u32;
    }
    var method = h.method;
    let dir = zip_is_dir_name(h.name);
    if dir {
        method = ZIP_STORE;
        flags &= ~ZIP_FLAG_DESCRIPTOR;
    } else {
        flags |= ZIP_FLAG_DESCRIPTOR;
        if method != ZIP_STORE && method != ZIP_DEFLATE { return ERR_UNSUPPORTED; }
    }
    let e2 = zw_begin(w, h, flags, method, creator, ZIP_VERSION20, mtime, mdate, h.modified.set, mt, false, out);
    if e2 != 0 { return e2; }
    w.crc_given = h.crc32;
    w.csize = 0;
    w.usize = 0;
    if dir {
        w.state = ZW_DIR;
        return 0;
    }
    w.state = ZW_FILE;
    w.crc = 0;
    w.raw_count = 0;
    w.comp_start = w.count;
    if method == ZIP_DEFLATE { deflate_reset(w.def); }
    return 0;
}

// Go's Create: a file of that name, Deflate, no times.
fn zip_create(w: ZipWriter&, name: const u8[:], out: u8[>..]&) -> i64 {
    return zip_create_header(w, ZipHeader { name: name, method: ZIP_DEFLATE, .. }, out);
}

// Go's CreateRaw: a file whose data is written as it is (already
// compressed, by the header's method), with the header's CRC-32 and sizes.
fn zip_create_raw(w: ZipWriter&, h, out: u8[>..]&) -> i64 {
    if w.closed { return ERR_ARGUMENT; }
    let e = zw_end_file(w, out);
    if e != 0 { return e; }
    let e2 = zw_begin(w, h, h.flags, h.method, h.creator_version, h.reader_version, h.mod_time, h.mod_date,
                      false, 0, true, out);
    if e2 != 0 { return e2; }
    w.crc_given = h.crc32;
    w.csize = h.compressed_size64;
    w.usize = h.uncompressed_size64;
    // A raw directory takes no data and gets no data descriptor; its
    // record has the header's sizes (Go).
    w.state = if zip_is_dir_name(h.name) { ZW_DIR } else { ZW_RAW };
    return 0;
}

// Writes data to the file being written.
fn zip_write(w: ZipWriter&, data: const u8[:], out: u8[>..]&) -> i64 {
    if w.closed || w.state == ZW_NONE { return ERR_ARGUMENT; }
    if w.state == ZW_DIR {
        if data.len == 0 { return 0; }
        return ERR_ARGUMENT;        // Go: "zip: write to directory"
    }
    if w.state == ZW_RAW {
        zw_emit(w, out, data);
        return 0;
    }
    w.crc = crc32_update(w.crc, data);
    w.raw_count += data.len;
    if w.method == ZIP_STORE {
        zw_emit(w, out, data);
        return 0;
    }
    let before = out.len;
    let e = deflate_write(w.def, data, out);
    w.count += out.len - before;
    if out.len > before { w.wrote = true; }
    return e;
}

// Go's Copy: a file of another archive, its compressed data as it is.
fn zip_copy(w: ZipWriter&, r: const ZipReader&, archive: const u8[:], e: const ZipEntry&, out: u8[>..]&) -> i64 {
    let f = zip_file_open(r, archive, e);
    if !f.header_ok { return f.err; }
    let h = ZipHeader {
        name: zip_name(r, archive, e), comment: zip_entry_comment(r, archive, e), extra: zip_extra(r, archive, e),
        non_utf8: e.non_utf8, creator_version: e.creator_version, reader_version: e.reader_version, flags: e.flags,
        method: e.method, modified: e.modified, mod_time: e.mod_time, mod_date: e.mod_date, crc32: e.crc32,
        compressed_size64: e.compressed_size64, uncompressed_size64: e.uncompressed_size64,
        external_attrs: e.external_attrs,
    };
    let e2 = zip_create_raw(w, h, out);
    if e2 != 0 { return e2; }
    if zip_is_dir_name(h.name) { return 0; }
    // OpenRaw: the compressed bytes the archive has.
    let dp = f.data_pos;
    var n: i64 = 0;
    if dp >= 0 && dp < r.size { n = min(r.size - dp, min(e.compressed_size64, 0x7fffffffffffffff) as! i64); }
    let p = dp - r.buf_start;
    return zip_write(w, archive[p..p + n], out);
}

// Ends the archive: the last file, the central directory, ZIP64's end
// records where Go writes them, the end record and the comment.
fn zip_close(w: ZipWriter&, out: u8[>..]&) -> i64 {
    let e = zw_end_file(w, out);
    if e != 0 { return e; }
    if w.closed { return ERR_ARGUMENT; }     // Go: "zip: writer closed twice"
    w.closed = true;
    let start = w.count;
    zw_emit(w, out, w.cd);
    let end = w.count;
    let records = w.records;
    let size = (end - start) as u64;
    let offset = start as u64;
    var b: u8[>..] = [];
    if w.used_zip64 || records >= ZIP_U16MAX || size >= ZIP_U32MAX || offset >= ZIP_U32MAX {
        zw_put32(b, ZIP_END64_SIG);
        put_le64(b, 44);
        zw_put16(b, ZIP_VERSION45);
        zw_put16(b, ZIP_VERSION45);
        zw_put32(b, 0);
        zw_put32(b, 0);
        put_le64(b, records);
        put_le64(b, records);
        put_le64(b, size);
        put_le64(b, offset);
        zw_put32(b, ZIP_END64_LOC_SIG);
        zw_put32(b, 0);
        put_le64(b, end as u64);
        zw_put32(b, 1);
    }
    zw_put32(b, ZIP_END_SIG);
    zw_put16(b, 0);
    zw_put16(b, 0);
    zw_put16(b, min(ZIP_U16MAX, records));
    zw_put16(b, min(ZIP_U16MAX, records));
    zw_put32(b, min(ZIP_U32MAX, size));
    zw_put32(b, min(ZIP_U32MAX, offset));
    zw_put16(b, w.comment.len as u64);
    b.append(w.comment);
    zw_emit(w, out, b);
    return 0;
}
