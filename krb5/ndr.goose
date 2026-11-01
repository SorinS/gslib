// krb5.ndr: reading NDR (DCE 1.1 RPC, chapter 14) as MS-RPCE's type
// serialization version 1 (§2.2.6) lays it out for the PAC: a common
// header (version 1, little-endian), a private header with the object's
// length, then the object, little-endian, each primitive aligned to its
// size from the start of the object.
//
// The PAC's types are read by hand in krb5.pac: their fixed parts in
// order, embedded pointers as referent ids, then the pointed-to data
// ("deferred") in the order the pointers came. This module has the
// cursor, the primitives and the shapes that recur: conformant arrays,
// conformant varying strings, SIDs.

namespace krb5;

import std;

struct Ndr { pos: i64, end: i64, base: i64, bad: bool }

fn ndr_align(n: Ndr&, a: i64) {
    let off = (n.pos - n.base) % a;
    if off != 0 { n.pos += a - off; }
    if n.pos > n.end { n.bad = true; n.pos = n.end; }
}

fn ndr_u8(b: const u8[:], n: Ndr&) -> u32 {
    if n.pos + 1 > n.end { n.bad = true; return 0; }
    let v: u32 = b[n.pos];
    n.pos++;
    return v;
}

fn ndr_u16(b: const u8[:], n: Ndr&) -> u32 {
    ndr_align(n, 2);
    if n.pos + 2 > n.end { n.bad = true; return 0; }
    let lo: u32 = b[n.pos];
    let hi: u32 = b[n.pos + 1];
    n.pos += 2;
    return lo | hi << 8;
}

fn ndr_u32(b: const u8[:], n: Ndr&) -> u32 {
    ndr_align(n, 4);
    if n.pos + 4 > n.end { n.bad = true; return 0; }
    var v: u32 = 0;
    for i in 4 {
        let x: u32 = b[n.pos + 3 - i];
        v = v << 8 | x;
    }
    n.pos += 4;
    return v;
}

fn ndr_u64(b: const u8[:], n: Ndr&) -> u64 {
    ndr_align(n, 8);
    if n.pos + 8 > n.end { n.bad = true; return 0; }
    var v: u64 = 0;
    for i in 8 {
        let x: u64 = b[n.pos + 7 - i];
        v = v << 8 | x;
    }
    n.pos += 8;
    return v;
}

// A FILETIME: two ULONGs, low first (aligned 4, not 8).
fn ndr_filetime(b: const u8[:], n: Ndr&) -> u64 {
    let lo: u64 = ndr_u32(b, n);
    let hi: u64 = ndr_u32(b, n);
    return hi << 32 | lo;
}

fn ndr_bytes(b: const u8[:], n: Ndr&, len: i64) -> u8[>..] {
    var out: u8[>..] = [];
    if len < 0 || n.pos + len > n.end { n.bad = true; return out; }
    out.append(b[n.pos..n.pos + len]);
    n.pos += len;
    return out;
}

// The serialization headers (MS-RPCE §2.2.6.1, §2.2.6.2): a cursor on the
// object that follows.
fn ndr_open(b: const u8[:]) -> Ndr {
    var n = Ndr { pos: 0, end: b.len, base: 0, bad: false };
    if b.len < 16 || b[0] != 1 || b[1] != 0x10 || b[2] != 8 || b[3] != 0 { n.bad = true; return n; }
    n.pos = 8;
    let len = ndr_u32(b, n) as i64;
    let filler = ndr_u32(b, n);
    if 16 + len > b.len { n.bad = true; return n; }
    n.base = 16;
    n.end = 16 + len;
    return n;
}

// A UTF-16LE string as UTF-8 (unpaired surrogates become U+FFFD).
fn utf16_to_utf8(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < b.len {
        let lo: u32 = b[i];
        let hi: u32 = b[i + 1];
        var cp = lo | hi << 8;
        i += 2;
        if cp >= 0xd800 && cp < 0xdc00 && i + 1 < b.len {
            let lo2: u32 = b[i];
            let hi2: u32 = b[i + 1];
            let c2 = lo2 | hi2 << 8;
            if c2 >= 0xdc00 && c2 < 0xe000 {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (c2 - 0xdc00);
                i += 2;
            } else {
                cp = 0xfffd;
            }
        } else if cp >= 0xd800 && cp < 0xe000 {
            cp = 0xfffd;
        }
        if cp < 0x80 { out.push(cp as! u8); }
        else if cp < 0x800 { out.push((0xc0 | cp >> 6) as! u8); out.push((0x80 | cp & 0x3f) as! u8); }
        else if cp < 0x10000 {
            out.push((0xe0 | cp >> 12) as! u8);
            out.push((0x80 | (cp >> 6) & 0x3f) as! u8);
            out.push((0x80 | cp & 0x3f) as! u8);
        } else {
            out.push((0xf0 | cp >> 18) as! u8);
            out.push((0x80 | (cp >> 12) & 0x3f) as! u8);
            out.push((0x80 | (cp >> 6) & 0x3f) as! u8);
            out.push((0x80 | cp & 0x3f) as! u8);
        }
    }
    return out;
}

// An RPC_UNICODE_STRING's fixed part: its length in bytes and whether its
// buffer pointer is set.
fn ndr_ustring_head(b: const u8[:], n: Ndr&) -> i64, bool {
    let len = ndr_u16(b, n) as i64;
    let max = ndr_u16(b, n) as i64;
    let ptr = ndr_u32(b, n);
    if len > max || len % 2 != 0 { n.bad = true; }
    return len, ptr != 0;
}

// The deferred buffer of an RPC_UNICODE_STRING (a conformant varying
// array of WCHAR): as UTF-8. `len` is the fixed part's byte length.
fn ndr_ustring_body(b: const u8[:], n: Ndr&, len: i64) -> u8[>..] {
    let max = ndr_u32(b, n) as i64;
    let off = ndr_u32(b, n) as i64;
    let count = ndr_u32(b, n) as i64;
    if off != 0 || count > max || count * 2 != len { n.bad = true; }
    let raw = ndr_bytes(b, n, count * 2);
    return utf16_to_utf8(raw);
}

// A NUL-terminated conformant varying WCHAR string (LPWSTR, [string]),
// as UTF-8 without the NUL.
fn ndr_wstring(b: const u8[:], n: Ndr&) -> u8[>..] {
    let max = ndr_u32(b, n) as i64;
    let off = ndr_u32(b, n) as i64;
    let count = ndr_u32(b, n) as i64;
    if off != 0 || count > max || count < 1 { n.bad = true; }
    let raw = ndr_bytes(b, n, count * 2);
    var keep = raw.len;
    if keep >= 2 && raw[keep - 2] == 0 && raw[keep - 1] == 0 { keep -= 2; }
    return utf16_to_utf8(raw[..keep]);
}

// A SID in its text form (MS-DTYP §2.4.2.1): S-revision-authority-sub...,
// the authority in hex when it does not fit in 32 bits.
fn sid_text(revision: u32, auth: const u8[:], subs: const u32[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append("S-");
    format_int(out, revision, 10, 0, ' ');
    out.push('-');
    var a: u64 = 0;
    for x in auth { a = a << 8 | x; }
    if a >> 32 != 0 {
        out.append("0x");
        let hex = "0123456789ABCDEF";
        for x in auth { out.push(hex[x >> 4]); out.push(hex[x & 15]); }
    } else {
        format_int(out, a as! i64, 10, 0, ' ');
    }
    for s in subs {
        out.push('-');
        format_int(out, s, 10, 0, ' ');
    }
    return out;
}

// An RPC_SID (MS-DTYP §2.4.2.3), deferred or not: the conformance count,
// then revision, sub-authority count, authority, sub-authorities.
fn ndr_sid(b: const u8[:], n: Ndr&) -> u8[>..] {
    let max = ndr_u32(b, n) as i64;
    let rev = ndr_u8(b, n);
    let cnt = ndr_u8(b, n) as i64;
    let auth = ndr_bytes(b, n, 6);
    if cnt != max || cnt > 15 { n.bad = true; var e: u8[>..] = []; return e; }
    var subs: u32[>..] = [];
    for i in cnt { subs.push(ndr_u32(b, n)); }
    return sid_text(rev, auth, subs);
}

// A SID as Windows stores it outside NDR (PAC_REQUESTOR, UPN_DNS_INFO's
// extension): revision, count, authority, little-endian sub-authorities.
fn sid_from_bytes(b: const u8[:]) -> u8[>..], bool {
    var e: u8[>..] = [];
    if b.len < 8 { return e, false; }
    let cnt = b[1] as i64;
    if b.len != 8 + 4 * cnt { return e, false; }
    var subs: u32[>..] = [];
    for i in cnt {
        let p = 8 + 4 * i;
        subs.push(b[p] | (b[p + 1] as u32) << 8 | (b[p + 2] as u32) << 16 | (b[p + 3] as u32) << 24);
    }
    return sid_text(b[0], b[2..8], subs), true;
}
