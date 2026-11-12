// dns.rdata: each type's rdata, described as miekg's struct tags describe
// it, by a layout: one character per field.
//
//   1 2 4 6 8   unsigned integers of 1, 2, 4, 6 and 8 bytes
//   c           a domain name that may be compressed (RFC 3597 §4's types)
//   n           a domain name never compressed
//   a A         an IPv4 and an IPv6 address
//   s           a character-string, written in quotes
//   S           a character-string, written bare (X25, GPOS, CAA's tag)
//   t           character-strings to the end (TXT)
//   o           octets to the end, written in quotes (URI, CAA's value)
//   x X         hex to the end, in lower and upper case
//   Z           hex to the end, in groups of 1024 digits (SMIMEA)
//   b           base64 to the end
//   h           a byte of length, then that much hex; "-" for none (NSEC3 salt)
//   B           a byte of length, then that much base32hex (NSEC3's next name)
//   m           a type bitmap to the end (NSEC, NSEC3, CSYNC)
//   y           a type, as a 2-byte integer written as its mnemonic
//   T           a 4-byte time, written YYYYMMDDHHMMSS (RRSIG)
//   C g         CERT's type and algorithm, written as mnemonics
//   e E         EUI-48 and EUI-64
//   d D         a 64-bit locator in groups of 4 hex digits, lower (NID) and upper (L64)
//   L           LOC's 16 bytes
//   P           APL's prefixes
//   I           IPSECKEY after its first 3 bytes
//   G M         AMTRELAY's D-bit and gateway type (one byte), and its gateway
//   H           HIP
//   V           SVCB's parameters
//   W           TSIG and TKEY, which have no text form
//   R           opaque to the end (NULL; OPT, whose options dns.edns reads)
//
// One walk over a layout checks rdata, finds its names (to decompress,
// compress or lower-case them) and writes its text. A type without a
// layout is unknown: its rdata is opaque, written as RFC 3597's \# form.

namespace dns;

import std;
import base64;
import os;
import dns;

struct Layout { t: u16, f: u8[..12], lower: bool }

// lower: the type's rdata names are lower-cased in DNSSEC's canonical form
// (RFC 4034 §6.2, less HINFO as RFC 6840 §5.1 has it), miekg's list.
let LAYOUTS: Layout[88] = [
    Layout { 1, "a", false },            // A
    Layout { 2, "c", true },             // NS
    Layout { 3, "c", true },             // MD
    Layout { 4, "c", true },             // MF
    Layout { 5, "c", true },             // CNAME
    Layout { 6, "cc44444", true },       // SOA
    Layout { 7, "c", true },             // MB
    Layout { 8, "c", true },             // MG
    Layout { 9, "c", true },             // MR
    Layout { 10, "R", false },           // NULL: its own text
    Layout { 12, "c", true },            // PTR
    Layout { 13, "ss", false },          // HINFO
    Layout { 14, "cc", true },           // MINFO
    Layout { 15, "2c", true },           // MX
    Layout { 16, "t", false },           // TXT
    Layout { 17, "nn", true },           // RP
    Layout { 18, "2n", true },           // AFSDB
    Layout { 19, "S", false },           // X25
    Layout { 20, "ss", false },          // ISDN
    Layout { 21, "2n", true },           // RT
    Layout { 23, "n", false },           // NSAP-PTR
    Layout { 24, "y114TT2nb", true },    // SIG
    Layout { 25, "211b", false },        // KEY
    Layout { 26, "2nn", true },          // PX
    Layout { 27, "SSS", false },         // GPOS
    Layout { 28, "A", false },           // AAAA
    Layout { 29, "L", false },           // LOC
    Layout { 31, "X", false },           // EID
    Layout { 32, "X", false },           // NIMLOC
    Layout { 33, "222n", true },         // SRV
    Layout { 35, "22sssn", true },       // NAPTR
    Layout { 36, "2n", true },           // KX
    Layout { 37, "C2gb", false },        // CERT
    Layout { 39, "n", true },            // DNAME
    Layout { 41, "R", false },           // OPT: its own text
    Layout { 42, "P", false },           // APL
    Layout { 43, "211X", false },        // DS
    Layout { 44, "11X", false },         // SSHFP
    Layout { 45, "111I", false },        // IPSECKEY
    Layout { 46, "y114TT2nb", false },   // RRSIG
    Layout { 47, "nm", false },          // NSEC
    Layout { 48, "211b", false },        // DNSKEY
    Layout { 49, "b", false },           // DHCID
    Layout { 50, "112hBm", false },      // NSEC3
    Layout { 51, "112h", false },        // NSEC3PARAM
    Layout { 52, "111x", false },        // TLSA
    Layout { 53, "111Z", false },        // SMIMEA
    Layout { 55, "H", false },           // HIP
    Layout { 56, "t", false },           // NINFO
    Layout { 57, "211b", false },        // RKEY
    Layout { 58, "nn", false },          // TALINK
    Layout { 59, "211X", false },        // CDS
    Layout { 60, "211b", false },        // CDNSKEY
    Layout { 61, "b", false },           // OPENPGPKEY
    Layout { 62, "42m", false },         // CSYNC
    Layout { 63, "411x", false },        // ZONEMD
    Layout { 64, "2nV", false },         // SVCB
    Layout { 65, "2nV", false },         // HTTPS
    Layout { 99, "t", false },           // SPF
    Layout { 100, "s", false },          // UINFO
    Layout { 101, "4", false },          // UID
    Layout { 102, "4", false },          // GID
    Layout { 104, "2d", false },         // NID
    Layout { 105, "2a", false },         // L32
    Layout { 106, "2D", false },         // L64
    Layout { 107, "2n", false },         // LP
    Layout { 108, "e", false },          // EUI48
    Layout { 109, "E", false },          // EUI64
    Layout { 128, "", false },           // NXNAME
    Layout { 249, "nW", false },         // TKEY
    Layout { 250, "nW", false },         // TSIG
    Layout { 255, "", false },           // ANY
    Layout { 256, "22o", false },        // URI
    Layout { 257, "1So", false },        // CAA
    Layout { 258, "t", false },          // AVC
    Layout { 260, "1GM", false },        // AMTRELAY
    Layout { 261, "t", false },          // RESINFO
    Layout { 32768, "211X", false },     // TA
    Layout { 32769, "211X", false },     // DLV
    // Types with a name but no rdata of their own: kept opaque.
    Layout { 0, "?", false }, Layout { 0, "?", false }, Layout { 0, "?", false }, Layout { 0, "?", false },
    Layout { 0, "?", false }, Layout { 0, "?", false }, Layout { 0, "?", false }, Layout { 0, "?", false },
    Layout { 0, "?", false },
];

// The type's layout and whether it has one.
fn layout(t: u16) -> Layout, bool {
    for i in LAYOUTS.len {
        if LAYOUTS[i].t == t && LAYOUTS[i].f != "?" { return LAYOUTS[i], true; }
    }
    return Layout { t, "", false }, false;
}

fn known_type(t: u16) -> bool { let l, ok = layout(t); return ok; }

// Where the field of kind k starting at i in the uncompressed rdata rd ends,
// -1 if rd is malformed there. For a whole-rest kind, rd.len.
fn field_end(rd: const u8[:], i: i64, k: u8) -> i64 {
    let n = rd.len;
    if k == '1' || k == 'g' || k == 'G' { return if i + 1 <= n { i + 1 } else { -1 }; }
    if k == '2' || k == 'y' || k == 'C' { return if i + 2 <= n { i + 2 } else { -1 }; }
    if k == '4' || k == 'T' || k == 'a' { return if i + 4 <= n { i + 4 } else { -1 }; }
    if k == '6' || k == 'e' { return if i + 6 <= n { i + 6 } else { -1 }; }
    if k == '8' || k == 'E' || k == 'd' || k == 'D' { return if i + 8 <= n { i + 8 } else { -1 }; }
    if k == 'A' { return if i + 16 <= n { i + 16 } else { -1 }; }
    if k == 'L' { return if i + 16 <= n && rd[i] == 0 { i + 16 } else { -1 }; }
    if k == 'c' || k == 'n' {
        let l = name_len_at(rd, i);
        return if l < 0 { -1 } else { i + l };
    }
    if k == 's' || k == 'S' || k == 'h' || k == 'B' {
        if i >= n { return -1; }
        let e = i + 1 + rd[i];
        return if e <= n { e } else { -1 };
    }
    if k == 't' {
        if i >= n { return -1; }       // TXT has at least one string
        var j = i;
        while j < n { j += 1 + rd[j] as i64; }
        return if j == n { n } else { -1 };
    }
    if k == 'm' { return if bitmap_valid(rd[i..]) { n } else { -1 }; }
    if k == 'P' { return if apl_valid(rd[i..]) { n } else { -1 }; }
    if k == 'V' { return if svcb_valid(rd[i..]) { n } else { -1 }; }
    if k == 'I' || k == 'M' { return gateway_end(rd, i, k); }
    if k == 'H' { return if hip_valid(rd[i..]) { n } else { -1 }; }
    return n;      // o x X Z b W R: the rest
}

// --- Walking a layout ---------------------------------------------------------

// The names in uncompressed rdata, as offsets: each name's start. -1 for
// malformed rdata. Names are where 'c' and 'n' are, and the gateway of
// IPSECKEY and AMTRELAY when it is a name, and HIP's rendezvous servers.
fn rdata_names(t: u16, rd: const u8[:]) -> i64[..16], bool {
    var out: i64[..16] = [];
    let lay, known = layout(t);
    if !known { return out, true; }
    var i = 0;
    for k in lay.f {
        if i == rd.len && k != 't' { return out, true; }       // trailing fields may be absent
        let e = field_end(rd, i, k);
        if e < 0 { return out, false; }
        if k == 'c' || k == 'n' { out.push(i); }
        if (k == 'I' && rd[1] == 3) || (k == 'M' && rd[1] & 0x7f == 3) { out.push(i); }
        if k == 'H' {
            var j = 4 + rd[i] as i64 + get16(rd, i + 2);
            while j < rd.len && out.len < 16 { out.push(j); j += name_len_at(rd, j); }
        }
        i = e;
    }
    return out, i == rd.len;
}

// Reads the rdata of a record of type t from msg[off..off+rdlen], its names
// decompressed, onto out. ERR_RDATA if it is malformed.
fn rdata_unpack(msg: const u8[:], off: i64, rdlen: i64, t: u16, out: u8[>..]&) -> i64 {
    let end = off + rdlen;
    if end > msg.len { return ERR_SHORT; }
    let lay, known = layout(t);
    if !known || rdlen == 0 { out.append(msg[off..end]); return OK; }
    var i = off;
    for k in lay.f {
        if i == end { break; }
        if k == 'c' || k == 'n' {
            let nm, next, e = read_name(msg, i);
            if e != OK { return e; }
            if next > end { return ERR_RDATA; }
            out.append(nm);
            i = next;
            continue;
        }
        if k == 'I' || k == 'M' {
            // The gateway: maybe a name, which miekg reads as one with pointers.
            let gt = if k == 'I' { msg[off + 1] } else { msg[off + 1] & 0x7f };
            if gt == 3 {
                let nm, next, e = read_name(msg, i);
                if e != OK { return e; }
                if next > end { return ERR_RDATA; }
                out.append(nm);
                i = next;
            } else {
                let gl = if gt == 0 { 0 } else if gt == 1 { 4 } else if gt == 2 { 16 } else { -1 };
                if gl < 0 || i + gl > end { return ERR_RDATA; }
                out.append(msg[i .. i + gl]);
                i += gl;
            }
            if k == 'I' { out.append(msg[i..end]); i = end; }      // the public key
            continue;
        }
        if k == 'H' {
            if end - i < 4 { return ERR_RDATA; }
            let hl = msg[i] as i64;
            let pl = get16(msg, i + 2) as i64;
            if i + 4 + hl + pl > end { return ERR_RDATA; }
            out.append(msg[i .. i + 4 + hl + pl]);
            i += 4 + hl + pl;
            while i < end {
                let nm, next, e = read_name(msg, i);
                if e != OK { return e; }
                if next > end { return ERR_RDATA; }
                out.append(nm);
                i = next;
            }
            continue;
        }
        let e = field_end(msg[..end], i, k);
        if e < 0 { return ERR_RDATA; }
        out.append(msg[i..e]);
        i = e;
    }
    if i != end { return ERR_RDATA; }
    return OK;
}

// Whether the uncompressed rdata is well formed for its type.
fn rdata_valid(t: u16, rd: const u8[:]) -> bool {
    let names, ok = rdata_names(t, rd);
    return ok;
}

// The rdata with its names lower-cased where DNSSEC's canonical form says so.
fn rdata_canonical(t: u16, rd: const u8[:], out: u8[>..]&) {
    let lay, known = layout(t);
    let start = out.len;
    out.append(rd);
    if !lay.lower { return; }
    let names, ok = rdata_names(t, rd);
    for p in names {
        var i = p;
        while i < rd.len && rd[i] != 0 {
            let l = rd[i] as i64;
            for j in l { out[start + i + 1 + j] = lower(rd[i + 1 + j]); }
            i += 1 + l;
        }
    }
}

// --- Text --------------------------------------------------------------------

fn hex_append(out: u8[>..]&, b: const u8[:], upper: bool) {
    let digits = if upper { "0123456789ABCDEF" } else { "0123456789abcdef" };
    for c in b { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
}

let BASE32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

// Base32hex (RFC 4648 §7), upper case and unpadded, as miekg writes NSEC3's.
fn base32_append(out: u8[>..]&, b: const u8[:]) {
    var acc: u64 = 0;
    var bits = 0;
    for c in b {
        acc = (acc << 8) | c;
        bits += 8;
        while bits >= 5 { bits -= 5; out.push(BASE32HEX[(acc >> bits) & 31]); }
    }
    if bits > 0 { out.push(BASE32HEX[(acc << (5 - bits)) & 31]); }
}

fn base32_decode(out: u8[>..]&, s: const u8[:]) -> bool {
    var acc: u64 = 0;
    var bits = 0;
    for c in s {
        var v: i64 = -1;
        if c >= '0' && c <= '9' { v = c - '0'; }
        else if c >= 'a' && c <= 'v' { v = c - 'a' + 10; }
        else if c >= 'A' && c <= 'V' { v = c - 'A' + 10; }
        if v < 0 { return false; }
        acc = ((acc << 5) | v as! u64) & 0xffff;
        bits += 5;
        if bits >= 8 { bits -= 8; out.push((acc >> bits) as! u8); }
    }
    return true;
}

fn ip4_append(out: u8[>..]&, b: const u8[:]) {
    for i in 4 { if i > 0 { out.push('.'); } format(out, b[i]); }
}

// An IPv6 address as Go's net.IP.String writes it (RFC 5952): the longest
// run of two or more zero groups, the first if tied, as "::"; an
// IPv4-mapped address as its IPv4 form, which miekg prefixes with "::ffff:".
fn ip6_append(out: u8[>..]&, b: const u8[:]) {
    var mapped = true;
    for i in 10 { if b[i] != 0 { mapped = false; } }
    if mapped && b[10] == 0xff && b[11] == 0xff { out.append("::ffff:"); ip4_append(out, b[12..16]); return; }
    var best = -1;
    var best_len = 0;
    var g = 0;
    while g < 8 {
        if get16(b, g * 2) == 0 {
            var h = g;
            while h < 8 && get16(b, h * 2) == 0 { h++; }
            if h - g > best_len { best = g; best_len = h - g; }
            g = h;
        } else {
            g++;
        }
    }
    if best_len < 2 { best = -1; }
    g = 0;
    while g < 8 {
        if g == best {
            out.append("::");
            g += best_len;
            continue;
        }
        if g > 0 && g != best + best_len { out.push(':'); }
        format_uint(out, get16(b, g * 2), 16, 0, '0');
        g++;
    }
}

// A character-string's bytes in quotes, as miekg's sprintTxt writes each.
fn quoted_append(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    for c in s {
        if c == '"' || c == '\\' { out.push('\\'); out.push(c); }
        else if c < ' ' || c > '~' { escape_ddd(out, c); }
        else { out.push(c); }
    }
    out.push('"');
}

// A character-string bare, escaped as miekg's unpackString escapes it.
fn bare_append(out: u8[>..]&, s: const u8[:]) {
    for c in s {
        if c == '"' || c == '\\' { out.push('\\'); out.push(c); }
        else if c < ' ' || c > '~' { escape_ddd(out, c); }
        else { out.push(c); }
    }
}

// miekg's sprintTxtOctet over the raw octets: a backslash starts an
// escape, as it would in the text it came from.
fn octet_append(out: u8[>..]&, s: const u8[:]) {
    out.push('"');
    var i = 0;
    while i < s.len {
        if i + 1 < s.len && s[i] == '\\' && s[i + 1] == '.' { out.append("\\."); i += 2; continue; }
        var b = s[i];
        var n = 1;
        if s[i] == '\\' {
            if i + 1 == s.len { i++; continue; }
            if s.len - i >= 4 && is_ddd(s, i + 1) { b = (ddd(s, i + 1) & 255) as! u8; n = 4; } else { b = s[i + 1]; n = 2; }
        }
        if b == '"' || b == '\\' { out.push('\\'); out.push(b); }
        else if b < ' ' || b > '~' { escape_ddd(out, b); }
        else { out.push(b); }
        i += n;
    }
    out.push('"');
}

// The types of a type bitmap (RFC 4034 §4.1.2), in order.
fn bitmap_types(b: const u8[:]) -> u16[>..] {
    var out: u16[>..] = [];
    var i = 0;
    while i + 2 <= b.len {
        let win = b[i] as i64;
        let len = b[i + 1] as i64;
        for j in len {
            let byte = b[i + 2 + j];
            for k in 8 {
                if byte & (0x80 >> k) != 0 { out.push((win * 256 + j * 8 + k) as! u16); }
            }
        }
        i += 2 + len;
    }
    return out;
}

// Windows in increasing order, each 1 to 32 bytes; miekg allows an empty
// bitmap, and a last byte of zero too.
fn bitmap_valid(b: const u8[:]) -> bool {
    var i = 0;
    var last = -1;
    while i < b.len {
        if i + 2 > b.len { return false; }
        let win = b[i] as i64;
        let len = b[i + 1] as i64;
        if win <= last || len == 0 || len > 32 || i + 2 + len > b.len { return false; }
        last = win;
        i += 2 + len;
    }
    return true;
}

// A bitmap of the types, which must be sorted, duplicates allowed.
fn bitmap_build(out: u8[>..]&, types: const u16[:]) {
    var i = 0;
    while i < types.len {
        let win = types[i] >> 8;
        var bits: u8[32] = [0; 32];
        var len = 0;
        while i < types.len && types[i] >> 8 == win {
            let lo = types[i] & 255;
            bits[lo / 8] |= (0x80 >> (lo % 8)) as! u8;
            if lo / 8 + 1 > len { len = lo / 8 + 1; }
            i++;
        }
        out.push(win as! u8);
        out.push(len as! u8);
        out.append(bits[..len]);
    }
}

fn apl_valid(b: const u8[:]) -> bool {
    var i = 0;
    while i < b.len {
        if i + 4 > b.len { return false; }
        let fam = get16(b, i);
        let prefix = b[i + 2] as i64;
        let afd = (b[i + 3] & 0x7f) as i64;
        if fam != 1 && fam != 2 { return false; }
        let max = if fam == 1 { 4 } else { 16 };
        if afd > max || prefix > max * 8 || i + 4 + afd > b.len { return false; }
        i += 4 + afd;
    }
    return true;
}

fn gateway_end(rd: const u8[:], i: i64, k: u8) -> i64 {
    if rd.len < 2 { return -1; }
    let gt = if k == 'I' { rd[1] } else { rd[1] & 0x7f };
    var e = i;
    if gt == 0 { e = i; }
    else if gt == 1 { e = i + 4; }
    else if gt == 2 { e = i + 16; }
    else if gt == 3 { let l = name_len_at(rd, i); if l < 0 { return -1; } e = i + l; }
    else { return -1; }
    if e > rd.len { return -1; }
    if k == 'I' { return rd.len; }      // the public key: base64 to the end
    return if e == rd.len { e } else { -1 };
}

fn hip_valid(b: const u8[:]) -> bool {
    if b.len < 4 { return false; }
    var i = 4 + b[0] as i64 + get16(b, 2);
    if i > b.len { return false; }
    while i < b.len {
        let l = name_len_at(b, i);
        if l < 0 { return false; }
        i += l;
    }
    return true;
}

fn svcb_valid(b: const u8[:]) -> bool {
    var i = 0;
    var last = -1;
    while i < b.len {
        if i + 4 > b.len { return false; }
        let key = get16(b, i) as i64;
        let len = get16(b, i + 2) as i64;
        if key <= last || i + 4 + len > b.len { return false; }
        last = key;
        i += 4 + len;
    }
    return true;
}

// --- Times -------------------------------------------------------------------

// Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
fn civil(days: i64) -> i64, i64, i64 {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (if m <= 2 { 1 } else { 0 });
    return y, m, d;
}

fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

// Seconds since the epoch as YYYYMMDDHHMMSS, UTC.
fn utc_append(out: u8[>..]&, secs: i64) {
    var days = secs / 86400;
    var rem = secs % 86400;
    if rem < 0 { rem += 86400; days--; }
    let y, m, d = civil(days);
    format_int(out, y, 10, 4, '0');
    format_int(out, m, 10, 2, '0');
    format_int(out, d, 10, 2, '0');
    format_int(out, rem / 3600, 10, 2, '0');
    format_int(out, rem / 60 % 60, 10, 2, '0');
    format_int(out, rem % 60, 10, 2, '0');
}

let YEAR68: i64 = 1 << 31;

// An RRSIG time in serial arithmetic (RFC 1982), as miekg's TimeToString:
// the 32-bit value placed in the 136-year window that holds now.
fn time_append(out: u8[>..]&, t: u32, now: i64) {
    var m = (t - now) / YEAR68 - 1;
    if m < 0 { m = 0; }
    utc_append(out, t - m * YEAR68);
}

// "YYYYMMDDHHMMSS" (or a plain number of seconds) back to the 32-bit value,
// as miekg's StringToTime.
fn time_parse(s: const u8[:]) -> u32, bool {
    if s.len != 14 || !all_digits(s) {
        let n, ok = parse_int(s);
        if ok && all_digits(s) && n <= 0xffffffff { return n as! u32, true; }
        return 0, false;
    }
    let y, a = parse_int(s[0..4]);
    let mo, b = parse_int(s[4..6]);
    let d, c = parse_int(s[6..8]);
    let h, e = parse_int(s[8..10]);
    let mi, f = parse_int(s[10..12]);
    let se, g = parse_int(s[12..14]);
    if mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 59 { return 0, false; }
    let t = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    var m = t / YEAR68 - 1;
    if m < 0 { m = 0; }
    return (t - m * YEAR68) as! u32, true;
}

// --- Mnemonics -----------------------------------------------------------------

let ALG_CODES: u8[16] = [1, 2, 3, 5, 6, 7, 8, 10, 12, 13, 14, 15, 16, 252, 253, 254];
let ALG_NAMES: u8[..20][16] = [
    "RSAMD5", "DH", "DSA", "RSASHA1", "DSA-NSEC3-SHA1", "RSASHA1-NSEC3-SHA1", "RSASHA256", "RSASHA512",
    "ECC-GOST", "ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519", "ED448", "INDIRECT", "PRIVATEDNS", "PRIVATEOID",
];

let CERT_CODES: u16[10] = [1, 2, 3, 4, 5, 6, 7, 8, 253, 254];
let CERT_NAMES: u8[..8][10] = ["PKIX", "SPKI", "PGP", "IPKIX", "ISPKI", "IPGP", "ACPKIX", "IACPKIX", "URI", "OID"];

fn alg_append(out: u8[>..]&, a: u8) {
    for i in ALG_CODES.len { if ALG_CODES[i] == a { out.append(ALG_NAMES[i]); return; } }
    format(out, a);
}

fn alg_from_string(s: const u8[:]) -> i64 {
    for i in ALG_CODES.len { if ascii_eq_fold(s, ALG_NAMES[i]) { return ALG_CODES[i]; } }
    return -1;
}

fn cert_append(out: u8[>..]&, t: u16) {
    for i in CERT_CODES.len { if CERT_CODES[i] == t { out.append(CERT_NAMES[i]); return; } }
    format(out, t);
}

fn cert_from_string(s: const u8[:]) -> i64 {
    for i in CERT_CODES.len { if ascii_eq_fold(s, CERT_NAMES[i]) { return CERT_CODES[i]; } }
    return -1;
}

let SVCB_KEY_NAMES: u8[..16][9] = ["mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint", "dohpath", "ohttp"];

fn svcb_key_append(out: u8[>..]&, key: u16) {
    if key < 9 { out.append(SVCB_KEY_NAMES[key]); return; }
    if key == 65535 { return; }
    out.append("key");
    format(out, key);
}

fn svcb_param_append(out: u8[>..]&, v: const u8[:]) {
    for e in v {
        if e >= ' ' && e <= '~' {
            if e == '"' || e == ';' || e == ' ' || e == '\\' { out.push('\\'); }
            out.push(e);
        } else {
            escape_ddd(out, e);
        }
    }
}

// One SVCB parameter's value as miekg writes it.
fn svcb_value_append(out: u8[>..]&, key: u16, v: const u8[:]) {
    if key == 0 {
        var i = 0;
        while i + 2 <= v.len { if i > 0 { out.push(','); } svcb_key_append(out, get16(v, i)); i += 2; }
    } else if key == 1 {
        var i = 0;
        var first = true;
        while i < v.len {
            let l = v[i] as i64;
            if !first { out.push(','); }
            first = false;
            for e in v[i + 1 .. i + 1 + l] {
                if e < ' ' || e > '~' { escape_ddd(out, e); }
                else if e == '"' || e == ';' || e == ' ' { out.push('\\'); out.push(e); }
                else if e == ',' { out.append("\\\\\\044"); }
                else if e == '\\' { out.append("\\\\\\092"); }
                else { out.push(e); }
            }
            i += 1 + l;
        }
    } else if key == 2 || key == 8 {
    } else if key == 3 {
        if v.len == 2 { format(out, get16(v, 0)); }
    } else if key == 4 {
        var i = 0;
        while i + 4 <= v.len { if i > 0 { out.push(','); } ip4_append(out, v[i .. i + 4]); i += 4; }
    } else if key == 5 {
        base64::encode(out, v);
    } else if key == 6 {
        var i = 0;
        while i + 16 <= v.len { if i > 0 { out.push(','); } ip6_append(out, v[i .. i + 16]); i += 16; }
    } else {
        svcb_param_append(out, v);
    }
}

// --- Rdata as text -------------------------------------------------------------

// LOC's size and precision bytes (RFC 1876 §2) in metres, as miekg's cmToM.
fn cm_append(out: u8[>..]&, x: u8) {
    var m = (x >> 4) as i64;
    var e = (x & 15) as i64;
    if e < 2 {
        if e == 1 { m *= 10; }
        out.append("0.");
        format_int(out, m, 10, 2, '0');
        return;
    }
    format(out, m);
    while e > 2 { out.push('0'); e--; }
}

let LOC_EQUATOR: i64 = 1 << 31;
let LOC_DEGREES: i64 = 3600000;
let LOC_HOURS: i64 = 60000;

fn loc_angle(out: u8[>..]&, v0: i64, pos: u8, neg: u8) {
    var v = v0;
    var c = pos;
    if v > LOC_EQUATOR { v -= LOC_EQUATOR; } else { c = neg; v = LOC_EQUATOR - v; }
    format_int(out, v / LOC_DEGREES, 10, 2, '0');
    out.push(' ');
    v %= LOC_DEGREES;
    format_int(out, v / LOC_HOURS, 10, 2, '0');
    out.push(' ');
    v %= LOC_HOURS;
    format(out, v / 1000);
    out.push('.');
    format_int(out, v % 1000, 10, 3, '0');
    out.push(' ');
    out.push(c);
    out.push(' ');
}

fn loc_append(out: u8[>..]&, b: const u8[:]) {
    loc_angle(out, get32(b, 4), 'N', 'S');
    loc_angle(out, get32(b, 8), 'E', 'W');
    let alt = get32(b, 12) as i64 - 10000000;    // centimetres above the base
    let a = if alt < 0 { -alt } else { alt };
    if alt < 0 { out.push('-'); }
    format(out, a / 100);
    if get32(b, 12) % 100 != 0 { out.push('.'); format_int(out, a % 100, 10, 2, '0'); }
    out.append("m ");
    cm_append(out, b[1]); out.append("m ");
    cm_append(out, b[2]); out.append("m ");
    cm_append(out, b[3]); out.push('m');
}

fn apl_append(out: u8[>..]&, b: const u8[:]) {
    var i = 0;
    while i < b.len {
        let fam = get16(b, i);
        let prefix = b[i + 2];
        let afd = (b[i + 3] & 0x7f) as i64;
        if i > 0 { out.push(' '); }
        if b[i + 3] & 0x80 != 0 { out.push('!'); }
        format(out, fam);
        out.push(':');
        var ip: u8[16] = [0; 16];
        for j in afd { ip[j] = b[i + 4 + j]; }
        if fam == 1 { ip4_append(out, ip[..4]); } else { ip6_append(out, ip); }
        out.push('/');
        format(out, prefix);
        i += 4 + afd;
    }
}

fn locator_append(out: u8[>..]&, b: const u8[:], upper: bool) {
    for g in 4 {
        if g > 0 { out.push(':'); }
        hex_append(out, b[g * 2 .. g * 2 + 2], upper);
    }
}

fn eui_append(out: u8[>..]&, b: const u8[:]) {
    for i in b.len {
        if i > 0 { out.push('-'); }
        hex_append(out, b[i .. i + 1], false);
    }
}

// The text of uncompressed rdata, after the header, as miekg's String()
// writes it; now is the time RRSIG dates are read against.
fn rdata_append(out: u8[>..]&, t: u16, rd: const u8[:], now: i64) {
    let lay, known = layout(t);
    if !known { rfc3597_append(out, rd); return; }
    if t == TYPE_NULL { return; }          // NULL: the caller writes it
    var i = 0;
    var first = true;
    for k in lay.f {
        if i >= rd.len && k != 'h' && k != 'M' { break; }
        let e = field_end(rd, i, k);
        if e < 0 { break; }
        let f = rd[i..e];
        if k == 'h' && i >= rd.len { break; }
        if !first { out.push(' '); }
        first = false;
        if k == '1' { format(out, f[0]); }
        else if k == '2' { format(out, get16(f, 0)); }
        else if k == '4' { format(out, get32(f, 0)); }
        else if k == '6' { format(out, get48(f, 0)); }
        else if k == '8' { format(out, get64(f, 0)); }
        else if k == 'c' || k == 'n' { name_append(out, f); }
        else if k == 'a' { ip4_append(out, f); }
        else if k == 'A' { ip6_append(out, f); }
        else if k == 's' { quoted_append(out, f[1..]); }
        else if k == 'S' { bare_append(out, f[1..]); }
        else if k == 't' {
            var j = 0;
            while j < f.len {
                if j > 0 { out.push(' '); }
                quoted_append(out, f[j + 1 .. j + 1 + f[j]]);
                j += 1 + f[j] as i64;
            }
        }
        else if k == 'o' { octet_append(out, f); }
        else if k == 'x' { hex_append(out, f, false); }
        else if k == 'X' { hex_append(out, f, true); }
        else if k == 'Z' {
            var tmp: u8[>..] = [];
            hex_append(tmp, f, false);
            var j = 0;
            while j < tmp.len {
                if j > 0 { out.push(' '); }
                let e2 = if j + 1024 < tmp.len { j + 1024 } else { tmp.len };
                out.append(tmp[j..e2]);
                j = e2;
            }
        }
        else if k == 'b' { base64::encode(out, f); }
        else if k == 'h' { if f.len <= 1 { out.push('-'); } else { hex_append(out, f[1..], true); } }
        else if k == 'B' { base32_append(out, f[1..]); }
        else if k == 'm' {
            let ts = bitmap_types(f);
            for j in ts.len { if j > 0 { out.push(' '); } type_append(out, ts[j]); }
            if ts.len == 0 { out.pop(); }
        }
        else if k == 'y' { type_append(out, get16(f, 0)); }
        else if k == 'T' { time_append(out, get32(f, 0), now); }
        else if k == 'C' { cert_append(out, get16(f, 0)); }
        else if k == 'g' { alg_append(out, f[0]); }
        else if k == 'e' || k == 'E' { eui_append(out, f); }
        else if k == 'd' { locator_append(out, f, false); }
        else if k == 'D' { locator_append(out, f, true); }
        else if k == 'L' { loc_append(out, f); }
        else if k == 'P' { apl_append(out, f); }
        else if k == 'I' {
            let gt = rd[1];
            var g = i;
            if gt == 1 { ip4_append(out, rd[i .. i + 4]); g = i + 4; }
            else if gt == 2 { ip6_append(out, rd[i .. i + 16]); g = i + 16; }
            else if gt == 3 { let l = name_len_at(rd, i); name_append(out, rd[i .. i + l]); g = i + l; }
            else { out.push('.'); }
            out.push(' ');
            base64::encode(out, rd[g..]);
        }
        else if k == 'G' {
            out.push(if f[0] & 0x80 != 0 { '1' } else { '0' });
            out.push(' ');
            format(out, f[0] & 0x7f);
        }
        else if k == 'M' {
            let gt = rd[1];
            if gt & 0x7f == 1 { ip4_append(out, f); }
            else if gt & 0x7f == 2 { ip6_append(out, f); }
            else if gt & 0x7f == 3 { name_append(out, f); }
            else { out.push('.'); }
        }
        else if k == 'H' {
            let hl = f[0] as i64;
            let pl = get16(f, 2) as i64;
            format(out, f[1]);
            out.push(' ');
            hex_append(out, f[4 .. 4 + hl], false);
            out.push(' ');
            base64::encode(out, f[4 + hl .. 4 + hl + pl]);
            var j = 4 + hl + pl;
            while j < f.len { out.push(' '); let l = name_len_at(f, j); name_append(out, f[j .. j + l]); j += l; }
        }
        else if k == 'V' {
            var j = 0;
            var firstp = true;
            while j < f.len {
                let key = get16(f, j);
                let len = get16(f, j + 2) as i64;
                if !firstp { out.push(' '); }
                firstp = false;
                svcb_key_append(out, key);
                out.append("=\"");
                svcb_value_append(out, key, f[j + 4 .. j + 4 + len]);
                out.push('"');
                j += 4 + len;
            }
            if firstp { out.pop(); }
        }
        i = e;
    }
}

// RFC 3597's generic form: "\# n hex".
fn rfc3597_append(out: u8[>..]&, rd: const u8[:]) {
    out.append("\\# ");
    format(out, rd.len);
    out.push(' ');
    hex_append(out, rd, false);
}
