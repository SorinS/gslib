// asn1: reading and writing ASN.1 in DER (X.690), strictly: definite,
// minimal lengths, minimal integers and identifiers, DER's booleans and
// bit strings, and the time and string forms RFC 5280 allows. The readers
// that take `ber` read BER as LDAP (RFC 4511 §5.1) has it instead: lengths
// in more octets than they need, any nonzero boolean, integers with
// redundant leading octets; still only definite lengths. A parse
// never copies: an element is a Tlv of offsets into the caller's buffer,
// and the typed readers decode its content when asked. Also PEM (RFC 7468)
// and a dump in the style of `openssl asn1parse`.

namespace asn1;

import std;
import base64;

// Universal tags, as their identifier octets.
let BOOLEAN: u32 = 0x01;
let INTEGER: u32 = 0x02;
let BIT_STRING: u32 = 0x03;
let OCTET_STRING: u32 = 0x04;
let NULL: u32 = 0x05;
let OID: u32 = 0x06;
let ENUMERATED: u32 = 0x0a;
let UTF8_STRING: u32 = 0x0c;
let PRINTABLE_STRING: u32 = 0x13;
let T61_STRING: u32 = 0x14;
let IA5_STRING: u32 = 0x16;
let UTC_TIME: u32 = 0x17;
let GENERALIZED_TIME: u32 = 0x18;
let VISIBLE_STRING: u32 = 0x1a;
let UNIVERSAL_STRING: u32 = 0x1c;
let BMP_STRING: u32 = 0x1e;
let SEQUENCE: u32 = 0x30;
let SET: u32 = 0x31;

let CLASS_UNIVERSAL: u8 = 0;
let CLASS_APPLICATION: u8 = 1;
let CLASS_CONTEXT: u8 = 2;
let CLASS_PRIVATE: u8 = 3;

// The tag of [n] in the context class, constructed (EXPLICIT, or IMPLICIT
// over a constructed type) or primitive.
fn ctx(n: u32, constructed: bool) -> u32 {
    let base: u32 = if constructed { 0xa0 } else { 0x80 };
    return if n < 31 { base | n } else { base << 24 | n };
}

// One element: its tag (the identifier octet for numbers below 31, else
// class and constructed bits << 24 | number), and where its header,
// content and end are in the buffer.
struct Tlv { tag: u32, cls: u8, constructed: bool, number: u32, start: i64, off: i64, end: i64 }

fn content_len(t: Tlv) -> i64 { t.end - t.off }

// Reads the element at `at`, which must end by `limit`.
fn read(buf: const u8[:], at: i64, limit: i64, ber: bool = false) -> Tlv, bool {
    var t = Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: at, off: at, end: at };
    if at < 0 || limit > buf.len || at + 2 > limit { return t, false; }
    let id = buf[at];
    t.cls = id >> 6;
    t.constructed = id & 0x20 != 0;
    var p = at + 1;
    if id & 0x1f != 0x1f {
        t.number = id & 0x1f;
        t.tag = id;
    } else {
        // High tag numbers: base 128, minimal, and really 31 or more.
        var n: u32 = 0;
        loop {
            if p >= limit { return t, false; }
            let b = buf[p];
            p++;
            if n == 0 && b == 0x80 { return t, false; }
            if n > 0x00ffffff { return t, false; }
            n = (n << 7) | (b & 0x7f);
            if b & 0x80 == 0 { break; }
        }
        if n < 31 { return t, false; }
        t.number = n;
        t.tag = ((id & 0xe0) as u32) << 24 | n;
    }
    if p >= limit { return t, false; }
    let l0 = buf[p];
    p++;
    var len: i64 = 0;
    if l0 < 0x80 {
        len = l0;
    } else {
        let nb: i64 = l0 & 0x7f;
        // 0x80 is BER's indefinite length; DER uses the fewest octets.
        if nb == 0 || p + nb > limit { return t, false; }
        if !ber && (nb > 4 || buf[p] == 0) { return t, false; }
        for i in nb {
            if len > 0x7fffffff { return t, false; }
            len = (len << 8) | buf[p + i];
        }
        p += nb;
        if !ber && len < 128 { return t, false; }
    }
    if len > limit - p { return t, false; }
    t.off = p;
    t.end = p + len;
    return t, true;
}

// The one element that makes up all of buf.
fn parse(buf: const u8[:], ber: bool = false) -> Tlv, bool {
    let t, ok = read(buf, 0, buf.len, ber);
    return t, ok && t.end == buf.len;
}

// The elements inside a constructed one, which must fill it exactly.
fn children(buf: const u8[:], t: Tlv, ber: bool = false) -> Tlv[>..], bool {
    var out: Tlv[>..] = [];
    if !t.constructed { return out, false; }
    var p = t.off;
    while p < t.end {
        let c, ok = read(buf, p, t.end, ber);
        if !ok { out.clear(); return out, false; }
        out.push(c);
        p = c.end;
    }
    return out, true;
}

// The children of a constructed element of a given tag.
fn children_of(buf: const u8[:], t: Tlv, tag: u32, ber: bool = false) -> Tlv[>..], bool {
    var out, ok = children(buf, t, ber);
    if t.tag != tag { out.clear(); return out, false; }
    return out, ok;
}

// The single element inside an EXPLICIT tag.
fn explicit(buf: const u8[:], t: Tlv, ber: bool = false) -> Tlv, bool {
    let cs, ok = children(buf, t, ber);
    if !ok || cs.len != 1 { return t, false; }
    return cs[0], true;
}

fn is_tag(t: Tlv, tag: u32) -> bool { t.tag == tag }

// BOOLEAN: DER allows only 0x00 and 0xff, BER any nonzero octet for true.
// tag is for an IMPLICIT one.
fn read_bool(buf: const u8[:], t: Tlv, ber: bool = false, tag: u32 = BOOLEAN) -> bool, bool {
    if t.tag != tag || content_len(t) != 1 { return false, false; }
    let v = buf[t.off];
    if ber { return v != 0, true; }
    return v == 0xff, v == 0 || v == 0xff;
}

fn read_null(buf: const u8[:], t: Tlv) -> bool { t.tag == NULL && content_len(t) == 0 }

// Whether an integer's content is minimal: no 9 leading zero or one bits.
fn int_minimal(buf: const u8[:], t: Tlv) -> bool {
    let n = content_len(t);
    if n == 0 { return false; }
    if n == 1 { return true; }
    let a = buf[t.off];
    let b = buf[t.off + 1];
    return !(a == 0 && b < 0x80) && !(a == 0xff && b >= 0x80);
}

// INTEGER (or ENUMERATED, with that tag) as an i64.
fn read_i64(buf: const u8[:], t: Tlv, tag: u32 = INTEGER, ber: bool = false) -> i64, bool {
    if t.tag != tag || content_len(t) == 0 { return 0, false; }
    var from = t.off;
    if ber {
        // Leading octets that only repeat the sign.
        while t.end - from > 1 && ((buf[from] == 0 && buf[from + 1] < 0x80) || (buf[from] == 0xff && buf[from + 1] >= 0x80)) { from++; }
    } else if !int_minimal(buf, t) {
        return 0, false;
    }
    if t.end - from > 8 { return 0, false; }
    var v: i64 = if buf[from] >= 0x80 { -1 } else { 0 };
    for i in from..t.end { v = (v << 8) | buf[i]; }
    return v, true;
}

// A non-negative INTEGER as big-endian magnitude bytes (no sign octet):
// moduli, exponents, serial numbers.
fn read_uint(buf: const u8[:], t: Tlv) -> u8[>..], bool {
    var out: u8[>..] = [];
    if t.tag != INTEGER || !int_minimal(buf, t) || buf[t.off] >= 0x80 { return out, false; }
    let from = if buf[t.off] == 0 && content_len(t) > 1 { t.off + 1 } else { t.off };
    out.append(buf[from..t.end]);
    return out, true;
}

// An INTEGER's content as it is, two's complement, if minimal.
fn read_int_bytes(buf: const u8[:], t: Tlv) -> u8[>..], bool {
    var out: u8[>..] = [];
    if t.tag != INTEGER || !int_minimal(buf, t) { return out, false; }
    out.append(buf[t.off..t.end]);
    return out, true;
}

// BIT STRING: the bytes and the number of unused bits in the last one,
// which DER requires to be zero bits.
fn read_bits(buf: const u8[:], t: Tlv) -> u8[>..], i64, bool {
    var out: u8[>..] = [];
    let n = content_len(t);
    if t.tag != BIT_STRING || n < 1 { return out, 0, false; }
    let unused: i64 = buf[t.off];
    if unused > 7 || (n == 1 && unused != 0) { return out, 0, false; }
    if n > 1 && buf[t.end - 1] & ((1 << unused) - 1) != 0 { return out, 0, false; }
    out.append(buf[t.off + 1..t.end]);
    return out, unused, true;
}

// The bit at index i of a BIT STRING (bit 0 is the first, most significant).
fn bit(bits: const u8[:], i: i64) -> bool {
    i / 8 < bits.len && (bits[i / 8] >> (7 - i % 8)) & 1 == 1
}

fn read_octets(buf: const u8[:], t: Tlv) -> u8[>..], bool {
    var out: u8[>..] = [];
    if t.tag != OCTET_STRING { return out, false; }
    out.append(buf[t.off..t.end]);
    return out, true;
}

// OBJECT IDENTIFIER as dotted text, "1.2.840.113549".
fn read_oid(buf: const u8[:], t: Tlv) -> u8[>..], bool {
    var out: u8[>..] = [];
    if t.tag != OID || content_len(t) == 0 { return out, false; }
    var v: u64 = 0;
    var first = true;
    var start = true;
    for i in t.off..t.end {
        let b = buf[i];
        if start && b == 0x80 { out.clear(); return out, false; }   // not minimal
        if v >> 57 != 0 { out.clear(); return out, false; }          // past 64 bits
        v = (v << 7) | (b & 0x7f);
        start = b & 0x80 == 0;
        if b & 0x80 == 0 {
            if first {
                let top: u64 = if v < 40 { 0 } else if v < 80 { 1 } else { 2 };
                format_uint(out, top, 10, 0, ' ');
                out.push('.');
                format_uint(out, v - 40 * top, 10, 0, ' ');
                first = false;
            } else {
                out.push('.');
                format_uint(out, v, 10, 0, ' ');
            }
            v = 0;
        }
    }
    if !start { out.clear(); return out, false; }                  // ends inside an arc
    return out, true;
}

// The content octets of a dotted OID, and false for bad text.
fn oid_encode(text: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var arcs: u64[>..] = [];
    for part in split(text, '.') {
        if part.len == 0 || (part.len > 1 && part[0] == '0') { out.clear(); return out, false; }
        var v: u64 = 0;
        for c in part {
            if c < '0' || c > '9' { out.clear(); return out, false; }
            let d: u64 = c - '0';
            // At most 2^64 - 1 = 18446744073709551615.
            if v > 1844674407370955161 || (v == 1844674407370955161 && d > 5) { out.clear(); return out, false; }
            v = v * 10 + d;
        }
        arcs.push(v);
    }
    if arcs.len < 2 || arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39) { out.clear(); return out, false; }
    for i in 1..arcs.len {
        var v = if i == 1 { 40 * arcs[0] + arcs[1] } else { arcs[i] };
        var tmp: u8[10] = [0; 10];
        var n = 0;
        loop {
            tmp[n] = (v & 0x7f) as! u8;
            n++;
            v = v >> 7;
            if v == 0 { break; }
        }
        while n > 0 {
            n--;
            out.push(tmp[n] | (if n > 0 { 0x80 } else { 0 }));
        }
    }
    return out, true;
}

// Whether t is the OID with this dotted text.
fn oid_is(buf: const u8[:], t: Tlv, text: const u8[:]) -> bool {
    let enc, ok = oid_encode(text);
    return ok && t.tag == OID && buf[t.off..t.end] == enc;
}

fn is_leap(y: i64) -> bool { (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }

fn days_in_month(y: i64, m: i64) -> i64 {
    if m == 2 { return if is_leap(y) { 29 } else { 28 }; }
    if m == 4 || m == 6 || m == 9 || m == 11 { return 30; }
    return 31;
}

// Days since 1970-01-01 (Howard Hinnant's days_from_civil).
fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn civil_from_days(days: i64) -> i64, i64, i64 {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    return yoe + era * 400 + (if m <= 2 { 1 } else { 0 }), m, d;
}

fn digits(s: const u8[:], at: i64, n: i64) -> i64 {
    var v = 0;
    for i in n {
        let c = s[at + i];
        if c < '0' || c > '9' { return -1; }
        v = v * 10 + (c - '0');
    }
    return v;
}

// UTCTime (YYMMDDHHMMSSZ, years 1950 to 2049) or GeneralizedTime
// (YYYYMMDDHHMMSSZ) as seconds since 1970, in RFC 5280's profile: UTC,
// seconds present, no fractions.
fn read_time(buf: const u8[:], t: Tlv) -> i64, bool {
    let s = buf[t.off..t.end];
    var y = 0;
    var p = 0;
    if t.tag == UTC_TIME && s.len == 13 {
        let yy = digits(s, 0, 2);
        if yy < 0 { return 0, false; }
        y = if yy < 50 { 2000 + yy } else { 1900 + yy };
        p = 2;
    } else if t.tag == GENERALIZED_TIME && s.len == 15 {
        y = digits(s, 0, 4);
        if y < 0 { return 0, false; }
        p = 4;
    } else {
        return 0, false;
    }
    let mo = digits(s, p, 2);
    let d = digits(s, p + 2, 2);
    let h = digits(s, p + 4, 2);
    let mi = digits(s, p + 6, 2);
    let se = digits(s, p + 8, 2);
    if s[s.len - 1] != 'Z' || mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, mo)
        || h < 0 || h > 23 || mi < 0 || mi > 59 || se < 0 || se > 59 {
        return 0, false;
    }
    return days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se, true;
}

// Appends the UTF-8 of a code point.
fn put_utf8(out: u8[>..]&, cp: u32) {
    if cp < 0x80 {
        out.push(cp as! u8);
    } else if cp < 0x800 {
        out.push((0xc0 | (cp >> 6)) as! u8);
        out.push((0x80 | (cp & 0x3f)) as! u8);
    } else if cp < 0x10000 {
        out.push((0xe0 | (cp >> 12)) as! u8);
        out.push((0x80 | ((cp >> 6) & 0x3f)) as! u8);
        out.push((0x80 | (cp & 0x3f)) as! u8);
    } else {
        out.push((0xf0 | (cp >> 18)) as! u8);
        out.push((0x80 | ((cp >> 12) & 0x3f)) as! u8);
        out.push((0x80 | ((cp >> 6) & 0x3f)) as! u8);
        out.push((0x80 | (cp & 0x3f)) as! u8);
    }
}

// Whether s is well-formed UTF-8: shortest forms, no surrogates, at most
// U+10FFFF.
fn utf8_valid(s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        let c = s[i];
        var n = 0;
        var cp: u32 = 0;
        var min: u32 = 0;
        if c < 0x80 { i++; continue; }
        if c >= 0xc2 && c <= 0xdf { n = 1; cp = c & 0x1f; min = 0x80; }
        else if c >= 0xe0 && c <= 0xef { n = 2; cp = c & 0x0f; min = 0x800; }
        else if c >= 0xf0 && c <= 0xf4 { n = 3; cp = c & 0x07; min = 0x10000; }
        else { return false; }
        if i + n >= s.len { return false; }
        for k in 1..n + 1 {
            let b = s[i + k];
            if b & 0xc0 != 0x80 { return false; }
            cp = (cp << 6) | (b & 0x3f);
        }
        if cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) { return false; }
        i += n + 1;
    }
    return true;
}

fn printable_char(c: u8) -> bool {
    (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
        || c == ' ' || c == '\'' || c == '(' || c == ')' || c == '+' || c == ','
        || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' || c == '?'
        || c == '*' || c == '&'                          // outside the set, but common in real names
}

// A character string of any of the types names use, as UTF-8: UTF8String
// (validated), PrintableString, IA5String and VisibleString (checked
// against their sets), T61String (taken as Latin-1, as most decoders do),
// BMPString (UCS-2) and UniversalString (UCS-4).
fn read_string(buf: const u8[:], t: Tlv) -> u8[>..], bool {
    var out: u8[>..] = [];
    let s = buf[t.off..t.end];
    if t.tag == UTF8_STRING {
        if !utf8_valid(s) { return out, false; }
        out.append(s);
    } else if t.tag == PRINTABLE_STRING {
        for c in s { if !printable_char(c) { return out, false; } }
        out.append(s);
    } else if t.tag == IA5_STRING || t.tag == VISIBLE_STRING {
        for c in s {
            if c >= 0x80 || (t.tag == VISIBLE_STRING && c < 0x20) { return out, false; }
        }
        out.append(s);
    } else if t.tag == T61_STRING {
        for c in s { put_utf8(out, c); }
    } else if t.tag == BMP_STRING {
        if s.len % 2 != 0 { return out, false; }
        var i = 0;
        while i < s.len {
            let cp = (s[i] as u32) << 8 | s[i + 1];
            if cp >= 0xd800 && cp <= 0xdfff { out.clear(); return out, false; }
            put_utf8(out, cp);
            i += 2;
        }
    } else if t.tag == UNIVERSAL_STRING {
        if s.len % 4 != 0 { return out, false; }
        var i = 0;
        while i < s.len {
            let cp = (s[i] as u32) << 24 | (s[i + 1] as u32) << 16 | (s[i + 2] as u32) << 8 | s[i + 3];
            if cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) { out.clear(); return out, false; }
            put_utf8(out, cp);
            i += 4;
        }
    } else {
        return out, false;
    }
    return out, true;
}

// --- Writing ----------------------------------------------------------------

// A header for a tag (as Tlv.tag holds it) and a content length.
fn put_header(out: u8[>..]&, tag: u32, len: i64) {
    assert(len >= 0 && len < 1 << 32);
    if tag < 256 {
        out.push(tag as! u8);
    } else {
        let n = tag & 0x00ffffff;
        out.push(((tag >> 24) | 0x1f) as! u8);
        var tmp: u8[5] = [0; 5];
        var k = 0;
        var v = n;
        loop {
            tmp[k] = (v & 0x7f) as! u8;
            k++;
            v = v >> 7;
            if v == 0 { break; }
        }
        while k > 0 {
            k--;
            out.push(tmp[k] | (if k > 0 { 0x80 } else { 0 }));
        }
    }
    if len < 128 {
        out.push(len as! u8);
        return;
    }
    var nb = 1;
    while len >> (8 * nb) != 0 { nb++; }
    out.push((0x80 | nb) as! u8);
    var i = nb;
    while i > 0 { i--; out.push((len >> (8 * i)) as! u8); }
}

// tag, length, content.
fn put(out: u8[>..]&, tag: u32, content: const u8[:]) {
    put_header(out, tag, content.len);
    out.append(content);
}

fn put_bool(out: u8[>..]&, v: bool) {
    let c: u8[1] = [if v { 0xff } else { 0 }];
    put(out, BOOLEAN, c);
}

fn put_null(out: u8[>..]&) { put_header(out, NULL, 0); }

fn put_i64(out: u8[>..]&, v: i64, tag: u32 = INTEGER) {
    var n = 8;
    // Drop leading bytes that only repeat the sign.
    while n > 1 {
        let top = (v >> (8 * (n - 1))) & 0xff;
        let next = (v >> (8 * (n - 2))) & 0x80;
        if (top == 0 && next == 0) || (top == 0xff && next == 0x80) { n--; } else { break; }
    }
    put_header(out, tag, n);
    var i = n;
    while i > 0 { i--; out.push((v >> (8 * i)) as! u8); }
}

// A non-negative INTEGER from big-endian magnitude bytes (leading zeros
// are dropped and a sign octet added where needed).
fn put_uint(out: u8[>..]&, mag: const u8[:]) {
    if mag.len == 0 { let z: u8[1] = [0]; put(out, INTEGER, z); return; }
    var i = 0;
    while i < mag.len - 1 && mag[i] == 0 { i++; }
    let lead0 = mag[i] >= 0x80;
    put_header(out, INTEGER, mag.len - i + (if lead0 { 1 } else { 0 }));
    if lead0 { out.push(0); }
    out.append(mag[i..]);
}

fn put_bits(out: u8[>..]&, bits: const u8[:], unused: i64 = 0) {
    assert(unused >= 0 && unused <= 7 && (bits.len > 0 || unused == 0));
    put_header(out, BIT_STRING, bits.len + 1);
    out.push(unused as! u8);
    out.append(bits);
}

fn put_octets(out: u8[>..]&, b: const u8[:]) { put(out, OCTET_STRING, b); }

fn put_oid(out: u8[>..]&, text: const u8[:]) {
    let enc, ok = oid_encode(text);
    assert(ok);
    put(out, OID, enc);
}

fn put_utf8_string(out: u8[>..]&, s: const u8[:]) {
    assert(utf8_valid(s));
    put(out, UTF8_STRING, s);
}

fn put_printable(out: u8[>..]&, s: const u8[:]) {
    for c in s { assert(printable_char(c)); }
    put(out, PRINTABLE_STRING, s);
}

fn put_ia5(out: u8[>..]&, s: const u8[:]) {
    for c in s { assert(c < 0x80); }
    put(out, IA5_STRING, s);
}

// A time as RFC 5280 wants it: UTCTime through 2049, GeneralizedTime after.
fn put_time(out: u8[>..]&, unix: i64) {
    let days = if unix >= 0 { unix / 86400 } else { (unix - 86399) / 86400 };
    let secs = unix - days * 86400;
    let y, m, d = civil_from_days(days);
    assert(y >= 0 && y <= 9999);
    var s: u8[>..] = [];
    let utc = y >= 1950 && y < 2050;
    if utc { format_int(s, y % 100, 10, 2, '0'); } else { format_int(s, y, 10, 4, '0'); }
    format_int(s, m, 10, 2, '0');
    format_int(s, d, 10, 2, '0');
    format_int(s, secs / 3600, 10, 2, '0');
    format_int(s, secs / 60 % 60, 10, 2, '0');
    format_int(s, secs % 60, 10, 2, '0');
    s.push('Z');
    put(out, if utc { UTC_TIME } else { GENERALIZED_TIME }, s);
}

// --- PEM (RFC 7468) ---------------------------------------------------------

// The contents of every PEM block with this label ("CERTIFICATE", say), or
// of every block when the label is empty; false if one is malformed.
fn pem_decode(text: const u8[:], label: const u8[:]) -> u8[][>..], bool {
    var out: u8[][>..] = [];
    var p = 0;
    loop {
        let begin = find_from(text, "-----BEGIN ", p);
        if begin < 0 { break; }
        let lab_end = find_from(text, "-----", begin + 11);
        if lab_end < 0 { return out, false; }
        let lab = text[begin + 11..lab_end];
        var endm: u8[>..] = [];
        endm.append("-----END ");
        endm.append(lab);
        endm.append("-----");
        let end = find_from(text, endm, lab_end + 5);
        if end < 0 { return out, false; }
        p = end + endm.len;
        if label.len > 0 && lab != label { continue; }
        var b64: u8[>..] = [];
        for c in text[lab_end + 5..end] {
            if c == '\n' || c == '\r' || c == ' ' || c == '\t' { continue; }
            b64.push(c);
        }
        var der: u8[>..] = [];
        if !base64::decode(der, b64) { return out, false; }
        out.push(copy(der));
    }
    return out, true;
}

fn find_from(s: const u8[:], pat: const u8[:], from: i64) -> i64 {
    var i = from;
    while i + pat.len <= s.len {
        if s[i..i + pat.len] == pat { return i; }
        i++;
    }
    return -1;
}

// A PEM block, base64 in lines of 64.
fn pem_encode(out: u8[>..]&, label: const u8[:], der: const u8[:]) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    base64::encode(b64, der);
    var i = 0;
    while i < b64.len {
        let n = ::min(64, b64.len - i);
        out.append(b64[i..i + n]);
        out.push('\n');
        i += n;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

// --- Dump -------------------------------------------------------------------

// One line per element, like `openssl asn1parse -i`: offset, depth, header
// and content lengths, constructed or primitive, class and number. False
// when buf is not DER.
fn dump(buf: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let top, ok = parse(buf);
    if !ok { return out, false; }
    var ends: i64[>..<] = [];
    var p = 0;
    while p < buf.len {
        let limit = if ends.len > 0 { ends[ends.len - 1] } else { buf.len };
        let t, okt = read(buf, p, limit);
        if !okt { out.clear(); return out, false; }
        format(out, t.start, " d=", ends.len, " hl=", t.off - t.start, " l=", content_len(t), " ",
               if t.constructed { "cons" } else { "prim" }, " ", t.cls, ":", t.number, "\n");
        if t.constructed {
            ends.push(t.end);
            p = t.off;
        } else {
            p = t.end;
        }
        while ends.len > 0 && p == ends[ends.len - 1] { let e = ends.pop(); }
    }
    return out, true;
}
