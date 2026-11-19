// kmip.text: what KMIP's XML and JSON encodings share (KMIP Profiles 2.1
// §5.4.1 and §5.5.1): names for tags, types, enumerations and masks, and
// each type's value as text. A tag is its normalized name
// (UniqueIdentifier) or its hex (0x420094); an Enumeration is its value's
// name (SymmetricKey) or hex (0x00000002), its names those of the tag it
// is under, or for KMIP 1.x's Attribute Value those of the attribute its
// Attribute Name names; an Attribute Reference's names are the tags'. A
// mask (Cryptographic Usage Mask, Storage Status Mask, Protection Storage
// Mask) is its bits' names, with what has no name in hex: "Sign Verify",
// or with JSON's separator "Sign|Verify". What is read takes every form
// the profiles allow; what is written is one of them, always the same.

namespace kmip;

import std;
import binary;
import kmip;
import kmip.tables;

// --- Names ----------------------------------------------------------------------

// The tag of a normalized name, or false.
fn tag_by_name(name: const u8[:]) -> u32, bool {
    var lo = 0;
    var hi = TAG_BY_NAME.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        let c = compare(TAG_BY_NAME[mid].name, name);
        if c == 0 { return TAG_BY_NAME[mid].tag, true; }
        if c < 0 { lo = mid + 1; } else { hi = mid; }
    }
    return 0, false;
}

fn hex_digit(c: u8) -> i64 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    if c >= 'A' && c <= 'F' { return c - 'A' + 10; }
    return -1;
}

// "0x" and exactly `digits` hex digits, as a number; false for anything
// else.
fn hex_number(s: const u8[:], digits: i64) -> u64, bool {
    if s.len != digits + 2 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X') { return 0, false; }
    var v: u64 = 0;
    for k in 2..s.len {
        let d = hex_digit(s[k]);
        if d < 0 { return 0, false; }
        v = (v << 4) | d as u64;
    }
    return v, true;
}

// A tag from its text: a name, or 0x and six hex digits.
fn tag_from_text(s: const u8[:]) -> u32, bool {
    let h, hok = hex_number(s, 6);
    if hok { return h as! u32, tag_ok(h as! u32); }
    let t, ok = tag_by_name(s);
    return t, ok;
}

// A tag's text: its name, or 0x and its hex for one not named here.
fn tag_text(out: u8[>..]&, tag: u32) {
    let n = tag_name(tag);
    if n.len > 0 { out.append(n); return; }
    out.append("0x");
    format_uint(out, tag, 16, 6, '0');
}

// An item type from its name ("TextString"), or 0.
fn type_from_text(s: const u8[:]) -> u8 {
    var t: u8 = STRUCTURE;
    while t <= DATE_TIME_EXTENDED {
        if type_name(t) == s { return t; }
        t++;
    }
    return 0;
}

// The tag an Enumeration or a mask under tag takes its names from: the
// tag's own, or for an Attribute Value the attribute's (attr, from the
// Attribute Name beside it; 0 when there is none or it is not named here).
// Data as an Enumeration (2.1) names an operation of the batch.
fn names_tag(tag: u32, attr: u32) -> u32 {
    if tag == TAG_ATTRIBUTE_VALUE { return attr; }
    if tag == TAG_DATA { return TAG_OPERATION; }
    return tag;
}

// The value of an Enumeration's name under a tag, or false.
fn enum_by_name(tag: u32, name: const u8[:]) -> u32, bool {
    if tag == TAG_ATTRIBUTE_REFERENCE {
        let t, ok = tag_by_name(name);
        return t, ok;
    }
    var lo = 0;
    var hi = ENUM_NAMES.len;
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ENUM_NAMES[mid].tag < tag { lo = mid + 1; } else { hi = mid; }
    }
    var k = lo;
    while k < ENUM_NAMES.len && ENUM_NAMES[k].tag == tag {
        if ENUM_NAMES[k].name == name { return ENUM_NAMES[k].value, true; }
        k++;
    }
    for a in ENUM_ALIASES {
        if a.tag == tag && a.name == name { return a.value, true; }
    }
    return 0, false;
}

// An Enumeration from its text: 0x and eight hex digits, or a name.
fn enum_from_text(tag: u32, s: const u8[:]) -> u32, bool {
    let h, hok = hex_number(s, 8);
    if hok { return h as! u32, true; }
    let v, ok = enum_by_name(tag, s);
    return v, ok;
}

fn enum_text(out: u8[>..]&, tag: u32, v: u32) {
    let n = if tag == TAG_ATTRIBUTE_REFERENCE { tag_name(v) } else { enum_name(tag, v) };
    if n.len > 0 { out.append(n); return; }
    out.append("0x");
    format_uint(out, v, 16, 8, '0');
}

// Whether an Integer under the tag is a mask with named bits.
fn is_mask(tag: u32) -> bool {
    for m in MASK_NAMES {
        if m.tag == tag { return true; }
    }
    return false;
}

fn mask_bit(tag: u32, name: const u8[:]) -> u32, bool {
    for m in MASK_NAMES {
        if m.tag == tag && m.name == name { return m.value, true; }
    }
    return 0, false;
}

// A mask's text: its bits' names, lowest first, separated by sep, and the
// bits without one as a hex number at the end; 0 for none.
fn mask_text(out: u8[>..]&, tag: u32, v: u32, sep: u8) {
    if v == 0 { out.push('0'); return; }
    var rest = v;
    var first = true;
    for m in MASK_NAMES {
        if m.tag == tag && v & m.value != 0 {
            if !first { out.push(sep); }
            out.append(m.name);
            rest &= ~m.value;
            first = false;
        }
    }
    if rest != 0 {
        if !first { out.push(sep); }
        out.append("0x");
        format_uint(out, rest, 16, 8, '0');
    }
}

// A mask from its text: a number (decimal or 0x and eight hex digits), or
// names and hex numbers separated by spaces or '|'.
fn mask_from_text(tag: u32, s: const u8[:]) -> u32, bool {
    let n, nok = int_from_text(s);
    if nok { return n as! u32, true; }
    var v: u32 = 0;
    var i = 0;
    var any = false;
    while i < s.len {
        while i < s.len && (s[i] == ' ' || s[i] == '|' || s[i] == '\t' || s[i] == '\n') { i++; }
        if i >= s.len { break; }
        var j = i;
        while j < s.len && s[j] != ' ' && s[j] != '|' && s[j] != '\t' && s[j] != '\n' { j++; }
        let w = s[i..j];
        let h, hok = hex_number(w, 8);
        if hok { v |= h as! u32; }
        else {
            let b, bok = mask_bit(tag, w);
            if !bok { return 0, false; }
            v |= b;
        }
        any = true;
        i = j;
    }
    return v, any;
}

// --- Numbers ----------------------------------------------------------------------

// A decimal integer in [lo, hi], with an optional sign; false for anything
// else (no spaces, no '+' on its own, no leading zeros rule: xsd allows them).
fn decimal(s: const u8[:], lo: i64, hi: i64) -> i64, bool {
    var i = 0;
    var neg = false;
    if s.len > 0 && (s[0] == '-' || s[0] == '+') { neg = s[0] == '-'; i = 1; }
    if i >= s.len { return 0, false; }
    var v: i64 = 0;
    while i < s.len {
        let c = s[i];
        if c < '0' || c > '9' { return 0, false; }
        let d: i64 = c - '0';
        // Build the number negative, where i64 has one more value.
        if v < (-9223372036854775807 - 1 + d) / 10 { return 0, false; }
        v = v * 10 - d;
        i++;
    }
    if !neg {
        if v == -9223372036854775807 - 1 { return 0, false; }
        v = -v;
    }
    if v < lo || v > hi { return 0, false; }
    return v, true;
}

// An Integer: decimal (xsd:int) or 0x and eight hex digits.
fn int_from_text(s: const u8[:]) -> i32, bool {
    let h, hok = hex_number(s, 8);
    if hok { return h as! u32 as! i32, true; }
    let v, ok = decimal(s, -2147483648, 2147483647);
    return v as! i32, ok;
}

// A Long Integer or Date-Time Extended: decimal (xsd:long) or 0x and
// sixteen hex digits.
fn long_from_text(s: const u8[:]) -> i64, bool {
    let h, hok = hex_number(s, 16);
    if hok { return h as! i64, true; }
    let v, ok = decimal(s, -9223372036854775807 - 1, 9223372036854775807);
    return v, ok;
}

// An Interval: decimal (xsd:unsignedInt) or 0x and eight hex digits.
fn interval_from_text(s: const u8[:]) -> u32, bool {
    let h, hok = hex_number(s, 8);
    if hok { return h as! u32, true; }
    let v, ok = decimal(s, 0, 4294967295);
    return v as! u32, ok;
}

// A Boolean: true, false, 1 or 0 (xsd:boolean), or 0x and sixteen hex
// digits holding 0 or 1.
fn bool_from_text(s: const u8[:]) -> bool, bool {
    if s == "true" || s == "1" { return true, true; }
    if s == "false" || s == "0" { return false, true; }
    let h, hok = hex_number(s, 16);
    if hok && h <= 1 { return h == 1, true; }
    return false, false;
}

// Hex digits, an even number of them, as bytes onto out.
fn hex_from_text(out: u8[>..]&, s: const u8[:]) -> bool {
    if s.len % 2 != 0 { return false; }
    var i = 0;
    while i < s.len {
        let a = hex_digit(s[i]);
        let b = hex_digit(s[i + 1]);
        if a < 0 || b < 0 { return false; }
        out.push((a * 16 + b) as! u8);
        i += 2;
    }
    return true;
}

fn hex_text(out: u8[>..]&, b: const u8[:]) {
    let digits = "0123456789abcdef";
    for c in b { out.push(digits[(c >> 4) as i64]); out.push(digits[(c & 15) as i64]); }
}

// A Big Integer's value from hex, with or without 0x: two's complement,
// big-endian, sign-extended to a multiple of 8 bytes when it is not one.
fn bigint_from_text(out: u8[>..]&, s: const u8[:]) -> bool {
    var t = s;
    if t.len >= 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X') { t = t[2..]; }
    if t.len == 0 { return false; }
    var digits: u8[>..] = [];
    if t.len % 2 != 0 {
        // An odd count: the top digit's sign extends into its byte.
        digits.push(if hex_digit(t[0]) >= 8 { 'f' } else { '0' });
    }
    digits.append(t);
    var v: u8[>..] = [];
    if !hex_from_text(v, digits) { return false; }
    let neg = v[0] & 0x80 != 0;
    for k in padded(v.len) - v.len { out.push(if neg { 0xFF } else { 0 }); }
    out.append(v);
    return true;
}

// --- Dates ------------------------------------------------------------------------

// Days since 1970-01-01 of a date in the proleptic Gregorian calendar.
fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

fn civil_from_days(z0: i64) -> i64, i64, i64 {
    let z = z0 + 719468;
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

fn floor_div(a: i64, b: i64) -> i64 {
    let q = a / b;
    if (a % b != 0) && ((a < 0) != (b < 0)) { return q - 1; }
    return q;
}

// Seconds since 1970 as xsd:dateTime in UTC: 2001-01-01T00:00:00+00:00;
// outside the years 1 to 9999, as 0x and sixteen hex digits.
fn datetime_text(out: u8[>..]&, secs: i64) {
    if secs < -62135596800 || secs > 253402300799 {
        out.append("0x");
        format_uint(out, secs as! u64, 16, 16, '0');
        return;
    }
    let days = floor_div(secs, 86400);
    let rem = secs - days * 86400;
    let y, m, d = civil_from_days(days);
    format_int(out, y, 10, 4, '0');
    out.push('-');
    format_int(out, m, 10, 2, '0');
    out.push('-');
    format_int(out, d, 10, 2, '0');
    out.push('T');
    format_int(out, rem / 3600, 10, 2, '0');
    out.push(':');
    format_int(out, rem / 60 % 60, 10, 2, '0');
    out.push(':');
    format_int(out, rem % 60, 10, 2, '0');
    out.append("+00:00");
}

fn digits_at(s: const u8[:], at: i64, n: i64) -> i64, bool {
    if at + n > s.len { return 0, false; }
    var v: i64 = 0;
    for k in n {
        let c = s[at + k];
        if c < '0' || c > '9' { return 0, false; }
        v = v * 10 + (c - '0');
    }
    return v, true;
}

fn days_in_month(y: i64, m: i64) -> i64 {
    if m == 2 {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        return if leap { 29 } else { 28 };
    }
    if m == 4 || m == 6 || m == 9 || m == 11 { return 30; }
    return 31;
}

// xsd:dateTime with its time zone, which KMIP requires ('Z' or ±hh:mm):
// '-'? yyyy '-' mm '-' dd 'T' hh ':' mm ':' ss ('.' s+)? zone. Fractions
// of a second are dropped, as the profiles say.
fn datetime_from_text(s: const u8[:]) -> i64, bool {
    var i = 0;
    var neg = false;
    if s.len > 0 && s[0] == '-' { neg = true; i = 1; }
    var j = i;
    while j < s.len && s[j] >= '0' && s[j] <= '9' { j++; }
    if j - i < 4 || j - i > 9 || (j - i > 4 && s[i] == '0') { return 0, false; }
    let y0, yok = digits_at(s, i, j - i);
    if !yok { return 0, false; }
    let y = if neg { -y0 } else { y0 };
    i = j;
    if i >= s.len || s[i] != '-' { return 0, false; }
    let mo, mok = digits_at(s, i + 1, 2);
    if !mok || i + 3 >= s.len || s[i + 3] != '-' { return 0, false; }
    let d, dok = digits_at(s, i + 4, 2);
    if !dok || i + 6 >= s.len || s[i + 6] != 'T' { return 0, false; }
    let hh, hok = digits_at(s, i + 7, 2);
    if !hok || i + 9 >= s.len || s[i + 9] != ':' { return 0, false; }
    let mi, miok = digits_at(s, i + 10, 2);
    if !miok || i + 12 >= s.len || s[i + 12] != ':' { return 0, false; }
    let ss, sok = digits_at(s, i + 13, 2);
    if !sok { return 0, false; }
    if mo < 1 || mo > 12 || d < 1 || d > days_in_month(y, mo) || hh > 23 || mi > 59 || ss > 59 { return 0, false; }
    i += 15;
    if i < s.len && s[i] == '.' {
        i++;
        let f = i;
        while i < s.len && s[i] >= '0' && s[i] <= '9' { i++; }
        if i == f { return 0, false; }
    }
    var off: i64 = 0;
    if i < s.len && s[i] == 'Z' { i++; }
    else if i < s.len && (s[i] == '+' || s[i] == '-') {
        let oh, ohok = digits_at(s, i + 1, 2);
        if !ohok || i + 3 >= s.len || s[i + 3] != ':' { return 0, false; }
        let om, omok = digits_at(s, i + 4, 2);
        if !omok || oh > 14 || om > 59 || (oh == 14 && om != 0) { return 0, false; }
        off = (oh * 60 + om) * 60;
        if s[i] == '-' { off = -off; }
        i += 6;
    } else {
        return 0, false;
    }
    if i != s.len { return 0, false; }
    return days_from_civil(y, mo, d) * 86400 + hh * 3600 + mi * 60 + ss - off, true;
}

// --- Values ------------------------------------------------------------------------

// Writes the item of the given tag and type whose value is the text s, as
// KMIP's XML writes values (and JSON its strings); ntag is the tag whose
// names an Enumeration or a mask takes (names_tag). ERR_MALFORMED for text
// that is no value of the type.
fn put_from_text(out: u8[>..]&, tag: u32, typ: u8, s: const u8[:], ntag: u32) -> i64 {
    if typ == INTEGER {
        if is_mask(ntag) {
            let m, ok = mask_from_text(ntag, s);
            if !ok { return ERR_MALFORMED; }
            put_int(out, tag, m as! i32);
            return OK;
        }
        let v, ok = int_from_text(s);
        if !ok { return ERR_MALFORMED; }
        put_int(out, tag, v);
        return OK;
    }
    if typ == LONG_INTEGER || typ == DATE_TIME_EXTENDED {
        let v, ok = long_from_text(s);
        if !ok { return ERR_MALFORMED; }
        if typ == LONG_INTEGER { put_long(out, tag, v); } else { put_datetime_ext(out, tag, v); }
        return OK;
    }
    if typ == BIG_INTEGER {
        var v: u8[>..] = [];
        if !bigint_from_text(v, s) { return ERR_MALFORMED; }
        put_head(out, tag, BIG_INTEGER, v.len);
        out.append(v);
        return OK;
    }
    if typ == ENUMERATION {
        let v, ok = enum_from_text(ntag, s);
        if !ok { return ERR_MALFORMED; }
        put_enum(out, tag, v);
        return OK;
    }
    if typ == BOOLEAN {
        let v, ok = bool_from_text(s);
        if !ok { return ERR_MALFORMED; }
        put_bool(out, tag, v);
        return OK;
    }
    if typ == TEXT_STRING {
        if !utf8_ok(s) { return ERR_UTF8; }
        put_text(out, tag, s);
        return OK;
    }
    if typ == BYTE_STRING {
        var v: u8[>..] = [];
        if !hex_from_text(v, s) { return ERR_MALFORMED; }
        put_bytes(out, tag, v);
        return OK;
    }
    if typ == DATE_TIME {
        let h, hok = hex_number(s, 16);
        if hok { put_datetime(out, tag, h as! i64); return OK; }
        let v, ok = datetime_from_text(s);
        if !ok { return ERR_MALFORMED; }
        put_datetime(out, tag, v);
        return OK;
    }
    if typ == INTERVAL {
        let v, ok = interval_from_text(s);
        if !ok { return ERR_MALFORMED; }
        put_interval(out, tag, v);
        return OK;
    }
    return ERR_TYPE;
}

// The text of an item's value as KMIP's XML writes it: decimal numbers, a
// Big Integer, a Byte String in hex without 0x, names for Enumerations and
// masks (sep between a mask's names), xsd:dateTime in UTC.
fn value_text(out: u8[>..]&, buf: const u8[:], doc: const Node[:], i: i64, ntag: u32, sep: u8) {
    let n = doc[i];
    if n.typ == INTEGER {
        let v, ok = as_int(buf, doc, i);
        if is_mask(ntag) { mask_text(out, ntag, v as! u32, sep); } else { format_int(out, v, 10, 0, ' '); }
    } else if n.typ == LONG_INTEGER {
        let v, ok = as_long(buf, doc, i);
        format_int(out, v, 10, 0, ' ');
    } else if n.typ == ENUMERATION {
        let v, ok = as_enum(buf, doc, i);
        enum_text(out, ntag, v);
    } else if n.typ == BOOLEAN {
        let v, ok = as_bool(buf, doc, i);
        out.append(if v { "true" } else { "false" });
    } else if n.typ == TEXT_STRING {
        out.append(value(buf, doc, i));
    } else if n.typ == DATE_TIME {
        let v, ok = as_datetime(buf, doc, i);
        datetime_text(out, v);
    } else if n.typ == INTERVAL {
        let v, ok = as_interval(buf, doc, i);
        format_uint(out, v, 10, 0, ' ');
    } else if n.typ == DATE_TIME_EXTENDED {
        format_int(out, binary::u64be(buf, n.off) as! i64, 10, 0, ' ');
    } else {
        hex_text(out, value(buf, doc, i));
    }
}

// The attribute an Attribute (KMIP 1.x's, or 2.0's vendor one) names in its
// Attribute Name, for the names of its Attribute Value; 0 if none.
fn attribute_of(buf: const u8[:], doc: const Node[:], i: i64) -> u32 {
    if doc[i].tag != TAG_ATTRIBUTE { return 0; }
    let name, ok = child_text(buf, doc, i, TAG_ATTRIBUTE_NAME);
    if !ok { return 0; }
    return attribute_tag(name);
}
