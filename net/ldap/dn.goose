// ldap.dn: distinguished names in their string form (RFC 4514), as
// go-ldap's ParseDN reads them: RDNs separated by ',' (or ';'), AVAs by
// '+', \-escapes of a special character or of two hex digits, '#' and
// hex for a BER value, spaces around types and values dropped unless
// escaped. Where go-ldap goes wrong this does not: an '=' inside a value
// is part of it ("cn=a=b" is cn "a=b"; go-ldap makes the type "a"), a
// last AVA with an empty value is kept, and a trailing ',' is refused.
// dn_string writes the DN as go-ldap's DN.String() does; dn_equal,
// dn_equal_fold and dn_ancestor_of compare as its Equal, EqualFold and
// AncestorOf (EqualFold folding ASCII only).

namespace ldap;

import std;
import net.ldap;
import encoding.asn1;

let DN_MAX_AVAS: i64 = 512;

// An AVA: its RDN's index and where its type and value are in Dn.data.
struct Ava { rdn: i64, type_off: i64, type_end: i64, value_off: i64, value_end: i64 }

// A parsed DN: its AVAs, RDN by RDN, and their bytes, unescaped.
struct Dn { rdns: i64, avas: Ava[..512], data: u8[>..] }

fn empty_dn() -> Dn { Dn { rdns: 0, avas: [], data: [] } }

fn ava_type(d: const Dn&, a: Ava) -> const u8[:] { d.data[a.type_off..a.type_end] }
fn ava_value(d: const Dn&, a: Ava) -> const u8[:] { d.data[a.value_off..a.value_end] }

fn dn_special(c: u8) -> bool {
    c == ' ' || c == '"' || c == '#' || c == '+' || c == ',' || c == ';' || c == '<' || c == '=' || c == '>' || c == '\\'
}

// Parses s into d; false, with err saying why, if it is not a DN.
fn parse_dn_into(s: const u8[:], d: Dn&, err: u8[>..]&) -> bool {
    d.rdns = 0;
    d.avas.clear();
    d.data.clear();
    var buf: u8[>..] = [];
    var trailing = 0;              // unescaped spaces at the end of buf
    var has_type = false;
    var typ: u8[>..] = [];
    var after_sep = false;
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '\\' {
            trailing = 0;
            if i + 1 >= s.len { err.append("got corrupted escaped character"); return false; }
            let e = s[i + 1];
            if dn_special(e) { buf.push(e); i += 2; continue; }
            if i + 2 >= s.len { err.append("got corrupted escaped character"); return false; }
            let h = hex_value(s[i + 1]);
            let l = hex_value(s[i + 2]);
            if h < 0 || l < 0 { err.append("failed to decode escaped character: encoding/hex: invalid byte"); return false; }
            buf.push((h * 16 + l) as! u8);
            i += 3;
            continue;
        }
        if c == '=' && !has_type {
            if buf.len - trailing == 0 { err.append("incomplete type, value pair"); return false; }
            typ.clear();
            typ.append(buf[..buf.len - trailing]);
            buf.clear();
            trailing = 0;
            has_type = true;
            i++;
            if i < s.len && s[i] == '#' {
                // A BER value in hex, to the next ',' or '+'.
                i++;
                var j = i;
                while j < s.len && s[j] != ',' && s[j] != '+' { j++; }
                var raw: u8[>..] = [];
                if (j - i) % 2 != 0 { err.append("failed to decode BER encoding: encoding/hex: odd length hex string"); return false; }
                var k = i;
                while k < j {
                    let h = hex_value(s[k]);
                    let l = hex_value(s[k + 1]);
                    if h < 0 || l < 0 { err.append("failed to decode BER encoding: encoding/hex: invalid byte"); return false; }
                    raw.push((h * 16 + l) as! u8);
                    k += 2;
                }
                let t, okt = asn1::parse(raw, true);
                if !okt { err.append("failed to decode BER packet"); return false; }
                buf.append(raw[t.off..t.end]);
                i = j;
            }
            continue;
        }
        if c == ',' || c == '+' || c == ';' {
            if !has_type { err.append("incomplete type, value pair"); return false; }
            if d.avas.len >= DN_MAX_AVAS { err.append("too many attributes in DN"); return false; }
            let to = d.data.len;
            d.data.append(typ);
            let vo = d.data.len;
            d.data.append(buf[..buf.len - trailing]);
            d.avas.push(Ava { rdn: d.rdns, type_off: to, type_end: vo, value_off: vo, value_end: d.data.len });
            if c != '+' { d.rdns++; }
            buf.clear();
            trailing = 0;
            has_type = false;
            after_sep = true;
            i++;
            continue;
        }
        if c == ' ' && buf.len == 0 { i++; continue; }
        if c == ' ' { trailing++; } else { trailing = 0; }
        buf.push(c);
        i++;
    }
    if has_type {
        if d.avas.len >= DN_MAX_AVAS { err.append("too many attributes in DN"); return false; }
        let to = d.data.len;
        d.data.append(typ);
        let vo = d.data.len;
        d.data.append(buf[..buf.len - trailing]);
        d.avas.push(Ava { rdn: d.rdns, type_off: to, type_end: vo, value_off: vo, value_end: d.data.len });
        d.rdns++;
    } else if buf.len > 0 || after_sep {
        err.append("DN ended with incomplete type, value pair");
        return false;
    }
    return true;
}

fn parse_dn(s: const u8[:]) -> Dn, bool {
    var d = empty_dn();
    var err: u8[>..] = [];
    let ok = parse_dn_into(s, d, err);
    return d, ok;
}

// Why s is not a DN, "" if it is one.
fn dn_error(s: const u8[:]) -> u8[>..] {
    var d = empty_dn();
    var err: u8[>..] = [];
    let ok = parse_dn_into(s, d, err);
    return err;
}

// A value escaped as go-ldap's AttributeTypeAndValue.String() escapes it:
// a leading space, '#' anywhere, a trailing space, " + , ; < > \ with a
// backslash, bytes outside ' '..'~' as \xx.
fn escape_dn_value_into(out: u8[>..]&, v: const u8[:]) {
    let digits = "0123456789abcdef";
    for i in v.len {
        let c = v[i];
        if (i == 0 && c == ' ') || c == '#' || (i == v.len - 1 && c == ' ') ||
           c == '"' || c == '+' || c == ',' || c == ';' || c == '<' || c == '>' || c == '\\' {
            out.push('\\');
            out.push(c);
        } else if c < ' ' || c > '~' {
            out.push('\\');
            out.push(digits[c >> 4]);
            out.push(digits[c & 15]);
        } else {
            out.push(c);
        }
    }
}

fn escape_dn_value(v: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    escape_dn_value_into(out, v);
    return out;
}

fn bytes_less(a: const u8[:], b: const u8[:]) -> bool {
    let n = if a.len < b.len { a.len } else { b.len };
    for i in n { if a[i] != b[i] { return a[i] < b[i]; } }
    return a.len < b.len;
}

// One AVA as "type=value", the type in lower case.
fn ava_string(d: const Dn&, a: Ava) -> u8[>..] {
    var out: u8[>..] = [];
    for c in ava_type(d, a) { out.push(lower(c)); }
    out.push('=');
    escape_dn_value_into(out, ava_value(d, a));
    return out;
}

// The DN as go-ldap's DN.String() writes it: each RDN's AVAs as strings,
// sorted, joined by '+'; the RDNs joined by ','.
fn dn_string(d: const Dn&) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    var r = 0;
    while i < d.avas.len {
        var j = i;
        while j < d.avas.len && d.avas[j].rdn == d.avas[i].rdn { j++; }
        var idx: i64[>..] = [];
        for k in i..j { idx.push(k); }
        // A few AVAs at most: sort their indices by string.
        sort(idx) { a, b => bytes_less(ava_string(d, d.avas[a]), ava_string(d, d.avas[b])) };
        if r > 0 { out.push(','); }
        for k in idx.len {
            if k > 0 { out.push('+'); }
            out.append(ava_string(d, d.avas[idx[k]]));
        }
        r++;
        i = j;
    }
    return out;
}

fn rdn_bounds(d: const Dn&, r: i64) -> i64, i64 {
    var i = 0;
    while i < d.avas.len && d.avas[i].rdn < r { i++; }
    var j = i;
    while j < d.avas.len && d.avas[j].rdn == r { j++; }
    return i, j;
}

fn ava_equal(a: const Dn&, x: Ava, b: const Dn&, y: Ava, fold: bool) -> bool {
    if !equal_fold(ava_type(a, x), ava_type(b, y)) { return false; }
    return if fold { equal_fold(ava_value(a, x), ava_value(b, y)) } else { ava_value(a, x) == ava_value(b, y) };
}

// RDN ra of a against RDN rb of b: the same AVAs, in any order.
fn rdn_equal(a: const Dn&, ra: i64, b: const Dn&, rb: i64, fold: bool) -> bool {
    let i0, i1 = rdn_bounds(a, ra);
    let j0, j1 = rdn_bounds(b, rb);
    if i1 - i0 != j1 - j0 { return false; }
    for i in i0..i1 {
        var found = false;
        for j in j0..j1 { if ava_equal(a, a.avas[i], b, b.avas[j], fold) { found = true; break; } }
        if !found { return false; }
    }
    for j in j0..j1 {
        var found = false;
        for i in i0..i1 { if ava_equal(a, a.avas[i], b, b.avas[j], fold) { found = true; break; } }
        if !found { return false; }
    }
    return true;
}

fn dn_equal_with(a: const Dn&, b: const Dn&, fold: bool) -> bool {
    if a.rdns != b.rdns { return false; }
    for r in a.rdns { if !rdn_equal(a, r, b, r, fold) { return false; } }
    return true;
}

// Types without regard to case, values exactly.
fn dn_equal(a: const Dn&, b: const Dn&) -> bool { dn_equal_with(a, b, false) }
fn dn_equal_fold(a: const Dn&, b: const Dn&) -> bool { dn_equal_with(a, b, true) }

// Whether a is above b: b ends with a's RDNs and has more.
fn dn_ancestor_with(a: const Dn&, b: const Dn&, fold: bool) -> bool {
    if a.rdns >= b.rdns { return false; }
    let skip = b.rdns - a.rdns;
    for r in a.rdns { if !rdn_equal(a, r, b, r + skip, fold) { return false; } }
    return true;
}

fn dn_ancestor_of(a: const Dn&, b: const Dn&) -> bool { dn_ancestor_with(a, b, false) }
fn dn_ancestor_of_fold(a: const Dn&, b: const Dn&) -> bool { dn_ancestor_with(a, b, true) }
