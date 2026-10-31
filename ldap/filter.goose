// ldap.filter: search filters in their string form (RFC 4515), compiled
// to the BER of §4.5.1.7 and back, as go-ldap's CompileFilter and
// DecompileFilter do: the same encodings and the same errors, except
// that a filter must close each parenthesis it opens where go-ldap
// assumes it does ("(!(a=b)x" and "(&(a=b)x" are refused here), and "!"
// takes a parenthesized filter. EscapeFilter too.

namespace ldap;

import std;
import ldap;
import asn1;

// Filter choices, the context tags of §4.5.1.
let FILTER_AND: u32 = 0;
let FILTER_OR: u32 = 1;
let FILTER_NOT: u32 = 2;
let FILTER_EQUALITY: u32 = 3;
let FILTER_SUBSTRINGS: u32 = 4;
let FILTER_GREATER_OR_EQUAL: u32 = 5;
let FILTER_LESS_OR_EQUAL: u32 = 6;
let FILTER_PRESENT: u32 = 7;
let FILTER_APPROX: u32 = 8;
let FILTER_EXTENSIBLE: u32 = 9;

// How deep filters may nest.
let FILTER_MAX_DEPTH: i64 = 256;

// The width of the UTF-8 sequence at s[i], 0 where Go's decoder gives
// RuneError (malformed bytes, and U+FFFD itself, which go-ldap refuses).
fn rune_width(s: const u8[:], i: i64) -> i64 {
    let c = s[i];
    if c < 0x80 { return 1; }
    var n = 0;
    var cp: u32 = 0;
    var min: u32 = 0;
    if c >= 0xc2 && c <= 0xdf { n = 2; cp = c & 0x1f; min = 0x80; }
    else if c >= 0xe0 && c <= 0xef { n = 3; cp = c & 0x0f; min = 0x800; }
    else if c >= 0xf0 && c <= 0xf4 { n = 4; cp = c & 0x07; min = 0x10000; }
    else { return 0; }
    if i + n > s.len { return 0; }
    for k in 1..n {
        let b = s[i + k];
        if b & 0xc0 != 0x80 { return 0; }
        cp = (cp << 6) | (b & 0x3f);
    }
    if cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) || cp == 0xfffd { return 0; }
    return n;
}

// A value with its \xx escapes decoded (go-ldap's decodeEscapedSymbols).
fn unescape_filter_value(src: const u8[:], out: u8[>..]&, err: u8[>..]&) -> bool {
    var i = 0;
    while i < src.len {
        let w = rune_width(src, i);
        if w == 0 { format(err, "ldap: error reading rune at position ", i); return false; }
        if src[i] == '\\' {
            if i + 3 > src.len { err.append("ldap: missing characters for escape in filter"); return false; }
            let h = hex_value(src[i + 1]);
            let l = hex_value(src[i + 2]);
            if h < 0 || l < 0 { err.append("ldap: invalid characters for escape in filter: encoding/hex: invalid byte"); return false; }
            out.push((h * 16 + l) as! u8);
            i += 3;
        } else {
            out.append(src[i..i + w]);
            i += w;
        }
    }
    return true;
}

// The placeholder header of a constructed filter: its tag and a length
// in four octets, filled in by close_set and made minimal by
// minimal_lengths.
fn open_set(out: u8[>..]&, tag: u32) -> i64 {
    let at = out.len;
    out.push(tag as! u8);
    out.push(0x84);
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    return at;
}

fn close_set(out: u8[>..]&, at: i64) {
    let n = out.len - at - 6;
    for i in 4 { out[at + 2 + i] = ((n >> (8 * (3 - i))) & 0xff) as! u8; }
}

// One filter item that is not a set, at pos, its ')' at the end: its BER
// into out and where it ends past the ')', or -1.
fn compile_item(f: const u8[:], pos: i64, out: u8[>..]&, err: u8[>..]&) -> i64 {
    // The attribute, the operator, the condition, read as go-ldap reads
    // them, up to the ')'.
    let READING_ATTR = 0;
    let READING_RULE = 1;
    let READING_CONDITION = 2;
    var state = READING_ATTR;
    var kind: i64 = -1;
    var dn_attrs = false;
    var attr: u8[>..] = [];
    var rule: u8[>..] = [];
    var cond: u8[>..] = [];
    var p = pos;
    while p < f.len {
        if f[p] == ')' { break; }
        let w = rune_width(f, p);
        if w == 0 { format(err, "ldap: error reading rune at position ", p); return -1; }
        let rest = f[p..];
        if state == READING_ATTR {
            if starts_with(rest, ":dn:=") { kind = FILTER_EXTENSIBLE; dn_attrs = true; state = READING_CONDITION; p += 5; }
            else if starts_with(rest, ":dn:") { kind = FILTER_EXTENSIBLE; dn_attrs = true; state = READING_RULE; p += 4; }
            else if starts_with(rest, ":=") { kind = FILTER_EXTENSIBLE; state = READING_CONDITION; p += 2; }
            else if rest[0] == ':' { kind = FILTER_EXTENSIBLE; state = READING_RULE; p += 1; }
            else if rest[0] == '=' { kind = FILTER_EQUALITY; state = READING_CONDITION; p += 1; }
            else if starts_with(rest, ">=") { kind = FILTER_GREATER_OR_EQUAL; state = READING_CONDITION; p += 2; }
            else if starts_with(rest, "<=") { kind = FILTER_LESS_OR_EQUAL; state = READING_CONDITION; p += 2; }
            else if starts_with(rest, "~=") { kind = FILTER_APPROX; state = READING_CONDITION; p += 2; }
            else { attr.append(rest[..w]); p += w; }
        } else if state == READING_RULE {
            if starts_with(rest, ":=") { state = READING_CONDITION; p += 2; }
            else { rule.append(rest[..w]); p += w; }
        } else {
            cond.append(rest[..w]);
            p += w;
        }
    }
    if p >= f.len { err.append("ldap: unexpected end of filter"); return -1; }
    if kind < 0 { err.append("ldap: error parsing filter"); return -1; }

    var body: u8[>..] = [];
    if kind == FILTER_EXTENSIBLE {
        if rule.len > 0 { asn1::put(body, ctx_prim(1), rule); }
        if attr.len > 0 { asn1::put(body, ctx_prim(2), attr); }
        var v: u8[>..] = [];
        if !unescape_filter_value(cond, v, err) { return -1; }
        asn1::put(body, ctx_prim(3), v);
        if dn_attrs { var t: u8[1] = [0xff]; asn1::put(body, ctx_prim(4), t); }
        asn1::put(out, ctx_cons(FILTER_EXTENSIBLE), body);
    } else if kind == FILTER_EQUALITY && cond == "*" {
        asn1::put(out, ctx_prim(FILTER_PRESENT), attr);
    } else if kind == FILTER_EQUALITY && position(cond, '*') >= 0 {
        asn1::put_octets(body, attr);
        var parts: u8[>..] = [];
        let pieces = split(cond, '*');
        for i in pieces.len {
            if pieces[i].len == 0 { continue; }
            let tag: u32 = if i == 0 { 0 } else if i == pieces.len - 1 { 2 } else { 1 };
            var v: u8[>..] = [];
            if !unescape_filter_value(pieces[i], v, err) { return -1; }
            asn1::put(parts, ctx_prim(tag), v);
        }
        asn1::put(body, asn1::SEQUENCE, parts);
        asn1::put(out, ctx_cons(FILTER_SUBSTRINGS), body);
    } else {
        var v: u8[>..] = [];
        if !unescape_filter_value(cond, v, err) { return -1; }
        asn1::put_octets(body, attr);
        asn1::put_octets(body, v);
        asn1::put(out, ctx_cons(kind as! u32), body);
    }
    return p + 1;
}

// The filter at pos (just past its '('): its BER into out (sets with
// placeholder lengths) and where it ends past its ')', or -1.
recursive fn compile_at(f: const u8[:], pos: i64, depth: i64, out: u8[>..]&, err: u8[>..]&) -> i64 {
    if depth > FILTER_MAX_DEPTH { err.append("ldap: filter nested too deeply"); return -1; }
    if pos >= f.len || rune_width(f, pos) == 0 {
        format(err, "ldap: error reading rune at position ", pos);
        return -1;
    }
    let c = f[pos];
    if c == '(' {
        let p = compile_at(f, pos + 1, depth + 1, out, err);
        if p < 0 { return -1; }
        if p >= f.len { err.append("ldap: unexpected end of filter"); return -1; }
        if f[p] != ')' { err.append("ldap: expected ')' in filter"); return -1; }
        return p + 1;
    }
    if c == '&' || c == '|' {
        let at = open_set(out, ctx_cons(if c == '&' { FILTER_AND } else { FILTER_OR }));
        var p = pos + 1;
        while p < f.len && f[p] == '(' {
            p = compile_at(f, p + 1, depth + 1, out, err);
            if p < 0 { return -1; }
        }
        if p >= f.len { err.append("ldap: unexpected end of filter"); return -1; }
        if f[p] != ')' { err.append("ldap: expected ')' in filter"); return -1; }
        close_set(out, at);
        return p + 1;
    }
    if c == '!' {
        if pos + 1 >= f.len { err.append("ldap: unexpected end of filter"); return -1; }
        if f[pos + 1] != '(' { err.append("ldap: expected '(' after '!' in filter"); return -1; }
        let at = open_set(out, ctx_cons(FILTER_NOT));
        let p = compile_at(f, pos + 2, depth + 1, out, err);
        if p < 0 { return -1; }
        if p >= f.len { err.append("ldap: unexpected end of filter"); return -1; }
        if f[p] != ')' { err.append("ldap: expected ')' in filter"); return -1; }
        close_set(out, at);
        return p + 1;
    }
    return compile_item(f, pos, out, err);
}

// The BER element b written again with every length in the fewest
// octets: the nodes in order, then their new lengths from the leaves up.
fn minimal_lengths(b: const u8[:], out: u8[>..]&) -> bool {
    var nodes: asn1::Tlv[>..] = [];
    var parent: i64[>..] = [];
    var stack: i64[>..] = [];
    let root, ok = asn1::parse(b, true);
    if !ok { return false; }
    nodes.push(root);
    parent.push(-1);
    var i = 0;
    while i < nodes.len {
        let t = nodes[i];
        if t.constructed {
            var p = t.off;
            while p < t.end {
                let ch, okc = asn1::read(b, p, t.end, true);
                if !okc { return false; }
                // A node's children land next to each other.
                nodes.push(ch);
                parent.push(i);
                p = ch.end;
            }
        }
        i++;
    }
    // nodes is in breadth-first order; lengths bottom-up (children come
    // after their parent).
    var len: i64[>..] = [];
    for t in nodes { len.push(if t.constructed { 0 } else { t.end - t.off }); }
    var k = nodes.len - 1;
    while k > 0 {
        let n = len[k];
        let hl = if n < 128 { 2 } else if n < 256 { 3 } else if n < 65536 { 4 } else if n < 1 << 24 { 5 } else { 6 };
        len[parent[k]] = len[parent[k]] + hl + n;
        k--;
    }
    // Written depth first: a stack of node indices, children pushed in reverse.
    var kids: i64[>..] = [];
    var first: i64[>..] = [];
    var count: i64[>..] = [];
    for t in nodes { first.push(-1); count.push(0); }
    for j in 1..nodes.len {
        if first[parent[j]] < 0 { first[parent[j]] = j; }
        count[parent[j]] = count[parent[j]] + 1;
    }
    stack.push(0);
    while stack.len > 0 {
        let j = stack.pop();
        let t = nodes[j];
        asn1::put_header(out, t.tag, len[j]);
        if !t.constructed {
            out.append(b[t.off..t.end]);
        } else {
            var c = count[j];
            while c > 0 { c--; stack.push(first[j] + c); }
        }
    }
    return true;
}

// A filter's BER into out; false, with err saying why, if it is not one.
fn compile_filter(f: const u8[:], out: u8[>..]&, err: u8[>..]&) -> bool {
    if f.len == 0 || f[0] != '(' { err.append("ldap: filter does not start with an '('"); return false; }
    var b: u8[>..] = [];
    let p = compile_at(f, 1, 0, b, err);
    if p < 0 { return false; }
    if p < f.len {
        format(err, "ldap: finished compiling filter with extra at end: ", f[p..]);
        return false;
    }
    return minimal_lengths(b, out);
}

fn compile(f: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    var err: u8[>..] = [];
    let ok = compile_filter(f, out, err);
    return out, ok;
}

// RFC 4515's escapes of the bytes a value cannot hold as they are:
// ( ) * \ NUL and every byte from 0x80 (go-ldap's EscapeFilter).
fn escape_filter_into(out: u8[>..]&, v: const u8[:]) {
    let digits = "0123456789abcdef";
    for c in v {
        if c > 0x7f || c == '(' || c == ')' || c == '\\' || c == '*' || c == 0 {
            out.push('\\');
            out.push(digits[c >> 4]);
            out.push(digits[c & 15]);
        } else {
            out.push(c);
        }
    }
}

fn escape_filter(v: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    escape_filter_into(out, v);
    return out;
}

// The string form of the filter t, as go-ldap's DecompileFilter writes it.
recursive fn decompile_at(buf: const u8[:], t: asn1::Tlv, depth: i64, out: u8[>..]&) -> bool {
    if depth > FILTER_MAX_DEPTH || t.cls != asn1::CLASS_CONTEXT { return false; }
    out.push('(');
    let n = t.number;
    if n == FILTER_AND || n == FILTER_OR || n == FILTER_NOT {
        if !t.constructed { return false; }
        out.push(if n == FILTER_AND { '&' } else if n == FILTER_OR { '|' } else { '!' });
        var p = t.off;
        var k = 0;
        while p < t.end {
            let ch, ok = asn1::read(buf, p, t.end, true);
            if !ok || !decompile_at(buf, ch, depth + 1, out) { return false; }
            p = ch.end;
            k++;
        }
        if n == FILTER_NOT && k != 1 { return false; }
    } else if n == FILTER_PRESENT {
        if t.constructed { return false; }
        out.append(bytes(buf, t));
        out.append("=*");
    } else if n == FILTER_SUBSTRINGS {
        let cs, ok = asn1::children(buf, t, true);
        if !ok || cs.len != 2 || !octets_ok(cs[0]) || cs[1].tag != asn1::SEQUENCE { return false; }
        let parts, okp = asn1::children(buf, cs[1], true);
        if !okp { return false; }
        out.append(bytes(buf, cs[0]));
        out.push('=');
        for i in parts.len {
            let tag = parts[i].tag;
            if tag != ctx_prim(0) && tag != ctx_prim(1) && tag != ctx_prim(2) { return false; }
            if i == 0 && tag != ctx_prim(0) { out.push('*'); }
            escape_filter_into(out, bytes(buf, parts[i]));
            if tag != ctx_prim(2) { out.push('*'); }
        }
    } else if n == FILTER_EQUALITY || n == FILTER_GREATER_OR_EQUAL || n == FILTER_LESS_OR_EQUAL || n == FILTER_APPROX {
        let cs, ok = asn1::children(buf, t, true);
        if !ok || cs.len != 2 || !octets_ok(cs[0]) || !octets_ok(cs[1]) { return false; }
        out.append(bytes(buf, cs[0]));
        out.append(if n == FILTER_EQUALITY { "=" } else if n == FILTER_GREATER_OR_EQUAL { ">=" } else if n == FILTER_LESS_OR_EQUAL { "<=" } else { "~=" });
        escape_filter_into(out, bytes(buf, cs[1]));
    } else if n == FILTER_EXTENSIBLE {
        let cs, ok = asn1::children(buf, t, true);
        if !ok { return false; }
        // Each part as a Tlv; an absent one is empty.
        var rule = asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: t.off, off: t.off, end: t.off };
        var attr = rule;
        var value = rule;
        var dn_attrs = false;
        for c in cs {
            if c.tag == ctx_prim(1) { rule = c; }
            else if c.tag == ctx_prim(2) { attr = c; }
            else if c.tag == ctx_prim(3) { value = c; }
            else if c.tag == ctx_prim(4) {
                let v, okb = asn1::read_bool(buf, c, true, ctx_prim(4));
                if !okb { return false; }
                dn_attrs = v;
            } else { return false; }
        }
        out.append(bytes(buf, attr));
        if dn_attrs { out.append(":dn"); }
        if asn1::content_len(rule) > 0 { out.push(':'); out.append(bytes(buf, rule)); }
        out.append(":=");
        escape_filter_into(out, bytes(buf, value));
    } else {
        return false;
    }
    out.push(')');
    return true;
}

// A compiled filter's string form; false if ber is not one filter.
fn decompile_filter(ber: const u8[:], out: u8[>..]&) -> bool {
    let t, ok = asn1::parse(ber, true);
    if !ok { return false; }
    var s: u8[>..] = [];
    if !decompile_at(ber, t, 0, s) { return false; }
    out.append(s);
    return true;
}

fn decompile(ber: const u8[:]) -> u8[>..], bool {
    var out: u8[>..] = [];
    let ok = decompile_filter(ber, out);
    return out, ok;
}
