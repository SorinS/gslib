// ldap.filter: search filters in their string form (RFC 4515), compiled
// to the BER of §4.5.1.7 and back, as go-ldap's CompileFilter and
// DecompileFilter do: the same encodings and the same errors, except
// that a filter must close each parenthesis it opens where go-ldap
// assumes it does ("(!(a=b)x" and "(&(a=b)x" are refused here), and "!"
// takes a parenthesized filter. EscapeFilter too. And a compiled filter
// matched against an entry's attributes (filter_match, filter_matches),
// without a schema: attribute types compare without regard to case and
// options, values as caseIgnoreMatch (or, exact, octet by octet).

namespace ldap;

import std;
import net.ldap;
import encoding.asn1;

// Filter choices, the context tags of §4.5.1.
let FILTER_AND:              u32 = 0;
let FILTER_OR:               u32 = 1;
let FILTER_NOT:              u32 = 2;
let FILTER_EQUALITY:         u32 = 3;
let FILTER_SUBSTRINGS:       u32 = 4;
let FILTER_GREATER_OR_EQUAL: u32 = 5;
let FILTER_LESS_OR_EQUAL:    u32 = 6;
let FILTER_PRESENT:          u32 = 7;
let FILTER_APPROX:           u32 = 8;
let FILTER_EXTENSIBLE:       u32 = 9;

// How deep filters may nest.
let FILTER_MAX_DEPTH: i64 = 256;

// The width of the UTF-8 sequence at s[i], 0 where Go's decoder gives
// RuneError (malformed bytes, and U+FFFD itself, which go-ldap refuses).
fn rune_width(s: const u8[:], i: i64) -> i64 {
    let c = s[i];
    if c < 0x80 { return 1; }
    var n = 0;
    var cp:  u32 = 0;
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
    var nodes:  asn1::Tlv[>..] = [];
    var parent: i64[>..]       = [];
    var stack:  i64[>..]       = [];
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
    var kids:  i64[>..] = [];
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

// --- Matching ---------------------------------------------------------------------

// What a filter is for an entry (§4.5.1.7): TRUE, FALSE or Undefined,
// and MATCH_INVALID for a filter (or attribute list) that is not well
// formed, whatever the entry, where a server answers protocolError.
let MATCH_FALSE:     i64 = 0;
let MATCH_TRUE:      i64 = 1;
let MATCH_UNDEFINED: i64 = 2;
let MATCH_INVALID:   i64 = -1;

// How values compare, without a schema: caseIgnoreMatch's way (ASCII
// case folded, spaces as RFC 4518 §2.6.1 has them, simplified: none at
// either end, a run of them one), caseExactMatch's (the spaces alone),
// or octet by octet (octetStringMatch, and every value when matching
// is exact).
let RULE_CASE_IGNORE: i64 = 0;
let RULE_CASE_EXACT:  i64 = 1;
let RULE_OCTET:       i64 = 2;

// A matching rule by OID or name, -1 for one not known here.
fn matching_rule(r: const u8[:]) -> i64 {
    if r == "2.5.13.2" || equal_fold(r, "caseIgnoreMatch") { return RULE_CASE_IGNORE; }
    if r == "2.5.13.5" || equal_fold(r, "caseExactMatch") { return RULE_CASE_EXACT; }
    if r == "2.5.13.17" || equal_fold(r, "octetStringMatch") { return RULE_OCTET; }
    return -1;
}

// v as the rule compares it; lead and trail keep one space for spaces at
// that end (a substring piece's inner ends are significant).
fn prep_value(out: u8[>..]&, v: const u8[:], rule: i64, lead: bool = false, trail: bool = false) {
    if rule == RULE_OCTET { out.append(v); return; }
    var space = false;
    for c in v {
        if c == ' ' { space = true; continue; }
        if space && (out.len > 0 || lead) { out.push(' '); }
        space = false;
        out.push(if rule == RULE_CASE_IGNORE { lower(c) } else { c });
    }
    if space && trail { out.push(' '); }
}

fn compare_bytes(a: const u8[:], b: const u8[:]) -> i64 {
    let n = if a.len < b.len { a.len } else { b.len };
    for i in n {
        if a[i] != b[i] { return if a[i] < b[i] { -1 } else { 1 }; }
    }
    return if a.len < b.len { -1 } else if a.len > b.len { 1 } else { 0 };
}

// An attribute description without its options: cn;lang-en is cn.
fn description_type(d: const u8[:]) -> const u8[:] {
    let i = position(d, ';');
    return if i >= 0 { d[..i] } else { d };
}

// Whether attrs is attributes one after another, each a SEQUENCE of its
// description and SET of values.
fn attributes_ok(attrs: const u8[:]) -> bool {
    var p = 0;
    while p < attrs.len {
        let a, ok = asn1::read(attrs, p, attrs.len, true);
        if !ok || a.tag != asn1::SEQUENCE { return false; }
        let parts, okp = asn1::children(attrs, a, true);
        if !okp || parts.len != 2 || !octets_ok(parts[0]) || parts[1].tag != asn1::SET { return false; }
        let vals, okv = asn1::children(attrs, parts[1], true);
        if !okv { return false; }
        for v in vals { if !octets_ok(v) { return false; } }
        p = a.end;
    }
    return true;
}

// The values of the attributes the description d names, its type
// compared without regard to case and the options of both left out (all:
// every attribute's), and whether there was such an attribute.
fn values_of(attrs: const u8[:], d: const u8[:], all: bool) -> const u8[:][>..], bool {
    var out: const u8[:][>..] = [];
    var found = false;
    var p = 0;
    while p < attrs.len {
        let a, ok = asn1::read(attrs, p, attrs.len, true);
        p = a.end;
        let parts, okp = asn1::children(attrs, a, true);
        if !all && !equal_fold(description_type(bytes(attrs, parts[0])), description_type(d)) { continue; }
        found = true;
        let vals, okv = asn1::children(attrs, parts[1], true);
        for v in vals { out.push(bytes(attrs, v)); }
    }
    return out, found;
}

// An equality, ordering or approximate assertion of value a: TRUE if
// one of the values satisfies it, FALSE if none does, Undefined without
// the attribute. Approximate is equality (no phonetic rule here);
// ordering compares the prepared values byte by byte.
fn match_assertion(attrs: const u8[:], d: const u8[:], all: bool, n: u32, a: const u8[:], rule: i64) -> i64 {
    var pa: u8[>..] = [];
    prep_value(pa, a, rule);
    let vals, found = values_of(attrs, d, all);
    if !found { return MATCH_UNDEFINED; }
    for v in vals {
        var pv: u8[>..] = [];
        prep_value(pv, v, rule);
        let c = compare_bytes(pv, pa);
        if n == FILTER_GREATER_OR_EQUAL { if c >= 0 { return MATCH_TRUE; } }
        else if n == FILTER_LESS_OR_EQUAL { if c <= 0 { return MATCH_TRUE; } }
        else if c == 0 { return MATCH_TRUE; }
    }
    return MATCH_FALSE;
}

// Whether v holds the pieces in order, none overlapping another: initial
// [0] at the start, each any [1] at its first place after the piece
// before it, final [2] at the end.
fn substrings_hold(v: const u8[:], tags: const u32[:], pieces: const u8[:], ends: const i64[:]) -> bool {
    var pos = 0;
    var start = 0;
    for i in tags.len {
        let s = pieces[start..ends[i]];
        start = ends[i];
        if tags[i] == 0 {
            if !starts_with(v, s) { return false; }
            pos = s.len;
        } else if tags[i] == 1 {
            let k = find(v[pos..], s);
            if k < 0 { return false; }
            pos = pos + k + s.len;
        } else {
            if v.len - pos < s.len || !ends_with(v, s) { return false; }
            pos = v.len;
        }
    }
    return true;
}

fn match_substrings(buf: const u8[:], t: asn1::Tlv, attrs: const u8[:], rule: i64) -> i64 {
    let cs, ok = asn1::children(buf, t, true);
    if !ok || cs.len != 2 || !octets_ok(cs[0]) || cs[1].tag != asn1::SEQUENCE { return MATCH_INVALID; }
    let parts, okp = asn1::children(buf, cs[1], true);
    if !okp || parts.len == 0 { return MATCH_INVALID; }
    var tags:   u32[>..] = [];
    var pieces: u8[>..]  = [];
    var ends:   i64[>..] = [];
    for i in parts.len {
        let tag = parts[i].tag;
        // At most one initial, first, and one final, last.
        if tag != ctx_prim(0) && tag != ctx_prim(1) && tag != ctx_prim(2) { return MATCH_INVALID; }
        if (tag == ctx_prim(0) && i != 0) || (tag == ctx_prim(2) && i != parts.len - 1) { return MATCH_INVALID; }
        let k = parts[i].number;
        // A space at the value's own start or end is not significant.
        var pp: u8[>..] = [];
        prep_value(pp, bytes(buf, parts[i]), rule, k != 0, k != 2);
        pieces.append(pp);
        tags.push(k);
        ends.push(pieces.len);
    }
    let vals, found = values_of(attrs, bytes(buf, cs[0]), false);
    if !found { return MATCH_UNDEFINED; }
    for v in vals {
        var pv: u8[>..] = [];
        prep_value(pv, v, rule);
        if substrings_hold(pv, tags, pieces, ends) { return MATCH_TRUE; }
    }
    return MATCH_FALSE;
}

// An extensible match: by caseIgnoreMatch, caseExactMatch or
// octetStringMatch (by OID or name), or, without a rule, as equality of
// the type; without a type, against every attribute. dnAttributes and
// any other rule are Undefined.
fn match_extensible(buf: const u8[:], t: asn1::Tlv, attrs: const u8[:], rule: i64) -> i64 {
    let cs, ok = asn1::children(buf, t, true);
    if !ok { return MATCH_INVALID; }
    // The type and the value as Tlvs; an absent one is empty.
    var name = asn1::Tlv { tag: 0, cls: 0, constructed: false, number: 0, start: t.off, off: t.off, end: t.off };
    var value = name;
    var has_rule = false;
    var has_type = false;
    var has_value = false;
    var dn_attrs = false;
    var r = rule;
    for c in cs {
        if c.tag == ctx_prim(1) {
            has_rule = true;
            r = matching_rule(bytes(buf, c));
        } else if c.tag == ctx_prim(2) { name = c; has_type = true; }
        else if c.tag == ctx_prim(3) { value = c; has_value = true; }
        else if c.tag == ctx_prim(4) {
            let v, okb = asn1::read_bool(buf, c, true, ctx_prim(4));
            if !okb { return MATCH_INVALID; }
            dn_attrs = v;
        } else { return MATCH_INVALID; }
    }
    if !has_value || (!has_rule && !has_type) { return MATCH_INVALID; }
    if dn_attrs || r < 0 { return MATCH_UNDEFINED; }
    return match_assertion(attrs, bytes(buf, name), !has_type, FILTER_EQUALITY, bytes(buf, value), r);
}

// The filter t of buf for the entry's attributes.
recursive fn match_at(buf: const u8[:], t: asn1::Tlv, depth: i64, attrs: const u8[:], exact: bool) -> i64 {
    if depth > FILTER_MAX_DEPTH || t.cls != asn1::CLASS_CONTEXT { return MATCH_INVALID; }
    let n = t.number;
    let rule = if exact { RULE_OCTET } else { RULE_CASE_IGNORE };
    if n == FILTER_AND || n == FILTER_OR || n == FILTER_NOT {
        if !t.constructed { return MATCH_INVALID; }
        // Every term is read, so that a filter that is not well formed
        // is invalid whatever the entry.
        var trues = 0;
        var falses = 0;
        var undefined = 0;
        var p = t.off;
        while p < t.end {
            let c, ok = asn1::read(buf, p, t.end, true);
            if !ok { return MATCH_INVALID; }
            let r = match_at(buf, c, depth + 1, attrs, exact);
            if r == MATCH_INVALID { return r; }
            if r == MATCH_TRUE { trues++; } else if r == MATCH_FALSE { falses++; } else { undefined++; }
            p = c.end;
        }
        if n == FILTER_NOT && trues + falses + undefined != 1 { return MATCH_INVALID; }
        // An empty and is TRUE, an empty or FALSE (RFC 4526).
        if n == FILTER_NOT { return if trues > 0 { MATCH_FALSE } else if falses > 0 { MATCH_TRUE } else { MATCH_UNDEFINED }; }
        if n == FILTER_AND { return if falses > 0 { MATCH_FALSE } else if undefined > 0 { MATCH_UNDEFINED } else { MATCH_TRUE }; }
        return if trues > 0 { MATCH_TRUE } else if undefined > 0 { MATCH_UNDEFINED } else { MATCH_FALSE };
    }
    if n == FILTER_PRESENT {
        if t.constructed { return MATCH_INVALID; }
        let vals, found = values_of(attrs, bytes(buf, t), false);
        return if found { MATCH_TRUE } else { MATCH_FALSE };
    }
    if n == FILTER_SUBSTRINGS { return match_substrings(buf, t, attrs, rule); }
    if n == FILTER_EQUALITY || n == FILTER_GREATER_OR_EQUAL || n == FILTER_LESS_OR_EQUAL || n == FILTER_APPROX {
        let cs, ok = asn1::children(buf, t, true);
        if !ok || cs.len != 2 || !octets_ok(cs[0]) || !octets_ok(cs[1]) { return MATCH_INVALID; }
        return match_assertion(attrs, bytes(buf, cs[0]), false, n, bytes(buf, cs[1]), rule);
    }
    if n == FILTER_EXTENSIBLE { return match_extensible(buf, t, attrs, rule); }
    return MATCH_INVALID;
}

// What the compiled filter is for an entry's attributes: a
// SearchResultEntry's (entry_attributes) or an LDIF add record's
// (Record.body), each an attribute SEQUENCE after another. A filter from
// a decoded SearchRequest is its element, buf[t.start..t.end]. exact
// compares values octet by octet, not as caseIgnoreMatch.
fn filter_match(filter: const u8[:], attrs: const u8[:], exact: bool = false) -> i64 {
    let t, ok = asn1::parse(filter, true);
    if !ok || !attributes_ok(attrs) { return MATCH_INVALID; }
    return match_at(filter, t, 0, attrs, exact);
}

// Whether the entry matches: TRUE; Undefined is not a match (§4.5.1.7).
fn filter_matches(filter: const u8[:], attrs: const u8[:], exact: bool = false) -> bool {
    return filter_match(filter, attrs, exact) == MATCH_TRUE;
}

// A SearchResultEntry's attributes, as filter_match takes them.
fn entry_attributes(buf: const u8[:], m: const Message&) -> const u8[:] {
    if m.op != OP_SEARCH_ENTRY { return ""; }
    let cs, ok = asn1::children(buf, m.body, true);
    return if ok && cs.len == 2 { bytes(buf, cs[1]) } else { "" };
}

fn entry_matches(filter: const u8[:], buf: const u8[:], m: const Message&, exact: bool = false) -> bool {
    return m.op == OP_SEARCH_ENTRY && filter_matches(filter, entry_attributes(buf, m), exact);
}
