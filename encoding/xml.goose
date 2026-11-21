// XML 1.0 (fifth edition) with Namespaces 1.0 (docs in xml/README.md): a
// parser into a document of numbered nodes, its accessors, a builder, and
// a writer. The parser is made for documents that carry signatures and
// come from strangers: there is no DTD processing at all, so no entity is
// ever declared, expanded or fetched (no XXE, no billion laughs); a
// DOCTYPE is refused unless Options.allow_doctype, and then only one
// without an internal subset is let through, and ignored. Only the five
// predefined entities and character references are read. Depth, attributes
// per element, names, nodes and the whole input have limits, and going
// over one is an error, never a cut. Well-formedness is checked in full:
// one root, matched tags, legal characters and UTF-8, names, unique
// attributes (also by namespace and local name, so p:a and q:a of one
// namespace are refused), namespace prefixes bound, the reserved
// prefixes. Line ends and attribute values are normalized as the spec
// says. Attributes named by Options.id_attrs (ID, Id and id unprefixed,
// by default) and xml:id are IDs, and an ID value repeated in a document
// is an error, so a lookup by ID (by_id) finds one element or none.
//
// xml.c14n canonicalizes (Canonical XML 1.0 and 1.1, Exclusive XML
// Canonicalization 1.0), xml.dsig signs and verifies (XML Signature 1.1),
// and xml.enc encrypts and decrypts (XML Encryption 1.1).

namespace xml;

import std;
import dictionary;
import base64;

// --- the document ---------------------------------------------------------------

// Node kinds.
let DOCUMENT:  u8 = 1;
let ELEMENT:   u8 = 2;
let ATTRIBUTE: u8 = 3;
let NAMESPACE: u8 = 4;   // a namespace declaration, xmlns or xmlns:p
let TEXT:      u8 = 5;
let CDATA:     u8 = 6;
let COMMENT:   u8 = 7;
let PI:        u8 = 8;

let XML_NS:   const u8[:] = "http://www.w3.org/XML/1998/namespace";
let XMLNS_NS: const u8[:] = "http://www.w3.org/2000/xmlns/";

// Bytes at..at+len of the document's text.
struct Span { at: i64 = 0, len: i64 = 0 }

// A node, by its index in Doc.nodes; links are indices, -1 for none. The
// document is node 0. An element's children are first..last by next, and
// its attributes and namespace declarations, in the order written, are a
// chain from attrs by next. Names and values are spans of Doc.text:
//   ELEMENT    prefix, local, ns (the namespace URI; empty: none)
//   ATTRIBUTE  prefix, local, ns, value; is_id for an ID
//   NAMESPACE  local: the prefix declared (empty for xmlns), value: the URI
//   TEXT, CDATA, COMMENT  value
//   PI         local: the target, value: the data
struct Node {
    kind:   u8,
    is_id:  bool = false,
    parent: i64  = -1,
    first:  i64  = -1,
    last:   i64  = -1,
    next:   i64  = -1,
    prev:   i64  = -1,
    attrs:  i64  = -1,
    prefix: Span = Span { .. },
    local:  Span = Span { .. },
    ns:     Span = Span { .. },
    value:  Span = Span { .. },
}

// A document: its nodes and the text they point into. Make one with
// `var d = xml::Doc { .. };` and fill it with parse or new_document.
root struct Doc {
    nodes:  Node[>..] = [],
    text:   u8[>..]   = [],
    xml_ns: Span      = Span { .. },
}

// --- errors -------------------------------------------------------------------

let OK:            i64 = 0;
let ERR_SYNTAX:    i64 = 1;      // not well-formed
let ERR_CHAR:      i64 = 2;      // a character XML does not allow, or bad UTF-8
let ERR_ENCODING:  i64 = 3;      // not UTF-8 (a UTF-16 BOM, another encoding declared)
let ERR_DOCTYPE:   i64 = 4;      // a DOCTYPE, refused
let ERR_ENTITY:    i64 = 5;      // a reference to an entity other than the five predefined
let ERR_TAG:       i64 = 6;      // an end tag that does not match its start tag
let ERR_DUP_ATTR:  i64 = 7;      // an attribute twice (by name, or namespace and local name)
let ERR_NAMESPACE: i64 = 8;      // an unbound prefix, a reserved one misused, xmlns:p=""
let ERR_DUP_ID:    i64 = 9;      // an ID value twice in the document
let ERR_LIMIT:     i64 = 10;     // over a limit of Options
let ERR_ARG:       i64 = 11;     // a builder's argument that XML cannot hold

fn error_name(code: i64) -> const u8[:] {
    if code == OK { return "ok"; }
    if code == ERR_SYNTAX { return "syntax"; }
    if code == ERR_CHAR { return "character"; }
    if code == ERR_ENCODING { return "encoding"; }
    if code == ERR_DOCTYPE { return "doctype"; }
    if code == ERR_ENTITY { return "entity"; }
    if code == ERR_TAG { return "tag"; }
    if code == ERR_DUP_ATTR { return "duplicate attribute"; }
    if code == ERR_NAMESPACE { return "namespace"; }
    if code == ERR_DUP_ID { return "duplicate ID"; }
    if code == ERR_LIMIT { return "limit"; }
    if code == ERR_ARG { return "argument"; }
    return "unknown";
}

// What went wrong and where: the byte offset, and line and column from 1.
struct Error { code: i64 = 0, offset: i64 = 0, line: i64 = 0, column: i64 = 0, message: u8[>..] }

fn ok(e: const Error&) -> bool { e.code == OK }

// The parser's limits and choices.
struct Options {
    max_size:       i64  = 16 << 20, // bytes of input
    max_depth:      i64  = 256,      // elements open at once
    max_attrs:      i64  = 64,       // attributes and namespace declarations of an element
    max_name:       i64  = 1024,     // bytes of a name
    max_nodes:      i64  = 1 << 20,  // nodes, attributes included
    max_namespaces: i64  = 256,      // namespace declarations in scope at once, hidden ones included
    allow_doctype:  bool = false,    // let a DOCTYPE without an internal subset through (ignored)
    unique_ids:     bool = true,     // refuse an ID value seen twice
    // The unprefixed attribute names that are IDs, besides xml:id,
    // separated by single spaces.
    id_attrs: u8[..256] = "ID Id id",
}

fn options() -> Options { Options { .. } }

// --- characters ---------------------------------------------------------------

// The code point at s[i] and its length in bytes; -1 and 1 for bytes that
// are not UTF-8 (overlong, a surrogate, past U+10FFFF, cut short).
fn decode(s: const u8[:], i: i64) -> i64, i64 {
    let c: i64 = s[i];
    if c < 0x80 { return c, 1; }
    let n = s.len - i;
    if c >= 0xC2 && c <= 0xDF {
        if n < 2 { return -1, 1; }
        let c1: i64 = s[i + 1];
        if (c1 & 0xC0) != 0x80 { return -1, 1; }
        return ((c & 0x1F) << 6) | (c1 & 0x3F), 2;
    }
    if c >= 0xE0 && c <= 0xEF {
        if n < 3 { return -1, 1; }
        let c1: i64 = s[i + 1];
        let c2: i64 = s[i + 2];
        if (c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 { return -1, 1; }
        if c == 0xE0 && c1 < 0xA0 { return -1, 1; }
        if c == 0xED && c1 > 0x9F { return -1, 1; }
        return ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F), 3;
    }
    if c >= 0xF0 && c <= 0xF4 {
        if n < 4 { return -1, 1; }
        let c1: i64 = s[i + 1];
        let c2: i64 = s[i + 2];
        let c3: i64 = s[i + 3];
        if (c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80 { return -1, 1; }
        if c == 0xF0 && c1 < 0x90 { return -1, 1; }
        if c == 0xF4 && c1 > 0x8F { return -1, 1; }
        return ((c & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F), 4;
    }
    return -1, 1;
}

// Char (XML 1.0 §2.2).
fn is_char(c: i64) -> bool {
    if c >= 0x20 { return c <= 0xD7FF || (c >= 0xE000 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0x10FFFF); }
    return c == 0x9 || c == 0xA || c == 0xD;
}

fn is_space(c: i64) -> bool { c == 0x20 || c == 0x9 || c == 0xA || c == 0xD }

// Whether s has white space: then it is not a URI reference, so not a
// namespace name (Namespaces in XML §2.2, RFC 3986; libxml2 refuses it too).
fn has_space(s: const u8[:]) -> bool {
    for c in s { if is_space(c) { return true; } }
    return false;
}

// NameStartChar and NameChar (§2.3), the colon left to the caller.
fn is_name_start(c: i64) -> bool {
    if c < 0x80 { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':'; }
    return (c >= 0xC0 && c <= 0xD6) || (c >= 0xD8 && c <= 0xF6) || (c >= 0xF8 && c <= 0x2FF)
        || (c >= 0x370 && c <= 0x37D) || (c >= 0x37F && c <= 0x1FFF) || (c >= 0x200C && c <= 0x200D)
        || (c >= 0x2070 && c <= 0x218F) || (c >= 0x2C00 && c <= 0x2FEF) || (c >= 0x3001 && c <= 0xD7FF)
        || (c >= 0xF900 && c <= 0xFDCF) || (c >= 0xFDF0 && c <= 0xFFFD) || (c >= 0x10000 && c <= 0xEFFFF);
}

fn is_name_char(c: i64) -> bool {
    if is_name_start(c) { return true; }
    if c < 0x80 { return (c >= '0' && c <= '9') || c == '-' || c == '.'; }
    return c == 0xB7 || (c >= 0x300 && c <= 0x36F) || (c >= 0x203F && c <= 0x2040);
}

// Whether s is a Name; with no_colon, an NCName.
fn is_name(s: const u8[:], no_colon: bool) -> bool {
    if s.len == 0 { return false; }
    var i = 0;
    var first = true;
    while i < s.len {
        let c, w = decode(s, i);
        if c < 0 { return false; }
        if no_colon && c == ':' { return false; }
        if first { if !is_name_start(c) { return false; } }
        else if !is_name_char(c) { return false; }
        first = false;
        i += w;
    }
    return true;
}

fn is_ncname(s: const u8[:]) -> bool { is_name(s, true) }

// Whether s is a QName: an NCName, or two joined by one colon.
fn is_qname(s: const u8[:]) -> bool {
    let c = find(s, ":");
    if c < 0 { return is_ncname(s); }
    return is_ncname(s[..c]) && is_ncname(s[c + 1..]);
}

// Whether every character of s is a Char, in valid UTF-8.
fn is_text(s: const u8[:]) -> bool {
    var i = 0;
    while i < s.len {
        let c, w = decode(s, i);
        if c < 0 || !is_char(c) { return false; }
        i += w;
    }
    return true;
}

// --- the document's text and nodes --------------------------------------------

fn view(d: const Doc&, s: Span) -> const u8[:] {
    let a = s.at;
    let b = s.at + s.len;
    return d.text[a..b];
}

fn put(d: Doc&, s: const u8[:]) -> Span {
    let at = d.text.len;
    d.text.append(s);
    return Span { at: at, len: s.len };
}

fn add_node(d: Doc&, n: Node) -> i64 {
    d.nodes.push(n);
    return d.nodes.len - 1;
}

// Links n as the last child of parent.
fn link_last(d: Doc&, parent: i64, n: i64) {
    let l = d.nodes[parent].last;
    d.nodes[n].parent = parent;
    d.nodes[n].prev = l;
    d.nodes[n].next = -1;
    if l >= 0 { d.nodes[l].next = n; } else { d.nodes[parent].first = n; }
    d.nodes[parent].last = n;
}

// Links n into parent's children before `before` (-1: last).
fn link_before(d: Doc&, parent: i64, n: i64, before: i64) {
    if before < 0 { link_last(d, parent, n); return; }
    let p = d.nodes[before].prev;
    d.nodes[n].parent = parent;
    d.nodes[n].next = before;
    d.nodes[n].prev = p;
    d.nodes[before].prev = n;
    if p >= 0 { d.nodes[p].next = n; } else { d.nodes[parent].first = n; }
}

// Links attribute or declaration a last in el's chain.
fn link_attr(d: Doc&, el: i64, a: i64) {
    d.nodes[a].parent = el;
    var c = d.nodes[el].attrs;
    if c < 0 { d.nodes[el].attrs = a; return; }
    while d.nodes[c].next >= 0 { c = d.nodes[c].next; }
    d.nodes[c].next = a;
    d.nodes[a].prev = c;
}

// --- the parser -------------------------------------------------------------------

// An attribute as written: its name in the input, and its value.
struct RawAttr { from: i64, to: i64, value: Span }

// A namespace binding in scope: the prefix and URI, and the binding of the
// same prefix it hides (-1: none).
struct Binding { prefix: Span, uri: Span, prev: i64 }

struct Parser {
    s:        const u8[:],
    pos:      i64 = 0,
    nodes0:   i64 = 0,
    text0:    i64 = 0,
    d:        Doc&,
    o:        const Options&,
    raw:      RawAttr[>..<]&,
    bindings: Binding[>..<]&,
    scope:    dictionary<const u8[:], i64>&,
    ids:      dictionary<const u8[:], i64>&,
}

fn line_col(s: const u8[:], pos: i64) -> i64, i64 {
    var line = 1;
    var col = 1;
    var i = 0;
    let end = ::min(pos, s.len);
    while i < end {
        if s[i] == '\n' { line++; col = 1; } else if (s[i] & 0xC0) != 0x80 { col++; }
        i++;
    }
    return line, col;
}

// The functions that take the Parser are generic over it (as yaml's are):
// goose checks a plain function no call reaches on its own, and one that
// reaches fail_at's return from parse_core that way has no parse_core to
// return from. A program that declares xml but parses nothing (kmip's
// tests, say) would not compile.
fn fail_at(s: const u8[:], at: i64, code: i64, msg: const u8[:]) {
    let line, col = line_col(s, at);
    return Error { code: code, offset: at, line: line, column: col,
                   message: str("xml: line ", line, " column ", col, ": ", msg) } from parse_core;
}

fn fail<P>(p: P&, code: i64, msg: const u8[:]) { fail_at(p.s, p.pos, code, msg); }

fn at_end<P>(p: const P&) -> bool { p.pos >= p.s.len }

fn peek<P>(p: const P&, k: i64) -> i64 { if p.pos + k < p.s.len { p.s[p.pos + k] } else { -1 } }

fn looking_at<P>(p: const P&, w: const u8[:]) -> bool {
    p.pos + w.len <= p.s.len && p.s[p.pos..p.pos + w.len] == w
}

fn expect<P>(p: P&, w: const u8[:]) {
    if !looking_at(p, w) { fail(p, ERR_SYNTAX, str("expected ", w)); }
    p.pos += w.len;
}

// Skips white space; whether there was some.
fn skip_space<P>(p: P&) -> bool {
    let start = p.pos;
    while p.pos < p.s.len && is_space(p.s[p.pos]) { p.pos++; }
    return p.pos > start;
}

// One character, checked: the code point and its width.
fn next_char<P>(p: P&) -> i64, i64 {
    let c, w = decode(p.s, p.pos);
    if c < 0 { fail(p, ERR_CHAR, "not UTF-8"); }
    if !is_char(c) { fail(p, ERR_CHAR, str("character U+", hex_of(c), " not allowed")); }
    return c, w;
}

fn hex_of(c: i64) -> u8[>..] {
    var out: u8[>..] = [];
    format_int(out, c, 16, 4, '0');
    to_upper(out);
    return out;
}

// A Name at the cursor: its bytes in the input.
fn read_name<P>(p: P&) -> i64, i64 {
    let start = p.pos;
    var first = true;
    while p.pos < p.s.len {
        let c, w = decode(p.s, p.pos);
        if c < 0 { fail(p, ERR_CHAR, "not UTF-8"); }
        if first { if !is_name_start(c) { break; } }
        else if !is_name_char(c) { break; }
        first = false;
        p.pos += w;
        if p.pos - start > p.o.max_name { fail_at(p.s, start, ERR_LIMIT, "name too long"); }
    }
    if p.pos == start { fail(p, ERR_SYNTAX, "expected a name"); }
    return start, p.pos;
}

fn check_size<P>(p: P&) {
    if p.d.text.len - p.text0 > p.o.max_size + p.o.max_size { fail(p, ERR_LIMIT, "document too large"); }
}

fn new_node<P>(p: P&, n: Node) -> i64 {
    if p.d.nodes.len - p.nodes0 >= p.o.max_nodes { fail(p, ERR_LIMIT, "too many nodes"); }
    return add_node(p.d, n);
}

// A character or entity reference at '&', appended to the text: the
// predefined five and &#N; and &#xN; of a Char.
fn read_reference<P>(p: P&) {
    let start = p.pos;
    p.pos++;
    if peek(p, 0) == '#' {
        p.pos++;
        var base = 10;
        if peek(p, 0) == 'x' { base = 16; p.pos++; }
        var v = 0;
        var digits = 0;
        while p.pos < p.s.len && p.s[p.pos] != ';' {
            let h = ascii::hex_value(p.s[p.pos]);
            if h < 0 || (base == 10 && h > 9) { fail_at(p.s, start, ERR_SYNTAX, "bad character reference"); }
            v = v * base + h;
            if v > 0x10FFFF { fail_at(p.s, start, ERR_CHAR, "character reference out of range"); }
            digits++;
            p.pos++;
        }
        if at_end(p) || digits == 0 { fail_at(p.s, start, ERR_SYNTAX, "bad character reference"); }
        p.pos++;
        if !is_char(v) { fail_at(p.s, start, ERR_CHAR, "character reference to a character not allowed"); }
        push_utf8(p.d.text, v);
        return;
    }
    let ns, ne = read_name(p);
    let name = p.s[ns..ne];
    if peek(p, 0) != ';' { fail(p, ERR_SYNTAX, "expected ; after an entity name"); }
    p.pos++;
    if name == "lt" { p.d.text.push('<'); }
    else if name == "gt" { p.d.text.push('>'); }
    else if name == "amp" { p.d.text.push('&'); }
    else if name == "apos" { p.d.text.push('\''); }
    else if name == "quot" { p.d.text.push('"'); }
    else { fail_at(p.s, start, ERR_ENTITY, str("undeclared entity &", name, ";")); }
}

// An attribute value at its quote, normalized (§3.3.3, every attribute
// CDATA since there is no DTD), into the text.
fn read_att_value<P>(p: P&) -> Span {
    let q = peek(p, 0);
    if q != '"' && q != '\'' { fail(p, ERR_SYNTAX, "expected a quoted attribute value"); }
    p.pos++;
    let at = p.d.text.len;
    loop {
        if at_end(p) { fail(p, ERR_SYNTAX, "attribute value not closed"); }
        let b: i64 = p.s[p.pos];
        if b == q { p.pos++; break; }
        if b == '<' { fail(p, ERR_SYNTAX, "< in an attribute value"); }
        if b == '&' { read_reference(p); continue; }
        if b == '\r' {
            p.d.text.push(' ');
            p.pos++;
            if peek(p, 0) == '\n' { p.pos++; }
            continue;
        }
        if b == '\n' || b == '\t' { p.d.text.push(' '); p.pos++; continue; }
        let c, w = next_char(p);
        p.d.text.append(p.s[p.pos..p.pos + w]);
        p.pos += w;
    }
    check_size(p);
    return Span { at: at, len: p.d.text.len - at };
}

// The XML declaration, at "<?xml ".
fn read_xml_decl<P>(p: P&) {
    p.pos += 5;
    var seen = 0;
    loop {
        let sp = skip_space(p);
        if looking_at(p, "?>") { p.pos += 2; break; }
        if !sp { fail(p, ERR_SYNTAX, "malformed XML declaration"); }
        let ns, ne = read_name(p);
        let name = p.s[ns..ne];
        skip_space(p);
        expect(p, "=");
        skip_space(p);
        let q = peek(p, 0);
        if q != '"' && q != '\'' { fail(p, ERR_SYNTAX, "malformed XML declaration"); }
        p.pos++;
        let vs = p.pos;
        while p.pos < p.s.len && p.s[p.pos] != q && p.s[p.pos] != '<' && p.s[p.pos] != '>' { p.pos++; }
        if peek(p, 0) != q { fail(p, ERR_SYNTAX, "malformed XML declaration"); }
        let v = p.s[vs..p.pos];
        p.pos++;
        if name == "version" && seen == 0 {
            if v != "1.0" { fail_at(p.s, vs, ERR_SYNTAX, str("XML version ", v, " not supported")); }
            seen = 1;
        } else if name == "encoding" && seen == 1 {
            var lower: u8[>..] = [];
            lower.append(v);
            to_lower(lower);
            if lower != "utf-8" && lower != "utf8" && lower != "us-ascii" && lower != "ascii" {
                fail_at(p.s, vs, ERR_ENCODING, str("encoding ", v, " not supported (UTF-8 only)"));
            }
            if lower == "us-ascii" || lower == "ascii" {
                for i in p.s.len { if p.s[i] >= 0x80 { fail_at(p.s, i, ERR_ENCODING, "a byte over 0x7F in a document declared US-ASCII"); } }
            }
            seen = 2;
        } else if name == "standalone" && seen >= 1 && seen < 3 {
            if v != "yes" && v != "no" { fail_at(p.s, vs, ERR_SYNTAX, "standalone must be yes or no"); }
            seen = 3;
        } else {
            fail_at(p.s, ns, ERR_SYNTAX, "malformed XML declaration");
        }
    }
    if seen == 0 { fail(p, ERR_SYNTAX, "XML declaration without a version"); }
}

// A DOCTYPE, at "<!DOCTYPE": refused, unless allowed and without an
// internal subset, when it is passed over.
fn read_doctype<P>(p: P&) {
    if !p.o.allow_doctype { fail(p, ERR_DOCTYPE, "DOCTYPE not allowed"); }
    p.pos += 9;
    if !skip_space(p) { fail(p, ERR_SYNTAX, "malformed DOCTYPE"); }
    read_name(p);
    skip_space(p);
    if looking_at(p, "SYSTEM") || looking_at(p, "PUBLIC") {
        let public = looking_at(p, "PUBLIC");
        p.pos += 6;
        var lits = if public { 2 } else { 1 };
        while lits > 0 {
            if !skip_space(p) { fail(p, ERR_SYNTAX, "malformed DOCTYPE"); }
            let q = peek(p, 0);
            if q != '"' && q != '\'' { fail(p, ERR_SYNTAX, "malformed DOCTYPE"); }
            p.pos++;
            while p.pos < p.s.len && p.s[p.pos] != q { let c, w = next_char(p); p.pos += w; }
            if at_end(p) { fail(p, ERR_SYNTAX, "malformed DOCTYPE"); }
            p.pos++;
            lits--;
        }
        skip_space(p);
    }
    if peek(p, 0) == '[' { fail(p, ERR_DOCTYPE, "DOCTYPE with an internal subset not allowed"); }
    expect(p, ">");
}

// A comment, at "<!--".
fn read_comment<P>(p: P&, parent: i64) {
    p.pos += 4;
    let at = p.d.text.len;
    loop {
        if at_end(p) { fail(p, ERR_SYNTAX, "comment not closed"); }
        if looking_at(p, "--") {
            if !looking_at(p, "-->") { fail(p, ERR_SYNTAX, "-- in a comment"); }
            p.pos += 3;
            break;
        }
        copy_char(p);
    }
    check_size(p);
    let n = new_node(p, Node { kind: COMMENT, value: Span { at: at, len: p.d.text.len - at }, .. });
    link_last(p.d, parent, n);
}

// One character of the input to the text, a line end normalized.
fn copy_char<P>(p: P&) {
    let b = p.s[p.pos];
    if b == '\r' {
        p.d.text.push('\n');
        p.pos++;
        if peek(p, 0) == '\n' { p.pos++; }
        return;
    }
    if b >= 0x20 && b < 0x80 || b == '\n' || b == '\t' { p.d.text.push(b); p.pos++; return; }
    let c, w = next_char(p);
    p.d.text.append(p.s[p.pos..p.pos + w]);
    p.pos += w;
}

// A processing instruction, at "<?".
fn read_pi<P>(p: P&, parent: i64) {
    p.pos += 2;
    let ns, ne = read_name(p);
    let target = p.s[ns..ne];
    if find(target, ":") >= 0 { fail_at(p.s, ns, ERR_NAMESPACE, "colon in a processing instruction's target"); }
    var lower: u8[>..] = [];
    lower.append(target);
    to_lower(lower);
    if lower == "xml" { fail_at(p.s, ns, ERR_SYNTAX, "XML declaration not at the start"); }
    let tspan = put(p.d, target);
    let at = p.d.text.len;
    if !looking_at(p, "?>") {
        if !skip_space(p) { fail(p, ERR_SYNTAX, "malformed processing instruction"); }
        let data_at = p.d.text.len;
        loop {
            if at_end(p) { fail(p, ERR_SYNTAX, "processing instruction not closed"); }
            if looking_at(p, "?>") { break; }
            copy_char(p);
        }
        check_size(p);
        p.pos += 2;
        let n = new_node(p, Node { kind: PI, local: tspan, value: Span { at: data_at, len: p.d.text.len - data_at }, .. });
        link_last(p.d, parent, n);
        return;
    }
    p.pos += 2;
    let n = new_node(p, Node { kind: PI, local: tspan, value: Span { at: at, len: 0 }, .. });
    link_last(p.d, parent, n);
}

// A CDATA section, at "<![CDATA[".
fn read_cdata<P>(p: P&, parent: i64) {
    p.pos += 9;
    let at = p.d.text.len;
    loop {
        if at_end(p) { fail(p, ERR_SYNTAX, "CDATA section not closed"); }
        if looking_at(p, "]]>") { p.pos += 3; break; }
        copy_char(p);
    }
    check_size(p);
    let n = new_node(p, Node { kind: CDATA, value: Span { at: at, len: p.d.text.len - at }, .. });
    link_last(p.d, parent, n);
}

// Character data up to the next '<' or the end, into a text node of
// parent; only white space where `text_ok` is false, and then dropped.
fn read_text<P>(p: P&, parent: i64, text_ok: bool) {
    if !text_ok {
        while p.pos < p.s.len && p.s[p.pos] != '<' {
            if !is_space(p.s[p.pos]) { fail(p, ERR_SYNTAX, "text outside the root element"); }
            p.pos++;
        }
        return;
    }
    let at = p.d.text.len;
    while p.pos < p.s.len {
        let b = p.s[p.pos];
        if b == '<' { break; }
        if b == '&' { read_reference(p); continue; }
        if b == ']' && looking_at(p, "]]>") { fail(p, ERR_SYNTAX, "]]> in text"); }
        copy_char(p);
    }
    check_size(p);
    if p.d.text.len > at {
        let n = new_node(p, Node { kind: TEXT, value: Span { at: at, len: p.d.text.len - at }, .. });
        link_last(p.d, parent, n);
    }
}

fn is_id_name(o: const Options&, name: const u8[:]) -> bool {
    var found = false;
    each_split(o.id_attrs[..], ' ') { if it.len > 0 && it == name { found = true; } };
    return found;
}

// Adds a namespace binding, hiding the prefix's previous one.
fn bind<P>(p: P&, prefix: Span, uri: Span) {
    let key = view(p.d, prefix);
    let prev = p.scope.get(key);
    let pv = if prev { prev } else { -1 };
    p.bindings.push(Binding { prefix: prefix, uri: uri, prev: pv });
    p.scope.insert(key, p.bindings.len - 1);
}

// Removes the bindings from `mark` up.
fn unbind<P>(p: P&, mark: i64) {
    while p.bindings.len > mark {
        let b = p.bindings.pop();
        let key = view(p.d, b.prefix);
        if b.prev >= 0 { p.scope.insert(key, b.prev); } else { p.scope.remove(key); }
    }
}

// The URI bound to a prefix, and whether it is bound.
fn resolve<P>(p: P&, prefix: const u8[:]) -> Span, bool {
    if prefix == "xml" { return p.d.xml_ns, true; }
    let b = p.scope.get(prefix);
    if b { return p.bindings[b].uri, true; }
    return Span { .. }, false;
}

// A start tag at '<': the element, its attributes and declarations; true
// when it was empty (<a/>).
fn read_start_tag<P>(p: P&, parent: i64) -> i64, bool {
    let tag_at = p.pos;
    p.pos++;
    let qs, qe = read_name(p);
    let qname = p.s[qs..qe];
    if !is_qname(qname) { fail_at(p.s, qs, ERR_NAMESPACE, str("element name ", qname, " is not a QName")); }
    p.raw.clear();
    var empty = false;
    loop {
        let sp = skip_space(p);
        if at_end(p) { fail(p, ERR_SYNTAX, "start tag not closed"); }
        if looking_at(p, "/>") { p.pos += 2; empty = true; break; }
        if peek(p, 0) == '>' { p.pos++; break; }
        if !sp { fail(p, ERR_SYNTAX, "expected white space before an attribute"); }
        let a0, a1 = read_name(p);
        skip_space(p);
        if peek(p, 0) != '=' { fail(p, ERR_SYNTAX, "expected = after an attribute name"); }
        p.pos++;
        skip_space(p);
        let v = read_att_value(p);
        if p.raw.len >= p.o.max_attrs { fail_at(p.s, a0, ERR_LIMIT, "too many attributes"); }
        let an = p.s[a0..a1];
        for r in p.raw {
            if p.s[r.from..r.to] == an { fail_at(p.s, a0, ERR_DUP_ATTR, str("attribute ", an, " twice")); }
        }
        p.raw.push(RawAttr { from: a0, to: a1, value: v });
    }
    let colon = find(qname, ":");
    var el_node = Node { kind: ELEMENT, .. };
    if colon >= 0 {
        el_node.prefix = put(p.d, qname[..colon]);
        el_node.local = put(p.d, qname[colon + 1..]);
    } else {
        el_node.local = put(p.d, qname);
    }
    let el = new_node(p, el_node);
    link_last(p.d, parent, el);
    // The declarations first: they are in scope for the element's own names.
    for r in p.raw {
        let an = p.s[r.from..r.to];
        let is_default = an == "xmlns";
        if !is_default && !starts_with(an, "xmlns:") { continue; }
        let declared = if is_default { "" } else { an[6..] };
        let uri = view(p.d, r.value);
        if !is_default && !is_ncname(declared) { fail_at(p.s, r.from, ERR_NAMESPACE, str("bad prefix in ", an)); }
        if declared == "xmlns" { fail_at(p.s, r.from, ERR_NAMESPACE, "the prefix xmlns cannot be declared"); }
        if declared == "xml" {
            if uri != XML_NS { fail_at(p.s, r.from, ERR_NAMESPACE, "the prefix xml bound to another namespace"); }
            continue;   // allowed, and already bound: not kept
        }
        if uri == XML_NS || uri == XMLNS_NS { fail_at(p.s, r.from, ERR_NAMESPACE, str("namespace ", uri, " is reserved")); }
        if !is_default && uri.len == 0 { fail_at(p.s, r.from, ERR_NAMESPACE, str(an, "=\"\": a prefix cannot be undeclared")); }
        if has_space(uri) { fail_at(p.s, r.from, ERR_NAMESPACE, str(an, ": a namespace URI with white space")); }
        let pspan = put(p.d, declared);
        let a = new_node(p, Node { kind: NAMESPACE, local: pspan, value: r.value, .. });
        link_attr(p.d, el, a);
        bind(p, pspan, r.value);
        if p.bindings.len > p.o.max_namespaces { fail_at(p.s, r.from, ERR_LIMIT, "too many namespaces in scope"); }
    }
    if colon >= 0 {
        let pre = qname[..colon];
        if pre == "xmlns" { fail_at(p.s, qs, ERR_NAMESPACE, "element with the prefix xmlns"); }
        let uri, bound = resolve(p, pre);
        if !bound { fail_at(p.s, qs, ERR_NAMESPACE, str("prefix ", pre, " not bound")); }
        p.d.nodes[el].ns = uri;
    } else {
        let uri, bound = resolve(p, "");
        if bound { p.d.nodes[el].ns = uri; }
    }
    // Then the attributes, each prefix resolved.
    let first_attr = p.d.nodes.len;
    for r in p.raw {
        let an = p.s[r.from..r.to];
        if an == "xmlns" || starts_with(an, "xmlns:") { continue; }
        if !is_qname(an) { fail_at(p.s, r.from, ERR_NAMESPACE, str("attribute name ", an, " is not a QName")); }
        let c = find(an, ":");
        var a_node = Node { kind: ATTRIBUTE, value: r.value, .. };
        if c >= 0 {
            let pre = an[..c];
            let uri, bound = resolve(p, pre);
            if !bound { fail_at(p.s, r.from, ERR_NAMESPACE, str("prefix ", pre, " not bound")); }
            a_node.prefix = put(p.d, pre);
            a_node.local = put(p.d, an[c + 1..]);
            a_node.ns = uri;
            a_node.is_id = pre == "xml" && an[c + 1..] == "id";
        } else {
            a_node.local = put(p.d, an);
            a_node.is_id = is_id_name(p.o, an);
        }
        let a = new_node(p, a_node);
        link_attr(p.d, el, a);
        if a_node.is_id && p.o.unique_ids {
            let idv = view(p.d, r.value);
            if p.ids.contains(idv) { fail_at(p.s, r.from, ERR_DUP_ID, str("ID ", idv[.. ::min(idv.len, 64)], if idv.len > 64 { "... twice" } else { " twice" })); }
            p.ids.insert(idv, a);
        }
    }
    // Two attributes of one namespace and local name.
    var i = first_attr;
    while i < p.d.nodes.len {
        if p.d.nodes[i].kind == ATTRIBUTE && p.d.nodes[i].ns.len > 0 {
            var j = i + 1;
            while j < p.d.nodes.len {
                if p.d.nodes[j].kind == ATTRIBUTE && view(p.d, p.d.nodes[j].local) == view(p.d, p.d.nodes[i].local)
                   && view(p.d, p.d.nodes[j].ns) == view(p.d, p.d.nodes[i].ns) {
                    fail_at(p.s, tag_at, ERR_DUP_ATTR, str("attribute {", view(p.d, p.d.nodes[i].ns), "}",
                                                             view(p.d, p.d.nodes[i].local), " twice"));
                }
                j++;
            }
        }
        i++;
    }
    return el, empty;
}

// Whether the end tag's name at the cursor is el's.
fn end_tag_matches<P>(p: P&, el: i64, name: const u8[:]) -> bool {
    let pre = view(p.d, p.d.nodes[el].prefix);
    let loc = view(p.d, p.d.nodes[el].local);
    if pre.len == 0 { return name == loc; }
    return name.len == pre.len + 1 + loc.len && name[..pre.len] == pre && name[pre.len] == ':' && name[pre.len + 1..] == loc;
}

// Content into `top`: the whole document (fragment false: prolog, one
// root element, epilogue) or a fragment's (any content, no DOCTYPE).
fn read_content<P>(p: P&, top: i64, fragment: bool) {
    var cur = top;
    var depth = 0;
    var marks: i64[>..<] = [];
    var root_done = false;
    var seen_root = false;
    var seen_doctype = false;
    while !at_end(p) {
        let in_element = depth > 0 || fragment;
        if p.s[p.pos] != '<' {
            read_text(p, cur, in_element);
            continue;
        }
        if looking_at(p, "</") {
            if depth == 0 { fail(p, ERR_TAG, "end tag without a start tag"); }
            let at = p.pos;
            p.pos += 2;
            let ns, ne = read_name(p);
            if !end_tag_matches(p, cur, p.s[ns..ne]) {
                fail_at(p.s, at, ERR_TAG, str("end tag ", p.s[ns..ne], " does not match ",
                                               qname_of(p.d, cur)));
            }
            skip_space(p);
            expect(p, ">");
            unbind(p, marks.pop());
            cur = p.d.nodes[cur].parent;
            depth--;
            if depth == 0 && !fragment { root_done = true; }
        } else if looking_at(p, "<!--") {
            read_comment(p, cur);
        } else if looking_at(p, "<![CDATA[") {
            if !in_element { fail(p, ERR_SYNTAX, "CDATA outside the root element"); }
            read_cdata(p, cur);
        } else if looking_at(p, "<!DOCTYPE") {
            if fragment || seen_root || seen_doctype { fail(p, ERR_SYNTAX, "DOCTYPE not in the prolog"); }
            read_doctype(p);
            seen_doctype = true;
        } else if looking_at(p, "<!") {
            fail(p, ERR_SYNTAX, "markup declaration not allowed");
        } else if looking_at(p, "<?") {
            read_pi(p, cur);
        } else {
            if root_done { fail(p, ERR_SYNTAX, "a second root element"); }
            if depth >= p.o.max_depth { fail(p, ERR_LIMIT, "elements nested too deep"); }
            let mark = p.bindings.len;
            let el, empty = read_start_tag(p, cur);
            seen_root = true;
            if empty {
                unbind(p, mark);
                if depth == 0 && !fragment { root_done = true; }
            } else {
                marks.push(mark);
                cur = el;
                depth++;
            }
        }
    }
    if depth > 0 { fail(p, ERR_TAG, str("element ", qname_of(p.d, cur), " not closed")); }
    if !fragment && !seen_root { fail(p, ERR_SYNTAX, "no root element"); }
}

// The qualified name of an element or attribute, as written.
fn qname_of(d: const Doc&, n: i64) -> u8[>..] {
    var out: u8[>..] = [];
    let pre = view(d, d.nodes[n].prefix);
    if pre.len > 0 { out.append(pre); out.push(':'); }
    out.append(view(d, d.nodes[n].local));
    return out;
}

fn parse_core<P>(p: P&, fragment: bool, top: i64) -> Error {
    if p.s.len > p.o.max_size { fail_at(p.s, 0, ERR_LIMIT, "document too large"); }
    if !fragment {
        if p.s.len >= 2 && ((p.s[0] == 0xFE && p.s[1] == 0xFF) || (p.s[0] == 0xFF && p.s[1] == 0xFE)) {
            fail_at(p.s, 0, ERR_ENCODING, "UTF-16 not supported (UTF-8 only)");
        }
        if looking_at(p, "\xEF\xBB\xBF") { p.pos += 3; }
        if looking_at(p, "<?xml") && p.pos + 5 < p.s.len && is_space(p.s[p.pos + 5]) { read_xml_decl(p); }
    }
    read_content(p, top, fragment);
    return Error { message: [] };
}

fn new_doc_node(d: Doc&) {
    assert(d.nodes.len == 0);
    add_node(d, Node { kind: DOCUMENT, .. });
    d.xml_ns = put(d, XML_NS);
}

// Collects every ID of the document into ids, refusing a repeated one.
fn index_ids(d: const Doc&, ids: dictionary<const u8[:], i64>&) -> i64 {
    for i in d.nodes.len {
        if d.nodes[i].kind == ATTRIBUTE && d.nodes[i].is_id && d.nodes[i].parent >= 0 && attached(d, d.nodes[i].parent) {
            let v = view(d, d.nodes[i].value);
            if ids.contains(v) { return i; }
            ids.insert(v, i);
        }
    }
    return -1;
}

// Parses text into d, which must be empty, with options o.
fn parse(d: Doc&, text: const u8[:], o: const Options&) -> Error {
    new_doc_node(d);
    var raw:      RawAttr[>..<] = [];
    var bindings: Binding[>..<] = [];
    var scope = dictionary<const u8[:], i64> {};
    var ids = dictionary<const u8[:], i64> {};
    var p = Parser { s: text, d: d, o: o, raw: raw, bindings: bindings, scope: scope, ids: ids };
    return parse_core(p, false, 0);
}

fn parse(d: Doc&, text: const u8[:]) -> Error {
    let o = options();
    return parse(d, text, o);
}

// Parses text as content (elements, text, comments, processing
// instructions; no DOCTYPE, no XML declaration) into the element parent
// of d, before the child `before` (-1: after its last), its prefixes
// resolved in parent's scope, as XML Encryption's decrypted content is.
// An ID of the fragment that d already has is refused when o.unique_ids.
// On an error, nothing is linked into d.
fn parse_fragment(d: Doc&, parent: i64, before: i64, text: const u8[:], o: const Options&) -> Error {
    assert(d.nodes[parent].kind == ELEMENT || d.nodes[parent].kind == DOCUMENT);
    // Parse under a detached holder, then move the children in.
    let holder = add_node(d, Node { kind: ELEMENT, prefix: d.nodes[parent].prefix, local: d.nodes[parent].local,
                                    ns: d.nodes[parent].ns, .. });
    var raw:      RawAttr[>..<] = [];
    var bindings: Binding[>..<] = [];
    var scope = dictionary<const u8[:], i64> {};
    var ids = dictionary<const u8[:], i64> {};
    if o.unique_ids { index_ids(d, ids); }
    var p = Parser { s: text, d: d, o: o, raw: raw, bindings: bindings, scope: scope, ids: ids };
    p.nodes0 = d.nodes.len;
    p.text0 = d.text.len;
    if d.nodes[parent].kind == ELEMENT {
        each_in_scope(d, parent) { decl, uri => bind(p, d.nodes[decl].local, d.nodes[decl].value); };
    }
    let e = parse_core(p, true, holder);
    if e.code != OK { return e; }
    var c = d.nodes[holder].first;
    while c >= 0 {
        let nx = d.nodes[c].next;
        link_before(d, parent, c, before);
        c = nx;
    }
    d.nodes[holder].first = -1;
    d.nodes[holder].last = -1;
    return e;
}

fn parse_fragment(d: Doc&, parent: i64, before: i64, text: const u8[:]) -> Error {
    let o = options();
    return parse_fragment(d, parent, before, text, o);
}

// --- reading the document ------------------------------------------------------

fn kind(d: const Doc&, n: i64) -> u8 { d.nodes[n].kind }
fn parent(d: const Doc&, n: i64) -> i64 { d.nodes[n].parent }
fn first_child(d: const Doc&, n: i64) -> i64 { d.nodes[n].first }
fn last_child(d: const Doc&, n: i64) -> i64 { d.nodes[n].last }
fn next_sibling(d: const Doc&, n: i64) -> i64 { d.nodes[n].next }
fn prev_sibling(d: const Doc&, n: i64) -> i64 { d.nodes[n].prev }
fn first_attr(d: const Doc&, n: i64) -> i64 { d.nodes[n].attrs }
fn local_name(d: const Doc&, n: i64) -> const u8[:] { view(d, d.nodes[n].local) }
fn prefix(d: const Doc&, n: i64) -> const u8[:] { view(d, d.nodes[n].prefix) }
fn ns_uri(d: const Doc&, n: i64) -> const u8[:] { view(d, d.nodes[n].ns) }
fn value(d: const Doc&, n: i64) -> const u8[:] { view(d, d.nodes[n].value) }

// Whether n is an element of namespace ns named local.
fn is(d: const Doc&, n: i64, ns: const u8[:], local: const u8[:]) -> bool {
    n >= 0 && d.nodes[n].kind == ELEMENT && view(d, d.nodes[n].local) == local && view(d, d.nodes[n].ns) == ns
}

// The document element, -1 if none.
fn root_element(d: const Doc&) -> i64 {
    if d.nodes.len == 0 { return -1; }
    var c = d.nodes[0].first;
    while c >= 0 && d.nodes[c].kind != ELEMENT { c = d.nodes[c].next; }
    return c;
}

// The first element child of n, the next element sibling; -1 if none.
fn first_element(d: const Doc&, n: i64) -> i64 {
    var c = d.nodes[n].first;
    while c >= 0 && d.nodes[c].kind != ELEMENT { c = d.nodes[c].next; }
    return c;
}

fn next_element(d: const Doc&, n: i64) -> i64 {
    var c = d.nodes[n].next;
    while c >= 0 && d.nodes[c].kind != ELEMENT { c = d.nodes[c].next; }
    return c;
}

// The first child element of el in namespace ns named local, -1 if none.
fn child(d: const Doc&, el: i64, ns: const u8[:], local: const u8[:]) -> i64 {
    var c = first_element(d, el);
    while c >= 0 && !is(d, c, ns, local) { c = next_element(d, c); }
    return c;
}

// The number of element children of el in ns named local.
fn count_children(d: const Doc&, el: i64, ns: const u8[:], local: const u8[:]) -> i64 {
    var n = 0;
    var c = first_element(d, el);
    while c >= 0 { if is(d, c, ns, local) { n++; } c = next_element(d, c); }
    return n;
}

// F(child) for each element child of el.
fn each_element<F>(d: const Doc&, el: i64) {
    var c = first_element(d, el);
    while c >= 0 {
        let nx = next_element(d, c);
        F(c);
        c = nx;
    }
}

// F(attribute) for each attribute of el (not the declarations).
fn each_attr<F>(d: const Doc&, el: i64) {
    var a = d.nodes[el].attrs;
    while a >= 0 {
        let nx = d.nodes[a].next;
        if d.nodes[a].kind == ATTRIBUTE { F(a); }
        a = nx;
    }
}

// The attribute node of el in namespace ns (empty: none) named local, -1.
fn attr_node(d: const Doc&, el: i64, ns: const u8[:], local: const u8[:]) -> i64 {
    var a = d.nodes[el].attrs;
    while a >= 0 {
        if d.nodes[a].kind == ATTRIBUTE && view(d, d.nodes[a].local) == local && view(d, d.nodes[a].ns) == ns { return a; }
        a = d.nodes[a].next;
    }
    return -1;
}

// The value of el's attribute in ns named local, and whether it has one.
fn attr(d: const Doc&, el: i64, ns: const u8[:], local: const u8[:]) -> const u8[:], bool {
    let a = attr_node(d, el, ns, local);
    if a < 0 { return "", false; }
    return view(d, d.nodes[a].value), true;
}

// The value of el's unprefixed attribute `local`.
fn attr(d: const Doc&, el: i64, local: const u8[:]) -> const u8[:], bool {
    let v, ok = attr(d, el, "", local);
    return v, ok;
}

// The text of el's text and CDATA descendants, in order, appended to out.
fn text_content(d: const Doc&, el: i64, out: u8[>..]&) {
    walk(d, el) { n, entering =>
        if entering && (d.nodes[n].kind == TEXT || d.nodes[n].kind == CDATA) { out.append(view(d, d.nodes[n].value)); }
        true
    };
}

// Whether n is linked into the document (node 0 is an ancestor).
fn attached(d: const Doc&, n: i64) -> bool {
    var c = n;
    while c > 0 { c = d.nodes[c].parent; }
    return c == 0;
}

// Whether n is a or in a's subtree.
fn within(d: const Doc&, a: i64, n: i64) -> bool {
    var c = n;
    while c >= 0 { if c == a { return true; } c = d.nodes[c].parent; }
    return false;
}

// Walks the subtree of n in document order: F(node, true) on the way in,
// and for nodes with children F(node, false) on the way out. F returns
// whether to go into the node's children (read on the way in only).
fn walk<F>(d: const Doc&, n: i64) {
    var c = n;
    loop {
        let down = F(c, true);
        let f = d.nodes[c].first;
        if down && f >= 0 { c = f; continue; }
        if c == n { return; }
        // Up until there is a next sibling.
        loop {
            let nx = d.nodes[c].next;
            if nx >= 0 { c = nx; break; }
            c = d.nodes[c].parent;
            F(c, false);
            if c == n { return; }
        }
    }
}

// F(namespace declaration node) for each namespace in scope at el, the
// nearest declaration of each prefix (xmlns="" included, as the default's
// undeclaration), nearest element first.
fn each_in_scope<F>(d: const Doc&, el: i64) {
    var seen: u8[][>..] = [];
    var e = el;
    while e > 0 {
        if d.nodes[e].kind == ELEMENT {
            var a = d.nodes[e].attrs;
            while a >= 0 {
                if d.nodes[a].kind == NAMESPACE {
                    let pre = view(d, d.nodes[a].local);
                    var dup = false;
                    for s in seen { if s == pre { dup = true; } }
                    if !dup {
                        seen.push(pre);
                        F(a, view(d, d.nodes[a].value));
                    }
                }
                a = d.nodes[a].next;
            }
        }
        e = d.nodes[e].parent;
    }
}

// The URI bound to prefix at el, and whether it is bound ("" for the
// default namespace; xmlns="" leaves it unbound).
fn lookup_ns(d: const Doc&, el: i64, prefix: const u8[:]) -> const u8[:], bool {
    if prefix == "xml" { return XML_NS, true; }
    var e = el;
    while e > 0 {
        if d.nodes[e].kind == ELEMENT {
            var a = d.nodes[e].attrs;
            while a >= 0 {
                if d.nodes[a].kind == NAMESPACE && view(d, d.nodes[a].local) == prefix {
                    let v = view(d, d.nodes[a].value);
                    return v, v.len > 0;
                }
                a = d.nodes[a].next;
            }
        }
        e = d.nodes[e].parent;
    }
    return "", false;
}

// The element whose ID is id, and how many attached elements have it: the
// element is only to be trusted when the count is 1.
fn by_id(d: const Doc&, id: const u8[:]) -> i64, i64 {
    var found = -1;
    var count = 0;
    for i in d.nodes.len {
        let n = d.nodes[i];
        if n.kind == ATTRIBUTE && n.is_id && n.parent >= 0 && view(d, n.value) == id && attached(d, n.parent) {
            if found != n.parent { count++; }
            found = n.parent;
        }
    }
    return found, count;
}

// The ID of el (its first ID attribute), and whether it has one.
fn id_of(d: const Doc&, el: i64) -> const u8[:], bool {
    var a = d.nodes[el].attrs;
    while a >= 0 {
        if d.nodes[a].kind == ATTRIBUTE && d.nodes[a].is_id { return view(d, d.nodes[a].value), true; }
        a = d.nodes[a].next;
    }
    return "", false;
}

// --- building and changing -----------------------------------------------------

// Starts an empty document in d, which must be empty.
fn new_document(d: Doc&) { new_doc_node(d); }

// Whether a node can go into parent (an element, or the document) before
// `before`: -1, or one of parent's children.
fn can_insert(d: const Doc&, parent: i64, before: i64) -> bool {
    if parent < 0 || parent >= d.nodes.len { return false; }
    let k = d.nodes[parent].kind;
    if k != ELEMENT && k != DOCUMENT { return false; }
    return before < 0 || (before < d.nodes.len && d.nodes[before].parent == parent
                          && d.nodes[before].kind != ATTRIBUTE && d.nodes[before].kind != NAMESPACE);
}

// Whether prefix:local (prefix may be empty) are names an element can have.
fn names_ok(prefix: const u8[:], local: const u8[:]) -> bool {
    (prefix.len == 0 || (is_ncname(prefix) && prefix != "xmlns")) && is_ncname(local)
}

// A new element prefix:local in namespace ns, a child of parent before
// `before` (-1: last), with a declaration of the prefix added when parent's
// scope does not already bind it to ns. -1 for names that are not NCNames,
// a prefix without a namespace, or the reserved prefixes misused.
fn insert_element(d: Doc&, parent: i64, before: i64, prefix: const u8[:], local: const u8[:], ns: const u8[:]) -> i64 {
    if !can_insert(d, parent, before) { return -1; }
    if !names_ok(prefix, local) || (prefix.len > 0 && ns.len == 0) || !is_text(ns) || has_space(ns) { return -1; }
    if (prefix == "xml") != (ns == XML_NS) && prefix.len > 0 { return -1; }
    if prefix.len == 0 && (ns == XML_NS || ns == XMLNS_NS) { return -1; }
    let el = add_node(d, Node { kind: ELEMENT, prefix: put(d, prefix), local: put(d, local), .. });
    link_before(d, parent, el, before);
    if prefix != "xml" {
        let cur, bound = lookup_ns(d, parent, prefix);
        if !(bound && cur == ns) && !(!bound && ns.len == 0) { bind_ns(d, el, prefix, ns); }
    }
    let uri, bound = lookup_ns(d, el, prefix);
    if bound { d.nodes[el].ns = put(d, uri); }
    return el;
}

fn element(d: Doc&, parent: i64, prefix: const u8[:], local: const u8[:], ns: const u8[:]) -> i64 {
    insert_element(d, parent, -1, prefix, local, ns)
}

// Declares prefix (empty: the default namespace) as uri on el, replacing
// a declaration of it there. False for names XML cannot declare, and for
// a binding that would change the namespace of el, of one of its
// attributes or of something in its subtree that has the prefix (what is
// written must parse back to what is in memory; a descendant that
// declares the prefix again is not told apart).
fn declare_ns(d: Doc&, el: i64, prefix: const u8[:], uri: const u8[:]) -> bool {
    if prefix.len > 0 && (!is_ncname(prefix) || uri.len == 0) { return false; }
    if prefix == "xml" || prefix == "xmlns" || uri == XML_NS || uri == XMLNS_NS || !is_text(uri) || has_space(uri) { return false; }
    if el < 0 || el >= d.nodes.len || d.nodes[el].kind != ELEMENT || rebinds_used(d, el, prefix, uri) { return false; }
    bind_ns(d, el, prefix, uri);
    return true;
}

// Whether binding prefix to uri at el changes the namespace of a name
// under it with that prefix: el's, its attributes' (a prefix only), its
// descendants'.
fn rebinds_used(d: const Doc&, el: i64, prefix: const u8[:], uri: const u8[:]) -> bool {
    let cur, bound = lookup_ns(d, el, prefix);
    if (bound && cur == uri) || (!bound && uri.len == 0) { return false; }
    var used = false;
    walk(d, el) { n, entering =>
        if entering && d.nodes[n].kind == ELEMENT {
            if view(d, d.nodes[n].prefix) == prefix && view(d, d.nodes[n].ns) != uri { used = true; }
            var a = d.nodes[n].attrs;
            while prefix.len > 0 && a >= 0 {
                if d.nodes[a].kind == ATTRIBUTE && view(d, d.nodes[a].prefix) == prefix && view(d, d.nodes[a].ns) != uri { used = true; }
                a = d.nodes[a].next;
            }
        }
        !used
    };
    return used;
}

// The declaration itself, checked by the caller.
fn bind_ns(d: Doc&, el: i64, prefix: const u8[:], uri: const u8[:]) {
    var a = d.nodes[el].attrs;
    while a >= 0 {
        if d.nodes[a].kind == NAMESPACE && view(d, d.nodes[a].local) == prefix {
            d.nodes[a].value = put(d, uri);
            return;
        }
        a = d.nodes[a].next;
    }
    let n = add_node(d, Node { kind: NAMESPACE, local: put(d, prefix), value: put(d, uri), .. });
    link_attr(d, el, n);
}

// Sets el's attribute prefix:local in namespace ns to value (replacing
// the value of one it has), declaring the prefix when needed. False for
// bad names or a value with characters XML does not allow.
fn set_attr(d: Doc&, el: i64, prefix: const u8[:], local: const u8[:], ns: const u8[:], value: const u8[:]) -> bool {
    if !names_ok(prefix, local) || (prefix.len > 0) != (ns.len > 0) || !is_text(value) || !is_text(ns) { return false; }
    if prefix == "xml" && ns != XML_NS { return false; }
    if prefix.len == 0 && local == "xmlns" { return false; }   // a namespace declaration: declare_ns
    let a = attr_node(d, el, ns, local);
    if a >= 0 { d.nodes[a].value = put(d, value); return true; }
    if prefix.len > 0 && prefix != "xml" {
        let cur, bound = lookup_ns(d, el, prefix);
        if !bound || cur != ns {
            if !declare_ns(d, el, prefix, ns) { return false; }
        }
    }
    var n = Node { kind: ATTRIBUTE, prefix: put(d, prefix), local: put(d, local), value: put(d, value), .. };
    if ns.len > 0 { n.ns = put(d, ns); }
    n.is_id = (prefix.len == 0 && (local == "ID" || local == "Id" || local == "id")) || (prefix == "xml" && local == "id");
    let i = add_node(d, n);
    link_attr(d, el, i);
    return true;
}

// Sets an unprefixed attribute.
fn set_attr(d: Doc&, el: i64, local: const u8[:], value: const u8[:]) -> bool {
    set_attr(d, el, "", local, "", value)
}

// Marks el's unprefixed attribute `local` as an ID (or not).
fn set_id_attr(d: Doc&, el: i64, local: const u8[:], is_id: bool) -> bool {
    let a = attr_node(d, el, "", local);
    if a < 0 { return false; }
    d.nodes[a].is_id = is_id;
    return true;
}

// A text node with value, a child of parent before `before`; -1 when value
// has characters XML does not allow.
fn insert_text(d: Doc&, parent: i64, before: i64, value: const u8[:]) -> i64 {
    if !is_text(value) || !can_insert(d, parent, before) { return -1; }
    let n = add_node(d, Node { kind: TEXT, value: put(d, value), .. });
    link_before(d, parent, n, before);
    return n;
}

fn text(d: Doc&, parent: i64, value: const u8[:]) -> i64 { insert_text(d, parent, -1, value) }

// A comment; -1 for "--" in it, a "-" at its end, or a bad character.
fn comment(d: Doc&, parent: i64, value: const u8[:]) -> i64 {
    if !can_insert(d, parent, -1) || !is_text(value) || find(value, "--") >= 0 || ends_with(value, "-") { return -1; }
    let n = add_node(d, Node { kind: COMMENT, value: put(d, value), .. });
    link_last(d, parent, n);
    return n;
}

// A processing instruction; -1 for a bad target or "?>" in data.
fn pi(d: Doc&, parent: i64, target: const u8[:], data: const u8[:]) -> i64 {
    var lower: u8[>..] = [];
    lower.append(target);
    to_lower(lower);
    if !can_insert(d, parent, -1) || !is_ncname(target) || lower == "xml" || !is_text(data) || find(data, "?>") >= 0 { return -1; }
    let n = add_node(d, Node { kind: PI, local: put(d, target), value: put(d, data), .. });
    link_last(d, parent, n);
    return n;
}

// Replaces el's children with one text node; false for a bad character.
fn set_text(d: Doc&, el: i64, value: const u8[:]) -> bool {
    if !is_text(value) { return false; }
    var c = d.nodes[el].first;
    while c >= 0 { let nx = d.nodes[c].next; d.nodes[c].parent = -1; d.nodes[c].next = -1; d.nodes[c].prev = -1; c = nx; }
    d.nodes[el].first = -1;
    d.nodes[el].last = -1;
    text(d, el, value);
    return true;
}

// Unlinks n (and its subtree) from its parent; it stays in d.nodes, detached.
fn detach(d: Doc&, n: i64) {
    let par = d.nodes[n].parent;
    if par < 0 { return; }
    let p = d.nodes[n].prev;
    let x = d.nodes[n].next;
    if d.nodes[n].kind == ATTRIBUTE || d.nodes[n].kind == NAMESPACE {
        if p >= 0 { d.nodes[p].next = x; } else { d.nodes[par].attrs = x; }
        if x >= 0 { d.nodes[x].prev = p; }
    } else {
        if p >= 0 { d.nodes[p].next = x; } else { d.nodes[par].first = x; }
        if x >= 0 { d.nodes[x].prev = p; } else { d.nodes[par].last = p; }
    }
    d.nodes[n].parent = -1;
    d.nodes[n].next = -1;
    d.nodes[n].prev = -1;
}

// Moves n (detached or not) into parent before `before` (-1: last);
// false, and nothing moved, when `before` is not parent's child or the
// move would put n inside itself. An element moved keeps its names'
// namespaces: where its new scope binds a prefix it uses (the default
// namespace too) otherwise, or not at all, n declares it, as
// insert_element does.
fn move_to(d: Doc&, n: i64, parent: i64, before: i64) -> bool {
    if before == n || within(d, n, parent) { return false; }
    if !can_insert(d, parent, before) { return false; }
    let k = d.nodes[n].kind;
    if k == DOCUMENT || k == ATTRIBUTE || k == NAMESPACE { return false; }
    detach(d, n);
    link_before(d, parent, n, before);
    if k != ELEMENT { return true; }
    // One declaration on n fixes every name that took the prefix from
    // above it; a name that n's subtree binds otherwise is left as it was
    // (each prefix is declared once: "|p:" in done).
    var done: u8[>..] = [];
    loop {
        let m = scope_mismatch(d, n);
        if m < 0 { return true; }
        var key: u8[>..] = [];
        key.push('|');
        key.append(view(d, d.nodes[m].prefix));
        key.push(':');
        if find(done, key) >= 0 { return true; }
        done.append(key);
        var uri: u8[>..] = [];
        uri.append(view(d, d.nodes[m].ns));
        bind_ns(d, n, key[1..key.len - 1], uri);
    }
    return true;
}

// The first element or prefixed attribute under el whose prefix its scope
// binds to other than its namespace (or does not bind), -1 for none.
fn scope_mismatch(d: const Doc&, el: i64) -> i64 {
    var found = -1;
    walk(d, el) { n, entering =>
        if entering && d.nodes[n].kind == ELEMENT {
            if name_unbound(d, n, n) { found = n; }
            var a = d.nodes[n].attrs;
            while found < 0 && a >= 0 {
                if d.nodes[a].kind == ATTRIBUTE && d.nodes[a].prefix.len > 0 && name_unbound(d, n, a) { found = a; }
                a = d.nodes[a].next;
            }
        }
        found < 0
    };
    return found;
}

// Whether name x (el or one of its attributes) has a namespace other than
// what el's scope binds its prefix to.
fn name_unbound(d: const Doc&, el: i64, x: i64) -> bool {
    let uri, bound = lookup_ns(d, el, view(d, d.nodes[x].prefix));
    let ns = view(d, d.nodes[x].ns);
    return if bound { uri != ns } else { ns.len > 0 };
}

// --- writing ---------------------------------------------------------------------

// Text escaped for content: & < > and CR as references.
fn escape_text(out: u8[>..]&, s: const u8[:]) {
    var from = 0;
    for i in s.len {
        let c = s[i];
        if c == '&' || c == '<' || c == '>' || c == '\r' {
            out.append(s[from..i]);
            out.append(if c == '&' { "&amp;" } else if c == '<' { "&lt;" } else if c == '>' { "&gt;" } else { "&#xD;" });
            from = i + 1;
        }
    }
    out.append(s[from..]);
}

// Text escaped for a double-quoted attribute value: & < " and the white
// space that normalization would turn into spaces.
fn escape_attr(out: u8[>..]&, s: const u8[:]) {
    var from = 0;
    for i in s.len {
        let c = s[i];
        if c == '&' || c == '<' || c == '"' || c == '\t' || c == '\n' || c == '\r' {
            out.append(s[from..i]);
            out.append(if c == '&' { "&amp;" } else if c == '<' { "&lt;" } else if c == '"' { "&quot;" }
                       else if c == '\t' { "&#x9;" } else if c == '\n' { "&#xA;" } else { "&#xD;" });
            from = i + 1;
        }
    }
    out.append(s[from..]);
}

fn write_start(d: const Doc&, el: i64, out: u8[>..]&, top: bool) {
    out.push('<');
    out.append(qname_of(d, el));
    var a = d.nodes[el].attrs;
    while a >= 0 {
        let n = d.nodes[a];
        if n.kind == NAMESPACE {
            out.append(if n.local.len == 0 { " xmlns" } else { " xmlns:" });
            out.append(view(d, n.local));
        } else {
            out.push(' ');
            out.append(qname_of(d, a));
        }
        out.append("=\"");
        escape_attr(out, view(d, n.value));
        out.push('"');
        a = n.next;
    }
    if top {
        // The namespaces in scope from outside the subtree, so that it
        // stands on its own.
        let par = d.nodes[el].parent;
        if par > 0 {
            each_in_scope(d, par) { decl, uri =>
                let pre = view(d, d.nodes[decl].local);
                var here = false;
                var b = d.nodes[el].attrs;
                while b >= 0 {
                    if d.nodes[b].kind == NAMESPACE && view(d, d.nodes[b].local) == pre { here = true; }
                    b = d.nodes[b].next;
                }
                if !here && !(pre.len == 0 && uri.len == 0) {
                    out.append(if pre.len == 0 { " xmlns" } else { " xmlns:" });
                    out.append(pre);
                    out.append("=\"");
                    escape_attr(out, uri);
                    out.push('"');
                }
            };
        }
    }
}

// Writes the subtree of n to out as XML. An element whose ancestors are
// left out declares the namespaces they bound, so that what is written
// parses on its own. Empty elements are written <a/>.
fn write_node(d: const Doc&, n: i64, out: u8[>..]&) {
    walk(d, n) { c, entering =>
        let node = d.nodes[c];
        if node.kind == ELEMENT {
            if entering {
                write_start(d, c, out, c == n);
                if node.first < 0 { out.append("/>"); } else { out.push('>'); }
            } else {
                out.append("</");
                out.append(qname_of(d, c));
                out.push('>');
            }
        } else if entering {
            if node.kind == TEXT {
                escape_text(out, view(d, node.value));
            } else if node.kind == CDATA {
                let v = view(d, node.value);
                if find(v, "]]>") >= 0 { escape_text(out, v); }
                else { out.append("<![CDATA["); out.append(v); out.append("]]>"); }
            } else if node.kind == COMMENT {
                out.append("<!--"); out.append(view(d, node.value)); out.append("-->");
            } else if node.kind == PI {
                out.append("<?"); out.append(view(d, node.local));
                if node.value.len > 0 { out.push(' '); out.append(view(d, node.value)); }
                out.append("?>");
            }
        }
        true
    };
}

// Writes the subtree of n (the document for 0, its top-level nodes on
// lines of their own) to out as XML.
fn write(d: const Doc&, n: i64, out: u8[>..]&) {
    if d.nodes[n].kind != DOCUMENT { write_node(d, n, out); return; }
    var c = d.nodes[n].first;
    while c >= 0 {
        write_node(d, c, out);
        c = d.nodes[c].next;
        if c >= 0 { out.push('\n'); }
    }
}

// The whole document with an XML declaration.
fn write_document(d: const Doc&, out: u8[>..]&) {
    out.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    write(d, 0, out);
}

// --- base64 content (XML Signature and Encryption values) ----------------------

// The bytes of el's text content read as base64 (XML Schema's
// base64Binary: white space anywhere is passed over), appended to out;
// false for an element with element children or text that is not base64.
fn base64_content(d: const Doc&, el: i64, out: u8[>..]&) -> bool {
    if first_element(d, el) >= 0 { return false; }
    var t: u8[>..] = [];
    var c = d.nodes[el].first;
    while c >= 0 {
        let k = d.nodes[c].kind;
        if k == TEXT || k == CDATA {
            for b in view(d, d.nodes[c].value) { if !is_space(b) { t.push(b); } }
        }
        c = d.nodes[c].next;
    }
    return base64::decode(out, t);
}

// Whether el has nothing but white space, comments and processing
// instructions besides its element children.
fn only_elements(d: const Doc&, el: i64) -> bool {
    var c = d.nodes[el].first;
    while c >= 0 {
        let k = d.nodes[c].kind;
        if k == TEXT || k == CDATA {
            for b in view(d, d.nodes[c].value) { if !is_space(b) { return false; } }
        }
        c = d.nodes[c].next;
    }
    return true;
}
