// mime.textproto: MIME header sections as Go's net/textproto reads them
// (ReadMIMEHeader, readMIMEHeader's limits), and Go's MIMEHeader: keys in
// canonical form (CanonicalMIMEHeaderKey), each key with its values in the
// order they came.
//
// The reader works on a buffer the caller holds and knows whether more
// input may follow: read_mime_header_at answers NEED_MORE until the bytes
// it has decide the result as Go's reader would decide it.

namespace textproto;

import std;
import dictionary;
import mime;

// A header field: its key (canonical when it was valid) and a value.
struct Field { key: u8[varint], value: u8[varint] }

// MIMEHeader: the fields in the order they came; Go's map keeps the
// order of each key's values, which this keeps too.
struct Header { fields: Field[>..] = [] }

fn new_header() -> Header { Header { .. } }

// validHeaderFieldByte: an RFC 7230 tchar.
fn is_field_byte(c: u8) -> bool {
    if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' ||
           c == '+' || c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

// validHeaderValueByte: VCHAR, SP, HTAB or obs-text.
fn is_value_byte(c: u8) -> bool { c == '\t' || (c >= 0x20 && c != 0x7f) }

// CanonicalMIMEHeaderKey: the first letter and each letter after a hyphen
// in upper case, the rest in lower case; a key with a byte that is not a
// tchar (a space, for one) is left as it is.
fn canonical_mime_header_key(out: u8[>..]&, s: const u8[:]) {
    for c in s { if !is_field_byte(c) { out.append(s); return; } }
    var upper = true;
    for c in s {
        var d = c;
        if upper && d >= 'a' && d <= 'z' { d -= 32; } else if !upper && d >= 'A' && d <= 'Z' { d += 32; }
        out.push(d);
        upper = d == '-';
    }
}

fn canonical_mime_header_key(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    canonical_mime_header_key(out, s);
    return out;
}

// canonicalMIMEHeaderKey as the reader uses it: false for an empty key or
// one with a byte that is neither a tchar nor a space; a key with a space
// is accepted but not canonicalized (Go issue 34540).
fn reader_key(out: u8[>..]&, k: const u8[:]) -> bool {
    if k.len == 0 { return false; }
    var space = false;
    for c in k {
        if is_field_byte(c) { continue; }
        if c == ' ' { space = true; continue; }
        return false;
    }
    if space { out.append(k); return true; }
    canonical_mime_header_key(out, k);
    return true;
}

// --- MIMEHeader's methods ---------------------------------------------------

// Get: the first value of the key (canonicalized), "" if none.
fn get(h: const Header&, key: const u8[:]) -> const u8[:] {
    var k: u8[>..] = [];
    canonical_mime_header_key(k, key);
    for f in h.fields { if f.key == k { return f.value; } }
    return "";
}

// Whether the key (canonicalized) has a value.
fn has(h: const Header&, key: const u8[:]) -> bool {
    var k: u8[>..] = [];
    canonical_mime_header_key(k, key);
    for f in h.fields { if f.key == k { return true; } }
    return false;
}

// Values: F(value) for each value of the key, in order.
fn each_value<F>(h: const Header&, key: const u8[:]) {
    var k: u8[>..] = [];
    canonical_mime_header_key(k, key);
    for f in h.fields { if f.key == k { F(f.value[..]); } }
}

fn count_values(h: const Header&, key: const u8[:]) -> i64 {
    var n = 0;
    each_value(h, key) { n++; };
    return n;
}

// Add: appends a value to the key (canonicalized).
fn add(h: Header&, key: const u8[:], value: const u8[:]) {
    var k: u8[>..] = [];
    canonical_mime_header_key(k, key);
    h.fields.push(Field { key: k[..], value: value });
}

// Del: removes the key's values.
fn del(h: Header&, key: const u8[:]) {
    var k: u8[>..] = [];
    canonical_mime_header_key(k, key);
    var kept = Header { .. };
    for f in h.fields { if f.key != k { kept.fields.push(Field { key: f.key[..], value: f.value[..] }); } }
    h.fields.clear();
    for f in kept.fields { h.fields.push(Field { key: f.key[..], value: f.value[..] }); }
}

// Set: the key's values replaced by this one.
fn set(h: Header&, key: const u8[:], value: const u8[:]) {
    del(h, key);
    add(h, key, value);
}

// The number of distinct keys (the size of Go's map).
fn key_count(h: const Header&) -> i64 {
    var n = 0;
    var i = 0;
    for f in h.fields {
        var first = true;
        var j = 0;
        for g in h.fields {
            if j >= i { break; }
            if g.key == f.key { first = false; break; }
            j++;
        }
        if first { n++; }
        i++;
    }
    return n;
}

// --- Reading -------------------------------------------------------------------

let NEED_MORE: i64 = -1;
let MAX_INT64: i64 = 9223372036854775807;

// Where the reader is in its buffer, and what it knows of the input.
struct Cursor { pos: i64, eof: bool }

// ReadLine (bufio) over data[c.pos..]: the line without its "\n" or
// "\r\n". The result: 1 a line, 0 need more, -1 io.EOF (nothing left).
// A line whose content will pass `lim` (when lim >= 0) is
// errMessageTooLarge, -2, as soon as enough of it is there to know.
fn read_line(data: const u8[:], c: Cursor&, lim: i64, line: Span&) -> i64 {
    var k = c.pos;
    while k < data.len && data[k] != '\n' { k++; }
    if k == data.len {
        let have = data.len - c.pos;
        if lim >= 0 && have > lim + 1 { return -2; }
        if !c.eof { return 0; }
        if have == 0 { return -1; }
        if lim >= 0 && have > lim { return -2; }
        line.pos = c.pos;
        line.end = data.len;
        c.pos = data.len;
        return 1;
    }
    var e = k;
    if e > c.pos && data[e - 1] == '\r' { e--; }
    if lim >= 0 && e - c.pos > lim { return -2; }
    line.pos = c.pos;
    line.end = e;
    c.pos = k + 1;
    return 1;
}

struct Span { pos: i64, end: i64 }

fn trim_lwsp(s: const u8[:]) -> const u8[:] {
    var a = 0;
    var b = s.len;
    while a < b && (s[a] == ' ' || s[a] == '\t') { a++; }
    while b > a && (s[b - 1] == ' ' || s[b - 1] == '\t') { b--; }
    return s[a..b];
}

// readContinuedLineSlice(lim, mustHaveFieldNameColon): the line with its
// continuation lines joined by single spaces into kv. 1 a line (kv empty
// for the blank line), 0 need more, or a negative: -1 io.EOF, -2 too
// large, -3 missing colon (kv holds the line).
fn read_continued(data: const u8[:], c: Cursor&, lim0: i64, kv: u8[>..]&) -> i64 {
    kv.clear();
    var sp = Span { pos: 0, end: 0 };
    let r = read_line(data, c, lim0, sp);
    if r != 1 { return r; }
    if sp.end == sp.pos { return 1; }
    let first = data[sp.pos..sp.end];
    if mime::index_byte(first, ':') < 0 { kv.append(first); return -3; }
    kv.append(trim_lwsp(first));
    var lim = if lim0 < 0 { MAX_INT64 } else { lim0 };
    lim -= kv.len;
    loop {
        // skipSpace: the spaces and tabs that start the next line
        var k = c.pos;
        while k < data.len && (data[k] == ' ' || data[k] == '\t') { k++; }
        if k == data.len && !c.eof { return 0; }
        if k == c.pos { break; }
        c.pos = k;
        kv.push(' ');
        if kv.len >= lim { return -2; }
        var cl = Span { pos: 0, end: 0 };
        let rr = read_line(data, c, lim - kv.len, cl);
        if rr == 0 { return 0; }
        if rr != 1 { break; }        // Go ignores an error here and stops
        kv.append(trim_lwsp(data[cl.pos..cl.end]));
    }
    return 1;
}

// readMIMEHeader(r, maxMemory, maxHeaders) on data from `pos`, with `eof`
// saying whether data holds all of the input. The fields go into h.
// Returns the code (mime::OK, NEED_MORE, mime::ERR_EOF,
// mime::ERR_MESSAGE_TOO_LARGE, or a malformed-line error whose line is in
// detail) and where the reader stopped. On ERR_EOF the fields read before
// the end are in h, as Go returns them with io.EOF.
fn read_mime_header_at(data: const u8[:], pos: i64, eof: bool, max_memory: i64, max_headers: i64,
                       h: Header&, detail: u8[>..]&) -> i64, i64 {
    h.fields.clear();
    detail.clear();
    var c = Cursor { pos: pos, eof: eof };
    var mem = max_memory - 400;
    var hdrs = max_headers;
    if pos >= data.len && !eof { return NEED_MORE, pos; }
    if pos < data.len && (data[pos] == ' ' || data[pos] == '\t') {
        var sp = Span { pos: 0, end: 0 };
        let r = read_line(data, c, 80, sp);
        if r == 0 { return NEED_MORE, pos; }
        if r == -2 { return mime::ERR_MESSAGE_TOO_LARGE, c.pos; }
        detail.append(data[sp.pos..sp.end]);
        return mime::ERR_MALFORMED_INITIAL_LINE, c.pos;
    }
    var kv: u8[>..] = [];
    var key: u8[>..] = [];
    var seen = dictionary<u64, bool> {};
    loop {
        let r = read_continued(data, c, mem, kv);
        if r == 0 { return NEED_MORE, pos; }
        if r == -1 { return mime::ERR_EOF, c.pos; }
        if r == -2 { return mime::ERR_MESSAGE_TOO_LARGE, c.pos; }
        if r == -3 { detail.append(kv); return mime::ERR_MISSING_COLON, c.pos; }
        if kv.len == 0 { return mime::OK, c.pos; }
        let colon = mime::index_byte(kv, ':');
        key.clear();
        if !reader_key(key, kv[..colon]) { detail.append(kv); return mime::ERR_MALFORMED_LINE, c.pos; }
        let v = kv[colon + 1..];
        for b in v { if !is_value_byte(b) { detail.append(kv); return mime::ERR_MALFORMED_LINE, c.pos; } }
        hdrs--;
        if hdrs < 0 { h.fields.clear(); return mime::ERR_MESSAGE_TOO_LARGE, c.pos; }
        var a = 0;
        while a < v.len && (v[a] == ' ' || v[a] == '\t') { a++; }
        let value = v[a..];
        let kh = hash(key);
        var known = false;
        if seen.contains(kh) {
            for f in h.fields { if f.key == key { known = true; break; } }
        }
        if !known {
            mem -= key.len;
            mem -= 200;
            seen.insert(kh, true);
        }
        mem -= value.len;
        if mem < 0 { return mime::ERR_MESSAGE_TOO_LARGE, c.pos; }
        h.fields.push(Field { key: key[..], value: value });
    }
}

// ReadMIMEHeader of a whole buffer: the header, the code (mime::OK, or
// mime::ERR_EOF when the input ends before the blank line, as Go's
// io.EOF, or an error) and the bytes read, up to the blank line's end.
fn read_mime_header(data: const u8[:], h: Header&) -> i64, i64 {
    var detail: u8[>..] = [];
    return read_mime_header_at(data, 0, true, MAX_INT64, MAX_INT64, h, detail);
}

// Go's message for a read_mime_header_at error, with its line.
fn error_message(out: u8[>..]&, code: i64, detail: const u8[:]) {
    out.append(mime::error_text(code));
    if code == mime::ERR_MALFORMED_INITIAL_LINE || code == mime::ERR_MALFORMED_LINE || code == mime::ERR_MISSING_COLON {
        out.append(": ");
        mime::go_quote(out, detail);
    }
}
