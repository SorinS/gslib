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

// readMIMEHeader as a reader that is resumed as its input grows: the
// fields read so far stay read (in the Header the caller passes each time,
// with the same `seen`), and a field is read again only when the bytes
// that came can decide it.
struct HeaderReader {
    pos: i64,            // where the next field starts (after the blank line once done)
    mem: i64,            // what is left of maxMemory (Go's accounting)
    hdrs: i64,           // what is left of maxHeaders
    started: bool,
    // when to try the next field again (see field_ready)
    scan: i64,
    waiting: i64,        // a '\n' whose next byte has not come, or -1
    nl_seen: bool,       // the field's first line has ended
    tried: i64,          // the field's bytes at the last try
}

fn header_reader(pos: i64, max_memory: i64, max_headers: i64) -> HeaderReader {
    HeaderReader { pos: pos, mem: max_memory - 400, hdrs: max_headers, started: false,
                   scan: pos, waiting: -1, nl_seen: false, tried: 0 }
}

// The input moved by delta bytes (the caller dropped what was before it).
fn shift(hr: HeaderReader&, delta: i64) {
    hr.pos -= delta;
    hr.scan -= delta;
    if hr.waiting >= 0 { hr.waiting -= delta; }
}

// Whether the next field could be decided now: its first line has ended
// (a missing colon, the blank line), its end is known (a line end then a
// byte that is not a space or a tab), or its bytes have doubled since the
// last try (a limit). Each field is so tried a few times, at a cost in
// proportion to its size.
fn field_ready(data: const u8[:], hr: HeaderReader&) -> bool {
    var i = ::max(hr.scan, hr.pos);
    while i < data.len {
        if hr.waiting >= 0 {
            let nb = data[hr.waiting + 1];
            hr.waiting = -1;
            if nb != ' ' && nb != '\t' { hr.scan = i; return true; }
        }
        if data[i] == '\n' {
            hr.waiting = i;
            i++;
            if !hr.nl_seen { hr.nl_seen = true; hr.scan = i; return true; }
            continue;
        }
        i++;
    }
    hr.scan = i;
    let have = data.len - hr.pos;
    return have >= 4096 && have >= 2 * hr.tried;
}

// One field read and checked, as readMIMEHeader's loop body does; 1 to go
// on, else the result.
fn take_field(kv: const u8[:], hr: HeaderReader&, h: Header&, detail: u8[>..]&, seen: dictionary<u64, bool>&,
              key: u8[>..]&) -> i64 {
    let colon = mime::index_byte(kv, ':');
    key.clear();
    if !reader_key(key, kv[..colon]) { detail.append(kv); return mime::ERR_MALFORMED_LINE; }
    let v = kv[colon + 1..];
    for b in v {
        if !is_value_byte(b) {
            // Go canonicalizes the key in place first: its message has the key so
            detail.append(key);
            detail.append(kv[colon..]);
            return mime::ERR_MALFORMED_LINE;
        }
    }
    hr.hdrs--;
    if hr.hdrs < 0 { h.fields.clear(); return mime::ERR_MESSAGE_TOO_LARGE; }
    var a = 0;
    while a < v.len && (v[a] == ' ' || v[a] == '\t') { a++; }
    let value = v[a..];
    let kh = hash(key);
    var known = false;
    if seen.contains(kh) {
        for f in h.fields { if f.key == key { known = true; break; } }
    }
    if !known {
        hr.mem -= key.len;
        hr.mem -= 200;
        seen.insert(kh, true);
    }
    hr.mem -= value.len;
    if hr.mem < 0 { return mime::ERR_MESSAGE_TOO_LARGE; }
    h.fields.push(Field { key: key[..], value: value });
    return 1;
}

// Reads on from hr. Returns mime::OK (hr.pos after the blank line),
// NEED_MORE (feed more, call again with the same hr, h and seen),
// mime::ERR_EOF (the fields before the end are in h, as Go returns them
// with io.EOF), mime::ERR_MESSAGE_TOO_LARGE, or a malformed-line error
// whose line is in detail. With gate false it tries whatever bytes there
// are; with gate true only when field_ready says they may decide.
fn read_mime_header_step(data: const u8[:], hr: HeaderReader&, eof: bool, h: Header&, detail: u8[>..]&,
                         seen: dictionary<u64, bool>&, gate: bool) -> i64 {
    if !hr.started {
        if hr.pos >= data.len && !eof { return NEED_MORE; }
        if hr.pos < data.len && (data[hr.pos] == ' ' || data[hr.pos] == '\t') {
            var c = Cursor { pos: hr.pos, eof: eof };
            var sp = Span { pos: 0, end: 0 };
            let r = read_line(data, c, 80, sp);
            if r == 0 { return NEED_MORE; }
            hr.pos = c.pos;
            if r == -2 { return mime::ERR_MESSAGE_TOO_LARGE; }
            detail.clear();
            detail.append(data[sp.pos..sp.end]);
            return mime::ERR_MALFORMED_INITIAL_LINE;
        }
        hr.started = true;
    }
    var kv: u8[>..] = [];
    var key: u8[>..] = [];
    loop {
        if gate && !eof && !field_ready(data, hr) { return NEED_MORE; }
        hr.tried = data.len - hr.pos;
        var c = Cursor { pos: hr.pos, eof: eof };
        let r = read_continued(data, c, hr.mem, kv);
        if r == 0 { return NEED_MORE; }
        hr.pos = c.pos;
        hr.scan = c.pos;
        hr.waiting = -1;
        hr.nl_seen = false;
        hr.tried = 0;
        if r == -1 { return mime::ERR_EOF; }
        if r == -2 { return mime::ERR_MESSAGE_TOO_LARGE; }
        if r == -3 { detail.clear(); detail.append(kv); return mime::ERR_MISSING_COLON; }
        if kv.len == 0 { return mime::OK; }
        detail.clear();
        let t = take_field(kv, hr, h, detail, seen, key);
        if t != 1 { return t; }
    }
}

// readMIMEHeader(r, maxMemory, maxHeaders) on data from `pos`, with `eof`
// saying whether data holds all of the input, from the start each time.
// The fields go into h. Returns the code (mime::OK, NEED_MORE,
// mime::ERR_EOF, mime::ERR_MESSAGE_TOO_LARGE, or a malformed-line error
// whose line is in detail) and where the reader stopped.
fn read_mime_header_at(data: const u8[:], pos: i64, eof: bool, max_memory: i64, max_headers: i64,
                       h: Header&, detail: u8[>..]&) -> i64, i64 {
    h.fields.clear();
    detail.clear();
    var hr = header_reader(pos, max_memory, max_headers);
    var seen = dictionary<u64, bool> {};
    let code = read_mime_header_step(data, hr, eof, h, detail, seen, false);
    if code == NEED_MORE { return NEED_MORE, pos; }
    return code, hr.pos;
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
