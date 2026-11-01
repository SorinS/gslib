// tv: what the tests share: counting checks, hex, and reading the vector
// files that scripts/gen_vectors.py writes (fields separated
// by '|', bytes outside 0x20..0x7e and '\' '|' as \xHH, \N for nil, "=>"
// before Go's own results).

namespace tv;

import std;
import os;

var checks = 0;
var failures = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok {
        failures++;
        if failures <= 40 { print("FAIL ", what); }
    }
}

// Like check, printing what was got and wanted on a failure.
fn check_eq(what: const u8[:], got: const u8[:], want: const u8[:]) {
    check(what, got == want);
    if got != want && failures <= 40 {
        var g: u8[>..] = [];
        var w: u8[>..] = [];
        escape(g, got);
        escape(w, want);
        print("      got  ", g);
        print("      want ", w);
    }
}

fn check_int(what: const u8[:], got: i64, want: i64) {
    check(what, got == want);
    if got != want && failures <= 40 { print("      got ", got, ", want ", want); }
}

// Prints the totals; exits 1 if anything failed.
fn done(name: const u8[:]) {
    print(name, ": ", checks - failures, "/", checks, " checks passed");
    if failures > 0 { exit(1); }
}

fn escape(out: u8[>..]&, s: const u8[:]) {
    let hex = "0123456789abcdef";
    for c in s {
        if c < 0x20 || c > 0x7e || c == '\\' || c == '|' {
            out.append("\\x"); out.push(hex[c >> 4]); out.push(hex[c & 15]);
        } else {
            out.push(c);
        }
    }
}

fn unhex(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

struct Span { pos: i64, end: i64 }

// A row of a vector file: its fields, decoded, and a cursor over them.
root struct Row {
    buf: u8[>..] = [],
    spans: Span[>..] = [],
    nils: bool[>..] = [],
    pos: i64 = 0,
    line: i64 = 0,
}

fn count(r: Row&) -> i64 { r.spans.len }

fn field(r: Row&, i: i64) -> const u8[:] { r.buf[r.spans[i].pos..r.spans[i].end] }

// The next field.
fn next(r: Row&) -> const u8[:] {
    let i = r.pos;
    r.pos++;
    if i >= r.spans.len { abort(str("vector line ", r.line, ": too few fields")); }
    return r.buf[r.spans[i].pos..r.spans[i].end];
}

// Whether the next field is \N; it is skipped if so.
fn next_is_nil(r: Row&) -> bool {
    if r.pos < r.spans.len && r.nils[r.pos] { r.pos++; return true; }
    return false;
}

fn next_int(r: Row&) -> i64 {
    let f = next(r);
    let n, ok = parse_int(f);
    if !ok { abort(str("vector line ", r.line, ": not a number: ", f)); }
    return n;
}

fn next_bool(r: Row&) -> bool { next(r) == "1" }

// Moves the cursor past the "=>" that starts Go's results.
fn to_results(r: Row&) {
    while r.pos < r.spans.len {
        let f = next(r);
        if f == "=>" { return; }
    }
    abort(str("vector line ", r.line, ": no =>"));
}

fn has_more(r: Row&) -> bool { r.pos < r.spans.len }

fn decode_line(r: Row&, line: const u8[:]) {
    r.buf.clear();
    r.spans.clear();
    r.nils.clear();
    r.pos = 0;
    var start = r.buf.len;
    var nil_field = false;
    var i = 0;
    while i <= line.len {
        if i == line.len || line[i] == '|' {
            r.spans.push(Span { pos: start, end: r.buf.len });
            r.nils.push(nil_field);
            nil_field = false;
            start = r.buf.len;
            i++;
            continue;
        }
        let c = line[i];
        if c == '\\' && i + 1 < line.len && line[i + 1] == 'N' { nil_field = true; i += 2; continue; }
        if c == '\\' && i + 3 < line.len {
            r.buf.push((unhex(line[i + 2]) << 4) | unhex(line[i + 3]));
            i += 4;
            continue;
        }
        r.buf.push(c);
        i++;
    }
}

// Calls F(row) for every row of the vector file at path (relative to test/).
fn each_row<F>(path: const u8[:]) {
    var text: u8[>..] = [];
    if !read_file(path, text) { abort(str("cannot read ", path)); }
    var r = Row { .. };
    var n = 0;
    each_split(text, '\n') {
        n++;
        if it.len > 0 && it[0] != '#' {
            r.line = n;
            decode_line(r, it);
            F(r);
        }
    };
}

// Bytes from hex, spaces ignored.
fn hex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var hi = -1;
    for c in s {
        if c == ' ' || c == '\n' { continue; }
        let v = unhex(c) as i64;
        if hi < 0 { hi = v; } else { out.push(((hi << 4) | v) as! u8); hi = -1; }
    }
    return out;
}

fn to_hex(s: const u8[:]) -> u8[>..] {
    let digits = "0123456789abcdef";
    var out: u8[>..] = [];
    for c in s { out.push(digits[c >> 4]); out.push(digits[c & 15]); }
    return out;
}

// check_eq on bytes, printed as hex.
fn check_hex(what: const u8[:], got: const u8[:], want_hex: const u8[:]) {
    let want = hex(want_hex);
    check(what, got == want);
    if got != want && failures <= 40 {
        print("      got  ", to_hex(got));
        print("      want ", to_hex(want));
    }
}
