// mime.textproto against net/textproto's tests of what multipart relies
// on: canonicalHeaderKeyTests, TestReadMIMEHeaderMalformed's inputs and the
// inputs of the other TestReadMIMEHeader* functions (test/vectors, from
// $GOROOT/src/net/textproto by scripts/gen_vectors.py, with Go's own
// ReadMIMEHeader of each); TestReadMIMEHeaderBytes, TestLargeReadMIMEHeader
// and TestMIMEHeaderMultipleValues ported; every input also read as it
// grows, a byte at a time, which must give the same.

import std;
import mime from "..";
import mime.textproto;
import tv;

// Every field after a '|', so that an empty field is never lost.
fn push_field(out: u8[>..]&, s: const u8[:]) {
    out.push('|');
    tv::escape(out, s);
}

// The error's text and the header, flattened as the oracle writes Go's.
fn read_text(input: const u8[:], bytewise: bool) -> u8[>..] {
    var h = textproto::new_header();
    var detail: u8[>..] = [];
    var code = 0;
    if bytewise {
        // what is decided with fewer bytes must not change with more
        var n = 0;
        loop {
            let c, end = textproto::read_mime_header_at(input[..n], 0, n == input.len, textproto::MAX_INT64,
                                                        textproto::MAX_INT64, h, detail);
            if c != textproto::NEED_MORE { code = c; break; }
            n++;
        }
    } else {
        let c, end = textproto::read_mime_header_at(input, 0, true, textproto::MAX_INT64, textproto::MAX_INT64, h, detail);
        code = c;
    }
    var out: u8[>..] = [];
    var msg: u8[>..] = [];
    if code != mime::OK { textproto::error_message(msg, code, detail); }
    push_field(out, msg);
    var keys: const u8[:][>..] = [];
    for f in h.fields {
        var dup = false;
        for k in keys { if k == f.key { dup = true; } }
        if !dup { keys.push(f.key); }
    }
    sort(keys) { a, b => compare(a, b) < 0 };
    push_field(out, str(keys.len));
    for k in keys {
        push_field(out, k);
        var n = 0;
        for f in h.fields { if f.key == k { n++; } }
        push_field(out, str(n));
        for f in h.fields { if f.key == k { push_field(out, f.value); } }
    }
    return out;
}

fn results_text(r: tv::Row&) -> u8[>..] {
    r.to_results();
    var out: u8[>..] = [];
    while r.has_more() { push_field(out, r.next()); }
    return out;
}

fn tables() {
    tv::each_row("vectors/go_canonical_key.txt") { r: tv::Row& =>
        let input = r.next();
        let want = r.next();
        r.to_results();
        let go = r.next();
        let got = textproto::canonical_mime_header_key(input);
        tv::check_eq(str("canonical key ", input), got, go);
        tv::check_eq(str("canonical key (table) ", input), got, want);
    };
    for name in ["header_malformed", "read_mime_header"] {
        tv::each_row(str("vectors/go_", name, ".txt")) { r: tv::Row& =>
            let n = r.next_int();
            for i in n - 1 { r.next(); }
            let input = r.next();
            let go = results_text(r);
            tv::check_eq(str(name, " ", input), read_text(input, false), go);
            tv::check_eq(str(name, " bytewise ", input), read_text(input, true), go);
        };
    }
}

// TestReadMIMEHeaderBytes: which bytes a key and a value may hold.
fn header_bytes() {
    for i in 256 {
        let c = i as u8;
        var s: u8[>..] = [];
        s.append("Foo");
        mime::push_rune(s, i);
        s.append("Bar: foo\r\n\r\n");
        let ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                 c == '!' || c == '#' || c == '$' || c == '%' || c == '&' || c == '\'' || c == '*' || c == '+' ||
                 c == '-' || c == '.' || c == '^' || c == '_' || c == '`' || c == '|' || c == '~' || c == ':' || c == ' ';
        var h = textproto::new_header();
        let code, used = textproto::read_mime_header(s, h);
        tv::check(str("key byte ", i), (code == 0) == ok);
    }
    for i in 256 {
        let c = i as u8;
        var s: u8[>..] = [];
        s.append("Foo: foo");
        mime::push_rune(s, i);
        s.append("bar\r\n\r\n");
        let ok = (c >= 0x21 && c <= 0x7e) || c == ' ' || c == '\t' || c >= 0x80;
        var h = textproto::new_header();
        let code, used = textproto::read_mime_header(s, h);
        tv::check(str("value byte ", i), (code == 0) == ok);
    }
}

// TestLargeReadMIMEHeader.
fn large() {
    var data: u8[>..] = [];
    for i in 16 * 1024 { data.push('x'); }
    var h = textproto::new_header();
    let code, used = textproto::read_mime_header(str("Cookie: ", data, "\r\n\n"), h);
    tv::check_int("large header", code, 0);
    tv::check("large header value", textproto::get(h, "Cookie") == data);
}

// TestMIMEHeaderMultipleValues, and the methods.
fn methods() {
    var h = textproto::new_header();
    textproto::add(h, "Set-Cookie", "cookie 1");
    textproto::add(h, "set-cookie", "cookie 2");
    tv::check_int("multiple values", textproto::count_values(h, "set-cookie"), 2);
    textproto::set(h, "x-a", "1");
    textproto::add(h, "X-A", "2");
    tv::check_eq("get first", textproto::get(h, "x-a"), "1");
    textproto::set(h, "X-a", "3");
    tv::check_int("set replaces", textproto::count_values(h, "X-A"), 1);
    tv::check_eq("set value", textproto::get(h, "X-A"), "3");
    textproto::del(h, "set-COOKIE");
    tv::check("del", !textproto::has(h, "Set-Cookie"));
    tv::check_int("keys", textproto::key_count(h), 1);
}

// Limits: Go's 400 + (200 + len(key)) per new key + len(value) per value,
// and the number of lines.
fn limits() {
    var h = textproto::new_header();
    var d: u8[>..] = [];
    let s = "A: 12345\r\nA: 678\r\n\r\n";
    // 400 + 200 + 1 + 5 + 3 = 609 bytes, but a line may not be longer than
    // what is left: the second line's 6 bytes need 612 (checked with Go)
    let c1, e1 = textproto::read_mime_header_at(s, 0, true, 612, 100, h, d);
    tv::check_int("memory limit fits", c1, 0);
    let c2, e2 = textproto::read_mime_header_at(s, 0, true, 611, 100, h, d);
    tv::check_int("memory limit exceeded", c2, mime::ERR_MESSAGE_TOO_LARGE);
    let c3, e3 = textproto::read_mime_header_at(s, 0, true, 10000, 2, h, d);
    tv::check_int("header count fits", c3, 0);
    let c4, e4 = textproto::read_mime_header_at(s, 0, true, 10000, 1, h, d);
    tv::check_int("header count exceeded", c4, mime::ERR_MESSAGE_TOO_LARGE);
    let c5, e5 = textproto::read_mime_header_at("A: 1\r\n", 0, true, 10000, 10, h, d);
    tv::check_int("EOF before the blank line", c5, mime::ERR_EOF);
    tv::check_eq("EOF keeps the fields", textproto::get(h, "A"), "1");
    let c6, e6 = textproto::read_mime_header_at("A: 1\r\n  ", 0, true, 10000, 10, h, d);
    tv::check_eq("continuation at EOF keeps its space", textproto::get(h, "A"), "1 ");
}

fn main() {
    tables();
    header_bytes();
    large();
    methods();
    limits();
    tv::done("textproto");
}
