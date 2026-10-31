// mime.multipart's reader against Go's tests: parseTests and
// TestNameAccessors' tables, and the bodies Go's test functions build
// inline (test/vectors, extracted from $GOROOT/src/mime/multipart by
// scripts/gen_vectors.py with Go's own parse of each); the test functions'
// logic ported (TestMultipart, TestMultipartOnlyNewlines,
// TestMultipartSlowInput, TestVariousTextLineEndings, TestLineLimit,
// TestMultipartTruncated, TestMultipartStreamReadahead,
// TestLineContinuation, TestQuotedPrintableEncoding, TestRawPart,
// TestNested, TestParseAllSizes, roundTripParseTest, TestNoBoundary,
// TestBoundaryLine). Every body is also fed whole, a byte at a time and in
// pieces of pseudo-random sizes, which must all read the same.

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.textproto;
import gslib.mime.multipart;
import tv;

let FEED_WHOLE: i64 = 0;
let FEED_BYTES: i64 = 1;
let FEED_RANDOM: i64 = 2;

// Every field after a '|', so that an empty field is never lost.
fn push_field(out: u8[>..]&, s: const u8[:]) {
    out.push('|');
    tv::escape(out, s);
}

// A part's header as Go's map flattens: its size, then each key (sorted)
// with the number of its values and the values.
fn flatten_header(out: u8[>..]&, h: const textproto::Header&) {
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
        push_field(out, str(textproto::count_values(h, k)));
        for f in h.fields { if f.key == k { push_field(out, f.value); } }
    }
}

// Reads body with boundary, fed as `mode` says; every part (its header and
// body), then the error that ended the loop ("" for io.EOF), flattened as
// the oracle's parseFields writes Go's.
fn parse_fields(body: const u8[:], boundary: const u8[:], mode: i64, raw_first: bool) -> u8[>..] {
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    var out: u8[>..] = [];
    var parts: u8[>..] = [];
    var count = 0;
    var data: u8[>..] = [];
    var fed = 0;
    var seed: u64 = 0x9E3779B97F4A7C15 ^ (body.len as u64);
    var final: u8[>..] = [];
    r.raw = raw_first;
    loop {
        let ev = multipart::next(r, data);
        if ev == multipart::EV_NEED_MORE {
            if fed == body.len { multipart::finish(r); continue; }
            var n = body.len - fed;
            if mode == FEED_BYTES { n = 1; }
            if mode == FEED_RANDOM {
                seed = seed * 6364136223846793005 + 1442695040888963407;
                n = ::min(n, ((seed >> 33) % 700) as i64 + 1);
            }
            multipart::feed(r, body[fed..fed + n]);
            fed += n;
            continue;
        }
        if ev == multipart::EV_PART { data.clear(); continue; }
        if ev == multipart::EV_DATA { continue; }
        if ev == multipart::EV_PART_END {
            r.raw = false;
            count++;
            flatten_header(parts, r.header);
            push_field(parts, data);
            if r.part_err != 0 {
                final.append("body: ");
                final.append(r.part_err_text);
                break;
            }
            continue;
        }
        if ev == multipart::EV_ERROR { multipart::message(r, final); }
        break;
    }
    push_field(out, str(count));
    out.append(parts);
    push_field(out, final);
    return out;
}

// The Go results of a row (after "=>"), as one string.
fn results_text(r: tv::Row&) -> u8[>..] {
    r.to_results();
    var out: u8[>..] = [];
    while r.has_more() { push_field(out, r.next()); }
    return out;
}

// Every way of feeding gives Go's result.
fn check_parse(what: const u8[:], body: const u8[:], boundary: const u8[:], want: const u8[:]) {
    tv::check_eq(str(what, " (whole)"), parse_fields(body, boundary, FEED_WHOLE, false), want);
    tv::check_eq(str(what, " (bytes)"), parse_fields(body, boundary, FEED_BYTES, false), want);
    tv::check_eq(str(what, " (random)"), parse_fields(body, boundary, FEED_RANDOM, false), want);
}

fn parse_tests() {
    tv::each_row("vectors/go_multipart_parse.txt") { r: tv::Row& =>
        let name = r.next();
        let input = r.next();
        let sep = r.next();
        let go = results_text(r);
        check_parse(str("parse ", name), input, sep, go);
    };
    tv::each_row("vectors/go_name_accessors.txt") { r: tv::Row& =>
        r.next_int();
        let cd = r.next();
        let want_name = r.next();
        let want_file = r.next();
        r.to_results();
        let go_name = r.next();
        let go_file = r.next();
        var mr = multipart::Reader { .. };
        multipart::init(mr, "b");
        multipart::feed(mr, str("--b\r\nContent-Disposition: ", cd, "\r\n\r\n\r\n--b--\r\n"));
        multipart::finish(mr);
        { let ev = multipart::next_part(mr); tv::check_int(str("name accessors part ", cd), ev, multipart::EV_PART); }
        tv::check_eq(str("FormName ", cd), multipart::form_name(mr), go_name);
        tv::check_eq(str("FileName ", cd), multipart::file_name(mr), go_file);
        tv::check_eq(str("FormName (table) ", cd), multipart::form_name(mr), want_name);
        tv::check_eq(str("FileName (table) ", cd), multipart::file_name(mr), want_file);
    };
    for name in ["truncated_bodies", "line_continuation", "raw_part", "qp_part"] {
        let boundary = if name == "truncated_bodies" { "MyBoundary" } else if name == "line_continuation" { "Apple-Mail-2-292336769" } else { "0016e68ee29c5d515f04cedf6733" };
        tv::each_row(str("vectors/go_", name, ".txt")) { r: tv::Row& =>
            r.next_int();
            var body: u8[>..] = [];
            if name == "truncated_bodies" { format_replaced(body, r.next(), "\n", "\r\n"); } else { body.append(r.next()); }
            let go = results_text(r);
            check_parse(name, body, boundary, go);
        };
    }
}

// TestBoundaryLine.
fn boundary_line() {
    var r = multipart::Reader { .. };
    multipart::init(r, "myBoundary");
    tv::check("boundary line CRLF", multipart::is_boundary_delimiter_line(r, "--myBoundary\r\n"));
    tv::check("boundary line space CRLF", multipart::is_boundary_delimiter_line(r, "--myBoundary \r\n"));
    tv::check("boundary line space LF", multipart::is_boundary_delimiter_line(r, "--myBoundary \n"));
    tv::check("boundary line bogus", !multipart::is_boundary_delimiter_line(r, "--myBoundary bogus \n"));
    tv::check("boundary line bogus--", !multipart::is_boundary_delimiter_line(r, "--myBoundary bogus--"));
}

// Reads the next part's whole body; the event that ended it.
fn read_part(r: multipart::Reader&, data: u8[>..]&) -> i64 {
    data.clear();
    loop {
        let ev = multipart::next(r, data);
        if ev != multipart::EV_DATA { return ev; }
    }
}

// TestMultipart, TestMultipartOnlyNewlines, TestMultipartSlowInput: Go's
// testMultipartBody with its long line, read part by part.
fn test_multipart(sep: const u8[:], bytewise: bool) {
    var template: u8[>..] = [];
    tv::each_row("vectors/go_multipart_body.txt") { r: tv::Row& => r.next_int(); template.append(r.next()); };
    var long_line: u8[>..] = [];
    for i in (1 << 20) / 8 { long_line.append("\n\n\r\r\r\n\r\x00"); }
    var with_sep: u8[>..] = [];
    format_replaced(with_sep, template, "\n", sep);
    let at = find(with_sep, "[longline]");
    var body: u8[>..] = [];
    body.append(with_sep[..at]);
    body.append(long_line);
    body.append(with_sep[at + 10..]);
    let what = if sep == "\n" { "TestMultipartOnlyNewlines" } else if bytewise { "TestMultipartSlowInput" } else { "TestMultipart" };

    var r = multipart::Reader { .. };
    multipart::init(r, "MyBoundary");
    var fed = 0;
    var data: u8[>..] = [];
    fn step(r: multipart::Reader&, data: u8[>..]&) -> i64 {
        loop {
            let ev = multipart::next(r, data);
            if ev != multipart::EV_NEED_MORE { return ev; }
            if fed == body.len { multipart::finish(r); continue; }
            let n = if bytewise { 1 } else { body.len - fed };
            multipart::feed(r, body[fed..fed + n]);
            fed += n;
        }
    }
    fn whole_part(r: multipart::Reader&, data: u8[>..]&) -> i64 {
        data.clear();
        loop { let ev = step(r, data); if ev != multipart::EV_DATA { return ev; } }
    }
    var adjusted: u8[>..] = [];
    { let ev = step(r, data); tv::check_int(str(what, " part 1"), ev, multipart::EV_PART); }
    tv::check_eq(str(what, " Header1"), textproto::get(r.header, "Header1"), "value1");
    tv::check_eq(str(what, " foo-bar"), textproto::get(r.header, "foo-bar"), "baz");
    tv::check_eq(str(what, " Foo-Bar"), textproto::get(r.header, "Foo-Bar"), "baz");
    { let ev = whole_part(r, data); tv::check_int(str(what, " part 1 end"), ev, multipart::EV_PART_END); }
    format_replaced(adjusted, "My value\r\nThe end.", "\r\n", sep);
    tv::check_eq(str(what, " part 1 body"), data, adjusted);
    { let ev = step(r, data); tv::check_int(str(what, " part 2"), ev, multipart::EV_PART); }
    tv::check_eq(str(what, " part 2 name"), textproto::get(r.header, "name"), "bigsection");
    { let ev = whole_part(r, data); tv::check_int(str(what, " part 2 end"), ev, multipart::EV_PART_END); }
    tv::check(str(what, " part 2 long line"), data == long_line);
    { let ev = step(r, data); tv::check_int(str(what, " part 3"), ev, multipart::EV_PART); }
    tv::check_eq(str(what, " part 3 foo-bar"), textproto::get(r.header, "foo-bar"), "bazb");
    { let ev = whole_part(r, data); tv::check_int(str(what, " part 3 end"), ev, multipart::EV_PART_END); }
    adjusted.clear();
    format_replaced(adjusted, "Line 1\r\nLine 2\r\nLine 3 ends in a newline, but just one.\r\n", "\r\n", sep);
    tv::check_eq(str(what, " part 3 body"), data, adjusted);
    { let ev = step(r, data); tv::check_int(str(what, " part 4"), ev, multipart::EV_PART); }
    { let ev = whole_part(r, data); tv::check_int(str(what, " part 4 end"), ev, multipart::EV_PART_END); }
    { let ev = step(r, data); tv::check_int(str(what, " no part 5"), ev, multipart::EV_END); }
}

// TestVariousTextLineEndings.
fn line_endings() {
    tv::each_row("vectors/go_line_endings.txt") { row: tv::Row& =>
        row.next_int();
        let expected = row.next();
        let body = str("--BOUNDARY\r\nContent-Disposition: form-data; name=\"value\"\r\n\r\n", expected, "\r\n--BOUNDARY--\r\n");
        var r = multipart::Reader { .. };
        multipart::init(r, "BOUNDARY");
        multipart::feed(r, body);
        multipart::finish(r);
        var data: u8[>..] = [];
        tv::check_int("line endings part", multipart::next(r, data), multipart::EV_PART);
        tv::check_int("line endings end", read_part(r, data), multipart::EV_PART_END);
        tv::check_eq("line endings body", data, expected);
        tv::check_int("line endings no more", multipart::next(r, data), multipart::EV_END);
    };
}

// TestLineLimit: a body with no line end is an error early, not a buffer
// that grows with it.
fn line_limit() {
    var r = multipart::Reader { .. };
    multipart::init(r, "fooBoundary");
    var junk: u8[>..] = [];
    for i in 1024 { junk.push('x'); }
    var data: u8[>..] = [];
    var fed = 0;
    var ev = multipart::EV_NEED_MORE;
    while ev == multipart::EV_NEED_MORE && fed < (1 << 20) {
        multipart::feed(r, junk);
        fed += junk.len;
        ev = multipart::next(r, data);
    }
    tv::check_int("line limit error", ev, multipart::EV_ERROR);
    tv::check("line limit: read little", fed <= 8192);
    var m: u8[>..] = [];
    multipart::message(r, m);
    tv::check_eq("line limit message", m, "multipart: NextPart: bufio: buffer full");
}

// TestMultipartStreamReadahead: a part ends as soon as its boundary line
// is there, before more input.
fn readahead() {
    var b1: u8[>..] = [];
    var b2: u8[>..] = [];
    tv::each_row("vectors/go_readahead_1.txt") { r: tv::Row& => r.next_int(); b1.append(r.next()); };
    tv::each_row("vectors/go_readahead_2.txt") { r: tv::Row& => r.next_int(); b2.append(r.next()); };
    var r = multipart::Reader { .. };
    multipart::init(r, "MyBoundary");
    multipart::feed(r, b1);
    var data: u8[>..] = [];
    tv::check_int("readahead part 1", multipart::next(r, data), multipart::EV_PART);
    tv::check_eq("readahead part 1 header", textproto::get(r.header, "Foo-Bar"), "baz");
    tv::check_int("readahead part 1 end", read_part(r, data), multipart::EV_PART_END);
    tv::check_eq("readahead part 1 body", data, "Body");
    tv::check_int("readahead waits for part 2", multipart::next(r, data), multipart::EV_NEED_MORE);
    multipart::feed(r, b2);
    tv::check_int("readahead part 2", multipart::next(r, data), multipart::EV_PART);
    tv::check_eq("readahead part 2 header", textproto::get(r.header, "Foo-Bar"), "bop");
    tv::check_int("readahead part 2 end", read_part(r, data), multipart::EV_PART_END);
    tv::check_eq("readahead part 2 body", data, "Body 2");
    tv::check_int("readahead end", multipart::next(r, data), multipart::EV_END);
}

// TestQuotedPrintableEncoding and TestRawPart, beyond the parse above.
fn quoted_printable() {
    var body: u8[>..] = [];
    var go: u8[>..] = [];
    tv::each_row("vectors/go_qp_part.txt") { r: tv::Row& => r.next_int(); body.append(r.next()); go.append(results_text(r)); };
    for cte in ["quoted-printable", "Quoted-PRINTABLE"] {
        var b: u8[>..] = [];
        format_replaced(b, body, "quoted-printable", cte);
        // Go's result for its own spelling is the result for both
        tv::check_eq(str("qp part ", cte), parse_fields(b, "0016e68ee29c5d515f04cedf6733", FEED_RANDOM, false), go);
        var r = multipart::Reader { .. };
        multipart::init(r, "0016e68ee29c5d515f04cedf6733");
        multipart::feed(r, b);
        multipart::finish(r);
        var data: u8[>..] = [];
        { let ev = multipart::next(r, data); tv::check_int(str("qp part ", cte), ev, multipart::EV_PART); }
        tv::check(str("qp part: no Content-Transfer-Encoding ", cte), !textproto::has(r.header, "Content-Transfer-Encoding"));
        { let ev = read_part(r, data); tv::check_int(str("qp part end ", cte), ev, multipart::EV_PART_END); }
        tv::check_int(str("qp part error ", cte), r.part_err, 0);
        tv::check(str("qp part body ", cte), starts_with(data, "words words") && find(data, "=") < 0);
    }
    var raw: u8[>..] = [];
    tv::each_row("vectors/go_raw_part.txt") { r: tv::Row& => r.next_int(); raw.append(r.next()); };
    var r = multipart::Reader { .. };
    multipart::init(r, "0016e68ee29c5d515f04cedf6733");
    multipart::feed(r, raw);
    multipart::finish(r);
    var data: u8[>..] = [];
    r.raw = true;
    tv::check_int("raw part", multipart::next(r, data), multipart::EV_PART);
    tv::check("raw part keeps Content-Transfer-Encoding", textproto::has(r.header, "Content-Transfer-Encoding"));
    tv::check_int("raw part end", read_part(r, data), multipart::EV_PART_END);
    tv::check_eq("raw part body", data, "<div dir=3D\"ltr\">Hello World.</div>");
    r.raw = false;
    tv::check_int("decoded part", multipart::next(r, data), multipart::EV_PART);
    tv::check("decoded part: no Content-Transfer-Encoding", !textproto::has(r.header, "Content-Transfer-Encoding"));
    tv::check_int("decoded part end", read_part(r, data), multipart::EV_PART_END);
    tv::check_eq("decoded part body", data, "<div dir=\"ltr\">Hello World.</div>");
}

// TestNested: a part that is itself multipart.
fn nested() {
    var f: u8[>..] = [];
    tv::check("nested-mime read", read_file("vectors/go_nested-mime", f));
    var outer = multipart::Reader { .. };
    multipart::init(outer, "e89a8ff1c1e83553e304be640612");
    multipart::feed(outer, f);
    multipart::finish(outer);
    var data: u8[>..] = [];
    tv::check_int("nested outer part 1", multipart::next(outer, data), multipart::EV_PART);
    tv::check_int("nested outer part 1 end", read_part(outer, data), multipart::EV_PART_END);
    var inner = multipart::Reader { .. };
    multipart::init(inner, "e89a8ff1c1e83553e004be640610");
    multipart::feed(inner, data);
    multipart::finish(inner);
    var d2: u8[>..] = [];
    tv::check_int("nested text/plain", multipart::next(inner, d2), multipart::EV_PART);
    tv::check_int("nested text/plain end", read_part(inner, d2), multipart::EV_PART_END);
    tv::check_eq("nested text/plain body", d2, "*body*\r\n");
    tv::check_int("nested text/html", multipart::next(inner, d2), multipart::EV_PART);
    tv::check_int("nested text/html end", read_part(inner, d2), multipart::EV_PART_END);
    tv::check_eq("nested text/html body", d2, "<b>body</b>\r\n");
    tv::check_int("nested inner end", multipart::next(inner, d2), multipart::EV_END);
    tv::check_int("nested image", multipart::next(outer, data), multipart::EV_PART);
    tv::check_int("nested image end", read_part(outer, data), multipart::EV_PART_END);
    tv::check_int("nested image error", outer.part_err, 0);
    tv::check_int("nested outer end", multipart::next(outer, data), multipart::EV_END);
}

// TestParseAllSizes: a field of every size up to 5 KiB, written and read back.
fn all_sizes() {
    var body: u8[>..] = [];
    for i in 5 << 10 { body.push('a'); }
    var bad = 0;
    for size in 5 << 10 {
        var w = multipart::new_writer();
        var out: u8[>..] = [];
        multipart::create_form_field(w, out, "f");
        out.append(body[..size]);
        multipart::create_form_field(w, out, "key");
        out.append("val");
        multipart::close(w, out);
        var r = multipart::Reader { .. };
        multipart::init(r, multipart::boundary(w));
        multipart::feed(r, out);
        multipart::finish(r);
        var data: u8[>..] = [];
        var ok = multipart::next(r, data) == multipart::EV_PART && read_part(r, data) == multipart::EV_PART_END &&
                 data.len == size;
        ok = ok && multipart::next(r, data) == multipart::EV_PART && read_part(r, data) == multipart::EV_PART_END &&
             data == "val" && multipart::next(r, data) == multipart::EV_END;
        if !ok { bad++; if bad < 5 { print("      size ", size); } }
    }
    tv::check_int("TestParseAllSizes failures", bad, 0);
}

// roundTripParseTest: Go's formData parts through the writer and back.
fn round_trip() {
    var w = multipart::new_writer();
    var out: u8[>..] = [];
    let names = ["empty", "lf", "cr", "crlf", "foo"];
    let values = ["", "\n", "\r", "\r\n", "bar"];
    for i in names.len {
        multipart::create_part(w, out, [mime::KV { key: "Content-Type", value: "text/plain; charset=ISO-8859-1" },
                                        mime::KV { key: "Content-Disposition", value: str("form-data; name=", names[i]) }]);
        out.append(values[i]);
    }
    multipart::close(w, out);
    var r = multipart::Reader { .. };
    multipart::init(r, multipart::boundary(w));
    multipart::feed(r, out);
    multipart::finish(r);
    var data: u8[>..] = [];
    for i in names.len {
        { let ev = multipart::next(r, data); tv::check_int(str("round trip part ", names[i]), ev, multipart::EV_PART); }
        tv::check_eq(str("round trip name ", names[i]), multipart::form_name(r), names[i]);
        tv::check_eq(str("round trip type ", names[i]), textproto::get(r.header, "Content-Type"), "text/plain; charset=ISO-8859-1");
        { let ev = read_part(r, data); tv::check_int(str("round trip end ", names[i]), ev, multipart::EV_PART_END); }
        tv::check_eq(str("round trip body ", names[i]), data, values[i]);
    }
    tv::check_int("round trip end", multipart::next(r, data), multipart::EV_END);
}

// A part's header fails as soon as the line that makes it fail (and the
// byte after it, where a continuation could follow) has come, without the
// end of the input, as Go's NextPart does.
fn header_fails_early() {
    let cases = ["--b\r\nBad line\r\n", "--b\r\nK\x01: v\r\nX", "--b\r\nA: 1\r\nB: 2\r\nC: 3\r\nD"];
    let wants = ["malformed MIME header: missing colon: \"Bad line\"", "malformed MIME header line: \"K\\x01: v\"",
                 "multipart: message too large"];
    for i in cases.len {
        for bytewise in [false, true] {
            var r = multipart::Reader { .. };
            multipart::init(r, "b");
            if i == 2 { r.max_headers = 2; }
            let body = cases[i];
            var data: u8[>..] = [];
            var ev = multipart::EV_NEED_MORE;
            var fed = 0;
            while ev == multipart::EV_NEED_MORE && fed < body.len {
                let n = if bytewise { 1 } else { body.len };
                multipart::feed(r, body[fed..fed + n]);
                fed += n;
                ev = multipart::next(r, data);
            }
            tv::check_int(str("fails early ", i, " ", bytewise), ev, multipart::EV_ERROR);
            tv::check_int(str("fails at the last byte ", i, " ", bytewise), fed, body.len);
            var m: u8[>..] = [];
            multipart::message(r, m);
            tv::check_eq(str("fails early message ", i), m, wants[i]);
        }
    }
    // and a header line that may still go on waits
    var r = multipart::Reader { .. };
    multipart::init(r, "b");
    multipart::feed(r, "--b\r\nK\x01: v\r\n");
    var data: u8[>..] = [];
    { let ev = multipart::next(r, data); tv::check_int("a possible continuation waits", ev, multipart::EV_NEED_MORE); }
}

// TestNoBoundary.
fn no_boundary() {
    var r = multipart::Reader { .. };
    multipart::init(r, "");
    multipart::finish(r);
    var data: u8[>..] = [];
    tv::check_int("no boundary", multipart::next(r, data), multipart::EV_ERROR);
    var m: u8[>..] = [];
    multipart::message(r, m);
    tv::check_eq("no boundary message", m, "multipart: boundary is empty");
}

fn main() {
    parse_tests();
    boundary_line();
    test_multipart("\r\n", false);
    test_multipart("\n", false);
    test_multipart("\r\n", true);
    line_endings();
    line_limit();
    readahead();
    quoted_printable();
    nested();
    all_sizes();
    round_trip();
    no_boundary();
    header_fails_early();
    tv::done("multipart");
}
