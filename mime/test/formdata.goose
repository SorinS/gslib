// mime.formdata (ReadForm) against Go's formdata_test.go: its messages
// (test/vectors, extracted with Go's own ReadForm of each, which the form
// read here must equal) and TestReadFormLimits' table; TestReadForm,
// TestReadFormWithNamelessFile, TestReadFormWitFileNameMaxMemoryOverflow,
// TestReadFormMaxMemoryOverflow, TestReadFormWithTextContentType,
// TestReadForm_NoReadAfterEOF, TestReadForm_NonFileMaxMemory,
// TestReadForm_MetadataTooLarge, TestReadForm_ManyFiles_Distinct,
// TestReadFormEndlessHeaderLine ported.

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.textproto;
import gslib.mime.multipart;
import gslib.mime.formdata;
import gslib.crypto.bignum.entropy;
import tv;

let MAX_INT64: i64 = 9223372036854775807;

// Every field after a '|', so that an empty field is never lost.
fn push_field(out: u8[>..]&, s: const u8[:]) {
    out.push('|');
    tv::escape(out, s);
}

// The form as the oracle flattens Go's: the error, the values by name,
// the files by name (file name, size, content, on disk).
fn form_text(f: multipart::Form&, rc: i64, r: multipart::Reader&) -> u8[>..] {
    var out: u8[>..] = [];
    if rc != 0 {
        var m: u8[>..] = [];
        if rc == r.err && rc != mime::ERR_MULTIPART_TOO_LARGE { multipart::message(r, m); } else { m.append(mime::error_text(rc)); }
        push_field(out, m);
        return out;
    }
    push_field(out, "");
    var names: const u8[:][>..] = [];
    for i in multipart::value_count(f) {
        let n, v = multipart::value_at(f, i);
        var dup = false;
        for k in names { if k == n { dup = true; } }
        if !dup { names.push(n); }
    }
    sort(names) { a, b => compare(a, b) < 0 };
    push_field(out, str(names.len));
    for k in names {
        push_field(out, k);
        var c = 0;
        multipart::each_form_value(f, k) { c++; };
        push_field(out, str(c));
        multipart::each_form_value(f, k) { push_field(out, it); };
    }
    var fnames: const u8[:][>..] = [];
    for i in multipart::file_count(f) {
        let n = multipart::file_field_name(f, i);
        var dup = false;
        for k in fnames { if k == n { dup = true; } }
        if !dup { fnames.push(n); }
    }
    sort(fnames) { a, b => compare(a, b) < 0 };
    push_field(out, str(fnames.len));
    for k in fnames {
        push_field(out, k);
        var c = 0;
        for i in multipart::file_count(f) { if multipart::file_field_name(f, i) == k { c++; } }
        push_field(out, str(c));
        for i in multipart::file_count(f) {
            if multipart::file_field_name(f, i) != k { continue; }
            push_field(out, multipart::file_filename(f, i));
            push_field(out, str(multipart::file_size(f, i)));
            var content: u8[>..] = [];
            multipart::file_content(f, i, content);
            push_field(out, content);
            push_field(out, if multipart::file_on_disk(f, i) { "1" } else { "0" });
        }
    }
    return out;
}

fn results_text(r: tv::Row&) -> u8[>..] {
    r.to_results();
    var out: u8[>..] = [];
    while r.has_more() { push_field(out, r.next()); }
    return out;
}

// Reads body (newlines made CRLF) as ReadForm(max_memory); also fed in
// pieces, which must read the same.
fn read_text(body0: const u8[:], max_memory: i64, chunked: bool) -> u8[>..] {
    var body: u8[>..] = [];
    format_replaced(body, body0, "\n", "\r\n");
    var r = multipart::Reader { .. };
    multipart::init(r, "MyBoundary");
    var f = multipart::Form { .. };
    multipart::form_init(f, max_memory);
    var rc = 0;
    if chunked {
        var fed = 0;
        loop {
            rc = multipart::read_form(r, f);
            if rc != multipart::NEED_MORE { break; }
            if fed == body.len { multipart::finish(r); continue; }
            let n = ::min(7, body.len - fed);
            multipart::feed(r, body[fed..fed + n]);
            fed += n;
        }
    } else {
        multipart::feed(r, body);
        multipart::finish(r);
        rc = multipart::read_form(r, f);
    }
    let t = form_text(f, rc, r);
    multipart::remove_all(f);
    return t;
}

fn messages() {
    for name in ["form_message", "form_nameless", "form_filename", "form_textct"] {
        tv::each_row(str("vectors/go_", name, ".txt")) { r: tv::Row& =>
            r.next_int();
            let body = r.next();
            let go = results_text(r);
            let mm = if name == "form_filename" { MAX_INT64 } else { 25 };
            tv::check_eq(str("ReadForm ", name), read_text(body, mm, false), go);
            tv::check_eq(str("ReadForm fed in pieces ", name), read_text(body, mm, true), go);
        };
    }
    // TestReadFormMaxMemoryOverflow: messageWithTextContentType with MaxInt64
    tv::each_row("vectors/go_form_textct.txt") { r: tv::Row& =>
        r.next_int();
        let body = r.next();
        let t = read_text(body, MAX_INT64, false);
        tv::check("ReadForm(MaxInt64) text content type", starts_with(t, "||1|texta|1|foo|0"));
    };
}

// TestReadForm_NoReadAfterEOF: no CRLF after the final boundary.
fn no_read_after_eof() {
    var f = multipart::Form { .. };
    let body = "\n-----------------------------8d345eef0d38dc9\nContent-Disposition: form-data; name=\"version\"\n\n171\n-----------------------------8d345eef0d38dc9--";
    var b: u8[>..] = [];
    format_replaced(b, body, "\n", "\r\n");
    let rc = multipart::read_form_bytes(f, b, "---------------------------8d345eef0d38dc9", 32 << 20);
    tv::check_int("no read after EOF", rc, 0);
    let v, ok = multipart::form_value(f, "version");
    tv::check_eq("no read after EOF value", v, "171");
}

// TestReadForm_NonFileMaxMemory: a 10 MiB value is refused below some
// limit and read whole above it; the limit is at least 128.
fn non_file_max_memory() {
    var big: u8[>..] = [];
    for i in 10 << 20 { big.push('1'); }
    var body: u8[>..] = [];
    body.append("--MyBoundary\r\nContent-Disposition: form-data; name=\"largetext\"\r\n\r\n");
    body.append(big);
    body.append("\r\n--MyBoundary--\r\n");
    var first_ok = -1;
    var mm = 0;
    while mm < 256 {
        var f = multipart::Form { .. };
        if multipart::read_form_bytes(f, body, "MyBoundary", mm) == 0 {
            let v, ok = multipart::form_value(f, "largetext");
            tv::check("largetext value", v == big);
            first_ok = mm;
            break;
        }
        mm += 16;
    }
    tv::check("non-file max memory: succeeds below 256", first_ok >= 0);
    tv::check("non-file max memory: fails below 128", first_ok >= 128);
}

// TestReadForm_MetadataTooLarge.
fn metadata_too_large() {
    var name: u8[>..] = [];
    for i in 10 << 20 { name.push('a'); }
    {
        var w = multipart::new_writer();
        var b: u8[>..] = [];
        multipart::create_form_field(w, b, name);
        b.append("value");
        multipart::close(w, b);
        var f = multipart::Form { .. };
        tv::check_int("large name", multipart::read_form_bytes(f, b, multipart::boundary(w), 0), mime::ERR_MULTIPART_TOO_LARGE);
    }
    {
        var w = multipart::new_writer();
        var b: u8[>..] = [];
        multipart::create_part(w, b, [mime::KV { key: "Content-Disposition", value: "form-data; name=\"a\"" },
                                      mime::KV { key: "X-Foo", value: name }]);
        b.append("value");
        multipart::close(w, b);
        var f = multipart::Form { .. };
        tv::check_int("large MIME header", multipart::read_form_bytes(f, b, multipart::boundary(w), 0), mime::ERR_MULTIPART_TOO_LARGE);
    }
    {
        var w = multipart::new_writer();
        var b: u8[>..] = [];
        for i in 110000 { multipart::create_form_field(w, b, "f"); b.append("v"); }
        multipart::close(w, b);
        var f = multipart::Form { .. };
        tv::check_int("many parts", multipart::read_form_bytes(f, b, multipart::boundary(w), 0), mime::ERR_MULTIPART_TOO_LARGE);
    }
}

// TestReadForm_ManyFiles_Distinct: ReadForm(0) puts every file on disk,
// one temporary file each (Go's GODEBUG multipartfiles=distinct), and
// RemoveAll removes them.
fn many_files() {
    var dir: u8[>..] = [];
    if !::env("TMPDIR", dir) || dir.len == 0 { dir.clear(); dir.append("/tmp"); }
    if dir[dir.len - 1] != '/' { dir.push('/'); }
    var rnd: u8[6] = [0; 6];
    bignum::random_bytes(rnd);
    dir.append("mimegoose-test-");
    for b in rnd { dir.push(mime::LOWERHEX[b >> 4]); dir.push(mime::LOWERHEX[b & 15]); }
    tv::check("temp dir", ::make_dir(dir));
    var w = multipart::new_writer();
    var b: u8[>..] = [];
    for i in 10 { multipart::create_form_file(w, b, str(i), str(i)); b.append(str(i)); }
    multipart::close(w, b);
    var f = multipart::Form { .. };
    f.tmp_dir.append(dir);
    var r = multipart::Reader { .. };
    multipart::init(r, multipart::boundary(w));
    multipart::feed(r, b);
    multipart::finish(r);
    multipart::form_init(f, 0);
    tv::check_int("many files", multipart::read_form(r, f), 0);
    for i in 10 {
        let k = multipart::form_file(f, str(i));
        tv::check(str("file ", i), k >= 0 && multipart::file_on_disk(f, k));
        var c: u8[>..] = [];
        if k >= 0 { multipart::file_content(f, k, c); }
        tv::check_eq(str("file content ", i), c, str(i));
    }
    var names: u8[>..] = [];
    ::list_dir(dir, names);
    var n = 0;
    each_split(names, '\n') { if it.len > 0 { n++; } };
    tv::check_int("temp files", n, 10);
    tv::check("remove all", multipart::remove_all(f));
    names.clear();
    ::list_dir(dir, names);
    tv::check_eq("temp files removed", names, "");
    ::delete_dir(dir);
}

// TestReadFormLimits.
fn limits() {
    tv::each_row("vectors/go_form_limits.txt") { row: tv::Row& =>
        let values = row.next_int();
        let files = row.next_int();
        let extra = row.next_int();
        let nil_err = row.next_is_nil();
        let want_err = if nil_err { "" } else { row.next() };
        let godebug = row.next();
        var w = multipart::new_writer();
        var b: u8[>..] = [];
        for i in values { multipart::create_form_field(w, b, str("field", i)); format(b, "value ", i); }
        for i in files {
            var h: mime::KV[>..] = [];
            let cd = str("form-data; name=\"file", i, "\"; filename=\"file", i, "\"");
            var keys: u8[][>..] = [];
            for j in extra { keys.push(str("K", j)); }
            h.push(mime::KV { key: "Content-Disposition", value: cd });
            h.push(mime::KV { key: "Content-Type", value: "application/octet-stream" });
            for k in keys { h.push(mime::KV { key: k, value: "v" }); }
            multipart::create_part(w, b, h);
            format(b, "value ", i);
        }
        multipart::close(w, b);
        var f = multipart::Form { .. };
        var r = multipart::Reader { .. };
        multipart::init(r, multipart::boundary(w));
        multipart::feed(r, b);
        multipart::finish(r);
        multipart::form_init(f, 1 << 10);
        if starts_with(godebug, "multipartmaxparts=") { let n, ok = parse_int(godebug[18..]); f.max_parts = n; }
        if starts_with(godebug, "multipartmaxheaders=") { let n, ok = parse_int(godebug[20..]); f.max_headers = n; }
        let rc = multipart::read_form(r, f);
        multipart::remove_all(f);
        tv::check_eq(str("limits values=", values, " files=", files, " extra=", extra, " ", godebug), mime::error_text(rc), want_err);
    };
}

// TestReadFormEndlessHeaderLine: an endless line in a part's header is
// refused, not buffered without end.
fn endless_header_line() {
    for prefix in ["X-", "X-Header: ", "X-Header: foo\r\n  "] {
        var r = multipart::Reader { .. };
        multipart::init(r, "boundary");
        var f = multipart::Form { .. };
        multipart::form_init(f, 1 << 20);
        multipart::feed(r, str("--boundary\r\nContent-Disposition: form-data; name=\"a\"\r\nContent-Type: text/plain\r\n", prefix));
        var xs: u8[>..] = [];
        for i in 65536 { xs.push('X'); }
        var fed = 0;
        var rc = multipart::read_form(r, f);
        while rc == multipart::NEED_MORE && fed < (64 << 20) {
            multipart::feed(r, xs);
            fed += xs.len;
            rc = multipart::read_form(r, f);
        }
        tv::check_int(str("endless header line ", prefix), rc, mime::ERR_MULTIPART_TOO_LARGE);
        tv::check(str("endless header line read little ", prefix), fed <= (24 << 20));
    }
}

fn main() {
    messages();
    no_read_after_eof();
    non_file_max_memory();
    metadata_too_large();
    many_files();
    limits();
    endless_header_line();
    tv::done("formdata");
}
