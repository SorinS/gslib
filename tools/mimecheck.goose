// mimecheck: the Goose side of scripts/differential.py. Reads a file of
// cases (one per line, fields separated by '|', escaped \xHH, \N for nil;
// the first field the kind) and writes one line of results per case, as
// tools/mimeoracle's serve mode does for Go (see tools/mimeoracle/serve.go
// for the kinds). Multipart bodies and forms are fed to the reader in
// pieces of pseudo-random sizes (seeded per case), so the results also say
// that the way the input comes does not change them.
//
//     goose run tools/mimecheck.goose -- cases.txt > results.txt

import std;
import os;
import mime from "..";
import mime.encodedword;
import mime.quotedprintable;
import mime.textproto;
import mime.multipart;
import mime.formdata;
import mime.types;

fn unhex(c: u8) -> u8 {
    if c >= '0' && c <= '9' { return c - '0'; }
    if c >= 'a' && c <= 'f' { return c - 'a' + 10; }
    return c - 'A' + 10;
}

struct FSpan { pos: i64, end: i64 }

root struct Case {
    buf: u8[>..] = [],
    spans: FSpan[>..] = [],
}

fn field(c: Case&, i: i64) -> const u8[:] { c.buf[c.spans[i].pos..c.spans[i].end] }

fn decode_line(c: Case&, line: const u8[:]) {
    c.buf.clear();
    c.spans.clear();
    var start = 0;
    var i = 0;
    while i <= line.len {
        if i == line.len || line[i] == '|' {
            c.spans.push(FSpan { pos: start, end: c.buf.len });
            start = c.buf.len;
            i++;
            continue;
        }
        if line[i] == '\\' && i + 3 < line.len && line[i + 1] == 'x' {
            c.buf.push((unhex(line[i + 2]) << 4) | unhex(line[i + 3]));
            i += 4;
            continue;
        }
        if line[i] == '\\' && i + 1 < line.len && line[i + 1] == 'N' { i += 2; continue; }
        c.buf.push(line[i]);
        i++;
    }
}

// A field, after a '|' (main drops the line's first one).
fn put(out: u8[>..]&, s: const u8[:], first: bool) {
    out.push('|');
    let hex = "0123456789abcdef";
    for c in s {
        if c < 0x20 || c > 0x7e || c == '\\' || c == '|' {
            out.append("\\x"); out.push(hex[c >> 4]); out.push(hex[c & 15]);
        } else {
            out.push(c);
        }
    }
}

fn put_int(out: u8[>..]&, v: i64) { put(out, str(v), false); }

fn put_header(out: u8[>..]&, h: const textproto::Header&) {
    var keys: const u8[:][>..] = [];
    for f in h.fields {
        var dup = false;
        for k in keys { if k == f.key { dup = true; } }
        if !dup { keys.push(f.key); }
    }
    sort(keys) { a, b => compare(a, b) < 0 };
    put_int(out, keys.len);
    for k in keys {
        put(out, k, false);
        var n = 0;
        for f in h.fields { if f.key == k { n++; } }
        put_int(out, n);
        for f in h.fields { if f.key == k { put(out, f.value, false); } }
    }
}

fn parse_i64(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s);
    return v;
}

fn next_size(seed: u64&, left: i64) -> i64 {
    seed = seed * 6364136223846793005 + 1442695040888963407;
    let n = ((seed >> 33) % 97) as i64 + 1;
    return ::min(n, left);
}

fn multipart_case(out: u8[>..]&, boundary: const u8[:], raw: const u8[:], body: const u8[:], seed0: u64) {
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    var seed = seed0;
    var fed = 0;
    var data: u8[>..] = [];
    var parts = 0;
    loop {
        r.raw = parts < raw.len && raw[parts] == '1';
        let ev = multipart::next(r, data);
        if ev == multipart::EV_NEED_MORE {
            if fed == body.len { multipart::finish(r); continue; }
            let n = next_size(seed, body.len - fed);
            multipart::feed(r, body[fed..fed + n]);
            fed += n;
            continue;
        }
        if ev == multipart::EV_PART { data.clear(); continue; }
        if ev == multipart::EV_DATA { continue; }
        if ev == multipart::EV_PART_END {
            parts++;
            put_header(out, r.header);
            put(out, multipart::form_name(r), false);
            put(out, multipart::file_name(r), false);
            put(out, data, false);
            put(out, r.part_err_text, false);
            if r.part_err != 0 { put(out, "stopped", false); return; }
            continue;
        }
        var m: u8[>..] = [];
        if ev == multipart::EV_ERROR { multipart::message(r, m); }
        put(out, m, true);
        return;
    }
}

fn form_case(out: u8[>..]&, boundary: const u8[:], max_memory: i64, body: const u8[:], seed0: u64) {
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    var f = multipart::Form { .. };
    multipart::form_init(f, max_memory);
    var seed = seed0;
    var fed = 0;
    var rc = 0;
    loop {
        rc = multipart::read_form(r, f);
        if rc != multipart::NEED_MORE { break; }
        if fed == body.len { multipart::finish(r); continue; }
        let n = next_size(seed, body.len - fed);
        multipart::feed(r, body[fed..fed + n]);
        fed += n;
    }
    if rc != 0 {
        var m: u8[>..] = [];
        if rc == r.err && rc != mime::ERR_MULTIPART_TOO_LARGE { multipart::message(r, m); }
        else if rc == r.part_err { m.append(r.part_err_text); }
        else { m.append(mime::error_text(rc)); }
        put(out, m, true);
        return;
    }
    put(out, "", true);
    var names: const u8[:][>..] = [];
    for i in multipart::value_count(f) {
        let n, v = multipart::value_at(f, i);
        var dup = false;
        for k in names { if k == n { dup = true; } }
        if !dup { names.push(n); }
    }
    sort(names) { a, b => compare(a, b) < 0 };
    put_int(out, names.len);
    for k in names {
        put(out, k, false);
        var c = 0;
        multipart::each_form_value(f, k) { c++; };
        put_int(out, c);
        multipart::each_form_value(f, k) { put(out, it, false); };
    }
    var fnames: const u8[:][>..] = [];
    for i in multipart::file_count(f) {
        let n = multipart::file_field_name(f, i);
        var dup = false;
        for k in fnames { if k == n { dup = true; } }
        if !dup { fnames.push(n); }
    }
    sort(fnames) { a, b => compare(a, b) < 0 };
    put_int(out, fnames.len);
    for k in fnames {
        put(out, k, false);
        var c = 0;
        for i in multipart::file_count(f) { if multipart::file_field_name(f, i) == k { c++; } }
        put_int(out, c);
        for i in multipart::file_count(f) {
            if multipart::file_field_name(f, i) != k { continue; }
            put(out, multipart::file_filename(f, i), false);
            put_int(out, multipart::file_size(f, i));
            var content: u8[>..] = [];
            multipart::file_content(f, i, content);
            put(out, content, false);
            put(out, if multipart::file_on_disk(f, i) { "1" } else { "0" }, false);
        }
    }
    multipart::remove_all(f);
}

fn answer(c: Case&, out: u8[>..]&, n: i64) {
    let kind = field(c, 0);
    if kind == "mt" {
        let mt = mime::parse_media_type(field(c, 1));
        put(out, mime::error_text(mt.err), true);
        put(out, mt.typ, false);
        put_int(out, mt.params.len);
        for p in mt.params { put(out, p.name, false); put(out, p.value, false); }
    } else if kind == "fmt" {
        var kvs: mime::KV[>..] = [];
        let k = parse_i64(field(c, 2));
        for i in k { kvs.push(mime::KV { key: field(c, 3 + 2 * i), value: field(c, 4 + 2 * i) }); }
        put(out, mime::format_media_type(field(c, 1), kvs), true);
    } else if kind == "ew" {
        put(out, mime::encode_word(field(c, 1)[0], field(c, 2), field(c, 3)), true);
    } else if kind == "dw" {
        var s: u8[>..] = [];
        mime::decode_word(s, field(c, 1));
        var m: u8[>..] = [];
        mime::word_error(m, field(c, 1));
        put(out, s, true);
        put(out, m, false);
    } else if kind == "dh" {
        var s: u8[>..] = [];
        mime::decode_header(s, field(c, 1));
        var m: u8[>..] = [];
        mime::header_error(m, field(c, 1));
        put(out, s, true);
        put(out, m, false);
    } else if kind == "qpr" {
        var s: u8[>..] = [];
        var m: u8[>..] = [];
        quotedprintable::decode_all(s, field(c, 1), m);
        put(out, s, true);
        put(out, m, false);
    } else if kind == "qpw" {
        var s: u8[>..] = [];
        quotedprintable::encode_all(s, field(c, 2), field(c, 1) == "1");
        put(out, s, true);
    } else if kind == "hdr" || kind == "hdrl" {
        let lim_mem = if kind == "hdr" { textproto::MAX_INT64 } else { parse_i64(field(c, 1)) };
        let lim_n = if kind == "hdr" { textproto::MAX_INT64 } else { parse_i64(field(c, 2)) };
        let data = if kind == "hdr" { field(c, 1) } else { field(c, 3) };
        var h = textproto::new_header();
        var d: u8[>..] = [];
        let code, end = textproto::read_mime_header_at(data, 0, true, lim_mem, lim_n, h, d);
        var m: u8[>..] = [];
        if code != 0 { textproto::error_message(m, code, d); }
        put(out, m, true);
        put_header(out, h);
    } else if kind == "mp" {
        multipart_case(out, field(c, 1), field(c, 2), field(c, 3), n as u64);
    } else if kind == "form" {
        form_case(out, field(c, 1), parse_i64(field(c, 2)), field(c, 3), n as u64);
    } else if kind == "type" {
        put(out, mime::type_by_extension(field(c, 1)), true);
    } else if kind == "exts" {
        var e: u8[][>..] = [];
        let rc = mime::extensions_by_type(e, field(c, 1));
        put(out, mime::error_text(rc), true);
        put_int(out, e.len);
        for x in e { put(out, x, false); }
    } else if kind == "cd" {
        put(out, multipart::file_content_disposition(field(c, 1), field(c, 2)), true);
    } else if kind == "sb" {
        var w = multipart::new_writer();
        let rc = multipart::set_boundary(w, field(c, 1));
        put(out, mime::error_text(rc), true);
        if rc == 0 { put(out, multipart::form_data_content_type(w), false); } else { put(out, "", false); }
    } else {
        abort(str("mimecheck: unknown kind ", kind));
    }
}

fn main() {
    let args = args();
    if args.len != 2 { write_stderr("usage: mimecheck cases.txt\n"); exit(2); }
    var text: u8[>..] = [];
    if !read_file(args[1], text) { write_stderr(str("mimecheck: cannot read ", args[1], "\n")); exit(1); }
    var c = Case { .. };
    var out: u8[>..] = [];
    var line: u8[>..] = [];
    var n = 0;
    each_split(text, '\n') {
        if it.len > 0 {
            n++;
            decode_line(c, it);
            line.clear();
            answer(c, line, n);
            if line.len > 0 { out.append(line[1..]); }
            out.push('\n');
            if out.len > (1 << 20) { write_stdout(out); out.clear(); }
        }
    };
    write_stdout(out);
}
