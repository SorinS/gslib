// mime.formdata: multipart/form-data (RFC 7578) read into a Form, as Go's
// Reader.ReadForm does it, limits and all:
//
//   - at most max_memory bytes of file contents are kept in memory; a file
//     that would pass what is left of that goes to a temporary file
//     (TMPDIR, else /tmp; "multipart-" and 16 random hex digits), all its
//     bytes;
//   - names, values and the headers of files count against max_memory
//     plus 10 MiB, with Go's overheads (200 bytes a name, 400 + 200 a key
//     for a header, 100 a file); passing that is ERR_MULTIPART_TOO_LARGE;
//   - at most 1000 parts and 10000 header fields in all (Go's GODEBUG
//     multipartmaxparts and multipartmaxheaders; max_parts, max_headers);
//   - parts without a form name are skipped.
//
// read_form consumes a Reader's events as its input comes, so a body can
// be fed while it is read; it answers NEED_MORE until the body has ended.
// On an error the form is emptied and its temporary files removed, as Go
// returns no form.

namespace multipart;

import std;
import os;
import mime;
import textproto;

let NEED_MORE: i64 = -1;

let MAX_PARTS: i64 = 1000;          // GODEBUG multipartmaxparts default

struct FSpan { pos: i64, end: i64 }

// A field's value.
struct FormValue { name: FSpan, value: FSpan }

// A file: its field name, file name, header (fields hfirst..hfirst+hcount
// of the form's hfields), size, and its content (in the form's text) or
// the temporary file that holds it.
struct FileHeader {
    name: FSpan,
    filename: FSpan,
    hfirst: i64,
    hcount: i64,
    size: i64,
    content: FSpan,
    tmpfile: FSpan,         // empty when the content is in memory
}

struct FormField { key: FSpan, value: FSpan }

let K_NONE: i64 = 0;        // between parts
let K_SKIP: i64 = 1;        // a part without a form name
let K_VALUE: i64 = 2;
let K_FILE: i64 = 3;

root struct Form {
    text: u8[>..] = [],                  // names, values, file names, headers, contents, paths
    values: FormValue[>..] = [],
    files: FileHeader[>..] = [],
    hfields: FormField[>..] = [],
    // Go's limits, before read_form starts (form_init sets them from max_memory)
    max_parts: i64 = MAX_PARTS,
    max_headers: i64 = MAX_MIME_HEADERS,
    tmp_dir: u8[>..] = [],               // "" for TMPDIR, else /tmp
    // the reading
    started: bool = false,
    done: bool = false,
    err: i64 = 0,
    max_memory_bytes: i64 = 0,
    max_file_memory_bytes: i64 = 0,
    kind: i64 = K_NONE,
    part_start: i64 = 0,                 // where the current part's data starts in text
    part_bytes: i64 = 0,
    spill: u8[>..] = [],                 // the current file's temporary file, once it has one
    chunk: u8[>..] = [],
}

let MAX_INT64: i64 = 9223372036854775807;

// ReadForm(maxMemory)'s limits; call before read_form.
fn form_init(f: Form&, max_memory: i64) {
    remove_all(f);
    f.text.clear();
    f.values.clear();
    f.files.clear();
    f.hfields.clear();
    f.started = true;
    f.done = false;
    f.err = 0;
    f.kind = K_NONE;
    f.max_file_memory_bytes = max_memory;
    if f.max_file_memory_bytes == MAX_INT64 { f.max_file_memory_bytes--; }
    // maxMemory + 10 MiB, as Go computes it (wrapping, then clamped)
    let ten: i64 = 10 << 20;
    var mm = 0;
    if max_memory > MAX_INT64 - ten { mm = MAX_INT64; }
    else { mm = max_memory + ten; if mm <= 0 { mm = if max_memory < 0 { 0 } else { MAX_INT64 }; } }
    f.max_memory_bytes = mm;
}

fn span_text(f: const Form&, s: FSpan) -> const u8[:] { f.text[s.pos..s.end] }

fn add_text(f: Form&, s: const u8[:]) -> FSpan {
    let p = f.text.len;
    f.text.append(s);
    return FSpan { pos: p, end: f.text.len };
}

// mimeHeaderSize.
fn mime_header_size(h: const textproto::Header&) -> i64 {
    var size = 400;
    var i = 0;
    for f in h.fields {
        var first = true;
        var j = 0;
        for g in h.fields {
            if j >= i { break; }
            if g.key == f.key { first = false; break; }
            j++;
        }
        if first { size += f.key.len + 200; }
        size += f.value.len;
        i++;
    }
    return size;
}

fn fail(f: Form&, code: i64) -> i64 {
    f.err = code;
    f.done = true;
    remove_all(f);
    f.text.clear();
    f.values.clear();
    f.files.clear();
    f.hfields.clear();
    return code;
}

fn temp_dir(f: const Form&, out: u8[>..]&) {
    if f.tmp_dir.len > 0 { out.append(f.tmp_dir); return; }
    if !::env("TMPDIR", out) || out.len == 0 { out.clear(); out.append("/tmp"); }
}

// Moves the current file's bytes in memory to a new temporary file.
fn start_spill(f: Form&) -> bool {
    f.spill.clear();
    temp_dir(f, f.spill);
    if f.spill.len > 0 && f.spill[f.spill.len - 1] != '/' { f.spill.push('/'); }
    f.spill.append("multipart-");
    var rnd: u8[8] = [0; 8];
    mime::random_bytes(rnd);
    for b in rnd { f.spill.push(mime::LOWERHEX[b >> 4]); f.spill.push(mime::LOWERHEX[b & 15]); }
    if ::file_exists(f.spill) { return false; }
    if !::write_file(f.spill, f.text[f.part_start..]) { return false; }
    f.text.resize(f.part_start);
    return true;
}

// The current part's data so far: in f.text from part_start, or on disk.
fn take_data(f: Form&) -> i64 {
    let n = f.chunk.len;
    f.part_bytes += n;
    if f.kind == K_SKIP || n == 0 { return 0; }
    if f.kind == K_VALUE {
        f.text.append(f.chunk);
        if f.part_bytes > f.max_memory_bytes { return mime::ERR_MULTIPART_TOO_LARGE; }
        return 0;
    }
    if f.spill.len > 0 {
        if !::append_file(f.spill, f.chunk) { return mime::ERR_FILE; }
        return 0;
    }
    f.text.append(f.chunk);
    if f.part_bytes > f.max_file_memory_bytes && !start_spill(f) { return mime::ERR_FILE; }
    return 0;
}

// A part has begun: what Go does between NextPart and reading its body.
fn begin_part(f: Form&, r: const Reader&) -> i64 {
    if f.max_parts <= 0 { return mime::ERR_MULTIPART_TOO_LARGE; }
    f.max_parts--;
    let name = form_name(r);
    f.part_bytes = 0;
    f.spill.clear();
    if name.len == 0 { f.kind = K_SKIP; return 0; }
    let filename = file_name(r);
    f.max_memory_bytes -= name.len;
    f.max_memory_bytes -= 200;
    if f.max_memory_bytes < 0 { return mime::ERR_MULTIPART_TOO_LARGE; }
    if filename.len == 0 {
        f.kind = K_VALUE;
        let ns = add_text(f, name);
        f.values.push(FormValue { name: ns, value: FSpan { pos: 0, end: 0 } });
        f.part_start = f.text.len;
        return 0;
    }
    f.max_memory_bytes -= mime_header_size(r.header);
    f.max_memory_bytes -= 200;
    f.max_memory_bytes -= 100;
    if f.max_memory_bytes < 0 { return mime::ERR_MULTIPART_TOO_LARGE; }
    f.max_headers -= r.header.fields.len;
    f.kind = K_FILE;
    let ns = add_text(f, name);
    let fs = add_text(f, filename);
    let first = f.hfields.len;
    for h in r.header.fields {
        let k = add_text(f, h.key);
        let v = add_text(f, h.value);
        f.hfields.push(FormField { key: k, value: v });
    }
    f.files.push(FileHeader { name: ns, filename: fs, hfirst: first, hcount: r.header.fields.len, size: 0,
                              content: FSpan { pos: 0, end: 0 }, tmpfile: FSpan { pos: 0, end: 0 } });
    f.part_start = f.text.len;
    return 0;
}

// The part's body has ended.
fn end_form_part(f: Form&) -> i64 {
    if f.kind == K_VALUE {
        f.max_memory_bytes -= f.part_bytes;
        if f.max_memory_bytes < 0 { return mime::ERR_MULTIPART_TOO_LARGE; }
        f.values[f.values.len - 1].value = FSpan { pos: f.part_start, end: f.text.len };
    } else if f.kind == K_FILE {
        if f.spill.len == 0 && f.part_bytes > f.max_file_memory_bytes && !start_spill(f) { return mime::ERR_FILE; }
        let fh .= f.files[f.files.len - 1];
        fh.size = f.part_bytes;
        if f.spill.len > 0 {
            let at = f.text.len;
            f.text.append(f.spill);
            fh.tmpfile = FSpan { pos: at, end: f.text.len };
        } else {
            fh.content = FSpan { pos: f.part_start, end: f.text.len };
            f.max_file_memory_bytes -= f.part_bytes;
            f.max_memory_bytes -= f.part_bytes;
        }
    }
    f.kind = K_NONE;
    f.spill.clear();
    return 0;
}

// ReadForm: reads the parts r has (or will have) into the form. NEED_MORE
// until the input has ended (feed r, then call again); then 0, or an
// error code (r's message() for a reader error).
fn read_form(r: Reader&, f: Form&) -> i64 {
    if !f.started { form_init(f, 32 << 20); }
    if f.done { return f.err; }
    loop {
        r.max_header_bytes = f.max_memory_bytes;
        r.max_headers = f.max_headers;
        f.chunk.clear();
        let ev = next(r, f.chunk);
        if ev == EV_NEED_MORE { return NEED_MORE; }
        if ev == EV_END {
            if f.kind != K_NONE { return fail(f, mime::ERR_MULTIPART_TOO_LARGE); }   // not reached: END follows PART_END
            f.done = true;
            return 0;
        }
        if ev == EV_ERROR { return fail(f, r.err); }
        if ev == EV_PART {
            let rc = begin_part(f, r);
            if rc != 0 { return fail(f, rc); }
            continue;
        }
        let rc = take_data(f);
        if rc != 0 { return fail(f, rc); }
        if ev == EV_PART_END {
            if r.part_err != 0 && f.kind != K_SKIP { return fail(f, r.part_err); }
            let rc2 = end_form_part(f);
            if rc2 != 0 { return fail(f, rc2); }
        }
    }
}

// ReadForm of a whole body.
fn read_form_bytes(f: Form&, body: const u8[:], boundary: const u8[:], max_memory: i64) -> i64 {
    var r = Reader { .. };
    init(r, boundary);
    feed(r, body);
    finish(r);
    form_init(f, max_memory);
    return read_form(r, f);
}

// Form.RemoveAll: deletes the temporary files. False if one could not be.
fn remove_all(f: Form&) -> bool {
    var ok = true;
    for fh in f.files {
        if fh.tmpfile.end > fh.tmpfile.pos {
            let p = f.text[fh.tmpfile.pos..fh.tmpfile.end];
            if ::file_exists(p) && !::delete_file(p) { ok = false; }
        }
    }
    if f.spill.len > 0 && ::file_exists(f.spill) { ::delete_file(f.spill); }
    return ok;
}

// --- The form's contents ----------------------------------------------------

fn value_count(f: const Form&) -> i64 { f.values.len }
fn file_count(f: const Form&) -> i64 { f.files.len }

// Form.Value[name][0], and whether there is one.
fn form_value(f: const Form&, name: const u8[:]) -> const u8[:], bool {
    for v in f.values { if f.text[v.name.pos..v.name.end] == name { return f.text[v.value.pos..v.value.end], true; } }
    return "", false;
}

// F(value) for each value of the name, in order (Form.Value[name]).
fn each_form_value<F>(f: const Form&, name: const u8[:]) {
    for v in f.values { if f.text[v.name.pos..v.name.end] == name { F(f.text[v.value.pos..v.value.end]); } }
}

// The i-th value's name and value.
fn value_at(f: const Form&, i: i64) -> const u8[:], const u8[:] {
    let v = f.values[i];
    return f.text[v.name.pos..v.name.end], f.text[v.value.pos..v.value.end];
}

// The index of the first file of the field name (Form.File[name][0]), -1 if none.
fn form_file(f: const Form&, name: const u8[:]) -> i64 {
    for i in f.files.len { let fh = f.files[i]; if f.text[fh.name.pos..fh.name.end] == name { return i; } }
    return -1;
}

fn file_field_name(f: const Form&, i: i64) -> const u8[:] { let fh = f.files[i]; return f.text[fh.name.pos..fh.name.end]; }
fn file_filename(f: const Form&, i: i64) -> const u8[:] { let fh = f.files[i]; return f.text[fh.filename.pos..fh.filename.end]; }
fn file_size(f: const Form&, i: i64) -> i64 { f.files[i].size }
fn file_on_disk(f: const Form&, i: i64) -> bool { f.files[i].tmpfile.end > f.files[i].tmpfile.pos }
fn file_tmpfile(f: const Form&, i: i64) -> const u8[:] { let fh = f.files[i]; return f.text[fh.tmpfile.pos..fh.tmpfile.end]; }

// The first value of a key of the file's header (FileHeader.Header.Get).
fn file_header_get(f: const Form&, i: i64, key: const u8[:]) -> const u8[:] {
    var k: u8[>..] = [];
    textproto::canonical_mime_header_key(k, key);
    let fh = f.files[i];
    for j in fh.hfirst..fh.hfirst + fh.hcount {
        let h = f.hfields[j];
        if f.text[h.key.pos..h.key.end] == k { return f.text[h.value.pos..h.value.end]; }
    }
    return "";
}

// F(key, value) for each field of the file's header.
fn each_file_header<F>(f: const Form&, i: i64) {
    let fh = f.files[i];
    for j in fh.hfirst..fh.hfirst + fh.hcount {
        let h = f.hfields[j];
        F(f.text[h.key.pos..h.key.end], f.text[h.value.pos..h.value.end]);
    }
}

// FileHeader.Open, read whole: appends the file's content to out.
fn file_content(f: const Form&, i: i64, out: u8[>..]&) -> bool {
    let fh = f.files[i];
    if fh.tmpfile.end > fh.tmpfile.pos { return ::read_file(f.text[fh.tmpfile.pos..fh.tmpfile.end], out); }
    out.append(f.text[fh.content.pos..fh.content.end]);
    return true;
}
