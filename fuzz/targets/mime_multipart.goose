// Fuzz target: mime_multipart. The multipart reader (mime multipart,
// formdata). Byte 0: bit 0 reads raw parts (no quoted-printable decoding),
// the rest picks the size of the pieces the body is fed in. Then the
// boundary, up to the first newline (CR dropped; "MyBoundary" if empty or
// longer than 70), then the body. The body is read fed whole and fed in
// pieces (the same parts, headers and data, as Go's reader is the same
// whatever its reads return), each part's header, form name and file name
// read; then read as a form (ReadForm: values and files in memory, never
// spilled to disk at these sizes).

import std;
import gslib from "../..";
import gslib.mime;
import gslib.mime.textproto;
import gslib.mime.quotedprintable;
import gslib.mime.multipart;
import gslib.mime.formdata;

fn parse_text(body: const u8[:], boundary: const u8[:], step0: i64, raw: bool) -> u8[>..] {
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    r.raw = raw;
    var out:  u8[>..] = [];
    var data: u8[>..] = [];
    var fed = 0;
    var step = step0;
    var iters = 0;
    while iters < 1000000 {
        iters++;
        let ev = multipart::next(r, data);
        if ev == multipart::EV_NEED_MORE {
            if r.eof { abort("mime_multipart: NEED_MORE after the input ended"); }
            if fed == body.len { multipart::finish(r); continue; }
            let m = if step <= 0 { body.len - fed } else { if body.len - fed < step { body.len - fed } else { step } };
            multipart::feed(r, body[fed..fed + m]);
            fed += m;
            if step > 0 { step = step % 13 + 1; }
            continue;
        }
        if ev == multipart::EV_PART {
            data.clear();
            for f in r.header.fields { format(out, f.key, ":", f.value, ";"); }
            format(out, "[", multipart::form_name(r), "|", multipart::file_name(r), "]");
            let _ = textproto::get(r.header, "Content-Type");
            continue;
        }
        if ev == multipart::EV_DATA { continue; }
        if ev == multipart::EV_PART_END { format(out, "{", data, "}", r.part_err, ";"); data.clear(); continue; }
        var msg: u8[>..] = [];
        if ev == multipart::EV_ERROR { multipart::message(r, msg); }
        format(out, "end ", ev, " ", r.err);
        return out;
    }
    abort("mime_multipart: the reader does not end");
    return out;
}

fn form(body: const u8[:], boundary: const u8[:]) {
    var f = multipart::Form { .. };
    let rc = multipart::read_form_bytes(f, body, boundary, 1 << 20);
    if rc == 0 {
        for i in multipart::value_count(f) {
            let name, v = multipart::value_at(f, i);
            let _ = multipart::form_value(f, name);
        }
        for i in multipart::file_count(f) {
            let _ = multipart::file_field_name(f, i);
            let _ = multipart::file_filename(f, i);
            let _ = multipart::file_size(f, i);
            if multipart::file_on_disk(f, i) { abort("mime_multipart: a form file spilled to disk"); }
            let _ = multipart::file_header_get(f, i, "Content-Type");
            var c: u8[>..] = [];
            let _ = multipart::file_content(f, i, c);
        }
    }
    let _ = multipart::remove_all(f);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let raw = (data[0] & 1) != 0;
    let step: i64 = ((data[0] >> 1) % 13) + 1;
    let rest = data[1..];
    var nl = position(rest, '\n');
    var boundary = if nl < 0 { rest[..0] } else { rest[..nl] };
    let body = if nl < 0 { rest } else { rest[nl + 1..] };
    if boundary.len > 0 && boundary[boundary.len - 1] == '\r' { boundary = boundary[..boundary.len - 1]; }
    if boundary.len == 0 || boundary.len > 70 { boundary = "MyBoundary"; }
    let a = parse_text(body, boundary, 0, raw);
    let b = parse_text(body, boundary, step, raw);
    if a[..] != b[..] { abort("mime_multipart: the parts differ fed in pieces"); }
    form(body, boundary);
    return 0;
}

fn main() {}
