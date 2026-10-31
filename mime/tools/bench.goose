// bench: multipart reading, quoted-printable and media type parsing speed,
// for comparison with tools/mimeoracle's Go (scripts/bench.py runs both).
//
//     goose build tools/bench.goose && tools/bench

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.quotedprintable;
import gslib.mime.multipart;
import gslib.mime.formdata;

fn body_of(parts: i64, size: i64, boundary: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var line: u8[>..] = [];
    for i in 70 { line.push(('a' + (i % 26)) as u8); }
    line.append("\r\n");
    for p in parts {
        format(out, "--", boundary, "\r\nContent-Disposition: form-data; name=\"f", p, "\"; filename=\"f.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n");
        var n = 0;
        while n < size { out.append(line); n += line.len; }
        out.append("\r\n");
    }
    format(out, "--", boundary, "--\r\n");
    return out;
}

fn main() {
    let boundary = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab";
    let body = body_of(10, 10 << 20, boundary);
    // the reader, fed 64 KiB at a time
    let t0 = clock();
    var r = multipart::Reader { .. };
    multipart::init(r, boundary);
    var data: u8[>..] = [];
    var fed = 0;
    var total = 0;
    var parts = 0;
    loop {
        data.clear();
        let ev = multipart::next(r, data);
        total += data.len;
        if ev == multipart::EV_NEED_MORE {
            if fed == body.len { multipart::finish(r); continue; }
            let n = ::min(65536, body.len - fed);
            multipart::feed(r, body[fed..fed + n]);
            fed += n;
            continue;
        }
        if ev == multipart::EV_PART { parts++; }
        if ev == multipart::EV_END || ev == multipart::EV_ERROR { break; }
    }
    let t1 = clock();
    print("multipart read: ", parts, " parts, ", total, " bytes, ", ((body.len as f64) / (t1 - t0) / 1e6) as i64, " MB/s");
    // many small fields through ReadForm
    var small: u8[>..] = [];
    for i in 1000 { format(small, "--", boundary, "\r\nContent-Disposition: form-data; name=\"field", i, "\"\r\n\r\nvalue ", i, "\r\n"); }
    format(small, "--", boundary, "--\r\n");
    let t2 = clock();
    for k in 100 {
        var f = multipart::Form { .. };
        multipart::read_form_bytes(f, small, boundary, 32 << 20);
    }
    let t3 = clock();
    print("ReadForm, 1000 fields: ", ((t3 - t2) * 1e6 / 100.0) as i64, " us/form");
    // quoted-printable both ways
    var text: u8[>..] = [];
    for i in 1 << 20 { text.push(if i % 7 == 0 { 0xe9 } else if i % 61 == 0 { '\n' } else { ('a' + (i % 26)) as u8 }); }
    let t4 = clock();
    var enc: u8[>..] = [];
    for k in 10 { enc.clear(); quotedprintable::encode_all(enc, text); }
    let t5 = clock();
    var dec: u8[>..] = [];
    for k in 10 { dec.clear(); quotedprintable::decode_all(dec, enc); }
    let t6 = clock();
    print("QP encode: ", ((10.0 * text.len as f64) / (t5 - t4) / 1e6) as i64, " MB/s, decode: ", ((10.0 * enc.len as f64) / (t6 - t5) / 1e6) as i64, " MB/s");
    let t7 = clock();
    var n = 0;
    for k in 100000 {
        let mt = mime::parse_media_type("multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW; charset=\"utf-8\"");
        n += mt.params.len;
    }
    let t8 = clock();
    print("ParseMediaType: ", ((t8 - t7) * 1e9 / 100000.0) as i64, " ns/op (", n, ")");
}
