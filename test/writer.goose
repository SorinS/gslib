// mime.multipart's writer against Go's writer_test.go: TestWriter,
// TestSortedHeader ported; TestWriterSetBoundary's and
// TestFileContentDisposition's tables (test/vectors, extracted from Go with
// Go's own result for each row).

import std;
import mime from "..";
import mime.textproto;
import mime.multipart;
import tv;

fn read_part(r: multipart::Reader&, data: u8[>..]&) -> i64 {
    data.clear();
    loop {
        let ev = multipart::next(r, data);
        if ev != multipart::EV_DATA { return ev; }
    }
}

// TestWriter.
fn writer() {
    var w = multipart::new_writer();
    var b: u8[>..] = [];
    multipart::create_form_file(w, b, "myfile", "my-file.txt");
    b.append("my file contents");
    multipart::write_field(w, b, "key", "val");
    multipart::close(w, b);
    tv::check("writer output", b.len > 0 && b[0] != '\r' && b[0] != '\n');
    var r = multipart::Reader { .. };
    multipart::init(r, multipart::boundary(w));
    multipart::feed(r, b);
    multipart::finish(r);
    var data: u8[>..] = [];
    { let ev = multipart::next(r, data); tv::check_int("writer part 1", ev, multipart::EV_PART); }
    tv::check_eq("writer part 1 name", multipart::form_name(r), "myfile");
    tv::check_eq("writer part 1 file", multipart::file_name(r), "my-file.txt");
    tv::check_eq("writer part 1 type", textproto::get(r.header, "Content-Type"), "application/octet-stream");
    { let ev = read_part(r, data); tv::check_int("writer part 1 end", ev, multipart::EV_PART_END); }
    tv::check_eq("writer part 1 body", data, "my file contents");
    { let ev = multipart::next(r, data); tv::check_int("writer part 2", ev, multipart::EV_PART); }
    tv::check_eq("writer part 2 name", multipart::form_name(r), "key");
    { let ev = read_part(r, data); tv::check_int("writer part 2 end", ev, multipart::EV_PART_END); }
    tv::check_eq("writer part 2 body", data, "val");
    { let ev = multipart::next(r, data); tv::check_int("writer end", ev, multipart::EV_END); }
}

// NewWriter's random boundary: 30 bytes from the OS in hex.
fn random_boundary() {
    let a = multipart::new_writer();
    let b = multipart::new_writer();
    tv::check_int("boundary length", multipart::boundary(a).len, 60);
    var hex = true;
    for c in multipart::boundary(a) { if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) { hex = false; } }
    tv::check("boundary is hex", hex);
    tv::check("boundaries differ", multipart::boundary(a) != multipart::boundary(b));
}

fn set_boundary() {
    tv::each_row("vectors/go_set_boundary.txt") { r: tv::Row& =>
        let b = r.next();
        let ok = r.next_bool();
        r.to_results();
        let go_err = r.next();
        let go_ct = r.next();
        var w = multipart::new_writer();
        let rc = multipart::set_boundary(w, b);
        tv::check_eq(str("set_boundary ", b), mime::error_text(rc), go_err);
        tv::check(str("set_boundary (table) ", b), (rc == 0) == ok);
        if rc == 0 {
            tv::check_eq(str("boundary ", b), multipart::boundary(w), b);
            let ct = multipart::form_data_content_type(w);
            tv::check_eq(str("content type ", b), ct, go_ct);
            let mt = mime::parse_media_type(ct);
            tv::check_eq(str("content type parses ", b), mt.typ, "multipart/form-data");
            tv::check_eq(str("content type boundary ", b), mime::get_or(mt, "boundary"), b);
            var out: u8[>..] = [];
            multipart::close(w, out);
            tv::check(str("close ", b), find(out, str("\r\n--", b, "--\r\n")) >= 0);
        }
    };
    // after a part, SetBoundary is refused; after Close it is allowed again (Go's lastpart = nil)
    var w = multipart::new_writer();
    var out: u8[>..] = [];
    multipart::create_form_field(w, out, "a");
    tv::check_int("set_boundary after write", multipart::set_boundary(w, "x"), mime::ERR_SET_BOUNDARY_AFTER_WRITE);
    multipart::close(w, out);
    tv::check_int("set_boundary after close", multipart::set_boundary(w, "x"), 0);
}

// TestSortedHeader.
fn sorted_header() {
    var w = multipart::new_writer();
    tv::check_int("MIMEBOUNDARY", multipart::set_boundary(w, "MIMEBOUNDARY"), 0);
    var out: u8[>..] = [];
    multipart::create_part(w, out, [mime::KV { key: "A", value: "2" }, mime::KV { key: "B", value: "5" },
                                    mime::KV { key: "B", value: "7" }, mime::KV { key: "B", value: "6" },
                                    mime::KV { key: "C", value: "4" }, mime::KV { key: "M", value: "3" },
                                    mime::KV { key: "Z", value: "1" }]);
    out.append("foo");
    multipart::close(w, out);
    tv::check_eq("sorted header", out,
                 "--MIMEBOUNDARY\r\nA: 2\r\nB: 5\r\nB: 7\r\nB: 6\r\nC: 4\r\nM: 3\r\nZ: 1\r\n\r\nfoo\r\n--MIMEBOUNDARY--\r\n");
    // a Header's keys come out sorted too, each key's values in order
    var h = textproto::new_header();
    textproto::add(h, "z", "1");
    textproto::add(h, "b", "5");
    textproto::add(h, "a", "2");
    textproto::add(h, "B", "7");
    var w2 = multipart::new_writer();
    multipart::set_boundary(w2, "X");
    var o2: u8[>..] = [];
    multipart::create_part(w2, o2, h);
    tv::check_eq("sorted Header", o2, "--X\r\nA: 2\r\nB: 5\r\nB: 7\r\nZ: 1\r\n\r\n");
}

fn file_disposition() {
    tv::each_row("vectors/go_file_disposition.txt") { r: tv::Row& =>
        let field = r.next();
        let file = r.next();
        let want = r.next();
        r.to_results();
        let go = r.next();
        let got = multipart::file_content_disposition(field, file);
        tv::check_eq(str("file disposition ", field), got, go);
        tv::check_eq(str("file disposition (table) ", field), got, want);
    };
}

fn main() {
    writer();
    random_boundary();
    set_boundary();
    sorted_header();
    file_disposition();
    tv::done("writer");
}
