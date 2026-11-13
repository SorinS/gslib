// form_upload: an HTML form posted as multipart/form-data, both ends: the
// client writes text fields and two files; the server reads the body as
// it arrives into a form (Go's ReadForm), looks up values and files, and
// lets a file larger than its memory budget go to a temporary file.
//
//   goose examples/mime/form_upload.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.textproto;
import gslib.mime.multipart;
import gslib.mime.formdata;

fn fail(what: const u8[:]) {
    print("form_upload: ", what);
    exit(1);
}

fn main() {
    var photo: u8[>..] = [];
    var r = rng { 7 };
    for i in 300000 { photo.push((r.rand_u64() & 0xff) as! u8); }
    let notes = "first line\nsecond line\n";

    // --- The client ------------------------------------------------------
    var w = multipart::new_writer();
    var body: u8[>..] = [];
    multipart::write_field(w, body, "title", "Holiday in Zürich");
    multipart::write_field(w, body, "tag", "lake");
    multipart::write_field(w, body, "tag", "mountains");
    multipart::create_form_file(w, body, "notes", "notes.txt");     // application/octet-stream
    body.append(notes);
    // A file part with its own Content-Type.
    multipart::create_part(w, body, [
        mime::KV { key: "Content-Disposition", value: multipart::file_content_disposition("photo", "IMG_0001.jpg") },
        mime::KV { key: "Content-Type", value: "image/jpeg" },
    ]);
    body.append(photo);
    multipart::close(w, body);
    let ct = multipart::form_data_content_type(w);
    print("POST /upload with Content-Type: ", ct, ", ", body.len, " bytes");

    // --- The server ------------------------------------------------------
    // The boundary comes from the request's Content-Type.
    let mt = mime::parse_media_type(ct);
    if mt.err != mime::OK || mt.typ != "multipart/form-data" { fail("not a form"); }
    var mr = multipart::Reader { .. };
    multipart::init(mr, mime::get_or(mt, "boundary"));
    var f = multipart::Form { .. };
    multipart::form_init(f, 64 << 10);      // files past 64 KiB in all go to disk ($TMPDIR)

    // The body arrives 16 KiB at a time; read_form takes what has come.
    var p: i64 = 0;
    var rc = multipart::NEED_MORE;
    while rc == multipart::NEED_MORE {
        let n = min(16384, body.len - p);
        multipart::feed(mr, body[p..p + n]);
        p += n;
        if p == body.len { multipart::finish(mr); }
        rc = multipart::read_form(mr, f);
    }
    if rc != 0 { fail(mime::error_text(rc)); }

    // Text fields: the first value, or every value of a name.
    let title, has = multipart::form_value(f, "title");
    print("title: ", title);
    var tags: u8[>..] = [];
    multipart::each_form_value(f, "tag") { tags.append(str(" ", it)); };
    print("tags:", tags);
    if !has || title != "Holiday in Zürich" || tags[..] != " lake mountains" { fail("the fields"); }

    // Files: by field name; the name, size, header and content.
    for name in ["notes", "photo"] {
        let i = multipart::form_file(f, name);
        if i < 0 { fail(str("no file ", name)); }
        var data: u8[>..] = [];
        if !multipart::file_content(f, i, data) { fail("cannot read the file"); }
        let where = if multipart::file_on_disk(f, i) { "on disk" } else { "in memory" };
        print(name, ": ", multipart::file_filename(f, i), ", ", multipart::file_size(f, i), " bytes, ",
              multipart::file_header_get(f, i, "Content-Type"), ", ", where);
        let want = if name == "notes" { notes } else { photo[..] };
        if data[..] != want { fail(str("the content of ", name)); }
    }
    let ph = multipart::form_file(f, "photo");
    if !multipart::file_on_disk(f, ph) { fail("the photo should have gone to disk"); }

    // As Go's Form.RemoveAll: delete the temporary files when done.
    let tmp = str(multipart::file_tmpfile(f, ph));
    if !multipart::remove_all(f) || file_exists(tmp) { fail("the temporary file is still there"); }
    print("temporary file removed");
}
