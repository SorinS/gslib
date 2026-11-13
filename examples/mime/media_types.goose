// media_types: reads Content-Type and Content-Disposition values into a
// type and its parameters (quoted strings, RFC 2231 continuations and
// charsets included), and writes them back, quoting and encoding the
// parameters that need it.
//
//   goose examples/mime/media_types.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;

fn main() {
    // A header value as a server sends it: the type is lower-cased,
    // parameter names too; values are unquoted.
    let mt = mime::parse_media_type("Text/HTML; Charset=\"UTF-8\"; format=flowed");
    guard mt.err == mime::OK else { print("media_types: ", mime::error_text(mt.err)); exit(1); }
    print("type ", mt.typ);
    for p in mt.params { print("  ", p.name, " = ", p.value); }
    guard mt.typ == "text/html" && mime::get_or(mt, "charset") == "UTF-8" else { print("media_types: wrong parse"); exit(1); }

    // A parameter that is absent: param says so; get_or gives "".
    let v, ok = mime::param(mt, "boundary");
    guard !ok && v == "" && mime::get_or(mt, "boundary") == "" else { print("media_types: a boundary appeared"); exit(1); }

    // RFC 2231: a long file name in pieces (filename*0, *1, ...) and in
    // UTF-8 with percent escapes, as mail clients write them.
    let cd = mime::parse_media_type("attachment; filename*0*=UTF-8''Gr%C3%BC%C3%9Fe%20aus; filename*1=\" Berlin.pdf\"");
    guard cd.err == mime::OK else { print("media_types: ", mime::error_text(cd.err)); exit(1); }
    print("disposition ", cd.typ, ", filename ", mime::get_or(cd, "filename"));
    guard cd.typ == "attachment" && mime::get_or(cd, "filename") == "Grüße aus Berlin.pdf" else {
        print("media_types: wrong RFC 2231 parse");
        exit(1);
    }

    // A malformed value is refused; a bad parameter keeps the type, as Go.
    // (A value with no slash, like "attachment", is a disposition: fine.)
    let bad = mime::parse_media_type("text/");
    print("\"text/\": ", mime::error_text(bad.err));
    guard bad.err == mime::ERR_NO_TOKEN_AFTER_SLASH else { print("media_types: \"text/\" was taken"); exit(1); }
    let half = mime::parse_media_type("text/plain; charset");
    print("\"text/plain; charset\": ", mime::error_text(half.err), " (type ", half.typ, ")");
    guard half.err == mime::ERR_INVALID_MEDIA_PARAMETER && half.typ == "text/plain" else {
        print("media_types: wrong result for a bad parameter");
        exit(1);
    }

    // Writing: parameters come out sorted, quoted where they hold
    // specials, and RFC 2231-encoded where they are not ASCII.
    let ct = mime::format_media_type("multipart/form-data", [mime::KV { key: "boundary", value: "a b;c" }]);
    print(ct);
    guard ct == "multipart/form-data; boundary=\"a b;c\"" else { print("media_types: wrong format"); exit(1); }
    let att = mime::format_media_type("attachment", [mime::KV { key: "filename", value: "Grüße.pdf" }, mime::KV { key: "size", value: "1024" }]);
    print(att);

    // What is written reads back the same.
    let again = mime::parse_media_type(att);
    guard again.err == mime::OK && mime::get_or(again, "filename") == "Grüße.pdf" && mime::get_or(again, "size") == "1024" else {
        print("media_types: the round trip failed");
        exit(1);
    }
    // A type that is not a token cannot be written: "" as Go.
    guard mime::format_media_type("text/plain text", []) == "" else { print("media_types: a bad type was written"); exit(1); }
}
