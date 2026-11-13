// file_types: the media type to send for a file name, as a web server
// picks a Content-Type (Go's built-in table, then the system's mime.types
// or globs2); the extensions of a type; and a type of the program's own.
//
//   goose examples/mime/file_types.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.types;

// The extension of a path, with its dot: "" if none.
fn extension(path: const u8[:]) -> const u8[:] {
    var i = path.len - 1;
    while i >= 0 && path[i] != '/' {
        if path[i] == '.' { return path[i..]; }
        i--;
    }
    return "";
}

fn main() {
    let files = ["index.html", "logo.PNG", "data/report.json", "style.css", "notes.unknownext", "Makefile"];
    for f in files {
        var t = mime::type_by_extension(extension(f));
        if t.len == 0 { t = "application/octet-stream"; }      // the usual fallback
        print(f, ": ", t);
    }

    // Text types get a charset; the lookup ignores case when it must.
    // (The system's tables may add to these, but not change the basics.)
    guard starts_with(mime::type_by_extension(".html"), "text/html") else { print("file_types: .html"); exit(1); }
    guard mime::type_by_extension(".PNG") == "image/png" else { print("file_types: .PNG"); exit(1); }
    guard mime::type_by_extension(".unknownext") == "" else { print("file_types: .unknownext"); exit(1); }

    // The other way: every extension known for a type, sorted.
    var exts: u8[][>..] = [];
    guard mime::extensions_by_type(exts, "image/jpeg") == mime::OK else { print("file_types: extensions_by_type"); exit(1); }
    var line: u8[>..] = [];
    for e in exts { line.append(str(" ", e)); }
    print("image/jpeg:", line);
    var has_jpg = false;
    for e in exts { if e == ".jpg" { has_jpg = true; } }
    guard has_jpg else { print("file_types: no .jpg for image/jpeg"); exit(1); }

    // A program's own types: a text type gets "; charset=utf-8".
    guard mime::add_extension_type(".goose", "text/x-goose") == mime::OK else { print("file_types: add"); exit(1); }
    print(".goose: ", mime::type_by_extension(".goose"));
    guard mime::type_by_extension(".goose") == "text/x-goose; charset=utf-8" else { print("file_types: .goose"); exit(1); }

    // The extension must start with a dot.
    let e = mime::add_extension_type("goose", "text/x-goose");
    var msg: u8[>..] = [];
    mime::add_extension_type_error(msg, "goose", e);
    print(msg);
    guard e == mime::ERR_EXTENSION_NO_DOT else { print("file_types: an extension without a dot was taken"); exit(1); }
}
