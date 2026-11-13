// header_section: reads the header section of a mail or HTTP message
// (folded lines, repeated fields, keys in any case) into a header, looks
// fields up, changes them, and reads a header that arrives in pieces.
//
//   goose examples/mime/header_section.goose

import std;
import os;
import gslib from "../..";
import gslib.mime;
import gslib.mime.textproto;

fn main() {
    let msg = str(
        "from: Alice <alice@example.com>\r\n",
        "To: bob@example.com\r\n",
        "Subject: a subject that is long enough\r\n",
        "  to be folded onto a second line\r\n",
        "Received: by mx2.example.com\r\n",
        "Received: by mx1.example.com\r\n",
        "content-type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hello Bob.\r\n");

    // read_mime_header stops after the blank line: the body is the rest.
    var h = textproto::new_header();
    let code, used = textproto::read_mime_header(msg, h);
    guard code == mime::OK else { print("header_section: ", mime::error_text(code)); exit(1); }
    print(textproto::key_count(h), " keys; the body: ", trim(msg[used..]));
    guard msg[used..] == "Hello Bob.\r\n" else { print("header_section: the body is wrong"); exit(1); }

    // Keys are canonical (From, Content-Type); lookups take any case.
    for f in h.fields { print("  ", f.key, ": ", f.value); }
    let subject = textproto::get(h, "SUBJECT");
    guard subject == "a subject that is long enough to be folded onto a second line" else {
        print("header_section: the folded line");
        exit(1);
    }
    guard textproto::get(h, "from") == "Alice <alice@example.com>" && textproto::has(h, "Content-Type") else {
        print("header_section: lookups");
        exit(1);
    }

    // A repeated field: get gives the first, each_value all of them.
    print("Received ", textproto::count_values(h, "received"), " times:");
    textproto::each_value(h, "Received") { print("  ", it); };
    guard textproto::count_values(h, "Received") == 2 else { print("header_section: Received"); exit(1); }

    // Changing it: add appends a value, set replaces all, del removes.
    textproto::add(h, "X-Tag", "one");
    textproto::add(h, "x-tag", "two");
    textproto::set(h, "To", "carol@example.com");
    textproto::del(h, "Received");
    guard textproto::count_values(h, "X-Tag") == 2 && textproto::get(h, "To") == "carol@example.com" && !textproto::has(h, "Received") else {
        print("header_section: changes");
        exit(1);
    }
    print("canonical form of x-forwarded-for: ", textproto::canonical_mime_header_key("x-forwarded-for"));

    // Arriving in pieces: with eof false, NEED_MORE until the blank line
    // decides it. read_mime_header_at reads from `pos` each time.
    var got: i64 = 0;
    var done = false;
    var detail: u8[>..] = [];
    while !done {
        got = min(got + 16, msg.len);
        var h2 = textproto::new_header();
        let c, end = textproto::read_mime_header_at(msg[..got], 0, got == msg.len, 10 << 20, 1000, h2, detail);
        if c == textproto::NEED_MORE { continue; }
        guard c == mime::OK && textproto::key_count(h2) == 5 else { print("header_section: in pieces: ", mime::error_text(c)); exit(1); }
        print("complete after ", got, " bytes; the header is ", end, " bytes");
        done = true;
    }

    // A malformed header: Go's error, with the line.
    var bad = textproto::new_header();
    let c, end = textproto::read_mime_header_at("Subject: hi\r\nno colon here\r\n\r\n", 0, true, 10 << 20, 1000, bad, detail);
    var m: u8[>..] = [];
    textproto::error_message(m, c, detail);
    print(m);
    guard c == mime::ERR_MISSING_COLON else { print("header_section: a line without a colon was taken"); exit(1); }
}
