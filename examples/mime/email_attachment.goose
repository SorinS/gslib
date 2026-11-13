// email_attachment: writes a MIME mail with a quoted-printable text part
// and a base64 attachment (multipart/mixed), then reads it back as a mail
// client would: the header, the Content-Type's boundary, each part, the
// text decoded and the attachment saved under its file name.
//
//   goose examples/mime/email_attachment.goose

import std;
import os;
import base64;
import gslib from "../..";
import gslib.mime;
import gslib.mime.encodedword;
import gslib.mime.quotedprintable;
import gslib.mime.textproto;
import gslib.mime.multipart;

fn fail(what: const u8[:]) {
    print("email_attachment: ", what);
    exit(1);
}

fn main() {
    let text = "Hi Bob,\r\n\r\nthe figures for the café are attached.\r\n\r\nAlice\r\n";
    var csv: u8[>..] = [];
    csv.append("month,sales\r\n");
    for m in 12 { csv.append(str(m + 1, ",", 1000 + m * 37, "\r\n")); }

    // --- Writing ---------------------------------------------------------
    var w = multipart::new_writer();        // a random boundary
    var mail: u8[>..] = [];
    mail.append("From: Alice <alice@example.com>\r\nTo: bob@example.com\r\n");
    mail.append(str("Subject: ", mime::encode_word(mime::Q_ENCODING, "UTF-8", "Sales for the café"), "\r\n"));
    mail.append("MIME-Version: 1.0\r\n");
    let ct = mime::format_media_type("multipart/mixed", [mime::KV { key: "boundary", value: multipart::boundary(w) }]);
    mail.append(str("Content-Type: ", ct, "\r\n\r\n"));

    multipart::create_part(w, mail, [
        mime::KV { key: "Content-Type", value: "text/plain; charset=utf-8" },
        mime::KV { key: "Content-Transfer-Encoding", value: "quoted-printable" },
    ]);
    quotedprintable::encode_all(mail, text);

    let disp = mime::format_media_type("attachment", [mime::KV { key: "filename", value: "sales 2026.csv" }]);
    multipart::create_part(w, mail, [
        mime::KV { key: "Content-Type", value: "text/csv" },
        mime::KV { key: "Content-Transfer-Encoding", value: "base64" },
        mime::KV { key: "Content-Disposition", value: disp },
    ]);
    var b64: u8[>..] = [];
    base64::encode(b64, csv);
    var p: i64 = 0;
    while p < b64.len {                     // lines of 76 characters
        let n = min(76, b64.len - p);
        if p > 0 { mail.append("\r\n"); }
        mail.append(b64[p..p + n]);
        p += n;
    }
    multipart::close(w, mail);
    print(mail);

    // --- Reading ---------------------------------------------------------
    var h = textproto::new_header();
    let code, used = textproto::read_mime_header(mail, h);
    if code != mime::OK { fail(mime::error_text(code)); }
    var subject: u8[>..] = [];
    if mime::decode_header(subject, textproto::get(h, "Subject")) != mime::OK { fail("subject"); }
    print("--- read back: \"", subject, "\" from ", textproto::get(h, "From"));
    let mt = mime::parse_media_type(textproto::get(h, "Content-Type"));
    if mt.err != mime::OK || mt.typ != "multipart/mixed" { fail("not multipart/mixed"); }

    var r = multipart::Reader { .. };
    multipart::init(r, mime::get_or(mt, "boundary"));
    multipart::feed(r, mail[used..]);       // as the bytes come; here all at once
    multipart::finish(r);
    var data: u8[>..] = [];
    var parts = 0;
    var ptype: u8[>..] = [];
    var fname: u8[>..] = [];
    var cte:   u8[>..] = [];
    loop {
        let ev = multipart::next(r, data);
        if ev == multipart::EV_PART {
            // A quoted-printable part is decoded as it is read, and its
            // Content-Transfer-Encoding is removed, as Go does.
            data.clear();
            ptype.clear();
            ptype.append(textproto::get(r.header, "Content-Type"));
            fname.clear();
            fname.append(multipart::file_name(r));
            cte.clear();
            cte.append(textproto::get(r.header, "Content-Transfer-Encoding"));
        } else if ev == multipart::EV_PART_END {
            if r.part_err != 0 { fail(mime::error_text(r.part_err)); }
            parts++;
            if fname.len == 0 {
                print("part ", parts, " (", ptype, "):\n", data);
                if data[..] != text { fail("the text differs"); }
            } else {
                var body: u8[>..] = [];
                var flat: u8[>..] = [];
                for c in data { if c != '\r' && c != '\n' { flat.push(c); } }
                if cte[..] != "base64" || !base64::decode(body, flat) { fail("bad base64"); }
                print("part ", parts, " (", ptype, "): attachment \"", fname, "\", ", body.len, " bytes");
                if body[..] != csv[..] { fail("the attachment differs"); }
            }
        } else if ev == multipart::EV_END {
            break;
        } else if ev == multipart::EV_ERROR || ev == multipart::EV_NEED_MORE {
            var m: u8[>..] = [];
            multipart::message(r, m);
            fail(m);
        }
    }
    if parts != 2 { fail(str(parts, " parts")); }
}
