// attachments: a message with every level go-mail nests: multipart/mixed
// for the attachments, multipart/related for an image the HTML shows by
// its Content-ID, multipart/alternative for the text and HTML bodies.
// The Date, Message-ID and boundaries are fixed, so the output is the
// same each run. No network.
//
//   goose examples/mail/attachments.goose

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.message;

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("attachments: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

fn main() {
    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Reports <reports@example.com>"));
    must("to", mail::add_to(m, "finance@example.com"));
    must("subject", mail::set_subject(m, "Figures for March"));
    mail::set_date(m, 1711929600);                              // 2024-04-01 00:00:00 UTC
    must("id", mail::set_message_id(m, "figures-2024-03@example.com"));
    must("boundary", mail::set_boundary(m, "example"));
    must("importance", mail::set_importance(m, mail::IMPORTANCE_HIGH));

    must("text", mail::set_body(m, mail::TEXT_PLAIN, "The figures for March are attached.\n"));
    must("html", mail::add_alternative(m, mail::TEXT_HTML,
                                       "<p><img src=\"cid:chart@example.com\" alt=\"chart\"></p>\n<p>The figures for March are attached.</p>\n"));

    // A small image, shown inline by the HTML (a few bytes stand in for one).
    var png: u8[>..] = [];
    png.append("\x89PNG\r\n\x1a\n");
    for i in 64 { png.push((i * 13) as! u8); }
    must("embed", mail::embed(m, "chart.png", png, "chart@example.com"));

    // Attachments: the type from the extension, or given; a name that is
    // not ASCII goes as RFC 2231's filename*=utf-8''...
    var csv: u8[>..] = [];
    csv.append("day,sales\r\n");
    for d in 31 { csv.append(str(d + 1, ",", 1000 + 17 * d, "\r\n")); }
    must("csv", mail::attach(m, "März 2024.csv", csv));
    must("notes", mail::attach(m, "NOTES", "Checked by the auditors.\n", "text/plain"));

    var out: u8[>..] = [];
    must("write", mail::write(m, out));
    write_stdout(out);
}
