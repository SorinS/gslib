// compose: builds a message with a text body and an HTML alternative,
// non-ASCII in the names and the subject, and a Bcc, then prints it as an
// SMTP client would send it (CRLF line ends; write_stdout keeps them)
// and the envelope the client would give the server. No network.
//
//   goose examples/mail/compose.goose

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.message;

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("compose: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

fn main() {
    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Zoë Ångström <zoe@example.com>"));
    must("to", mail::add_to(m, "Bob <bob@example.com>, \"Müller, Jörg\" <joerg@example.org>"));
    must("cc", mail::add_cc(m, "team@example.net"));
    must("bcc", mail::add_bcc(m, "archive@example.com"));      // in the envelope, not the header
    must("subject", mail::set_subject(m, "Réunion à midi ☕"));
    must("header", mail::set_header(m, "X-Mailer", "gslib mail example"));
    must("host", mail::set_host(m, "mail.example.com"));       // for the Message-ID
    must("text", mail::set_body(m, mail::TEXT_PLAIN, "Bonjour à tous,\n\nlunch at noon?\n\nZoë\n"));
    must("html", mail::add_alternative(m, mail::TEXT_HTML,
                                       "<p>Bonjour à tous,</p><p>lunch at <b>noon</b>?</p><p>Zoë</p>\n"));

    var out: u8[>..] = [];
    must("write", mail::write(m, out));
    write_stdout(out);

    // What SMTP's MAIL FROM and RCPT TO take.
    var rcpts: u8[][>..] = [];
    mail::recipients(m, rcpts);
    print("--- MAIL FROM:<", mail::envelope_from(m), ">");
    for r in rcpts { print("--- RCPT TO:<", r, ">"); }
    print("--- ", out.len, " bytes, Message-ID <", mail::message_id(m), ">, SMTPUTF8 ",
          if mail::needs_smtputf8(m) { "needed" } else { "not needed" });

    // Addresses alone: read and written back as Go's net/mail does.
    let a, rc = mail::parse_address("=?utf-8?q?J=C3=B6rg?= (the boss) <joerg@example.org>");
    must("parse_address", rc);
    print("--- parsed: name \"", a.name, "\", address ", a.addr, ", written ", mail::address_string(a));
}
