// send: builds a message with mail.message and sends it over SMTP with
// STARTTLS on the submission port (587), signing in with the best
// mechanism the server offers. The password comes from MAIL_PASSWORD.
//
//   MAIL_PASSWORD=... goose examples/mail/send.goose -- HOST USER FROM TO

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.message;
import gslib.mail.smtp;

fn main() {
    let a = args();
    guard a.len >= 5 else { print("usage: send HOST USER FROM TO"); exit(2); }
    var password: u8[>..] = [];
    guard env("MAIL_PASSWORD", password) else { print("send: set MAIL_PASSWORD"); exit(2); }

    var m = mail::Msg { .. };
    var e = mail::set_from(m, a[3]);
    if e == mail::OK { e = mail::add_to(m, a[4]); }
    if e == mail::OK { e = mail::set_subject(m, "Hello from Goose"); }
    if e == mail::OK { e = mail::set_body(m, mail::TEXT_PLAIN, "Sent with gslib's mail package.\n"); }
    if e == mail::OK { e = mail::attach(m, "hello.txt", "an attachment\n"); }
    guard e == mail::OK else { print("send: ", mail::error_text(e)); exit(1); }

    var c = smtp::Client { .. };
    e = smtp::dial(c, a[1], 0, smtp::TLS_MANDATORY);       // port 0: 587
    if e == mail::OK { e = smtp::auth(c, mail::AUTH_AUTO, a[2], password); }
    if e == mail::OK { e = smtp::send_message(c, m); }
    guard e == mail::OK else {
        print("send: ", mail::error_text(e));
        if e == mail::ERR_REPLY { print("  the server said: ", c.code, " ", c.text); }
        smtp::close(c);
        exit(1);
    }
    print("sent ", mail::message_id(m), ": ", c.code, " ", c.text);
    smtp::quit(c);
}
