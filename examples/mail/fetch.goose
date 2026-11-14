// fetch: lists a POP3 mailbox and prints the headers of its newest
// message, over TLS (STLS on 110, or --implicit for 995). The password
// comes from MAIL_PASSWORD.
//
//   MAIL_PASSWORD=... goose examples/mail/fetch.goose -- HOST USER [--implicit]

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.pop3;

fn main() {
    let a = args();
    guard a.len >= 3 else { print("usage: fetch HOST USER [--implicit]"); exit(2); }
    var password: u8[>..] = [];
    guard env("MAIL_PASSWORD", password) else { print("fetch: set MAIL_PASSWORD"); exit(2); }
    let policy = if a.len > 3 && a[3] == "--implicit" { pop3::TLS_IMPLICIT } else { pop3::TLS_MANDATORY };

    var c = pop3::Client { .. };
    var e = pop3::dial(c, a[1], 0, policy);       // port 0: 995 or 110
    guard e == mail::OK else { print("fetch: ", mail::error_text(e)); exit(1); }
    // SCRAM or CRAM-MD5 when the server lists them, USER/PASS otherwise.
    e = if pop3::capability(c, "SASL") { pop3::auth(c, mail::AUTH_AUTO, a[2], password) }
        else { pop3::login(c, a[2], password) };
    guard e == mail::OK else { print("fetch: login: ", mail::error_text(e), " ", c.text); pop3::close(c); exit(1); }

    let count, size, se = pop3::stat(c);
    print(count, " messages, ", size, " bytes");
    var uids: pop3::Uid[>..] = [];
    if pop3::uidl(c, uids) == mail::OK {
        for u in uids { print("  ", u.num, "  ", u.uid); }
    }
    if count > 0 {
        var head: u8[>..] = [];
        if pop3::top(c, count, 0, head) == mail::OK { print(head); }   // TOP n 0: the headers alone
    }
    pop3::quit(c);
}
