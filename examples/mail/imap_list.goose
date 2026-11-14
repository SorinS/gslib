// imap_list: lists an IMAP account's mailboxes, then the envelope and the
// parts of the newest message in INBOX, over TLS (993, or STARTTLS on 143
// with --starttls). The password comes from MAIL_PASSWORD.
//
//   MAIL_PASSWORD=... goose examples/mail/imap_list.goose -- HOST USER [--starttls]

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.imap;

fn main() {
    let a = args();
    guard a.len >= 3 else { print("usage: imap_list HOST USER [--starttls]"); exit(2); }
    var password: u8[>..] = [];
    guard env("MAIL_PASSWORD", password) else { print("imap_list: set MAIL_PASSWORD"); exit(2); }
    let policy = if a.len > 3 && a[3] == "--starttls" { imap::TLS_MANDATORY } else { imap::TLS_IMPLICIT };

    var c = imap::Client { .. };
    var e = imap::dial(c, a[1], 0, policy);         // port 0: 993 or 143
    guard e == mail::OK else { print("imap_list: ", mail::error_text(e)); exit(1); }
    // SCRAM or CRAM-MD5 when the server lists them, LOGIN otherwise.
    e = if imap::auth_list(c).len > 0 { imap::authenticate(c, mail::AUTH_AUTO, a[2], password) }
        else { imap::login(c, a[2], password) };
    guard e == mail::OK else { print("imap_list: login: ", mail::error_text(e), " ", c.text); imap::close(c); exit(1); }

    var boxes: imap::Mailbox[>..] = [];
    if imap::list(c, "", "*", boxes) == mail::OK {
        for b in boxes { print("  ", b.name, "  (", b.attrs, ")"); }
    }
    e = imap::examine(c, "INBOX");                  // read-only: nothing is marked \Seen
    guard e == mail::OK else { print("imap_list: INBOX: ", mail::error_text(e)); imap::logout(c); exit(1); }
    print("INBOX: ", c.exists, " messages, UIDVALIDITY ", c.uidvalidity);
    if c.exists > 0 {
        var msgs: imap::Message[>..] = [];
        e = imap::fetch(c, str(c.exists), "(UID FLAGS ENVELOPE BODYSTRUCTURE)", msgs);
        for m in msgs {
            var env = imap::Envelope { .. };
            if imap::envelope(c, m, env) {
                print("newest: uid ", m.uid, ", ", env.date);
                for f in env.from { print("  from:    ", mail::address_string(f)); }
                print("  subject: ", env.subject);
            }
            var parts: imap::Part[>..] = [];
            if imap::bodystructure(c, m, parts) {
                for p in parts { print("  part ", p.section, ": ", p.mtype, "/", p.subtype, " ", p.size, " bytes ", p.filename); }
            }
        }
    }
    imap::logout(c);
}
