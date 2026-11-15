// Messages: four written with a fixed Date, Message-ID and boundary and
// compared with expected/*.txt byte for byte (a plain one; alternative
// bodies with non-ASCII; every level, mixed > related > alternative; the
// fields); then the rules around them: dates, refused fields and
// addresses, the envelope, the made-up Date/Message-ID/boundary and a
// second write the same, base64 and 8bit bodies, and the 998-byte limit.
// Every message written is checked for CRLF line ends and line lengths.
//
//   goose message.goose               // the test
//   goose message.goose -- update     // rewrites expected/*.txt
import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.message;

var failures = 0;
var update = false;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

fn check_rc(what: const u8[:], got: i64, want: i64) {
    if got != want { print("FAIL ", what, ": ", got, " (", mail::error_text(got), "), want ", want); failures++; }
}

fn contains(s: const u8[:], sub: const u8[:]) -> bool { find(s, sub) >= 0 }

// CRLF only, a CRLF at the end, no line over 998 bytes.
fn check_lines(what: const u8[:], s: const u8[:]) {
    check(str(what, ": ends with CRLF"), s.len >= 2 && s[s.len - 2] == '\r' && s[s.len - 1] == '\n');
    var start = 0;
    for i in s.len {
        if s[i] == '\n' {
            if i == 0 || s[i - 1] != '\r' { check(str(what, ": bare LF at ", i), false); return; }
            if i - 1 - start > 998 { check(str(what, ": line longer than 998 at ", start), false); return; }
            start = i + 1;
        } else if s[i] == '\r' && (i + 1 == s.len || s[i + 1] != '\n') {
            check(str(what, ": bare CR at ", i), false);
            return;
        }
    }
}

fn write_ok(what: const u8[:], m: mail::Msg&) -> u8[>..] {
    var out: u8[>..] = [];
    let rc = mail::write(m, out);
    check_rc(str(what, ": write"), rc, mail::OK);
    check_lines(what, out);
    return out;
}

// The message against expected/NAME.txt (or written there with update).
fn expect(name: const u8[:], m: mail::Msg&) {
    let out = write_ok(name, m);
    let path = str("expected/", name, ".txt");
    if update {
        check(str("writing ", path), write_file(path, out));
        return;
    }
    var want: u8[>..] = [];
    if !read_file(path, want) { check(str("reading ", path), false); return; }
    if out != want {
        print("FAIL ", name, ": differs from ", path, "\n--- got\n", out, "--- end");
        failures++;
    }
}

fn fixed(m: mail::Msg&) {
    mail::set_date(m, 1700000000);
    check_rc("set_message_id", mail::set_message_id(m, "<20231114.1@example.com>"), mail::OK);
    check_rc("set_boundary", mail::set_boundary(m, "b0und"), mail::OK);
}

fn expected_messages() {
    {
        var m = mail::Msg { .. };
        fixed(m);
        check_rc("plain from", mail::set_from(m, "alice@example.com"), mail::OK);
        check_rc("plain to", mail::set_to(m, "Bob <bob@example.com>"), mail::OK);
        check_rc("plain subject", mail::set_subject(m, "Lunch"), mail::OK);
        check_rc("plain body", mail::set_body(m, mail::TEXT_PLAIN, "Noon?\n\n-- \nAlice\n"), mail::OK);
        expect("plain", m);
    }
    {
        var m = mail::Msg { .. };
        fixed(m);
        check_rc("alt from", mail::set_from(m, "Zoë <zoe@example.com>"), mail::OK);
        check_rc("alt to", mail::set_to(m, "\"Müller, Jörg\" <joerg@example.org>, \"Smith, Bob\" <bob@example.com>"),
                 mail::OK);
        check_rc("alt cc", mail::set_cc(m, "carol@example.net"), mail::OK);
        check_rc("alt bcc", mail::set_bcc(m, "hidden@example.com"), mail::OK);
        check_rc("alt subject", mail::set_subject(m, "Grüße aus Zürich"), mail::OK);
        check_rc("alt body", mail::set_body(m, mail::TEXT_PLAIN, "Grüße! ☕\nA line with = and trailing space \n"), mail::OK);
        check_rc("alt html", mail::add_alternative(m, mail::TEXT_HTML, "<p>Grüße! ☕</p>\n"), mail::OK);
        expect("alternative", m);
    }
    {
        var m = mail::Msg { .. };
        fixed(m);
        check_rc("nested from", mail::set_from(m, "News <news@example.com>"), mail::OK);
        check_rc("nested to", mail::set_to(m, "reader@example.com"), mail::OK);
        check_rc("nested reply-to", mail::set_reply_to(m, "Desk <desk@example.com>"), mail::OK);
        check_rc("nested subject", mail::set_subject(m, "Issue 7"), mail::OK);
        check_rc("nested body", mail::set_body(m, mail::TEXT_PLAIN, "Logo and PDF.\n"), mail::OK);
        check_rc("nested html", mail::add_alternative(m, mail::TEXT_HTML, "<p><img src=\"cid:logo\"> Logo and PDF.</p>\n"),
                 mail::OK);
        check_rc("embed", mail::embed(m, "logo.png", "\x89PNG\r\n\x1a\nnot really", "logo"), mail::OK);
        check_rc("attach", mail::attach(m, "Übersicht.pdf", "%PDF-1.4\n"), mail::OK);
        check_rc("attach csv", mail::attach(m, "data.csv", "a,b\r\n1,2\r\n"), mail::OK);
        expect("nested", m);
    }
    {
        var m = mail::Msg { .. };
        fixed(m);
        check_rc("headers from", mail::set_from(m, "\"O'Brien, Seán\" <sean@example.ie>"), mail::OK);
        for i in 6 {
            check_rc("headers to", mail::add_to(m, str("List Member ", i, " <member", i, "@lists.example.com>")), mail::OK);
        }
        check_rc("headers subject",
                 mail::set_subject(m, "A subject of plain ASCII that is long enough to fold onto a second line, or a third"),
                 mail::OK);
        check_rc("headers importance", mail::set_importance(m, mail::IMPORTANCE_URGENT), mail::OK);
        check_rc("X-Mailer", mail::set_header(m, "X-Mailer", "gslib"), mail::OK);
        check_rc("In-Reply-To", mail::set_header(m, "In-Reply-To", "<1@example.com>"), mail::OK);
        check_rc("References", mail::add_header(m, "References", "<1@example.com>"), mail::OK);
        check_rc("X-Note", mail::set_header(m, "X-Note", "für alle"), mail::OK);
        check_rc("headers body", mail::set_body(m, mail::TEXT_PLAIN, "Fields.\n"), mail::OK);
        expect("headers", m);
    }
}

fn dates() {
    fn one(t: i64, want: const u8[:]) {
        var s: u8[>..] = [];
        mail::write_date(s, t);
        check(str("date ", t, ": ", s, " != ", want), s == want);
    }
    // Python's email.utils.formatdate for each, with +0000 for its -0000.
    one(0, "Thu, 01 Jan 1970 00:00:00 +0000");
    one(1700000000, "Tue, 14 Nov 2023 22:13:20 +0000");
    one(-1, "Wed, 31 Dec 1969 23:59:59 +0000");
    one(951782400, "Tue, 29 Feb 2000 00:00:00 +0000");
    one(4102444799, "Thu, 31 Dec 2099 23:59:59 +0000");
    one(-2208988800, "Mon, 01 Jan 1900 00:00:00 +0000");
}

fn refusals() {
    var m = mail::Msg { .. };
    check_rc("subject with CRLF", mail::set_subject(m, "Hi\r\nBcc: x@example.com"), mail::ERR_HEADER);
    check_rc("subject with LF", mail::set_subject(m, "Hi\nthere"), mail::ERR_HEADER);
    check_rc("header with CRLF", mail::set_header(m, "X-A", "1\r\nBcc: x@example.com"), mail::ERR_HEADER);
    check_rc("header name empty", mail::set_header(m, "", "v"), mail::ERR_HEADER);
    check_rc("header name colon", mail::set_header(m, "X:A", "v"), mail::ERR_HEADER);
    check_rc("header name space", mail::set_header(m, "X A", "v"), mail::ERR_HEADER);
    check_rc("header name non-ASCII", mail::set_header(m, "X-Ä", "v"), mail::ERR_HEADER);
    check_rc("header Subject", mail::set_header(m, "subject", "v"), mail::ERR_HEADER);
    check_rc("header Content-Type", mail::add_header(m, "Content-Type", "text/html"), mail::ERR_HEADER);
    check_rc("header Bcc", mail::add_header(m, "BCC", "x@example.com"), mail::ERR_HEADER);
    check_rc("from injection", mail::set_from(m, "a@example.com\r\nBcc: x@example.com"), mail::ERR_ADDRESS);
    check_rc("to injection", mail::add_to(m, "a@example.com\nBcc: x@example.com"), mail::ERR_ADDRESS);
    check_rc("to unparsable", mail::add_to(m, "John Doe"), mail::ERR_ADDRESS);
    check_rc("message id with space", mail::set_message_id(m, "a b@example.com"), mail::ERR_HEADER);
    check_rc("message id with CRLF", mail::set_message_id(m, "a\r\n@example.com"), mail::ERR_HEADER);
    check_rc("message id empty", mail::set_message_id(m, "<>"), mail::ERR_HEADER);
    check_rc("host with @", mail::set_host(m, "a@b"), mail::ERR_ARG);
    check_rc("boundary with space", mail::set_boundary(m, "a b"), mail::ERR_ARG);
    check_rc("boundary too long", mail::set_boundary(m, "0123456789012345678901234567890123456789012345678901234567890"),
             mail::ERR_ARG);
    check_rc("body type without slash", mail::set_body(m, "text", "x"), mail::ERR_ARG);
    check_rc("body type with CRLF", mail::set_body(m, "text/plain\r\nX: y", "x"), mail::ERR_ARG);
    check_rc("attach without a name", mail::attach(m, "", "x"), mail::ERR_ARG);
    check_rc("attach bad type", mail::attach(m, "a.bin", "x", "nonsense"), mail::ERR_ARG);
    check_rc("embed cid with space", mail::embed(m, "a.png", "x", "a b"), mail::ERR_ARG);
    check_rc("encoding", mail::set_encoding(m, 7), mail::ERR_ARG);
    check_rc("importance", mail::set_importance(m, 9), mail::ERR_ARG);
    // Nothing refused was kept.
    check("refused nothing kept", m.to.len == 0 && !m.has_from && !m.has_subject && m.fields.len == 0 &&
                                  m.parts.len == 0 && m.files.len == 0);
}

// An Address made by hand (or from a server's ENVELOPE) with CR or LF in
// it: write refuses it rather than let it start a header.
fn hand_made_addresses() {
    for i in 3 {
        var m = mail::Msg { .. };
        fixed(m);
        check_rc("hand-made: from", mail::set_from(m, "me@example.com"), mail::OK);
        check_rc("hand-made: body", mail::set_body(m, mail::TEXT_PLAIN, "ok\n"), mail::OK);
        var a = mail::Address { .. };
        a.name.append("Eve");
        a.addr.append("eve@example.com");
        if i == 0 { a.addr.append(">\r\nX-Injected: 1"); }
        if i == 1 { a.name.append("\nX-Injected: 1"); }
        if i == 2 { a.addr.push(0); }
        mail::add_to(m, a);
        var out: u8[>..] = [];
        check_rc("hand-made: refused", mail::write(m, out), mail::ERR_ADDRESS);
    }
}

fn fields() {
    var m = mail::Msg { .. };
    fixed(m);
    mail::set_from(m, "a@example.com");
    mail::set_header(m, "X-One", "1");
    mail::add_header(m, "X-Two", "2");
    mail::add_header(m, "x-two", "two");
    mail::set_header(m, "X-One", "uno");
    let v1, ok1 = mail::header(m, "x-one");
    check("set_header replaces", ok1 && v1 == "uno");
    let v2, ok2 = mail::header(m, "X-TWO");
    check("header gives the first", ok2 && v2 == "2");
    mail::del_header(m, "X-Two");
    let v3, ok3 = mail::header(m, "X-Two");
    check("del_header", !ok3);
    let out = write_ok("fields", m);
    check("fields written", contains(out, "\r\nX-One: uno\r\n") && !contains(out, "X-Two") && !contains(out, "x-two") &&
                            !contains(out, ": 1\r\n"));
    // An unbreakable value longer than a line can be.
    var long: u8[>..] = [];
    for i in 1000 { long.push('a'); }
    mail::set_header(m, "X-Long", long);
    var bad: u8[>..] = [];
    bad.append("kept");
    check_rc("unbreakable header", mail::write(m, bad), mail::ERR_HEADER);
    check("out as it was", bad == "kept");
    // Breakable: folds.
    var words: u8[>..] = [];
    for i in 300 { words.append("ab "); }
    words.append("end");
    mail::set_header(m, "X-Long", words);
    let folded = write_ok("folded header", m);
    check("folded at 76", contains(folded, "\r\n ab ab"));
}

fn envelope() {
    var m = mail::Msg { .. };
    check("no envelope", mail::envelope_from(m) == "");
    mail::set_from(m, "Alice <alice@example.com>");
    check("envelope is From", mail::envelope_from(m) == "alice@example.com");
    mail::set_envelope_from(m, "bounces@example.com");
    check("envelope set", mail::envelope_from(m) == "bounces@example.com");
    mail::add_to(m, "bob@example.com, Carol <carol@Example.COM>");
    mail::add_cc(m, "BOB@example.com, bob@EXAMPLE.com, dave@example.com");
    mail::add_bcc(m, "carol@example.com, eve@example.com");
    var r: u8[][>..] = [];
    mail::recipients(m, r);
    var joined: u8[>..] = [];
    for a in r { joined.append(a); joined.push(' '); }
    check(str("recipients: ", joined),
          joined == "bob@example.com carol@Example.COM BOB@example.com dave@example.com eve@example.com ");
    check("ascii envelope", !mail::needs_smtputf8(m));
    let out = write_ok("envelope", m);
    check("no Bcc written", !contains(out, "Bcc") && !contains(out, "eve@") && !contains(out, "bounces@"));
    mail::add_bcc(m, "jörg@example.de");
    check("utf-8 envelope", mail::needs_smtputf8(m));
    // set_to with a blank list empties it.
    check_rc("set_to blank", mail::set_to(m, "  "), mail::OK);
    check("set_to blank empties", m.to.len == 0);
    check_rc("set_cc replaces", mail::set_cc(m, "x@example.com"), mail::OK);
    check("set_cc replaced", m.cc.len == 1 && m.cc[0].addr == "x@example.com");
}

fn defaults() {
    var m = mail::Msg { .. };
    mail::set_from(m, "a@example.com");
    mail::set_body(m, mail::TEXT_PLAIN, "x");
    mail::attach(m, "a.txt", "y");
    check("no id before write", mail::message_id(m) == "");
    let before = time_ns() / 1000000000;
    let one = write_ok("defaults", m);
    let after = time_ns() / 1000000000;
    check("date is now", m.has_date && m.date >= before && m.date <= after);
    let id = mail::message_id(m);
    check(str("message id ", id), id.len == 22 + 1 + 21 && id[22..] == "@localhost.localdomain");
    for i in 22 {
        let c = id[i];
        check("message id alphabet", ascii::is_alnum(c) || c == '-' || c == '_');
    }
    check("boundary 48 hex", m.boundary.len == 48);
    for c in m.boundary { check("boundary hex", (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')); }
    let two = write_ok("defaults again", m);
    check("a second write is the same", one == two);
    var n = mail::Msg { .. };
    check_rc("set_host", mail::set_host(n, "mx.example.com"), mail::OK);
    let o = write_ok("host", n);
    check("host in id", ends_with(mail::message_id(n), "@mx.example.com") && contains(o, "@mx.example.com>\r\n"));
    check("empty body", contains(o, "Content-Type: text/plain; charset=UTF-8\r\n\r\n"));
    var k = mail::Msg { .. };
    check_rc("explicit id", mail::set_message_id(k, "plain-id"), mail::OK);
    check("explicit id kept", mail::message_id(k) == "plain-id");
    let ko = write_ok("explicit id", k);
    check("explicit id gets the host", contains(ko, "\r\nMessage-ID: <plain-id@localhost.localdomain>\r\n") &&
                                       mail::message_id(k) == "plain-id@localhost.localdomain");
    check_rc("message id with two @", mail::set_message_id(k, "a@b@c"), mail::ERR_HEADER);
    check_rc("message id with a comma", mail::set_message_id(k, "a,b@c"), mail::ERR_HEADER);
    check_rc("message id ending in @", mail::set_message_id(k, "<ab@>"), mail::ERR_HEADER);
    check_rc("message id literal", mail::set_message_id(k, "<ab@[192.0.2.1]>"), mail::OK);
    // A fold never leaves a line of white space alone.
    var t = mail::Msg { .. };
    var ws: u8[>..] = [];
    for i in 30 { ws.append("word \t "); }
    mail::set_header(t, "X-Ws", ws);
    let to = write_ok("white space words", t);
    check("no blank folded line", !contains(to, "\r\n \t\r\n") && !contains(to, "\r\n \r\n"));
}

fn encodings() {
    var text: u8[>..] = [];
    for i in 3 { text.append("Zeile mit Ümlauten\n"); }
    {
        var m = mail::Msg { .. };
        fixed(m);
        mail::set_encoding(m, mail::ENC_BASE64);
        mail::set_body(m, mail::TEXT_PLAIN, text);
        let out = write_ok("base64", m);
        // The text with CRLF line ends, in base64.
        check("base64 body", contains(out, "Content-Transfer-Encoding: base64\r\n") &&
                             contains(out, "WmVpbGUgbWl0IMOcbWxhdXRlbg0KWmVpbGUgbWl0IMOcbWxhdXRlbg0KWmVpbGUgbWl0IMOcbWxh\r\ndXRlbg0K\r\n"));
    }
    {
        var m = mail::Msg { .. };
        fixed(m);
        mail::set_encoding(m, mail::ENC_8BIT);
        mail::set_body(m, mail::TEXT_PLAIN, "a\nb\rc\r\nd");
        let out = write_ok("8bit", m);
        check("8bit body", ends_with(out, "Content-Transfer-Encoding: 8bit\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\na\r\nb\r\nc\r\nd\r\n"));
        // A line of 999 bytes cannot go as 8bit.
        var long: u8[>..] = [];
        for i in 999 { long.push('x'); }
        mail::set_body(m, mail::TEXT_PLAIN, long);
        var bad: u8[>..] = [];
        check_rc("8bit long line", mail::write(m, bad), mail::ERR_LONG_LINE);
        check("8bit long line: nothing written", bad.len == 0);
        long.resize(998);
        mail::set_body(m, mail::TEXT_PLAIN, long);
        write_ok("8bit 998", m);
        // As quoted-printable it breaks.
        long.push('x');
        mail::set_encoding(m, mail::ENC_QP);
        mail::set_body(m, mail::TEXT_PLAIN, long);
        write_ok("qp 999", m);
    }
    {
        // Files: types from the extension (Go's built-in table only), names sanitized.
        var m = mail::Msg { .. };
        fixed(m);
        mail::attach(m, "Photo.JPG", "j");
        mail::attach(m, "dir/x:y?.unknownext", "u");
        mail::attach(m, "page.html", "<p>");
        mail::embed(m, "<logo>", "l", "<cid-1@example.com>", "image/png");
        let out = write_ok("files", m);
        check("jpeg by extension", contains(out, "Content-Type: image/jpeg; name=Photo.JPG\r\n"));
        check("unknown extension", contains(out, "Content-Type: application/octet-stream; name=dir_x_y_.unknownext\r\n"));
        check("html keeps its charset", contains(out, "Content-Type: text/html; charset=utf-8; name=page.html\r\n"));
        check("cid without its <>", contains(out, "Content-ID: <cid-1@example.com>\r\n"));
        check("inline name sanitized", contains(out, "Content-Disposition: inline; filename=_logo_\r\n"));
        check("mixed for three attachments", contains(out, "Content-Type: multipart/mixed;\r\n boundary=b0und-mixed\r\n"));
    }
}

fn main() {
    hand_made_addresses();
    let a = args();
    update = a.len > 1 && a[1] == "update";
    expected_messages();
    if update { print("message: expected/*.txt written"); return; }
    dates();
    refusals();
    fields();
    envelope();
    defaults();
    encodings();
    if failures > 0 {
        print(failures, " failures");
        exit(1);
    }
    print("message: ok");
}
