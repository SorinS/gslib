// gen_messages: the messages scripts/check_message.py reads with Python's
// email package. Each case is written to DIR as NAME.eml, with NAME.json
// saying what went in: the addresses, the subject and other fields, the
// bodies and files, the nesting the message should have. Then the
// addresses: addr_out.json holds write_address of name/addr pairs, and
// each line of addr_in.txt (Python's formataddr, if the script wrote it)
// is parsed into addr_parsed.json.
//
//   goose gen_messages.goose -- DIR
//
// Not a test by itself: without DIR it only checks that every case writes.

import std;
import os;
import json;
import base64;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.message;

// What a case put in, as the JSON pieces of the manifest.
root struct Rec {
    from:     u8[>..] = [],
    to:       u8[>..] = [],
    cc:       u8[>..] = [],
    reply_to: u8[>..] = [],
    bcc:      u8[>..] = [],
    subject:  u8[>..] = [],
    headers:  u8[>..] = [],
    bodies:   u8[>..] = [],
    files:    u8[>..] = [],
    encoding: u8[>..] = [],
}

var failures = 0;

fn ok(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("gen_messages: ", what, ": ", mail::error_text(rc));
        failures++;
    }
}

fn sep(s: u8[>..]&) { if s.len > 0 { s.push(','); } }

fn pair(out: u8[>..]&, a: const u8[:], b: const u8[:]) {
    out.push('[');
    json::format_string(out, a);
    out.push(',');
    json::format_string(out, b);
    out.push(']');
}

fn addr(name: const u8[:], spec: const u8[:]) -> mail::Address {
    let a, rc = mail::make_address(name, spec);
    ok(str("make_address ", spec), rc);
    return a;
}

fn from(m: mail::Msg&, r: Rec&, name: const u8[:], spec: const u8[:]) {
    let a = addr(name, spec);
    mail::set_from(m, a);
    r.from.clear();
    pair(r.from, a.name, a.addr);
}

fn to(m: mail::Msg&, r: Rec&, name: const u8[:], spec: const u8[:]) {
    let a = addr(name, spec);
    mail::add_to(m, a);
    sep(r.to);
    pair(r.to, a.name, a.addr);
}

fn cc(m: mail::Msg&, r: Rec&, name: const u8[:], spec: const u8[:]) {
    let a = addr(name, spec);
    mail::add_cc(m, a);
    sep(r.cc);
    pair(r.cc, a.name, a.addr);
}

fn bcc(m: mail::Msg&, r: Rec&, spec: const u8[:]) {
    ok("add_bcc", mail::add_bcc(m, spec));
    sep(r.bcc);
    json::format_string(r.bcc, spec);
}

// Reply-To from a list's text, with the pairs it should read back as.
fn reply_to(m: mail::Msg&, r: Rec&, list: const u8[:], name: const u8[:], spec: const u8[:]) {
    ok("add_reply_to", mail::add_reply_to(m, list));
    sep(r.reply_to);
    pair(r.reply_to, name, spec);
}

fn subject(m: mail::Msg&, r: Rec&, s: const u8[:]) {
    ok("set_subject", mail::set_subject(m, s));
    r.subject.clear();
    json::format_string(r.subject, s);
}

fn header(m: mail::Msg&, r: Rec&, name: const u8[:], value: const u8[:]) {
    ok(str("set_header ", name), mail::set_header(m, name, value));
    sep(r.headers);
    pair(r.headers, name, value);
}

fn body(m: mail::Msg&, r: Rec&, ctype: const u8[:], text: const u8[:]) {
    ok("add_alternative", mail::add_alternative(m, ctype, text));
    sep(r.bodies);
    pair(r.bodies, ctype, text);
}

fn file(m: mail::Msg&, r: Rec&, name: const u8[:], data: const u8[:], ctype: const u8[:], want_name: const u8[:],
        want_type: const u8[:]) {
    ok(str("attach ", name), mail::attach(m, name, data, ctype));
    file_rec(r, want_name, want_type, "", data);
}

fn inline_file(m: mail::Msg&, r: Rec&, name: const u8[:], data: const u8[:], cid: const u8[:], want_type: const u8[:]) {
    ok(str("embed ", name), mail::embed(m, name, data, cid));
    file_rec(r, name, want_type, if cid.len > 0 { cid } else { name }, data);
}

fn file_rec(r: Rec&, name: const u8[:], typ: const u8[:], cid: const u8[:], data: const u8[:]) {
    sep(r.files);
    r.files.push('{');
    json::format_key(r.files, "name");
    json::format_string(r.files, name);
    r.files.push(',');
    json::format_key(r.files, "type");
    json::format_string(r.files, typ);
    r.files.push(',');
    json::format_key(r.files, "cid");
    json::format_string(r.files, cid);
    r.files.push(',');
    json::format_key(r.files, "data");
    var b: u8[>..] = [];
    base64::encode(b, data);
    json::format_string(r.files, b);
    r.files.push('}');
}

fn encoding(m: mail::Msg&, r: Rec&, enc: i64, name: const u8[:]) {
    ok("set_encoding", mail::set_encoding(m, enc));
    r.encoding.clear();
    r.encoding.append(name);
}

// Writes NAME.eml and NAME.json into dir ("" for none).
fn finish(dir: const u8[:], name: const u8[:], m: mail::Msg&, r: Rec&, structure: const u8[:]) {
    var eml: u8[>..] = [];
    let rc = mail::write(m, eml);
    ok(str("write ", name), rc);
    if rc != mail::OK || dir.len == 0 { return; }
    var j: u8[>..] = [];
    j.push('{');
    json::format_key(j, "from");
    j.append(if r.from.len > 0 { r.from[..] } else { "null" });
    fn list(key: const u8[:], items: const u8[:]) {
        j.push(',');
        json::format_key(j, key);
        j.push('[');
        j.append(items);
        j.push(']');
    }
    list("to", r.to);
    list("cc", r.cc);
    list("reply_to", r.reply_to);
    list("bcc", r.bcc);
    list("headers", r.headers);
    list("bodies", r.bodies);
    list("files", r.files);
    j.push(',');
    json::format_key(j, "subject");
    j.append(if r.subject.len > 0 { r.subject[..] } else { "null" });
    j.push(',');
    json::format_key(j, "encoding");
    json::format_string(j, if r.encoding.len > 0 { r.encoding[..] } else { "quoted-printable" });
    j.push(',');
    json::format_key(j, "structure");
    json::format_string(j, structure);
    j.push(',');
    json::format_key(j, "date");
    json::format_int(j, m.date);
    j.push(',');
    json::format_key(j, "message_id");
    json::format_string(j, mail::message_id(m));
    j.append("}\n");
    if !write_file(str(dir, "/", name, ".eml"), eml) || !write_file(str(dir, "/", name, ".json"), j) {
        print("gen_messages: cannot write into ", dir);
        exit(1);
    }
}

// --- The cases -----------------------------------------------------------------

fn plain(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "alice@example.com");
    to(m, r, "", "bob@example.com");
    subject(m, r, "Hello");
    body(m, r, "text/plain", "Hi Bob,\n\nlunch at noon?\n\n-- \nAlice\n");
    mail::set_date(m, 1700000000);
    finish(dir, "plain", m, r, "text/plain");
}

// Two forms of the body; non-ASCII everywhere, a long subject that folds
// as several encoded-words, lines QP must break.
fn alternative(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "Zoë Ångström", "zoe@example.com");
    to(m, r, "Bob \"the Builder\" Smith", "bob@example.com");
    to(m, r, "Müller, Jörg", "joerg@example.org");
    cc(m, r, "Carol", "carol@example.net");
    subject(m, r, "Réunion trimestrielle : résultats, prévisions et questions ouvertes pour l'équipe — 日本語も");
    var long: u8[>..] = [];
    for i in 60 { long.append("word "); }
    long.append("end=of=line\n.leading dot\nFrom the start\ntrailing space   \n\ttab\n");
    var text: u8[>..] = [];
    text.append("Grüße aus Zürich! ☕\n");
    text.append(long);
    body(m, r, "text/plain", text);
    body(m, r, "text/html", "<html><body><p>Grüße aus <b>Zürich</b>! ☕</p></body></html>\n");
    finish(dir, "alternative", m, r, "multipart/alternative(text/plain,text/html)");
}

// Attachments: one binary of every byte, one whose name is not ASCII
// (RFC 2231), one whose type is given; Bcc and Reply-To.
fn attachments(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "Reports", "reports@example.com");
    to(m, r, "", "team@example.com");
    bcc(m, r, "auditor@example.com");
    bcc(m, r, "boss@example.org");
    reply_to(m, r, "Help Desk <help@example.com>", "Help Desk", "help@example.com");
    subject(m, r, "Monthly figures");
    body(m, r, "text/plain", "The figures are attached.\n");
    var bin: u8[>..] = [];
    for k in 3 { for i in 256 { bin.push(i as u8); } }
    file(m, r, "blob.bin", bin, "", "blob.bin", "application/octet-stream");
    var csv: u8[>..] = [];
    csv.append("month,sales\r\n");
    for i in 12 { csv.append(str(i + 1, ",", 1000 + 37 * i, "\r\n")); }
    file(m, r, "Übersicht März 2024.csv", csv, "", "Übersicht März 2024.csv", "text/csv");
    file(m, r, "notes", "plain notes\n", "text/plain; charset=us-ascii", "notes", "text/plain");
    file(m, r, "a/b:c?.txt", "sanitized\n", "", "a_b_c_.txt", "text/plain");
    finish(dir, "attachments", m, r, "multipart/mixed(text/plain,application/octet-stream,text/csv,text/plain,text/plain)");
}

// Every level: mixed > related > alternative.
fn nested(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "News", "news@example.com");
    to(m, r, "Reader", "reader@example.com");
    subject(m, r, "Newsletter №7");
    body(m, r, "text/plain", "Our logo, and the PDF.\n");
    body(m, r, "text/html", "<p>Our logo: <img src=\"cid:logo@example.com\"></p>\n");
    var png: u8[>..] = [];
    png.append("\x89PNG\r\n\x1a\n");
    for i in 500 { png.push((i * 7) as! u8); }
    inline_file(m, r, "logo.png", png, "logo@example.com", "image/png");
    inline_file(m, r, "spacer.gif", "GIF89a\x01\x00\x01\x00", "", "image/gif");
    file(m, r, "issue7.pdf", "%PDF-1.4\n%\xe2\xe3\xcf\xd3\n", "", "issue7.pdf", "application/pdf");
    finish(dir, "nested", m, r,
           "multipart/mixed(multipart/related(multipart/alternative(text/plain,text/html),image/png,image/gif),application/pdf)");
}

fn base64_text(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "alice@example.com");
    to(m, r, "", "bob@example.com");
    subject(m, r, "Base64 body");
    encoding(m, r, mail::ENC_BASE64, "base64");
    var text: u8[>..] = [];
    for i in 40 { text.append(str("Line ", i, ": ünïcödé text that goes on for a while\n")); }
    body(m, r, "text/plain", text);
    finish(dir, "base64_text", m, r, "text/plain");
}

fn eight_bit(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "alice@example.com");
    to(m, r, "", "bob@example.com");
    subject(m, r, "8bit body");
    encoding(m, r, mail::ENC_8BIT, "8bit");
    body(m, r, "text/plain", "Ünïcödé as it is.\r\nMixed line ends\nhere\rand there.\n");
    body(m, r, "text/html", "<p>Ünïcödé</p>\n");
    finish(dir, "eight_bit", m, r, "multipart/alternative(text/plain,text/html)");
}

// A file alone is the whole body.
fn file_only(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "scanner@example.com");
    to(m, r, "", "bob@example.com");
    subject(m, r, "Scan");
    file(m, r, "scan.jpg", "\xff\xd8\xff\xe0JFIF fake", "", "scan.jpg", "image/jpeg");
    finish(dir, "file_only", m, r, "image/jpeg");
}

// Inline parts and an attachment, no text: related is not needed for one
// inline part, but mixed is, for the two (go-mail writes both at the top).
fn files_no_text(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "scanner@example.com");
    to(m, r, "", "bob@example.com");
    inline_file(m, r, "page.png", "PNG page", "", "image/png");
    file(m, r, "page.pdf", "%PDF page", "", "page.pdf", "application/pdf");
    finish(dir, "files_no_text", m, r, "multipart/mixed(image/png,application/pdf)");
}

// Two inline parts and no text: multipart/related alone.
fn inline_only(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "scanner@example.com");
    to(m, r, "", "bob@example.com");
    inline_file(m, r, "a.png", "PNG a", "", "image/png");
    inline_file(m, r, "b.png", "PNG b", "b-part", "image/png");
    finish(dir, "inline_only", m, r, "multipart/related(image/png,image/png)");
}

// Fields of every kind, and lists long enough to fold.
fn headers(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "O'Brien, Seán (Dublin)", "sean.obrien@example.ie");
    for i in 12 { to(m, r, str("Recipient Number ", i), str("recipient", i, "@lists.example.com")); }
    cc(m, r, "", "\"odd local\"@example.com");
    cc(m, r, "Dr. J. R. \"Bob\" Dobbs", "bob@subgenius.example");
    cc(m, r, "Ünïcödé Nämé", "unicode@example.com");
    subject(m, r, "A subject that is plain ASCII but long enough that the header must fold over several lines");
    header(m, r, "X-Mailer", "gslib mail");
    header(m, r, "In-Reply-To", "<1234@example.com>");
    header(m, r, "References", "<1@example.com> <2@example.com> <3@example.com> <4@example.com> <5@example.com>");
    header(m, r, "X-Note", "Ein Hinweis für alle Empfänger");
    header(m, r, "X-Tab", "a\tb");
    ok("set_importance", mail::set_importance(m, mail::IMPORTANCE_HIGH));
    body(m, r, "text/plain", "Fields.\n");
    finish(dir, "headers", m, r, "text/plain");
}

fn empty(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "alice@example.com");
    to(m, r, "", "bob@example.com");
    finish(dir, "empty", m, r, "text/plain");
}

// Long lines and nothing but white space: QP's soft breaks.
fn long_lines(dir: const u8[:]) {
    var m = mail::Msg { .. };
    var r = Rec { .. };
    from(m, r, "", "alice@example.com");
    to(m, r, "", "bob@example.com");
    subject(m, r, "x");
    var text: u8[>..] = [];
    for i in 3000 { text.push(('a' + i % 26) as u8); }
    text.append("\n   \n\n");
    for i in 500 { text.append("é"); }
    text.append("\n=\n");
    body(m, r, "text/plain", text);
    finish(dir, "long_lines", m, r, "text/plain");
}

// --- Addresses ------------------------------------------------------------------

let NAMES = [
    "", "Alice", "Bob Smith", "Joe Q. Public", "O'Brien, Seán", "Zoë", "\"Quoted\" Name", "a\\b", "Ångström (Lab)",
    "日本語の名前", "Tab\there", "=?utf-8?q?not_encoded?=", "Müller; Jörg", "  spaced  out  ", "x@y",
];
let SPECS = [
    "alice@example.com", "first.last@example.com", "user+tag@example.org", "\"odd local\"@example.com",
    "o'brien@example.ie", "a@[192.168.0.1]", "jörg@exämple.de",
];

fn addresses(dir: const u8[:]) {
    var j: u8[>..] = [];
    j.push('[');
    var n = 0;
    for name in NAMES {
        for spec in SPECS {
            let a, rc = mail::make_address(name, spec);
            ok(str("make_address ", name, " ", spec), rc);
            if n > 0 { j.append(",\n"); }
            n++;
            j.push('[');
            json::format_string(j, a.name);
            j.push(',');
            json::format_string(j, a.addr);
            j.push(',');
            json::format_string(j, mail::address_string(a));
            j.push(']');
        }
    }
    j.append("]\n");
    if dir.len == 0 { return; }
    if !write_file(str(dir, "/addr_out.json"), j) { exit(1); }
    // Python's formataddr for its own pairs, a line each: our reading.
    var input: u8[>..] = [];
    if !read_file(str(dir, "/addr_in.txt"), input) { return; }
    var p: u8[>..] = [];
    p.push('[');
    var first = true;
    each_split(input, '\n') {
        let line = if it.len > 0 && it[it.len - 1] == '\r' { it[..it.len - 1] } else { it };
        if line.len > 0 {
            let a, rc = mail::parse_address(line);
            if !first { p.append(",\n"); }
            first = false;
            p.push('[');
            json::format_string(p, line);
            p.push(',');
            json::format_bool(p, rc == mail::OK);
            p.push(',');
            json::format_string(p, a.name);
            p.push(',');
            json::format_string(p, a.addr);
            p.push(']');
        }
    };
    p.append("]\n");
    if !write_file(str(dir, "/addr_parsed.json"), p) { exit(1); }
}

fn main() {
    let a = args();
    let dir = if a.len > 1 { a[1] } else { "" };
    plain(dir);
    alternative(dir);
    attachments(dir);
    nested(dir);
    base64_text(dir);
    eight_bit(dir);
    file_only(dir);
    files_no_text(dir);
    inline_only(dir);
    headers(dir);
    empty(dir);
    long_lines(dir);
    addresses(dir);
    if failures > 0 { exit(1); }
}
