// mail.message: an email message, built up and written in RFC 5322 and
// MIME form, as go-mail's Msg and msgWriter compose one.
//
//     var m = mail::Msg { .. };
//     mail::set_from(m, "Alice <alice@example.com>");
//     mail::add_to(m, "bob@example.com, Carol <carol@example.com>");
//     mail::set_subject(m, "Café at noon?");
//     mail::set_body(m, mail::TEXT_PLAIN, "See you there.\n");
//     mail::add_alternative(m, mail::TEXT_HTML, "<p>See you there.</p>");
//     mail::attach(m, "menu.pdf", pdf_bytes);
//     var out: u8[>..] = [];
//     let rc = mail::write(m, out);        // the message, ready for SMTP's DATA
//
// The body nests as go-mail nests it: multipart/mixed (the attachments)
// around multipart/related (the inline parts, each with a Content-ID)
// around multipart/alternative (the text and HTML bodies), each level
// there only when it has more than one thing in it. Text bodies are UTF-8,
// quoted-printable unless set_encoding says base64 or 8bit; files are
// base64 in 76-column lines; non-ASCII header text is RFC 2047
// encoded-words, non-ASCII file names RFC 2231 parameters.
//
// write gives CRLF line endings throughout, ends with CRLF, and folds
// header lines at 76 columns where they have room; no line passes 998
// bytes (RFC 5322 §2.1.1), or write fails with ERR_LONG_LINE. It does not
// dot-stuff: that is SMTP's DATA. Bcc is never written; recipients gives
// it to the SMTP client with To and Cc.
//
// What write cannot be told it makes up the first time and keeps in the
// message, so that a second write is the same: the Date (now), the
// Message-ID (22 random characters @ the host, "localhost.localdomain"
// unless set_host) and the multipart boundaries (24 random bytes in hex).
// set_date, set_message_id and set_boundary fix them for tests.

namespace mail;

import std;
import os;
import base64;
import mime;
import mime.encodedword;
import mime.quotedprintable;
import mime.types_builtin;
import encoding.asn1;
import crypto.bignum.entropy;
import mail;
import mail.address;

// Content-Transfer-Encodings of the text bodies.
let ENC_QP:     i64 = 0;         // quoted-printable (the default)
let ENC_BASE64: i64 = 1;
let ENC_8BIT:   i64 = 2;         // as it is, line ends made CRLF; for servers with 8BITMIME

// set_importance: go-mail's levels and the headers they write.
let IMPORTANCE_NORMAL:     i64 = 0; // no header
let IMPORTANCE_LOW:        i64 = 1;
let IMPORTANCE_HIGH:       i64 = 2;
let IMPORTANCE_NON_URGENT: i64 = 3;
let IMPORTANCE_URGENT:     i64 = 4;

let TEXT_PLAIN: const u8[:] = "text/plain";
let TEXT_HTML:  const u8[:] = "text/html";

let MAX_HEADER_LINE: i64 = 76;   // where header lines fold (go-mail's MaxHeaderLength)
let MAX_LINE:        i64 = 998;  // RFC 5322 §2.1.1, without the CRLF
let FILE_NAME_MAX:   i64 = 255;
let BOUNDARY_MAX:    i64 = 60;   // set_boundary's; a level's suffix makes it at most 70

// Bytes of the message's arena.
struct MsgSpan { pos: i64 = 0, end: i64 = 0 }

// A header field of set_header and add_header (gone: replaced or deleted).
struct MsgField { name: u8[..76] = [], value: MsgSpan = MsgSpan { .. }, gone: bool = false }

// A body: its Content-Type (charset included) and its text.
struct MsgPart { ctype: MsgSpan = MsgSpan { .. }, body: MsgSpan = MsgSpan { .. } }

// An attachment, or an inline part of multipart/related.
struct MsgFile {
    name:   MsgSpan = MsgSpan { .. },      // sanitized
    ctype:  MsgSpan = MsgSpan { .. },      // with its name parameter
    cid:    MsgSpan = MsgSpan { .. },      // inline parts: the Content-ID, without <>
    inline: bool    = false,
    data:   MsgSpan = MsgSpan { .. },
}

root struct Msg {
    from:         Address       = Address { .. },
    has_from:     bool          = false,
    envelope:     Address       = Address { .. }, // set_envelope_from: MAIL FROM, when not From's
    has_envelope: bool          = false,
    to:           Address[>..]  = [],
    cc:           Address[>..]  = [],
    bcc:          Address[>..]  = [],
    reply_to:     Address[>..]  = [],
    subject:      u8[>..]       = [],
    has_subject:  bool          = false,
    fields:       MsgField[>..] = [],
    parts:        MsgPart[>..]  = [],
    files:        MsgFile[>..]  = [],
    arena:        u8[>..]       = [],      // header values, bodies, files' names and bytes
    encoding:     i64           = ENC_QP,
    importance:   i64           = IMPORTANCE_NORMAL,
    date:         i64           = 0,       // unix seconds
    has_date:     bool          = false,
    message_id:   u8[>..]       = [],      // without <>
    host:         u8[>..]       = [],      // "" for localhost.localdomain
    boundary:     u8[..60]      = [],
}

fn msg_keep(m: Msg&, s: const u8[:]) -> MsgSpan {
    let pos = m.arena.len;
    m.arena.append(s);
    return MsgSpan { pos: pos, end: m.arena.len };
}

fn msg_text(m: const Msg&, s: MsgSpan) -> const u8[:] { m.arena[s.pos..s.end] }

fn msg_has_break(s: const u8[:]) -> bool {
    for c in s { if c == '\r' || c == '\n' || c == 0 { return true; } }
    return false;
}

// --- Addresses ---------------------------------------------------------------

fn set_from(m: Msg&, s: const u8[:]) -> i64 {
    let a, rc = parse_address(s);
    if rc != OK { return rc; }
    m.from = a;
    m.has_from = true;
    return OK;
}

fn set_from(m: Msg&, a: const Address&) {
    m.from = a;
    m.has_from = true;
}

// The address for SMTP's MAIL FROM, when it is not From's (a bounce
// address); not written in the header.
fn set_envelope_from(m: Msg&, s: const u8[:]) -> i64 {
    let a, rc = parse_address(s);
    if rc != OK { return rc; }
    m.envelope = a;
    m.has_envelope = true;
    return OK;
}

// A list into l: appended, or in place of what l held. On an error l is
// as it was; a blank list empties it.
fn msg_list(l: Address[>..]&, s: const u8[:], replace: bool) -> i64 {
    var blank = true;
    for c in s { if c != ' ' && c != '\t' { blank = false; } }
    if blank && !msg_has_break(s) {
        if replace { l.clear(); }
        return OK;
    }
    var got: Address[>..] = [];
    let rc = parse_address_list(s, got);
    if rc != OK { return rc; }
    if replace { l.clear(); }
    for a in got { l.push(a); }
    return OK;
}

// set_*: the list in place of the one there; add_*: appended to it. s is
// a comma-separated list (parse_address_list).
fn set_to(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.to, s, true) }
fn add_to(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.to, s, false) }
fn set_cc(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.cc, s, true) }
fn add_cc(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.cc, s, false) }
fn set_bcc(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.bcc, s, true) }
fn add_bcc(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.bcc, s, false) }
fn set_reply_to(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.reply_to, s, true) }
fn add_reply_to(m: Msg&, s: const u8[:]) -> i64 { msg_list(m.reply_to, s, false) }

fn add_to(m: Msg&, a: const Address&) { m.to.push(a); }
fn add_cc(m: Msg&, a: const Address&) { m.cc.push(a); }
fn add_bcc(m: Msg&, a: const Address&) { m.bcc.push(a); }

// MAIL FROM: the envelope address if set, else From's ("" if neither).
fn envelope_from(m: const Msg&) -> const u8[:] {
    if m.has_envelope { return m.envelope.addr[..]; }
    if m.has_from { return m.from.addr[..]; }
    return "";
}

// RCPT TO: the addr-specs of To, Cc and Bcc, each once, appended to out.
// The domain is compared without case, the local part as it is.
fn recipients(m: const Msg&, out: u8[][>..]&) {
    var seen: u8[..320][>..] = [];
    fn one(a: const Address&) {
        for s in seen { if msg_same_addr(s, a.addr) { return; } }
        seen.push(a.addr);
        out.push(a.addr[..]);
    }
    for a in m.to { one(a); }
    for a in m.cc { one(a); }
    for a in m.bcc { one(a); }
}

fn msg_same_addr(a: const u8[:], b: const u8[:]) -> bool {
    if a.len != b.len { return false; }
    var at = -1;
    for i in a.len { if a[i] == '@' { at = i; } }
    for i in a.len {
        if i > at { if mime::lower_byte(a[i]) != mime::lower_byte(b[i]) { return false; } }
        else if a[i] != b[i] { return false; }
    }
    return true;
}

// Whether an envelope address is not ASCII, so the SMTP client needs the
// server's SMTPUTF8 (RFC 6531).
fn needs_smtputf8(m: const Msg&) -> bool {
    fn wide(a: const Address&) -> bool {
        for c in a.addr { if c >= 0x80 { return true; } }
        return false;
    }
    if m.has_envelope && wide(m.envelope) { return true; }
    if m.has_from && wide(m.from) { return true; }
    for a in m.to { if wide(a) { return true; } }
    for a in m.cc { if wide(a) { return true; } }
    for a in m.bcc { if wide(a) { return true; } }
    return false;
}

// --- Header fields -------------------------------------------------------------

fn set_subject(m: Msg&, s: const u8[:]) -> i64 {
    if msg_has_break(s) { return ERR_HEADER; }
    m.subject.clear();
    m.subject.append(s);
    m.has_subject = true;
    return OK;
}

// The fields the message writes itself, which set_header refuses.
fn msg_own_field(name: const u8[:]) -> bool {
    eq_fold(name, "From") || eq_fold(name, "To") || eq_fold(name, "Cc") || eq_fold(name, "Bcc") ||
    eq_fold(name, "Reply-To") || eq_fold(name, "Subject") || eq_fold(name, "Date") ||
    eq_fold(name, "Message-ID") || eq_fold(name, "MIME-Version") || eq_fold(name, "Content-Type") ||
    eq_fold(name, "Content-Transfer-Encoding") || eq_fold(name, "Content-Disposition") ||
    eq_fold(name, "Content-ID")
}

// A field name: 1 to 76 printable ASCII bytes, no colon (RFC 5322 §2.2).
fn msg_field_name_ok(name: const u8[:]) -> bool {
    if name.len == 0 || name.len > 76 { return false; }
    for c in name { if c < '!' || c > '~' || c == ':' { return false; } }
    return true;
}

fn msg_check_field(name: const u8[:], value: const u8[:]) -> i64 {
    if !msg_field_name_ok(name) || msg_own_field(name) || msg_has_break(value) { return ERR_HEADER; }
    return OK;
}

// A header field, in place of any of that name (compared without case).
// Non-ASCII in the value is written as encoded-words, so the value is
// unstructured text; one that must stay as it is (a structured field)
// must be ASCII. The fields the message writes itself are refused.
fn set_header(m: Msg&, name: const u8[:], value: const u8[:]) -> i64 {
    let rc = msg_check_field(name, value);
    if rc != OK { return rc; }
    del_header(m, name);
    return add_header(m, name, value);
}

// Another field of that name, after those there.
fn add_header(m: Msg&, name: const u8[:], value: const u8[:]) -> i64 {
    let rc = msg_check_field(name, value);
    if rc != OK { return rc; }
    var f = MsgField { .. };
    f.name.append(name);
    f.value = msg_keep(m, value);
    m.fields.push(f);
    return OK;
}

fn del_header(m: Msg&, name: const u8[:]) {
    for &f in m.fields { if eq_fold(f.name, name) { f.gone = true; } }
}

// The value of the first field of that name set by set_header or
// add_header, and whether there is one.
fn header(m: const Msg&, name: const u8[:]) -> const u8[:], bool {
    for f in m.fields { if !f.gone && eq_fold(f.name, name) { return msg_text(m, f.value), true; } }
    return "", false;
}

// The Date, in seconds since 1970 (UTC); written as RFC 5322 has it, +0000.
fn set_date(m: Msg&, unix_seconds: i64) {
    m.date = unix_seconds;
    m.has_date = true;
}

// The Message-ID: "id" (write puts "@" and the host after it) or
// "id@host", with or without the <>; atext and dots, one "@", brackets
// for a domain-literal.
fn set_message_id(m: Msg&, id: const u8[:]) -> i64 {
    var s = id;
    if s.len >= 2 && s[0] == '<' && s[s.len - 1] == '>' { s = s[1..s.len - 1]; }
    if s.len == 0 || s.len > 900 || s[0] == '@' || s[s.len - 1] == '@' { return ERR_HEADER; }
    var ats = 0;
    for c in s {
        if c == '@' { ats++; }
        else if c >= 0x80 || !(addr_is_atext(c, true) || c == '[' || c == ']') { return ERR_HEADER; }
    }
    if ats > 1 { return ERR_HEADER; }
    var id2: u8[>..] = [];
    id2.append(s);              // s may be a view of the one there
    m.message_id.clear();
    m.message_id.append(id2);
    return OK;
}

// The host of a made-up Message-ID ("localhost.localdomain" if not set;
// nothing asks the system for its name).
fn set_host(m: Msg&, host: const u8[:]) -> i64 {
    if host.len == 0 || host.len > 255 { return ERR_ARG; }
    for c in host { if c <= ' ' || c >= 0x7f || c == '<' || c == '>' || c == '@' { return ERR_ARG; } }
    m.host.clear();
    m.host.append(host);
    return OK;
}

// The Message-ID without its <>: set_message_id's, or the one the first
// write made ("" before).
fn message_id(m: const Msg&) -> const u8[:] { m.message_id[..] }

// Importance, Priority, X-Priority and X-MSMail-Priority, as go-mail
// writes them (none for IMPORTANCE_NORMAL).
fn set_importance(m: Msg&, level: i64) -> i64 {
    if level < IMPORTANCE_NORMAL || level > IMPORTANCE_URGENT { return ERR_ARG; }
    m.importance = level;
    return OK;
}

fn set_encoding(m: Msg&, enc: i64) -> i64 {
    if enc != ENC_QP && enc != ENC_BASE64 && enc != ENC_8BIT { return ERR_ARG; }
    m.encoding = enc;
    return OK;
}

// The multipart boundaries: b with "-mixed", "-related" or "-alt" after
// it. b is 1 to 60 of RFC 2046's bchars, no space; it must not appear in
// a body that is 8bit.
fn set_boundary(m: Msg&, b: const u8[:]) -> i64 {
    if b.len < 1 || b.len > BOUNDARY_MAX { return ERR_ARG; }
    for c in b {
        let ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                 c == '\'' || c == '(' || c == ')' || c == '+' || c == '_' || c == ',' || c == '-' ||
                 c == '.' || c == '/' || c == ':' || c == '=' || c == '?';
        if !ok { return ERR_ARG; }
    }
    m.boundary.clear();
    m.boundary.append(b);
    return OK;
}

// --- Bodies and files ---------------------------------------------------------

// A body's Content-Type: ctype's type and parameters, charset=UTF-8 in
// place of any charset. ERR_ARG if ctype does not parse.
fn msg_body_type(m: Msg&, ctype: const u8[:]) -> MsgSpan, i64 {
    if msg_has_break(ctype) { return MsgSpan { .. }, ERR_ARG; }
    let mt = mime::parse_media_type(ctype);
    if mt.err != mime::OK || mime::index_byte(mt.typ, '/') < 0 { return MsgSpan { .. }, ERR_ARG; }
    var kvs: mime::KV[>..] = [];
    for p in mt.params { if p.name != "charset" { kvs.push(mime::KV { key: p.name, value: p.value }); } }
    kvs.push(mime::KV { key: "charset", value: "UTF-8" });
    var s: u8[>..] = [];
    if !mime::format_media_type(s, mt.typ, kvs) { return MsgSpan { .. }, ERR_ARG; }
    return msg_keep(m, s), OK;
}

// The body: one of this type (TEXT_PLAIN, TEXT_HTML, ...), in place of
// any there. body is UTF-8 text, its line ends LF or CRLF.
fn set_body(m: Msg&, ctype: const u8[:], body: const u8[:]) -> i64 {
    let ct, rc = msg_body_type(m, ctype);
    if rc != OK { return rc; }
    m.parts.clear();
    m.parts.push(MsgPart { ctype: ct, body: msg_keep(m, body) });
    return OK;
}

// Another form of the body (multipart/alternative), after those there:
// the plainest first, the one the sender prefers last (RFC 2046 §5.1.4).
fn add_alternative(m: Msg&, ctype: const u8[:], body: const u8[:]) -> i64 {
    let ct, rc = msg_body_type(m, ctype);
    if rc != OK { return rc; }
    m.parts.push(MsgPart { ctype: ct, body: msg_keep(m, body) });
    return OK;
}

// sanitizeFilename: controls and " / : < > ? \ | made '_'.
fn msg_sanitize(out: u8[>..]&, name: const u8[:]) {
    for c in name {
        if c < 32 || c == '"' || c == '/' || c == ':' || c == '<' || c == '>' || c == '?' || c == '\\' ||
           c == '|' || c == 127 { out.push('_'); } else { out.push(c); }
    }
}

// The media type of a file name's extension from Go's built-in table
// (not the system's, which would make the message depend on the machine);
// application/octet-stream if it has none there.
fn msg_type_by_name(name: const u8[:]) -> const u8[:] {
    var dot = -1;
    for i in name.len { if name[i] == '.' { dot = i; } }
    if dot < 0 { return "application/octet-stream"; }
    var ext: u8[>..] = [];
    mime::append_lower(ext, name[dot..]);
    for i in mime::BUILTIN_TYPES.len { if mime::BUILTIN_TYPES[i].key == ext { return mime::BUILTIN_TYPES[i].value; } }
    return "application/octet-stream";
}

fn msg_add_file(m: Msg&, name: const u8[:], data: const u8[:], ctype: const u8[:], cid: const u8[:],
                inline: bool) -> i64 {
    if name.len == 0 || name.len > FILE_NAME_MAX || msg_has_break(ctype) { return ERR_ARG; }
    var clean: u8[>..] = [];
    msg_sanitize(clean, name);
    let typ = if ctype.len > 0 { ctype } else { msg_type_by_name(clean) };
    let mt = mime::parse_media_type(typ);
    if mt.err != mime::OK || mime::index_byte(mt.typ, '/') < 0 { return ERR_ARG; }
    var kvs: mime::KV[>..] = [];
    for p in mt.params { if p.name != "name" { kvs.push(mime::KV { key: p.name, value: p.value }); } }
    kvs.push(mime::KV { key: "name", value: clean });
    var ct: u8[>..] = [];
    if !mime::format_media_type(ct, mt.typ, kvs) { return ERR_ARG; }
    var id = if cid.len > 0 { cid } else { clean[..] };
    if inline {
        if id.len >= 2 && id[0] == '<' && id[id.len - 1] == '>' { id = id[1..id.len - 1]; }
        if id.len == 0 || id.len > 900 { return ERR_ARG; }
        for c in id { if c <= ' ' || c >= 0x7f || c == '<' || c == '>' { return ERR_ARG; } }
    }
    var f = MsgFile { inline: inline, .. };
    f.name = msg_keep(m, clean);
    f.ctype = msg_keep(m, ct);
    if inline { f.cid = msg_keep(m, id); }
    f.data = msg_keep(m, data);
    m.files.push(f);
    return OK;
}

// An attachment (Content-Disposition: attachment), base64. ctype ""
// takes the type from the name's extension. The name is the file's name
// for the reader, its controls and " / : < > ? \ | made '_'.
fn attach(m: Msg&, name: const u8[:], data: const u8[:], ctype: const u8[:] = "") -> i64 {
    return msg_add_file(m, name, data, ctype, "", false);
}

// An inline part (multipart/related), which an HTML body shows as
// "cid:" and its Content-ID; content_id "" takes the name.
fn embed(m: Msg&, name: const u8[:], data: const u8[:], content_id: const u8[:] = "", ctype: const u8[:] = "") -> i64 {
    return msg_add_file(m, name, data, ctype, content_id, true);
}

// --- Writing -------------------------------------------------------------------

let DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
let MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

// RFC 5322 §3.3 (Go's RFC1123Z), in UTC: "Mon, 02 Jan 2006 15:04:05 +0000".
fn write_date(out: u8[>..]&, unix_seconds: i64) {
    let rem = unix_seconds % 86400;                  // Euclidean: 0..86399
    let days = (unix_seconds - rem) / 86400;
    let y, mo, d = asn1::civil_from_days(days);
    out.append(DAY_NAMES[(days + 4) % 7]);           // 1970-01-01 was a Thursday
    out.append(", ");
    format_int(out, d, 10, 2, '0');
    out.push(' ');
    out.append(MONTH_NAMES[mo - 1]);
    out.push(' ');
    format_int(out, y, 10, 4, '0');
    out.push(' ');
    format_int(out, rem / 3600, 10, 2, '0');
    out.push(':');
    format_int(out, rem / 60 % 60, 10, 2, '0');
    out.push(':');
    format_int(out, rem % 60, 10, 2, '0');
    out.append(" +0000");
}

// go-mail's alphabet for random strings, '.' made '-' so that the
// Message-ID is a dot-atom.
let ID_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// What write makes up when it was not set: the Date, Message-ID and boundary.
fn msg_defaults(m: Msg&) {
    if !m.has_date { set_date(m, time_ns() / 1000000000); }
    if m.message_id.len == 0 {
        var raw: u8[22] = [0; 22];
        bignum::random_bytes(raw);
        for b in raw { m.message_id.push(ID_CHARS[b & 63]); }
    }
    if mime::index_byte(m.message_id, '@') < 0 {
        m.message_id.push('@');
        if m.host.len > 0 { m.message_id.append(m.host); } else { m.message_id.append("localhost.localdomain"); }
    }
    if m.boundary.len == 0 {
        var raw: u8[24] = [0; 24];
        bignum::random_bytes(raw);
        for b in raw { m.boundary.push(mime::LOWERHEX[b >> 4]); m.boundary.push(mime::LOWERHEX[b & 15]); }
    }
}

// A header field, folded: a space where the line would pass 76 bytes
// becomes CRLF and the space, so unfolding gives the value back. With
// structured set, never inside a quoted-string. ERR_HEADER if a line must
// still pass 998 bytes.
fn write_field(out: u8[>..]&, name: const u8[:], value: const u8[:], structured: bool) -> i64 {
    out.append(name);
    out.append(":");
    var line = name.len + 1;
    if value.len == 0 { out.append("\r\n"); return OK; }
    out.push(' ');
    line++;
    var i = 0;
    var first = true;
    loop {
        // The word from i to the next space (outside quotes when structured).
        var j = i;
        var quoted = false;
        while j < value.len {
            let c = value[j];
            if structured && quoted && c == '\\' && j + 1 < value.len { j += 2; continue; }
            if structured && c == '"' { quoted = !quoted; }
            else if c == ' ' && !quoted { break; }
            j++;
        }
        let word = value[i..j];
        if !first {
            // Never before a word of white space alone, which would be a
            // line of it (RFC 5322 §3.2.2).
            if msg_has_text(word) && line + 1 + word.len > MAX_HEADER_LINE && line > 1 {
                out.append("\r\n ");
                line = 1;
            } else {
                out.push(' ');
                line++;
            }
        }
        out.append(word);
        line += word.len;
        if line > MAX_LINE { return ERR_HEADER; }
        first = false;
        if j >= value.len { break; }
        i = j + 1;
    }
    out.append("\r\n");
    return OK;
}

fn msg_has_text(s: const u8[:]) -> bool {
    for c in s { if c != ' ' && c != '\t' { return true; } }
    return false;
}

// An address field: the addresses written as (*Address).String, ", "
// between them. ERR_ADDRESS for an Address made by hand (or given by a
// server) with CR, LF or NUL in it, which could start a header of its own.
fn write_address_field(out: u8[>..]&, name: const u8[:], list: const Address[:]) -> i64 {
    var v: u8[>..] = [];
    for i in list.len {
        if addr_has_break(list[i].name) || addr_has_break(list[i].addr) { return ERR_ADDRESS; }
        if i > 0 { v.append(", "); }
        write_address(v, list[i]);
    }
    return write_field(out, name, v, true);
}

// Unstructured text: encoded-words (Q, UTF-8) when it is not printable ASCII.
fn write_text_field(out: u8[>..]&, name: const u8[:], value: const u8[:]) -> i64 {
    var v: u8[>..] = [];
    mime::encode_word(v, mime::Q_ENCODING, "UTF-8", value);
    return write_field(out, name, v, false);
}

// Text with its line ends made CRLF (a lone CR or LF, or CRLF).
fn msg_crlf(out: u8[>..]&, s: const u8[:]) {
    var i = 0;
    while i < s.len {
        let c = s[i];
        if c == '\r' {
            out.append("\r\n");
            if i + 1 < s.len && s[i + 1] == '\n' { i++; }
        } else if c == '\n' {
            out.append("\r\n");
        } else {
            out.push(c);
        }
        i++;
    }
}

// Base64 in lines of 76, each ended by CRLF (go-mail's base64LineBreaker).
fn msg_base64(out: u8[>..]&, data: const u8[:]) {
    var enc: u8[>..] = [];
    base64::encode(enc, data);
    var i = 0;
    while i < enc.len {
        let e = ::min(i + 76, enc.len);
        out.append(enc[i..e]);
        out.append("\r\n");
        i = e;
    }
}

fn msg_encoding_name(enc: i64) -> const u8[:] {
    if enc == ENC_BASE64 { return "base64"; }
    if enc == ENC_8BIT { return "8bit"; }
    return "quoted-printable";
}

// The multiparts open while writing: their kinds, outermost first, and
// whether each has had a part.
let MP_MIXED:   i64 = 0;
let MP_RELATED: i64 = 1;
let MP_ALT:     i64 = 2;

struct MsgNest { kind: i64[3] = [0; 3], started: bool[3] = [false; 3], depth: i64 = 0 }

fn msg_mp_name(kind: i64) -> const u8[:] {
    if kind == MP_MIXED { return "mixed"; }
    if kind == MP_RELATED { return "related"; }
    return "alternative";
}

fn msg_mp_suffix(kind: i64) -> const u8[:] {
    if kind == MP_MIXED { return "-mixed"; }
    if kind == MP_RELATED { return "-related"; }
    return "-alt";
}

fn msg_write_boundary(out: u8[>..]&, m: const Msg&, kind: i64) {
    out.append(m.boundary);
    out.append(msg_mp_suffix(kind));
}

// A part's start: its delimiter line inside the multipart around it (none
// at the top, where its fields go on with the message's).
fn msg_begin_part(out: u8[>..]&, m: const Msg&, w: MsgNest&) {
    if w.depth == 0 { return; }
    let d = w.depth - 1;
    out.append(if w.started[d] { "\r\n--" } else { "--" });
    msg_write_boundary(out, m, w.kind[d]);
    out.append("\r\n");
    w.started[d] = true;
}

fn msg_open(out: u8[>..]&, m: const Msg&, w: MsgNest&, kind: i64) {
    msg_begin_part(out, m, w);
    out.append("Content-Type: multipart/");
    out.append(msg_mp_name(kind));
    out.append(";\r\n boundary=");
    var b: u8[>..] = [];
    msg_write_boundary(b, m, kind);
    if mime::is_token(b) { out.append(b); } else { out.push('"'); out.append(b); out.push('"'); }
    out.append("\r\n\r\n");
    w.kind[w.depth] = kind;
    w.started[w.depth] = false;
    w.depth++;
}

fn msg_close(out: u8[>..]&, m: const Msg&, w: MsgNest&) {
    w.depth--;
    out.append("\r\n--");
    msg_write_boundary(out, m, w.kind[w.depth]);
    out.append("--\r\n");
}

// A body: its fields (sorted, as Go's CreatePart writes them), a blank
// line, the text encoded.
fn msg_write_part(out: u8[>..]&, m: const Msg&, w: MsgNest&, p: MsgPart) -> i64 {
    msg_begin_part(out, m, w);
    var rc = write_field(out, "Content-Transfer-Encoding", msg_encoding_name(m.encoding), true);
    if rc == OK { rc = write_field(out, "Content-Type", msg_text(m, p.ctype), true); }
    if rc != OK { return rc; }
    out.append("\r\n");
    let body = msg_text(m, p.body);
    if m.encoding == ENC_QP {
        quotedprintable::encode_all(out, body);
    } else {
        var text: u8[>..] = [];
        msg_crlf(text, body);
        if m.encoding == ENC_BASE64 { msg_base64(out, text); } else { out.append(text); }
    }
    return OK;
}

// A file: Content-Disposition, Content-ID (inline), the encoding and
// Content-Type, then its bytes in base64.
fn msg_write_file(out: u8[>..]&, m: const Msg&, w: MsgNest&, f: MsgFile) -> i64 {
    msg_begin_part(out, m, w);
    var cd: u8[>..] = [];
    if !mime::format_media_type(cd, if f.inline { "inline" } else { "attachment" },
                                [mime::KV { key: "filename", value: msg_text(m, f.name) }]) { return ERR_ARG; }
    var rc = write_field(out, "Content-Disposition", cd, true);
    if rc == OK && f.inline {
        var cid: u8[>..] = [];
        cid.push('<');
        cid.append(msg_text(m, f.cid));
        cid.push('>');
        rc = write_field(out, "Content-ID", cid, true);
    }
    if rc == OK { rc = write_field(out, "Content-Transfer-Encoding", "base64", true); }
    if rc == OK { rc = write_field(out, "Content-Type", msg_text(m, f.ctype), true); }
    if rc != OK { return rc; }
    out.append("\r\n");
    msg_base64(out, msg_text(m, f.data));
    return OK;
}

fn msg_header(out: u8[>..]&, m: Msg&) -> i64 {
    var date: u8[>..] = [];
    write_date(date, m.date);
    var rc = write_field(out, "Date", date, true);
    if rc == OK && m.has_from { rc = write_address_field(out, "From", [m.from]); }
    if rc == OK && m.reply_to.len > 0 { rc = write_address_field(out, "Reply-To", m.reply_to); }
    if rc == OK && m.to.len > 0 { rc = write_address_field(out, "To", m.to); }
    if rc == OK && m.cc.len > 0 { rc = write_address_field(out, "Cc", m.cc); }
    if rc == OK && m.has_subject { rc = write_text_field(out, "Subject", m.subject); }
    if rc == OK {
        var id: u8[>..] = [];
        id.push('<');
        id.append(m.message_id);
        id.push('>');
        rc = write_field(out, "Message-ID", id, true);
    }
    if rc == OK { rc = write_field(out, "MIME-Version", "1.0", true); }
    if rc == OK && m.importance != IMPORTANCE_NORMAL {
        let lv = m.importance;
        let high = lv == IMPORTANCE_HIGH || lv == IMPORTANCE_URGENT;
        let word = if lv == IMPORTANCE_LOW { "low" } else if lv == IMPORTANCE_HIGH { "high" }
                   else if lv == IMPORTANCE_URGENT { "urgent" } else { "non-urgent" };
        rc = write_field(out, "Importance", word, true);
        if rc == OK { rc = write_field(out, "Priority", if high { "1" } else { "0" }, true); }
        if rc == OK { rc = write_field(out, "X-Priority", if high { "1" } else { "5" }, true); }
        if rc == OK { rc = write_field(out, "X-MSMail-Priority", if high { "1" } else { "0" }, true); }
    }
    for f in m.fields {
        if rc != OK { break; }
        if !f.gone { rc = write_text_field(out, f.name, msg_text(m, f.value)); }
    }
    return rc;
}

// The message, appended to out: the header, then the body. On an error
// out is as it was.
fn write(m: Msg&, out: u8[>..]&) -> i64 {
    msg_defaults(m);
    let mark = out.len;
    let rc = msg_write(m, out);
    if rc != OK { out.resize(mark); return rc; }
    // CRLF at the end, and no line longer than 998 bytes.
    if out.len == mark || out[out.len - 1] != '\n' { out.append("\r\n"); }
    var start = mark;
    for i in mark..out.len {
        if out[i] == '\n' {
            if i - 1 - start > MAX_LINE { out.resize(mark); return ERR_LONG_LINE; }
            start = i + 1;
        }
    }
    return OK;
}

fn msg_write(m: Msg&, out: u8[>..]&) -> i64 {
    var rc = msg_header(out, m);
    if rc != OK { return rc; }
    var nembed = 0;
    var nattach = 0;
    for f in m.files { if f.inline { nembed++; } else { nattach++; } }
    let nparts = m.parts.len;
    // Each level only when it holds more than one thing.
    let alt = nparts > 1;
    let related = nembed > 0 && (nparts > 0 || nembed > 1);
    let mixed = nattach > 0 && (nparts > 0 || nembed > 0 || nattach > 1);
    var w = MsgNest { .. };
    if mixed { msg_open(out, m, w, MP_MIXED); }
    if related { msg_open(out, m, w, MP_RELATED); }
    if alt { msg_open(out, m, w, MP_ALT); }
    if nparts == 0 && m.files.len == 0 {
        let empty = MsgPart { ctype: msg_keep(m, "text/plain; charset=UTF-8"), body: MsgSpan { .. } };
        rc = msg_write_part(out, m, w, empty);
    }
    for p in m.parts {
        if rc != OK { break; }
        rc = msg_write_part(out, m, w, p);
    }
    if rc != OK { return rc; }
    if alt { msg_close(out, m, w); }
    for f in m.files {
        if rc != OK { break; }
        if f.inline { rc = msg_write_file(out, m, w, f); }
    }
    if rc != OK { return rc; }
    if related { msg_close(out, m, w); }
    for f in m.files {
        if rc != OK { break; }
        if !f.inline { rc = msg_write_file(out, m, w, f); }
    }
    if rc != OK { return rc; }
    if mixed { msg_close(out, m, w); }
    return OK;
}
