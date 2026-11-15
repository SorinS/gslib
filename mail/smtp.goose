// mail.smtp: an SMTP client (RFC 5321), as go-mail's smtp package and its
// Client have it: EHLO (HELO when the server has no ESMTP), STARTTLS
// (RFC 3207) or TLS from the first byte (RFC 8314's submissions on 465),
// AUTH (RFC 4954) with mail.sasl's mechanisms, MAIL with 8BITMIME,
// SMTPUTF8 (RFC 6531) and DSN (RFC 3461), RCPT, DATA with dot-stuffing,
// RSET, NOOP, VRFY and QUIT.
//
//   var c = smtp::Client { .. };
//   var e = smtp::dial(c, "mail.example.com", 587, smtp::TLS_MANDATORY);
//   if e == mail::OK { e = smtp::auth(c, mail::AUTH_AUTO, "user", "password"); }
//   if e == mail::OK { e = smtp::send(c, "me@example.com", ["you@example.com"], msg); }
//   // or a message built with mail.message: smtp::send_message(c, m)
//   smtp::quit(c);
//   // on mail::ERR_REPLY, c.code and c.text are the server's reply
//
// One message at a time on a connection; send may be called again after
// it returns (a refused message is RSET first). c.tlscfg is the TLS
// client's configuration: its roots (the system's by default), verify
// (false skips the certificate check, for tests) and the rest.

namespace smtp;

import std;
import base64;
import mail;
import mail.link;
import mail.sasl;
import mail.address;
import mail.message;
import crypto.tls;
import crypto.tls.handshake;

// How a connection gets TLS, as go-mail's TLSPolicy and SSL options.
let TLS_MANDATORY:     i64 = 0;  // STARTTLS, and fail (ERR_NO_TLS) when the server does not offer it
let TLS_OPPORTUNISTIC: i64 = 1;  // STARTTLS when the server offers it, plain text when not
let TLS_NONE:          i64 = 2;  // never: plain text throughout
let TLS_IMPLICIT:      i64 = 3;  // TLS from the first byte, the submissions port's way (465)

let MAX_LINE:        i64 = 4096; // a reply line's limit (RFC 5321's is 512; servers send more)
let MAX_REPLY_LINES: i64 = 1000;

root struct Client {
    // mail.link's
    fd:         i64               = -1,
    secure:     bool              = false,
    tc:         tls::Conn         = tls::new_conn(false, 0),
    tlscfg:     tls::ClientConfig = tls::client_config("", ""),
    inbuf:      u8[>..]           = [],
    inpos:      i64               = 0,
    wire:       u8[>..]           = [],
    raw:        u8[>..]           = [],
    timeout_ms: i64               = 30000,
    // SMTP's
    host:       u8[..255] = "",      // the server's name, for TLS
    local_name: u8[..255] = "localhost", // EHLO's argument
    esmtp:      bool      = false,   // EHLO worked (HELO did not need to be used)
    ext:        u8[>..]   = [],      // EHLO's extension lines, each "KEYWORD params\n"
    code:       i64       = 0,       // the last reply's code
    text:       u8[>..]   = [],      // its text, the lines joined with '\n', the codes left out
    dsn_ret:    u8[..8]   = "",      // DSN: MAIL's RET= (FULL or HDRS), "" for none
    dsn_notify: u8[..64]  = "",      // DSN: RCPT's NOTIFY= (NEVER, or SUCCESS,FAILURE,DELAY), "" for none
    line:       u8[>..]   = [],      // scratch
}

// --- Replies and commands ------------------------------------------------------

// Reads one reply, its lines "NNN-text" and the last "NNN text", into
// c.code and c.text.
fn read_reply(c: Client&) -> i64 {
    c.code = 0;
    c.text.clear();
    for n in MAX_REPLY_LINES {
        let e = mail::link_read_line(c, c.line, MAX_LINE);
        if e != mail::OK { return e; }
        let l = c.line[..];
        if l.len < 3 { return mail::ERR_PROTOCOL; }
        var code = 0;
        for i in 3 {
            if l[i] < '0' || l[i] > '9' { return mail::ERR_PROTOCOL; }
            code = code * 10 + (l[i] - '0');
        }
        if code < 200 && code != 0 || code > 599 { return mail::ERR_PROTOCOL; }
        if n > 0 && code != c.code { return mail::ERR_PROTOCOL; }
        c.code = code;
        if n > 0 { c.text.push('\n'); }
        let more = l.len > 3 && l[3] == '-';
        if l.len > 3 && l[3] != '-' && l[3] != ' ' { return mail::ERR_PROTOCOL; }
        if l.len > 4 { c.text.append(l[4..]); }
        if !more { return mail::OK; }
    }
    return mail::ERR_PROTOCOL;
}

// Sends a command line (CRLF added) and reads the reply: OK when its code
// is `expect`, ERR_REPLY when it is another (c.code and c.text say which).
fn cmd(c: Client&, expect: i64, line: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    if mail::has_crlf(line) { return mail::ERR_LINE; }
    var b: u8[>..] = [];
    b.append(line);
    b.append("\r\n");
    var e = mail::link_write(c, b);
    if e != mail::OK { return e; }
    e = read_reply(c);
    if e != mail::OK { return e; }
    return if c.code == expect { mail::OK } else { mail::ERR_REPLY };
}

// --- Connecting -----------------------------------------------------------------

// Connects, reads the greeting, says EHLO, and gets TLS as policy asks
// (EHLO again under it). Port 0 is the policy's usual: 465 for
// TLS_IMPLICIT, 587 otherwise.
fn dial(c: Client&, host: const u8[:], port: i64, policy: i64) -> i64 {
    if host.len > 255 { return mail::ERR_ARG; }
    let p = if port != 0 { port } else if policy == TLS_IMPLICIT { 465 } else { 587 };
    // A server name left from a dial to another host is not this one's.
    if c.tlscfg.server_name[..] == c.host[..] { c.tlscfg.server_name.clear(); }
    c.host.clear();
    c.host.append(host);
    c.ext.clear();
    c.esmtp = false;
    var e = mail::link_open(c, host, p, policy == TLS_IMPLICIT);
    if e == mail::OK { e = read_reply(c); }
    if e == mail::OK && c.code != 220 { e = mail::ERR_REPLY; }
    if e == mail::OK { e = hello(c); }
    if e == mail::OK && !c.secure && (policy == TLS_MANDATORY || policy == TLS_OPPORTUNISTIC) {
        let has, params = extension(c, "STARTTLS");
        if has { e = starttls(c); }
        else if policy == TLS_MANDATORY { e = mail::ERR_NO_TLS; }
    }
    if e != mail::OK { close(c); }
    return e;
}

// EHLO, or HELO when the server refuses it; the extensions EHLO lists are
// kept for extension().
fn hello(c: Client&) -> i64 {
    if mail::has_crlf(c.local_name) || c.local_name.len == 0 { return mail::ERR_ARG; }
    c.ext.clear();
    c.esmtp = false;
    var e = cmd(c, 250, str("EHLO ", c.local_name));
    if e == mail::ERR_REPLY && c.code >= 500 {
        return cmd(c, 250, str("HELO ", c.local_name));
    }
    if e != mail::OK { return e; }
    c.esmtp = true;
    // The first line is the server's name; each other is an extension.
    var i = 0;
    while i < c.text.len && c.text[i] != '\n' { i++; }
    i++;
    while i < c.text.len {
        var j = i;
        while j < c.text.len && c.text[j] != '\n' { j++; }
        var k = i;
        while k < j && c.text[k] != ' ' {
            let ch = c.text[k];
            c.ext.push(if ch >= 'a' && ch <= 'z' { ch - 32 } else { ch });
            k++;
        }
        c.ext.append(c.text[k..j]);
        c.ext.push('\n');
        i = j + 1;
    }
    return mail::OK;
}

// Whether the server has an extension (by EHLO), and its parameters ("" if
// none). The name is compared without case.
fn extension(c: const Client&, name: const u8[:]) -> bool, const u8[:] {
    var i = 0;
    while i < c.ext.len {
        var j = i;
        while j < c.ext.len && c.ext[j] != '\n' { j++; }
        var k = i;
        while k < j && c.ext[k] != ' ' { k++; }
        if mail::eq_fold(c.ext[i..k], name) {
            return true, if k < j { c.ext[k + 1..j] } else { c.ext[j..j] };
        }
        i = j + 1;
    }
    return false, c.ext[0..0];
}

// STARTTLS, the handshake, and EHLO again: what the server said before
// TLS is not to be trusted.
fn starttls(c: Client&) -> i64 {
    if c.secure { return mail::ERR_STATE; }
    var e = cmd(c, 220, "STARTTLS");
    if e != mail::OK { return e; }
    e = mail::link_tls(c, c.host);
    if e != mail::OK { return e; }
    return hello(c);
}

// --- Authentication -------------------------------------------------------------

fn is_local(host: const u8[:]) -> bool { host == "localhost" || host == "127.0.0.1" || host == "::1" }

// AUTH with a mechanism (AUTH_AUTO: the best the server offers, by
// mail::auth_choose). The mechanisms that send the password readable
// (PLAIN, LOGIN, XOAUTH2) are refused without TLS, except to localhost,
// as Go's smtp.PlainAuth refuses them. ERR_AUTH when nothing fits or a
// SCRAM server does not prove it knows the password; ERR_REPLY when the
// server says no (535: wrong credentials).
fn auth(c: Client&, mech: i64, user: const u8[:], secret: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    let has, list = extension(c, "AUTH");
    var m = mech;
    if m == mail::AUTH_AUTO {
        if !has { return mail::ERR_UNSUPPORTED; }
        m = mail::auth_choose(list);
        if m == mail::AUTH_AUTO { return mail::ERR_AUTH; }
    }
    if mail::auth_plaintext(m) && !c.secure && !is_local(c.host) { return mail::ERR_AUTH; }
    if mail::has_crlf(user) { return mail::ERR_LINE; }
    if !mail::sasl_fits(user, secret) { return mail::ERR_AUTH; }
    var s = mail::sasl_new(m, user, secret);
    if m == mail::AUTH_NTLM { mail::link_sasl_target(c, s, "SMTPSVC"); }
    var resp: u8[>..] = [];
    var line: u8[>..] = [];
    line.append("AUTH ");
    line.append(mail::auth_name(m));
    if mail::sasl_initial(s, resp) {
        line.push(' ');
        if resp.len == 0 { line.push('='); } else { base64::encode(line, resp); }
    }
    var e = cmd(c, 235, line);
    while e == mail::ERR_REPLY && c.code == 334 {
        var challenge: u8[>..] = [];
        let text = c.text[..];
        if !base64::decode(challenge, text) {
            cmd(c, 501, "*");
            return mail::ERR_AUTH;
        }
        if mail::sasl_step(s, challenge, resp) != mail::OK {
            cmd(c, 501, "*");              // cancels the exchange (RFC 4954 §4)
            return mail::ERR_AUTH;
        }
        line.clear();
        base64::encode(line, resp);
        e = cmd(c, 235, line);
    }
    if e != mail::OK { return e; }
    if !mail::sasl_done(s) { return mail::ERR_AUTH; }
    return mail::OK;
}

// --- A message ------------------------------------------------------------------

fn has_8bit(s: const u8[:]) -> bool {
    for b in s { if b >= 0x80 { return true; } }
    return false;
}

// An address for MAIL or RCPT: no CR, LF, '<' or '>' in it.
fn path_ok(addr: const u8[:]) -> bool {
    for b in addr { if b == '\r' || b == '\n' || b == '<' || b == '>' { return false; } }
    return true;
}

// MAIL FROM, with BODY=8BITMIME when the server has it, SMTPUTF8 when the
// address (or utf8) needs it (ERR_UNSUPPORTED when the server lacks it),
// and DSN's RET= when c.dsn_ret is set and the server has DSN.
fn mail_from(c: Client&, from: const u8[:], utf8: bool = false) -> i64 {
    if !path_ok(from) { return mail::ERR_ADDRESS; }
    var line: u8[>..] = [];
    line.append("MAIL FROM:<");
    line.append(from);
    line.push('>');
    let has8, p8 = extension(c, "8BITMIME");
    if has8 { line.append(" BODY=8BITMIME"); }
    if utf8 || has_8bit(from) {
        let hasu, pu = extension(c, "SMTPUTF8");
        if !hasu { return mail::ERR_UNSUPPORTED; }
        line.append(" SMTPUTF8");
    }
    let hasd, pd = extension(c, "DSN");
    if hasd && c.dsn_ret.len > 0 {
        line.append(" RET=");
        line.append(c.dsn_ret);
    }
    return cmd(c, 250, line);
}

// RCPT TO, with DSN's NOTIFY= when c.dsn_notify is set and the server has
// DSN. 251 (the server forwards it) is a yes too.
fn rcpt(c: Client&, to: const u8[:]) -> i64 {
    if !path_ok(to) { return mail::ERR_ADDRESS; }
    var line: u8[>..] = [];
    line.append("RCPT TO:<");
    line.append(to);
    line.push('>');
    let hasd, pd = extension(c, "DSN");
    if hasd && c.dsn_notify.len > 0 {
        line.append(" NOTIFY=");
        line.append(c.dsn_notify);
    }
    let e = cmd(c, 250, line);
    if e == mail::ERR_REPLY && c.code == 251 { return mail::OK; }
    return e;
}

// msg as DATA carries it: every line ending CRLF (a bare LF or CR becomes
// one), a line starting with '.' given another (RFC 5321 §4.5.2), and the
// ending ".".
fn dot_stuff(out: u8[>..]&, msg: const u8[:]) {
    var bol = true;
    var i = 0;
    while i < msg.len {
        let b = msg[i];
        if bol && b == '.' { out.push('.'); }
        if b == '\r' {
            out.append("\r\n");
            if i + 1 < msg.len && msg[i + 1] == '\n' { i++; }
            bol = true;
        } else if b == '\n' {
            out.append("\r\n");
            bol = true;
        } else {
            out.push(b);
            bol = false;
        }
        i++;
    }
    if !bol { out.append("\r\n"); }
    out.append(".\r\n");
}

// DATA: the message (RFC 5322 bytes), dot-stuffed here.
fn data(c: Client&, msg: const u8[:]) -> i64 {
    var e = cmd(c, 354, "DATA");
    if e != mail::OK { return e; }
    var b: u8[>..] = [];
    dot_stuff(b, msg);
    e = mail::link_write(c, b);
    if e != mail::OK { return e; }
    e = read_reply(c);
    if e != mail::OK { return e; }
    return if c.code == 250 { mail::OK } else { mail::ERR_REPLY };
}

// One message: MAIL, a RCPT for each of to (a list of addresses: a
// literal ["a@example.com", ...], args() slices, a u8[][>..]), DATA. When the server refuses
// any, the transaction is reset (RSET) and its reply is what c.code and
// c.text keep.
fn send(c: Client&, from: const u8[:], to, msg: const u8[:]) -> i64 {
    if to.len == 0 { return mail::ERR_ARG; }
    var utf8 = has_8bit(from);
    for t in to { if has_8bit(t) { utf8 = true; } }
    var e = mail_from(c, from, utf8);
    for t in to {
        if e != mail::OK { break; }
        e = rcpt(c, t);
    }
    if e == mail::OK { e = data(c, msg); }
    if e == mail::ERR_REPLY {
        // Keep the refusal, not RSET's reply.
        let code = c.code;
        var text: u8[>..] = [];
        text.append(c.text);
        reset(c);
        c.code = code;
        c.text.clear();
        c.text.append(text);
    }
    return e;
}

// A message built with mail.message: its envelope sender (Sender or From)
// and every recipient (To, Cc and Bcc, each once), the message as written
// (Bcc left out). The Date, Message-ID and boundaries it made up stay in
// m, so mail::message_id(m) names what was sent.
fn send_message(c: Client&, m: mail::Msg&) -> i64 {
    var b: u8[>..] = [];
    let e = mail::write(m, b);
    if e != mail::OK { return e; }
    var to: u8[][>..] = [];
    mail::recipients(m, to);
    return send(c, mail::envelope_from(m), to, b);
}

// --- The rest -------------------------------------------------------------------

fn reset(c: Client&) -> i64 { cmd(c, 250, "RSET") }
fn noop(c: Client&) -> i64 { cmd(c, 250, "NOOP") }

// VRFY: OK when the server knows the address (250 or 251); 252 (it cannot
// say) is ERR_REPLY, with the code to tell.
fn verify(c: Client&, addr: const u8[:]) -> i64 {
    if !path_ok(addr) { return mail::ERR_ADDRESS; }
    let e = cmd(c, 250, str("VRFY ", addr));
    if e == mail::ERR_REPLY && c.code == 251 { return mail::OK; }
    return e;
}

// QUIT and close the connection. The connection closes whatever the reply.
fn quit(c: Client&) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    let e = cmd(c, 221, "QUIT");
    close(c);
    return e;
}

// Closes the connection without QUIT.
fn close(c: Client&) { mail::link_close(c); }
