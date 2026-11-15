// mail.pop3: a POP3 client (RFC 1939), as Python's poplib has it, with
// CAPA (RFC 2449), STLS (RFC 2595) or TLS from the first byte (995), AUTH
// (RFC 5034) with mail.sasl's mechanisms, USER/PASS and APOP, STAT, LIST,
// UIDL, RETR, TOP, DELE, RSET, NOOP, UTF8 (RFC 6856) and QUIT.
//
//   var c = pop3::Client { .. };
//   var e = pop3::dial(c, "pop.example.com", 0, pop3::TLS_MANDATORY);
//   if e == mail::OK { e = pop3::login(c, "user", "password"); }
//   let count, size, se = pop3::stat(c);
//   var msg: u8[>..] = [];
//   if count > 0 { e = pop3::retr(c, 1, msg); }    // the message, CRLF lines, dots undone
//   pop3::quit(c);                                 // DELEs take effect here
//   // on mail::ERR_REPLY, c.text is the server's -ERR text
//
// Messages are numbered from 1, as the protocol numbers them. c.tlscfg is
// the TLS client's configuration, as in smtp.

namespace pop3;

import std;
import base64;
import mail;
import mail.link;
import mail.sasl;
import crypto.bignum;
import crypto.bignum.md5;
import crypto.tls;
import crypto.tls.handshake;

// How a connection gets TLS, as smtp's.
let TLS_MANDATORY:     i64 = 0;  // STLS, and fail (ERR_NO_TLS) when the server does not offer it
let TLS_OPPORTUNISTIC: i64 = 1;  // STLS when the server offers it
let TLS_NONE:          i64 = 2;
let TLS_IMPLICIT:      i64 = 3;  // TLS from the first byte (995)

let MAX_STATUS: i64 = 2048;      // a status line's limit (poplib's; RFC 1939 says 512)
let MAX_LINE:   i64 = 1 << 20;   // a message line's: RFC 5322 says 998, mail in the wild has more
let MAX_DATA:   i64 = 1 << 28;   // c.max_data's default: one multi-line response, 256 MiB (as imap's)

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
    // POP3's
    host:     u8[..255]  = "",
    greeting: u8[..2048] = "",       // the server's greeting, for APOP's timestamp
    capa:     u8[>..]    = [],       // CAPA's lines, each "NAME params\n" (empty if CAPA failed)
    text:     u8[>..]    = [],       // the last status line's text, after +OK or -ERR
    line:     u8[>..]    = [],       // scratch
    max_data: i64        = MAX_DATA, // a multi-line response (RETR, TOP, LIST...) larger is ERR_PROTOCOL
}

// A message's number and size (LIST), or number and unique ID (UIDL).
struct Info { num: i64, size: i64 }
struct Uid { num: i64, uid: u8[..70] }

// --- Commands --------------------------------------------------------------------

// Reads a status line: OK for +OK, ERR_REPLY for -ERR (and c.text its
// text), ERR_PROTOCOL for anything else.
fn read_status(c: Client&) -> i64 {
    c.text.clear();
    let e = mail::link_read_line(c, c.line, MAX_STATUS);
    if e != mail::OK { return e; }
    return status_of(c);
}

// The status c.line holds, its text into c.text.
fn status_of(c: Client&) -> i64 {
    c.text.clear();
    let l = c.line[..];
    if l.starts_with("+OK") && (l.len == 3 || l[3] == ' ') {
        if l.len > 4 { c.text.append(l[4..]); }
        return mail::OK;
    }
    if l.starts_with("-ERR") && (l.len == 4 || l[4] == ' ') {
        if l.len > 5 { c.text.append(l[5..]); }
        return mail::ERR_REPLY;
    }
    return mail::ERR_PROTOCOL;
}

fn send_line(c: Client&, line: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    if mail::has_crlf(line) { return mail::ERR_LINE; }
    var b: u8[>..] = [];
    b.append(line);
    b.append("\r\n");
    return mail::link_write(c, b);
}

// A command and its status line.
fn cmd(c: Client&, line: const u8[:]) -> i64 {
    let e = send_line(c, line);
    if e != mail::OK { return e; }
    return read_status(c);
}

// The lines of a multi-line response up to its ".", appended to out with
// CRLF endings, a leading '.' that was doubled undone (RFC 1939 §3).
// ERR_PROTOCOL past c.max_data bytes: the rest is unread, so close then.
fn read_multi(c: Client&, out: u8[>..]&) -> i64 {
    let start = out.len;
    loop {
        let e = mail::link_read_line(c, c.line, MAX_LINE);
        if e != mail::OK { return e; }
        let l = c.line[..];
        if l == "." { return mail::OK; }
        if l.len + 2 > c.max_data - (out.len - start) { return mail::ERR_PROTOCOL; }
        out.append(if l.len > 0 && l[0] == '.' { l[1..] } else { l });
        out.append("\r\n");
    }
    return mail::ERR_IO;
}

// A command whose +OK is followed by lines.
fn long_cmd(c: Client&, line: const u8[:], out: u8[>..]&) -> i64 {
    let e = cmd(c, line);
    if e != mail::OK { return e; }
    return read_multi(c, out);
}

// --- Connecting -----------------------------------------------------------------

// Connects, reads the greeting, asks CAPA, and gets TLS as policy asks
// (CAPA again under it). Port 0 is the policy's usual: 995 for
// TLS_IMPLICIT, 110 otherwise.
fn dial(c: Client&, host: const u8[:], port: i64, policy: i64) -> i64 {
    if host.len > 255 { return mail::ERR_ARG; }
    let p = if port != 0 { port } else if policy == TLS_IMPLICIT { 995 } else { 110 };
    // A server name left from a dial to another host is not this one's.
    if c.tlscfg.server_name[..] == c.host[..] { c.tlscfg.server_name.clear(); }
    c.host.clear();
    c.host.append(host);
    c.greeting.clear();
    c.capa.clear();
    var e = mail::link_open(c, host, p, policy == TLS_IMPLICIT);
    if e == mail::OK { e = read_status(c); }
    if e == mail::OK {
        c.greeting.append(c.text[.. ::min(c.text.len, 2048)]);
        // A server without CAPA says -ERR; anything else is a broken connection.
        let ce = capa(c);
        if ce != mail::OK && ce != mail::ERR_REPLY { e = ce; }
    }
    if e == mail::OK && !c.secure && (policy == TLS_MANDATORY || policy == TLS_OPPORTUNISTIC) {
        if capability(c, "STLS") { e = stls(c); }
        else if policy == TLS_MANDATORY { e = mail::ERR_NO_TLS; }
    }
    if e != mail::OK { close(c); }
    return e;
}

// CAPA: the server's capabilities, kept for capability(). A server without
// CAPA (-ERR) leaves none.
fn capa(c: Client&) -> i64 {
    c.capa.clear();
    var lines: u8[>..] = [];
    let e = long_cmd(c, "CAPA", lines);
    if e != mail::OK { return e; }
    var i = 0;
    while i < lines.len {
        var j = i;
        while j + 1 < lines.len && !(lines[j] == '\r' && lines[j + 1] == '\n') { j++; }
        if j + 1 >= lines.len { break; }
        var k = i;
        while k < j && lines[k] != ' ' {
            let ch = lines[k];
            c.capa.push(if ch >= 'a' && ch <= 'z' { ch - 32 } else { ch });
            k++;
        }
        c.capa.append(lines[k..j]);
        c.capa.push('\n');
        i = j + 2;
    }
    return mail::OK;
}

// Whether CAPA listed a capability, and its parameters ("" if none).
fn capability_params(c: const Client&, name: const u8[:]) -> bool, const u8[:] {
    var i = 0;
    while i < c.capa.len {
        var j = i;
        while j < c.capa.len && c.capa[j] != '\n' { j++; }
        var k = i;
        while k < j && c.capa[k] != ' ' { k++; }
        if mail::eq_fold(c.capa[i..k], name) {
            return true, if k < j { c.capa[k + 1..j] } else { c.capa[j..j] };
        }
        i = j + 1;
    }
    return false, c.capa[0..0];
}

fn capability(c: const Client&, name: const u8[:]) -> bool {
    let has, params = capability_params(c, name);
    return has;
}

// STLS, the handshake, and CAPA again (RFC 2595 §4: what came before TLS
// is forgotten).
fn stls(c: Client&) -> i64 {
    if c.secure { return mail::ERR_STATE; }
    var e = cmd(c, "STLS");
    if e != mail::OK { return e; }
    e = mail::link_tls(c, c.host);
    if e != mail::OK { return e; }
    let ce = capa(c);
    return if ce == mail::ERR_REPLY { mail::OK } else { ce };
}

// --- Authentication -------------------------------------------------------------

fn is_local(host: const u8[:]) -> bool { host == "localhost" || host == "127.0.0.1" || host == "::1" }

// USER and PASS. The password goes readable, so without TLS this is
// refused (ERR_AUTH) except to localhost.
fn login(c: Client&, user: const u8[:], password: const u8[:]) -> i64 {
    if !c.secure && !is_local(c.host) { return mail::ERR_AUTH; }
    var e = cmd(c, str("USER ", user));
    if e != mail::OK { return e; }
    if mail::has_crlf(password) { return mail::ERR_LINE; }
    var line: u8[>..] = [];
    line.append("PASS ");
    line.append(password);
    return cmd(c, line);
}

// The timestamp of the greeting, "<...>", that APOP needs; false if there
// is none.
fn apop_timestamp(greeting: const u8[:]) -> const u8[:], bool {
    var i = 0;
    while i < greeting.len && greeting[i] != '<' { i++; }
    var j = i;
    while j < greeting.len && greeting[j] != '>' { j++; }
    if j >= greeting.len { return greeting[0..0], false; }
    return greeting[i..j + 1], true;
}

// APOP's digest: MD5 of the timestamp and the password, in lower-case hex.
fn apop_digest(timestamp: const u8[:], password: const u8[:]) -> u8[>..] {
    var s = bignum::md5_init();
    bignum::md5_update(s, timestamp);
    bignum::md5_update(s, password);
    let d = bignum::md5_final(s);
    var out: u8[>..] = [];
    mail::hex_lower(out, d);
    return out;
}

// APOP (RFC 1939 §7): the password does not go over the wire, but MD5 of
// it is weak; ERR_UNSUPPORTED when the greeting had no timestamp.
fn apop(c: Client&, user: const u8[:], password: const u8[:]) -> i64 {
    let ts, ok = apop_timestamp(c.greeting);
    if !ok { return mail::ERR_UNSUPPORTED; }
    let d = apop_digest(ts, password);
    return cmd(c, str("APOP ", user, " ", d));
}

// AUTH with a SASL mechanism (AUTH_AUTO: the best the SASL capability
// lists). As smtp::auth: readable mechanisms only over TLS or to
// localhost, a SCRAM server must prove itself.
fn auth(c: Client&, mech: i64, user: const u8[:], secret: const u8[:]) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    var m = mech;
    if m == mail::AUTH_AUTO {
        let has, list = capability_params(c, "SASL");
        if !has { return mail::ERR_UNSUPPORTED; }
        m = mail::auth_choose(list);
        if m == mail::AUTH_AUTO { return mail::ERR_AUTH; }
    }
    if mail::auth_plaintext(m) && !c.secure && !is_local(c.host) { return mail::ERR_AUTH; }
    if !mail::sasl_fits(user, secret) { return mail::ERR_AUTH; }
    var s = mail::sasl_new(m, user, secret);
    if m == mail::AUTH_NTLM { mail::link_sasl_target(c, s, "POP"); }
    var resp: u8[>..] = [];
    var line: u8[>..] = [];
    line.append("AUTH ");
    line.append(mail::auth_name(m));
    if mail::sasl_initial(s, resp) {
        line.push(' ');
        if resp.len == 0 { line.push('='); } else { base64::encode(line, resp); }
    }
    var e = send_line(c, line);
    if e != mail::OK { return e; }
    loop {
        e = mail::link_read_line(c, c.line, MAX_STATUS);
        if e != mail::OK { return e; }
        // "+ challenge" continues the exchange; anything else is the status.
        if c.line.len >= 1 && c.line[0] == '+' && (c.line.len == 1 || c.line[1] == ' ') {
            var challenge: u8[>..] = [];
            let text = if c.line.len > 2 { c.line[2..] } else { c.line[0..0] };
            var se = mail::OK;
            if !base64::decode(challenge, text) { se = mail::ERR_AUTH; }
            if se == mail::OK { se = mail::sasl_step(s, challenge, resp); }
            if se != mail::OK {
                send_line(c, "*");         // cancels (RFC 5034 §4)
                read_status(c);
                return mail::ERR_AUTH;
            }
            line.clear();
            base64::encode(line, resp);
            e = send_line(c, line);
            if e != mail::OK { return e; }
            continue;
        }
        let st = status_of(c);
        if st == mail::OK && !mail::sasl_done(s) { return mail::ERR_AUTH; }
        return st;
    }
    return mail::ERR_IO;
}

// UTF8 (RFC 6856): the server may then send headers in UTF-8.
fn utf8(c: Client&) -> i64 { cmd(c, "UTF8") }

// --- The mailbox ----------------------------------------------------------------

// The leading number of s and the rest after one space.
fn number(s: const u8[:]) -> i64, const u8[:], bool {
    var i = 0;
    var n: i64 = 0;
    while i < s.len && s[i] >= '0' && s[i] <= '9' {
        if n > 922337203685477580 { return 0, s, false; }
        n = n * 10 + (s[i] - '0');
        i++;
    }
    if i == 0 { return 0, s, false; }
    while i < s.len && s[i] == ' ' { i++; }
    return n, s[i..], true;
}

// STAT: how many messages, and their size in bytes.
fn stat(c: Client&) -> i64, i64, i64 {
    let e = cmd(c, "STAT");
    if e != mail::OK { return 0, 0, e; }
    let count, rest, ok1 = number(c.text);
    let size, rest2, ok2 = number(rest);
    if !ok1 || !ok2 { return 0, 0, mail::ERR_PROTOCOL; }
    return count, size, mail::OK;
}

// Each line "num value" of a multi-line response, to F(num, value).
fn each_line<F>(lines: const u8[:]) -> bool {
    var i = 0;
    while i < lines.len {
        var j = i;
        while j + 1 < lines.len && !(lines[j] == '\r' && lines[j + 1] == '\n') { j++; }
        if j + 1 >= lines.len { return false; }
        let num, rest, ok = number(lines[i..j]);
        if !ok { return false; }
        F(num, rest);
        i = j + 2;
    }
    return true;
}

// LIST: every message's number and size.
fn list(c: Client&, out: Info[>..]&) -> i64 {
    out.clear();
    var lines: u8[>..] = [];
    let e = long_cmd(c, "LIST", lines);
    if e != mail::OK { return e; }
    var bad = false;
    let ok = each_line(lines) { num, rest =>
        let size, r2, oks = number(rest);
        if oks { out.push(Info { num: num, size: size }); } else { bad = true; }
    };
    return if ok && !bad { mail::OK } else { mail::ERR_PROTOCOL };
}

// LIST n: one message's size.
fn list_one(c: Client&, n: i64) -> i64, i64 {
    let e = cmd(c, str("LIST ", n));
    if e != mail::OK { return 0, e; }
    let num, rest, ok1 = number(c.text);
    let size, r2, ok2 = number(rest);
    if !ok1 || !ok2 || num != n { return 0, mail::ERR_PROTOCOL; }
    return size, mail::OK;
}

// UIDL: every message's number and unique ID (1 to 70 printable bytes).
fn uidl(c: Client&, out: Uid[>..]&) -> i64 {
    out.clear();
    var lines: u8[>..] = [];
    let e = long_cmd(c, "UIDL", lines);
    if e != mail::OK { return e; }
    var bad = false;
    let ok = each_line(lines) { num, rest =>
        if rest.len == 0 || rest.len > 70 { bad = true; } else {
            var u = Uid { num: num, uid: [] };
            u.uid.append(rest);
            out.push(u);
        }
    };
    return if ok && !bad { mail::OK } else { mail::ERR_PROTOCOL };
}

// RETR n: the whole message into out (appended), CRLF line endings.
fn retr(c: Client&, n: i64, out: u8[>..]&) -> i64 { long_cmd(c, str("RETR ", n), out) }

// TOP n lines: the headers and the first lines of the body.
fn top(c: Client&, n: i64, lines: i64, out: u8[>..]&) -> i64 { long_cmd(c, str("TOP ", n, " ", lines), out) }

// DELE n: marks it; QUIT deletes it, RSET unmarks it.
fn dele(c: Client&, n: i64) -> i64 { cmd(c, str("DELE ", n)) }
fn rset(c: Client&) -> i64 { cmd(c, "RSET") }
fn noop(c: Client&) -> i64 { cmd(c, "NOOP") }

// QUIT: the server deletes what DELE marked, then the connection closes
// (whatever the reply).
fn quit(c: Client&) -> i64 {
    if c.fd < 0 { return mail::ERR_STATE; }
    let e = cmd(c, "QUIT");
    close(c);
    return e;
}

// Closes without QUIT: nothing marked is deleted.
fn close(c: Client&) { mail::link_close(c); }
