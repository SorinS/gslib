// Fuzz target: mail_imap. A mail server's side of the wire, as the clients
// read it, selected by the first byte:
//   0: an IMAP server's responses, read by the client from its input buffer
//      (no socket: fd -1) to the tagged completion; then what the commands
//      take from them: FETCH messages (ENVELOPE, BODYSTRUCTURE, items),
//      LIST/LSUB, STATUS, SEARCH/ESEARCH, ID, EXPUNGE, capabilities.
//   1: the IMAP parsers one by one on the rest: tree, parse_fetch, item,
//      parse_envelope (addresses written back), parse_bodystructure,
//      parse_list, parse_status, parse_search, modified UTF-7, sequence
//      sets, literal_at_end, status_parts.
//   2: a POP3 server's status line and multi-line responses (LIST/UIDL
//      lines, APOP timestamp, CAPA parameters).
//   3: an SMTP server's replies (multi-line, EHLO extensions).
// Known: CRLF in ENVELOPE hosts kept into addresses; ENVELOPE/LIST fields
// cut at their caps (review findings imap.goose:1663, LOW truncations).

import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.address;
import gslib.mail.imap;
import gslib.mail.pop3;
import gslib.mail.smtp;

let MAX_ITEMS: i64 = 16;

fn write_addresses(l: const mail::Address[:]) {
    var out: u8[>..] = [];
    for &a in l { mail::write_address(out, a); out.append(", "); }
}

fn envelope_of(s: const u8[:]) {
    var env = imap::Envelope { .. };
    if imap::parse_envelope(s, env) {
        write_addresses(env.from);
        write_addresses(env.sender);
        write_addresses(env.reply_to);
        write_addresses(env.to);
        write_addresses(env.cc);
        write_addresses(env.bcc);
    }
}

fn imap_client(data: const u8[:]) {
    var c = imap::Client { .. };
    c.tag.append("A1");
    c.max_literal = 1 << 16;
    c.max_data = 1 << 20;
    c.inbuf.append(data);
    // Several commands' responses: c.data and c.ends keep accumulating.
    var k = 0;
    while k < 8 {
        let e = imap::finish(c);
        if e != mail::OK && e != mail::ERR_REPLY { break; }
        k++;
    }
    let _ = imap::capability(c, "IMAP4rev2");
    let _ = imap::auth_list(c);
    var msgs: imap::Message[>..] = [];
    let _ = imap::messages(c, msgs);
    for i in ::min(msgs.len, MAX_ITEMS) {
        let m = msgs[i];
        var env = imap::Envelope { .. };
        if imap::envelope(c, m, env) {
            write_addresses(env.from);
            write_addresses(env.to);
        }
        var parts: imap::Part[>..] = [];
        let _ = imap::bodystructure(c, m, parts);
        var body: u8[>..] = [];
        let _ = imap::fetch_item(c, m, "BODY[]", body);
        let _ = imap::fetch_item(c, m, "BODY[HEADER]", body);
    }
    var n: i64 = 0;
    imap::each_response(c) { r =>
        if n < MAX_ITEMS && r.len >= 2 {
            n++;
            let w, rest = imap::first_word(r[2..]);
            if mail::eq_fold(w, "LIST") || mail::eq_fold(w, "LSUB") {
                var mb = imap::Mailbox { .. };
                let _ = imap::parse_list(rest, c.utf8, mb);
            } else if mail::eq_fold(w, "STATUS") {
                var st = imap::Status { .. };
                let _ = imap::parse_status(rest, st);
            } else if mail::eq_fold(w, "SEARCH") || mail::eq_fold(w, "ESEARCH") {
                var found: i64[>..] = [];
                let _ = imap::parse_search(w, rest, c.max_data / 8, found);
            }
        }
    };
    var ex: i64[>..] = [];
    imap::expunged(c, ex);
}

fn imap_parsers(s: const u8[:]) {
    var nodes: imap::Node[>..] = [];
    let _ = imap::tree(s, nodes);
    var m = imap::Message { .. };
    let _ = imap::parse_fetch(s, m);
    var out: u8[>..] = [];
    let _ = imap::item(s, "BODY[]", out);
    let _ = imap::item(s, "ENVELOPE", out);
    envelope_of(s);
    var parts: imap::Part[>..] = [];
    let _ = imap::parse_bodystructure(s, parts);
    for utf8 in [false, true] {
        var mb = imap::Mailbox { .. };
        let _ = imap::parse_list(s, utf8, mb);
    }
    var st = imap::Status { .. };
    let _ = imap::parse_status(s, st);
    var found: i64[>..] = [];
    let _ = imap::parse_search("SEARCH", s, 1000, found);
    found.clear();
    let _ = imap::parse_search("ESEARCH", s, 1000, found);
    var dec: u8[>..] = [];
    if imap::utf7_decode(dec, s) {
        var enc: u8[>..] = [];
        let _ = imap::utf7_encode(enc, dec);
    }
    var nums: i64[>..] = [];
    if imap::seq_set_ok(s) { let _ = imap::parse_seq_set(s, 100, 1000, nums); }
    let _ = imap::literal_at_end(s);
    let _ = imap::status_parts(s);
}

fn pop3_client(data: const u8[:]) {
    var c = pop3::Client { .. };
    c.inbuf.append(data);
    let e = pop3::read_status(c);
    let _ = pop3::apop_timestamp(c.text);
    let _ = pop3::number(c.text);
    if e != mail::OK { return; }
    var lines: u8[>..] = [];
    if pop3::read_multi(c, lines) != mail::OK { return; }
    var count: i64 = 0;
    let _ = pop3::each_line(lines) { num, rest =>
        let _ = pop3::number(rest);
        count++;
    };
    c.capa.append(lines);
    let _ = pop3::capability_params(c, "SASL");
    let _ = pop3::capability(c, "STLS");
}

fn smtp_client(data: const u8[:]) {
    var c = smtp::Client { .. };
    c.inbuf.append(data);
    for i in 4 {
        if smtp::read_reply(c) != mail::OK { return; }
        c.ext.clear();
        c.ext.append(c.text);
        c.ext.push('\n');
        let _ = smtp::extension(c, "SIZE");
        let _ = smtp::extension(c, "AUTH");
    }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    match data[0] % 4 {
        0 => { imap_client(rest); },
        1 => { imap_parsers(rest); },
        2 => { pop3_client(rest); },
        _ => { smtp_client(rest); },
    }
    return 0;
}

fn main() {}
