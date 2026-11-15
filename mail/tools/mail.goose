// goose-mail: sends a message over SMTP, reads a mailbox over POP3, reads
// and changes one over IMAP, with mail.smtp, mail.pop3 and mail.imap; signs
// and verifies messages with DKIM (mail.dkim) and S/MIME (mail.smime). The
// user name and password come from the environment (MAIL_USER,
// MAIL_PASSWORD), never the command line, and are never printed; nor is a
// key.
//
//   goose-mail smtp [options] HOST FILE FROM TO...    send FILE (an RFC 5322 message); FILE "-"
//                                                     builds one with mail.message (TO in To,
//                                                     a "bcc:ADDR" in Bcc) and sends that
//   goose-mail pop3 [options] HOST COMMAND...         stat | list | uidl | retr N | top N LINES | dele N | capa
//   goose-mail imap [options] HOST COMMAND...         the IMAP COMMANDs below, run in order on one connection
//   goose-mail dkim sign|verify|record ...            DKIM, below
//   goose-mail smime sign|encrypt|sign-encrypt|verify|decrypt ...
//                                                     S/MIME, below
//
// Options (smtp, pop3, imap):
//   --port N          the port (default: the TLS mode's usual)
//   --tls MODE        mandatory (default), opportunistic, none, implicit
//   --insecure        do not check the server's certificate
//   --auth MECH       auto, plain, login, cram-md5, scram-sha-1, scram-sha-256, xoauth2, ntlm;
//                     for pop3 also user (USER/PASS) and apop; for imap also user (the
//                     LOGIN command); none: no login (default when MAIL_USER is not set).
//                     IMAP, unset with MAIL_USER: AUTHENTICATE auto when the server lists
//                     mechanisms, LOGIN otherwise.
//   --name NAME       SMTP: EHLO's name (default localhost)
//
// It prints what happened a line at a time, and the server's reply when a
// command is refused; it exits 1 then.
//
// IMAP COMMANDs:
//   capa                      the capabilities
//   id                        ID: the server's answer
//   enable CAPS               ENABLE, e.g. UTF8=ACCEPT
//   list [PATTERN]            LIST "" PATTERN (default *)
//   lsub [PATTERN]            LSUB "" PATTERN
//   select MBOX | examine MBOX
//   status MBOX
//   create MBOX | delete MBOX | subscribe MBOX | unsubscribe MBOX | rename OLD NEW
//   fetch SET ITEMS | uid-fetch SET ITEMS
//                             a line per message, then its envelope, its
//                             body structure and its BODY[...] items
//   search CRITERIA | uid-search CRITERIA
//   store SET HOW FLAGS | uid-store SET HOW FLAGS     HOW: FLAGS, +FLAGS, -FLAGS
//   copy SET MBOX | move SET MBOX | uid-copy SET MBOX | uid-move SET MBOX
//   expunge | uid-expunge SET
//   append MBOX FILE [FLAGS]
//   noop | close | unselect
//   idle SECONDS              IDLE, printing what comes, then DONE
//
// DKIM:
//   goose-mail dkim sign --key FILE --domain D --selector S [options] [FILE|-]
//       the message signed, on stdout
//   goose-mail dkim verify [--record TEXT | --record-file FILE | --dns SERVER] [options] [FILE|-]
//       a line per signature ("dkim=pass header.d=... header.s=..."); exit 0
//       when one passes, 1 when none does
//   goose-mail dkim record --key FILE
//       the key's TXT record ("v=DKIM1; k=...; p=...")
// Sign options:
//   --key FILE         an RSA or Ed25519 private key: PEM (PKCS #8 or PKCS #1),
//                      or an Ed25519 seed in base64
//   --canon H/B        simple or relaxed for the header and the body (relaxed/relaxed)
//   --headers LIST     h=, names joined by ':' (default: the usual fields, From over-signed)
//   --no-oversign      with the default list, From only as often as it is there
//   --identity ID      i=
//   --timestamp T      t= (unix seconds, or "now")
//   --expire T         x=
//   --length           l= with the whole body
// Verify options:
//   --record TEXT      the key record for every signature (offline)
//   --record-file FILE the same from a file
//   --dns SERVER       look the keys up at SERVER ("host" or "host:port"); the
//                      default is /etc/resolv.conf's first nameserver
//   --allow-sha1       accept rsa-sha1
//   --now T            the time x= is checked against
// FILE "-" or none reads stdin; errors go to stderr.
//
// S/MIME: certificates and keys are PEM files (a certificate file may hold
// a chain: the first is the signer's or recipient's, the others are sent
// with a signature). Messages are RFC 5322 files, CRLF or LF. RSA, EC,
// Ed25519 and ML-DSA keys sign; RSA, EC and ML-KEM certificates are
// encrypted to.
//   goose-mail smime sign [options] CERT KEY IN OUT            multipart/signed (--opaque: pkcs7-mime)
//   goose-mail smime encrypt [options] IN OUT RCERT...         enveloped (--cipher *-gcm: authEnveloped)
//   goose-mail smime sign-encrypt [options] CERT KEY IN OUT RCERT...
//   goose-mail smime verify [options] IN [OUT]                 a signed message: who signed it
//   goose-mail smime decrypt [options] CERT KEY IN [OUT]       every layer: decrypts, verifies
// Options:
//   --opaque            sign as application/pkcs7-mime; smime-type=signed-data
//   --pss               RSA keys sign with RSASSA-PSS
//   --hash N            256 (default), 384 or 512 (Ed25519, ML-DSA: always 512)
//   --keyid             signer and recipients by subject key identifier
//   --time T            signingTime, seconds since 1970 (default now; -1: none)
//   --boundary B        multipart/signed's boundary (default random)
//   --cipher C          aes256-cbc (default), aes128-cbc, aes128-gcm, aes256-gcm
//   --pkcs1             RSA recipients by RSAES-PKCS1-v1_5, not OAEP
//   --roots FILE        verify, decrypt: check the signer's path to these roots (PEM),
//                       for email protection, and its address against From
//   --now T             the time the path is checked at (default now)
// OUT is a file, or - for standard output; verify and decrypt write the
// message as it reads inside the layers (the outer header fields, then
// the entity). They print what they found: "signed by SUBJECT",
// "encrypted", "signing time T", "signer ok"; any error is printed and
// the exit status is 1.

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.sasl;
import gslib.mail.address;
import gslib.mail.message;
import gslib.mail.smtp;
import gslib.mail.pop3;
import gslib.mail.imap;
import gslib.mail.dkim;
import gslib.mail.smime;
import gslib.encoding.asn1;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;
import gslib.crypto.x509.pool;
import gslib.crypto.x509.cms;
import gslib.crypto.x509.cms_env;

struct Opts { port: i64, tls: i64, insecure: bool, auth: u8[..32], name: u8[..255] }

fn usage() {
    print("usage: goose-mail smtp [options] HOST FILE FROM TO...");
    print("       goose-mail pop3 [options] HOST stat|list|uidl|capa|retr N|top N LINES|dele N ...");
    print("       goose-mail imap [options] HOST COMMAND...");
    print("           COMMAND: capa | id | enable CAPS | list [PAT] | lsub [PAT] | select MBOX | examine MBOX |");
    print("                    status MBOX | create MBOX | delete MBOX | rename OLD NEW | subscribe MBOX |");
    print("                    unsubscribe MBOX | fetch SET ITEMS | search CRIT | store SET HOW FLAGS |");
    print("                    copy SET MBOX | move SET MBOX | expunge | uid-expunge SET | append MBOX FILE [FLAGS] |");
    print("                    noop | close | unselect | idle SECONDS   (uid- forms of fetch, search, store, copy, move)");
    print("       goose-mail dkim sign --key FILE --domain D --selector S [--canon H/B] [--headers LIST]");
    print("                            [--no-oversign] [--identity ID] [--timestamp T] [--expire T] [--length] [FILE]");
    print("       goose-mail dkim verify [--record TEXT | --record-file FILE | --dns SERVER] [--allow-sha1] [--now T] [FILE]");
    print("       goose-mail dkim record --key FILE");
    print("       goose-mail smime sign [options] CERT KEY IN OUT");
    print("       goose-mail smime encrypt [options] IN OUT RCERT...");
    print("       goose-mail smime sign-encrypt [options] CERT KEY IN OUT RCERT...");
    print("       goose-mail smime verify [options] IN [OUT]");
    print("       goose-mail smime decrypt [options] CERT KEY IN [OUT]");
    exit(2);
}

fn fail(what: const u8[:], e: i64, code: i64, text: const u8[:]) {
    if e == mail::ERR_REPLY { print(what, ": refused: ", code, " ", text); }
    else { print(what, ": ", mail::error_text(e)); }
    exit(1);
}

fn mech_of(name: const u8[:]) -> i64 {
    for m in [mail::AUTH_PLAIN, mail::AUTH_LOGIN, mail::AUTH_CRAM_MD5, mail::AUTH_SCRAM_SHA1,
              mail::AUTH_SCRAM_SHA256, mail::AUTH_XOAUTH2, mail::AUTH_NTLM] {
        if mail::eq_fold(name, mail::auth_name(m)) { return m; }
    }
    return mail::AUTH_AUTO;
}

fn smtp_main(o: const Opts&, a: u8[:][:]) {
    if a.len < 4 { usage(); }
    var msg: u8[>..] = [];
    var m = mail::Msg { .. };
    let compose = a[1] == "-";
    if compose {
        var e = mail::set_from(m, a[2]);
        for t in a[3..] {
            if e != mail::OK { break; }
            e = if t.starts_with("bcc:") { mail::add_bcc(m, t[4..]) } else { mail::add_to(m, t) };
        }
        if e == mail::OK { e = mail::set_subject(m, "goose-mail: a composed message"); }
        if e == mail::OK { e = mail::set_body(m, mail::TEXT_PLAIN, "Built by mail.message.\n.a dotted line\n"); }
        if e == mail::OK { e = mail::attach(m, "data.bin", "\x00\x01\x02binary\xff"); }
        if e != mail::OK { print("compose: ", mail::error_text(e)); exit(1); }
    } else if !read_file(a[1], msg) {
        print("smtp: cannot read ", a[1]);
        exit(1);
    }
    var c = smtp::Client { .. };
    c.tlscfg.verify = !o.insecure;
    c.local_name.clear();
    c.local_name.append(o.name);
    var e = smtp::dial(c, a[0], o.port, o.tls);
    if e != mail::OK { fail("connect", e, c.code, c.text); }
    print("connected", if c.secure { " (TLS)" } else { "" }, if c.esmtp { ", ESMTP" } else { "" });
    var user: u8[>..] = [];
    var pass: u8[>..] = [];
    let has_user = env("MAIL_USER", user);
    env("MAIL_PASSWORD", pass);
    if o.auth != "none" && (has_user || o.auth.len > 0) {
        e = smtp::auth(c, mech_of(o.auth), user, pass);
        if e != mail::OK { fail("auth", e, c.code, c.text); }
        print("authenticated");
    }
    e = if compose { smtp::send_message(c, m) } else { smtp::send(c, a[2], a[3..], msg) };
    if e != mail::OK { fail("send", e, c.code, c.text); }
    if compose { print("message-id: ", mail::message_id(m)); }
    print("sent: ", c.code, " ", c.text);
    e = smtp::quit(c);
    if e != mail::OK { fail("quit", e, c.code, c.text); }
    print("quit");
}

fn number_arg(a: u8[:][:], i: i64) -> i64 {
    if i >= a.len { usage(); }
    let n, ok = parse_int(a[i]);
    if !ok || n < 0 { usage(); }
    return n;
}

fn pop3_main(o: const Opts&, a: u8[:][:]) {
    if a.len < 2 { usage(); }
    var c = pop3::Client { .. };
    c.tlscfg.verify = !o.insecure;
    var e = pop3::dial(c, a[0], o.port, o.tls);
    if e != mail::OK { fail("connect", e, 0, c.text); }
    print("connected", if c.secure { " (TLS)" } else { "" });
    var user: u8[>..] = [];
    var pass: u8[>..] = [];
    let has_user = env("MAIL_USER", user);
    env("MAIL_PASSWORD", pass);
    if o.auth != "none" && (has_user || o.auth.len > 0) {
        if o.auth == "user" || (o.auth.len == 0 && !pop3::capability(c, "SASL")) { e = pop3::login(c, user, pass); }
        else if o.auth == "apop" { e = pop3::apop(c, user, pass); }
        else { e = pop3::auth(c, mech_of(o.auth), user, pass); }
        if e != mail::OK { fail("auth", e, 0, c.text); }
        print("authenticated");
    }
    var i = 1;
    var out: u8[>..] = [];
    while i < a.len {
        let w = a[i];
        i++;
        out.clear();
        if w == "stat" {
            let count, size, se = pop3::stat(c);
            if se != mail::OK { fail("stat", se, 0, c.text); }
            print("stat: ", count, " ", size);
        } else if w == "list" {
            var l: pop3::Info[>..] = [];
            e = pop3::list(c, l);
            if e != mail::OK { fail("list", e, 0, c.text); }
            for x in l { print("list: ", x.num, " ", x.size); }
        } else if w == "uidl" {
            var l: pop3::Uid[>..] = [];
            e = pop3::uidl(c, l);
            if e != mail::OK { fail("uidl", e, 0, c.text); }
            for x in l { print("uidl: ", x.num, " ", x.uid); }
        } else if w == "capa" {
            print("capa: ", c.capa.len > 0);
        } else if w == "retr" {
            let n = number_arg(a, i);
            i++;
            e = pop3::retr(c, n, out);
            if e != mail::OK { fail("retr", e, 0, c.text); }
            print("retr: ", n, " ", out.len, " bytes");
            print(out);
        } else if w == "top" {
            let n = number_arg(a, i);
            let lines = number_arg(a, i + 1);
            i += 2;
            e = pop3::top(c, n, lines, out);
            if e != mail::OK { fail("top", e, 0, c.text); }
            print("top: ", n, " ", out.len, " bytes");
            print(out);
        } else if w == "dele" {
            let n = number_arg(a, i);
            i++;
            e = pop3::dele(c, n);
            if e != mail::OK { fail("dele", e, 0, c.text); }
            print("dele: ", n);
        } else {
            usage();
        }
    }
    e = pop3::quit(c);
    if e != mail::OK { fail("quit", e, 0, c.text); }
    print("quit");
}

fn imap_fail(what: const u8[:], e: i64, c: const imap::Client&) {
    if e == mail::ERR_REPLY {
        if c.code.len > 0 { print(what, ": refused: [", c.code, "] ", c.text); }
        else { print(what, ": refused: ", c.text); }
    } else {
        print(what, ": ", mail::error_text(e));
    }
    exit(1);
}

fn arg_at(a: u8[:][:], i: i64) -> const u8[:] {
    if i >= a.len { usage(); }
    return a[i];
}

fn addrs(l: const mail::Address[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in l {
        if out.len > 0 { out.append(", "); }
        mail::write_address(out, x);
    }
    return out;
}

// What a FETCH brought: a line per message, its envelope and body
// structure when asked for, and each BODY[...] / BINARY[...] item asked for.
fn show_messages(c: const imap::Client&, msgs: const imap::Message[:], items: const u8[:]) {
    for m in msgs {
        print("fetch: ", m.seq, " uid ", m.uid, " size ", m.size, " flags (", m.flags, ") date \"", m.internaldate, "\"");
        var env = imap::Envelope { .. };
        if imap::envelope(c, m, env) {
            print("envelope: date \"", env.date, "\" subject \"", env.subject, "\"");
            print("envelope: from ", addrs(env.from), "; to ", addrs(env.to), "; cc ", addrs(env.cc));
            print("envelope: message-id ", env.message_id);
        }
        var parts: imap::Part[>..] = [];
        if imap::bodystructure(c, m, parts) {
            for p in parts {
                print("part: ", if p.section.len > 0 { p.section[..] } else { "-" }, " ", p.mtype, "/", p.subtype,
                      " size ", p.size, " lines ", p.lines, " charset ", p.charset, " encoding ", p.encoding,
                      " disposition ", p.disposition, " filename ", p.filename);
            }
        }
        // The body sections asked for, as the server names them back:
        // BODY.PEEK[x] comes back as BODY[x], BODY[x]<0.10> as BODY[x]<0>.
        var nodes: imap::Node[>..] = [];
        if !imap::tree(items, nodes) { continue; }
        var top = 0;
        if nodes[0].count == 1 && imap::kind_of(nodes, nodes[0].child) == imap::K_LIST { top = nodes[0].child; }
        var k = nodes[top].child;
        while k >= 0 {
            let t = imap::raw(items, nodes, k);
            k = nodes[k].next;
            var name: u8[>..] = [];
            if t.len > 10 && mail::eq_fold(t[..10], "BODY.PEEK[") { name.append("BODY"); name.append(t[9..]); }
            else if t.len > 12 && mail::eq_fold(t[..12], "BINARY.PEEK[") { name.append("BINARY"); name.append(t[11..]); }
            else if (t.len > 5 && mail::eq_fold(t[..5], "BODY[")) || (t.len > 7 && mail::eq_fold(t[..7], "BINARY[")) ||
                    mail::eq_fold(t, "RFC822") || mail::eq_fold(t, "RFC822.HEADER") || mail::eq_fold(t, "RFC822.TEXT") {
                name.append(t);
            } else {
                continue;
            }
            let lt = find(name, "<");
            let key = if lt >= 0 { name[..lt] } else { name[..] };
            var body: u8[>..] = [];
            if imap::fetch_item(c, m, key, body) {
                print("body: ", key, " ", body.len, " bytes");
                print(body);
            }
        }
    }
}

fn imap_main(o: const Opts&, a: u8[:][:]) {
    if a.len < 1 { usage(); }
    var c = imap::Client { .. };
    c.tlscfg.verify = !o.insecure;
    var e = imap::dial(c, a[0], o.port, o.tls);
    if e != mail::OK { imap_fail("connect", e, c); }
    print("connected", if c.secure { " (TLS)" } else { "" }, if c.authenticated { ", PREAUTH" } else { "" });
    var user: u8[>..] = [];
    var pass: u8[>..] = [];
    let has_user = env("MAIL_USER", user);
    env("MAIL_PASSWORD", pass);
    if o.auth != "none" && (has_user || o.auth.len > 0) && !c.authenticated {
        if o.auth == "user" || (o.auth.len == 0 && imap::auth_list(c).len == 0) { e = imap::login(c, user, pass); }
        else { e = imap::authenticate(c, mech_of(o.auth), user, pass); }
        if e != mail::OK { imap_fail("auth", e, c); }
        print("authenticated");
    }
    var i = 1;
    var msgs: imap::Message[>..] = [];
    var nums: i64[>..]           = [];
    while i < a.len {
        let w = a[i];
        i++;
        if w == "capa" {
            var caps: u8[>..] = [];
            for ch in c.caps { caps.push(if ch == '\n' { ' ' } else { ch }); }
            print("capability: ", trim(caps));
        } else if w == "id" {
            var out: u8[>..] = [];
            e = imap::id(c, "goose-mail", "1", out);
            if e != mail::OK { imap_fail("id", e, c); }
            print("id: ", out);
        } else if w == "enable" {
            e = imap::enable(c, arg_at(a, i));
            i++;
            if e != mail::OK { imap_fail("enable", e, c); }
            print("enabled: utf8 ", c.utf8, " rev2 ", c.rev2);
        } else if w == "list" || w == "lsub" {
            let pattern = if i < a.len && !is_command(a[i]) { a[i] } else { "*" };
            if i < a.len && !is_command(a[i]) { i++; }
            var boxes: imap::Mailbox[>..] = [];
            e = if w == "list" { imap::list(c, "", pattern, boxes) } else { imap::lsub(c, "", pattern, boxes) };
            if e != mail::OK { imap_fail(w, e, c); }
            for b in boxes {
                var d: u8[>..] = [];
                if b.delim != 0 { d.push('"'); d.push(b.delim); d.push('"'); } else { d.append("NIL"); }
                print(w, ": (", b.attrs, ") ", d, " \"", b.name, "\"");
            }
        } else if w == "select" || w == "examine" {
            let mb = arg_at(a, i);
            i++;
            e = if w == "select" { imap::select(c, mb) } else { imap::examine(c, mb) };
            if e != mail::OK { imap_fail(w, e, c); }
            print("selected: ", mb, " exists ", c.exists, " uidvalidity ", c.uidvalidity, " uidnext ", c.uidnext,
                  " readonly ", c.readonly, " flags (", c.flags, ")");
        } else if w == "status" {
            let mb = arg_at(a, i);
            i++;
            var st = imap::Status { .. };
            e = imap::status(c, mb, st);
            if e != mail::OK { imap_fail("status", e, c); }
            print("status: ", mb, " messages ", st.messages, " uidnext ", st.uidnext, " uidvalidity ", st.uidvalidity,
                  " unseen ", st.unseen);
        } else if w == "create" || w == "delete" || w == "subscribe" || w == "unsubscribe" {
            let mb = arg_at(a, i);
            i++;
            e = if w == "create" { imap::create(c, mb) } else if w == "delete" { imap::delete(c, mb) }
                else if w == "subscribe" { imap::subscribe(c, mb) } else { imap::unsubscribe(c, mb) };
            if e != mail::OK { imap_fail(w, e, c); }
            print(w, ": ", mb);
        } else if w == "rename" {
            let from = arg_at(a, i);
            let to = arg_at(a, i + 1);
            i += 2;
            e = imap::rename(c, from, to);
            if e != mail::OK { imap_fail("rename", e, c); }
            print("rename: ", from, " ", to);
        } else if w == "fetch" || w == "uid-fetch" {
            let set = arg_at(a, i);
            let items = arg_at(a, i + 1);
            i += 2;
            e = if w == "fetch" { imap::fetch(c, set, items, msgs) } else { imap::uid_fetch(c, set, items, msgs) };
            if e != mail::OK { imap_fail(w, e, c); }
            show_messages(c, msgs, items);
        } else if w == "search" || w == "uid-search" {
            let crit = arg_at(a, i);
            i++;
            e = if w == "search" { imap::search(c, crit, nums) } else { imap::uid_search(c, crit, nums) };
            if e != mail::OK { imap_fail(w, e, c); }
            var line: u8[>..] = [];
            for n in nums { format(line, " ", n); }
            print(w, ":", line);
        } else if w == "store" || w == "uid-store" {
            let set = arg_at(a, i);
            let how = arg_at(a, i + 1);
            let flags = arg_at(a, i + 2);
            i += 3;
            e = if w == "store" { imap::store(c, set, how, flags) } else { imap::uid_store(c, set, how, flags) };
            if e != mail::OK { imap_fail(w, e, c); }
            imap::messages(c, msgs);
            for m in msgs { print(w, ": ", m.seq, " flags (", m.flags, ")"); }
            print(w, ": ok");
        } else if w == "copy" || w == "move" || w == "uid-copy" || w == "uid-move" {
            let set = arg_at(a, i);
            let mb = arg_at(a, i + 1);
            i += 2;
            e = if w == "copy" { imap::copy(c, set, mb) } else if w == "move" { imap::move(c, set, mb) }
                else if w == "uid-copy" { imap::uid_copy(c, set, mb) } else { imap::uid_move(c, set, mb) };
            if e != mail::OK { imap_fail(w, e, c); }
            print(w, ": ", set, " ", mb, " [", c.code, "]");
        } else if w == "expunge" || w == "uid-expunge" {
            if w == "expunge" { e = imap::expunge(c); }
            else { e = imap::uid_expunge(c, arg_at(a, i)); i++; }
            if e != mail::OK { imap_fail(w, e, c); }
            imap::expunged(c, nums);
            var line: u8[>..] = [];
            for n in nums { format(line, " ", n); }
            print("expunged:", line, " exists ", c.exists);
        } else if w == "append" {
            let mb = arg_at(a, i);
            let file = arg_at(a, i + 1);
            i += 2;
            let has_flags = i < a.len && a[i].starts_with("\\");
            let flags = if has_flags { a[i] } else { file[0..0] };
            if has_flags { i++; }
            var msg: u8[>..] = [];
            if !read_file(file, msg) { print("append: cannot read ", file); exit(1); }
            e = imap::append(c, mb, flags, "", msg);
            if e != mail::OK { imap_fail("append", e, c); }
            print("append: ", msg.len, " bytes [", c.code, "]");
        } else if w == "noop" {
            e = imap::noop(c);
            if e != mail::OK { imap_fail("noop", e, c); }
            print("noop: exists ", c.exists);
        } else if w == "close" {
            e = imap::close_mailbox(c);
            if e != mail::OK { imap_fail("close", e, c); }
            print("close: ok");
        } else if w == "unselect" {
            e = imap::unselect(c);
            if e != mail::OK { imap_fail("unselect", e, c); }
            print("unselect: ok");
        } else if w == "idle" {
            let secs, ok = parse_int(arg_at(a, i));
            i++;
            if !ok || secs < 0 || secs > 3600 { usage(); }
            e = imap::idle_start(c);
            if e != mail::OK { imap_fail("idle", e, c); }
            print("idle: started");
            var waited = 0;
            while waited < secs * 1000 {
                e = imap::idle_wait(c, 250);
                waited += 250;
                if e == mail::ERR_TIMEOUT { continue; }
                if e != mail::OK { imap_fail("idle", e, c); }
                imap::each_response(c) { r => print("idle: ", r); };
            }
            e = imap::idle_done(c);
            if e != mail::OK { imap_fail("idle", e, c); }
            print("idle: done, exists ", c.exists);
        } else {
            usage();
        }
    }
    e = imap::logout(c);
    if e != mail::OK { imap_fail("logout", e, c); }
    print("logout");
}

fn is_command(w: const u8[:]) -> bool {
    for n in ["capa", "id", "enable", "list", "lsub", "select", "examine", "status", "create", "delete", "subscribe",
              "unsubscribe", "rename", "fetch", "uid-fetch", "search", "uid-search", "store", "uid-store", "copy",
              "move", "uid-copy", "uid-move", "expunge", "uid-expunge", "append", "noop", "close", "unselect", "idle"] {
        if w == n { return true; }
    }
    return false;
}

fn dkim_fail(what: const u8[:], e: i64) {
    write_stderr(str("dkim: ", what, ": ", mail::error_text(e), "\n"));
    exit(1);
}

fn read_input(path: const u8[:], out: u8[>..]&) {
    if path.len == 0 || path == "-" { read_stdin(out); return; }
    if !read_file(path, out) { write_stderr(str("dkim: cannot read ", path, "\n")); exit(1); }
}

fn time_arg(v: const u8[:]) -> i64 {
    if v == "now" { return time_ns() / 1000000000; }
    let n, ok = parse_int(v);
    if !ok || n < 0 { usage(); }
    return n;
}

fn canon_arg(v: const u8[:]) -> i64 {
    if v == "simple" { return dkim::SIMPLE; }
    if v == "relaxed" { return dkim::RELAXED; }
    usage();
    return 0;
}

fn load_key(path: const u8[:]) -> x509::PrivateKey {
    var text: u8[>..] = [];
    if path.len == 0 || !read_file(path, text) { write_stderr("dkim: cannot read the key\n"); exit(1); }
    let k, e = dkim::parse_key(text);
    if e != mail::OK { dkim_fail("the key", e); }
    return k;
}

fn dkim_sign_main(a: u8[:][:]) {
    var o = dkim::SignOptions { .. };
    var key_path: u8[>..] = [];
    var input:    u8[>..] = [];
    var i = 0;
    while i < a.len {
        let f = a[i];
        if f == "--no-oversign" { o.oversign_from = false; i++; continue; }
        if f == "--length" { o.body_length = dkim::BODY_ALL; i++; continue; }
        if !f.starts_with("--") { input.append(f); i++; continue; }
        if i + 1 >= a.len { usage(); }
        let v = a[i + 1];
        if f == "--key" { key_path.append(v); }
        else if f == "--domain" { o.domain.append(v[.. ::min(v.len, 253)]); }
        else if f == "--selector" { o.selector.append(v[.. ::min(v.len, 253)]); }
        else if f == "--headers" { o.headers.append(v[.. ::min(v.len, 1000)]); }
        else if f == "--identity" { o.identity.append(v[.. ::min(v.len, 320)]); }
        else if f == "--timestamp" { o.timestamp = time_arg(v); }
        else if f == "--expire" { o.expire = time_arg(v); }
        else if f == "--canon" {
            let h, b, has = split_once(v, '/');
            o.header_canon = canon_arg(h);
            o.body_canon = if has { canon_arg(b) } else { dkim::SIMPLE };
        } else { usage(); }
        i += 2;
    }
    let key = load_key(key_path);
    var msg: u8[>..] = [];
    read_input(input, msg);
    var out: u8[>..] = [];
    let e = dkim::sign(msg, key, o, out);
    if e != mail::OK { dkim_fail("sign", e); }
    write_stdout(out);
}

fn dkim_verify_main(a: u8[:][:]) {
    var o = dkim::VerifyOptions { .. };
    var record: u8[>..] = [];
    var has_record = false;
    var server: u8[>..] = [];
    var input:  u8[>..] = [];
    var i = 0;
    while i < a.len {
        let f = a[i];
        if f == "--allow-sha1" { o.allow_sha1 = true; i++; continue; }
        if !f.starts_with("--") { input.append(f); i++; continue; }
        if i + 1 >= a.len { usage(); }
        let v = a[i + 1];
        if f == "--record" { record.append(v); has_record = true; }
        else if f == "--record-file" {
            if !read_file(v, record) { write_stderr(str("dkim: cannot read ", v, "\n")); exit(1); }
            has_record = true;
        }
        else if f == "--dns" { server.append(v); }
        else if f == "--now" { o.now = time_arg(v); }
        else { usage(); }
        i += 2;
    }
    var msg: u8[>..] = [];
    read_input(input, msg);
    var res: dkim::Result[>..] = [];
    let e = if has_record { dkim::verify_record(msg, record, res, o) } else { dkim::verify_dns(msg, server, res, o) };
    if res.len == 0 { print("dkim=none"); }
    for r in res {
        var line: u8[>..] = [];
        dkim::result_text(r, line);
        print(line);
    }
    exit(if e == mail::OK { 0 } else { 1 });
}

fn dkim_record_main(a: u8[:][:]) {
    if a.len != 2 || a[0] != "--key" { usage(); }
    let key = load_key(a[1]);
    var out: u8[>..] = [];
    let e = dkim::key_record(key, out);
    if e != mail::OK { dkim_fail("record", e); }
    print(out);
}

fn dkim_main(a: u8[:][:]) {
    if a.len < 1 { usage(); }
    if a[0] == "sign" { dkim_sign_main(a[1..]); }
    else if a[0] == "verify" { dkim_verify_main(a[1..]); }
    else if a[0] == "record" { dkim_record_main(a[1..]); }
    else { usage(); }
}

fn smime_fail(what: const u8[:], rc: i64, detail: i64) {
    if detail != 0 { print("smime: ", what, ": ", mail::error_text(rc), " (", x509::cms_error_text(detail), ")"); }
    else { print("smime: ", what, ": ", mail::error_text(rc)); }
    exit(1);
}

fn read_all(path: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if !read_file(path, out) { print("smime: cannot read ", path); exit(1); }
    return out;
}

// Every certificate of a PEM file, DER laid end to end.
fn read_certs(path: const u8[:]) -> u8[>..] {
    let blocks, ok = asn1::pem_decode(read_all(path), "CERTIFICATE");
    if !ok || blocks.len == 0 { print("smime: no certificate in ", path); exit(1); }
    var out: u8[>..] = [];
    for b in blocks { out.append(b); }
    return out;
}

// The first certificate of a PEM file, and the others.
fn read_cert(path: const u8[:]) -> x509::Cert, u8[>..] {
    let all = read_certs(path);
    let t, ok = asn1::read(all, 0, all.len);
    let c, e = x509::parse(all[t.start..t.end]);
    if !ok || e != x509::OK { print("smime: ", path, ": ", x509::error_text(e)); exit(1); }
    var rest: u8[>..] = [];
    rest.append(all[t.end..]);
    return c, rest;
}

fn read_key(path: const u8[:]) -> x509::PrivateKey {
    let k, ok = x509::parse_private_key_pem(read_all(path));
    if !ok { print("smime: ", path, ": not a private key this reads"); exit(1); }
    return k;
}

fn write_out(path: const u8[:], data: const u8[:]) {
    if path == "-" { print(data); return; }
    if !write_file(path, data) { print("smime: cannot write ", path); exit(1); }
}

fn number(s: const u8[:]) -> i64 {
    let v, ok = parse_int(s, 10);
    if !ok { usage(); }
    return v;
}

fn smime_main(a: u8[:][:]) {
    if a.len < 1 { usage(); }
    let cmd = a[0];
    var o = smime::Options { .. };
    var opaque = false;
    var roots_file: u8[>..] = [];
    var now = time_ns() / 1000000000;
    var pos: i64[>..] = [];             // where the positional arguments are
    var i = 1;
    while i < a.len {
        let s = a[i];
        let more = i + 1 < a.len;
        if s == "--opaque" { opaque = true; }
        else if s == "--pss" { o.pss = true; }
        else if s == "--keyid" { o.by_key_id = true; }
        else if s == "--pkcs1" { o.rsa_pkcs1 = true; }
        else if s == "--hash" && more { i++; o.hash = number(a[i]); }
        else if s == "--time" && more { i++; o.signing_time = number(a[i]); }
        else if s == "--now" && more { i++; now = number(a[i]); }
        else if s == "--boundary" && more { i++; o.boundary.clear(); if a[i].len > 70 { usage(); } o.boundary.append(a[i]); }
        else if s == "--roots" && more { i++; roots_file.clear(); roots_file.append(a[i]); }
        else if s == "--cipher" && more {
            i++;
            let c = a[i];
            if c == "aes128-cbc" { o.cipher = x509::CMS_AES128_CBC; }
            else if c == "aes256-cbc" { o.cipher = x509::CMS_AES256_CBC; }
            else if c == "aes128-gcm" { o.cipher = x509::CMS_AES128_GCM; }
            else if c == "aes256-gcm" { o.cipher = x509::CMS_AES256_GCM; }
            else { usage(); }
        }
        else if s.len > 2 && s[0] == '-' && s[1] == '-' { usage(); }
        else { pos.push(i); }
        i++;
    }
    var out: u8[>..] = [];
    if cmd == "sign" || cmd == "sign-encrypt" {
        if pos.len < 4 || (cmd == "sign" && pos.len != 4) || (cmd == "sign-encrypt" && pos.len < 5) { usage(); }
        let cert, chain = read_cert(a[pos[0]]);
        let key = read_key(a[pos[1]]);
        let msg = read_all(a[pos[2]]);
        var rc = mail::OK;
        if cmd == "sign" {
            rc = if opaque { smime::sign_opaque(msg, key, cert, chain, o, out) } else { smime::sign(msg, key, cert, chain, o, out) };
        } else {
            var rs: u8[>..] = [];
            for j in 4..pos.len { rs.append(read_certs(a[pos[j]])); }
            rc = smime::sign_encrypt(msg, key, cert, chain, rs, o, out);
        }
        if rc != mail::OK { smime_fail(cmd, rc, 0); }
        write_out(a[pos[3]], out);
        return;
    }
    if cmd == "encrypt" {
        if pos.len < 3 { usage(); }
        let msg = read_all(a[pos[0]]);
        var rs: u8[>..] = [];
        for j in 2..pos.len { rs.append(read_certs(a[pos[j]])); }
        let rc = smime::encrypt(msg, rs, o, out);
        if rc != mail::OK { smime_fail(cmd, rc, 0); }
        write_out(a[pos[1]], out);
        return;
    }
    if cmd != "verify" && cmd != "decrypt" { usage(); }
    var at = 0;
    var r = smime::Opened { .. };
    var rc = mail::OK;
    if cmd == "verify" {
        if pos.len < 1 || pos.len > 2 { usage(); }
        let msg = read_all(a[pos[0]]);
        rc = smime::verify(msg, r);
        at = 1;
    } else {
        if pos.len < 3 || pos.len > 4 { usage(); }
        let cert, chain = read_cert(a[pos[0]]);
        let key = read_key(a[pos[1]]);
        let msg = read_all(a[pos[2]]);
        rc = smime::open(msg, key, cert, r);
        at = 3;
    }
    if rc != mail::OK { smime_fail(cmd, rc, r.cms_error); }
    if r.encrypted { print("encrypted"); }
    if r.signed {
        print("signed by ", x509::subject_text(r.signer));
        if r.has_signing_time { print("signing time ", r.signing_time); }
    }
    if roots_file.len > 0 && r.signed {
        var roots = x509::new_pool();
        let ok = x509::pool_add_concatenated(roots, read_certs(roots_file));
        let pe = smime::check_path(r, roots, now);
        if pe != x509::OK { print("smime: signer: ", x509::error_text(pe)); exit(1); }
        let msg = read_all(a[pos[at - 1]]);
        let from = smime::from_address(msg);
        if from.len > 0 && !smime::has_address(r.signer, from) { print("smime: signer: not ", from); exit(1); }
        print("signer ok");
    }
    if pos.len > at { write_out(a[pos[at]], r.message); }
}

fn main() {
    let a = args();
    if a.len < 2 { usage(); }
    if a[1] == "dkim" { dkim_main(a[2..]); return; }
    if a[1] == "smime" { smime_main(a[2..]); return; }
    var o = Opts { port: 0, tls: smtp::TLS_MANDATORY, insecure: false, auth: [], name: [] };
    o.name.append("localhost");
    var i = 2;
    while i < a.len && a[i].starts_with("--") {
        let f = a[i];
        if f == "--insecure" { o.insecure = true; i++; continue; }
        if i + 1 >= a.len { usage(); }
        let v = a[i + 1];
        if f == "--port" {
            let p, ok = parse_int(v);
            if !ok || p <= 0 || p > 65535 { usage(); }
            o.port = p;
        } else if f == "--tls" {
            if v == "mandatory" { o.tls = smtp::TLS_MANDATORY; }
            else if v == "opportunistic" { o.tls = smtp::TLS_OPPORTUNISTIC; }
            else if v == "none" { o.tls = smtp::TLS_NONE; }
            else if v == "implicit" { o.tls = smtp::TLS_IMPLICIT; }
            else { usage(); }
        } else if f == "--auth" {
            o.auth.clear();
            o.auth.append(v[.. ::min(v.len, 32)]);
        } else if f == "--name" {
            o.name.clear();
            o.name.append(v[.. ::min(v.len, 255)]);
        } else {
            usage();
        }
        i += 2;
    }
    if a[1] == "smtp" { smtp_main(o, a[i..]); }
    else if a[1] == "pop3" { pop3_main(o, a[i..]); }
    else if a[1] == "imap" { imap_main(o, a[i..]); }
    else { usage(); }
}
