// The parts of mail.smtp and mail.pop3 that need no server: DATA's
// dot-stuffing and line endings, APOP's timestamp and digest (RFC 1939 §7's
// example), POP3's numbers, the address and command checks, and the
// clients refusing commands before a connection. scripts/interop.py runs
// them against servers.
import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.link;
import gslib.mail.smtp;
import gslib.mail.pop3;

var failures = 0;

fn check(what: const u8[:], ok: bool) {
    if !ok { print("FAIL ", what); failures++; }
}

fn stuffed(msg: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    smtp::dot_stuff(out, msg);
    return out;
}

fn main() {
    // DATA: CRLF everywhere, a leading dot doubled, the ending dot.
    check("stuff: plain", stuffed("a\r\nb\r\n") == "a\r\nb\r\n.\r\n");
    check("stuff: no final newline", stuffed("a") == "a\r\n.\r\n");
    check("stuff: empty", stuffed("") == ".\r\n");
    check("stuff: bare LF", stuffed("a\nb\n") == "a\r\nb\r\n.\r\n");
    check("stuff: bare CR", stuffed("a\rb") == "a\r\nb\r\n.\r\n");
    check("stuff: dots", stuffed(".\r\n..x\r\ny.z\r\n.") == "..\r\n...x\r\ny.z\r\n..\r\n.\r\n");
    check("stuff: a dot after a bare LF", stuffed("a\n.b") == "a\r\n..b\r\n.\r\n");

    // APOP, RFC 1939 §7.
    let ts, ok = pop3::apop_timestamp("POP3 server ready <1896.697170952@dbc.mtview.ca.us>");
    check("apop: timestamp found", ok && ts == "<1896.697170952@dbc.mtview.ca.us>");
    check("apop: digest", pop3::apop_digest(ts, "tanstaaf") == "c4c9334bac560ecc979e58001b3e22fb");
    let ts2, ok2 = pop3::apop_timestamp("POP3 server ready");
    check("apop: no timestamp", !ok2);
    let ts3, ok3 = pop3::apop_timestamp("ready <unclosed");
    check("apop: unclosed timestamp", !ok3);

    // POP3's numbers: "count size", "num uid".
    let n, rest, okn = pop3::number("2 320");
    check("number: first", okn && n == 2 && rest == "320");
    let n2, rest2, okn2 = pop3::number("x 1");
    check("number: not a number", !okn2);
    let n3, rest3, okn3 = pop3::number("99999999999999999999");
    check("number: overflow", !okn3);

    // What may not go in a command.
    check("path: plain", smtp::path_ok("a@example.com"));
    check("path: angle", !smtp::path_ok("a@example.com> SIZE=1"));
    check("path: CRLF", !smtp::path_ok("a@example.com\r\nRCPT TO:<b@example.com>"));
    check("crlf: found", mail::has_crlf("USER a\r\nPASS b"));
    check("crlf: none", !mail::has_crlf("USER a"));

    // Before a connection, every command is out of order.
    var c = smtp::Client { .. };
    check("smtp: noop unconnected", smtp::noop(c) == mail::ERR_STATE);
    check("smtp: quit unconnected", smtp::quit(c) == mail::ERR_STATE);
    check("smtp: auth unconnected", smtp::auth(c, mail::AUTH_PLAIN, "u", "p") == mail::ERR_STATE);
    check("smtp: bad port", smtp::dial(c, "localhost", 70000, smtp::TLS_NONE) == mail::ERR_ARG);
    var p = pop3::Client { .. };
    check("pop3: noop unconnected", pop3::noop(p) == mail::ERR_STATE);
    check("pop3: quit unconnected", pop3::quit(p) == mail::ERR_STATE);
    let count, size, se = pop3::stat(p);
    check("pop3: stat unconnected", se == mail::ERR_STATE);
    check("pop3: empty host", pop3::dial(p, "", 110, pop3::TLS_NONE) == mail::ERR_ARG);

    check("eq_fold", mail::eq_fold("StartTLS", "STARTTLS") && !mail::eq_fold("STARTTLS", "STARTTLSX"));

    if failures > 0 { print(failures, " failures"); exit(1); }
    print("protocol: ok");
}
