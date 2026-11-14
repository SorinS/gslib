// dkim_sign: a message built with mail.message, signed with DKIM
// (Ed25519-SHA256, RFC 8463) and verified again, the key record handed in
// as DNS would give it. The key is RFC 8032's first test key (never sign
// real mail with it), and the Date, Message-ID and t= are fixed, so the
// output is the same each run. No network.
//
//   goose examples/mail/dkim_sign.goose

import std;
import os;
import gslib from "../..";
import gslib.mail;
import gslib.mail.message;
import gslib.mail.dkim;
import gslib.crypto.x509;
import gslib.crypto.x509.keys;

// RFC 8032 §7.1, test 1: the secret key (the seed), in base64.
let TEST_SEED = "nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";

fn must(what: const u8[:], rc: i64) {
    if rc != mail::OK {
        print("dkim_sign: ", what, ": ", mail::error_text(rc));
        exit(1);
    }
}

fn main() {
    var m = mail::Msg { .. };
    must("from", mail::set_from(m, "Reports <reports@example.com>"));
    must("to", mail::add_to(m, "finance@example.org"));
    must("subject", mail::set_subject(m, "Figures for March"));
    mail::set_date(m, 1711929600);                              // 2024-04-01 00:00:00 UTC
    must("id", mail::set_message_id(m, "figures-2024-03@example.com"));
    must("body", mail::set_body(m, mail::TEXT_PLAIN, "The figures are in.\n"));

    let key, ke = dkim::parse_key(TEST_SEED);
    must("key", ke);
    var o = dkim::SignOptions { timestamp: 1711929600, .. };
    o.domain.append("example.com");
    o.selector.append("march2024");
    var signed: u8[>..] = [];
    must("sign", dkim::sign_msg(m, key, o, signed));
    write_stdout(signed);

    // What march2024._domainkey.example.com's TXT record would hold.
    var record: u8[>..] = [];
    must("record", dkim::key_record(key, record));
    print("");
    print("TXT ", record);

    var res: dkim::Result[>..] = [];
    let e = dkim::verify(signed, res) { domain, selector, rec =>
        if domain == "example.com" && selector == "march2024" { rec.append(record); }
    };
    for r in res {
        var line: u8[>..] = [];
        dkim::result_text(r, line);
        print(line);
    }
    must("verify", e);
}
