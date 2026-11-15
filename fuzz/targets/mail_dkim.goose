// Fuzz target: mail_dkim. DKIM verification without DNS, selected by the
// first byte:
//   0: a signed message verified (dkim::verify) with the key records of
//      RFC 8463 Appendix A (Ed25519 "brisbane", RSA "test") given by the
//      lookup block for any domain, a fixed clock; results written out.
//   1: a key TXT record (parse_record), and the tag-list and h= parsers on
//      the same text (parse_tags, tag_value, list_has, split_names).
//   2: "record NUL message": verify_record with the input's own record;
//      the message's fields and body canonicalized both ways.
// Known: multiple From fields pass (review finding dkim.goose:820,932).

import std;
import gslib from "../..";
import gslib.mail;
import gslib.mail.dkim;

let ED_RECORD = "v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";
let RSA_RECORD = str(
    "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR",
    "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC",
    "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3",
    "Ip3G+2kryOTIKT+l/K4w3QIDAQAB");

// RFC 8463's t= is 1528637909.
let NOW: i64 = 1528640000;

fn keys(domain: const u8[:], selector: const u8[:], rec: u8[>..]&) {
    if selector == "brisbane" { rec.append(ED_RECORD); }
    else if selector == "test" { rec.append(RSA_RECORD); }
}

fn report(res: const dkim::Result[:]) {
    var out: u8[>..] = [];
    for &r in res { dkim::result_text(r, out); }
}

fn verify(msg: const u8[:]) {
    var res: dkim::Result[>..] = [];
    let _ = dkim::verify(msg, res, dkim::VerifyOptions { now: NOW, .. }) { d, s, rec => keys(d, s, rec); };
    report(res);
    res.clear();
    let _ = dkim::verify(msg, res, dkim::VerifyOptions { now: NOW, allow_sha1: true, min_rsa_bits: 512, max_signatures: 2 }) { d, s, rec => keys(d, s, rec); };
    report(res);
}

fn record(text: const u8[:]) {
    var k = dkim::PublicKey { .. };
    var r = dkim::Result { .. };
    let _ = dkim::parse_record(text, k, r);
    var tags: dkim::Tag[>..] = [];
    if dkim::parse_tags(text, tags) == mail::OK {
        for name in ["v", "a", "b", "bh", "c", "d", "h", "i", "l", "q", "s", "t", "x", "p", "k"] {
            let v, ok = dkim::tag_value(text, tags, name);
            if ok {
                let _ = dkim::list_has(v, "sha256");
                var names: dkim::Span[>..] = [];
                let _ = dkim::split_names(v, names);
            }
        }
    }
}

fn canon(msg: const u8[:]) {
    var fields: dkim::Field[>..] = [];
    let at = dkim::split_message(msg, fields);
    var out: u8[>..] = [];
    for f in fields {
        let _ = dkim::field_name(msg, f);
        for c in [dkim::SIMPLE, dkim::RELAXED] { dkim::canon_header(out, dkim::field_text(msg, f), c); }
    }
    if at >= 0 && at <= msg.len {
        for c in [dkim::SIMPLE, dkim::RELAXED] { dkim::canon_body(out, msg[at..], c); }
    }
}

fn with_record(data: const u8[:]) {
    var z = 0;
    while z < data.len && data[z] != 0 { z++; }
    let rec = data[..z];
    let msg = if z < data.len { data[z + 1..] } else { data[z..] };
    var res: dkim::Result[>..] = [];
    let _ = dkim::verify_record(msg, rec, res, dkim::VerifyOptions { now: NOW, .. });
    report(res);
    canon(msg);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    match data[0] % 3 {
        0 => { verify(rest); },
        1 => { record(rest); },
        _ => { with_record(rest); },
    }
    return 0;
}

fn main() {}
