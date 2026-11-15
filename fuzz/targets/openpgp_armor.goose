// Fuzz target: openpgp_armor. The first byte picks:
//   0  ASCII armor: is_armored, dearmor, decode_input, and every block of
//      the text (find_begin/dearmor_at in a loop), each armored again and
//      read back; canonical_text and dash_escape over the text;
//   1  a cleartext signed message: parse_cleartext, cleartext_body, and
//      verify_cleartext against a fixed keyring of public keys.

import std;
import gslib from "../..";
import gslib.crypto.openpgp;
import gslib.crypto.openpgp.armor;
import gslib.crypto.openpgp.packet;
import gslib.crypto.openpgp.key;
import gslib.crypto.openpgp.sig;
import gslib.crypto.openpgp.keyring;
import gslib.crypto.openpgp.message;

var KR = openpgp::Keyring { .. };

fn armor(text: const u8[:]) {
    let a = openpgp::is_armored(text);
    var out: u8[>..] = [];
    let label, err = openpgp::dearmor(text, out);
    if err == openpgp::OK {
        var again: u8[>..] = [];
        openpgp::armor(again, label, out, "Comment: fuzz\n");
        var back: u8[>..] = [];
        let l2, e2 = openpgp::dearmor(again, back);
    }
    var bin: u8[>..] = [];
    let e3 = openpgp::decode_input(text, bin);
    // Every block.
    var from = 0;
    var n = 0;
    while from < text.len && n < 256 {
        let at, l = openpgp::find_begin(text, from);
        if at < 0 { break; }
        var o:      u8[>..] = [];
        var hashes: u8[>..] = [];
        let lab, next, e = openpgp::dearmor_at(text, at, o, hashes);
        n++;
        from = if next > at { next } else { at + 1 };
    }
    var c: u8[>..] = [];
    openpgp::canonical_text(c, text);
    var cs: u8[>..] = [];
    openpgp::canonical_text(cs, text, true);
    var d: u8[>..] = [];
    openpgp::dash_escape(d, text);
}

fn cleartext(text: const u8[:]) {
    var ct = openpgp::Cleartext { .. };
    let e = openpgp::parse_cleartext(text, ct);
    if e == openpgp::OK {
        var body: u8[>..] = [];
        openpgp::cleartext_body(body, ct);
    }
    var m = openpgp::Message { .. };
    let e2 = openpgp::verify_cleartext(KR, text, m);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len < 1 { return 0; }
    let rest = data[1..];
    if data[0] % 2 == 0 { armor(rest); } else { cleartext(rest); }
    return 0;
}

fn main() {
    let e1 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/ed.pub"));
    let e2 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/rsa.pub"));
    let e3 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/bp256.pub"));
    let e4 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/ed448.pub"));
    let e5 = openpgp::add_keys(KR, embed_file("../../crypto/openpgp/test/vectors/rfc9580_a3_cert.asc"));
}
