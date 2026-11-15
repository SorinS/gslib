// Fuzz target: x509_ocsp. By the first byte (data[0] % 2): 0 an OCSP
// response, parsed for its only answer and for a fixed leaf's serial,
// then the responder certificate it carries, whether the ResponderID
// names the CA, the signature by the CA, and the whole check for the leaf
// at a fixed time; 1 an OCSP request parsed. The CA and leaf are those of
// crypto/x509/test/vectors/ocsp.txt.

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.ocsp;

let NOW: i64 = 1793034360;

var ca = x509::empty_cert();
var leaf = x509::empty_cert();

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

fn response(der: const u8[:]) {
    let _ = x509::ocsp_parse_response(der);
    let r, e = x509::ocsp_parse_response(der, leaf.der[leaf.serial.off..leaf.serial.end]);
    if e != x509::OK { return; }
    let rc, erc = x509::ocsp_responder_cert(r);
    if erc == x509::OK {
        let _ = x509::ocsp_names(r, rc);
        let _ = x509::subject_text(rc);
    }
    let _ = x509::ocsp_names(r, ca);
    let _ = x509::ocsp_signed_by(r, ca);
    let _ = x509::ocsp_check_response(r, leaf, ca, NOW);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let rest = data[1..];
    if data[0] % 2 == 0 { response(rest); }
    else { let _ = x509::ocsp_parse_request(rest); }
    return 0;
}

fn main() {
    let text = embed_file("../../crypto/x509/test/vectors/ocsp.txt");
    for line in split(text, '\n') {
        let w = split(line, ' ');
        if w.len < 3 || w[0] != "cert" { continue; }
        let c, e = x509::parse(unhex(w[2]));
        assert(e == x509::OK);
        if w[1] == "ca" { ca = copy(c); }
        if w[1] == "leaf" { leaf = copy(c); }
    }
    assert(ca.der.len > 0 && leaf.der.len > 0);
}
