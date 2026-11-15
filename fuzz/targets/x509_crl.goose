// Fuzz target: x509_crl. A CRL parsed, its issuer as text, then every
// revoked entry looked up (crl_lookup with a stand-in certificate whose
// serial is that entry's, which reads its extensions and reason code),
// then the checks against fixed certificates from
// crypto/x509/test/vectors/certs.txt: in scope (crl_covers), usable
// (check_crl: the issuer's key usage and signature), the leaf's lookup,
// and revocation_status over the input as a list of CRLs.

import std;
import gslib from "../..";
import gslib.crypto.x509;
import gslib.crypto.x509.crl;
import gslib.encoding.asn1;

let NOW: i64 = 1793000000;

var issuer = x509::empty_cert();
var leaf = x509::empty_cert();
var ca_leaf = x509::empty_cert();

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i + 1 < s.len {
        out.push((ascii::hex_value(s[i]) * 16 + ascii::hex_value(s[i + 1])) as! u8);
        i += 2;
    }
    return out;
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    let crl, e = x509::parse_crl(data);
    if e == x509::OK {
        let d = crl.der[..];
        let _ = x509::name_text(d, crl.issuer);
        if crl.has_revoked {
            let es, ok = asn1::children(d, crl.revoked);
            var n = 0;
            for en in es {
                if n >= 256 { break; }
                n++;
                let ef, okef = asn1::children(d, en);
                if !okef || ef.len == 0 { continue; }
                var stand_in = x509::empty_cert();
                stand_in.der.append(d);
                stand_in.serial = ef[0];
                let _ = x509::crl_lookup(crl, stand_in);
            }
        }
        let _ = x509::crl_covers(crl, leaf);
        let _ = x509::crl_covers(crl, ca_leaf);
        let _ = x509::crl_lookup(crl, leaf);
        let _ = x509::check_crl(crl, issuer, NOW);
    }
    let _ = x509::revocation_status(leaf, issuer, data, NOW);
    return 0;
}

fn main() {
    // The issuer of the first CRL in certs.txt, and a leaf it lists.
    let text = embed_file("../../crypto/x509/test/vectors/certs.txt");
    var crl_der: u8[>..] = [];
    for line in split(text, '\n') {
        let w = split(line, ' ');
        if w.len >= 3 && w[0] == "crl" && crl_der.len == 0 { crl_der = unhex(w[w.len - 1]); }
    }
    let first, e = x509::parse_crl(crl_der);
    assert(e == x509::OK);
    for line in split(text, '\n') {
        let w = split(line, ' ');
        if w.len < 3 || w[0] != "cert" { continue; }
        let c, ec = x509::parse(unhex(w[2]));
        if ec != x509::OK { continue; }
        if c.der[c.subject.start..c.subject.end] == first.der[first.issuer.start..first.issuer.end] { issuer = copy(c); }
        if w[1] == "leaf_revoked" { leaf = copy(c); }
        if w[1] == "int_ec" { ca_leaf = copy(c); }
    }
    assert(issuer.der.len > 0 && leaf.der.len > 0);
}
