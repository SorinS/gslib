// ldap_ber: an LDAP bind (RFC 4511) as a client sees it. The request is
// written with the DER writer (DER is BER, so any server reads it); the
// response is BER as Active Directory sends it, every length in five
// octets (84 00 00 00 nn), which the DER reader refuses and the readers
// read with `ber = true`.
//
//   LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE { ... } }
//   BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name OCTET STRING,
//                                              simple [0] IMPLICIT OCTET STRING }
//   BindResponse ::= [APPLICATION 1] SEQUENCE { resultCode ENUMERATED,
//                                               matchedDN OCTET STRING,
//                                               diagnosticMessage OCTET STRING }
//
//   goose examples/asn1/ldap_ber.goose

import std;
import gslib from "../..";
import gslib.encoding.asn1;

let BIND_REQUEST:  u32 = 0x60;     // [APPLICATION 0], constructed
let BIND_RESPONSE: u32 = 0x61;     // [APPLICATION 1], constructed

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn hex(b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    for x in b { format_int(out, x, 16, 2, '0'); }
    return out;
}

fn main() {
    // The request: message 1, a simple bind.
    var bind: u8[>..] = [];
    asn1::put_i64(bind, 3);
    asn1::put_octets(bind, "cn=reader,dc=example,dc=com");
    asn1::put(bind, asn1::ctx(0, false), "not-a-real-password");
    var msg: u8[>..] = [];
    asn1::put_i64(msg, 1);
    asn1::put(msg, BIND_REQUEST, bind);
    var req: u8[>..] = [];
    asn1::put(req, asn1::SEQUENCE, msg);
    print("request:  ", hex(req));
    let rq, okq = asn1::parse(req);
    guard okq && rq.end == req.len else { print("ldap_ber: the request is not DER"); exit(1); }

    // The response as AD sends it: message 1, success, empty DN and text.
    let resp = unhex("3084000000100201016184000000070a010004000400");
    print("response: ", hex(resp));
    let strict, okd = asn1::parse(resp);
    guard !okd else { print("ldap_ber: DER should refuse long-form lengths"); exit(1); }

    let top, ok = asn1::parse(resp, true);
    let m, okm = asn1::children_of(resp, top, asn1::SEQUENCE, true);
    guard ok && okm && m.len >= 2 else { print("ldap_ber: not an LDAPMessage"); exit(1); }
    let id, oki = asn1::read_i64(resp, m[0], asn1::INTEGER, true);
    guard oki && id == 1 else { print("ldap_ber: not a reply to message 1"); exit(1); }
    guard m[1].tag == BIND_RESPONSE && m[1].cls == asn1::CLASS_APPLICATION && m[1].number == 1
    else { print("ldap_ber: not a BindResponse"); exit(1); }
    let r, okr = asn1::children(resp, m[1], true);
    guard okr && r.len >= 3 else { print("ldap_ber: short BindResponse"); exit(1); }
    let code, okc = asn1::read_i64(resp, r[0], asn1::ENUMERATED, true);
    let dn, okn = asn1::read_octets(resp, r[1]);
    let text, okt = asn1::read_octets(resp, r[2]);
    guard okc && okn && okt else { print("ldap_ber: bad BindResponse fields"); exit(1); }
    print("message ", id, ": bind result ", code, if code == 0 { " (success)" } else { "" },
          ", matched DN \"", dn, "\", text \"", text, "\"");
    guard code == 0 else { exit(1); }

    // BER's other liberties: a BOOLEAN of 01 is true, an INTEGER with a
    // redundant leading octet is read, both refused as DER.
    let b = unhex("010101");
    let tb, okb = asn1::parse(b);
    let v0, strict_b = asn1::read_bool(b, tb);
    let v1, loose_b = asn1::read_bool(b, tb, true);
    let n = unhex("02020005");
    let tn, okn2 = asn1::parse(n);
    let i0, strict_i = asn1::read_i64(n, tn);
    let i1, loose_i = asn1::read_i64(n, tn, asn1::INTEGER, true);
    guard okb && okn2 && !strict_b && loose_b && v1 && !strict_i && loose_i && i1 == 5
    else { print("ldap_ber: BER booleans and integers"); exit(1); }

    // An indefinite length (80 ... 00 00) is refused either way.
    let indef = unhex("30800201010000");
    let ti, oki2 = asn1::parse(indef, true);
    guard !oki2 else { print("ldap_ber: accepted an indefinite length"); exit(1); }
    print("BER read; DER refused; indefinite lengths refused");
}
