// Fuzz target: ldap_text. LDAP's string forms (net/ldap). Byte 0 picks: 0
// a search filter (RFC 4515) compiled to BER, decompiled, compiled again
// (the same BER), and matched against an entry; 1 a DN (RFC 4514) parsed,
// written by dn_string, parsed again (the same string), compared; 2 LDIF
// (RFC 2849) records read one after another, an add record's attributes
// matched by a filter; 3 an LDAP URL (RFC 4516). The value escapers are
// checked against the parsers: an escaped value always compiles / parses
// back to itself.

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.net.ldap;
import gslib.net.ldap.filter;
import gslib.net.ldap.dn;
import gslib.net.ldap.ldif;
import gslib.net.ldap.url;

var entry_attrs: u8[>..] = [];
var some_filter: u8[>..] = [];
var rec = ldap::empty_record();

let ENTRY = "dn: cn=Alice Smith,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: Alice  Smith\ncn;lang-fr: Alice Lef\xc3\xa8vre\nsn: Smith\nmail: alice@Example.COM\nuidNumber: 1500\ndescription: a*b(c)d\\e\ntitle: aba\n";

fn filter(s: const u8[:]) {
    let ber, ok = ldap::compile(s);
    if !ok { return; }
    let _ = ldap::filter_match(ber, entry_attrs);
    let _ = ldap::filter_match(ber, entry_attrs, true);
    let s2, ok2 = ldap::decompile(ber);
    if !ok2 { abort("ldap_text: a compiled filter does not decompile"); }
    let ber2, ok3 = ldap::compile(s2);
    if !ok3 { abort("ldap_text: a decompiled filter does not compile"); }
    // compile(decompile(b)) == b does not hold for every b compile makes,
    // as go-ldap's does not: "(cn=**)" is a substrings filter of no
    // substrings, decompiled "(cn=)", an equality (goldap.txt has both).
    // The second round must be stable.
    let s3, ok4 = ldap::decompile(ber2);
    if !ok4 || s3[..] != s2[..] { abort("ldap_text: decompile(compile(s2)) differs from s2"); }
}

fn dn(s: const u8[:]) {
    let d, ok = ldap::parse_dn(s);
    if !ok { let _ = ldap::dn_error(s); return; }
    for a in d.avas {
        let _ = ldap::ava_type(d, a);
        let _ = ldap::ava_value(d, a);
    }
    let t = ldap::dn_string(d);
    let d2, ok2 = ldap::parse_dn(t);
    if !ok2 { abort("ldap_text: dn_string does not parse back"); }
    let t2 = ldap::dn_string(d2);
    if t2[..] != t[..] { abort("ldap_text: dn_string(parse_dn(dn_string(d))) differs"); }
    if !ldap::dn_equal_fold(d, d2) { abort("ldap_text: a DN is not equal to its string parsed back"); }
    let _ = ldap::dn_equal(d, d2);
    let base, okb = ldap::parse_dn("dc=example,dc=com");
    let _ = ldap::dn_ancestor_of(base, d);
    let _ = ldap::dn_ancestor_of_fold(d, d2);
}

fn ldif(s: const u8[:]) {
    var pos = 0;
    var lineno = 0;
    var n = 0;
    while n < 256 {
        n++;
        var err: u8[>..] = [];
        let before = pos;
        let k = ldap::next_record(s, pos, lineno, rec, err, (n & 1) == 1) { url, value => false };
        if k != 1 { break; }
        if pos <= before { abort("ldap_text: next_record made no progress"); }
        if rec.kind == ldap::CHANGE_ADD {
            let _ = ldap::filter_match(some_filter, rec.body);
        }
        let _ = ldap::parse_dn(rec.dn);
        let _ = asn1::parse(rec.body, true);
    }
}

fn url(s: const u8[:]) {
    let u, ok = ldap::parse_url(s);
    if ok && u.filter.len > 0 { filter(u.filter); }
    if ok && u.dn.len > 0 { let _ = ldap::parse_dn(u.dn); }
}

fn escapes(v: const u8[:]) {
    var f: u8[>..] = [];
    f.append("(cn=");
    ldap::escape_filter_into(f, v);
    f.push(')');
    let ber, ok = ldap::compile(f);
    if !ok { abort("ldap_text: an escaped value does not compile"); }
    var dv: u8[>..] = [];
    dv.append("cn=");
    ldap::escape_dn_value_into(dv, v);
    let d, okd = ldap::parse_dn(dv);
    if !okd || d.avas.len != 1 || ldap::ava_value(d, d.avas[0]) != v { abort("ldap_text: an escaped DN value does not parse back"); }
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0] % 4;
    let rest = data[1..];
    if sel == 0 { filter(rest); }
    else if sel == 1 { dn(rest); }
    else if sel == 2 { ldif(rest); }
    else { url(rest); }
    if rest.len <= 512 { escapes(rest); }
    return 0;
}

fn main() {
    var pos = 0;
    var lineno = 0;
    var err: u8[>..] = [];
    let k = ldap::next_record(ENTRY, pos, lineno, rec, err, true) { url, value => false };
    assert(k == 1);
    entry_attrs.append(rec.body);
    let f, ok = ldap::compile("(&(objectClass=person)(|(cn=*smith*)(mail=alice@example.com))(!(uidNumber>=2000)))");
    assert(ok);
    some_filter.append(f);
}
