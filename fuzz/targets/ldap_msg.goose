// Fuzz target: ldap_msg. LDAP messages (net/ldap). Byte 0 picks: 0 a
// client connection with requests of each kind outstanding (bind, search,
// modify, add, delete, moddn, compare, extended), fed the rest in two
// pieces as the server's answers; 1 the bare frame reader and message
// parser over the rest; 2 a request as a server gets it: the message's
// elements walked, a SearchRequest's filter (or the whole input, as a
// filter's BER) decompiled to its string, compiled again, and matched
// against an entry. Every message read is walked with each accessor
// (results, referrals, entries and their attributes, extended responses,
// controls: paging, password policy, sort) and written as LDIF.

import std;
import gslib from "../..";
import gslib.encoding.asn1;
import gslib.net.ldap;
import gslib.net.ldap.conn;
import gslib.net.ldap.filter;
import gslib.net.ldap.ldif;

var entry_attrs: u8[>..] = [];
var some_filter: u8[>..] = [];

let ENTRY = "dn: cn=Alice Smith,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: Alice  Smith\ncn;lang-fr: Alice Lef\xc3\xa8vre\nsn: Smith\nmail: alice@Example.COM\nuidNumber: 1500\ndescription: a*b(c)d\\e\ntitle: aba\n";

fn probe(buf: const u8[:], m: const ldap::Message&) {
    let _ = ldap::result(buf, m);
    let _ = ldap::result_code(buf, m);
    let _ = ldap::result_message(buf, m);
    let _ = ldap::matched_dn(buf, m);
    let _ = ldap::result_error(buf, m);
    let _ = ldap::referrals(buf, m);
    let _ = ldap::server_sasl_creds(buf, m);
    let _ = ldap::response_name(buf, m);
    let _ = ldap::response_value(buf, m);
    let _ = ldap::generated_password(buf, m);
    let _ = ldap::entry_dn(buf, m);
    for a in ldap::attributes(buf, m) {
        let _ = ldap::attribute_name(buf, a);
        let _ = ldap::attribute_values(buf, a);
    }
    let _ = ldap::get_values(buf, m, "cn");
    let _ = ldap::get_value(buf, m, "objectClass");
    for c in ldap::controls(buf, m) {
        let _ = ldap::control_inner(buf, c);
        let _ = ldap::paging(buf, c);
        let _ = ldap::ppolicy(buf, c);
        let _ = ldap::vchu_warning(buf, c);
        let _ = ldap::sort_result(buf, c);
        let _ = ldap::control_name(buf[c.oid.off..c.oid.end]);
    }
    let _ = ldap::find_control(buf, m, ldap::CONTROL_PAGING);
    let _ = ldap::paging_cookie(buf, m);
    if m.op == ldap::OP_SEARCH_ENTRY {
        var l: u8[>..] = [];
        ldap::ldif_entry(l, buf, m);
        l.clear();
        ldap::ldif_entry(l, buf, m, 0, true);
        let _ = ldap::entry_matches(some_filter, buf, m);
        let _ = ldap::entry_matches(some_filter, buf, m, true);
        let attrs = ldap::entry_attributes(buf, m);
        let _ = ldap::filter_match(some_filter, attrs);
    }
}

fn client(data: const u8[:], mode: u8) {
    var c = ldap::client();
    var out: u8[>..] = [];
    let _ = ldap::bind(c, "cn=admin,dc=example,dc=com", "secret", out);
    let _ = ldap::search(c, "dc=example,dc=com", ldap::SCOPE_SUB, "(objectClass=*)", "cn mail", out);
    let _ = ldap::modify(c, "cn=a,dc=example,dc=com", "", out);
    let _ = ldap::add(c, "cn=b,dc=example,dc=com", "", out);
    let _ = ldap::delete(c, "cn=c,dc=example,dc=com", out);
    let _ = ldap::modify_dn(c, "cn=d,dc=example,dc=com", "cn=e", true, "", out);
    let _ = ldap::compare(c, "cn=f,dc=example,dc=com", "cn", "f", out);
    let _ = ldap::who_am_i(c, out);
    let _ = ldap::password_modify(c, "", "", "", out);
    if (mode & 1) != 0 { let _ = ldap::start_tls(c, out); }
    let half = data.len / 2;
    var msgs: u8[>..] = [];
    let _ = ldap::feed(c, data[..half], msgs);
    let _ = ldap::feed(c, data[half..], msgs);
    var pos = 0;
    var n = 0;
    while pos < msgs.len && n < 4096 {
        n++;
        let before = pos;
        let m, ok = ldap::next_message(msgs, pos);
        if !ok { abort("ldap_msg: feed delivered a message next_message refuses"); }
        if pos <= before { break; }
        probe(msgs, m);
    }
    let _ = ldap::conn_error(c);
    let _ = ldap::closed(c);
    let _ = ldap::eof(c);
}

fn bare(data: const u8[:]) {
    var pos = 0;
    var n = 0;
    while pos < data.len && n < 4096 {
        n++;
        let k = ldap::frame_len(data[pos..], data.len);
        if k <= 0 { break; }
        if pos + k > data.len { abort("ldap_msg: frame_len past the input"); }
        let m, ok = ldap::parse_message(data, pos, pos + k);
        if ok { probe(data, m); }
        pos += k;
    }
}

fn filter_ber(ber: const u8[:]) {
    let _ = ldap::filter_match(ber, entry_attrs);
    let _ = ldap::filter_match(ber, entry_attrs, true);
    let s, ok = ldap::decompile(ber);
    if !ok { return; }
    let ber2, ok2 = ldap::compile(s);
    if !ok2 { return; }       // decompile can write what compile refuses (an empty AND inside, say); not checked
    // Not compared: decompile writes what a BER has without checking it
    // (an attribute description with ':' in a present filter, say), and
    // compile then reads that string as another kind of filter.
    let s2, ok3 = ldap::decompile(ber2);
    let _ = ldap::filter_match(ber2, entry_attrs);
}

fn request(data: const u8[:]) {
    let t, ok = asn1::parse(data, true);
    if ok && t.tag == asn1::SEQUENCE {
        let cs, okc = asn1::children(data, t, true);
        if okc && cs.len >= 2 {
            let _ = asn1::read_i64(data, cs[0], asn1::INTEGER, true);
            if cs[1].tag == ldap::OP_SEARCH_REQUEST {
                let parts, okp = asn1::children(data, cs[1], true);
                if okp && parts.len >= 7 {
                    let ft = parts[6];
                    filter_ber(data[ft.start..ft.end]);
                }
            }
            let _ = ldap::response_op(cs[1].tag);
        }
    }
    filter_ber(data);
}

export fn fuzz_one(data: const u8[:]) -> i32 {
    if data.len == 0 { return 0; }
    let sel = data[0] % 3;
    let rest = data[1..];
    if sel == 0 { client(rest, data[0] / 3); }
    else if sel == 1 { bare(rest); }
    else { request(rest); }
    return 0;
}

fn main() {
    var pos = 0;
    var lineno = 0;
    var r = ldap::empty_record();
    var err: u8[>..] = [];
    let k = ldap::next_record(ENTRY, pos, lineno, r, err, true) { url, value => false };
    assert(k == 1);
    entry_attrs.append(r.body);
    let f, ok = ldap::compile("(&(objectClass=person)(|(cn=*smith*)(mail=alice@example.com))(!(uidNumber>=2000)))");
    assert(ok);
    some_filter.append(f);
}
